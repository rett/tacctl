package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/yamlpy"
)

// LockName is the lock file next to the store (store_lock).
const LockName = ".store.lock"

// ErrNotInitialised is what a mutation returns while no store exists
// (legacy read-only mode). Its message is NotInitialisedMsg; 0.1.16
// prints it as '[ERROR] <message>'.
var ErrNotInitialised = errors.New(NotInitialisedMsg)

// ExistsError is "Store already exists at <path>." (store_init,
// store_seed_fresh); 0.1.16 prints it as '[ERROR] <message>'.
type ExistsError struct{ Path string }

func (e *ExistsError) Error() string { return "Store already exists at " + e.Path + "." }

// NotFoundError is "Store not found at <path>." (store_validate on a
// missing file); 0.1.16 prints it as '[ERROR] <message>'.
type NotFoundError struct{ Path string }

func (e *NotFoundError) Error() string { return "Store not found at " + e.Path + "." }

var reYAMLLine = regexp.MustCompile(`^line ([0-9]+): (.*)$`)

// reQuoted matches the quoted values yaml.v3 and strconv put into some
// messages ("cannot decode !!str `...`", `parsing "..."`): they are taken
// out, as a value may be a secret or a hash.
var reQuoted = regexp.MustCompile("`[^`]*`|\"[^\"]*\"")

// yamlProblem is yaml_problem: '<path>: <problem> (line N)', without any
// snippet of the file (a line may hold a secret).
func yamlProblem(path string, err error) error {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "yaml: ")
	msg = strings.TrimPrefix(msg, "yamlpy: ")
	msg = reQuoted.ReplaceAllString(msg, "(value not shown)")
	if m := reYAMLLine.FindStringSubmatch(msg); m != nil {
		return &Error{Msg: path + ": " + m[2] + " (line " + m[1] + ")"}
	}
	if errors.Is(err, yamlpy.ErrUnsupportedValue) {
		return &Error{Msg: path + ": not supported by tacctl: " + msg}
	}
	return &Error{Msg: path + ": " + msg}
}

// LoadRaw is store_load_raw: the file decoded as yaml.safe_load would
// (yamlpy.Decode), or an *Error naming the file and the problem, never its
// content.
func LoadRaw(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{Msg: path + ": " + strerror(err)}
	}
	v, err := yamlpy.Decode(data)
	if err != nil {
		return nil, yamlProblem(path, err)
	}
	return v, nil
}

// Load is the store loader of model_load ('dump-store'): LoadRaw then
// Normalize. It does not validate (0.1.16 reads a store that does not
// validate; every write refuses it).
func Load(path string) (*Store, error) {
	raw, err := LoadRaw(path)
	if err != nil {
		return nil, err
	}
	return Normalize(raw)
}

// ValidateFile is store_validate <file>: the validator's messages for a
// store file (each printed by 0.1.16 as 'tacctl store: <message>' on
// stderr; any message means exit 1). A missing file is *NotFoundError, a
// file that cannot be read, parsed or walked is an *Error.
func ValidateFile(path string) ([]string, error) {
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return nil, &NotFoundError{Path: path}
	}
	raw, err := LoadRaw(path)
	if err != nil {
		return nil, err
	}
	if _, ok := mapOf(raw); ok {
		s, err := Normalize(raw)
		if err != nil {
			return nil, err
		}
		raw = s.doc
	}
	return Validate(raw), nil
}

// Lock is store_lock: an exclusive flock on <dir>/.store.lock (created
// 0600, the directory 0700 if missing), held until the returned function
// is called. It blocks while another tacctl holds it.
func Lock(path string) (unlock func(), err error) {
	d := filepath.Dir(path)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, &osError{err}
	}
	f, err := os.OpenFile(filepath.Join(d, LockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, &osError{err}
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, &osError{&fs.PathError{Op: "flock", Path: f.Name(), Err: err}}
	}
	return func() { _ = f.Close() }, nil
}

// atomicWrite writes data to path through a temp file in the same
// directory (.store.*.tmp, 0600), fsync, rename, then fsyncs the
// directory (best effort, as 0.1.16).
func atomicWrite(path string, data []byte) error {
	d := filepath.Dir(path)
	f, err := os.CreateTemp(d, ".store.*.tmp")
	if err != nil {
		return &osError{err}
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return &osError{err}
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return &osError{err}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return &osError{err}
	}
	if df, err := os.Open(d); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

// writeValidated is store_write_validated without the lock: canonicalise,
// validate, render, and write unless the file already holds exactly these
// bytes (then nothing is touched and the inode stays). It reports whether
// the file was written.
func writeValidated(path string, s *Store) (bool, error) {
	s.Canonicalize()
	if errs := Validate(s.doc); len(errs) > 0 {
		return false, &Error{Msg: "store validation failed:\n  - " + strings.Join(errs, "\n  - ")}
	}
	text, err := s.Text()
	if err != nil {
		return false, writeRefusal(err)
	}
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, text) {
		return false, nil
	}
	if err := atomicWrite(path, text); err != nil {
		return false, err
	}
	return true, nil
}

// writeRefusal is the error for a store that validates but cannot be
// written: the emitter refuses a value outside the domain it is verified
// on (yamlpy.ErrUnsupportedScalar: not printable ASCII; 0.1.16 wrote such
// a value with PyYAML's escapes), or its write-time self-check failed.
func writeRefusal(err error) error {
	where := strings.TrimPrefix(err.Error(), "yamlpy: ")
	if errors.Is(err, yamlpy.ErrUnsupportedScalar) {
		where = strings.TrimSuffix(where, ": "+yamlpy.ErrUnsupportedScalar.Error())
		return &Error{Msg: "cannot write " + where + ": only printable ASCII can be stored; nothing was written"}
	}
	return &Error{Msg: "internal: cannot write the store (" + where + "); nothing was written"}
}

// Write is 'import-write': under the lock, canonicalise, validate and
// write s to path (see writeValidated). It reports whether the file
// changed.
func Write(path string, s *Store) (bool, error) {
	unlock, err := Lock(path)
	if err != nil {
		return false, err
	}
	defer unlock()
	return writeValidated(path, s)
}

// exists is os.path.exists (and bash's -e): symlinks followed.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// MutateOptions are the hooks of store_mutate.
type MutateOptions struct {
	// Snapshot is store_snapshot_hook: called before the store is loaded;
	// an error blocks the mutation (and is returned as it is).
	Snapshot func() error
	// Now is the clock of 'password_changed=today' (nil: time.Now).
	Now func() time.Time
}

// Mutate is store_mutate: with no store at path it fails with
// ErrNotInitialised; otherwise the snapshot hook runs, then under the
// lock the store is loaded, fn changes it, and the result is
// canonicalised, validated and written (nothing is written when fn or the
// validation fails, or when the bytes would not change). changed reports
// whether the file was replaced.
func Mutate(path string, opts MutateOptions, fn func(*Store) error) (changed bool, err error) {
	if !isRegular(path) {
		return false, ErrNotInitialised
	}
	if opts.Snapshot != nil {
		if err := opts.Snapshot(); err != nil {
			return false, err
		}
	}
	return mutate(path, false, opts.Now, fn)
}

// mutate is the dispatcher's 'mutate' command: the load-or-create under
// the lock, fn, and the validated write.
func mutate(path string, create bool, now func() time.Time, fn func(*Store) error) (bool, error) {
	unlock, err := Lock(path)
	if err != nil {
		return false, err
	}
	defer unlock()
	var s *Store
	switch {
	case exists(path) && create:
		return false, &Error{Msg: path + " already exists"}
	case exists(path):
		if s, err = Load(path); err != nil {
			return false, err
		}
	case create:
		s = Empty()
	default:
		return false, &Error{Msg: NotInitialisedMsg}
	}
	s.Now = now
	if fn != nil {
		if err := fn(s); err != nil {
			return false, err
		}
	}
	return writeValidated(path, s)
}

// Init is store_init: create a store holding only the built-in groups.
// An existing store is *ExistsError.
func Init(path string) error {
	if exists(path) {
		return &ExistsError{Path: path}
	}
	_, err := mutate(path, true, nil, nil)
	return err
}

// SeedUsage is the message of store_seed_fresh called without a scope,
// prefixes or secret; 0.1.16 prints it as '[ERROR] <message>'.
const SeedUsage = "Usage: store_seed_fresh <scope> <cidr>[,<cidr>...]  (shared secret on stdin)"

// ErrSeedUsage is SeedFresh's error for an empty argument (its message is
// SeedUsage).
var ErrSeedUsage error = seedUsageError{}

type seedUsageError struct{}

func (seedUsageError) Error() string { return SeedUsage }

// SeedFresh is store_seed_fresh: create the store of a fresh install in
// one validated write (the built-in groups, the scope, SeedUsers as its
// members). An existing store is *ExistsError; an empty argument is an
// ErrSeedUsage.
func SeedFresh(path, scope, prefixes, secret string) error {
	if exists(path) {
		return &ExistsError{Path: path}
	}
	if scope == "" || prefixes == "" || secret == "" {
		return ErrSeedUsage
	}
	_, err := mutate(path, true, nil, func(s *Store) error {
		return s.SeedFresh(scope, prefixes, secret)
	})
	return err
}
