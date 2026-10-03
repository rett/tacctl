// Package rendered is tacctl's bookkeeping of the artifacts it renders
// (lib/backend.sh at the 0.1.16 tag, "Rendered-artifact bookkeeping"):
// rendered.json maps the absolute path of every file a backend rendered to
// the sha256 of what tacctl wrote there, so a later run can tell a file it
// left alone from one somebody edited (drift), deleted (missing) or that
// tacctl never wrote (unrecorded).
//
// The file is json.dumps(records, indent=2, sort_keys=True) plus a newline,
// written 0600 through a temp file and a rename under the store's lock
// (<dir>/.store.lock), exactly as 0.1.16 writes it.
//
// The status words:
//
//	ok          the file is what tacctl recorded
//	drift       the file differs from what tacctl recorded
//	missing     there is no such file
//	unrecorded  tacctl has no record of the path
//
// and, for a live artifact compared with a fresh render (LiveStatus):
//
//	current     identical to the render, and recorded as such
//	same        identical to the render, but not (or wrongly) recorded
//	unreadable  differs, and the records cannot be read
package rendered

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/conf/py"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The status words.
const (
	Current    = "current"
	Same       = "same"
	OK         = "ok"
	Drift      = "drift"
	Unrecorded = "unrecorded"
	Missing    = "missing"
	Unreadable = "unreadable"
)

// Severity is the order in which the words decide a combined state, the
// one furthest from the render first (_tacacs_render_check_run: the
// artifact furthest from the render decides).
var Severity = []string{Unreadable, Drift, Unrecorded, Missing, OK, Same, Current}

// Furthest is the word of Severity that comes first among states; false
// when none of states is a status word.
func Furthest(states []string) (string, bool) {
	for _, w := range Severity {
		for _, s := range states {
			if s == w {
				return w, true
			}
		}
	}
	return "", false
}

// Error is a problem the 0.1.16 render and bookkeeping programs report as
// one 'tacctl render: <message>' line on stderr (exit 1). The message
// never contains a secret.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Report is the line 0.1.16 prints on stderr for err from this package or
// from internal/render/tacacs: 'tacctl render: <message>' for an *Error,
// a *store.Error and a file-system error ('<path>: <strerror>', Python's
// OSError report), the error's text otherwise.
func Report(err error) string {
	var re *Error
	if errors.As(err, &re) {
		return "tacctl render: " + re.Msg
	}
	var se *store.Error
	if errors.As(err, &se) {
		return "tacctl render: " + se.Msg
	}
	if t, ok := OSErrorText(err); ok {
		return "tacctl render: " + t
	}
	return err.Error()
}

// OSErrorText is how the 0.1.16 programs report an OSError:
// '<filename or "I/O">: <strerror>'. ok is false when err is not a
// file-system error.
func OSErrorText(err error) (string, bool) {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Path + ": " + Strerror(pe.Err), true
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Old + ": " + Strerror(le.Err), true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return "I/O: " + Strerror(errno), true
	}
	return "", false
}

// Strerror is the C library's text of an errno as Python's
// OSError.strerror has it ("No such file or directory"); Go's table holds
// the same words with a lower-case first letter.
func Strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		if s != "" {
			r, size := utf8.DecodeRuneInString(s)
			return string(unicode.ToUpper(r)) + s[size:]
		}
	}
	return err.Error()
}

// Records is rendered.json: absolute path -> sha256 (lower-case hex).
type Records map[string]string

// Load is rendered_load: the records of jsonPath, empty when the file does
// not exist. A file that is not JSON, or not a mapping of strings, is an
// *Error ("<path>: not valid JSON", "<path>: not a path-to-sha256
// mapping"); any other failure to read it is the file-system error.
func Load(jsonPath string) (Records, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return Records{}, nil
		}
		return nil, err
	}
	if !utf8.Valid(data) {
		// Python's text-mode read raises UnicodeDecodeError, a ValueError.
		return nil, &Error{Msg: jsonPath + ": not valid JSON"}
	}
	// open() in text mode translates \r\n and \r to \n.
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	v, err := py.Loads(text)
	if err != nil {
		return nil, &Error{Msg: jsonPath + ": not valid JSON"}
	}
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil, &Error{Msg: jsonPath + ": not a path-to-sha256 mapping"}
	}
	out := Records{}
	for k, val := range m.All() {
		s, isStr := val.(string)
		if !isStr {
			return nil, &Error{Msg: jsonPath + ": not a path-to-sha256 mapping"}
		}
		out[k] = s
	}
	return out, nil
}

// FileSHA256 is file_sha256: the lower-case hex sha256 of the file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", &fs.PathError{Op: "read", Path: path, Err: err}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exists is os.path.exists: false for anything that cannot be stat'ed.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Status is rendered_status: ok, drift, missing or unrecorded for path
// (looked up as given) against records. An existing file that cannot be
// read is an error.
func Status(records Records, path string) (string, error) {
	if !exists(path) {
		return Missing, nil
	}
	want, ok := records[path]
	if !ok {
		return Unrecorded, nil
	}
	got, err := FileSHA256(path)
	if err != nil {
		return "", err
	}
	if got == want {
		return OK, nil
	}
	return Drift, nil
}

// Abs is os.path.abspath.
func Abs(path string) string {
	a, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return a
}

// Check is 'rendered_check <path>': the word for the absolute form of path
// against the records of jsonPath. Records that cannot be read are an
// error (the bash function's status 4: never "ok").
func Check(jsonPath, path string) (string, error) {
	records, err := Load(jsonPath)
	if err != nil {
		return "", err
	}
	return Status(records, Abs(path))
}

// CheckCode is the return status of rendered_check for its word: ok 0,
// drift 1, missing 2, unrecorded 3, anything else (records unreadable) 4.
func CheckCode(word string) int {
	switch word {
	case OK:
		return 0
	case Drift:
		return 1
	case Missing:
		return 2
	case Unrecorded:
		return 3
	}
	return 4
}

// Marshal is json.dumps(records, indent=2, sort_keys=True) + "\n".
func Marshal(r Records) []byte {
	if len(r) == 0 {
		return []byte("{}\n")
	}
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	// Python sorts str keys by code point; UTF-8 byte order is the same.
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range keys {
		ks, _ := py.Dumps(k)
		vs, _ := py.Dumps(r[k])
		b.WriteString("  " + ks + ": " + vs)
		if i < len(keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// atomicWrite is lib/store.sh's atomic_write(path, text): a temp file
// .store.*.tmp in the same directory, 0600, fsync, rename, then a
// best-effort fsync of the directory.
func atomicWrite(path string, data []byte) error {
	d := filepath.Dir(path)
	f, err := os.CreateTemp(d, ".store.*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
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
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if df, err := os.Open(d); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

// Record is 'rendered_record <path>': remember the file's current sha256
// as what tacctl rendered at its absolute path, keeping every other
// record.
func Record(jsonPath, path string) error {
	path = Abs(path)
	unlock, err := store.Lock(jsonPath)
	if err != nil {
		return err
	}
	defer unlock()
	records, err := Load(jsonPath)
	if err != nil {
		return err
	}
	sum, err := FileSHA256(path)
	if err != nil {
		return err
	}
	records[path] = sum
	return atomicWrite(jsonPath, Marshal(records))
}

// Forget is 'rendered_forget <path>': drop the record of the absolute path
// (nothing is written when there is none, or no rendered.json).
func Forget(jsonPath, path string) error {
	path = Abs(path)
	if !exists(jsonPath) {
		return nil
	}
	unlock, err := store.Lock(jsonPath)
	if err != nil {
		return err
	}
	defer unlock()
	records, err := Load(jsonPath)
	if err != nil {
		return err
	}
	if _, ok := records[path]; !ok {
		return nil
	}
	delete(records, path)
	return atomicWrite(jsonPath, Marshal(records))
}

// Entry is one line of 'drift': an artifact that no longer is what tacctl
// rendered.
type Entry struct {
	Status string // drift | missing (unreadable from CheckDrift)
	Path   string
}

// Line is the '<status>\t<path>' line bash prints for the entry.
func (e Entry) Line() string { return e.Status + "\t" + e.Path }

// ListDrift is the bookkeeping program's 'drift <rendered.json>': every
// recorded artifact whose status is not ok, in path order. Records that
// cannot be read, and a recorded file that exists but cannot be read, are
// errors.
func ListDrift(jsonPath string) ([]Entry, error) {
	records, err := Load(jsonPath)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(records))
	for p := range records {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []Entry
	for _, p := range paths {
		st, err := Status(Records{p: records[p]}, p)
		if err != nil {
			return out, err
		}
		if st != OK {
			out = append(out, Entry{st, p})
		}
	}
	return out, nil
}

// CheckDrift is the unfiltered core of backends_check_drift: nothing when
// rendered.json does not exist or every artifact is as recorded; the
// drifted and missing artifacts otherwise; and when the program fails
// before it reported anything, the one entry 'unreadable <rendered.json>'.
// (Selecting by owning backend is internal/backend's.)
func CheckDrift(jsonPath string) []Entry {
	st, err := os.Stat(jsonPath)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	out, err := ListDrift(jsonPath)
	if err != nil && len(out) == 0 {
		return []Entry{{Unreadable, jsonPath}}
	}
	return out
}

// LiveStatus is the word render-live prints for a live artifact against
// the bytes just rendered for it: current or same when the live file holds
// exactly those bytes (current when it is also recorded as such), else its
// recorded status, or unreadable when the records cannot be read. live is
// made absolute first. A file-system error reading the records (other
// than their absence) or either file is returned.
func LiveStatus(jsonPath, live string, rendered []byte) (string, error) {
	live = Abs(live)
	status := Unreadable
	records, err := Load(jsonPath)
	var re *Error
	switch {
	case err == nil:
		if status, err = Status(records, live); err != nil {
			return "", err
		}
	case !errors.As(err, &re):
		return "", err
	}
	return combine(status, live, rendered)
}

// combine applies the "identical to the render" rule to a recorded status.
func combine(status, live string, rendered []byte) (string, error) {
	if !exists(live) {
		return status, nil
	}
	data, err := os.ReadFile(live)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(data, rendered) {
		return status, nil
	}
	if status == OK {
		return Current, nil
	}
	return Same, nil
}

// UnitStatus is render_units' word for one drop-in: like LiveStatus, with
// records loaded once by the caller (nil: they could not be read, so the
// word is same or unreadable).
func UnitStatus(records Records, live string, rendered []byte) (string, error) {
	live = Abs(live)
	if records == nil {
		st, err := combine(Unreadable, live, rendered)
		return st, err
	}
	st, err := Status(records, live)
	if err != nil {
		return "", err
	}
	return combine(st, live, rendered)
}

// LoadOrNil is the 'try: rendered_load except StoreError: None' of
// render_units: nil records (not an error) when the file is not usable
// JSON; other read failures are returned.
func LoadOrNil(jsonPath string) (Records, error) {
	records, err := Load(jsonPath)
	var re *Error
	if errors.As(err, &re) {
		return nil, nil
	}
	return records, err
}
