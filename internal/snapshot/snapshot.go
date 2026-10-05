// Package snapshot is tacctl's snapshot engine (lib/service.sh at the 0.1.16
// tag, "Snapshots of the canonical files"): before a change, store.yaml and
// tacctl.yaml are copied into a directory backups/<id>/ with a manifest (the
// rendered.json of that moment and the tacctl version). Restoring one
// restores the truth, not the artifacts derived from it. Snapshots hold
// shared secrets and password hashes: the directory is 0700 and its files
// 0600.
//
// An id is YYYYMMDD_HHMMSS_mmm (local time, milliseconds truncated), with
// -N appended when the name is taken. A directory under backups/ is a
// snapshot only if its name has the shape of ValidID (the milliseconds are
// optional there: older tacctl releases wrote YYYYMMDD_HHMMSS). Everything
// else under backups/ (password-dates/, disabled/, legacy/, old-style
// tacquito.yaml.<ts> files) is not this package's to prune.
//
// Listing, diffing and restoring snapshots are the 'backup' command's
// (internal/cli); this package takes them and keeps the newest Retention.
package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// Retention is how many snapshots are kept (BACKUP_RETENTION).
const Retention = 30

// FaultTake is the TACCTL_FAULT point that makes Take fail as a snapshot
// that cannot be written does (the bash tests override backup_snapshot).
const FaultTake = "snapshot"

// idRE is BACKUP_SNAPSHOT_RE.
var idRE = regexp.MustCompile(`^[0-9]{8}_[0-9]{6}(_[0-9]{3})?(-[0-9]+)?$`)

// ValidID reports whether name has the shape of a snapshot id.
func ValidID(name string) bool { return idRE.MatchString(name) }

// Compare orders two snapshot ids by time: -1 when a is older than b, +1
// when newer, 0 when they are the same id. Ids compare by their timestamp
// (an id without milliseconds before one with them), then by their -N
// suffix numerically (none before -1, -2 before -10). bash sorted them with
// 'sort -r', which agrees with this for every id tacctl writes below a
// suffix of -10; the numeric order is the one docs/plans/go-rewrite.md 1.2
// fixes for Go.
func Compare(a, b string) int {
	ka, kb := key(a), key(b)
	if c := strings.Compare(ka.stamp, kb.stamp); c != 0 {
		return c
	}
	if ka.ms != kb.ms {
		return cmpInt(ka.ms, kb.ms)
	}
	if ka.suffix != kb.suffix {
		return cmpInt(ka.suffix, kb.suffix)
	}
	return strings.Compare(a, b)
}

type idKey struct {
	stamp  string // YYYYMMDD_HHMMSS
	ms     int    // -1: none
	suffix int    // -1: none
}

func key(id string) idKey {
	k := idKey{ms: -1, suffix: -1}
	base, suf, hasSuf := strings.Cut(id, "-")
	if hasSuf {
		if n, err := strconv.Atoi(suf); err == nil {
			k.suffix = n
		}
	}
	if len(base) > 15 {
		k.stamp = base[:15]
		if n, err := strconv.Atoi(base[16:]); err == nil {
			k.ms = n
		}
	} else {
		k.stamp = base
	}
	return k
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// IDs is _backup_snapshot_ids: the snapshot ids under backupDir, newest
// first. It never fails: a directory that cannot be read has none.
func IDs(backupDir string) []string {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		// find -type d: the entry itself, not what a symlink points to.
		if e.Type().IsDir() && ValidID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	slices.SortFunc(ids, func(a, b string) int { return Compare(b, a) })
	return ids
}

// Snapshotter takes the snapshots of one invocation. The zero value is not
// usable; New fills it from the resolved paths.
type Snapshotter struct {
	StoreFile string // STORE_FILE
	Overrides string // TACCTL_OVERRIDES_FILE (tacctl.yaml)
	// DevicesFile is devices.yaml, the device registry: part of a snapshot
	// when it exists, nothing to do when it does not ("" too).
	DevicesFile string
	// ConsoleFile is console.yaml, the login console's settings: part of a
	// snapshot the same way.
	ConsoleFile string
	Rendered    string // RENDERED_FILE, copied into the manifest
	BackupDir   string // BACKUP_DIR
	// Version is the tacctl version the manifest records ("unknown" when
	// empty, as get_version prints when it cannot tell).
	Version string
	// Now is the clock of the id and of the manifest's "created" (nil:
	// time.Now). The id is in the clock's local time, as date(1) prints it.
	Now func() time.Time
	// Out receives the "Config snapshot saved to <dir>" line.
	Out ui.Output
	// Chown gives a newly created backups directory to tacquito:tacquito,
	// best effort (nil: no chown).
	Chown func(path string)
	// Fault is the TACCTL_FAULT check (nil: no faults); FaultTake makes Take
	// fail.
	Fault func(point string) error
	// KeepID is a snapshot retention must not delete (_BACKUP_KEEP_ID: the
	// one a restore reads from).
	KeepID string

	held int
}

// New is a Snapshotter over the state directory of p. Chown defaults to a
// best-effort chown to the tacquito account.
func New(p paths.Paths, version string, now func() time.Time, out ui.Output) *Snapshotter {
	return &Snapshotter{
		StoreFile:   p.StoreFile,
		Overrides:   p.Overrides,
		DevicesFile: p.DevicesFile,
		ConsoleFile: p.ConsoleFile,
		Rendered:    p.Rendered,
		BackupDir:   p.BackupDir,
		Version:     version,
		Now:         now,
		Out:         out,
		Chown:       chownTacquito,
	}
}

// chownTacquito is 'chown tacquito:tacquito <path> 2>/dev/null || true'.
func chownTacquito(path string) {
	u, err := user.Lookup("tacquito")
	if err != nil {
		return
	}
	g, err := user.LookupGroup("tacquito")
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(g.Gid)
	if err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
}

// Hold suppresses Take until the returned function is called
// (_BACKUP_SNAPSHOT_HELD=1): a command that took its own snapshot (store
// apply, backup restore) runs its writes without one snapshot per
// intermediate state. Holds nest.
func (s *Snapshotter) Hold() (release func()) {
	s.held++
	done := false
	return func() {
		if !done {
			done = true
			s.held--
		}
	}
}

// Held reports whether a Hold is in effect.
func (s *Snapshotter) Held() bool { return s.held > 0 }

// Hook is store_snapshot_hook for store.MutateOptions.Snapshot: Take,
// without the id.
func (s *Snapshotter) Hook() error {
	_, err := s.Take()
	return err
}

func (s *Snapshotter) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Take is backup_snapshot: snapshot store.yaml and tacctl.yaml before a
// change. It returns the id of the snapshot it made, or "" when it made
// none:
//   - while a Hold is in effect;
//   - when there is no store;
//   - when the live files already equal the newest snapshot (a command
//     that changes nothing, or a second write of one command, does not pile
//     up identical snapshots).
//
// The directory is built under a private name (.snap.*) and renamed into
// place, so a snapshot is never seen half written; a name already taken
// gets a -N suffix. Then the newest Retention snapshots are kept: never the
// one just made, KeepID, or anything that is not a snapshot is removed.
// "Config snapshot saved to <dir>" goes to Out. A snapshot that cannot be
// made is an error (printed by nobody here: the caller prints it as an
// [ERROR] line) and leaves no temporary directory behind.
func (s *Snapshotter) Take() (string, error) {
	if s.held > 0 || !isRegular(s.StoreFile) {
		return "", nil
	}
	ids := IDs(s.BackupDir)
	if len(ids) > 0 && s.current(filepath.Join(s.BackupDir, ids[0])) {
		return "", nil
	}

	if !isDir(s.BackupDir) {
		if err := os.MkdirAll(s.BackupDir, 0o750); err != nil {
			return "", errors.New("Cannot create " + s.BackupDir + ".")
		}
		_ = os.Chmod(s.BackupDir, 0o750)
		if s.Chown != nil {
			s.Chown(s.BackupDir)
		}
	}
	tmp, err := os.MkdirTemp(s.BackupDir, ".snap.")
	if err != nil {
		return "", errors.New("Cannot create a snapshot in " + s.BackupDir + ".")
	}
	now := s.now()
	if err := s.fill(tmp, now); err != nil {
		_ = os.RemoveAll(tmp)
		return "", errors.New("Cannot write a snapshot in " + s.BackupDir + ".")
	}

	// Milliseconds keep two commands in one second apart; the suffix covers
	// the same millisecond.
	name := now.Format("20060102_150405") + fmt.Sprintf("_%03d", now.Nanosecond()/int(time.Millisecond))
	final := filepath.Join(s.BackupDir, name)
	for n := 0; ; {
		if !lexists(final) && os.Rename(tmp, final) == nil {
			break
		}
		n++
		if n > 100 {
			_ = os.RemoveAll(tmp)
			return "", errors.New("Cannot name a snapshot in " + s.BackupDir + ".")
		}
		final = filepath.Join(s.BackupDir, name+"-"+strconv.Itoa(n))
	}
	name = filepath.Base(final)
	s.Out.Info("Config snapshot saved to " + final)

	// Retention. ids was read before this snapshot existed: the new one goes
	// in front, and the oldest of the rest go.
	ids = append([]string{name}, ids...)
	for i := Retention; i < len(ids); i++ {
		if ids[i] == name || ids[i] == s.KeepID {
			continue
		}
		_ = os.RemoveAll(filepath.Join(s.BackupDir, ids[i]))
	}
	return name, nil
}

// current is _backup_snapshot_current: the live store.yaml and tacctl.yaml
// are byte-identical to the ones in dir (tacctl.yaml absent on both sides
// counts).
func (s *Snapshotter) current(dir string) bool {
	if !sameBytes(s.StoreFile, filepath.Join(dir, "store.yaml")) {
		return false
	}
	if isRegular(s.DevicesFile) {
		if !sameBytes(s.DevicesFile, filepath.Join(dir, "devices.yaml")) {
			return false
		}
	} else if lexists(filepath.Join(dir, "devices.yaml")) {
		return false
	}
	if isRegular(s.ConsoleFile) {
		if !sameBytes(s.ConsoleFile, filepath.Join(dir, "console.yaml")) {
			return false
		}
	} else if lexists(filepath.Join(dir, "console.yaml")) {
		return false
	}
	if isRegular(s.Overrides) {
		return sameBytes(s.Overrides, filepath.Join(dir, "tacctl.yaml"))
	}
	return !lexists(filepath.Join(dir, "tacctl.yaml"))
}

// fill is _backup_snapshot_fill: the files of a snapshot in dir, 0600, the
// directory 0700.
func (s *Snapshotter) fill(dir string, now time.Time) error {
	if s.Fault != nil {
		if err := s.Fault(FaultTake); err != nil {
			return err
		}
	}
	if err := copyFile(s.StoreFile, filepath.Join(dir, "store.yaml")); err != nil {
		return err
	}
	if isRegular(s.Overrides) {
		if err := copyFile(s.Overrides, filepath.Join(dir, "tacctl.yaml")); err != nil {
			return err
		}
	}
	if isRegular(s.DevicesFile) {
		if err := copyFile(s.DevicesFile, filepath.Join(dir, "devices.yaml")); err != nil {
			return err
		}
	}
	if isRegular(s.ConsoleFile) {
		if err := copyFile(s.ConsoleFile, filepath.Join(dir, "console.yaml")); err != nil {
			return err
		}
	}
	version := s.Version
	if version == "" {
		version = "unknown"
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), Manifest(s.Rendered, version, now), 0o600); err != nil {
		return err
	}
	// MkdirTemp made the directory 0700 already; stated so the mode does
	// not depend on it.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Chmod(filepath.Join(dir, e.Name()), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// copyFile is cp(1) without -p: the content, into a new file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// sameBytes is 'cmp -s a b': both readable and identical.
func sameBytes(a, b string) bool {
	da, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	db, err := os.ReadFile(b)
	if err != nil {
		return false
	}
	return bytes.Equal(da, db)
}

// isRegular is bash's -f.
func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// isDir is bash's -d.
func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// lexists is '-e path || -L path'.
func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
