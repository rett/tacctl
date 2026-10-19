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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
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
	// SNMPFile is snmp.yaml (the default SNMP credentials) and SNMPDir the
	// directory of the per-scope credential files (snmp/<scope>.yaml): both
	// are part of a snapshot when they exist, in the modes they have
	// (0600, the directory 0700), so a restore brings the credentials of a
	// scope back that its removal (or a rollback) deleted.
	SNMPFile string
	SNMPDir  string
	// BlocksDir is the directory of the configuration blocks (blocks/
	// <scope>/<vendor>/<block> and blocks/_devices/<device>/<vendor>/<block>,
	// 0.2.7): part of a snapshot when it holds a file, in the modes it is
	// kept in (0600, the directories 0700). The list of blocks in force is
	// in tacctl.yaml, which a snapshot holds already.
	BlocksDir string
	// LinuxHosts is the registry of enrolled Linux hosts (linux-hosts),
	// HostRecords the directory of the per-host records (hosts/<name>.json),
	// StagingFile the staging addresses (staging) and LinuxUIDs the UID
	// ledger (linux-uids), all in the state directory (0.2.14, D188). A
	// snapshot holds them in the modes they are kept in (0600, the directory
	// 0700). linux-hosts is written to every snapshot, empty when there is no
	// registry, so that its presence says the snapshot knows the hosts: one
	// without it (0.2.13 and older) leaves all four alone on a restore. An
	// empty LinuxHosts leaves the host files out of snapshots altogether.
	// 0.2.13 ignores these entries: it reads a snapshot by the names it
	// knows (store.yaml, tacctl.yaml, devices.yaml, console.yaml, snmp*,
	// blocks, manifest), and the only directory listing it makes under
	// backups/ is of the snapshot ids and the old-style files.
	LinuxHosts  string
	HostRecords string
	StagingFile string
	LinuxUIDs   string
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
	// Exact makes the comparison with the newest snapshot byte for byte,
	// host records included; without it the records are compared on their
	// provisioner entry only (D210). A restore sets it for the snapshot it
	// takes first, which is what undoes the restore (D211).
	Exact bool

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
		SNMPFile:    p.SNMPFile,
		SNMPDir:     p.SNMPDir,
		BlocksDir:   p.BlocksDir,
		LinuxHosts:  p.LinuxHosts,
		HostRecords: p.HostRecords,
		StagingFile: filepath.Join(p.StateDir, StagingName),
		LinuxUIDs:   p.LinuxUIDs,
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

// Take is backup_snapshot: snapshot store.yaml and tacctl.yaml (and the
// registry files beside them) before a change. It returns the id of the snapshot it made, or "" when it made
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
// counts), and so is the rest of the state; but for the host records, which
// are compared on their meaningful part unless Exact is set.
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
	if isRegular(s.SNMPFile) {
		if !sameBytes(s.SNMPFile, filepath.Join(dir, "snmp.yaml")) {
			return false
		}
	} else if lexists(filepath.Join(dir, "snmp.yaml")) {
		return false
	}
	if !sameSNMPDir(s.SNMPDir, filepath.Join(dir, "snmp")) {
		return false
	}
	if !sameBlocksDir(s.BlocksDir, filepath.Join(dir, BlocksName)) {
		return false
	}
	if !s.sameHosts(dir) {
		return false
	}
	if isRegular(s.Overrides) {
		return sameBytes(s.Overrides, filepath.Join(dir, "tacctl.yaml"))
	}
	return !lexists(filepath.Join(dir, "tacctl.yaml"))
}

// The names of the host entries inside a snapshot (D188).
const (
	// HostsName is the registry; its presence says that the snapshot knows
	// the hosts.
	HostsName = "linux-hosts"
	// HostRecordsName is the directory of the per-host records.
	HostRecordsName = "hosts"
	// StagingName is the staging addresses.
	StagingName = "staging"
	// UIDsName is the UID ledger.
	UIDsName = "linux-uids"
)

// KnowsHosts reports whether the snapshot in dir holds the host state
// (linux-hosts is there, empty or not): a snapshot of 0.2.13 or older does
// not, and a restore of it leaves the live host files alone.
func KnowsHosts(dir string) bool { return isRegular(filepath.Join(dir, HostsName)) }

// sameHosts is whether the live host files equal the ones in snapshot
// directory dir: the registry (a missing one equals an empty one, as the
// snapshot writes it), the records, staging and the ledger (each present on
// both sides with the same bytes, or on neither; the records as sameRecords
// says). A snapshot that does not know the hosts is not the live state,
// whatever the files are, so the next one is taken. Nothing to compare when
// the host files are not configured.
func (s *Snapshotter) sameHosts(dir string) bool {
	if s.LinuxHosts == "" {
		return true
	}
	if !KnowsHosts(dir) {
		return false
	}
	live, _ := os.ReadFile(s.LinuxHosts)
	if !isRegular(s.LinuxHosts) {
		live = nil
	}
	if snap, err := os.ReadFile(filepath.Join(dir, HostsName)); err != nil || !bytes.Equal(live, snap) {
		return false
	}
	for _, f := range [][2]string{{s.StagingFile, StagingName}, {s.LinuxUIDs, UIDsName}} {
		if f[0] == "" {
			continue
		}
		if isRegular(f[0]) {
			if !sameBytes(f[0], filepath.Join(dir, f[1])) {
				return false
			}
		} else if lexists(filepath.Join(dir, f[1])) {
			return false
		}
	}
	return sameRecords(s.HostRecords, filepath.Join(dir, HostRecordsName), s.Exact)
}

// HostRecordFiles are the host records of dir (the regular <name>.json files;
// a name that starts with a dot is a record being written, a symbolic link
// or anything else is not one), sorted by name. A directory that cannot be
// read has none.
func HostRecordFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".") {
			out = append(out, n)
		}
	}
	return out
}

// sameRecords is whether the live records directory and the snapshot's
// hold the same host records (neither having any counts). With exact, the
// same bytes. Without it (D210) the same meaningful part: a record is equal
// when both sides have the same provisioner entry (both none, or equal),
// whatever last_sync and facts say, and a record on one side only is equal
// when it holds no provisioner entry. A record that cannot be read is
// compared by its bytes, or differs when it is on one side only.
func sameRecords(live, snap string, exact bool) bool {
	a, b := HostRecordFiles(live), HostRecordFiles(snap)
	if exact {
		if !slices.Equal(a, b) {
			return false
		}
		for _, n := range a {
			if !sameBytes(filepath.Join(live, n), filepath.Join(snap, n)) {
				return false
			}
		}
		return true
	}
	all := slices.Concat(a, b)
	slices.Sort(all)
	for _, n := range slices.Compact(all) {
		inLive, inSnap := slices.Contains(a, n), slices.Contains(b, n)
		switch {
		case inLive && inSnap:
			x, okX := recordProvisioner(filepath.Join(live, n))
			y, okY := recordProvisioner(filepath.Join(snap, n))
			if !okX || !okY {
				if !sameBytes(filepath.Join(live, n), filepath.Join(snap, n)) {
					return false
				}
			} else if !reflect.DeepEqual(x, y) {
				return false
			}
		case inLive:
			if p, ok := recordProvisioner(filepath.Join(live, n)); !ok || p != nil {
				return false
			}
		default:
			if p, ok := recordProvisioner(filepath.Join(snap, n)); !ok || p != nil {
				return false
			}
		}
	}
	return true
}

// recordProvisioner is the provisioner entry of the host record at path (nil
// when it has none), decoded generically so that two entries compare field
// by field; false when the record cannot be read. The package reads the one
// entry itself: internal/hosts, which owns the record type, depends on this
// package through the backends.
func recordProvisioner(path string) (any, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var r struct {
		Provisioner any `json:"provisioner"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false
	}
	return r.Provisioner, true
}

// copyRecordsDir copies the records of src into a new directory dst (0700,
// the files 0600); nothing when src has none.
func copyRecordsDir(src, dst string) error {
	files := HostRecordFiles(src)
	if len(files) == 0 {
		return nil
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	for _, n := range files {
		if err := copyFile(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
			return err
		}
	}
	return os.Chmod(dst, 0o700)
}

// fillHosts writes the host entries of a snapshot into dir: linux-hosts
// always (empty when there is no registry), the others when they exist.
func (s *Snapshotter) fillHosts(dir string) error {
	if s.LinuxHosts == "" {
		return nil
	}
	if isRegular(s.LinuxHosts) {
		if err := copyFile(s.LinuxHosts, filepath.Join(dir, HostsName)); err != nil {
			return err
		}
	} else if err := os.WriteFile(filepath.Join(dir, HostsName), nil, 0o600); err != nil {
		return err
	}
	for _, f := range [][2]string{{s.StagingFile, StagingName}, {s.LinuxUIDs, UIDsName}} {
		if f[0] != "" && isRegular(f[0]) {
			if err := copyFile(f[0], filepath.Join(dir, f[1])); err != nil {
				return err
			}
		}
	}
	return copyRecordsDir(s.HostRecords, filepath.Join(dir, HostRecordsName))
}

// SNMPFiles are the per-scope credential files of dir (the regular
// <scope>.yaml files; a symbolic link or anything else is not one), sorted
// by name. A directory that cannot be read has none. The per-device files
// are SNMPDeviceFiles'.
func SNMPFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, e.Name())
		}
	}
	return out
}

// SNMPDevicesDir is the name of the subdirectory of the credentials
// directory that holds the per-device files (snmpcred.DevicesDir; D72 of
// docs/plans/0.2.4-plan.md).
const SNMPDevicesDir = "devices"

// SNMPDeviceFiles are the per-device credential files of dir's 'devices'
// subdirectory (regular <device>.yaml files, as SNMPFiles has them; a
// subdirectory that is a symbolic link has none).
func SNMPDeviceFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	sub := filepath.Join(dir, SNMPDevicesDir)
	if fi, err := os.Lstat(sub); err != nil || !fi.IsDir() {
		return nil
	}
	return SNMPFiles(sub)
}

// sameSNMPDir is whether the live credentials directory and the snapshot's
// hold the same files with the same bytes, the per-device ones too (neither
// having any counts).
func sameSNMPDir(live, snap string) bool {
	for _, sub := range []string{"", SNMPDevicesDir} {
		l, s := filepath.Join(live, sub), filepath.Join(snap, sub)
		a, b := SNMPFiles(l), SNMPFiles(s)
		if sub != "" {
			a, b = SNMPDeviceFiles(live), SNMPDeviceFiles(snap)
		}
		if !slices.Equal(a, b) {
			return false
		}
		for _, n := range a {
			if !sameBytes(filepath.Join(l, n), filepath.Join(s, n)) {
				return false
			}
		}
	}
	return true
}

// copySNMPDir copies the credential files of src, the per-device ones
// included, into a new directory dst (0700, the files 0600); nothing when
// src has none.
func copySNMPDir(src, dst string) error {
	files, devFiles := SNMPFiles(src), SNMPDeviceFiles(src)
	if len(files) == 0 && len(devFiles) == 0 {
		return nil
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	for _, n := range files {
		if err := copyFile(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
			return err
		}
	}
	if len(devFiles) > 0 {
		sub := filepath.Join(dst, SNMPDevicesDir)
		if err := os.Mkdir(sub, 0o700); err != nil {
			return err
		}
		for _, n := range devFiles {
			if err := copyFile(filepath.Join(src, SNMPDevicesDir, n), filepath.Join(sub, n)); err != nil {
				return err
			}
		}
		if err := os.Chmod(sub, 0o700); err != nil {
			return err
		}
	}
	return os.Chmod(dst, 0o700)
}

// BlocksName is the name of the configuration blocks' directory inside a
// snapshot.
const BlocksName = "blocks"

// BlockFiles are the regular files of the blocks directory dir, as paths
// relative to it with '/' separators, sorted: a block is
// <scope>/<vendor>/<block> or _devices/<device>/<vendor>/<block>. Anything
// that is not a regular file or a directory (a symbolic link) is not
// followed or listed; a directory that cannot be read has none.
func BlockFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				return filepath.SkipAll
			}
			return nil
		}
		if d.Type().IsRegular() {
			if rel, err := filepath.Rel(dir, path); err == nil {
				out = append(out, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	slices.Sort(out)
	return out
}

// sameBlocksDir is whether the live blocks directory and the snapshot's
// hold the same files with the same bytes (neither having any counts).
func sameBlocksDir(live, snap string) bool {
	a, b := BlockFiles(live), BlockFiles(snap)
	if !slices.Equal(a, b) {
		return false
	}
	for _, n := range a {
		if !sameBytes(filepath.Join(live, filepath.FromSlash(n)), filepath.Join(snap, filepath.FromSlash(n))) {
			return false
		}
	}
	return true
}

// copyBlocksDir copies the files of src into a new directory dst (the
// directories 0700, the files 0600); nothing when src has none.
func copyBlocksDir(src, dst string) error {
	files := BlockFiles(src)
	if len(files) == 0 {
		return nil
	}
	made := map[string]bool{}
	mkdir := func(d string) error {
		if made[d] {
			return nil
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		// Every directory from dst down, whatever the umask.
		for cur := d; ; cur = filepath.Dir(cur) {
			if err := os.Chmod(cur, 0o700); err != nil {
				return err
			}
			if cur == dst {
				break
			}
		}
		made[d] = true
		return nil
	}
	for _, n := range files {
		to := filepath.Join(dst, filepath.FromSlash(n))
		if err := mkdir(filepath.Dir(to)); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(src, filepath.FromSlash(n)), to); err != nil {
			return err
		}
	}
	return nil
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
	if isRegular(s.SNMPFile) {
		if err := copyFile(s.SNMPFile, filepath.Join(dir, "snmp.yaml")); err != nil {
			return err
		}
	}
	if err := copySNMPDir(s.SNMPDir, filepath.Join(dir, "snmp")); err != nil {
		return err
	}
	if err := copyBlocksDir(s.BlocksDir, filepath.Join(dir, BlocksName)); err != nil {
		return err
	}
	if err := s.fillHosts(dir); err != nil {
		return err
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
		mode := os.FileMode(0o600)
		if e.IsDir() {
			mode = 0o700
		}
		if err := os.Chmod(filepath.Join(dir, e.Name()), mode); err != nil {
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
