package hosts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UIDs is the UID file (LINUX_UID_FILE): one "name:uid" line per user ever
// sent to a host. A number is allocated once, from UIDBase..UIDMax, after
// the highest one given so far (never into a gap), and never reused, not
// even when the user is removed; it is the user's UID and primary GID on
// every host. Entries of the legacy range are renumbered once
// (RenumberLegacy); entries outside the range (set by hand) are
// reported, never sent to a host.
type UIDs struct{ Path string }

// Touch is 'touch "$LINUX_UID_FILE"': the file is created (0600) when it is
// missing, and its times are set to now either way. 'config linux uid' does
// it only before a change; a read leaves the file alone.
func (u UIDs) Touch() error {
	f, err := os.OpenFile(u.Path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(u.Path, now, now)
}

func (u UIDs) records() ([]string, error) {
	data, err := os.ReadFile(u.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return awkRecords(string(data)), nil
}

// Lookup is "awk -F: -v u=<name> '$1 == u { print $2; exit }'": the number
// of the first line for name ("" when there is none).
func (u UIDs) Lookup(name string) (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	for _, r := range recs {
		f := awkFields(r, ":")
		if awkEqual(awkField(f, 1), name) {
			return awkField(f, 2), nil
		}
	}
	return "", nil
}

// Holder is "awk -F: -v id=<uid> '$2 == id { print $1; exit }'": the name
// on the first line with that number ("" when none).
func (u UIDs) Holder(uid string) (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	for _, r := range recs {
		f := awkFields(r, ":")
		if awkEqual(awkField(f, 2), uid) {
			return awkField(f, 1), nil
		}
	}
	return "", nil
}

// ErrUIDRangeFull is an allocation past UIDMax: every number of the
// range has been given out (numbers are never reused).
var ErrUIDRangeFull = errors.New("hosts: the UID range " + UIDRange + " is used up")

// next is the number after the highest one of the range in the file,
// UIDBase when there is none; never into a gap. Entries outside the range
// (set by hand before 0.2.1) are not counted. Past UIDMax it is
// ErrUIDRangeFull.
func (u UIDs) next() (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	m := UIDBase - 1
	for _, r := range recs {
		v := awkField(awkFields(r, ":"), 2)
		if !UIDInRange(v) {
			continue
		}
		if n, _ := strconv.Atoi(v); n > m {
			m = n
		}
	}
	if m+1 > UIDMax {
		return "", ErrUIDRangeFull
	}
	return strconv.Itoa(m + 1), nil
}

// For is linux_uid_for: the user's number, allocated (and appended to the
// file) the first time; ErrUIDRangeFull when there is none left.
func (u UIDs) For(name string) (string, error) {
	if err := u.Touch(); err != nil {
		return "", err
	}
	uid, err := u.Lookup(name)
	if err != nil || uid != "" {
		return uid, err
	}
	if uid, err = u.next(); err != nil {
		return "", err
	}
	f, err := os.OpenFile(u.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(name + ":" + uid + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	return uid, f.Close()
}

// Assign is the write of 'config linux uid <name> <uid>': every line of
// name dropped, "name:uid" appended, the file replaced with mode 0600.
func (u UIDs) Assign(name, uid string) error {
	recs, err := u.records()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, r := range recs {
		if !awkEqual(awkField(awkFields(r, ":"), 1), name) {
			b.WriteString(r + "\n")
		}
	}
	b.WriteString(name + ":" + uid + "\n")
	return replaceFile(u.Path, []byte(b.String()), 0o600)
}

// Listing is the body of 'config linux uid' with no user:
// "sort -t: -k2 -n | awk -F: '{ printf "  %-24s %s\n", $1, $2 }'", an
// entry outside the range (from before 0.2.1) marked as not used on hosts.
func (u UIDs) Listing() (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	sorted := append([]string(nil), recs...)
	key := func(r string) float64 {
		_, rest, _ := strings.Cut(r, ":")
		return sortNumber(rest)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		ki, kj := key(sorted[i]), key(sorted[j])
		if ki != kj {
			return ki < kj
		}
		return sorted[i] < sorted[j]
	})
	var b strings.Builder
	for _, r := range sorted {
		f := awkFields(r, ":")
		b.WriteString("  " + padRight(awkField(f, 1), 24) + " " + awkField(f, 2))
		if !UIDInRange(awkField(f, 2)) {
			b.WriteString("   outside " + UIDRange + ": not used on hosts")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// sortNumber is the numeric key of 'sort -n': leading blanks, an optional
// minus, digits and a decimal part; anything else is 0.
func sortNumber(s string) float64 {
	t := strings.TrimLeft(s, " \t")
	end := 0
	if end < len(t) && t[end] == '-' {
		end++
	}
	digits := end
	for end < len(t) && t[end] >= '0' && t[end] <= '9' {
		end++
	}
	if end < len(t) && t[end] == '.' {
		end++
		for end < len(t) && t[end] >= '0' && t[end] <= '9' {
			end++
		}
	}
	if end == digits {
		return 0
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(t[:end], "."), 64)
	if err != nil {
		return 0
	}
	return f
}

// padRight is printf's %-<n>s for ASCII text.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// UIDCollision is a renumbering RenumberLegacy refuses: the number a legacy
// entry would become is already another name's.
type UIDCollision struct {
	Name, Old, New, Holder string
}

func (c *UIDCollision) Error() string {
	return "hosts: " + c.Name + ":" + c.Old + " would become " + c.New + ", which is " + c.Holder + "'s"
}

// RenumberLegacy rewrites every entry of LegacyUIDBase..LegacyUIDMax to
// Renumbered (the same offset in UIDBase..UIDMax), users and removed users
// alike, and returns how many it rewrote. Before anything is written the old
// file is copied to backup (0600); the new one replaces it by a rename, so
// the file is never seen half written. Nothing to renumber (a missing file,
// a second call) changes nothing and makes no copy. A number another name
// already has (a line not being renumbered) is a *UIDCollision, and nothing
// is changed. Lines are otherwise kept as they are, in order.
func (u UIDs) RenumberLegacy(backup string) (int, error) {
	data, err := os.ReadFile(u.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	recs := awkRecords(string(data))
	held := map[string]string{} // number -> name, of the lines that stay
	for _, r := range recs {
		f := awkFields(r, ":")
		if v := awkField(f, 2); !LegacyUID(v) {
			if _, ok := held[v]; !ok {
				held[v] = awkField(f, 1)
			}
		}
	}
	n := 0
	out := make([]string, len(recs))
	for i, r := range recs {
		f := awkFields(r, ":")
		out[i] = r
		old := awkField(f, 2)
		if !LegacyUID(old) {
			continue
		}
		o, _ := strconv.Atoi(old)
		nu := strconv.Itoa(Renumbered(o))
		if h, ok := held[nu]; ok && h != awkField(f, 1) {
			return 0, &UIDCollision{Name: awkField(f, 1), Old: old, New: nu, Holder: h}
		}
		f[1] = nu
		out[i] = strings.Join(f, ":")
		n++
	}
	if n == 0 {
		return 0, nil
	}
	if err := writeAtomic(backup, data, 0o600); err != nil {
		return 0, err
	}
	return n, writeAtomic(u.Path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

// writeAtomic writes data to a new file next to path and renames it over
// path: a reader sees the old content or the new, never a part.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
