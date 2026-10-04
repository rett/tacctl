package hosts

import (
	"errors"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UIDs is the UID file (LINUX_UID_FILE): one "name:uid" line per user ever
// sent to a host. A number is allocated once, after the highest one given
// so far (never into a gap), and never reused; it is the user's UID and
// primary GID on every host.
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

// next is the number after the highest one in the file, UIDBase at least
// ("BEGIN { m = base - 1 } $2 > m { m = $2 } END { print m + 1 }").
func (u UIDs) next() (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	m, mStr, mIsNum := float64(UIDBase-1), "", true
	for _, r := range recs {
		v := awkField(awkFields(r, ":"), 2)
		n, isNum := awkNumber(v)
		var greater bool
		if isNum && mIsNum {
			greater = n > m
		} else {
			cur := mStr
			if mIsNum {
				cur = awkString(m)
			}
			greater = v > cur
		}
		if greater {
			if isNum {
				m, mIsNum = n, true
			} else {
				mStr, mIsNum = v, false
			}
		}
	}
	if !mIsNum {
		m = awkPrefixNumber(mStr)
	}
	return awkString(m + 1), nil
}

// For is linux_uid_for: the user's number, allocated (and appended to the
// file) the first time.
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
// "sort -t: -k2 -n | awk -F: '{ printf "  %-24s %s\n", $1, $2 }'".
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
		b.WriteString("  " + padRight(awkField(f, 1), 24) + " " + awkField(f, 2) + "\n")
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
