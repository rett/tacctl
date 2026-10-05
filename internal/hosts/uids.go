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
// sent to a host. A number is allocated once, from Range, after the highest
// one given so far (never into a gap), and never reused, not even when the
// user is removed; it is the user's UID and primary GID on every host.
// Entries outside the range (set by hand) are reported, never sent to a
// host.
//
// The file records the range it is numbered for in a first line '# range
// <min>-<max>', and the ranges it was numbered for before, newest last, in
// '# previous <min>-<max> ...'. The record lives in the file it describes,
// so a backup, a restore or a copy of the file to another server carries
// its numbers and their range together, and nothing else has to agree with
// it. When the configured range differs, RenumberTo moves the entries by
// offset; hosts move the accounts tacctl created in a previous range the
// same way (the script's TAC_UID_PREVIOUS). A file with no record was
// numbered by a release that gave out UIDs from 20000 up: LegacyRange when
// it has entries there.
type UIDs struct {
	Path  string
	Range Range // the zero Range is DefaultRange
}

func (u UIDs) rng() Range {
	if u.Range.IsZero() {
		return DefaultRange
	}
	return u.Range
}

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

// records are the entry lines of the file (the '#' lines left out).
func (u UIDs) records() ([]string, error) {
	_, recs, err := u.read()
	return recs, err
}

// read splits the file into its '#' lines and its entry lines.
func (u UIDs) read() (comments, recs []string, err error) {
	data, err := os.ReadFile(u.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, r := range awkRecords(string(data)) {
		if strings.HasPrefix(r, "#") {
			comments = append(comments, r)
		} else {
			recs = append(recs, r)
		}
	}
	return comments, recs, nil
}

// parseRecord reads the range lines of comments: the range the file is
// numbered for (zero when it records none) and the earlier ones.
func parseRecord(comments []string) (cur Range, prev []Range) {
	for _, c := range comments {
		f := strings.Fields(strings.TrimPrefix(c, "#"))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "range":
			if r, ok := ParseRange(f[1]); ok {
				cur = r
			}
		case "previous":
			for _, w := range f[1:] {
				if r, ok := ParseRange(w); ok {
					prev = append(prev, r)
				}
			}
		}
	}
	return cur, prev
}

// recordLines are the '#' lines of a file numbered for cur after prev.
func recordLines(cur Range, prev []Range) []string {
	out := []string{"# range " + cur.String()}
	if len(prev) > 0 {
		words := make([]string, len(prev))
		for i, r := range prev {
			words[i] = r.String()
		}
		out = append(out, "# previous "+strings.Join(words, " "))
	}
	return out
}

// Recorded is the range the file is numbered for and the ones it was
// numbered for before (zero and nil when it records none).
func (u UIDs) Recorded() (Range, []Range, error) {
	comments, _, err := u.read()
	if err != nil {
		return Range{}, nil, err
	}
	cur, prev := parseRecord(comments)
	return cur, prev, nil
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

// ErrUIDRangeFull is an allocation past the range's end: every number of
// the range has been given out (numbers are never reused).
var ErrUIDRangeFull = errors.New("hosts: the UID range is used up")

// next is the number after the highest one of the range in the file, the
// range's first when there is none; never into a gap. Entries outside the
// range are not counted. Past the range it is ErrUIDRangeFull.
func (u UIDs) next() (string, error) {
	recs, err := u.records()
	if err != nil {
		return "", err
	}
	r := u.rng()
	m := r.Min - 1
	for _, rec := range recs {
		v := awkField(awkFields(rec, ":"), 2)
		if !r.Contains(v) {
			continue
		}
		if n, _ := strconv.Atoi(v); n > m {
			m = n
		}
	}
	if m+1 > r.Max {
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
	line := name + ":" + uid + "\n"
	if st, err := os.Stat(u.Path); err == nil && st.Size() == 0 {
		// A new file records its range first.
		line = strings.Join(recordLines(u.rng(), nil), "\n") + "\n" + line
	}
	f, err := os.OpenFile(u.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(line); err != nil {
		_ = f.Close()
		return "", err
	}
	return uid, f.Close()
}

// Assign is the write of 'config linux uid <name> <uid>': every line of
// name dropped, "name:uid" appended, the file replaced with mode 0600.
func (u UIDs) Assign(name, uid string) error {
	comments, recs, err := u.read()
	if err != nil {
		return err
	}
	var b strings.Builder
	if len(comments) == 0 && len(recs) == 0 {
		// A new file records its range first, as For's does.
		comments = recordLines(u.rng(), nil)
	}
	for _, c := range comments {
		b.WriteString(c + "\n")
	}
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
// entry outside the range marked as not used on hosts.
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
		if !u.rng().Contains(awkField(f, 2)) {
			b.WriteString("   outside " + u.rng().String() + ": not used on hosts")
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

// UIDCollision is a renumbering RenumberTo refuses: the number an entry
// would become is already another name's.
type UIDCollision struct {
	Name, Old, New, Holder string
}

func (c *UIDCollision) Error() string {
	return "hosts: " + c.Name + ":" + c.Old + " would become " + c.New + ", which is " + c.Holder + "'s"
}

// RangeTooSmall is a renumbering RenumberTo refuses: the file has an entry
// (Name, at UID) that would land past the new range's end.
type RangeTooSmall struct {
	Name, UID string
	New       int // where it would land
}

func (e *RangeTooSmall) Error() string {
	return "hosts: " + e.Name + ":" + e.UID + " would become " + strconv.Itoa(e.New) + ", past the range"
}

// RangeOverlap is a renumbering RenumberTo refuses: the new range shares
// numbers with a range the file was numbered for (its current one, or an
// earlier one hosts may still have accounts in), so a host could not tell
// a moved account from one that still has to move.
type RangeOverlap struct{ With Range }

func (e *RangeOverlap) Error() string { return "hosts: the range overlaps " + e.With.String() }

// Renumbering is what RenumberTo did (or, dry, would do).
type Renumbering struct {
	From Range // the range the file was numbered for
	N    int   // entries moved
	// Changed: the file was (or would be) rewritten, entries or record.
	Changed bool
}

// unrecorded is the range a file with no record was numbered for:
// LegacyRange when it has entries there (a release up to 0.2.0), else
// DefaultRange when it has entries there and to is another range (the
// range was set in tacctl.yaml before anything recorded one), else to.
func unrecorded(recs []string, to Range) Range {
	in := func(r Range) bool {
		for _, rec := range recs {
			if r.Contains(awkField(awkFields(rec, ":"), 2)) {
				return true
			}
		}
		return false
	}
	switch {
	case in(LegacyRange):
		return LegacyRange
	case to != DefaultRange && in(DefaultRange):
		return DefaultRange
	}
	return to
}

// RenumberTo numbers the file for the range: an entry of the range it was
// numbered for (From: its record; for a file with no record, unrecorded)
// moves by the offset of the two ranges' starts, users and removed users
// alike, and the record names the new range, From joining the earlier ones. The same start (a range grown
// or shrunk) moves nothing. Refused, with nothing changed: a new range
// that overlaps one the file was numbered for (*RangeOverlap; unless the
// start is the same), an entry that would land past its end
// (*RangeTooSmall), and a number that is already another name's
// (*UIDCollision). With entries to move, the old file is first copied to
// backup (0600); the new one replaces it by a rename. A missing file, or
// one already numbered for the range, is left as it is. dry checks and
// reports without writing.
func (u UIDs) RenumberTo(backup string, dry bool) (Renumbering, error) {
	to := u.rng()
	data, err := os.ReadFile(u.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Renumbering{From: to}, nil
	}
	if err != nil {
		return Renumbering{}, err
	}
	comments, recs, _ := u.read()
	from, prev := parseRecord(comments)
	if from.IsZero() {
		from = unrecorded(recs, to)
	}
	res := Renumbering{From: from}
	offset := to.Min - from.Min
	if offset != 0 {
		for _, p := range append([]Range{from}, prev...) {
			if to.Overlaps(p) {
				return res, &RangeOverlap{With: p}
			}
		}
	}
	held := map[string]string{} // number -> name, of the lines that stay
	for _, r := range recs {
		f := awkFields(r, ":")
		if v := awkField(f, 2); !from.Contains(v) {
			if _, ok := held[v]; !ok {
				held[v] = awkField(f, 1)
			}
		}
	}
	out := make([]string, len(recs))
	for i, r := range recs {
		f := awkFields(r, ":")
		out[i] = r
		old := awkField(f, 2)
		if !from.Contains(old) {
			continue
		}
		o, _ := strconv.Atoi(old)
		n := o + offset
		if !to.Has(n) {
			return Renumbering{From: from}, &RangeTooSmall{Name: awkField(f, 1), UID: old, New: n}
		}
		if offset == 0 {
			continue
		}
		nu := strconv.Itoa(n)
		if h, ok := held[nu]; ok && h != awkField(f, 1) {
			return Renumbering{From: from}, &UIDCollision{Name: awkField(f, 1), Old: old, New: nu, Holder: h}
		}
		f[1] = nu
		out[i] = strings.Join(f, ":")
		res.N++
	}
	if offset != 0 {
		prev = append(prev, from)
	}
	record := recordLines(to, prev)
	// Other '#' lines are kept, after the record.
	for _, c := range comments {
		if f := strings.Fields(strings.TrimPrefix(c, "#")); len(f) > 0 && (f[0] == "range" || f[0] == "previous") {
			continue
		}
		record = append(record, c)
	}
	text := strings.Join(append(record, out...), "\n") + "\n"
	if text == string(data) {
		return res, nil
	}
	res.Changed = true
	if dry {
		return res, nil
	}
	if res.N > 0 {
		if err := writeAtomic(backup, data, 0o600); err != nil {
			return Renumbering{}, err
		}
	}
	return res, writeAtomic(u.Path, []byte(text), 0o600)
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
