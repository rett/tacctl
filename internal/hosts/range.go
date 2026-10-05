package hosts

// The range tacctl gives out Linux UIDs (and the matching primary GIDs)
// from, one per server: tacctl.yaml's linux.uid_min and linux.uid_max,
// DefaultRange when they are not set. tacctl never gives out a number
// outside it, and the client script never touches an account whose UID is
// outside it (or, once, outside a range the server used before: those
// accounts are renumbered into it).

import (
	"strconv"
	"strings"
)

// Range is a range of UIDs, Min..Max inclusive.
type Range struct{ Min, Max int }

// DefaultRange is 80000-89999. It is clear of everything else that hands
// out numbers on a Linux host: above the distributions' useradd range
// (UID_MAX 60000 on Debian/Ubuntu and the RHEL family) and above systemd's
// reserved ones (60001-60513 container UIDs, 61184-65519 DynamicUser,
// 65534/65535), inside the range systemd leaves unused (65536-524287), and
// below the conventional start of /etc/subuid (100000). A host that is an
// unprivileged container whose user namespace maps only 0-65535 cannot
// hold it (CheckIDMap); such a server chooses another range.
var DefaultRange = Range{Min: 80000, Max: 89999}

// LegacyRange is where releases up to 0.2.0 gave out UIDs (from 20000 up,
// inside useradd's default range). A UID file that records no range but
// has entries there was numbered for it, and is renumbered once.
var LegacyRange = Range{Min: 20000, Max: 29999}

// The limits a range must keep (RangeProblem).
const (
	RangeMinUID   = 1000       // below: system accounts
	RangeMaxUID   = 4294967293 // 2^32-3: 4294967294 is (gid_t)-2, 4294967295 is (uid_t)-1
	RangeMinSize  = 1000       // numbers are never reused
	systemdUnused = 524288     // from here up systemd hands out container UIDs
)

// systemdReserved are the numbers systemd hands out or reserves below
// systemdUnused (systemd's UIDS-GIDS.md).
var systemdReserved = []Range{{60001, 60513}, {61184, 65519}, {65534, 65535}}

// useraddRange is the range the distributions' useradd gives out by default.
var useraddRange = Range{1000, 60000}

// String is the range in words ("80000-89999").
func (r Range) String() string { return strconv.Itoa(r.Min) + "-" + strconv.Itoa(r.Max) }

// Size is how many numbers the range holds.
func (r Range) Size() int { return r.Max - r.Min + 1 }

// Has reports whether n is in the range.
func (r Range) Has(n int) bool { return n >= r.Min && n <= r.Max }

// Contains reports whether uid is a decimal number of the range written
// without leading zeros.
func (r Range) Contains(uid string) bool {
	n, ok := uidNumber(uid)
	return ok && r.Has(n)
}

// Overlaps reports whether the two ranges share a number.
func (r Range) Overlaps(o Range) bool { return r.Min <= o.Max && o.Min <= r.Max }

// IsZero reports whether r is the zero Range (no range).
func (r Range) IsZero() bool { return r == Range{} }

// ParseRange reads "<min>-<max>" (decimal numbers); ok is false for
// anything else.
func ParseRange(s string) (Range, bool) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return Range{}, false
	}
	a, okA := uidNumber(lo)
	b, okB := uidNumber(hi)
	if !okA || !okB {
		return Range{}, false
	}
	return Range{a, b}, true
}

// uidNumber is uid as a number when it is decimal digits without a leading
// zero (at most 10).
func uidNumber(uid string) (int, bool) {
	if uid == "" || uid[0] == '0' || strings.Trim(uid, "0123456789") != "" || len(uid) > 10 {
		return 0, false
	}
	n, err := strconv.Atoi(uid)
	return n, err == nil
}

// RangeProblem is why r cannot be tacctl's range ("" when it can): at
// least RangeMinSize numbers, none below RangeMinUID or above
// RangeMaxUID, and none systemd reserves (60001-60513, 61184-65519,
// 65534-65535, 524288 and up).
func RangeProblem(r Range) string {
	switch {
	case r.Min > r.Max:
		return "uid_min must be below uid_max"
	case r.Min < RangeMinUID:
		return "it starts below " + strconv.Itoa(RangeMinUID) + " (system accounts)"
	case r.Max > RangeMaxUID:
		return "it ends above " + strconv.Itoa(RangeMaxUID)
	case r.Size() < RangeMinSize:
		return "it holds " + strconv.Itoa(r.Size()) + " numbers; at least " + strconv.Itoa(RangeMinSize) + " are needed (numbers are never reused)"
	}
	for _, s := range systemdReserved {
		if r.Overlaps(s) {
			return "it overlaps " + s.String() + ", which systemd reserves"
		}
	}
	if r.Max >= systemdUnused {
		return "it reaches " + strconv.Itoa(systemdUnused) + " and up, where systemd gives out container UIDs"
	}
	return ""
}

// RangeWarning is a caution about r ("" for none): it overlaps the range
// local useradd gives out by default, so a local account could take one of
// its numbers unless the hosts' /etc/login.defs keep clear of it.
func RangeWarning(r Range) string {
	if !r.Overlaps(useraddRange) {
		return ""
	}
	return "UID range " + r.String() + " overlaps " + useraddRange.String() + ", where local useradd gives out UIDs by default; every host's /etc/login.defs must keep UID_MIN-UID_MAX clear of it (enroll and sync warn when it does not)."
}
