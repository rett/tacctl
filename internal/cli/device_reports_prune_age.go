package cli

// The age of 'device reports prune --older-than <age>' (docs/plans/0.2.26-plan.md
// D333): a whole number and one unit, h (hours), d (days) or w (weeks). There
// is no default and nothing else is read: no zero, no sign, no fraction, no
// space, no other unit.

import (
	"errors"
	"math"
	"strconv"
	"time"
)

// reportAgeUnits are the units of an age and how long each is.
var reportAgeUnits = map[byte]time.Duration{
	'h': time.Hour,
	'd': 24 * time.Hour,
	'w': 7 * 24 * time.Hour,
}

// errReportAge is the refusal of an age that is not <n>h, <n>d or <n>w.
var errReportAge = errors.New("an age is a whole number and one unit: <n>h, <n>d or <n>w (hours, days or weeks), for example 30d")

// parseReportAge is the length of time an age names. It refuses an empty
// age, a number that is not plain digits (a sign, a fraction, a space), zero,
// a unit other than h, d and w, and a number so large that the time would
// overflow.
func parseReportAge(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, errReportAge
	}
	unit, ok := reportAgeUnits[s[len(s)-1]]
	if !ok {
		return 0, errReportAge
	}
	digits := s[:len(s)-1]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, errReportAge
		}
	}
	n, err := strconv.ParseUint(digits, 10, 63)
	if err != nil {
		return 0, errors.New("the age '" + s + "' is too large")
	}
	if n == 0 {
		return 0, errors.New("the age must be more than zero: '" + s + "' would name every report")
	}
	if n > uint64(math.MaxInt64/int64(unit)) {
		return 0, errors.New("the age '" + s + "' is too large")
	}
	return time.Duration(n) * unit, nil
}
