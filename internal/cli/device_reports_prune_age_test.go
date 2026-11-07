package cli

import (
	"strings"
	"testing"
	"time"
)

// The age of 'device reports prune': <n>h, <n>d or <n>w, never zero, never
// anything else.
func TestReportsPruneAge(t *testing.T) {
	const day = 24 * time.Hour
	for in, want := range map[string]time.Duration{
		"1h": time.Hour, "36h": 36 * time.Hour, "1d": day, "30d": 30 * day, "2w": 14 * day,
		"007d": 7 * day, "1w": 7 * day,
	} {
		if got, err := parseReportAge(in); err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", in, got, err, want)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"", "a whole number and one unit"},
		{"d", "a whole number and one unit"},
		{"7", "a whole number and one unit"},
		{"30", "a whole number and one unit"},
		{"7D", "a whole number and one unit"},
		{"7m", "a whole number and one unit"},
		{"7y", "a whole number and one unit"},
		{"7s", "a whole number and one unit"},
		{"7 d", "a whole number and one unit"},
		{" 7d", "a whole number and one unit"},
		{"7d ", "a whole number and one unit"},
		{"-7d", "a whole number and one unit"},
		{"+7d", "a whole number and one unit"},
		{"1.5d", "a whole number and one unit"},
		{"7dd", "a whole number and one unit"},
		{"7d7h", "a whole number and one unit"},
		{"0x10d", "a whole number and one unit"},
		{"1e3h", "a whole number and one unit"},
		{"0h", "more than zero"},
		{"0d", "more than zero"},
		{"000w", "more than zero"},
		{"9223372036854775807h", "too large"},
		{"99999999999999999999999h", "too large"},
		{"2562048h", "too large"}, // one hour over the longest time.Duration
		{"106752d", "too large"},
		{"15251w", "too large"},
		{"13000000d", "too large"},
		{"2000000w", "too large"},
	} {
		got, err := parseReportAge(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, %v; want an error with %q", c.in, got, err, c.want)
		}
	}
	// the longest ages that fit
	for _, in := range []string{"2562047h", "106751d", "15250w"} {
		if _, err := parseReportAge(in); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}
