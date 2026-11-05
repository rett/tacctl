package backend

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var logNow = time.Date(2026, 11, 4, 12, 30, 45, 0, time.Local)

func at(y int, mo time.Month, d, h, mi, s int) time.Time {
	return time.Date(y, mo, d, h, mi, s, 0, time.Local)
}

func TestParseLogTime(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Time
	}{
		{"2026-11-03", at(2026, 11, 3, 0, 0, 0)},
		{"2026-11-03 09:15", at(2026, 11, 3, 9, 15, 0)},
		{"2026-11-03 09:15:30", at(2026, 11, 3, 9, 15, 30)},
		{"2026-11-03T09:15:30", at(2026, 11, 3, 9, 15, 30)},
		{"  2026-11-03 09:15  ", at(2026, 11, 3, 9, 15, 0)},
		{"now", logNow},
		{"today", at(2026, 11, 4, 0, 0, 0)},
		{"Yesterday", at(2026, 11, 3, 0, 0, 0)},
		{"-1h", at(2026, 11, 4, 11, 30, 45)},
		{"-30m", at(2026, 11, 4, 12, 0, 45)},
		{"-90s", at(2026, 11, 4, 12, 29, 15)},
		{"-2d", at(2026, 11, 2, 12, 30, 45)},
		{"-1w", at(2026, 10, 28, 12, 30, 45)},
		{"- 2 hours", at(2026, 11, 4, 10, 30, 45)},
		{"2 hours ago", at(2026, 11, 4, 10, 30, 45)},
		{"1 hour ago", at(2026, 11, 4, 11, 30, 45)},
		{"10 minutes ago", at(2026, 11, 4, 12, 20, 45)},
		{"3days ago", at(2026, 11, 1, 12, 30, 45)},
		{"2 weeks ago", at(2026, 10, 21, 12, 30, 45)},
		{"30 sec ago", at(2026, 11, 4, 12, 30, 15)},
	} {
		got, err := ParseLogTime(c.in, logNow)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%q: %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{
		"", "tomorrow", "next week", "1h", "+1h", "-h", "-1", "-1 fortnight", "ago", "2 hours", "2026-13-01", "2026-11-03 25:00",
		"11/03/2026", "2026-11-03 09", "@1793000000", "12:30", "-1h ago", "-9999999h",
	} {
		if got, err := ParseLogTime(in, logNow); err == nil {
			t.Errorf("%q was taken: %v", in, got)
		} else if !strings.Contains(err.Error(), "invalid time") || !strings.Contains(err.Error(), LogTimeForms) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestLogFilterWindow(t *testing.T) {
	var none LogFilter
	if none.Active() || none.HasWindow() || !none.InWindow(time.Time{}) || none.Window() != "" {
		t.Fatal("the zero filter filters")
	}
	f := LogFilter{Since: at(2026, 11, 4, 10, 0, 0), Until: at(2026, 11, 4, 11, 0, 0)}
	for tm, want := range map[time.Time]bool{
		at(2026, 11, 4, 9, 59, 59):  false,
		at(2026, 11, 4, 10, 0, 0):   true,
		at(2026, 11, 4, 10, 30, 0):  true,
		at(2026, 11, 4, 11, 0, 0):   true,
		at(2026, 11, 4, 11, 0, 1):   false,
		{}:                          false,
		at(2026, 11, 3, 10, 30, 0):  false,
		at(2026, 11, 5, 10, 30, 0):  false,
		at(2026, 11, 4, 10, 59, 59): true,
	} {
		if got := f.InWindow(tm); got != want {
			t.Errorf("%v: %v", tm, got)
		}
	}
	if got := f.Window(); got != "from 2026-11-04 10:00:00 to 2026-11-04 11:00:00" {
		t.Error(got)
	}
	if got := (LogFilter{Since: f.Since}).Window(); got != "since 2026-11-04 10:00:00" {
		t.Error(got)
	}
	if got := (LogFilter{Until: f.Until}).Window(); got != "until 2026-11-04 11:00:00" {
		t.Error(got)
	}
	if got := f.JournalArgs("24 hours ago"); !reflect.DeepEqual(got, []string{"--since", "2026-11-04 10:00:00", "--until", "2026-11-04 11:00:00"}) {
		t.Error(got)
	}
	if got := (LogFilter{}).JournalArgs("7 days ago"); !reflect.DeepEqual(got, []string{"--since", "7 days ago"}) {
		t.Error(got)
	}
	if got := (LogFilter{}).JournalArgs(""); got != nil {
		t.Error(got)
	}
	// Each of the filters makes it active; --json alone does not.
	for _, a := range []LogFilter{{Since: f.Since}, {Until: f.Until}, {User: "alice"}, {Device: "sw1"}, {Type: TypeLogin}} {
		if !a.Active() {
			t.Errorf("%+v is not active", a)
		}
	}
	if (LogFilter{JSON: true}).Active() {
		t.Error("--json selects entries")
	}
}

func TestLogFilterMatchAddr(t *testing.T) {
	f := LogFilter{Device: "rtr1", Addrs: []string{"2001:db8::1", "192.0.2.10"}}
	for in, want := range map[string]bool{
		"2001:db8::1":          true,
		"2001:DB8:0:0:0:0:0:1": true,
		"[2001:db8::1]":        true,
		"192.0.2.10":           true,
		"::ffff:192.0.2.10":    true,
		"192.0.2.11":           false,
		"unknown":              false,
		"":                     false,
		"sw1":                  false,
		"0.0.0.0":              false,
	} {
		if got := f.MatchAddr(in); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}

func TestLineSinkAndRing(t *testing.T) {
	var got []string
	s := &LineSink{Fn: func(l string) { got = append(got, l) }}
	_, _ = s.Write([]byte("a\nb"))
	_, _ = s.Write([]byte("c\n\nd"))
	s.Flush()
	s.Flush()
	if want := []string{"a", "bc", "", "d"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	for n, want := range map[int][]string{-1: {"a", "b", "c"}, 0: nil, 1: {"c"}, 2: {"b", "c"}, 5: {"a", "b", "c"}} {
		r := &Ring{N: n}
		for _, x := range []string{"a", "b", "c"} {
			r.Add(x)
		}
		if !reflect.DeepEqual(r.Items(), want) {
			t.Errorf("N=%d: %q", n, r.Items())
		}
	}
	for in, want := range map[string]int{"20": 20, "-5": 5, "0": 0} {
		if n, ok := CountArg(in); !ok || n != want {
			t.Errorf("%q: %d %v", in, n, ok)
		}
	}
	for _, in := range []string{"", "x", "+3", "1.5", "-", "99999999999"} {
		if _, ok := CountArg(in); ok {
			t.Errorf("%q is a count", in)
		}
	}
}

func TestJSONLineKeepsAngleBrackets(t *testing.T) {
	out := JSONLine(LogLine{Backend: "tacacs", Message: "a <b> & c"})
	if out != `{"backend":"tacacs","message":"a <b> & c"}`+"\n" {
		t.Fatal(out)
	}
	var back LogLine
	if json.Unmarshal([]byte(out), &back) != nil || back.Message != "a <b> & c" {
		t.Fatal(out)
	}
	if FormatLogTime(time.Time{}) != "" || FormatLogTime(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)) != "2026-11-04T12:00:00Z" {
		t.Fatal("time")
	}
}
