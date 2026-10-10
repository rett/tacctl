package devconf

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The derivation of D113 (docs/plans/0.2.5-plan.md): a test per row of
// SyntaxRows, the unknown line, and the lines the lab's images answer.
func TestDeriveSyntaxRows(t *testing.T) {
	cases := []struct {
		name, line, want string
		guessed          bool
	}{
		// The rows.
		{"IOS 12.4 (the lab router, an emulated 7200)", "Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 12.4(15)T14, RELEASE SOFTWARE (fc2)", SyntaxIOS12, false},
		{"IOS 12.2 train", "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE12, RELEASE SOFTWARE (fc1)", SyntaxIOS12, false},
		{"IOS 15.x (IOSv 15.6(2)T)", "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)", SyntaxModern, false},
		{"IOS 15.0 (the first of the dialect)", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.0(1)M, RELEASE SOFTWARE", SyntaxModern, false},
		{"IOS 16.x", "Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 16.12.4, RELEASE SOFTWARE (fc5)", SyntaxModern, false},
		{"IOS 17.x", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)", SyntaxModern, false},
		{"IOS-XE, spelled with a hyphen", "Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M), Version 03.04.00.SG", SyntaxModern, false},
		{"IOS XE, spelled with a space (CSR1000v 16.7.1)", "Cisco IOS XE Software, Version 16.07.01", SyntaxModern, false},
		// Anything else is modern with a note.
		{"an image that names no known train", "Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 3.16.0S, RELEASE SOFTWARE", SyntaxModern, true},
		{"not a Cisco line at all", "Some other OS Version 9.1", SyntaxModern, true},
		{"a version that merely starts with the same numerals", "Cisco IOS Software, Version 120.1", SyntaxModern, true},
	}
	for _, tc := range cases {
		got, guessed := DeriveSyntax(tc.line)
		if got != tc.want || guessed != tc.guessed {
			t.Errorf("%s: DeriveSyntax = %q guessed=%v, want %q guessed=%v", tc.name, got, guessed, tc.want, tc.guessed)
		}
	}
	if s, g := DeriveSyntax(""); s != "" || g {
		t.Errorf("empty line: %q %v", s, g)
	}
	if s, g := DeriveSyntax("   "); s != "" || g {
		t.Errorf("blank line: %q %v", s, g)
	}
	// Every row of the table decides at least one of the lines above: the
	// table is data, and a row nothing exercises is a row nobody checked.
	decided := map[string]bool{}
	for _, tc := range cases {
		for _, r := range SyntaxRows {
			if r.Match.MatchString(tc.line) {
				decided[r.Name] = true
				break
			}
		}
	}
	names := map[string]bool{}
	for _, r := range SyntaxRows {
		if names[r.Name] {
			t.Errorf("two rows are called %q", r.Name)
		}
		names[r.Name] = true
		if r.Syntax != SyntaxIOS12 && r.Syntax != SyntaxModern {
			t.Errorf("row %q has syntax %q", r.Name, r.Syntax)
		}
		if !decided[r.Name] {
			t.Errorf("no test line is decided by the row %q", r.Name)
		}
	}
}

func TestVersionLine(t *testing.T) {
	const ios = "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)"
	for _, tc := range []struct{ name, out, want string }{
		{"the image line", ios + "\nROM: Bootstrap program is IOSv\n", ios},
		{"the image line after a ROM line", "ROM: System Bootstrap, Version 12.4(13r)T\n" + ios + "\n", ios},
		{"the echo and an error", "show version | include Version\n% Invalid input detected at '^' marker.\n", ""},
		{"an unknown command", "% Unknown command: show version | include Version\n", ""},
		{"nothing", "", ""},
		{"a ROM line alone is the first line with Version", "ROM: System Bootstrap, Version 12.4(13r)T\n", "ROM: System Bootstrap, Version 12.4(13r)T"},
		{"indented", "  " + ios + "  \n", ios},
	} {
		if got := VersionLine(tc.out); got != tc.want {
			t.Errorf("%s: VersionLine = %q, want %q", tc.name, got, tc.want)
		}
	}
	// Bounded, and no control character survives into the record.
	long := "Cisco IOS Software, Version 15.6" + strings.Repeat("x", 500)
	if got := VersionLine(long); len(got) > maxVersionLine {
		t.Errorf("a %d-byte line kept", len(got))
	}
	if got := VersionLine("Cisco IOS Software, Version 15.6\x85(T)"); strings.ContainsRune(got, 0x85) {
		t.Errorf("a C1 control kept: %q", got)
	}
}

func TestResolveSyntax(t *testing.T) {
	good := &Record{Vendor: "cisco", Result: ResultOK, OS: "Cisco IOS Software, Version 12.4(15)T14", Syntax: SyntaxIOS12}
	guessed := &Record{Vendor: "cisco", Result: ResultOK, OS: "Some image Version 9", Syntax: SyntaxModern}
	old := &Record{Vendor: "cisco", Result: ResultOK, Sections: map[string]SectionRecord{"aaa": {State: "ok"}}}
	for _, tc := range []struct {
		name, setting string
		rec           *Record
		want          SyntaxResolution
	}{
		{"setting ios12 wins over a modern record", SyntaxIOS12, &Record{Syntax: SyntaxModern}, SyntaxResolution{SyntaxIOS12, "setting", false}},
		{"setting modern wins over an ios12 record", SyntaxModern, good, SyntaxResolution{SyntaxModern, "setting", false}},
		{"auto takes the record", SyntaxAuto, good, SyntaxResolution{SyntaxIOS12, "pull", false}},
		{"empty is auto", "", good, SyntaxResolution{SyntaxIOS12, "pull", false}},
		{"a guessed record says so", "", guessed, SyntaxResolution{SyntaxModern, "pull", true}},
		{"a record of 0.2.4 says nothing", "", old, SyntaxResolution{}},
		{"no record says nothing", "", nil, SyntaxResolution{}},
		{"an unknown setting is auto", "ios15", good, SyntaxResolution{SyntaxIOS12, "pull", false}},
	} {
		if got := ResolveSyntax(tc.setting, tc.rec); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
		if got := Syntax(tc.setting, tc.rec); got != tc.want.Syntax {
			t.Errorf("%s: Syntax = %q", tc.name, got)
		}
	}
}

// The pull compares in the syntax the device is in now: the setting, else
// the line it just answered (an upgraded device is not compared in the
// syntax it had), else the record's; nothing else says "".
func TestSyntaxFromRead(t *testing.T) {
	rec := &Record{Syntax: SyntaxIOS12, OS: "Cisco IOS Software, Version 12.4(15)T14"}
	for _, tc := range []struct {
		name, setting, os string
		old               *Record
		want              string
		guessed           bool
	}{
		{"the setting", SyntaxModern, "Cisco IOS Software, Version 12.4(15)T14", rec, SyntaxModern, false},
		{"the line it answered", "", "Cisco IOS Software, Version 15.6(2)T", rec, SyntaxModern, false},
		{"a guessed line", "", "Some image Version 9", nil, SyntaxModern, true},
		{"no line: the record's", "", "", rec, SyntaxIOS12, false},
		{"no line and no record", "", "", &Record{}, "", false},
		{"no line, no record, a nil one", "", "", nil, "", false},
	} {
		got, guessed := SyntaxFromRead(tc.setting, tc.os, tc.old)
		if got != tc.want || guessed != tc.guessed {
			t.Errorf("%s: %q %v, want %q %v", tc.name, got, guessed, tc.want, tc.guessed)
		}
	}
}

func TestNeedsSyntaxAndWithSyntax(t *testing.T) {
	sec := map[string]SectionRecord{"aaa": {State: "ok"}}
	old := &Record{Vendor: "cisco", Result: ResultOK, Sections: sec}
	known := &Record{Vendor: "cisco", Result: ResultOK, Sections: sec, Syntax: SyntaxModern, OS: "x Version 15.1"}
	for _, tc := range []struct {
		name    string
		rec     *Record
		setting string
		want    bool
	}{
		{"a record of 0.2.4", old, "", true},
		{"a record of 0.2.4 under auto", old, SyntaxAuto, true},
		{"a record with a syntax", known, "", false},
		{"a setting settles it", old, SyntaxIOS12, false},
		{"no record is never, not pull", nil, "", false},
		{"a failed pull is failed, not pull", &Record{Vendor: "cisco", Result: ResultTimeout, Sections: sec}, "", false},
		{"no sections is never", &Record{Vendor: "cisco", Result: ResultOK}, "", false},
		{"Junos has no syntax", &Record{Vendor: "juniper", Result: ResultOK, Sections: sec}, "", false},
	} {
		if got := NeedsSyntax(tc.rec, tc.setting); got != tc.want {
			t.Errorf("%s: NeedsSyntax = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := WithSyntax(StaleOK, old, "", true); got != StalePull {
		t.Errorf("ok -> %q", got)
	}
	if got := WithSyntax(StaleDiffers, old, "", true); got != StalePull {
		t.Errorf("differs -> %q", got)
	}
	if got := WithSyntax(StaleOK, old, "", false); got != StaleOK {
		t.Errorf("a scope the syntax does not matter for: %q", got)
	}
	for _, st := range []Staleness{StaleNever, StaleFailed, StalePull} {
		if got := WithSyntax(st, old, "", true); got != st {
			t.Errorf("%q -> %q", st, got)
		}
	}
	if !StalePull.IsStale() {
		t.Error("pull is not stale: --stale would not select it")
	}
}

// A Cisco read keeps the version line, and a device that refuses the command
// is read all the same (the record then has no syntax).
func TestReaderWithVersion(t *testing.T) {
	ctx := context.Background()
	const ios = "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)"
	read, err := ReaderWithVersion("cisco")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{out: map[string]string{VersionCommand: ios + "\r\n", "show running-config": "version 15.6\n"}}
	text, version, err := read(ctx, f)
	if err != nil || version != ios || !strings.HasPrefix(text, "version 15.6") ||
		!slices.Equal(f.ran, []string{"terminal length 0", VersionCommand, "show running-config"}) {
		t.Errorf("%q %q %v %q", text, version, err, f.ran)
	}
	f = &fakeRunner{out: map[string]string{VersionCommand: "% Unknown command: " + VersionCommand + "\n", "show running-config": "version 15.6\n"}}
	text, version, err = read(ctx, f)
	if err != nil || version != "" || !strings.HasPrefix(text, "version 15.6") {
		t.Errorf("a device that refuses it: %q %q %v", text, version, err)
	}
	// Junos has no such command.
	jread, _ := ReaderWithVersion("junos")
	jf := &fakeRunner{out: map[string]string{"show configuration | display inheritance no-comments | display set": "set a b\n"}}
	if _, version, err := jread(ctx, jf); err != nil || version != "" || len(jf.ran) != 1 {
		t.Errorf("junos: %q %v %q", version, err, jf.ran)
	}
}
