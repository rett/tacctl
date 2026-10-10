package devconf

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The derivation of D113 (docs/plans/0.2.5-plan.md): a test per row of
// SyntaxRows, the lines no row maps (never guessed), and the lines the lab's
// images answer.
func TestDeriveSyntaxRows(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		// The rows.
		{"IOS 12.4 (the lab router, an emulated 7200)", "Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 12.4(15)T14, RELEASE SOFTWARE (fc2)", SyntaxIOS12},
		{"IOS 12.2 train", "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE12, RELEASE SOFTWARE (fc1)", SyntaxIOS12},
		{"an ITP image of the 12.4 train", "Cisco IOS Software, 7200 Software (C7200-ITPK9-M), Version 12.4(15)SW4, RELEASE SOFTWARE", SyntaxIOS12},
		{"IOS 12.4(15)SW4 in the older shape", "IOS (tm) 2800 Software (C2800NM-ITPK9-M), Version 12.4(15)SW4", SyntaxIOS12},
		{"IOS 15.x (IOSv 15.6(2)T)", "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)", SyntaxModern},
		{"IOS 15.2", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.2(4)M, RELEASE SOFTWARE", SyntaxModern},
		{"IOS 16.x", "Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 16.12.4, RELEASE SOFTWARE (fc5)", SyntaxModern},
		{"IOS 16.7.1", "Cisco IOS Software, Version 16.7.1", SyntaxModern},
		{"IOS 17.x", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)", SyntaxModern},
		{"IOS 17.3.4", "Cisco IOS Software, Version 17.3.4", SyntaxModern},
		{"IOS-XE, spelled with a hyphen", "Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M), Version 03.04.00.SG", SyntaxModern},
		{"IOS XE, spelled with a space (CSR1000v 16.7.1)", "Cisco IOS XE Software, Version 16.07.01", SyntaxModern},
		// A line the table does not map is unknown, never modern.
		{"IOS 15.0 is not verified", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.0(1)M, RELEASE SOFTWARE", ""},
		{"IOS 15.1(4)M is not verified", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.1(4)M, RELEASE SOFTWARE", ""},
		{"IOS 11.3", "IOS (tm) 4500 Software (C4500-J-M), Version 11.3(11b)T1, RELEASE SOFTWARE (fc1)", ""},
		{"an ASA registered as cisco", "Cisco Adaptive Security Appliance Software Version 9.8(4)", ""},
		{"an ASA of a 12 series number", "Cisco Adaptive Security Appliance Software Version 9.12(4)", ""},
		{"IOS XR", "Cisco IOS XR Software, Version 6.1.3[Default]", ""},
		{"IOS XR with a 12 in it", "Cisco IOS XR Software, Version 12.1.3", ""},
		{"NX-OS", "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(5)", ""},
		{"an image that names no known train", "Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 3.16.0S, RELEASE SOFTWARE", ""},
		{"not a Cisco line at all", "Some other OS Version 9.1", ""},
		{"a version that merely starts with the same numerals", "Cisco IOS Software, Version 120.1", ""},
		{"a line with no image", "ROM: System Bootstrap", ""},
	}
	for _, tc := range cases {
		if got := DeriveSyntax(tc.line); got != tc.want {
			t.Errorf("%s: DeriveSyntax = %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, l := range []string{"", "   "} {
		if s := DeriveSyntax(l); s != "" {
			t.Errorf("blank line %q: %q", l, s)
		}
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
		if r.Syntax != "" && r.Syntax != SyntaxIOS12 && r.Syntax != SyntaxModern {
			t.Errorf("row %q has syntax %q", r.Name, r.Syntax)
		}
		if !decided[r.Name] {
			t.Errorf("no test line is decided by the row %q", r.Name)
		}
	}
}

func TestVersionLine(t *testing.T) {
	const ios = "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)"
	const asa = "Cisco Adaptive Security Appliance Software Version 9.8(4)"
	for _, tc := range []struct{ name, out, want string }{
		{"the image line", ios + "\nROM: Bootstrap program is IOSv\n", ios},
		{"the image line after a ROM line", "ROM: System Bootstrap, Version 12.4(13r)T\n" + ios + "\n", ios},
		{"the image line after ROM and BOOTLDR lines", "ROM: System Bootstrap, Version 12.4(13r)T\nBOOTLDR: 7200 Software, Version 12.2(44)SE\n" + ios + "\n", ios},
		{"the echo and an error", "show version | include Version\n% Invalid input detected at '^' marker.\n", ""},
		{"an unknown command", "% Unknown command: show version | include Version\n", ""},
		{"nothing", "", ""},
		{"a ROM line alone is no image line", "ROM: System Bootstrap, Version 12.4(13r)T\n", ""},
		{"ROM and BOOTLDR lines are no image line", "ROM: System Bootstrap, Version 12.4(13r)T\nBOOTLDR: ... Version 12.2(44)SE\n", ""},
		{"the loader lines in any case", "rom: system bootstrap, version 12.4(13r)t\nBootLdr: 7200 Software, Version 12.2(44)SE\n", ""},
		{"a bootstrap line without its prefix", "System Bootstrap, Version 12.4(13r)T, RELEASE SOFTWARE (fc1)\n", ""},
		{"an ASA is an image line", asa + "\n", asa},
		{"a line with Version and no image", "Hardware Version 3\n", ""},
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

func TestImageVersion(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 12.4(15)SW4, RELEASE SOFTWARE (fc2)", "12.4(15)SW4"},
		{"Cisco IOS XE Software, Version 16.07.01", "16.07.01"},
		{"Cisco IOS Software, Version 15.6(2)T", "15.6(2)T"},
		{"no number", ""},
	} {
		if got := ImageVersion(tc.line); got != tc.want {
			t.Errorf("ImageVersion(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestResolveSyntax(t *testing.T) {
	good := &Record{Vendor: "cisco", Result: ResultOK, OS: "Cisco IOS Software, Version 12.4(15)T14", Syntax: SyntaxIOS12}
	// A record written by a build that guessed: the line says nothing the
	// table knows, so the stored 'modern' is not believed.
	guessed := &Record{Vendor: "cisco", Result: ResultOK, OS: "Some image Version 9", Syntax: SyntaxModern}
	old := &Record{Vendor: "cisco", Result: ResultOK, Sections: map[string]SectionRecord{"aaa": {State: "ok"}}}
	modernRec := &Record{Vendor: "cisco", Result: ResultOK, OS: "Cisco IOS Software, Version 15.6(2)T", Syntax: SyntaxModern}
	for _, tc := range []struct {
		name, setting string
		rec           *Record
		want          SyntaxResolution
	}{
		{"setting ios12 wins over a modern record", SyntaxIOS12, modernRec, SyntaxResolution{SyntaxIOS12, "setting", true, SyntaxModern}},
		{"setting modern wins over an ios12 record, and says so", SyntaxModern, good, SyntaxResolution{SyntaxModern, "setting", true, SyntaxIOS12}},
		{"setting agrees with the record", SyntaxIOS12, good, SyntaxResolution{Syntax: SyntaxIOS12, Source: "setting", ImageSyntax: SyntaxIOS12}},
		{"setting with a record that kept no line", SyntaxIOS12, &Record{Syntax: SyntaxModern}, SyntaxResolution{Syntax: SyntaxIOS12, Source: "setting"}},
		{"setting with a line the table does not map", SyntaxModern, guessed, SyntaxResolution{Syntax: SyntaxModern, Source: "setting"}},
		{"setting with no record", SyntaxModern, nil, SyntaxResolution{Syntax: SyntaxModern, Source: "setting"}},
		{"auto takes the record", SyntaxAuto, good, SyntaxResolution{Syntax: SyntaxIOS12, Source: "pull"}},
		{"empty is auto", "", good, SyntaxResolution{Syntax: SyntaxIOS12, Source: "pull"}},
		{"a record of a guessing build says nothing", "", guessed, SyntaxResolution{}},
		{"a record of 0.2.4 says nothing", "", old, SyntaxResolution{}},
		{"no record says nothing", "", nil, SyntaxResolution{}},
		{"an unknown setting is auto", "ios15", good, SyntaxResolution{Syntax: SyntaxIOS12, Source: "pull"}},
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
// syntax it had), else, when it answered none, the record's; nothing else
// says "". A line the table does not map is unknown, never modern and never
// the record's.
func TestSyntaxFromRead(t *testing.T) {
	rec := &Record{Syntax: SyntaxIOS12, OS: "Cisco IOS Software, Version 12.4(15)T14"}
	for _, tc := range []struct {
		name, setting, os string
		old               *Record
		want              string
	}{
		{"the setting", SyntaxModern, "Cisco IOS Software, Version 12.4(15)T14", rec, SyntaxModern},
		{"the line it answered", "", "Cisco IOS Software, Version 15.6(2)T", rec, SyntaxModern},
		{"a line the table does not map", "", "Some image Version 9", nil, ""},
		{"an ASA line is not the record's either", "", "Cisco Adaptive Security Appliance Software Version 9.8(4)", rec, ""},
		{"IOS 15.1 needs the setting", "", "Cisco IOS Software, Version 15.1(4)M", rec, ""},
		{"no line: the record's", "", "", rec, SyntaxIOS12},
		{"no line and no record", "", "", &Record{}, ""},
		{"no line, no record, a nil one", "", "", nil, ""},
	} {
		if got := SyntaxFromRead(tc.setting, tc.os, tc.old); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestConflictOf(t *testing.T) {
	const v12 = "Cisco IOS Software, Version 12.4(15)T14"
	for _, tc := range []struct {
		name, setting, os string
		want              string
		conflict          bool
	}{
		{"modern on a 12.x image", SyntaxModern, v12, SyntaxIOS12, true},
		{"ios12 on a 15.6 image", SyntaxIOS12, "Cisco IOS Software, Version 15.6(2)T", SyntaxModern, true},
		{"agreeing", SyntaxIOS12, v12, SyntaxIOS12, false},
		{"auto has nothing to contradict", SyntaxAuto, v12, "", false},
		{"an image the table does not map", SyntaxModern, "Cisco IOS Software, Version 15.1(4)M", "", false},
		{"no line", SyntaxModern, "", "", false},
	} {
		got, c := ConflictOf(tc.setting, tc.os)
		if got != tc.want || c != tc.conflict {
			t.Errorf("%s: %q %v, want %q %v", tc.name, got, c, tc.want, tc.conflict)
		}
	}
}

func TestNeedsSyntaxAndWithSyntax(t *testing.T) {
	sec := map[string]SectionRecord{"aaa": {State: "ok"}}
	old := &Record{Vendor: "cisco", Result: ResultOK, Sections: sec}
	known := &Record{Vendor: "cisco", Result: ResultOK, Sections: sec, Syntax: SyntaxModern, OS: "x Software, Version 15.6"}
	unmapped := &Record{Vendor: "cisco", Result: ResultOK, Sections: sec, Syntax: SyntaxModern, OS: "x Version 11.3"}
	for _, tc := range []struct {
		name    string
		rec     *Record
		setting string
		want    bool
	}{
		{"a record of 0.2.4", old, "", true},
		{"a record of 0.2.4 under auto", old, SyntaxAuto, true},
		{"a record with a syntax", known, "", false},
		{"a record whose line the table does not map", unmapped, "", true},
		{"a setting settles it", old, SyntaxIOS12, false},
		{"a setting settles an unmapped line", unmapped, SyntaxModern, false},
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
	// A boot-ROM line alone is no version line (it names the loader).
	f = &fakeRunner{out: map[string]string{VersionCommand: "ROM: System Bootstrap, Version 12.4(13r)T\r\nBOOTLDR: 7200 Software, Version 12.2(44)SE\r\n", "show running-config": "version 15.6\n"}}
	if _, version, err = read(ctx, f); err != nil || version != "" {
		t.Errorf("ROM and BOOTLDR lines: %q %v", version, err)
	}
	// Junos has no such command.
	jread, _ := ReaderWithVersion("junos")
	jf := &fakeRunner{out: map[string]string{"show configuration | display inheritance no-comments | display set": "set a b\n"}}
	if _, version, err := jread(ctx, jf); err != nil || version != "" || len(jf.ran) != 1 {
		t.Errorf("junos: %q %v %q", version, err, jf.ran)
	}
}
