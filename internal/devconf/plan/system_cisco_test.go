package plan

// 0.2.7: the system block of a scope for an IOS device (the login banner,
// domain name and list, time zone, name servers and NTP) and the trap source
// (IOS and Junos). The section is additive as the Junos one is: a statement
// is set when missing, a single value that differs is replaced in place, and
// what the device holds beside is kept and listed. The banner is never in a
// report, a compared line or a stored section; only the pasted lines hold it.

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// H2: a login banner is text up to its closing delimiter: a line that
// begins with '!' is no comment in it, a blank line is part of it, and no
// label may stand inside.
func TestIOSRegionBannerState(t *testing.T) {
	wrap := func(body ...string) []string {
		return append(append([]string{"configure terminal"}, body...), "end")
	}
	for _, tc := range []struct {
		name  string
		lines []string
		frag  string // "" for a region that is safe
	}{
		{"a banner", wrap("banner login ^", "Authorized use only.", "^"), ""},
		{"a body line that starts with a bang", wrap("banner login ^", "! not a comment", "  !! nor this", "^", "ip domain name lab.example.net"), ""},
		{"a blank body line", wrap("banner login ~", "a", "", "b", "~"), ""},
		{"the delimiter is the last line", wrap("ip domain name lab.example.net", "banner login #", "text", "#"), ""},
		{"a body that looks like a statement", wrap("banner login ^", "aaa new-model", "snmp-server community leak RW", "^"), ""},
		{"a body with a leading blank", wrap("banner login ^", " indented", "^"), ""},
		{"a banner removed", wrap("no banner login"), ""},
		{"not closed before end", wrap("banner login ^", "text"), "is not closed by its delimiter"},
		{"not closed, the last line is a bang line", wrap("banner login ^", "! text"), "is not closed by its delimiter"},
		{"two characters as the delimiter", wrap("banner login ^C", "text", "^C"), "is not 'banner login' and one delimiter character"},
		{"no delimiter", wrap("banner login"), ""}, // 'banner login' alone is the no form's body only
		{"a delimiter and text", wrap("banner login ^hello^"), "is not 'banner login' and one delimiter character"},
		{"a banner of another type", wrap("banner motd ^", "x", "^"), "is not a statement of an owned shape"},
		{"a tab inside", wrap("banner login ^", "a\tb", "^"), "not printable ASCII"},
		{"a statement after the banner is checked", wrap("banner login ^", "a", "^", "hostname x"), "is not a statement of an owned shape"},
		{"the statements of the block", wrap("ip domain name a.example.net", "ip domain list a.example.net", "clock timezone CET 1",
			"ip name-server 192.0.2.53", "ntp authentication-key 5 md5 k", "ntp trusted-key 5", "ntp server 192.0.2.1", "ntp authenticate",
			"snmp-server trap-source Loopback0", "no ntp server 192.0.2.1", "no clock timezone", "no ip domain name"), ""},
	} {
		err := CheckRegion(devconf.FamilyIOS, tc.lines)
		switch {
		case tc.name == "no delimiter":
			// 'banner login' with nothing after it is a prefix shape: the
			// device would ask for a delimiter, which a paste cannot give
			if err == nil {
				t.Errorf("%s: a bare 'banner login' passes", tc.name)
			}
		case tc.frag == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.frag != "" && (err == nil || !strings.Contains(err.Error(), tc.frag)):
			t.Errorf("%s: %v, want %q", tc.name, err, tc.frag)
		}
	}
}

// The IOS system block of the new device: every statement is typed, the NTP
// lines in the order IOS needs, the key by value, and the report holds no word
// of the banner.
func TestIOSSystemNewDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-system-new")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	got := lines(d, "system")
	want := []string{
		"banner login ^\nAuthorized use only.\n! Activity is logged.\n^",
		"ip domain name lab.example.net",
		"ip domain list lab.example.net",
		"clock timezone CET 1",
		"ip name-server 192.0.2.53",
		"ip name-server 192.0.2.54",
		"ntp authentication-key 5 <secret>",
		"ntp trusted-key 5",
		"ntp server 192.0.2.123 version 4 key 5 prefer",
		"ntp server ntp2.example.net",
		"ntp authenticate",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the system lines:\n%q\nwant\n%q", got, want)
	}
	if sp := d.Of("system"); sp.State != StatePlanned || sp.Statements != 14 {
		t.Errorf("system: %s, %d lines", sp.State, sp.Statements)
	}
	// the key is typed by value, and only the plan's own paste holds it
	var key Line
	for _, l := range d.Lines {
		if strings.HasPrefix(l.Text, "ntp authentication-key") {
			key = l
		}
	}
	if !key.HasValue || key.Text != "ntp authentication-key 5 md5 lab-ntp-key-0123" {
		t.Errorf("the key: %+v", key)
	}
	// the banner's text is in the paste and nowhere in the report, the items,
	// the JSON's findings or the stored back-out
	h := f.header()
	report := Report(d, h, Wrapper{})
	for _, s := range []string{"Authorized use only", "Activity is logged", "lab-ntp-key-0123"} {
		if strings.Contains(report, s) {
			t.Errorf("the report holds %q", s)
		}
	}
	for _, it := range d.Items {
		if strings.Contains(it.Words+it.Statement+it.Action, "Authorized") {
			t.Errorf("an item holds the banner: %+v", it)
		}
	}
	if !strings.Contains(Region(d, h, Wrapper{}), "banner login ^\nAuthorized use only.\n! Activity is logged.\n^\n") {
		t.Errorf("the region lacks the banner:\n%s", Region(d, h, Wrapper{}))
	}
	// the paste is one run of the section under one label, the banner whole
	region := RegionLines(d, h, Wrapper{})
	var texts []string
	for _, rl := range region {
		texts = append(texts, rl.Text)
	}
	if err := CheckRegion(devconf.FamilyIOS, texts); err != nil {
		t.Errorf("the region: %v", err)
	}
	// the back-out takes every statement away as the device takes it, the
	// banner by 'no banner login', the key by its number
	bo := iosBackout(d)
	var undo []string
	for _, l := range bo {
		undo = append(undo, l.Text)
	}
	for _, w := range []string{"banner login", "ip domain name", "clock timezone", "ntp authenticate", "ntp trusted-key 5",
		"ntp server 192.0.2.123", "ntp server ntp2.example.net", "ntp authentication-key 5", "ip name-server 192.0.2.53",
		"ip domain list lab.example.net", "snmp-server trap-source"} {
		if !slices.Contains(undo, w) {
			t.Errorf("the back-out lacks %q:\n%q", w, undo)
		}
	}
	for _, l := range bo {
		if l.Op == OpNo && (strings.Contains(l.Text, "md5") || strings.Contains(l.Text, "lab-ntp-key") || strings.Contains(l.Text, "\n")) {
			t.Errorf("a removal holds more than the object: %q", l.Text)
		}
	}
	// the order of the paste: keys, trusted keys, servers, authenticate last
	var ntp []string
	for _, l := range d.Lines {
		if strings.HasPrefix(l.Text, "ntp ") {
			ntp = append(ntp, strings.Fields(l.Text)[1])
		}
	}
	if strings.Join(ntp, " ") != "authentication-key trusted-key server server authenticate" {
		t.Errorf("the NTP order: %q", ntp)
	}
	// the note names the NTP key lines as not run on a device, and the order
	if !slices.ContainsFunc(d.Notes, func(n string) bool {
		return strings.HasPrefix(n, "system: the NTP key lines") && strings.Contains(n, "not lab-tested") && strings.Contains(n, "'ntp authenticate' last")
	}) {
		t.Errorf("notes: %q", d.Notes)
	}
	// the plain form is the statements, the banner whole
	p, err := Plain(d, h, Wrapper{})
	if err != nil || !strings.Contains(p, "banner login ^\nAuthorized use only.\n! Activity is logged.\n^\nip domain name lab.example.net\n") {
		t.Errorf("plain: %v\n%s", err, p)
	}
	// --section system plans the system block alone
	opt := f.options()
	opt.Sections = []string{"system"}
	d2, err := Plan(f.vendor, exp, cur, plain, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines(d2, "aaa"))+len(lines(d2, "snmp")) != 0 || len(lines(d2, "system")) != len(want) {
		t.Errorf("--section system:\n%s", d2.Display())
	}
}

// The device holds the objects in other shapes: the plan replaces a single
// value in place (the old one is typed again by the back-out, the banner by a
// note) and keeps every other statement.
func TestIOSSystemStrayDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-system-stray")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"banner login ^\nAuthorized use only.\n! Activity is logged.\n^", "ip domain name lab.example.net",
		"clock timezone CET 1", "ntp server 192.0.2.123 version 4 key 5 prefer", "ntp trusted-key 5", "ntp authenticate"} {
		wantLine(t, d, "system", w)
	}
	noLine(t, d, "system", "no ")
	for _, k := range []string{"ip domain list other.example.net", "ip name-server 198.51.100.53", "ntp server 198.51.100.123", "ntp master 3",
		"ntp source Loopback0", "ntp trusted-key 6"} {
		wantKept(t, d, "system", k)
	}
	// replaced values are not left as extras
	for _, k := range d.Kept {
		for _, s := range []string{"clock timezone", "ip domain name", "banner login", "ntp server 192.0.2.123"} {
			if k.Section == "system" && strings.HasPrefix(k.Text, s) {
				t.Errorf("kept: %q", k.Text)
			}
		}
	}
	wantLine(t, d, "snmp", "snmp-server trap-source Loopback0")
	noLine(t, d, "snmp", "no snmp-server trap-source")
	// the back-out: the old single values typed again, the banner a note
	var typed, notes []string
	for _, l := range iosBackout(d) {
		switch l.Op {
		case OpComment:
			notes = append(notes, l.Text)
		case OpLine:
			typed = append(typed, l.Text)
		}
	}
	for _, w := range []string{"clock timezone PST -8 0", "ip domain name other.example.net", "ntp server 192.0.2.123 version 3",
		"snmp-server trap-source loopback1"} {
		if !slices.Contains(typed, w) {
			t.Errorf("the back-out does not type %q again:\n%q", w, typed)
		}
	}
	if !slices.ContainsFunc(notes, func(n string) bool {
		return strings.Contains(n, "login banner that tacctl keeps no text of") && strings.Contains(n, "configure replace") && !strings.Contains(n, "An older banner")
	}) {
		t.Errorf("the banner's note: %q", notes)
	}
	for _, l := range iosBackout(d) {
		if strings.Contains(l.Text, "An older banner") {
			t.Errorf("the back-out holds the old banner: %q", l.Text)
		}
	}
	// the stored back-out is the printed one: no banner, no key
	sb, err := StoredBackout(d, f.header(), Wrapper{})
	if err != nil || strings.Contains(sb, "Authorized use only") || strings.Contains(sb, "lab-ntp-key") {
		t.Errorf("stored back-out: %v\n%s", err, sb)
	}
}

// A banner line that IOS would not take on a typed line is a warning, and the
// banner is typed as it is.
func TestIOSBannerLongLineWarning(t *testing.T) {
	long := strings.Repeat("x", 300)
	sec := devices.Section{Name: "system", Lines: []string{"banner login ^", long, "^"}, Secret: make([]bool, 3), Block: []bool{true, true, true}}
	f := fixtureNamed(t, "cisco.synthetic-system-new")
	exp := slices.Clone(expectedSections(t, f.expected))
	for i := range exp {
		if exp[i].Name == "system" {
			exp[i] = sec
		}
	}
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan(f.vendor, exp, cur, cur, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool {
		return strings.Contains(w, "a line of the login banner is 300 characters") && strings.Contains(w, "at most "+strconv.Itoa(iosMaxTypedLine))
	}) {
		t.Errorf("warnings: %q", d.Warnings)
	}
	if strings.Contains(strings.Join(d.Warnings, "\n"), long) {
		t.Error("the warning holds the line")
	}
	wantLine(t, d, "system", "banner login ^\n"+long+"\n^")
}

// --converge removes none of the system block's neighbours: the extras of the
// system section have a removal line to show, and the cleanup refuses each.
func TestIOSSystemExtrasAreNeverCleanedUp(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-system")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	ic := &iosCleanupCtx{proto: "tacacs", groups: map[string]string{}}
	n := 0
	for _, e := range d.Extras {
		if e.Section != "system" {
			continue
		}
		n++
		if len(e.Remove) == 0 {
			t.Errorf("no removal line for %q", e.Text)
		}
		for _, r := range e.Remove {
			if ok, _ := ic.allowed(r); ok {
				t.Errorf("the cleanup removes %q", r.Text)
			}
			if strings.Contains(r.Text, "<message") {
				t.Errorf("a removal holds a mark: %q", r.Text)
			}
		}
	}
	if n != 5 {
		t.Errorf("%d extras of the system section", n)
	}
	// and a plan with --converge says so
	opt := f.options()
	opt.Converge = true
	d, err = Plan(f.vendor, exp, cur, plain, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range d.Cleanup.Lines {
		if l.Section == "system" {
			t.Errorf("the cleanup types %q", l.Text)
		}
	}
}

// The same trap-options leaf with another address is replaced in place on
// Junos (a set over the old value, nothing deleted), and the report names it.
func TestJunosTrapSourceReplacedInPlace(t *testing.T) {
	f := blockFixture(t)
	exp := expectedSections(t, f.expected)
	for i := range exp {
		if exp[i].Name != "snmp" {
			continue
		}
		exp[i].Lines = append(exp[i].Lines, "set snmp trap-options source-address 192.0.2.7")
		exp[i].Secret = append(exp[i].Secret, false)
		exp[i].Block = append(exp[i].Block, true)
	}
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan(f.vendor, exp, cur, cur, blockOpt)
	if err != nil {
		t.Fatal(err)
	}
	wantLine(t, d, "snmp", "set snmp trap-options source-address 192.0.2.7")
	noLine(t, d, "snmp", "delete snmp trap-options")
	found := false
	for _, it := range d.Items {
		if strings.Contains(it.Words, "a trap option of the SNMP block of scope 'lab': source-address 192.0.2.7") {
			found = true
		}
	}
	if !found {
		t.Errorf("the report does not name it:\n%v", d.Items)
	}
	// the device's own, with the block stating none, is kept (the fixture)
	d = planJ(t, f, nil, blockOpt)
	wantKept(t, d, "snmp", "snmp trap-options source-address 192.0.2.250")
	// pasted, the leaf is the block's address, set over the old value
	d2, err := Plan(f.vendor, exp, cur, cur, blockOpt)
	if err != nil {
		t.Fatal(err)
	}
	c := ParseJunos(capture(t, f.raw))
	if err := c.Apply(d2.Lines); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.Text(), "source-address 192.0.2.250") || !strings.Contains(c.Text(), "source-address 192.0.2.7") {
		t.Errorf("the leaf was not replaced")
	}
	// lo0 is the same leaf with another word
	exp2 := slices.Clone(exp)
	for i := range exp2 {
		if exp2[i].Name == "snmp" {
			exp2[i].Lines = slices.Clone(exp2[i].Lines)
			exp2[i].Lines[len(exp2[i].Lines)-1] = "set snmp trap-options source-address lo0"
		}
	}
	cur2, err := devconf.Extract(f.vendor, capture(t, f.raw)+"set snmp trap-options source-address lo0\n", exp2...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := devconf.CompareAll(exp2, cur2)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP {
			for _, l := range r.Lines {
				if l.Op == devconf.OpMissing && strings.Contains(l.Text, "trap-options source-address") {
					t.Errorf("lo0 is missing: %v", r.Lines)
				}
			}
		}
	}
}
