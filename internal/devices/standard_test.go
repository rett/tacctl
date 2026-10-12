package devices

// The standard Cisco block (plan §13, D116-D120): the order of the managed
// aaa section (which is the order the region types it in), the console's
// list, the source interface and what an unset one renders, the hardening
// checklist that is never compared, and the names.

import (
	"slices"
	"strings"
	"testing"
)

// standardWorld is the managed world with a source interface on the lab
// scope.
func standardWorld(t *testing.T, sourceInterface bool) (Request, Data) {
	t.Helper()
	over := managedOverrides
	if sourceInterface {
		over += "cisco:\n  source_interface:\n    lab: Loopback0\n"
	}
	m, c := fixtureGroups(t, managedGroups, over)
	req, d := managedProfiles()[0].input(m, c, variants[0])
	return req, d
}

func aaaOf(t *testing.T, req Request, d Data) []string {
	t.Helper()
	s, ok := sectionOf(mustManaged(t, req, d), "aaa")
	if !ok {
		t.Fatal("no aaa section")
	}
	return s.Lines
}

// D118 for the section Managed returns: aaa new-model first (nothing under
// aaa exists on IOS until it is set), the server and its group, the source
// interface, the login lists, exec authorization, accounting, the session
// id, the lines' leaves (the console first), command authorization last.
// There is no enable list (0.2.6).
func TestStandardOrder(t *testing.T) {
	req, d := standardWorld(t, true)
	lines := aaaOf(t, req, d)
	want := []string{
		"aaa new-model",
		"tacacs server TACACS",
		"aaa group server tacacs+ LAB-TACACS",
		"ip tacacs source-interface Loopback0",
		"aaa authentication login default local group LAB-TACACS",
		"aaa authentication login CONSOLE local",
		"aaa authorization exec default local group LAB-TACACS if-authenticated",
		"aaa accounting exec default start-stop group LAB-TACACS",
		"aaa session-id common",
		"line con 0",
		"  login authentication CONSOLE",
		"line vty 0 15",
		"  login authentication default",
		"aaa authorization commands 15 default local group LAB-TACACS",
		"aaa authorization config-commands",
	}
	last := -1
	for _, w := range want {
		at := slices.Index(lines, w)
		if at < 0 {
			t.Errorf("no %q in\n%s", w, strings.Join(lines, "\n"))
			continue
		}
		if at <= last {
			t.Errorf("%q is out of order (at %d, after %d):\n%s", w, at, last, strings.Join(lines, "\n"))
		}
		last = at
	}
	if lines[len(lines)-1] != "aaa authorization config-commands" {
		t.Errorf("command authorization is not last: %q", lines[len(lines)-1])
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "aaa authentication enable") {
			t.Errorf("the standard has no enable list: %q", l)
		}
	}
	// the walkthrough has it live, in the same order
	text := renderText(t, req, d)
	if !strings.Contains(text, "\naaa new-model\n!\ntacacs server TACACS\n") ||
		!strings.Contains(text, "\naaa group server tacacs+ LAB-TACACS\n  server name TACACS\n!\nip tacacs source-interface Loopback0\n!\n") {
		t.Errorf("the walkthrough's order:\n%s", text)
	}
	if strings.Contains(text, "Source interface not set") {
		t.Errorf("the walkthrough says the source interface is not set:\n%s", text)
	}
}

// D119: unset, nothing is rendered or compared and nothing is a placeholder
// in a statement; the walkthrough names the command in a comment and the gap
// is a sentence for a plan's report.
func TestStandardSourceInterfaceUnset(t *testing.T) {
	req, d := standardWorld(t, false)
	for _, l := range aaaOf(t, req, d) {
		if strings.Contains(l, "source-interface") || strings.Contains(l, "<") {
			t.Errorf("a statement for an unset value: %q", l)
		}
	}
	text := renderText(t, req, d)
	for _, want := range []string{"! Source interface not set for scope lab",
		"!   tacctl config cisco source-interface lab <interface>",
		"! then render this again to get the line:  ip tacacs source-interface <interface>"} {
		if !strings.Contains(text, want) {
			t.Errorf("the walkthrough lacks %q", want)
		}
	}
	if got := PolicyGaps(req, d); len(got) != 1 || got[0] != "policy value not set: source interface (tacctl config cisco source-interface lab <interface>); the server matches this device by its source address" {
		t.Errorf("gaps: %q", got)
	}
	req2, d2 := standardWorld(t, true)
	if got := PolicyGaps(req2, d2); len(got) != 0 {
		t.Errorf("a gap for a set value: %q", got)
	}
	if got := PolicyGaps(Request{Vendor: "juniper", Scope: "lab"}, d); got != nil {
		t.Errorf("a Junos gap: %q", got)
	}
}

// RADIUS has the standard where RADIUS has it: the console list and the
// session id, its own source-interface command, and no command
// authorization. Like TACACS+ it has no enable list: no 'aaa authentication
// enable' line, live or commented, in the section or any walkthrough.
func TestStandardRadius(t *testing.T) {
	m, c := fixtureGroups(t, managedGroups, managedOverrides+"cisco:\n  source_interface:\n    lab: Loopback3\n")
	req, d := managedProfiles()[0].input(m, c, variants[2])
	lines := aaaOf(t, req, d)
	for _, want := range []string{
		"radius server RADIUS", "aaa group server radius LAB-RADIUS", "ip radius source-interface Loopback3", "aaa new-model",
		"aaa authentication login CONSOLE local",
		"aaa session-id common", "line con 0", "  login authentication CONSOLE",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("radius aaa lacks %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	for _, l := range lines {
		if strings.Contains(l, "commands") || strings.Contains(l, "tacacs") || strings.HasPrefix(l, "aaa authentication enable") {
			t.Errorf("radius aaa has %q", l)
		}
	}
	text := renderText(t, req, d)
	for _, bad := range []string{"NOT VERIFIED", "lab item E2", "treat the local enable secret as the way up"} {
		if strings.Contains(text, bad) {
			t.Errorf("the RADIUS walkthrough still says %q:\n%s", bad, text)
		}
	}
}

// 0.2.6: the standard has no enable list, in any vendor syntax or protocol:
// no 'aaa authentication enable' line, live or commented, in a walkthrough or
// a managed rendering (with a list that asks the server, anyone the server
// knows reaches level 15 with their own password). The walkthrough says so.
func TestStandardHasNoEnableList(t *testing.T) {
	for _, v := range variants {
		m, c := managedWorld(t)
		req, d := managedProfiles()[0].input(m, c, v)
		if v.vendor != "cisco" {
			continue
		}
		for _, l := range strings.Split(renderText(t, req, d), "\n") {
			if strings.Contains(strings.TrimPrefix(strings.TrimSpace(l), "!"), "aaa authentication enable") {
				t.Errorf("%s: the walkthrough has %q", v.name, l)
			}
		}
		for _, s := range mustManaged(t, req, d) {
			for _, l := range s.Lines {
				if strings.Contains(l, "aaa authentication enable") {
					t.Errorf("%s: section %s has %q", v.name, s.Name, l)
				}
			}
		}
		if !strings.Contains(renderText(t, req, d), "there is no enable list") {
			t.Errorf("%s: the walkthrough does not say there is no enable list", v.name)
		}
	}
}

// D116 (B): the hardening checklist is comments only, in the walkthrough and
// never in the managed sections, and the break-glass accounts come before the
// AAA step they back.
func TestStandardHardeningIsOnlyComments(t *testing.T) {
	for _, v := range []variant{variants[0], variants[1], variants[2]} {
		m, c := managedWorld(t)
		req, d := managedProfiles()[0].input(m, c, v)
		d.SNMP.DeviceName = "rtr-lab-1"
		text := renderText(t, req, d)
		step0 := text[strings.Index(text, "! --- Step 0:"):strings.Index(text, "! --- Step 1:")]
		for _, l := range strings.Split(strings.TrimSpace(step0), "\n") {
			if !strings.HasPrefix(l, "!") {
				t.Errorf("%s: a live line in Step 0: %q", v.name, l)
			}
		}
		for _, want := range []string{"!   hostname rtr-lab-1", "!   ip domain name <DOMAIN>", "!   no ip domain lookup",
			"!   no ip http server", "!   ip ssh version 2", "!   no enable password", "! username lab-admin privilege"} {
			if !strings.Contains(step0, want) {
				t.Errorf("%s: Step 0 lacks %q", v.name, want)
			}
		}
		enable := "!   enable algorithm-type scrypt secret <PASSWORD>"
		if v.legacy {
			enable = "!   enable secret <PASSWORD>"
		}
		if !strings.Contains(step0, enable) || (v.legacy && strings.Contains(step0, "scrypt")) {
			t.Errorf("%s: the enable secret line is not %q", v.name, enable)
		}
		for _, s := range mustManaged(t, req, d) {
			for _, l := range s.Lines {
				for _, hard := range []string{"hostname ", "ip domain", "no service pad", "no ip http", "ip ssh ", "enable ", "no enable"} {
					if strings.HasPrefix(l, hard) {
						t.Errorf("%s: the hardening line %q is managed", v.name, l)
					}
				}
			}
		}
	}
}

// D117: the names are the plain ones, with no setting for a server name: the
// group is tacacs_group.<scope>, which stays.
func TestStandardNames(t *testing.T) {
	m, c := fixtureGroups(t, managedGroups, "") // no tacacs_group: the default
	req, d := managedProfiles()[0].input(m, c, variants[0])
	lines := aaaOf(t, req, d)
	for _, want := range []string{"tacacs server TACACS", "aaa group server tacacs+ TACACS-GROUP", "  server name TACACS",
		"aaa authentication login CONSOLE local"} {
		if !slices.Contains(lines, want) {
			t.Errorf("lacks %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

// walkLive are the live configuration lines of a walkthrough, in order: what
// stands between its first and second rule, less comments and blanks.
func walkLive(t *testing.T, text string) []string {
	t.Helper()
	const rule = "--------------------------------------------"
	var out []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		if l == rule {
			if in {
				break
			}
			in = true
			continue
		}
		if tl := strings.TrimLeft(l, " \t"); in && tl != "" && !strings.HasPrefix(tl, "!") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no configuration between the rules:\n%s", text)
	}
	return out
}

// checkNewModelFirst fails unless 'aaa new-model' stands before every other
// 'aaa ...' line and before every server, group, address and key statement:
// on IOS nothing under 'aaa' exists until it is set, so a group and its
// server leaf typed first are rejected.
func checkNewModelFirst(t *testing.T, what string, lines []string) {
	t.Helper()
	at := slices.Index(lines, "aaa new-model")
	if at < 0 {
		t.Errorf("%s: no 'aaa new-model' in\n%s", what, strings.Join(lines, "\n"))
		return
	}
	for i, l := range lines[:at] {
		w := strings.TrimSpace(l)
		for _, p := range []string{"aaa ", "tacacs server ", "radius server ", "tacacs-server host ", "radius-server host ",
			"ip tacacs source-interface ", "ip radius source-interface ", "server ", "address ", "key "} {
			if strings.HasPrefix(w, p) {
				t.Errorf("%s: %q (line %d) is before 'aaa new-model' (line %d)", what, l, i+1, at+1)
			}
		}
	}
}

// B1: 'aaa new-model' is first in every managed aaa unit and in the paste
// of every Cisco walkthrough, whatever the syntax, protocol and scope.
func TestStandardNewModelIsFirst(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range variants[:3] {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			what := v.name + "/" + p.scope
			s, ok := sectionOf(mustManaged(t, req, d), "aaa")
			if !ok {
				t.Fatalf("%s: no aaa section", what)
			}
			if s.Lines[0] != "aaa new-model" {
				t.Errorf("%s: the unit starts %q", what, s.Lines[0])
			}
			checkNewModelFirst(t, what+" managed", s.Lines)
			checkNewModelFirst(t, what+" walkthrough", walkLive(t, renderText(t, req, d)))
		}
	}
}

// asciiOnly reports the first byte outside tab, newline and 0x20-0x7e.
func asciiOnly(s string) (int, byte, bool) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\t' && c != '\n' && (c < 0x20 || c > 0x7e) {
			return i, c, false
		}
	}
	return 0, 0, true
}

// S3: what an engineer pastes is ASCII: the managed Cisco text of every
// scenario, and the whole of each Cisco walkthrough (the header, the notes
// under the configuration and the mappings too: a copy of the output is
// pasted from, comments included).
func TestStandardCiscoIsASCII(t *testing.T) {
	const rule = "--------------------------------------------\n"
	m, c := managedWorld(t)
	for _, v := range variants[:3] {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			what := v.name + "/" + p.scope
			if at, b, ok := asciiOnly(managedText(mustManaged(t, req, d))); !ok {
				t.Errorf("%s: managed text has byte 0x%02x at %d", what, b, at)
			}
			text := renderText(t, req, d)
			from := strings.Index(text, rule)
			to := strings.Index(text[from+1:], rule)
			if from < 0 || to < 0 {
				t.Fatalf("%s: no rules", what)
			}
			if at, b, ok := asciiOnly(text[from : from+1+to]); !ok {
				t.Errorf("%s: the pasted part has byte 0x%02x at %d", what, b, at)
			}
			if at, b, ok := asciiOnly(text); !ok {
				from := max(0, at-30)
				t.Errorf("%s: the walkthrough has byte 0x%02x at %d: %q", what, b, at, text[from:min(len(text), at+30)])
			}
		}
	}
}
