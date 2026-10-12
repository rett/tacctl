package plan

// The output of plan §3 (Junos) and §4b (IOS) from devices shaped like the
// plan's samples: the report's structure, the region's statements exactly,
// and what follows the region. The words of the items are the planner's
// (the goldens pin them).

import (
	"slices"
	"strings"
	"testing"
)

// between returns the lines between the banners of an output.
func between(t *testing.T, out, bc, dev string) []string {
	t.Helper()
	from := bc + " PASTE FROM HERE: " + dev + " " + bc + "\n"
	to := bc + " PASTE TO HERE: " + dev + " " + bc + "\n"
	i, j := strings.Index(out, from), strings.Index(out, to)
	if i < 0 || j < i {
		t.Fatalf("no region in:\n%s", out)
	}
	return strings.Split(strings.TrimSuffix(out[i+len(from):j], "\n"), "\n")
}

// between2 is between for a named banner pair ('PASTE' or 'BACK-OUT').
func between2(t *testing.T, out, bc, word, dev string) []string {
	t.Helper()
	from := bc + " " + word + " FROM HERE: " + dev + " " + bc + "\n"
	to := bc + " " + word + " TO HERE: " + dev + " " + bc + "\n"
	i, j := strings.Index(out, from), strings.Index(out, to)
	if i < 0 || j < i {
		t.Fatalf("no %s region in:\n%s", word, out)
	}
	return strings.Split(strings.TrimSuffix(out[i+len(from):j], "\n"), "\n")
}

func nonComments(lines []string, leader string) []string {
	var out []string
	for _, l := range lines {
		if !strings.HasPrefix(l, leader) {
			out = append(out, l)
		}
	}
	return out
}

func TestJunosOutputIsThePlansSample(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	// the sample's device: an extra accounting event, a community that
	// allows clients by its own entries (no client list), a second TACACS+
	// server the standard does not have
	d := planJ(t, f, func(c *JunosConfig) {
		for _, s := range []string{
			"set snmp client-list TACCTL-SNMP 192.0.2.10/32",
			"set snmp client-list TACCTL-SNMP 198.51.100.0/24",
			"set snmp client-list TACCTL-SNMP 0.0.0.0/0 restrict",
			"set snmp community example-community client-list-name TACCTL-SNMP",
			`set snmp description "Core switch"`,
		} {
			c.Remove(s)
		}
		c.Add("set system accounting events interactive-commands")
		c.Add("set snmp community example-community clients 192.0.2.0/24")
		c.Add(`set system tacplus-server 203.0.113.5 secret "$9$EXAMPLEEXAMPLE"`)
	}, Options{Scope: "lab"})
	h := f.header()
	h.Device, h.Address = "sw-lab-1", "192.0.2.21"
	w := Wrapper{ConfirmMinutes: 5}
	out := Block(d, h, w)

	if !strings.HasPrefix(out, "##### sw-lab-1  192.0.2.21  scope lab  juniper (TACACS+) #####\n") {
		t.Errorf("the box:\n%s", out[:120])
	}
	for _, want := range []string{
		"# What is irregular on sw-lab-1 (",
		"# Type this first, on sw-lab-1, and check the name:   show version | match Hostname",
		"##### PASTE FROM HERE: sw-lab-1 #####",
		"##### PASTE TO HERE: sw-lab-1 #####",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	// the region: statements and the wrapper, exactly
	region := between(t, out, "#####", "sw-lab-1")
	wantStmts := []string{
		"configure private",
		"delete system accounting events interactive-commands",
		"set snmp client-list TACCTL-SNMP 192.0.2.10/32",
		"set snmp client-list TACCTL-SNMP 198.51.100.0/24",
		"set snmp client-list TACCTL-SNMP 0.0.0.0/0 restrict",
		"set snmp community lab-ro-community client-list-name TACCTL-SNMP",
		`set snmp description "Core switch"`,
		"delete snmp community lab-ro-community clients 192.0.2.0/24",
		"show | compare | no-more",
		"commit check",
		`commit confirmed 5 comment "tacctl plan sw-lab-1 2026-10-10T14:20Z by alice"`,
	}
	if got := nonComments(region, "#"); !slices.Equal(got, wantStmts) {
		t.Errorf("the region's statements:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantStmts, "\n"))
	}
	if n := len(region) - len(wantStmts); n != 2 {
		t.Errorf("one label per section expected (aaa, snmp): %d comment lines in the region", n)
	}
	// the second server is a finding, left alone, with its severity
	var extra *Item
	for i := range d.Items {
		if strings.Contains(d.Items[i].Statement, "203.0.113.5") {
			extra = &d.Items[i]
		}
	}
	if extra == nil || extra.Kind != KindExtra || extra.Severity != SevAccess || extra.Fixed {
		t.Fatalf("the second server: %+v", extra)
	}
	if !strings.Contains(extra.Action, "Left alone") || !strings.Contains(extra.Action, "delete system tacplus-server 203.0.113.5") {
		t.Errorf("the extra's action: %q", extra.Action)
	}
	// the event is fixed by its region line
	var ev *Item
	for i := range d.Items {
		if strings.Contains(d.Items[i].Statement, "interactive-commands") {
			ev = &d.Items[i]
		}
	}
	if ev == nil || !ev.Fixed || ev.Severity != SevCosmetic || ev.Action != "Fixed by region line 3." {
		t.Errorf("the event: %+v", ev)
	}
	// what follows: the one word, as a comment (a copy of the whole output
	// must not confirm the commit before the check)
	after := out[strings.Index(out, "##### PASTE TO HERE: sw-lab-1 #####"):]
	if got := nonComments(strings.Split(after, "\n")[1:], "#"); !slices.Equal(got, []string{""}) {
		t.Errorf("after the region: %q", got)
	}
	if !strings.Contains(after, "# When both checks are fine, type this one word yourself:  commit") {
		t.Errorf("the follow-up is not said:\n%s", after)
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(after, "# ", "")), " ")
	for _, want := range []string{"do not type commit; the switch undoes this by itself in 5 minutes",
		"show system commit", "the newest entry is that commit itself", "tacctl device config pull sw-lab-1 --diff",
		"tacctl device config plan sw-lab-1 --backout", "Do not: "} {
		if !strings.Contains(flat, want) {
			t.Errorf("the after-steps lack %q", want)
		}
	}
	if strings.Contains(after, "rollback 0") {
		t.Errorf("rollback 0 is meaningless once the confirmed commit ran:\n%s", after)
	}
	// the prompt check is above the region
	if !strings.Contains(out[:strings.Index(out, "##### PASTE FROM HERE")], "prompt must end in >") {
		t.Errorf("no prompt check before the region")
	}
	// the plain form: the region without a comment line
	plain, err := Plain(d, h, w)
	if err != nil {
		t.Fatal(err)
	}
	// statements only (D99, M5): `load set` reports the wrapper lines
	if got := strings.Split(strings.TrimSuffix(plain, "\n"), "\n"); !slices.Equal(got, wantStmts[1:len(wantStmts)-3]) {
		t.Errorf("plain:\n%s", plain)
	}
}

func TestIOSOutputIsThePlansSample(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	d := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("snmp-server community stray-rw RW")
		// no enable secret
		for i := range c.blocks {
			if strings.HasPrefix(c.blocks[i].lines[0], "enable secret") {
				c.blocks[i].lines[0] = "!"
			}
		}
	}, Options{Scope: "lab", Syntax: SyntaxIOS12})
	h := f.header()
	h.Device, h.Address = "rtr-lab-1", "192.0.2.31"
	out := Block(d, h, Wrapper{})
	if !strings.HasPrefix(out, "!!!!! rtr-lab-1  192.0.2.31  scope lab  cisco (IOS 12.x syntax, TACACS+) !!!!!\n") {
		t.Errorf("the box:\n%s", out[:140])
	}
	for _, want := range []string{
		"! What is irregular on rtr-lab-1 (",
		"! Type this first, on rtr-lab-1, and check the name:   show version | include uptime",
		"NOTHING rolls it back by itself",
		"!!!!! PASTE FROM HERE: rtr-lab-1 !!!!!",
		"!!!!! PASTE TO HERE: rtr-lab-1 !!!!!",
		"WARNING: the device has no enable secret",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q", want)
		}
	}
	region := between(t, out, "!!!!!", "rtr-lab-1")
	body := nonComments(region, "!")
	if body[0] != "configure terminal" || body[len(body)-1] != "end" {
		t.Errorf("the region is %q ... %q", body[0], body[len(body)-1])
	}
	// the unit in D118's order: aaa new-model, the server and the group,
	// the login lists with exec authorization right after them, accounting,
	// the session id (no enable list: the standard has none); the lines'
	// login method after mgmt-acl; command authorization the last statements
	idx := func(s string) int { return slices.Index(body, s) }
	if g, m := idx("aaa group server tacacs+ LAB-TACACS"), idx("aaa new-model"); g < 0 || m != 1 || m > g {
		t.Errorf("aaa new-model is not the first statement, before the group (group at %d, new-model at %d)", g, m)
	}
	a := idx("aaa authentication login default local group LAB-TACACS")
	if a < 0 || body[a+1] != "aaa authentication login CONSOLE local" || !strings.HasPrefix(body[a+2], "aaa authorization exec ") {
		t.Errorf("the login lists and authorization exec are not in a row")
	}
	for _, s := range body {
		if strings.HasPrefix(s, "aaa authentication enable") {
			t.Errorf("the standard has no enable list: %q", s)
		}
	}
	if e := idx("aaa accounting exec default start-stop group LAB-TACACS"); e != a+3 {
		t.Errorf("accounting is not right after authorization exec (at %d, want %d)", e, a+3)
	}
	// D118 (12): the device is bare, so command authorization is not in the
	// paste (the one group of lines left, said in the report); the lines'
	// login method are the last statements, the console's first
	if v, c := idx("ip access-list standard VTY-ACL"), idx("line con 0"); v <= 0 || v >= c {
		t.Errorf("the console's leaf is not after mgmt-acl (%d %d)", v, c)
	}
	for _, s := range body {
		if strings.HasPrefix(s, "aaa authorization commands ") || s == "aaa authorization config-commands" {
			t.Errorf("command authorization is in the region of a device whose server is not proven: %q", s)
		}
	}
	if last := body[len(body)-2]; last != " login authentication default" {
		t.Errorf("the last statement is %q", last)
	}
	if !strings.Contains(strings.Join(strings.Fields(strings.ReplaceAll(out, "\n!", " ")), " "), cmdAuthHeldText) {
		t.Errorf("the report does not say that command authorization is not in this paste:\n%s", out)
	}
	// 'write memory' is said after the region as a comment, never as a line
	after := out[strings.Index(out, "!!!!! PASTE TO HERE: rtr-lab-1 !!!!!"):]
	if got := nonComments(strings.Split(after, "\n")[1:], "!"); !slices.Equal(got, []string{""}) {
		t.Errorf("after the region: %q", got)
	}
	if !strings.Contains(after, "! When both checks are fine, type this one command yourself:  write memory") {
		t.Errorf("the follow-up is not said:\n%s", after)
	}
	// the back-out is its own region of plain lines (H2): no aaa new-model,
	// the login method restored
	bo, err := Backout(d, h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	back := nonComments(between2(t, bo, "!!!!!", "BACK-OUT", "rtr-lab-1"), "!")
	for _, want := range []string{"configure terminal", "no aaa new-model", "line vty 0 4", " login local", "line con 0", " no login authentication CONSOLE", "end"} {
		if !slices.Contains(back, want) {
			t.Errorf("the back-out lacks %q:\n%s", want, bo)
		}
	}
	if strings.Contains(after, "no aaa new-model") {
		t.Errorf("the main output holds the back-out lines")
	}
	// the stray community is reported, left alone
	var stray bool
	for _, it := range d.Items {
		if it.Kind == KindExtra && strings.Contains(it.Statement, "snmp-server community") && !it.Fixed {
			stray = true
		}
	}
	if !stray {
		t.Errorf("the stray community is not an item: %+v", d.Items)
	}
}
