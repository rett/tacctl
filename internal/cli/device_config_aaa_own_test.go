package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The device's own settings of the aaa section are no difference: the leaves
// of tacctl's server block that tacctl does not render (a source address, a
// timeout, a routing instance) and the options of the client. A device that
// agrees with tacctl and holds them reads the same everywhere: ok in
// 'device config list' and in the CONFIG column of 'device list', left out of
// --differs, consistent in 'device config diff' and 'device config plan'
// (exit 0, no item), with the same count in the plan's Kept line and its
// --json. A leaf the rendering states with another value, and another server,
// group or list, stay differences.

// aaaBox is a box with one device of the vendor (a Junos 'lab-j' or a Cisco
// 'lab-c') in a TACACS+ or a RADIUS scope, whose text is text(rendering) and
// whose pull was made.
func aaaBox(t *testing.T, vendor string, radius bool, text func(string) string) (*pullBox, string) {
	t.Helper()
	b := newPullBox(t)
	name := "lab-j"
	if vendor == "cisco" {
		name = "lab-c"
		b.ciscoDevice("")
	} else {
		b.devices([3]string{name, "192.168.1.20", vendor})
	}
	if radius {
		b.sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper"})
		b.sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth: {network: udp, address: \"10.0.0.77:1645\", role: auth}\n", 0o600)
		b.sb.run("", []string{"scope", "auth-method", "lab", "radius"})
		if b.sb.code != 0 {
			t.Fatalf("auth-method: %d %s", b.sb.code, b.sb.stderr())
		}
	}
	got := text(b.expected(name))
	b.serve(vendor, got)
	if vendor == "juniper" {
		b.servePlain(got)
	}
	if out := b.run("device", "config", "pull", name); b.sb.code != 0 {
		t.Fatalf("pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	return b, name
}

// wordAfter is the word that follows prefix on the first line that holds it.
func wordAfter(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), prefix); ok {
			return strings.Fields(rest)[0]
		}
	}
	t.Fatalf("no %q in\n%s", prefix, text)
	return ""
}

// inBlock puts leaf under the header line that starts with header.
func inBlock(t *testing.T, text, header, leaf string) string {
	t.Helper()
	ls := strings.Split(text, "\n")
	for i, l := range ls {
		if strings.HasPrefix(l, header) {
			return strings.Join(append(ls[:i+1:i+1], append([]string{"  " + leaf}, ls[i+1:]...)...), "\n")
		}
	}
	t.Fatalf("no %q in\n%s", header, text)
	return ""
}

// swapLine replaces the line that starts with from (after its indentation)
// by to.
func swapLine(t *testing.T, text, from, to string) string {
	t.Helper()
	ls := strings.Split(text, "\n")
	for i, l := range ls {
		if strings.HasPrefix(strings.TrimSpace(l), from) {
			ls[i] = l[:len(l)-len(strings.TrimLeft(l, " "))] + to
			return strings.Join(ls, "\n")
		}
	}
	t.Fatalf("no line %q in\n%s", from, text)
	return ""
}

// appendStmts adds statements at the end of a Junos text, and at the end of
// a Cisco text before its closing 'end'.
func appendStmts(text string, ss ...string) string {
	add := strings.Join(ss, "\n") + "\n"
	if i := strings.LastIndex(text, "\nend"); i >= 0 {
		return text[:i+1] + add + text[i+1:]
	}
	return text + add
}

type aaaOwnCase struct {
	name   string
	vendor string
	radius bool
	// own adds the device's own settings (n statements, of the kind named)
	own   func(t *testing.T, text string) string
	n     int
	kinds []string
	field string // the text of the own setting, which no report may list
	// differs gives a rendered leaf another value
	differs func(t *testing.T, text string) string
	// findings are the access-relevant extras, by name
	findings map[string]func(t *testing.T, text string) string
}

func aaaOwnCases() []aaaOwnCase {
	return []aaaOwnCase{
		{name: "junos tacplus", vendor: "juniper", n: 3, kinds: []string{"TACACS+ server settings", "TACACS+ options"}, field: "source-address 192.0.2.1",
			own: func(t *testing.T, text string) string {
				a := wordAfter(t, text, "set system tacplus-server ")
				return appendStmts(text, "set system tacplus-server "+a+" source-address 192.0.2.1", "set system tacplus-server "+a+" timeout 10",
					"set system tacplus-options service-name junos-exec")
			},
			differs: func(t *testing.T, text string) string {
				// the rendered 'single-connection' is gone: the leaf is missing
				return swapLine(t, text, "set system tacplus-server "+wordAfter(t, text, "set system tacplus-server ")+" single-connection", "# gone")
			},
			findings: map[string]func(*testing.T, string) string{
				"another server": func(t *testing.T, text string) string {
					return appendStmts(text, "set system tacplus-server 192.0.2.98 source-address 192.0.2.1")
				},
				"a port the rendering does not state": func(t *testing.T, text string) string {
					return appendStmts(text, "set system tacplus-server "+wordAfter(t, text, "set system tacplus-server ")+" port 4949")
				},
				"an option that changes the service": func(t *testing.T, text string) string {
					return appendStmts(text, "set system tacplus-options service-name other-exec")
				},
			}},
		{name: "junos radius", vendor: "juniper", radius: true, n: 3, kinds: []string{"RADIUS server settings", "RADIUS options"}, field: "source-address 192.0.2.1",
			own: func(t *testing.T, text string) string {
				a := wordAfter(t, text, "set system radius-server ")
				return appendStmts(text, "set system radius-server "+a+" source-address 192.0.2.1", "set system radius-server "+a+" retry 3",
					"set system radius-options attributes nas-ip-address 192.0.2.1")
			},
			differs: func(t *testing.T, text string) string {
				a := wordAfter(t, text, "set system radius-server ")
				return swapLine(t, text, "set system radius-server "+a+" port ", "set system radius-server "+a+" port 1700")
			},
			findings: map[string]func(*testing.T, string) string{
				"another server": func(t *testing.T, text string) string {
					return appendStmts(text, "set system radius-server 192.0.2.98 source-address 192.0.2.1")
				},
				"an option that changes the password check": func(t *testing.T, text string) string {
					return appendStmts(text, "set system radius-options password-protocol mschap-v2")
				},
			}},
		{name: "ios tacacs", vendor: "cisco", n: 1, kinds: []string{"TACACS+ server settings"}, field: "send-nat-address",
			own: func(t *testing.T, text string) string {
				return inBlock(t, text, "tacacs server TACACS", "send-nat-address")
			},
			differs: func(t *testing.T, text string) string { return swapLine(t, text, "timeout 5", "timeout 9") },
			findings: map[string]func(*testing.T, string) string{
				"another server block": func(t *testing.T, text string) string {
					return appendStmts(text, "tacacs server OTHER", "  address ipv4 192.0.2.98")
				},
				"a port the rendering does not state": func(t *testing.T, text string) string {
					return inBlock(t, text, "tacacs server TACACS", "port 4949")
				},
				"another group": func(t *testing.T, text string) string {
					return appendStmts(text, "aaa group server tacacs+ OTHER", "  server name OTHER")
				},
				"another method list": func(t *testing.T, text string) string {
					return appendStmts(text, "aaa authentication login OTHER local")
				},
			}},
		{name: "ios radius", vendor: "cisco", radius: true, n: 1, kinds: []string{"RADIUS server settings"}, field: "automate-tester",
			own: func(t *testing.T, text string) string {
				return inBlock(t, text, "radius server RADIUS", "automate-tester username probe")
			},
			differs: func(t *testing.T, text string) string { return swapLine(t, text, "retransmit 2", "retransmit 5") },
			findings: map[string]func(*testing.T, string) string{
				"another server block": func(t *testing.T, text string) string {
					return appendStmts(text, "radius server OTHER", "  address ipv4 192.0.2.98 auth-port 1812 acct-port 1813")
				},
				"another group": func(t *testing.T, text string) string {
					return appendStmts(text, "aaa group server radius OTHER", "  server name OTHER")
				},
			}},
	}
}

func TestAAAOwnSettingsReadTheSameEverywhere(t *testing.T) {
	for _, c := range aaaOwnCases() {
		t.Run(c.name, func(t *testing.T) {
			b, name := aaaBox(t, c.vendor, c.radius, func(s string) string { return c.own(t, s) })
			count := "aaa +" + itoa(c.n) + " unmanaged"
			if list := b.run("device", "config", "list"); b.sb.code != 0 || !strings.Contains(list, count) || strings.Contains(list, "differs") {
				t.Fatalf("list: %d\n%s", b.sb.code, list)
			}
			if out := b.run("device", "config", "list", "--differs"); strings.Contains(out, name) {
				t.Errorf("config list --differs holds the device:\n%s", out)
			}
			if out := b.run("device", "list", "--differs"); strings.Contains(out, name) {
				t.Errorf("list --differs holds the device:\n%s", out)
			}
			if out := b.run("device", "list"); !strings.Contains(out, name) || strings.Contains(out, "differs") {
				t.Errorf("device list:\n%s", out)
			}
			diff := b.run("device", "config", "diff", name, "--exit-code")
			if b.sb.code != 0 || !strings.Contains(diff, "aaa         ok (+"+itoa(c.n)+" unmanaged)") ||
				!strings.Contains(diff, "note: "+itoa(c.n)+c.noun()+" of the device's own, kept on purpose") {
				t.Errorf("diff: %d\n%s", b.sb.code, diff)
			}
			if !strings.Contains(diff, "+ ") || !strings.Contains(diff, c.field) {
				t.Errorf("diff does not list the device's own settings:\n%s", diff)
			}
			out := b.run("device", "config", "plan", name, "--exit-code")
			if b.sb.code != 0 {
				t.Errorf("plan: exit %d\n%s", b.sb.code, out)
			}
			flat := strings.Join(strings.Fields(strings.ReplaceAll(out, "\n#", " ")), " ")
			for _, want := range []string{"CONSISTENT: nothing to paste.", "Kept: aaa " + itoa(c.n) + c.noun() + " of the device's own (" + strings.Join(c.kinds, ", ") + ")"} {
				if !strings.Contains(flat, want) {
					t.Errorf("the plan lacks %q:\n%s", want, out)
				}
			}
			for _, bad := range []string{"What is irregular", "PASTE FROM HERE", c.field} {
				if strings.Contains(out, bad) {
					t.Errorf("the plan holds %q:\n%s", bad, out)
				}
			}
			js := b.run("device", "config", "plan", name, "--json")
			var got []struct {
				Status         string
				Irregularities []any
				Kept           []struct {
					Section string
					Count   int
					Kinds   []string
				}
			}
			if err := json.Unmarshal([]byte(js), &got); err != nil || len(got) != 1 {
				t.Fatalf("json: %v\n%s", err, js)
			}
			if g := got[0]; g.Status != "consistent" || len(g.Irregularities) != 0 || len(g.Kept) != 1 || g.Kept[0].Section != "aaa" ||
				g.Kept[0].Count != c.n || !slices.Equal(g.Kept[0].Kinds, c.kinds) {
				t.Errorf("json: %+v", g)
			}
		})
	}
}

// The same device with a leaf the rendering states set otherwise, or with
// another server, group or list, differs everywhere, and the plan lists the
// finding and not the device's own settings beside it.
func TestAAAFindingsStayDifferencesBesideTheDevicesOwn(t *testing.T) {
	for _, c := range aaaOwnCases() {
		cases := map[string]func(*testing.T, string) string{"a rendered leaf with another value": c.differs}
		for k, f := range c.findings {
			cases[k] = f
		}
		for what, find := range cases {
			t.Run(c.name+"/"+what, func(t *testing.T) {
				b, name := aaaBox(t, c.vendor, c.radius, func(s string) string { return find(t, c.own(t, s)) })
				list := b.run("device", "config", "list")
				if b.sb.code != 0 || !strings.Contains(list, "differs") || !strings.Contains(list, "aaa") {
					t.Fatalf("list: %d\n%s", b.sb.code, list)
				}
				if out := b.run("device", "config", "list", "--differs"); !strings.Contains(out, name) {
					t.Errorf("config list --differs lacks the device:\n%s", out)
				}
				if out := b.run("device", "list", "--differs"); !strings.Contains(out, name) {
					t.Errorf("list --differs lacks the device:\n%s", out)
				}
				if out := b.run("device", "config", "diff", name, "--exit-code"); b.sb.code != 2 || strings.Contains(out, "aaa         ok") {
					t.Errorf("diff: %d\n%s", b.sb.code, out)
				}
				out := b.run("device", "config", "plan", name, "--exit-code")
				if !strings.Contains(out, "What is irregular") || strings.Contains(out, "CONSISTENT") {
					t.Errorf("plan: exit %d\n%s", b.sb.code, out)
				}
				if strings.Contains(out, c.field) && !strings.Contains(what, "another") {
					t.Errorf("the plan lists the device's own setting %q:\n%s", c.field, out)
				}
			})
		}
	}
}

func (c aaaOwnCase) noun() string {
	if c.n == 1 {
		return " statement"
	}
	return " statements"
}

func itoa(n int) string { return string(rune('0' + n)) }
