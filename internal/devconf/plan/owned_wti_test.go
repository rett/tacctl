package plan

// One test per row of the WTI ownership table (owned_wti.go): the table says
// what is owned, these say what the comparison does with an extra or a
// difference of each, and that the resolver names the row of every statement
// tacctl renders and every shape the comparison keeps. A row without a case
// fails TestEveryWTIRowHasACase. The planner of a unit is a later change; the
// rows are data until then.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// wtiRendering is a rendering of the goldens of internal/devices
// (managed.wti.<scope>.txt and managed.wti-radius.<scope>.txt) as a unit
// prints it: a secret as its mark, a community as its string.
func wtiRendering(t *testing.T, name string) []devices.Section {
	t.Helper()
	return goldenSections(t, name)
}

func wtiLinesOf(secs []devices.Section, section string) (devices.Section, []string) {
	s := sectionNamed(secs, section)
	out := make([]string, len(s.Lines))
	for i, l := range s.Lines {
		if f := strings.Fields(l); s.Secret[i] && len(f) > 0 && !strings.Contains(l, "ro-community") {
			f[len(f)-1] = "<secret>"
			l = strings.Join(f, " ")
		}
		out[i] = l
	}
	return s, out
}

// wtiCompare reads a unit's statements of a section against the rendering.
func wtiCompare(t *testing.T, secs []devices.Section, section string, edit func([]string) []string) devconf.SectionResult {
	t.Helper()
	want, dev := wtiLinesOf(secs, section)
	if edit != nil {
		dev = edit(slices.Clone(dev))
	}
	res, err := devconf.Compare(devconf.FamilyWTI, want, devices.Section{Name: section, Lines: dev}, true)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func replaceLine(old, repl string) func([]string) []string {
	return func(l []string) []string {
		i := slices.Index(l, old)
		if i < 0 {
			panic("no line " + old)
		}
		l[i] = repl
		return l
	}
}

func appendLines(extra ...string) func([]string) []string {
	return func(l []string) []string { return append(l, extra...) }
}

// resultLine is the comparison's line with the text.
func resultLine(res devconf.SectionResult, op byte, text string) (devconf.DiffLine, bool) {
	for _, l := range res.Lines {
		if l.Op == op && strings.HasPrefix(l.Text, text) {
			return l, true
		}
	}
	return devconf.DiffLine{}, false
}

// wantDifference asserts that a section differs by the missing and extra
// statements, that both belong to the row, and the finding's severity.
func wantDifference(t *testing.T, res devconf.SectionResult, section, row, proto, severity, missing, extra string) {
	t.Helper()
	if res.State != devconf.StateDiffers {
		t.Errorf("%s: %s, want differs: %v", row, res.StateText(), res.Lines)
		return
	}
	for op, text := range map[byte]string{devconf.OpMissing: missing, devconf.OpExtra: extra} {
		if text == "" {
			continue
		}
		l, ok := resultLine(res, op, text)
		switch {
		case !ok:
			t.Errorf("%s: no %c line %q: %v", row, op, text, res.Lines)
			continue
		case l.Unmanaged:
			t.Errorf("%s: %q is the device's own, want a finding", row, text)
		}
		stem := strings.SplitN(l.Text, " (", 2)[0]
		if got := WTIRowID(section, stem, proto); got != row {
			t.Errorf("%s: %q is of row %q", row, stem, got)
		}
		if got := devconf.WTISeverity(section, stem); got != severity {
			t.Errorf("%s: %q severity %s, want %s", row, stem, got, severity)
		}
	}
}

// wantOwn asserts that the unit's extra statement is the device's own: the
// section reads ok with it counted as unmanaged.
func wantOwn(t *testing.T, res devconf.SectionResult, section, row, proto, stmt string, n int) {
	t.Helper()
	if res.State != devconf.StateOK || res.Unmanaged != n {
		t.Errorf("%s: %s (%d unmanaged), want ok (+%d unmanaged): %v", row, res.StateText(), res.Unmanaged, n, res.Lines)
	}
	if got := WTIRowID(section, stmt, proto); got != row {
		t.Errorf("%s: %q is of row %q", row, stmt, got)
	}
}

var (
	wtiTacacs = "managed.wti.lab.txt"
	wtiRadius = "managed.wti-radius.lab.txt"
)

// The cases of the WTI rows.
var wtiRowCases = map[string]rowCase{
	"wti.aaa.tacacs": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "aaa", replaceLine("tacacs fallback-timer 15", "tacacs fallback-timer 16"))
		wantDifference(t, res, "aaa", "wti.aaa.tacacs", "tacacs", "ACCESS", "tacacs fallback-timer 15", "tacacs fallback-timer 16")
		// the debug mode and the session module are cosmetic
		res = wtiCompare(t, secs, "aaa", replaceLine("tacacs debug off", "tacacs debug on"))
		wantDifference(t, res, "aaa", "wti.aaa.tacacs", "tacacs", "COSMETIC", "tacacs debug off", "tacacs debug on")
		// a second server is a finding the plan keeps
		res = wtiCompare(t, secs, "aaa", appendLines("tacacs secondary 192.0.2.43"))
		wantDifference(t, res, "aaa", "wti.aaa.tacacs", "tacacs", "ACCESS", "", "tacacs secondary 192.0.2.43")
		// the secret word is compared by presence
		res = wtiCompare(t, secs, "aaa", replaceLine("tacacs secret <secret>", "tacacs secret <secret>"))
		if res.State != devconf.StateOK {
			t.Errorf("a defined secret: %s", res.StateText())
		}
	},
	"wti.aaa.radius": func(t *testing.T) {
		secs := wtiRendering(t, wtiRadius)
		res := wtiCompare(t, secs, "aaa", replaceLine("radius retries 3", "radius retries 4"))
		wantDifference(t, res, "aaa", "wti.aaa.radius", "radius", "ACCESS", "radius retries 3", "radius retries 4")
		res = wtiCompare(t, secs, "aaa", appendLines("radius secondary 192.0.2.43"))
		wantDifference(t, res, "aaa", "wti.aaa.radius", "radius", "ACCESS", "", "radius secondary 192.0.2.43")
	},
	"wti.aaa.radius-unrendered": func(t *testing.T) {
		secs := wtiRendering(t, wtiRadius)
		var items = []string{"radius secondary-secret <secret>", "radius onetime-timer 5", "radius onetime-type dbm",
			"radius session-module enabled", "radius message-authenticator off", "radius default-level viewonly",
			"radius default-services telnet-ssh"}
		res := wtiCompare(t, secs, "aaa", appendLines(items...))
		wantOwn(t, res, "aaa", "wti.aaa.radius-unrendered", "radius", "radius session-module enabled", len(items))
		for _, it := range items {
			if got := WTIRowID("aaa", it, "radius"); got != "wti.aaa.radius-unrendered" {
				t.Errorf("%q is of row %q", it, got)
			}
		}
	},
	"wti.aaa.inactive-protocol": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		items := []string{"radius enable off", "radius fallback-timer 3", "radius retries 3", "radius port 1812", "radius default-access on"}
		res := wtiCompare(t, secs, "aaa", appendLines(items...))
		wantOwn(t, res, "aaa", "wti.aaa.inactive-protocol", "tacacs", "radius retries 3", len(items))
		// turned on, it is a finding
		res = wtiCompare(t, secs, "aaa", appendLines("radius enable on", "radius retries 3"))
		wantDifference(t, res, "aaa", "wti.aaa.inactive-protocol", "tacacs", "ACCESS", "", "radius enable on")
		// and the other way round
		secs = wtiRendering(t, wtiRadius)
		res = wtiCompare(t, secs, "aaa", appendLines("tacacs enable off", "tacacs fallback-timer 15"))
		wantOwn(t, res, "aaa", "wti.aaa.inactive-protocol", "radius", "tacacs fallback-timer 15", 2)
	},
	"wti.aaa.multiple-logins": func(t *testing.T) {
		// the unit-wide setting of /N (item 31): rendered On for every
		// scope, so a unit with it Off is a finding with its step
		for _, c := range []struct{ file, proto string }{{wtiTacacs, "tacacs"}, {wtiRadius, "radius"}} {
			secs := wtiRendering(t, c.file)
			res := wtiCompare(t, secs, "aaa", nil)
			if res.State != devconf.StateOK {
				t.Errorf("%s: %s", c.proto, res.StateText())
			}
			res = wtiCompare(t, secs, "aaa", replaceLine("unit multiple-logins on", "unit multiple-logins off"))
			wantDifference(t, res, "aaa", "wti.aaa.multiple-logins", c.proto, "ACCESS", "unit multiple-logins on", "unit multiple-logins off")
		}
		if r := OwnedByID(devconf.FamilyWTI, "wti.aaa.multiple-logins"); r.Mode != ModeSingle || r.Kept != "" || r.Why != "multiple logins are on, so a second session can log in" {
			t.Errorf("the row: %+v", r)
		}
	},

	"wti.snmp.access": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", replaceLine("snmp version v1-v2-only", "snmp version all"))
		wantDifference(t, res, "snmp", "wti.snmp.access", "tacacs", "MONITORING", "snmp version v1-v2-only", "snmp version all")
		res = wtiCompare(t, secs, "snmp", replaceLine("snmp enable on", "snmp enable off"))
		wantDifference(t, res, "snmp", "wti.snmp.access", "tacacs", "MONITORING", "snmp enable on", "snmp enable off")
	},
	"wti.snmp.contact": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", replaceLine(`snmp contact "NOC <noc@example.net>"`, `snmp contact "Someone Else"`))
		wantDifference(t, res, "snmp", "wti.snmp.contact", "tacacs", "COSMETIC", `snmp contact "NOC <noc@example.net>"`, `snmp contact "Someone Else"`)
		// a unit's text the menu printed truncated, as the rendered one
		// begins, is equal
		res = wtiCompare(t, secs, "snmp", replaceLine(`snmp contact "NOC <noc@example.net>"`, `snmp contact "NOC <noc@ex..."`))
		if res.State != devconf.StateOK {
			t.Errorf("a truncated contact: %s: %v", res.StateText(), res.Lines)
		}
	},
	"wti.snmp.location": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", replaceLine(`snmp location "Rack 4, DC1"`, `snmp location "Rack 5"`))
		wantDifference(t, res, "snmp", "wti.snmp.location", "tacacs", "COSMETIC", `snmp location "Rack 4, DC1"`, `snmp location "Rack 5"`)
	},
	"wti.snmp.ro-community": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", replaceLine("snmp ro-community lab-ro-community", "snmp ro-community another-string"))
		wantDifference(t, res, "snmp", "wti.snmp.ro-community", "tacacs", "MONITORING",
			"snmp ro-community <secret:1>", "snmp ro-community <other:1>")
		// the same string is equal, whatever its label
		res = wtiCompare(t, secs, "snmp", nil)
		if res.State != devconf.StateOK {
			t.Errorf("the rendered community: %s", res.StateText())
		}
	},
	"wti.snmp.rw-community": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp rw-community lab-rw-community"))
		wantDifference(t, res, "snmp", "wti.snmp.rw-community", "tacacs", "MONITORING", "", "snmp rw-community <other:1>")
	},
	"wti.snmp.system-name": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp system-name wti.site.exam..."))
		wantOwn(t, res, "snmp", "wti.snmp.system-name", "tacacs", "snmp system-name wti.site.exam...", 1)
	},
	"wti.snmp.trap-manager": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp trap manager 1 192.0.2.34", "snmp trap manager 2 192.0.2.35"))
		wantOwn(t, res, "snmp", "wti.snmp.trap-manager", "tacacs", "snmp trap manager 1 192.0.2.34", 2)
	},
	"wti.snmp.trap-community": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp trap community lab-ro-community"))
		wantOwn(t, res, "snmp", "wti.snmp.trap-community", "tacacs", "snmp trap community <secret:1>", 1)
		// another string is the device's own too
		res = wtiCompare(t, secs, "snmp", appendLines("snmp trap community another-string"))
		wantOwn(t, res, "snmp", "wti.snmp.trap-community", "tacacs", "snmp trap community <other:1>", 1)
	},
	"wti.snmp.trap-version": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp trap version v2"))
		wantOwn(t, res, "snmp", "wti.snmp.trap-version", "tacacs", "snmp trap version v2", 1)
	},
	"wti.snmp.trap-engine-id": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "snmp", appendLines("snmp trap engine-id 0x80001234"))
		wantOwn(t, res, "snmp", "wti.snmp.trap-engine-id", "tacacs", "snmp trap engine-id 0x80001234", 1)
	},
	"wti.snmp.v3": func(t *testing.T) {
		// a v3 scope: the unit's V3 users are not read, so nothing of the
		// section is compared
		secs := wtiRendering(t, "managed.wti.prod.txt")
		res := wtiCompare(t, secs, "snmp", appendLines("snmp v3 user other-user"))
		if res.State != devconf.StateNA || !slices.Contains(res.Notes, devconf.NoteWTIv3) {
			t.Errorf("a v3 scope: %s %q", res.StateText(), res.Notes)
		}
		for _, l := range []string{"snmp v3 user tacctl-ro", "snmp v3 auth-protocol sha", "snmp v3 privacy-passphrase x"} {
			if got := WTIRowID("snmp", l, "tacacs"); got != "wti.snmp.v3" {
				t.Errorf("%q is of row %q", l, got)
			}
		}
		// and a v2c scope's unit that holds one: a finding
		secs = wtiRendering(t, wtiTacacs)
		res = wtiCompare(t, secs, "snmp", appendLines("snmp v3 user other-user"))
		wantDifference(t, res, "snmp", "wti.snmp.v3", "tacacs", "MONITORING", "", "snmp v3 user other-user")
	},

	"wti.mgmt-acl.list": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		tail := []string{"iptables -A INPUT -j DROP", "iptables -A OUTPUT -j ACCEPT", "iptables -P INPUT DROP", "iptables -P OUTPUT DROP", "iptables -P FORWARD DROP"}
		// the tail is kept, in place, and not compared
		res := wtiCompare(t, secs, "mgmt-acl", appendLines(tail...))
		wantOwn(t, res, "mgmt-acl", "wti.mgmt-acl.list", "tacacs", tail[0], len(tail))
		// the whole list is one ordered object: a reordered pair differs
		res = wtiCompare(t, secs, "mgmt-acl", func(l []string) []string {
			l[2], l[3] = l[3], l[2]
			return l
		})
		if res.State != devconf.StateDiffers || !slices.ContainsFunc(res.Lines, func(l devconf.DiffLine) bool { return strings.HasPrefix(l.Text, "iptables: order differs") }) {
			t.Errorf("a reordered list: %s: %v", res.StateText(), res.Lines)
		}
		// an entry the rendering lacks is a finding
		res = wtiCompare(t, secs, "mgmt-acl", appendLines("iptables -A INPUT -s 198.51.100.7 -j ACCEPT"))
		wantDifference(t, res, "mgmt-acl", "wti.mgmt-acl.list", "tacacs", "ACCESS", "", "iptables -A INPUT -s 198.51.100.7 -j ACCEPT")
		// and the table says the list is ordered and rewritten whole
		row := OwnedByID(devconf.FamilyWTI, "wti.mgmt-acl.list")
		if row.Mode != ModeList || !row.Ordered {
			t.Errorf("the list row: %+v", row)
		}
	},

	"wti.breakglass.level": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		res := wtiCompare(t, secs, "breakglass", replaceLine("user lab-ops level user", "user lab-ops level superuser"))
		wantDifference(t, res, "breakglass", "wti.breakglass.level", "tacacs", "ACCESS", "user lab-ops level user", "user lab-ops level superuser")
		// an account nobody recorded is a finding, and is not removed
		res = wtiCompare(t, secs, "breakglass", appendLines("user other-admin level administrator", "user other-admin password <secret>"))
		wantDifference(t, res, "breakglass", "wti.breakglass.level", "tacacs", "ACCESS", "", "user other-admin level administrator")
	},
	"wti.breakglass.password": func(t *testing.T) {
		secs := wtiRendering(t, wtiTacacs)
		// a recorded account that holds no password
		res := wtiCompare(t, secs, "breakglass", func(l []string) []string {
			return slices.DeleteFunc(l, func(s string) bool { return s == "user lab-ro password <secret>" })
		})
		wantDifference(t, res, "breakglass", "wti.breakglass.password", "tacacs", "ACCESS", "user lab-ro password <secret>", "")
		// its other credentials are a finding
		res = wtiCompare(t, secs, "breakglass", appendLines("user lab-ro keys <secret>"))
		wantDifference(t, res, "breakglass", "wti.breakglass.password", "tacacs", "ACCESS", "", "user lab-ro keys <secret>")
	},
}

func TestEveryWTIRowHasACase(t *testing.T) {
	for _, r := range wtiOwned {
		if wtiRowCases[r.ID] == nil {
			t.Errorf("WTI row %s has no case", r.ID)
		}
	}
	for id := range wtiRowCases {
		if !slices.ContainsFunc(wtiOwned, func(r OwnedRow) bool { return r.ID == id }) {
			t.Errorf("case %s names no WTI row", id)
		}
	}
}

func TestWTIOwnedRows(t *testing.T) {
	for id, c := range wtiRowCases {
		t.Run(id, c)
	}
}

// The table's own shape: the family's table is the WTI one, IDs unique and
// of the family, a section of a unit, a mode and a why-line on every row.
func TestWTIOwnedTableIsWellFormed(t *testing.T) {
	if got := OwnedTable(devconf.FamilyWTI); !slices.Equal(got, wtiOwned) || len(got) == 0 {
		t.Fatalf("OwnedTable(wti) is not the WTI table")
	}
	seen := map[string]bool{}
	for _, r := range wtiOwned {
		switch {
		case seen[r.ID]:
			t.Errorf("duplicate row %s", r.ID)
		case !strings.HasPrefix(r.ID, "wti."+r.Section+"."):
			t.Errorf("row %s is not of section %s", r.ID, r.Section)
		case !slices.Contains([]string{devconf.SectionAAA, devconf.SectionSNMP, devconf.SectionMgmtACL, devconf.SectionBreakGlass}, r.Section):
			t.Errorf("row %s: a unit has no %s section", r.ID, r.Section)
		case r.Mode == "" || r.Why == "" || r.Pattern == "":
			t.Errorf("row %s: %+v", r.ID, r)
		case r.Block || r.Depth != 0:
			t.Errorf("row %s: block and depth are not a unit's", r.ID)
		}
		if (r.Mode == ModeList) != r.Ordered {
			t.Errorf("row %s: mode %s, ordered %v", r.ID, r.Mode, r.Ordered)
		}
		seen[r.ID] = true
	}
	// the Junos and IOS tables are the ones they were
	if &OwnedTable("juniper")[0] != &junosOwned[0] || &OwnedTable("ios")[0] != &iosOwned[0] {
		t.Errorf("the Junos and IOS tables moved")
	}
}

// Every statement tacctl renders for a unit is of a row of its section, and
// the row is one of the rendered kind (not the unit's own).
func TestEveryRenderedWTIStatementIsOwned(t *testing.T) {
	for _, name := range []string{"wti", "wti-radius"} {
		proto := "tacacs"
		if strings.HasSuffix(name, "-radius") {
			proto = "radius"
		}
		for _, scope := range []string{"lab", "prod", "prod-inner", "dmz"} {
			for _, s := range goldenSections(t, "managed."+name+"."+scope+".txt") {
				for _, l := range s.Lines {
					id := WTIRowID(s.Name, l, proto)
					row := OwnedByID(devconf.FamilyWTI, id)
					switch {
					case id == "":
						t.Errorf("%s/%s/%s: %q is of no row", name, scope, s.Name, l)
					case row.Section != s.Name:
						t.Errorf("%s/%s/%s: %q is of row %s, section %s", name, scope, s.Name, l, id, row.Section)
					case id == "wti.aaa.radius-unrendered" || id == "wti.aaa.inactive-protocol":
						t.Errorf("%s/%s/%s: %q is rendered and the unit's own", name, scope, s.Name, l)
					}
				}
			}
		}
	}
}

// The comparison's shapes of a unit's own statements are named by rows, and
// the resolver names that row for a statement of the shape.
func TestWTIShapesResolveToTheirRows(t *testing.T) {
	for _, s := range devconf.KeptShapes(devconf.FamilyWTI) {
		row := OwnedByID(devconf.FamilyWTI, s.Row)
		if row.ID == "" || row.Kept == "" {
			t.Errorf("shape %q names row %q: no such row, or nothing kept", s.Pattern, s.Row)
			continue
		}
		stmt := strings.ReplaceAll(s.Pattern, "$", "1") + " x"
		proto := "radius"
		if strings.HasPrefix(s.Pattern, "radius") && s.Row == "wti.aaa.inactive-protocol" {
			proto = "tacacs"
		}
		if got := WTIRowID(row.Section, stmt, proto); got != s.Row {
			t.Errorf("shape %q: %q is of row %q, want %q", s.Pattern, stmt, got, s.Row)
		}
	}
	// the named rows the design lists
	for _, id := range []string{"wti.snmp.system-name", "wti.snmp.trap-manager", "wti.snmp.trap-community", "wti.snmp.trap-version",
		"wti.snmp.trap-engine-id", "wti.aaa.radius-unrendered", "wti.aaa.inactive-protocol", "wti.mgmt-acl.list"} {
		if r := OwnedByID(devconf.FamilyWTI, id); r.ID == "" || r.Kept == "" {
			t.Errorf("row %s: %+v", id, r)
		}
	}
}
