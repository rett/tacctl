package plan

// 0.2.7: the SNMP community labels. A community's name is shown as its label
// ('<secret:N>' for the rendering's, '<other:N>' for the device's own), so a
// leaf of another community is never deleted under tacctl's name, and
// another community's statement never stands for one of tacctl's.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// The device's own community, its clients and its trap group are kept; no
// delete under a community is emitted.
func TestOtherCommunityIsKept(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-communities")
	d := planJ(t, f, nil, Options{})
	noLine(t, d, "snmp", "delete snmp community")
	for _, k := range []string{"snmp community <other:1> authorization read-only", "snmp community <other:1> clients 192.0.2.10/32",
		"snmp community <other:1> clients 198.51.100.7/32", "snmp community <other:1> clients 0.0.0.0/0 restrict",
		"snmp trap-group <other:1> targets 198.51.100.7", "snmp trap-options source-address 192.0.2.250", "snmp name js1.lab.example.net"} {
		wantKept(t, d, "snmp", k)
	}
	if len(d.Unattributed) != 0 {
		t.Errorf("unattributed: %v", d.Unattributed)
	}
	if out := Block(d, f.header(), Wrapper{ConfirmMinutes: 5}); strings.Contains(out, "other-example") {
		t.Errorf("the output names another community:\n%s", out)
	}
}

// Another community's 'authorization' does not stand for tacctl's: the
// rendered community gets its own.
func TestOtherCommunityDoesNotSatisfyTheRenderedOne(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-communities")
	d := planJ(t, f, func(c *JunosConfig) {
		c.Remove("set snmp community lab-ro-community authorization read-only")
	}, Options{})
	wantLine(t, d, "snmp", "set snmp community <secret:1> authorization read-only")
	noLine(t, d, "snmp", "delete ")
	var typed bool
	for _, l := range d.Lines {
		typed = typed || l.Text == "set snmp community lab-ro-community authorization read-only" && l.HasValue
	}
	if !typed {
		t.Errorf("the rendered community's authorization is not typed by value:\n%s", d.Display())
	}
}

// A stray leaf of tacctl's own community is deleted, exactly that leaf,
// under the community's own name.
func TestStrayLeafOfTheRenderedCommunityIsDeleted(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-communities")
	d := planJ(t, f, add("set snmp community lab-ro-community clients 203.0.113.0/24"), Options{})
	if got := lines(d, "snmp"); len(got) != 1 || got[0] != "delete snmp community <secret:1> clients 203.0.113.0/24" {
		t.Errorf("the snmp lines: %q", got)
	}
	var real string
	for _, l := range d.Lines {
		if l.HasValue && strings.HasPrefix(l.Text, "delete snmp community ") {
			real = l.Text
		}
	}
	if real != "delete snmp community lab-ro-community clients 203.0.113.0/24" {
		t.Errorf("the delete: %q", real)
	}
	nd := planJ(t, f, add("set snmp community lab-ro-community clients 203.0.113.0/24"), Options{NoSecrets: true})
	wantLine(t, nd, "snmp", "delete snmp community <secret:1> clients 203.0.113.0/24")
	for _, l := range nd.Lines {
		if strings.Contains(l.Text, "lab-ro-community") {
			t.Errorf("--no-secrets types the name: %q", l.Text)
		}
	}
}

// A record of an older tacctl (every community's name the bare mark): the
// communities compare by presence, and nothing under a community is
// emitted: the statements are left alone, unattributed, and said so.
func TestOlderRecordLeavesCommunitiesAlone(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-communities")
	exp, cur, _ := f.load(t)
	old := devconf.Extracted{Vendor: cur.Vendor, SecretsVisible: true, Sections: map[string]devices.Section{}}
	for name, s := range cur.Sections {
		var ls []string
		for _, l := range s.Lines {
			ls = append(ls, reMarks.ReplaceAllString(l, secretMark))
		}
		old.Sections[name] = devices.Section{Name: name, Lines: ls}
	}
	d, err := Plan(f.vendor, exp, old, old, f.options())
	if err != nil {
		t.Fatal(err)
	}
	noLine(t, d, "snmp", "delete snmp community")
	if len(d.Unattributed) != 4 {
		t.Errorf("unattributed: %q", d.Unattributed)
	}
	out := flat(Block(d, f.header(), Wrapper{ConfirmMinutes: 5}))
	for _, want := range []string{"Left alone (the community's name is not visible)",
		"Note: the pull was made by an older tacctl and does not tell the SNMP communities apart; left alone: 4 statements under a community (the community's name is not visible)."} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	rs, err := devconf.CompareAll(exp, old)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP && (len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "older tacctl")) {
			t.Errorf("the comparison does not say the record is older: %q", r.Notes)
		}
	}
}

// --- the device's own statements (ok (+N unmanaged)) ---------------------------

func snmpResult(t *testing.T, f fixture, mut func(c *JunosConfig)) devconf.SectionResult {
	t.Helper()
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	if mut != nil {
		mut(c)
	}
	cur, err := devconf.Extract(f.vendor, c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := devconf.CompareAll(exp, cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP {
			return r
		}
	}
	t.Fatal("no snmp result")
	return devconf.SectionResult{}
}

// A section that lacks nothing and holds the device's own statements only is
// ok, with their number; a stray leaf of tacctl's own community is a
// difference.
func TestSectionWithTheDevicesOwnStatementsIsOK(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-communities")
	r := snmpResult(t, f, nil)
	if r.State != devconf.StateOK || r.Unmanaged != 11 || r.StateText() != "ok (+11 unmanaged)" {
		t.Errorf("%s %d %q:\n%v", r.State, r.Unmanaged, r.StateText(), r.Lines)
	}
	for _, l := range r.Lines {
		if l.Op == devconf.OpExtra && !l.Unmanaged {
			t.Errorf("an extra that is not the device's own: %q", l.Text)
		}
	}
	if got := r.UnmanagedNote(); got != "11 statements of the device's own, kept on purpose" {
		t.Errorf("the note: %q", got)
	}
	for name, mut := range map[string]func(c *JunosConfig){
		"a stray leaf of tacctl's community":    add("set snmp community lab-ro-community clients 203.0.113.0/24"),
		"a stray entry of tacctl's client list": add("set snmp client-list TACCTL-SNMP 203.0.113.9/32"),
		"tacctl's community lacks a statement": func(c *JunosConfig) {
			c.Remove("set snmp community lab-ro-community authorization read-only")
		},
		"another location than the rendered one": func(c *JunosConfig) {
			c.Remove(`set snmp location "Rack 4, DC1"`)
			c.Add(`set snmp location "Rack 5"`)
		},
	} {
		if r := snmpResult(t, f, mut); r.State != devconf.StateDiffers {
			t.Errorf("%s: %s", name, r.State)
		}
	}
}

// keptExamples are, per ownership row with a Kept column, a statement of
// that shape (as a pull shows it) and whether it is the device's own. Only
// the snmp rows are: an extra of the other sections (another server, class,
// user, filter or list) is a finding about who can log in, and stays a
// difference. unrender is a rendered statement taken out first (what is kept
// when tacctl renders none); dropped is a statement the comparison does not
// count at all.
var keptExamples = map[string]struct {
	stmt      string
	unmanaged bool
	unrender  string
	dropped   bool
	// radius: the unit is read against the RADIUS rendering (a WTI unit
	// whose scope uses RADIUS, with TACACS+ turned off) and not the lab
	// unit's TACACS+ one
	radius bool
}{
	"junos.roles.class":       {stmt: "set system login class OTHER-CLASS permissions view", unmanaged: false},
	"junos.roles.user-class":  {stmt: "set system login user OTHER-CLASS class OTHER-CLASS", unmanaged: false},
	"junos.aaa.tacplus":       {stmt: "set system tacplus-server 192.0.2.98 port 4949", unmanaged: false},
	"junos.aaa.radius":        {stmt: "set system radius-server 192.0.2.98 port 1812", unmanaged: false},
	"junos.snmp.client-list":  {stmt: "set snmp client-list OTHER-LIST 192.0.2.7/32", unmanaged: true},
	"junos.snmp.community":    {stmt: "set snmp community <other:2> authorization read-only", unmanaged: true},
	"junos.snmp.trap-group":   {stmt: "set snmp trap-group <other:2> targets 192.0.2.7", unmanaged: true},
	"junos.snmp.trap-options": {stmt: "set snmp trap-options agent-address outgoing-interface", unmanaged: true},
	"junos.snmp.v3-user":      {stmt: "set snmp v3 usm local-engine user other-user authentication-none", unmanaged: true},
	"junos.snmp.view":         {stmt: "set snmp view OTHER-VIEW oid .1 include", unmanaged: true},
	"junos.snmp.location":     {stmt: `set snmp location "Rack 5"`, unmanaged: true, unrender: "set snmp location"},
	"junos.snmp.contact":      {stmt: `set snmp contact "Other NOC"`, unmanaged: true, unrender: "set snmp contact"},
	"junos.snmp.description":  {stmt: `set snmp description "Other switch"`, unmanaged: true, unrender: "set snmp description"},
	// 0.2.7: the system section is additive, so what the device holds
	// beside the block's statements is its own (the stems of the compared
	// form: the message is its mark)
	"junos.system.login-message":               {stmt: `set system login message "` + devconf.MessageMark("Another banner") + `"`, unmanaged: true, unrender: "set system login message"},
	"junos.system.domain-name":                 {stmt: "set system domain-name other.example.net", unmanaged: true, unrender: "set system domain-name"},
	"junos.system.time-zone":                   {stmt: "set system time-zone America/New_York", unmanaged: true, unrender: "set system time-zone"},
	"junos.system.ntp-boot-server":             {stmt: "set system ntp boot-server 192.0.2.99", unmanaged: true, unrender: "set system ntp boot-server"},
	"junos.system.ntp-source-address":          {stmt: "set system ntp source-address 192.0.2.99", unmanaged: true, unrender: "set system ntp source-address"},
	"junos.system.ntp-server-version":          {stmt: "set system ntp server 192.0.2.77 version 3", unmanaged: true},
	"junos.system.ntp-server-key":              {stmt: "set system ntp server 192.0.2.77 key 3", unmanaged: true},
	"junos.system.ntp-server-routing-instance": {stmt: "set system ntp server 192.0.2.77 routing-instance mgmt", unmanaged: true},
	"junos.system.domain-search":               {stmt: "set system domain-search example.net", unmanaged: true},
	"junos.system.name-server":                 {stmt: "set system name-server 198.51.100.53", unmanaged: true},
	"junos.system.ntp-server":                  {stmt: "set system ntp server ntp.example.net", unmanaged: true},
	"junos.system.ntp-key":                     {stmt: "set system ntp authentication-key 9 value", unmanaged: true},
	"junos.system.ntp-trusted-key":             {stmt: "set system ntp trusted-key 9", unmanaged: true},
	"junos.mgmt-acl.filter":                    {stmt: "set firewall family inet filter OTHER-ACL term t then accept", unmanaged: false},
	"ios.aaa.method-list":                      {stmt: "aaa authentication login OTHER local", unmanaged: false},
	"ios.aaa.console-list":                     {stmt: "aaa authentication login OTHER local", unmanaged: false},
	"ios.aaa.enable-list":                      {stmt: "aaa authentication enable OTHER enable", unmanaged: false},
	"ios.aaa.source-interface":                 {stmt: "ip tacacs source-interface Loopback0", unmanaged: false, dropped: true},
	"ios.aaa.console-leaf":                     {stmt: "line con 0 > exec-timeout 5 0", unmanaged: false},
	"ios.aaa.vty-leaf":                         {stmt: "line vty 0 4 > exec-timeout 5 0", unmanaged: false},
	"ios.aaa.server-block":                     {stmt: "tacacs server OTHER > address ipv4 192.0.2.98", unmanaged: false},
	"ios.aaa.radius-block":                     {stmt: "radius server OTHER > address ipv4 192.0.2.98", unmanaged: false},
	"ios.aaa.legacy-host":                      {stmt: "tacacs-server host 192.0.2.98", unmanaged: false},
	"ios.aaa.legacy-radius-host":               {stmt: "radius-server host 192.0.2.98", unmanaged: false},
	"ios.aaa.group":                            {stmt: "aaa group server tacacs+ OTHER > server name OTHER", unmanaged: false},
	"ios.aaa.radius-group":                     {stmt: "aaa group server radius OTHER > server name OTHER", unmanaged: false},
	"ios.roles.privilege":                      {stmt: "privilege exec level 9 show", unmanaged: false},
	"ios.snmp.community":                       {stmt: "snmp-server community <other:2> RO", unmanaged: true},
	"ios.snmp.location":                        {stmt: "snmp-server location Rack 5", unmanaged: true, unrender: "snmp-server location"},
	"ios.snmp.contact":                         {stmt: "snmp-server contact Other NOC", unmanaged: true, unrender: "snmp-server contact"},
	"ios.snmp.acl":                             {stmt: "ip access-list standard OTHER-SNMP > permit 192.0.2.7", unmanaged: true},
	"ios.mgmt-acl.acl":                         {stmt: "ip access-list standard OTHER-VTY > permit 192.0.2.7", unmanaged: false},
	// 0.2.7: a WTI unit. The unit's own are the system name, the trap
	// settings, the RADIUS items the walkthrough leaves alone, the page of a
	// protocol that is off, and the tail of the IP tables list; a second
	// server, a read/write community, a V3 user and a local account nobody
	// recorded are findings.
	"wti.aaa.tacacs":            {stmt: "tacacs secondary 192.0.2.43", unmanaged: false},
	"wti.aaa.radius":            {stmt: "radius secondary 192.0.2.43", unmanaged: false, radius: true},
	"wti.aaa.radius-unrendered": {stmt: "radius session-module disabled", unmanaged: true, radius: true},
	"wti.aaa.inactive-protocol": {stmt: "radius secondary 192.0.2.99", unmanaged: true},
	"wti.snmp.rw-community":     {stmt: "snmp rw-community <other:2>", unmanaged: false},
	"wti.snmp.system-name":      {stmt: "snmp system-name other-name", unmanaged: true},
	"wti.snmp.contact":          {stmt: "snmp contact someone", unmanaged: true, unrender: "snmp contact"},
	"wti.snmp.location":         {stmt: "snmp location Anchorage", unmanaged: true, unrender: "snmp location"},
	"wti.snmp.trap-manager":     {stmt: "snmp trap manager 2 192.0.2.35", unmanaged: true},
	"wti.snmp.trap-community":   {stmt: "snmp trap community <other:2>", unmanaged: true},
	"wti.snmp.trap-version":     {stmt: "snmp trap version v1", unmanaged: true},
	"wti.snmp.trap-engine-id":   {stmt: "snmp trap engine-id 0x80001234", unmanaged: true},
	"wti.snmp.v3":               {stmt: "snmp v3 user other-user", unmanaged: false},
	"wti.mgmt-acl.list":         {stmt: "iptables -A INPUT -j DROP", unmanaged: true, unrender: "iptables -A INPUT -j DROP"},
	"wti.breakglass.level":      {stmt: "user other-admin level administrator", unmanaged: false},
	"wti.breakglass.password":   {stmt: "user localadmin keys <secret>", unmanaged: false},
}

// The comparison's shapes of the device's own statements are in step with
// the ownership rows: every row with a Kept column has an example, a row
// that a shape names is the device's own in the comparison (and the planner
// keeps it), the others are findings, and every shape names a row of its
// family or none. Junos and IOS have shapes in the snmp and system rows
// only; a unit's are in the aaa, snmp and mgmt-acl rows.
func TestKeptShapesFollowTheOwnedRows(t *testing.T) {
	for _, fam := range []string{devconf.FamilyJunos, devconf.FamilyIOS, devconf.FamilyWTI} {
		rows := map[string]OwnedRow{}
		for _, r := range OwnedTable(fam) {
			rows[r.ID] = r
		}
		shaped := map[string]bool{}
		for _, s := range devconf.KeptShapes(fam) {
			shaped[s.Row] = true
			ok := false
			r, named := rows[s.Row]
			switch fam {
			case devconf.FamilyWTI:
				ok = named && r.Kept != "" && slices.Contains([]string{devconf.SectionAAA, devconf.SectionSNMP, devconf.SectionMgmtACL}, r.Section)
			default:
				ok = named && (r.Section == devconf.SectionSNMP || r.Section == devconf.SectionSystem)
			}
			if s.Row != "" && !ok {
				t.Errorf("%s: shape %q names %q, not a row of the table that keeps something of the device's own", fam, s.Pattern, s.Row)
			}
		}
		for _, r := range OwnedTable(fam) {
			if r.Kept == "" {
				continue
			}
			ex, ok := keptExamples[r.ID]
			if !ok {
				t.Errorf("%s has a Kept column and no example: is what it keeps the device's own?", r.ID)
				continue
			}
			if ex.unmanaged != shaped[r.ID] {
				t.Errorf("%s: unmanaged %v, and a shape names the row: %v", r.ID, ex.unmanaged, shaped[r.ID])
			}
			var exp []devices.Section
			var dev devices.Section
			switch {
			case fam == devconf.FamilyWTI && ex.radius:
				// a RADIUS scope's unit: what the rendering holds, as the
				// unit prints it, and TACACS+ turned off
				exp = goldenSections(t, "managed.wti-radius.lab.txt")
				want := sectionNamed(exp, r.Section)
				for i, l := range want.Lines {
					if f := strings.Fields(l); want.Secret[i] && len(f) > 0 {
						f[len(f)-1] = "<secret>"
						l = strings.Join(f, " ")
					}
					dev.Lines = append(dev.Lines, l)
				}
				dev.Lines = append(dev.Lines, "tacacs enable off")
				dev.Name = r.Section
			case fam == devconf.FamilyWTI:
				e := expectedSections(t, "wti/lab-unit/expected.txt")
				cur, err := devconf.Extract("wti", capture(t, "wti/lab-unit/document.txt"), e...)
				if err != nil {
					t.Fatal(err)
				}
				exp, dev = e, cur.Sections[r.Section]
			case fam == devconf.FamilyJunos:
				fixture := "juniper.synthetic-communities"
				if r.Section == devconf.SectionSystem {
					fixture = "juniper.synthetic-system"
				}
				f := fixtureNamed(t, fixture)
				e, cur, _ := f.load(t)
				exp, dev = e, cur.Sections[r.Section]
			default:
				f := fixtureNamed(t, "cisco.reference-lab")
				e, cur, _ := f.load(t)
				exp, dev = e, cur.Sections[r.Section]
			}
			want := sectionNamed(exp, r.Section)
			if ex.unrender != "" {
				var keep devices.Section
				for i, l := range want.Lines {
					if !strings.HasPrefix(l, ex.unrender) {
						keep.Lines, keep.Secret = append(keep.Lines, l), append(keep.Secret, want.Secret[i])
					}
				}
				keep.Name, want = want.Name, keep
				var dkeep []string
				for _, l := range dev.Lines {
					if !strings.HasPrefix(l, ex.unrender) {
						dkeep = append(dkeep, l)
					}
				}
				dev.Lines = dkeep
			}
			// the stored form: a secret is known by its mark
			dev.Lines, dev.Secret = append(slices.Clone(dev.Lines), ex.stmt), nil
			res, err := devconf.Compare(fam, want, dev, true)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, l := range res.Lines {
				if l.Op == devconf.OpExtra && strings.HasPrefix(l.Text, strings.SplitN(ex.stmt, " (", 2)[0]) {
					found = true
					if l.Unmanaged != ex.unmanaged {
						t.Errorf("%s: %q unmanaged %v, want %v", r.ID, ex.stmt, l.Unmanaged, ex.unmanaged)
					}
				}
			}
			if found == ex.dropped {
				t.Errorf("%s: %q is an extra of the comparison: %v, want %v", r.ID, ex.stmt, found, !ex.dropped)
			}
		}
	}
}

func sectionNamed(secs []devices.Section, name string) devices.Section {
	for _, s := range secs {
		if s.Name == name {
			return s
		}
	}
	return devices.Section{Name: name}
}

// What the comparison calls the device's own the planner leaves alone: for
// every fixture, no line of the plan answers an unmanaged statement, and
// each is kept.
func TestUnmanagedStatementsAreKeptByThePlanner(t *testing.T) {
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		rs, err := devconf.CompareAll(exp, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			for _, l := range r.Lines {
				if !l.Unmanaged {
					continue
				}
				stem := strings.TrimSuffix(l.Text, " (present, not compared)")
				for _, pl := range d.Lines {
					if slices.Contains(pl.For, stem) {
						t.Errorf("%s: the plan answers the device's own %q with %q", f.name, stem, pl.Text)
					}
				}
				if !slices.ContainsFunc(d.Kept, func(k Kept) bool { return k.Section == r.Name && k.Text == stem }) &&
					!slices.Contains(d.Withheld, stem) && d.Of(r.Name).State != StateSkipped {
					t.Errorf("%s: the device's own %q is not kept", f.name, stem)
				}
			}
		}
	}
}
