package devices

// The managed sections of a WTI unit (wti_managed.go): the statements pinned
// in goldens per protocol and fixture scope, every value tied to the
// walkthrough of the same input, the secrets marked, and the purity every
// Managed has.

import (
	"errors"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// wtiVariants are the two WTI variants of the shared table.
func wtiVariants(t testing.TB) []variant {
	t.Helper()
	out := variants[5:7]
	if out[0].vendor != "wti" || out[1].vendor != "wti" {
		t.Fatalf("the WTI variants moved: %+v", out)
	}
	return out
}

// wtiManagedText is a golden's text of the sections.
func wtiManagedText(secs []Section) string { return managedText(secs) }

func TestManagedWTIGoldens(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			golden(t, "managed."+v.name+"."+p.scope+".txt", wtiManagedText(mustManaged(t, req, d)))
		}
	}
}

// The shape: sections in the order of the others, no section empty, Secret
// as long as Lines, no comment among the statements, and none of the
// sections a unit has nothing in.
func TestManagedWTIShape(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			secs := mustManaged(t, req, d)
			last := -1
			for _, s := range secs {
				at := slices.Index(managedSectionNames, s.Name)
				if at <= last {
					t.Errorf("%s/%s: section %q out of order or unknown", v.name, p.scope, s.Name)
				}
				last = at
				if s.Name == "roles" || s.Name == "netconf" || s.Name == "system" {
					t.Errorf("%s/%s: a %s section on a unit", v.name, p.scope, s.Name)
				}
				if len(s.Lines) == 0 || len(s.Lines) != len(s.Secret) || s.Block != nil {
					t.Errorf("%s/%s/%s: %d lines, %d marks, block %v", v.name, p.scope, s.Name, len(s.Lines), len(s.Secret), s.Block)
				}
				for _, l := range s.Lines {
					if tl := strings.TrimSpace(l); tl == "" || strings.HasPrefix(tl, "#") || strings.HasPrefix(tl, "!") || tl != l {
						t.Errorf("%s/%s/%s: %q is no statement", v.name, p.scope, s.Name, l)
					}
				}
			}
			if _, ok := sectionOf(secs, "aaa"); !ok {
				t.Errorf("%s/%s: no aaa section", v.name, p.scope)
			}
		}
	}
	// what a scope with no SNMP, permit list and accounts is not told it
	// lacks
	req, d := managedProfiles()[2].input(m, c, wtiVariants(t)[0])
	secs := mustManaged(t, req, d)
	if len(secs) != 1 || secs[0].Name != "aaa" {
		t.Errorf("prod-inner: %v", wtiManagedText(secs))
	}
}

// walkSteps are the steps of a WTI walkthrough, by number: the text between
// 'Step N:' and the next step.
func walkSteps(text string) map[int][]string {
	steps := map[int][]string{}
	re := regexp.MustCompile(`^Step (\d+):`)
	cur := 0
	for _, l := range strings.Split(text, "\n") {
		if m := re.FindStringSubmatch(l); m != nil {
			cur = 0
			for _, r := range m[1] {
				cur = cur*10 + int(r-'0')
			}
		}
		if cur != 0 {
			steps[cur] = append(steps[cur], l)
		}
	}
	return steps
}

var reMenuItem = regexp.MustCompile(`^\s*(?:\d+\.\s+)?([A-Za-z][A-Za-z0-9/ ()-]*?)\s+:\s*(.*)$`)

// menuItems are the 'label : value' items of a step, a value's continuation
// lines (no label) joined to it.
func menuItems(lines []string) (labels []string, values map[string]string) {
	values = map[string]string{}
	last := ""
	for _, l := range lines {
		if m := reMenuItem.FindStringSubmatch(l); m != nil {
			last = m[1]
			if _, dup := values[last]; !dup {
				labels = append(labels, last)
			}
			values[last] = strings.TrimSpace(m[2])
			continue
		}
		if t := strings.TrimSpace(l); last != "" && t != "" && strings.HasPrefix(l, strings.Repeat(" ", 20)) {
			values[last] += " " + t
		}
	}
	return labels, values
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// wtiTie says how a statement key is read back from the item it is of: its
// label in the step and what the item's value says.
type wtiTie struct {
	label string
	got   func(v string) string
}

var wtiTies = map[string]wtiTie{
	"tacacs enable":           {"Enable", func(v string) string { return wtiSlug(firstWord(v)) }},
	"tacacs primary":          {"Primary Host/Address", firstWord},
	"tacacs secret":           {"Secret Word", firstWord},
	"tacacs fallback-timer":   {"Fallback Timer", firstWord},
	"tacacs fallback-local":   {"Fallback Local", wtiSlug},
	"tacacs port":             {"Authentication Port", firstWord},
	"tacacs default-access":   {"Default User Access", func(v string) string { return wtiSlug(strings.TrimPrefix(firstWordsOf(v, 2), "Enable ")) }},
	"tacacs default-level":    {"Default User Access", func(v string) string { return strings.ToLower(subMatch(`Access Level (\w+)`, v)) }},
	"tacacs default-services": {"Default User Access", func(v string) string { return wtiSlug(subMatch(`Service Access (\S+) On`, v)) }},
	"tacacs account-module":   {"Account Management Module", func(v string) string { return wtiSlug(firstWord(v)) }},
	"tacacs session-module":   {"Session Management Module", func(v string) string { return wtiSlug(firstWord(v)) }},
	"tacacs service-name":     {"Service Name", firstWord},
	"tacacs debug":            {"Debug", func(v string) string { return wtiSlug(firstWord(v)) }},

	"radius enable":          {"Enable", func(v string) string { return wtiSlug(firstWord(v)) }},
	"radius primary":         {"Primary Host/Address (IPv4)", firstWord},
	"radius primary-secret":  {"Primary Secret Word", firstWord},
	"radius fallback-timer":  {"Fallback Timer", firstWord},
	"radius fallback-local":  {"Fallback Local", wtiSlug},
	"radius retries":         {"Retries", firstWord},
	"radius port":            {"Authentication Port", firstWord},
	"radius accounting-port": {"Accounting Port", firstWord},
	"radius onetime-auth":    {"OneTime Auth", func(v string) string { return wtiSlug(firstWord(v)) }},
	"radius default-access":  {"Default RADIUS User Access", func(v string) string { return wtiSlug(strings.TrimPrefix(firstWordsOf(v, 2), "Enable ")) }},
	"radius debug":           {"Debug", func(v string) string { return wtiSlug(firstWord(v)) }},

	"snmp enable":    {"Enable", func(v string) string { return wtiSlug(firstWord(v)) }},
	"snmp read-only": {"Read Only", func(v string) string { return wtiSlug(firstWord(v)) }},
	"snmp version": {"Version", func(v string) string {
		switch lv := strings.ToLower(v); {
		case strings.HasPrefix(lv, "v1/v2 only"):
			return "v1-v2-only"
		case strings.HasPrefix(lv, "v3"):
			return "v3"
		}
		return wtiSlug(firstWord(v))
	}},
	"snmp ro-community":          {"Read-only Community", func(v string) string { return v }},
	"snmp contact":               {"Contact", func(v string) string { return v }},
	"snmp location":              {"SNMP Location", func(v string) string { return v }},
	"snmp v3 user":               {"SNMPv3 User", func(v string) string { return v }},
	"snmp v3 auth-protocol":      {"Authentication Protocol", wtiSlug},
	"snmp v3 auth-passphrase":    {"Authentication Passphrase", func(v string) string { return v }},
	"snmp v3 privacy-protocol":   {"Privacy Protocol", wtiSlug},
	"snmp v3 privacy-passphrase": {"Privacy Passphrase", func(v string) string { return v }},
}

func firstWordsOf(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

func subMatch(pattern, s string) string {
	if m := regexp.MustCompile(pattern).FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// wtiKeyOf splits a statement into its key (the longest in wtiTies) and its
// value, unquoted.
func wtiKeyOf(line string) (key, value string, ok bool) {
	for k := range wtiTies {
		if rest, found := strings.CutPrefix(line, k+" "); found && len(k) > len(key) {
			key, value, ok = k, strings.Trim(rest, `"`), true
		}
	}
	return key, value, ok
}

// firstIptablesBlock is the lines of the first <iptables> block of a
// walkthrough (Step 5's; the last step's is another).
func firstIptablesBlock(text string) []string {
	var block []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		switch {
		case l == "<iptables>":
			in = true
		case l == "</iptables>" && in:
			return block
		case in:
			block = append(block, l)
		}
	}
	return nil
}

// The tie of the plan (D63) for a unit: every value of every statement is
// what the walkthrough of the same input tells the unit, item by item, for
// both protocols and every fixture scope; the IP tables list is the
// <iptables> block of Step 5 as it is; a break-glass account is a line of
// Step 10.
func TestManagedWTIStatementsAreInTheWalkthrough(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			text := renderText(t, req, d)
			steps := walkSteps(text)
			_, step3 := menuItems(steps[3])
			_, step6 := menuItems(steps[6])
			for _, s := range mustManaged(t, req, d) {
				for i, l := range s.Lines {
					switch s.Name {
					case "mgmt-acl":
						// checked as a block below
					case "breakglass":
						name, rest, _ := strings.Cut(strings.TrimPrefix(l, "user "), " ")
						var line string
						for _, w := range steps[10] {
							if strings.HasPrefix(strings.TrimSpace(w), name+" ") {
								line = w
							}
						}
						key, value, _ := strings.Cut(rest, " ")
						switch {
						case line == "":
							t.Errorf("%s/%s: no line of Step 10 for %q", v.name, p.scope, l)
						case key == "level" && !strings.Contains(strings.ToLower(line), "access level: "+value+" "):
							t.Errorf("%s/%s: %q is not %q", v.name, p.scope, line, l)
						case key == "password" && !strings.Contains(line, "Password: "+value):
							t.Errorf("%s/%s: %q is not %q", v.name, p.scope, line, l)
						}
					default:
						key, value, ok := wtiKeyOf(l)
						tie := wtiTies[key]
						if !ok {
							// the two statements of an SNMP step that sets
							// nothing the step names: the unit's access is
							// enabled, and read-only (it has no writable
							// community here)
							if l == "snmp enable on" || l == "snmp read-only yes" {
								if _, named := step6["Read-only Community"]; !named && req.Vendor == "wti" && !strings.Contains(strings.Join(steps[6], "\n"), "SNMPv3 User") {
									t.Errorf("%s/%s: %q, and Step 6 names no credential", v.name, p.scope, l)
								}
								continue
							}
							t.Errorf("%s/%s/%s: %q has no tie to the walkthrough", v.name, p.scope, s.Name, l)
							continue
						}
						items := step3
						if s.Name == "snmp" {
							items = step6
						}
						raw, found := items[tie.label]
						if !found {
							t.Errorf("%s/%s: %q: the walkthrough has no item %q", v.name, p.scope, l, tie.label)
							continue
						}
						if got := tie.got(raw); got != value {
							t.Errorf("%s/%s: %q: the walkthrough says %q (item %q: %q)", v.name, p.scope, l, got, tie.label, raw)
						}
						if s.Secret[i] != wtiSecret(l) {
							t.Errorf("%s/%s: %q: secret mark", v.name, p.scope, l)
						}
					}
				}
				if s.Name != "mgmt-acl" {
					continue
				}
				if block := firstIptablesBlock(text); !slices.Equal(block, s.Lines) {
					t.Errorf("%s/%s: the <iptables> block of Step 5 is not mgmt-acl:\n%s\n--- want\n%s",
						v.name, p.scope, strings.Join(block, "\n"), strings.Join(s.Lines, "\n"))
				}
			}
		}
	}
}

// The other direction: every item of Step 3 that the walkthrough sets has a
// statement, but the secondary server it leaves undefined.
func TestManagedWTILeavesOutOnlyWhatItSays(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			labels, _ := menuItems(walkSteps(renderText(t, req, d))[3])
			covered := map[string]bool{}
			for _, s := range mustManaged(t, req, d) {
				if s.Name != "aaa" {
					continue
				}
				for _, l := range s.Lines {
					if key, _, ok := wtiKeyOf(l); ok {
						covered[wtiTies[key].label] = true
					}
				}
			}
			var left []string
			for _, l := range labels {
				if !covered[l] {
					left = append(left, l)
				}
			}
			if !slices.Equal(left, []string{"Secondary Host/Address"}) {
				t.Errorf("%s/%s: items of Step 3 with no statement: %q", v.name, p.scope, left)
			}
		}
	}
}

// Statements that carry a secret are marked, and only those.
func TestManagedWTISecretMarks(t *testing.T) {
	for _, c := range []struct {
		line string
		want bool
	}{
		{"tacacs secret lab-secret-0123456789abcdef", true},
		{"tacacs primary 192.0.2.10", false},
		{"tacacs service-name wti", false},
		{"radius primary-secret lab-secret-0123456789abcdef", true},
		{"radius secondary-secret x", true},
		{"radius primary 192.0.2.10", false},
		{"snmp ro-community lab-ro-community", true},
		{"snmp rw-community lab-rw-community", true},
		{"snmp trap community lab-ro-community", true},
		{"snmp contact secret room", false},
		{`snmp location "key room"`, false},
		{"snmp v3 auth-passphrase auth-pass-0123", true},
		{"snmp v3 privacy-passphrase priv-pass-4567", true},
		{"snmp v3 user tacctl-ro", false},
		{"user lab-admin password <PASSWORD>", true},
		{"user lab-admin level administrator", false},
		{"iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT", false},
	} {
		if got := wtiSecret(c.line); got != c.want {
			t.Errorf("%q: secret = %v, want %v", c.line, got, c.want)
		}
	}
}

// In the sections themselves: a statement that holds the scope's secret, the
// community or an SNMPv3 passphrase is marked, a placeholder password too,
// and no other.
func TestManagedWTISecretsAreTheStatementsThatCarryThem(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			values := []string{m.Scope(p.scope).Secret, breakGlassPassword}
			for _, s := range []string{p.snmp.Community, p.snmp.V3AuthPass, p.snmp.V3PrivPass} {
				if s != "" {
					values = append(values, s)
				}
			}
			marked := 0
			for _, s := range mustManaged(t, req, d) {
				for i, l := range s.Lines {
					holds := false
					for _, val := range values {
						holds = holds || strings.Contains(l, val)
					}
					if holds != s.Secret[i] {
						t.Errorf("%s/%s/%s: %q: carries a secret %v, marked %v", v.name, p.scope, s.Name, l, holds, s.Secret[i])
					}
					if s.Secret[i] {
						marked++
					}
				}
			}
			if marked == 0 {
				t.Errorf("%s/%s: no statement is marked", v.name, p.scope)
			}
		}
	}
}

func wtiLines(secs []Section, name string) []string {
	s, _ := sectionOf(secs, name)
	return s.Lines
}

func TestManagedWTIStatements(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	vs := wtiVariants(t)

	// TACACS+: the statements of Step 3, in its order; the lab scope is
	// local-first (Fallback Local on all failures).
	req, d := lab.input(m, c, vs[0])
	secs := mustManaged(t, req, d)
	want := []string{
		"tacacs enable on", "tacacs primary 10.0.0.42", "tacacs secret lab-secret-0123456789abcdef",
		"tacacs fallback-timer 15", "tacacs fallback-local on-all-failures", "tacacs port 49",
		"tacacs default-access on", "tacacs default-level viewonly", "tacacs default-services telnet-ssh",
		"tacacs account-module enabled", "tacacs session-module enabled", "tacacs service-name wti", "tacacs debug off",
	}
	if got := wtiLines(secs, "aaa"); !slices.Equal(got, want) {
		t.Errorf("tacacs aaa:\n%s", strings.Join(got, "\n"))
	}
	if aaa, _ := sectionOf(secs, "aaa"); !slices.Equal(aaa.Secret, []bool{false, false, true, false, false, false, false, false, false, false, false, false, false}) {
		t.Errorf("tacacs aaa marks: %v", aaa.Secret)
	}

	// RADIUS: the page of 29, the listener's ports, no secondary server, no
	// session module type.
	req, d = lab.input(m, c, vs[1])
	want = []string{
		"radius enable on", "radius primary 10.0.0.42", "radius primary-secret lab-secret-0123456789abcdef",
		"radius fallback-timer 3", "radius fallback-local on-all-failures", "radius retries 3", "radius port 1812",
		"radius accounting-port 1813", "radius onetime-auth off", "radius default-access on", "radius debug off",
	}
	if got := wtiLines(mustManaged(t, req, d), "aaa"); !slices.Equal(got, want) {
		t.Errorf("radius aaa:\n%s", strings.Join(got, "\n"))
	}

	// The IP tables list: the unit's own traffic, the server, each permitted
	// range (a plain entry is every protocol and port: one rule, and no ICMP
	// line of its own), the SNMP server, the pingers; no final DROP, no policy.
	req, d = lab.input(m, c, vs[0])
	acl := wtiLines(mustManaged(t, req, d), "mgmt-acl")
	for _, w := range []string{
		"iptables -A INPUT -i lo -j ACCEPT",
		"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -A INPUT -p tcp -s 10.0.0.42/32 --dport 22 -j ACCEPT",
		"iptables -A INPUT -s 198.51.100.0/24 -j ACCEPT",
		"iptables -A INPUT -s 192.0.2.0/24 -j ACCEPT",
		"iptables -A INPUT -p udp -s 198.51.100.0/24 --dport 161 -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 10.0.0.42/32 -p icmp -j ACCEPT",
	} {
		if !slices.Contains(acl, w) {
			t.Errorf("mgmt-acl lacks %q:\n%s", w, strings.Join(acl, "\n"))
		}
	}
	for _, l := range acl {
		if !strings.HasPrefix(l, "iptables -A INPUT ") || strings.Contains(l, "-j DROP") {
			t.Errorf("mgmt-acl has %q", l)
		}
	}
	if want := WTIIPTables(d.iptablesInput("lab")).Commands; !slices.Equal(acl, want) {
		t.Errorf("mgmt-acl is not the builder's list in order")
	}

	// SNMP v2c: the access page; the system name is the unit's own.
	want = []string{
		"snmp enable on", "snmp version v1-v2-only", "snmp read-only yes",
		`snmp contact "NOC <noc@example.net>"`, `snmp location "Rack 4, DC1"`, "snmp ro-community lab-ro-community",
	}
	snmp, _ := sectionOf(mustManaged(t, req, d), "snmp")
	if !slices.Equal(snmp.Lines, want) || !slices.Equal(snmp.Secret, []bool{false, false, false, false, false, true}) {
		t.Errorf("snmp: %q %v", snmp.Lines, snmp.Secret)
	}

	// SNMPv3 (prod): the builder's user, protocols and passphrases.
	req, d = managedProfiles()[1].input(m, c, vs[0])
	snmp, _ = sectionOf(mustManaged(t, req, d), "snmp")
	want = []string{
		"snmp enable on", "snmp version v3", "snmp read-only yes",
		`snmp contact "NOC <noc@example.net>"`, `snmp location "Rack 4, DC1"`,
		"snmp v3 user tacctl-ro", "snmp v3 auth-protocol sha", "snmp v3 auth-passphrase auth-pass-0123",
		"snmp v3 privacy-protocol aes-128", "snmp v3 privacy-passphrase priv-pass-4567",
	}
	if !slices.Equal(snmp.Lines, want) {
		t.Errorf("snmp v3:\n%s", strings.Join(snmp.Lines, "\n"))
	}
	// prod's permit list is a /8 and an IPv6 range (skipped): the list is the
	// IPv4 one
	acl = wtiLines(mustManaged(t, req, d), "mgmt-acl")
	if !slices.Contains(acl, "iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT") {
		t.Errorf("prod mgmt-acl:\n%s", strings.Join(acl, "\n"))
	}
	for _, l := range acl {
		if strings.Contains(l, "2001:db8") {
			t.Errorf("an IPv6 entry: %q", l)
		}
	}

	// The break-glass accounts: the level of the role's group, the password
	// as the placeholder.
	req, d = lab.input(m, c, vs[0])
	bg, _ := sectionOf(mustManaged(t, req, d), "breakglass")
	want = []string{
		"user lab-admin level administrator", "user lab-admin password <PASSWORD>",
		"user lab-ops level user", "user lab-ops password <PASSWORD>",
		"user lab-ro level viewonly", "user lab-ro password <PASSWORD>",
	}
	if !slices.Equal(bg.Lines, want) || !slices.Equal(bg.Secret, []bool{false, true, false, true, false, true}) {
		t.Errorf("breakglass: %q %v", bg.Lines, bg.Secret)
	}

	// --server is the address the unit is told (dmz); an unset contact and
	// location render nothing.
	req, d = managedProfiles()[3].input(m, c, vs[0])
	secs = mustManaged(t, req, d)
	if !slices.Contains(wtiLines(secs, "aaa"), "tacacs primary 203.0.113.9") {
		t.Errorf("dmz aaa:\n%s", strings.Join(wtiLines(secs, "aaa"), "\n"))
	}
	for _, l := range wtiLines(secs, "snmp") {
		if strings.HasPrefix(l, "snmp contact") || strings.HasPrefix(l, "snmp location") {
			t.Errorf("dmz snmp has %q", l)
		}
	}
}

// What the walkthrough leaves unfilled renders no statement.
func TestManagedWTIUnfilled(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	for _, v := range wtiVariants(t) {
		// the route lookup found no address: no server, and so no list (the
		// server's own lines are in it)
		req, d := lab.input(m, c, v)
		d.ServerIP = UnknownServer
		d.SNMP.Server = ""
		secs := mustManaged(t, req, d)
		for _, l := range wtiLines(secs, "aaa") {
			if strings.Contains(l, " primary ") || strings.Contains(l, "<") {
				t.Errorf("%s: aaa has %q with no server address", v.name, l)
			}
		}
		if _, ok := sectionOf(secs, "mgmt-acl"); ok {
			t.Errorf("%s: a list with no server address", v.name)
		}

		// no secret
		req, d = lab.input(m, c, v)
		if v.protocol == RADIUS {
			d.Radius.Secret = ""
		} else {
			m2, c2 := fixtureGroups(t, managedGroups, managedOverrides)
			m2.Scope("lab").Secret = ""
			req, d = lab.input(m2, c2, v)
		}
		for _, l := range wtiLines(mustManaged(t, req, d), "aaa") {
			if strings.Contains(l, "secret") {
				t.Errorf("%s: aaa has %q with no secret", v.name, l)
			}
		}
	}

	// no permit list, or the server's own /32 alone: no list
	vs := wtiVariants(t)
	for _, cidrs := range [][]string{nil, {"10.0.0.42/32"}, {"2001:db8::/32"}} {
		p := lab
		p.cidrs = cidrs
		req, d := p.input(m, c, vs[0])
		if _, ok := sectionOf(mustManaged(t, req, d), "mgmt-acl"); ok {
			t.Errorf("a list for permits %v", cidrs)
		}
	}

	// no SNMP: none of it; a v2c scope with no community has the access page
	// without one
	p := lab
	p.snmp = SNMPInput{}
	req, d := p.input(m, c, vs[0])
	if _, ok := sectionOf(mustManaged(t, req, d), "snmp"); ok {
		t.Error("an snmp section for a scope with no SNMP")
	}
	p.snmp = v2cAll
	p.snmp.Community = ""
	req, d = p.input(m, c, vs[0])
	for _, l := range wtiLines(mustManaged(t, req, d), "snmp") {
		if strings.Contains(l, "community") {
			t.Errorf("snmp has %q with no community", l)
		}
	}
	// a v3 scope with no user
	p.snmp = v3All
	p.snmp.V3User = ""
	req, d = p.input(m, c, vs[0])
	for _, l := range wtiLines(mustManaged(t, req, d), "snmp") {
		if strings.HasPrefix(l, "snmp v3 ") {
			t.Errorf("snmp has %q with no v3 user", l)
		}
	}
}

// A group's 'wti-level' is the level of its break-glass role, as the
// walkthrough's mapping table says.
func TestManagedWTIBreakGlassLevels(t *testing.T) {
	m, c := fixtureGroups(t, managedGroups, managedOverrides+"wti_level:\n  readonly: user\n  operator: superuser\n  superuser: superuser\n")
	req, d := managedProfiles()[0].input(m, c, wtiVariants(t)[0])
	got := wtiLines(mustManaged(t, req, d), "breakglass")
	want := []string{
		"user lab-admin level superuser", "user lab-admin password <PASSWORD>",
		"user lab-ops level superuser", "user lab-ops password <PASSWORD>",
		"user lab-ro level user", "user lab-ro password <PASSWORD>",
	}
	if !slices.Equal(got, want) {
		t.Errorf("breakglass:\n%s", strings.Join(got, "\n"))
	}
}

// The unit's own items are not rendered: the system name, the traps, the
// read/write community, the RADIUS items the walkthrough leaves alone, the
// tail of the IP tables list.
func TestManagedWTIDoesNotRenderTheUnitsOwn(t *testing.T) {
	m, c := managedWorld(t)
	both := []string{"snmp system-name", "snmp trap", "rw-community", "secondary", "-j DROP", "-P ", "-A OUTPUT"}
	radius := []string{"onetime-timer", "onetime-type", "session-module", "message-authenticator", "default-level", "default-services"}
	for _, v := range wtiVariants(t) {
		req, d := managedProfiles()[0].input(m, c, v)
		own := both
		if v.protocol == RADIUS {
			own = append(slices.Clone(both), radius...)
		}
		for _, s := range mustManaged(t, req, d) {
			for _, l := range s.Lines {
				for _, o := range own {
					if strings.Contains(l, o) {
						t.Errorf("%s: %q is the unit's own", v.name, l)
					}
				}
			}
		}
	}
}

// Managed reads only Request and Data, for a unit too: the same sections
// however often, in parallel, from another directory, environment and with
// the operator's templates; a caller's edit does not reach the next result.
func TestManagedWTIIsPure(t *testing.T) {
	m, c := managedWorld(t)
	type job struct {
		name string
		req  Request
		d    Data
		want []Section
	}
	var jobs []job
	for _, v := range wtiVariants(t) {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			jobs = append(jobs, job{v.name + "/" + p.scope, req, d, mustManaged(t, req, d)})
		}
	}
	tpl := t.TempDir()
	for _, name := range []string{"wti", "wti-radius"} {
		writeTemplate(t, tpl, name, "MINE ${SERVER_IP}\n")
	}
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TZ", "Pacific/Auckland")
	t.Setenv("LC_ALL", "C")
	for _, j := range jobs {
		d := j.d
		d.TemplateDir = tpl
		if got := mustManaged(t, j.req, d); !slices.EqualFunc(j.want, got, sectionEqual) {
			t.Errorf("%s: differs with the operator's templates and another environment", j.name)
		}
	}
	for _, j := range jobs {
		got := mustManaged(t, j.req, j.d)
		for i := range got {
			for k := range got[i].Lines {
				got[i].Lines[k] = "x"
				got[i].Secret[k] = !got[i].Secret[k]
			}
		}
		if again := mustManaged(t, j.req, j.d); !slices.EqualFunc(j.want, again, sectionEqual) {
			t.Errorf("%s: a caller's edit reached the next result", j.name)
		}
	}
	for _, j := range jobs {
		before := renderText(t, j.req, j.d)
		cidrs, ranges := slices.Clone(j.d.ACL.CIDRs), slices.Clone(j.d.SNMP.Ranges)
		mustManaged(t, j.req, j.d)
		if after := renderText(t, j.req, j.d); after != before ||
			!slices.Equal(cidrs, j.d.ACL.CIDRs) || !slices.Equal(ranges, j.d.SNMP.Ranges) {
			t.Errorf("%s: Managed changed its input", j.name)
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		for _, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := Managed(j.req, j.d)
				if err != nil || !slices.EqualFunc(j.want, got, sectionEqual) {
					t.Errorf("%s: differs in parallel (%v)", j.name, err)
				}
			}()
		}
	}
	wg.Wait()
}

// An engineer's walkthrough has the same statements, and a RADIUS unit needs
// Data.Radius as its walkthrough does.
func TestManagedWTIRestrictedAndRadius(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range wtiVariants(t) {
		req, d := managedProfiles()[0].input(m, c, v)
		want := mustManaged(t, req, d)
		d.Restricted = true
		if got := mustManaged(t, req, d); !slices.EqualFunc(want, got, sectionEqual) {
			t.Errorf("%s: an engineer's sections differ", v.name)
		}
	}
	req, d := managedProfiles()[0].input(m, c, wtiVariants(t)[1])
	d.Radius = nil
	if secs, err := Managed(req, d); err == nil || errors.Is(err, ErrUnsupported) || secs != nil {
		t.Errorf("radius without Prepare: %v %v", secs, err)
	}
}

// wti_managed.go reaches nothing but strings, patterns and the CIDR package
// the builders use.
func TestManagedWTIImportsNothingImpure(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "wti_managed.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		switch path := strings.Trim(imp.Path.Value, `"`); path {
		case "regexp", "strings", "github.com/rett/tacctl/internal/cidr":
		default:
			t.Errorf("wti_managed.go imports %q", path)
		}
	}
}

// The facts of the list builder that a unit's plan reads: the address the
// list must permit, and why a scope that has a permit list has no list.
func TestWTIListFacts(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	vs := wtiVariants(t)
	req, d := lab.input(m, c, vs[0])
	if server, why := WTIListFacts(req, d); server != "10.0.0.42" || why != "" {
		t.Errorf("facts %q %q", server, why)
	}
	// the route lookup found no address: the list is not built, and why
	d.ServerIP = UnknownServer
	if server, why := WTIListFacts(req, d); server != "" || !strings.Contains(why, "tacctl server address") || !strings.Contains(why, "--source") {
		t.Errorf("no server: %q %q", server, why)
	}
	// no permit list: no list is asked for, so nothing to explain
	p := lab
	p.cidrs = nil
	req, d = p.input(m, c, vs[0])
	d.ServerIP = UnknownServer
	if server, why := WTIListFacts(req, d); server != "" || why != "" {
		t.Errorf("no permits: %q %q", server, why)
	}
}

// A management ACL with services (0.2.7): the WTI list renders each entry's
// services, a plain entry as every protocol and port, and the Cisco and Junos
// sections list only the sources whose entries permit ssh, so a compare and a
// plan read what the walkthrough says.
func TestManagedMgmtACLServices(t *testing.T) {
	m, c := managedWorld(t)
	p := managedProfile{scope: "lab", snmp: v2cAll, cidrs: []string{
		"172.16.100.0/23:tcp/22,udp/161,udp/162", "10.0.0.0/8", "192.0.2.0/24:udp/161,icmp", "198.51.100.0/24:tcp/20-30"}}
	vs := managedVariants()

	// WTI (the variant list has no WTI: the walkthrough variants do)
	for _, v := range []variant{variants[5], variants[6]} {
		req, d := p.input(m, c, v)
		secs := mustManaged(t, req, d)
		acl := wtiLines(secs, "mgmt-acl")
		for _, w := range []string{
			"iptables -A INPUT -p tcp -s 192.0.2.0/24 --dport 22 -j ACCEPT",
		} {
			if slices.Contains(acl, w) {
				t.Errorf("%s: the udp-only entry opens ssh: %q", v.name, w)
			}
		}
		for _, w := range []string{
			"iptables -A INPUT -p tcp -s 172.16.100.0/23 --dport 22 -j ACCEPT",
			"iptables -A INPUT -p udp -s 172.16.100.0/23 --dport 161 -j ACCEPT",
			"iptables -A INPUT -p udp -s 172.16.100.0/23 --dport 162 -j ACCEPT",
			"iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT",
			"iptables -A INPUT -p udp -s 192.0.2.0/24 --dport 161 -j ACCEPT",
			"iptables -A INPUT -i eth0 -s 192.0.2.0/24 -p icmp -j ACCEPT",
			"iptables -A INPUT -p tcp -s 198.51.100.0/24 --dport 20:30 -j ACCEPT",
			// the automatic ICMP line of a network whose entry lists no icmp
			"iptables -A INPUT -i eth0 -s 172.16.100.0/23 -p icmp -j ACCEPT",
		} {
			if !slices.Contains(acl, w) {
				t.Errorf("%s: mgmt-acl lacks %q:\n%s", v.name, w, strings.Join(acl, "\n"))
			}
		}
		// no ICMP line for the plain /8, and none twice for the entry that lists icmp
		n := 0
		for _, l := range acl {
			if strings.Contains(l, "-i eth0 -s 10.0.0.0/8 ") {
				t.Errorf("%s: an ICMP line for a plain entry: %q", v.name, l)
			}
			if strings.Contains(l, "-i eth0 -s 192.0.2.0/24 ") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d ICMP lines for the entry with icmp", v.name, n)
		}
	}

	// Cisco and Junos: the plain entry and the ones with tcp/22 (in a range)
	// are listed by their source, the udp/161-and-icmp entry is not
	for _, v := range vs {
		req, d := p.input(m, c, v)
		secs := mustManaged(t, req, d)
		acl := strings.Join(wtiLines(secs, "mgmt-acl"), "\n")
		for _, in := range []string{"172.16.100.0", "10.0.0.0", "198.51.100.0"} {
			if !strings.Contains(acl, in) {
				t.Errorf("%s %s: mgmt-acl lacks %s:\n%s", v.vendor, v.name, in, acl)
			}
		}
		if strings.Contains(acl, "192.0.2.0") {
			t.Errorf("%s %s: the entry without ssh is listed:\n%s", v.vendor, v.name, acl)
		}
	}
}
