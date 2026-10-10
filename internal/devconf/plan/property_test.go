package plan

// The property test (plan D103 (2)): for every fixture, and for a seeded
// fuzz of mutations of the pulled text, apply the delta with the in-memory
// editor, extract and compare again, and the planned sections must read ok
// with only the kept lines as '+' (the lines withheld by class or by rule are
// the only '-'). A second plan of the result is empty.

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// propertyCounts is what the test reports at the end.
type propertyCounts struct {
	fixtures, plans, linesApplied int
}

// check applies d to the pulled text and verifies the property. It returns
// the number of lines applied.
func checkConverges(t *testing.T, f fixture, exp []devices.Section, raw string, d Delta, opt Options, label string, inherited map[string]bool) int {
	t.Helper()
	var after string
	switch d.Vendor {
	case devconf.FamilyJunos:
		before := ParseJunos(raw)
		c := ParseJunos(raw)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatalf("%s %s: apply: %v\n%s", f.name, label, err, d.Display())
		}
		after = c.Text()
		checkJunosPreserved(t, f, exp, before, c, d, inherited, label)
		if len(d.Inherited) == 0 {
			checkJunosBackout(t, f, raw, d, label)
		}
	default:
		before := ParseIOS(raw)
		c := ParseIOS(raw)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatalf("%s %s: apply: %v\n%s", f.name, label, err, d.Display())
		}
		after = c.Text()
		checkIOSPreserved(t, f, exp, before, c, d, label)
		if !opt.Secrets {
			// a secret pushed by value replaces a value the record does not
			// have: its back-out is a note to type the original again
			checkIOSBackout(t, f, exp, raw, d, label)
		}
		// BLOCKER 2: no 'no line ...' anywhere in the delta
		for _, l := range d.Lines {
			if l.Op == OpNo && len(l.Context) == 0 && strings.HasPrefix(l.Text, "line ") {
				t.Errorf("%s %s: the plan removes %q", f.name, label, l.Text)
			}
		}
	}
	ex, err := devconf.Extract(f.vendor, after, exp...)
	if err != nil {
		t.Fatalf("%s %s: extract after: %v", f.name, label, err)
	}
	// the secrets stay as they were on the device (the editor keeps them)
	ex.SecretsVisible = true
	if f.class != nil || strings.Contains(f.name, "engineer") {
		ex.SecretsVisible = false
	}
	res, err := devconf.CompareAll(exp, ex)
	if err != nil {
		t.Fatal(err)
	}
	keptSet := map[string]bool{}
	for _, k := range d.Kept {
		keptSet[k.Text] = true
	}
	for _, u := range d.Unattributed {
		keptSet[u] = true
	}
	// a secret pushed by value (--secrets) is a new community when the
	// device's own has another name: the old one stays, by design (its name
	// is the secret and is not compared)
	for _, l := range d.Lines {
		if l.Secret && l.Elided != "" {
			keptSet[strings.TrimSuffix(l.Elided, " "+secretMark)] = true
			keptSet[l.Elided] = true
		}
	}
	withheld := map[string]bool{}
	for _, w := range d.Withheld {
		w = strings.TrimPrefix(w, "the access-class binding: ")
		w = strings.TrimPrefix(w, "the login method of lines the record does not show: ")
		withheld[strings.TrimSuffix(w, " "+secretMark)] = true
	}
	for _, r := range res {
		st := d.Of(r.Name).State
		if st != StatePlanned && st != StateNoChange {
			continue
		}
		partial := slices.ContainsFunc(d.Skipped, func(s Skip) bool { return s.Section == r.Name })
		for _, l := range r.Lines {
			stem := stemOf(l)
			switch l.Op {
			case devconf.OpMissing:
				if !withheld[stem] && !withheld[strings.TrimSuffix(stem, " "+secretMark)] {
					t.Errorf("%s %s [%s]: still missing after the plan: %s\n%s", f.name, label, r.Name, stem, d.Display())
				}
			case devconf.OpExtra:
				if !keptSet[stem] && !withheld[stem] && !withheld[strings.TrimSuffix(stem, " "+secretMark)] {
					t.Errorf("%s %s [%s]: extra after the plan and not kept: %s\n%s", f.name, label, r.Name, stem, d.Display())
				}
			case devconf.OpOrder:
				if !partial {
					t.Errorf("%s %s [%s]: out of order after the plan: %s\n%s", f.name, label, r.Name, l.Text, d.Display())
				}
			}
		}
	}
	// convergence: planning the result again says nothing new
	opt2 := opt
	opt2.Secrets = false
	d2, err := Plan(f.vendor, exp, ex, ex, opt2)
	if err != nil {
		t.Fatalf("%s %s: second plan: %v", f.name, label, err)
	}
	unattributed := map[string]bool{}
	for _, u := range d.Unattributed {
		u = strings.TrimPrefix(u, "set ")
		for _, fl := range []string{" restrict", " except"} {
			u = strings.TrimSuffix(u, fl)
		}
		unattributed[u] = true
	}
	if len(d.Inherited) > 0 {
		// a section refused for a statement of a group is not converged
		return len(d.Lines)
	}
	for _, l := range d2.Lines {
		if d.Vendor == devconf.FamilyJunos && l.Op == OpDelete && l.Secret && unattributed[strings.TrimPrefix(l.Elided, "delete ")] {
			continue // a leaf of another community (the name is not compared)
		}
		t.Errorf("%s %s: the plan of the result is not empty: %s\n%s\n--- first\n%s", f.name, label, l.Shown(), d2.Display(), d.Display())
		break
	}
	return len(d.Lines)
}

func TestPropertyFixtures(t *testing.T) {
	var c propertyCounts
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, secrets := range []bool{false, true} {
			opt := f.options()
			opt.Secrets = secrets
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			c.plans++
			c.linesApplied += checkConverges(t, f, exp, capture(t, f.raw), d, opt, fmt.Sprintf("secrets=%v", secrets), nil)
		}
		c.fixtures++
	}
	t.Logf("property: %d fixtures, %d plans, %d lines applied", c.fixtures, c.plans, c.linesApplied)
}

// --- the fuzz ---------------------------------------------------------------------

// junosManaged are the hierarchies the Junos mutations touch.
func junosManaged(path []string) bool {
	j := strings.Join(path, " ")
	for _, p := range []string{"system accounting", "system authentication-order", "system tacplus-server",
		"system login class", "snmp ", "firewall family inet filter MGMT-ACL"} {
		if strings.HasPrefix(j, p) {
			return true
		}
	}
	return false
}

// firstName returns the token after the prefix in the first rendered line
// that has it.
func renderedName(exp []devices.Section, prefix string) string {
	for _, s := range exp {
		for _, l := range s.Lines {
			if r, ok := strings.CutPrefix(l, prefix); ok {
				if f := strings.Fields(r); len(f) > 0 {
					return f[0]
				}
			}
		}
	}
	return ""
}

func junosPool(exp []devices.Section) []string {
	comm := renderedName(exp, "set snmp community ")
	srv := renderedName(exp, "set system tacplus-server ")
	pool := []string{
		"set system accounting events interactive-commands",
		"set system accounting events config-changes",
		"set system accounting destination radius",
		"set system authentication-order radius",
		"set system tacplus-server 203.0.113.5 secret \"$9$ZZZZZZZZ\"",
		"set system tacplus-server 203.0.113.5 single-connection",
		"set snmp client-list TACCTL-SNMP 203.0.113.9/32",
		"set snmp client-list OTHER-LIST 203.0.113.0/24",
		"set snmp community stray-comm clients 203.0.113.0/24",
		"set snmp location \"Elsewhere\"",
		"set snmp contact \"Someone Else\"",
		"set snmp name fuzz-device",
		"set snmp trap-group fuzz-traps targets 203.0.113.50",
		"set firewall family inet filter MGMT-ACL term zz-extra then accept",
		"set firewall family inet filter MGMT-ACL term zz-extra from source-address 203.0.113.0/24",
		"set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 203.0.113.0/24",
		"set firewall family inet filter MGMT-ACL term default-accept then log",
		"set system login class RO-CLASS allow-commands \"show .*\"",
		"set system login class RO-CLASS permissions all",
		"set system login class RW-CLASS deny-commands \"request .*\"",
		"set system login class FUZZ-CLASS permissions view",
		"set system login user RO-CLASS class RW-CLASS",
		// Opus review: flags of a list entry, other servers' accounting
		// destinations, a deactivated statement of tacctl's
		"set snmp client-list TACCTL-SNMP 203.0.113.0/24 restrict",
		"set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.66/32 except",
		"set system accounting destination radius server 203.0.113.7 secret \"$9$ZZZZZZZZ\"",
		"set system accounting destination tacplus server 203.0.113.8 port 49",
		"deactivate system accounting events",
		"deactivate firewall family inet filter MGMT-ACL term deny-snmp",
	}
	if comm != "" {
		pool = append(pool,
			"set snmp community "+comm+" clients 10.0.0.0/8 restrict",
			"set snmp community "+comm+" clients 203.0.113.0/24",
			"set snmp community "+comm+" authorization read-write",
			"set snmp community "+comm+" routing-instance fuzz")
	}
	if srv != "" {
		pool = append(pool, "set system tacplus-server "+srv+" source-address 203.0.113.77",
			"set system tacplus-server "+srv+" port 4949")
	}
	return pool
}

// termStatements are the statements of one term of the filter.
func moveTermToEnd(c *JunosConfig, r *rand.Rand) {
	var terms []string
	for _, s := range c.stmts {
		if len(s.path) >= 7 && s.path[0] == "firewall" && s.path[4] == "MGMT-ACL" && s.path[5] == "term" && !slices.Contains(terms, s.path[6]) {
			terms = append(terms, s.path[6])
		}
	}
	if len(terms) < 2 {
		return
	}
	moveNamedTermToEnd(c, terms[r.Intn(len(terms))])
}

// moveNamedTermToEnd puts a term of the filter after every other statement.
func moveNamedTermToEnd(c *JunosConfig, t string) {
	var moved, rest []jstmt
	for _, s := range c.stmts {
		if len(s.path) >= 7 && s.path[0] == "firewall" && s.path[4] == "MGMT-ACL" && s.path[5] == "term" && s.path[6] == t {
			moved = append(moved, s)
		} else {
			rest = append(rest, s)
		}
	}
	c.stmts = append(rest, moved...)
}

func mutateJunos(raw string, exp []devices.Section, r *rand.Rand) (string, string) {
	c := ParseJunos(raw)
	pool := junosPool(exp)
	var what []string
	for n := 1 + r.Intn(4); n > 0; n-- {
		switch r.Intn(5) {
		case 0, 1:
			var idx []int
			for i, s := range c.stmts {
				if s.head == "set" && junosManaged(s.path) {
					idx = append(idx, i)
				}
			}
			if len(idx) > 0 {
				i := idx[r.Intn(len(idx))]
				what = append(what, "drop "+c.stmts[i].text())
				c.stmts = slices.Delete(c.stmts, i, i+1)
			}
		case 2, 3:
			s := pool[r.Intn(len(pool))]
			what = append(what, "add "+s)
			if strings.HasPrefix(s, "deactivate ") {
				c.Add(s)
			} else {
				_ = c.Apply([]Line{{Op: OpSet, Text: s}})
			}
		case 4:
			if r.Intn(2) == 0 {
				moveTermToEnd(c, r)
				what = append(what, "move a term")
			} else {
				c.delete([]string{"system", "authentication-order"})
				c.Add("set system authentication-order tacplus")
				c.Add("set system authentication-order password")
				what = append(what, "reverse the authentication order")
			}
		}
	}
	return c.Text(), strings.Join(what, "; ")
}

func iosPool(exp []devices.Section) []string {
	grp := renderedName(exp, "aaa group server tacacs+ ")
	if grp == "" {
		grp = renderedName(exp, "aaa group server radius ")
	}
	return []string{
		"aaa authorization commands 5 default local group " + grp,
		"aaa accounting commands 3 default start-stop group " + grp,
		"aaa authentication login default group " + grp,
		"aaa authorization exec default local",
		"privilege exec level 7 fuzz thing",
		"privilege exec level 15 fuzz",
		"snmp-server location Elsewhere",
		"snmp-server contact Someone Else",
		"snmp-server community stray-comm RO",
		"snmp-server enable traps snmp",
		"ip access-list standard OTHER-ACL\n permit 203.0.113.0 0.0.0.255",
		// WP13.1b and the lab IOSv: the lines' login method, and what a
		// 15.x back-out leaves behind
		"line vty 0 4\n login local",
		"line vty 5 15\n login authentication OTHER",
		"line con 0\n login local",
		"snmp-server chassis-id",
		"privilege configure level 7 snmp-server",
		"privilege interface level 7 shutdown",
		"privilege exec level 1 ping",
		"privilege exec level 15 clear ip",
	}
}

// iosACLs finds the blocks of standard ACLs.
func iosACLBlocks(c *IOSConfig) []int {
	var out []int
	for i, b := range c.blocks {
		if strings.HasPrefix(norm(b.lines[0]), "ip access-list standard ") {
			out = append(out, i)
		}
	}
	return out
}

func mutateIOS(raw string, exp []devices.Section, r *rand.Rand) (string, string) {
	c := ParseIOS(raw)
	pool := iosPool(exp)
	var what []string
	for n := 1 + r.Intn(4); n > 0; n-- {
		switch r.Intn(6) {
		case 0, 1:
			// drop a managed line: a global one, or a child of a managed block
			type ref struct{ b, l int }
			var cand []ref
			for bi, b := range c.blocks {
				h := norm(b.lines[0])
				managedBlock := strings.HasPrefix(h, "tacacs server ") || strings.HasPrefix(h, "radius server ") ||
					strings.HasPrefix(h, "aaa group server ") || strings.HasPrefix(h, "ip access-list standard ")
				if len(b.lines) == 1 && (strings.HasPrefix(h, "aaa ") || strings.HasPrefix(h, "privilege ") ||
					strings.HasPrefix(h, "snmp-server ") || strings.HasPrefix(h, "tacacs-server host")) && h != "aaa new-model" {
					cand = append(cand, ref{bi, 0})
				}
				if managedBlock {
					for li := 1; li < len(b.lines); li++ {
						cand = append(cand, ref{bi, li})
					}
				}
			}
			if len(cand) > 0 {
				x := cand[r.Intn(len(cand))]
				b := &c.blocks[x.b]
				what = append(what, "drop "+norm(b.lines[x.l]))
				if x.l == 0 {
					c.blocks = slices.Delete(c.blocks, x.b, x.b+1)
				} else {
					b.lines = slices.Delete(b.lines, x.l, x.l+1)
				}
			}
		case 2, 3:
			p := pool[r.Intn(len(pool))]
			what = append(what, "add "+strings.ReplaceAll(p, "\n", " / "))
			var hdr *iosBlk
			for _, l := range strings.Split(p, "\n") {
				if strings.HasPrefix(l, " ") {
					if hdr != nil {
						hdr.lines = append(hdr.lines, l)
					}
					continue
				}
				c.typeGlobal(norm(l))
				hdr = c.blockFor(norm(l))
			}
		case 4:
			// a new entry at a random place of a rendered ACL
			acls := iosACLBlocks(c)
			if len(acls) > 0 {
				b := &c.blocks[acls[r.Intn(len(acls))]]
				at := 1 + r.Intn(len(b.lines))
				act := []string{"permit 203.0.113.9", "deny 203.0.113.99", "permit 203.0.113.0 0.0.0.255"}[r.Intn(3)]
				b.lines = slices.Insert(b.lines, at, " "+act)
				what = append(what, "entry "+act+" in "+norm(b.lines[0]))
			}
		case 5:
			// reorder an ACL: its last entry first
			acls := iosACLBlocks(c)
			if len(acls) > 0 {
				b := &c.blocks[acls[r.Intn(len(acls))]]
				if len(b.lines) > 3 {
					last := b.lines[len(b.lines)-1]
					b.lines = slices.Insert(b.lines[:len(b.lines)-1], 1, last)
					what = append(what, "move the last entry of "+norm(b.lines[0])+" first")
				}
			}
		}
	}
	return c.Text(), strings.Join(what, "; ")
}

func TestPropertyFuzz(t *testing.T) {
	const perFixture = 45
	total := 0
	ops := map[Op]int{}
	changed := 0
	inheritedCases := 0
	for fi, f := range fixtures(t) {
		exp, _, _ := f.load(t)
		raw := capture(t, f.raw)
		r := rand.New(rand.NewSource(int64(20261010 + fi)))
		for i := 0; i < perFixture; i++ {
			var text, what string
			if f.vendor == "juniper" {
				text, what = mutateJunos(raw, exp, r)
			} else {
				text, what = mutateIOS(raw, exp, r)
			}
			cur, err := devconf.Extract(f.vendor, text, exp...)
			if err != nil {
				t.Fatalf("%s #%d (%s): %v", f.name, i, what, err)
			}
			if f.class != nil {
				cur.SecretsVisible = false
			}
			// a plain view of its own on a third of the Junos cases: a
			// couple of statements come from a group
			plain := cur
			var inherited map[string]bool
			if f.vendor == "juniper" && r.Intn(3) == 0 {
				c := ParseJunos(text)
				var idx []int
				for k, s := range c.stmts {
					if s.head == "set" && junosManaged(s.path) {
						idx = append(idx, k)
					}
				}
				if len(idx) > 0 {
					inherited = map[string]bool{}
					for n := 1 + r.Intn(2); n > 0; n-- {
						inherited[c.stmts[idx[r.Intn(len(idx))]].text()] = true
					}
					var keepStmts []jstmt
					for _, s := range c.stmts {
						if !inherited[s.text()] {
							keepStmts = append(keepStmts, s)
						}
					}
					c.stmts = keepStmts
					plain, err = devconf.Extract(f.vendor, c.Text(), exp...)
					if err != nil {
						t.Fatal(err)
					}
					inheritedCases++
				}
			}
			opt := f.options()
			opt.Secrets = r.Intn(4) == 0
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatalf("%s #%d (%s): %v", f.name, i, what, err)
			}
			checkConverges(t, f, exp, text, d, opt, fmt.Sprintf("#%d (%s)", i, what), inherited)
			// D109: every fuzz case's output is safe to paste whole
			checkWholePaste(t, fmt.Sprintf("%s #%d", f.name, i), d, f.header(), Wrapper{})
			total++
			if len(d.Lines) > 0 {
				changed++
			}
			for _, l := range d.Lines {
				ops[l.Op]++
			}
			if t.Failed() {
				return
			}
		}
	}
	t.Logf("fuzz: %d mutated devices over %d fixtures, seeded; %d had a delta (%d set, %d delete, %d insert, %d line, %d no); %d with a plain view of their own",
		total, len(fixtures(t)), changed, ops[OpSet], ops[OpDelete], ops[OpInsert], ops[OpLine], ops[OpNo], inheritedCases)
	if changed < total*2/3 || ops[OpInsert] == 0 || ops[OpNo] == 0 || ops[OpDelete] == 0 {
		t.Errorf("the fuzz is too tame: %d of %d changed, ops %v", changed, total, ops)
	}
}
