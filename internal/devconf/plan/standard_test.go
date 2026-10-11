package plan

// The standard Cisco block in the plan (plan §13, D117-D119): the legacy
// server form on a modern image, the policy value that is not set, and the
// order of the unit.

import (
	"slices"
	"strings"
	"testing"
)

// legacyOnModern turns the reference-lab device into one that runs the
// legacy server form on a modern image: the named block is replaced by the
// global line at its address, and the group names the address.
func legacyOnModern(c *IOSConfig) {
	for i := range c.blocks {
		switch {
		case strings.HasPrefix(c.blocks[i].lines[0], "tacacs server "):
			c.blocks[i].lines = []string{"tacacs-server host 192.0.2.10 single-connection timeout 5 key 7 0822455D0A16"}
		case strings.HasPrefix(c.blocks[i].lines[0], "aaa group server tacacs+ "):
			c.blocks[i].lines = []string{c.blocks[i].lines[0], " server 192.0.2.10"}
		}
	}
}

// serverInUse makes a bare device one that already uses the scope's server:
// 'aaa new-model', the named block at the server's address and a login list
// that names a group (D118 (12)).
func serverInUse(c *IOSConfig) {
	c.typeGlobal("aaa new-model")
	c.insertBlock(iosBlk{lines: []string{"tacacs server TACACS", " address ipv4 192.0.2.10"}})
	c.typeGlobal("aaa authentication login default group tacacs+ local")
}

// legacyUnproven is legacyOnModern on a device that authorizes commands and
// shows no server in use: no login or exec list names a group, so nothing
// proves that the pasting session is a TACACS+ user (D117, amended).
func legacyUnproven(c *IOSConfig) {
	legacyOnModern(c)
	c.noGlobal("aaa authentication login default")
	c.noGlobal("aaa authorization exec default")
}

// D117 (amended): with command authorization on and no server in use, the
// old entry cannot be removed first and the named block cannot be added
// beside it: the unit is refused, with the steps outside any region.
func TestStandardLegacyHostWithCommandAuthorizationIsRefused(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	d := planI(t, f, legacyUnproven, Options{Scope: "lab", Device: "sw-lab-1"})
	st := d.Of("aaa")
	const why = "this device runs the legacy server form with command authorization: migrate it from the console as a user that reaches privilege 15 there (the steps are below the region)"
	if st.State != StateSkipped || st.Kind != KindRefused || st.Why != why {
		t.Fatalf("aaa: %+v", st)
	}
	if n := len(lines(d, "aaa")); n != 0 {
		t.Errorf("a refused unit has %d lines", n)
	}
	// S1: the steps are complete and in order: the old entry out, the named
	// block in, the group (whose method lists keep naming it) pointed at the
	// named block and the address dropped, then 'end'
	var typed []string
	for _, l := range d.ByHand {
		if strings.HasPrefix(l, byHandIndent) {
			typed = append(typed, strings.TrimPrefix(l, byHandIndent))
		}
	}
	wantTyped := []string{"configure terminal", "no tacacs-server host 192.0.2.10",
		"tacacs server TACACS", " address ipv4 192.0.2.10", " key <the scope's key: tacctl scope secret show lab>",
		" single-connection", " timeout 5", "exit",
		"aaa group server tacacs+ LAB-TACACS", " server name TACACS", " no server 192.0.2.10", "exit", "end"}
	if !slices.Equal(typed, wantTyped) {
		t.Errorf("the by-hand lines:\n%q\nwant\n%q", typed, wantTyped)
	}
	if got := d.ByHand[0]; !strings.HasPrefix(got, "1. ") {
		t.Errorf("the steps are not a numbered list: %q", got)
	}
	for _, l := range d.ByHand {
		if !strings.HasPrefix(l, byHandIndent) && l[0] != '0' && l[0] != '1' && l[0] != '2' && l[0] != '3' && l[0] != '4' {
			t.Errorf("a line of the steps is neither numbered nor typed: %q", l)
		}
	}
	// the steps are outside any region, as comments, and no value is in them
	h := f.header()
	out := Block(d, h, Wrapper{})
	if strings.Contains(out, "PASTE FROM HERE: "+h.Device) && strings.Contains(out, "no tacacs-server host") {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "no tacacs-server host") && !strings.HasPrefix(l, "!") {
				t.Errorf("a by-hand step is not a comment line: %q", l)
			}
		}
	}
	if !strings.Contains(out, "!       no tacacs-server host 192.0.2.10\n") || strings.Contains(out, "0822455D0A16") {
		t.Errorf("the by-hand steps:\n%s", out)
	}
	// the premise: the console, as any user that reaches privilege 15 there
	if flat := strings.Join(strings.Fields(strings.ReplaceAll(out, "\n!", " ")), " "); !strings.Contains(flat, "Do it on the console, as any user that reaches privilege 15 there") {
		t.Errorf("the premise of the steps:\n%s", out)
	}
	// SF2: with 'aaa authorization console' on, the four steps cannot be
	// typed: step 0 takes the setting off first, while the TACACS+ user's
	// commands still pass, and says what to do if the console is refused
	dc := planI(t, f, func(c *IOSConfig) {
		legacyUnproven(c)
		c.typeGlobal("aaa authorization console")
	}, Options{Scope: "lab", Device: "sw-lab-1"})
	if len(dc.ByHand) < 5 || !strings.HasPrefix(dc.ByHand[0], "0. ") {
		t.Fatalf("no step 0: %q", dc.ByHand)
	}
	for _, want := range []string{"'aaa authorization console'", "the standard never sets it and it is not put back",
		"If the console session is refused after it, type steps 1 to 4 from a new session"} {
		if !strings.Contains(dc.ByHand[0], want) {
			t.Errorf("step 0 lacks %q: %q", want, dc.ByHand[0])
		}
	}
	if got := dc.ByHand[1:4]; !slices.Equal(got, []string{byHandIndent + "configure terminal", byHandIndent + "no aaa authorization console", byHandIndent + "end"}) {
		t.Errorf("step 0 types %q", got)
	}
	if !strings.HasPrefix(dc.ByHand[4], "1. ") {
		t.Errorf("step 1 does not follow step 0: %q", dc.ByHand[4])
	}
	if strings.Contains(strings.Join(d.ByHand, "\n"), "aaa authorization console") {
		t.Errorf("step 0 is there without 'aaa authorization console': %q", d.ByHand)
	}
	// the text above the steps says so too
	if out := Block(dc, f.header(), Wrapper{}); !strings.Contains(strings.Join(strings.Fields(strings.ReplaceAll(out, "\n!", " ")), " "),
		"step 0 takes that setting off first") {
		t.Errorf("the by-hand preamble does not mention step 0:\n%s", out)
	}
	// the old entry is an ACCESS finding left alone, and the unit says why
	var item *Item
	for i := range d.Items {
		if strings.Contains(d.Items[i].Statement, "tacacs-server host") {
			item = &d.Items[i]
		}
	}
	if item == nil || item.Kind != KindExtra || item.Severity != SevAccess || item.Fixed {
		t.Errorf("the old server form: %+v", item)
	}
	// the rest of the plan stands
	if d.Of("roles").State == StateSkipped {
		t.Errorf("roles: %+v", d.Of("roles"))
	}
}

// S1: a group of another name than the standard that holds the old address
// is pointed at the named block by its own name, so the method lists that
// name it keep resolving.
func TestStandardByHandKeepsTheDevicesGroup(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	d := planI(t, f, func(c *IOSConfig) {
		legacyUnproven(c)
		for i := range c.blocks {
			if c.blocks[i].lines[0] == "aaa group server tacacs+ LAB-TACACS" {
				c.blocks[i].lines[0] = "aaa group server tacacs+ OLD-GROUP"
			}
		}
		for _, lvl := range []string{"1", "7", "15"} {
			c.typeGlobal("aaa authorization commands " + lvl + " default local group OLD-GROUP")
		}
	}, Options{Scope: "lab", Device: "sw-lab-1"})
	steps := strings.Join(d.ByHand, "\n")
	for _, want := range []string{"    aaa group server tacacs+ OLD-GROUP\n     server name TACACS\n     no server 192.0.2.10\n    exit\n", "1. ", "4. ",
		"3. Point each group that held the old address at the named block"} {
		if !strings.Contains(steps, want) {
			t.Errorf("the steps lack %q:\n%s", want, steps)
		}
	}
}

// When no group holds the old address (the method lists use 'group tacacs+',
// which takes every configured server) step 3 says that the standard group is
// created and that the lists keep using 'group tacacs+'; it does not point
// "each group that held the old address".
func TestStandardByHandWhenNoGroupHoldsTheAddress(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	d := planI(t, f, func(c *IOSConfig) {
		legacyUnproven(c)
		for i := range c.blocks {
			if strings.HasPrefix(c.blocks[i].lines[0], "aaa group server tacacs+ ") {
				c.blocks = append(c.blocks[:i], c.blocks[i+1:]...)
				break
			}
		}
		// the command lists use 'group tacacs+' and no login list names a
		// group: nothing proves the pasting session
		for _, l := range []string{"aaa authorization commands 1 default", "aaa authorization commands 7 default",
			"aaa authorization commands 15 default"} {
			c.noGlobal(l)
		}
		c.typeGlobal("aaa authorization commands 15 default group tacacs+ local")
	}, Options{Scope: "lab", Device: "sw-lab-1"})
	steps := strings.Join(d.ByHand, "\n")
	for _, want := range []string{"3. No server group holds the old address, so the standard group is created",
		"the method lists use 'group tacacs+' and keep using it",
		"    aaa group server tacacs+ LAB-TACACS\n     server name TACACS\n    exit\n"} {
		if !strings.Contains(steps, want) {
			t.Errorf("the steps lack %q:\n%s", want, steps)
		}
	}
	if strings.Contains(steps, "Point each group that held the old address") || strings.Contains(steps, "no server 192.0.2.10") {
		t.Errorf("the steps point a group at the block that holds nothing:\n%s", steps)
	}
}

// D117: without command authorization the region removes the old entry
// first and adds the standard block in the same paste.
func TestStandardLegacyHostWithoutCommandAuthorizationIsReplaced(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	d := planI(t, f, func(c *IOSConfig) {
		legacyOnModern(c)
		for _, l := range []string{"aaa authorization commands 1 default local group LAB-TACACS",
			"aaa authorization commands 7 default local group LAB-TACACS",
			"aaa authorization commands 15 default local group LAB-TACACS", "aaa authorization config-commands"} {
			c.noGlobal(l)
		}
	}, Options{Scope: "lab"})
	if st := d.Of("aaa"); st.State != StatePlanned {
		t.Fatalf("aaa: %+v", st)
	}
	ls := lines(d, "aaa")
	// (b): the group's entry first, then the old line, then the block
	ent := slices.Index(ls, "aaa group server tacacs+ LAB-TACACS > no server 192.0.2.10")
	rm := slices.Index(ls, "no tacacs-server host 192.0.2.10")
	blk := slices.Index(ls, "tacacs server TACACS > address ipv4 192.0.2.10")
	if ent != 0 || rm != 1 || blk <= rm {
		t.Errorf("the old entry is not removed first, then the block (%d, %d, %d):\n%s", ent, rm, blk, strings.Join(ls, "\n"))
	}
	if len(d.ByHand) != 0 {
		t.Errorf("by-hand steps with nothing refused: %q", d.ByHand)
	}
	// its back-out types the old line again, the key to be put in by hand
	var undo []string
	for _, l := range d.Lines {
		if l.Op == OpNo && l.Text == "tacacs-server host 192.0.2.10" {
			for _, u := range l.Undo {
				undo = append(undo, u.Text)
			}
		}
	}
	if len(undo) != 1 || !strings.Contains(undo[0], "type again with its original secret: tacacs-server host 192.0.2.10") {
		t.Errorf("undo: %q", undo)
	}
	// another server at another address is nobody's but its owner's; the
	// entry at the rendered address is replaced, command authorization on
	// the device or not (the server is in use here: the pasting session is a
	// TACACS+ user)
	d = planI(t, f, func(c *IOSConfig) {
		legacyOnModern(c)
		c.typeGlobal("tacacs-server host 192.0.2.77 key 7 0822455D0A16")
	}, Options{Scope: "lab"})
	if st := d.Of("aaa"); st.State != StatePlanned || len(d.ByHand) != 0 {
		t.Errorf("the entry at the rendered address with command authorization: %+v", st)
	}
	wantKept(t, d, "aaa", "tacacs-server host 192.0.2.77")
	dn := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("tacacs-server host 192.0.2.77 key 7 0822455D0A16")
	}, Options{Scope: "lab"})
	if st := dn.Of("aaa"); st.State == StateSkipped {
		t.Errorf("another server refused the unit: %+v", st)
	}
	wantKept(t, dn, "aaa", "tacacs-server host 192.0.2.77")
}

// D117: the ios12 syntax has the global line as its standard: nothing of the
// hazard applies.
func TestStandardLegacyHostOnIOS12IsNoHazard(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, func(c *IOSConfig) { c.noGlobal("aaa authentication login CONSOLE local") }, Options{})
	if st := d.Of("aaa"); st.State != StatePlanned {
		t.Errorf("aaa: %+v", st)
	}
	wantLine(t, d, "aaa", "aaa authentication login CONSOLE local")
}

// D119: an unset policy value is a warning of the report, never a line.
func TestStandardPolicyGapsAreWarnings(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	gap := "policy value not set: source interface (tacctl config cisco source-interface lab <interface>); the server matches this device by its source address"
	d := planI(t, f, nil, Options{PolicyGaps: []string{gap}})
	if !slices.Contains(d.Warnings, gap) {
		t.Errorf("warnings: %q", d.Warnings)
	}
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "source-interface") || strings.Contains(l.Text, "<interface>") {
			t.Errorf("a line for an unset value: %q", l.Text)
		}
	}
	out := Block(d, f.header(), Wrapper{})
	if flat := strings.Join(strings.Fields(strings.ReplaceAll(out, "\n! ", " ")), " "); !strings.Contains(flat, "WARNING: "+gap+".") {
		t.Errorf("the report lacks the warning:\n%s", out)
	}
	// it is no irregularity of the device
	for _, it := range d.Items {
		if strings.Contains(it.Words+it.Statement, "source interface") {
			t.Errorf("an item for an unset value: %+v", it)
		}
	}
	if d := planI(t, f, nil, Options{}); slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "policy value not set") }) {
		t.Errorf("a warning with no gap given: %q", d.Warnings)
	}
}

// regionStatements are the statements of a plan's region as typed, without
// the comments and the wrapper lines.
func regionStatements(d Delta) []string {
	var out []string
	for _, rl := range RegionLines(d, Header{}, Wrapper{}) {
		if !rl.Comment && !rl.Wrapper {
			out = append(out, rl.Text)
		}
	}
	return out
}

// B1: a region that turns 'aaa new-model' on types it before every other
// 'aaa ...' line and before every server, group, address and key statement
// (nothing under 'aaa' exists on IOS until it is set), and the simulated
// device, which rejects the lines typed before it, takes the whole paste.
func TestStandardRegionTypesNewModelFirst(t *testing.T) {
	var seen int
	for _, f := range fixtures(t) {
		if f.vendor != "cisco" {
			continue
		}
		for _, opt := range []Options{{Scope: "lab"}, {Scope: "lab", NoSecrets: true}} {
			d := planI(t, f, nil, opt)
			body := regionStatements(d)
			at := slices.Index(body, "aaa new-model")
			if at < 0 {
				continue
			}
			seen++
			if at != 0 {
				t.Errorf("%s: aaa new-model is statement %d, not the first:\n%s", f.name, at+1, strings.Join(body, "\n"))
			}
			for _, l := range body[:at] {
				w := strings.TrimSpace(l)
				if strings.HasPrefix(w, "aaa ") || strings.HasPrefix(w, "server ") || strings.HasPrefix(w, "address ") || strings.HasPrefix(w, "key ") {
					t.Errorf("%s: %q before aaa new-model", f.name, l)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no fixture's plan turns aaa new-model on")
	}
	// the simulated device rejects the group typed first
	f := fixtureNamed(t, "cisco.reference-bare")
	c := ParseIOS(capture(t, f.raw))
	err := c.Apply([]Line{{Op: OpLine, Context: []string{"aaa group server tacacs+ G"}, Text: "server name TACACS"}, {Op: OpLine, Text: "aaa new-model"}})
	if err == nil || !strings.Contains(err.Error(), "before 'aaa new-model'") {
		t.Errorf("the simulated device took a group before aaa new-model: %v", err)
	}
	if err := c.Apply([]Line{{Op: OpLine, Text: "aaa new-model"},
		{Op: OpLine, Context: []string{"tacacs server TACACS"}, Text: "address ipv4 192.0.2.10"},
		{Op: OpLine, Context: []string{"aaa group server tacacs+ G"}, Text: "server name TACACS"}}); err != nil {
		t.Errorf("the right order: %v", err)
	}
}

// N1: the line leaves are typed console first, then the vty ranges by their
// first line, whatever order the device showed them in.
func TestStandardLineLeavesAreConsoleFirstThenVty(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	d := planI(t, f, func(c *IOSConfig) {
		for i := range c.blocks {
			if c.blocks[i].lines[0] == "line vty 0 4" {
				c.blocks[i].lines = []string{"line vty 0 4", " login local", " transport input ssh"}
				// another method, so the extraction does not merge the ranges
				c.insertBlock(iosBlk{lines: []string{"line vty 5 15", " login", " transport input ssh"}})
				return
			}
		}
		t.Fatal("no line vty 0 4 in the fixture")
	}, Options{Scope: "lab"})
	var heads []string
	for _, s := range regionStatements(d) {
		if strings.HasPrefix(s, "line ") {
			heads = append(heads, s)
		}
	}
	if want := []string{"line con 0", "line vty 0 4", "line vty 5 15"}; !slices.Equal(heads, want) {
		t.Errorf("the leaves are under %q, want %q", heads, want)
	}
}

// N3: a legacy 'radius-server host' at the address of the named RADIUS block
// is an extra, removed first (RADIUS has no command authorization, so there is
// no refusal), and the back-out types it again with its key left to the
// person.
func TestStandardLegacyRadiusHostIsReplaced(t *testing.T) {
	f := fixtureNamed(t, "cisco.xe-reference-16")
	legacyRadius := func(c *IOSConfig) {
		for i := range c.blocks {
			switch {
			case strings.HasPrefix(c.blocks[i].lines[0], "radius server "):
				c.blocks[i].lines = []string{"radius-server host 192.0.2.10 auth-port 1812 acct-port 1813 key 7 0822455D0A16"}
			case strings.HasPrefix(c.blocks[i].lines[0], "aaa group server radius "):
				c.blocks[i].lines = []string{c.blocks[i].lines[0], " server 192.0.2.10 auth-port 1812 acct-port 1813"}
			}
		}
	}
	for _, withCmdAuth := range []bool{false, true} {
		d := planI(t, f, func(c *IOSConfig) {
			legacyRadius(c)
			if withCmdAuth {
				c.typeGlobal("aaa authorization commands 15 default group LAB-RADIUS local")
			}
		}, Options{Scope: "lab"})
		if st := d.Of("aaa"); st.State != StatePlanned {
			t.Fatalf("cmd auth %v: aaa: %+v", withCmdAuth, st)
		}
		ls := lines(d, "aaa")
		rm := slices.Index(ls, "no radius-server host 192.0.2.10 auth-port 1812 acct-port 1813")
		blk := slices.IndexFunc(ls, func(s string) bool { return strings.HasPrefix(s, "radius server RADIUS > address ipv4 192.0.2.10") })
		if rm < 0 || blk <= rm {
			t.Errorf("cmd auth %v: the old entry is not removed before the block (%d, %d):\n%s", withCmdAuth, rm, blk, strings.Join(ls, "\n"))
		}
		if len(d.ByHand) != 0 {
			t.Errorf("by-hand steps for RADIUS: %q", d.ByHand)
		}
		var undo []string
		for _, l := range d.Lines {
			if l.Op == OpNo && l.Text == "radius-server host 192.0.2.10 auth-port 1812 acct-port 1813" {
				for _, u := range l.Undo {
					undo = append(undo, u.Text)
				}
			}
		}
		if len(undo) != 1 || !strings.Contains(undo[0], "type again with its original secret: radius-server host 192.0.2.10") {
			t.Errorf("undo: %q", undo)
		}
	}
	// another server at another address is nobody's but its owner's
	d := planI(t, f, func(c *IOSConfig) {
		legacyRadius(c)
		c.typeGlobal("radius-server host 192.0.2.77 key 7 0822455D0A16")
	}, Options{Scope: "lab"})
	wantKept(t, d, "aaa", "radius-server host 192.0.2.77")
	// SF3: IOS keys a RADIUS host on its address and ports: the 'no' line
	// keeps the ports as the device stores them, and an entry on other ports
	// is another server, kept
	d = planI(t, f, func(c *IOSConfig) {
		legacyRadius(c)
		c.typeGlobal("radius-server host 192.0.2.10 auth-port 11812 acct-port 11813 key 7 0822455D0A16")
	}, Options{Scope: "lab"})
	wantLine(t, d, "aaa", "no radius-server host 192.0.2.10 auth-port 1812 acct-port 1813")
	noLine(t, d, "aaa", "no radius-server host 192.0.2.10 auth-port 11812")
	wantKept(t, d, "aaa", "radius-server host 192.0.2.10 auth-port 11812 acct-port 11813")
	// the removal line of the report keeps them too
	var rm []string
	for _, e := range d.Extras {
		if strings.HasPrefix(e.Text, "radius-server host 192.0.2.10 auth-port 11812") {
			rm = removeLines(e.Remove)
		}
	}
	if !slices.Equal(rm, []string{"no radius-server host 192.0.2.10 auth-port 11812 acct-port 11813"}) {
		t.Errorf("the removal of the extra RADIUS host: %q", rm)
	}
}

// SF3: a TACACS+ host entry is keyed on its address only.
func TestStandardLegacyTacacsHostNoIsAddressOnly(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"tacacs-server host 192.0.2.10 single-connection timeout 5 key <secret>", "tacacs-server host 192.0.2.10"},
		{"tacacs-server host 192.0.2.10 port 4949 key <secret>", "tacacs-server host 192.0.2.10"},
		{"radius-server host 192.0.2.10 auth-port 1812 acct-port 1813 key <secret>", "radius-server host 192.0.2.10 auth-port 1812 acct-port 1813"},
		{"radius-server host 192.0.2.10 acct-port 1813 auth-port 1812 timeout 3", "radius-server host 192.0.2.10 acct-port 1813 auth-port 1812"},
		{"radius-server host 192.0.2.10 key 7 0822455D0A16", "radius-server host 192.0.2.10"},
	} {
		if got := hostEntry(strings.Fields(tc.in)); got != tc.want {
			t.Errorf("hostEntry(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("tacacs-server host 192.0.2.77 single-connection timeout 5 key 7 0822455D0A16")
	}, Options{Scope: "lab"})
	var rm []string
	for _, e := range d.Extras {
		if strings.HasPrefix(e.Text, "tacacs-server host 192.0.2.77") {
			rm = removeLines(e.Remove)
		}
	}
	if !slices.Equal(rm, []string{"no tacacs-server host 192.0.2.77"}) {
		t.Errorf("the removal of the extra TACACS+ host: %q", rm)
	}
}

// S3: a paste is ASCII, comments included: CheckRegion refuses a byte that is
// not printable ASCII on either vendor, and every region and back-out of the
// fixtures passes it.
func TestCheckRegionRejectsNonASCII(t *testing.T) {
	ios := []string{"configure terminal", "aaa new-model", "end"}
	if err := CheckRegion("ios", ios); err != nil {
		t.Fatalf("a clean IOS region: %v", err)
	}
	for _, bad := range []string{"! a note — with a dash", "aaa new-model é", "! tab\there", "! \x7f"} {
		if err := CheckRegion("ios", []string{"configure terminal", bad, "aaa new-model", "end"}); err == nil || !strings.Contains(err.Error(), "not printable ASCII") {
			t.Errorf("IOS %q: %v", bad, err)
		}
	}
	junos := []string{"configure private", "set system host-name r1", "show | compare | no-more", "commit check", "commit confirmed 5"}
	if err := CheckRegion("junos", junos); err != nil {
		t.Fatalf("a clean Junos region: %v", err)
	}
	bad := slices.Clone(junos)
	bad[1] = "# note — here"
	if err := CheckRegion("junos", bad); err == nil || !strings.Contains(err.Error(), "not printable ASCII") {
		t.Errorf("Junos comment: %v", err)
	}
}
