package plan

// WP13.1d (D117, amended after a plan run on a real 15.6 device): a server
// entry at the standard's address under another form (a named block of
// another name, the legacy host line) is replaced in the order command
// authorization off, group entry, old entry, standard block, group entry,
// the rest, command authorization on; the simulated device refuses a second
// block with the same address and key and a group entry that names no block.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// indexOf returns the position of the first statement that equals want.
func indexOf(t *testing.T, got []string, want string) int {
	t.Helper()
	i := slices.Index(got, want)
	if i < 0 {
		t.Fatalf("%q is not in the region:\n%s", want, strings.Join(got, "\n"))
	}
	return i
}

// The shape of the real 15.6 device: 'tacacs server OLD-TACACS' (the
// standard's address and key) in the group TACACS-GROUP, the command lists on.
func TestSameAddressBlockRegionOrder(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	d := planI(t, f, nil, Options{Scope: "lab", Device: "sw-lab-1"})
	if st := d.Of("aaa"); st.State != StatePlanned || len(d.ByHand) != 0 {
		t.Fatalf("aaa: %+v by hand %q", st, d.ByHand)
	}
	got := regionStatements(d)
	want := []string{
		// (a) command authorization off, typed while the server answers
		"no aaa authorization config-commands",
		"no aaa authorization commands 1 default local group TACACS-GROUP",
		"no aaa authorization commands 7 default local group TACACS-GROUP",
		"no aaa authorization commands 15 default local group TACACS-GROUP",
		// (b) the group's entry, then the old block
		"aaa group server tacacs+ TACACS-GROUP", " no server name OLD-TACACS",
		"no tacacs server OLD-TACACS",
		// (c) the standard block, the group's entry, the rest
		"tacacs server TACACS", " address ipv4 192.0.2.10", " key lab-secret-0123456789abcdef", " single-connection", " timeout 5",
		"aaa group server tacacs+ TACACS-GROUP", " server name TACACS",
		"aaa authentication login CONSOLE local",
		"aaa authentication enable default group TACACS-GROUP enable",
		"aaa accounting commands 15 default start-stop group TACACS-GROUP",
		"line con 0", " login authentication CONSOLE",
		// (d) command authorization, last
		"aaa authorization commands 1 default local group TACACS-GROUP",
		"aaa authorization commands 7 default local group TACACS-GROUP",
		"aaa authorization commands 15 default local group TACACS-GROUP",
		"aaa authorization config-commands",
	}
	// the order of the groups of the region is what matters; compare the lines
	// of each group as they come
	if !slices.Equal(got, want) {
		t.Errorf("the region:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// the old block is not an extra left behind, nor reported as one
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "OLD-TACACS") {
			t.Errorf("kept: %+v", k)
		}
	}
	if len(d.Extras) > 0 {
		for _, e := range d.Extras {
			if strings.Contains(e.Text, "OLD-TACACS") {
				t.Errorf("extra: %+v", e)
			}
		}
	}
	// its findings are answered by the region
	for _, it := range d.Items {
		if strings.Contains(it.Statement, "OLD-TACACS") && !it.Fixed {
			t.Errorf("an item of the old block the region does not fix: %+v", it)
		}
	}
	// and the warning says why the old entry goes first
	if !slices.ContainsFunc(d.Warnings, func(w string) bool {
		return strings.Contains(w, "tacacs server OLD-TACACS is at the address of the standard server") &&
			strings.Contains(w, "command authorization is taken off first and typed again last")
	}) {
		t.Errorf("warnings: %q", d.Warnings)
	}
}

// A list of a level tacctl does not render is taken off once, in (a), where
// the plan removes it anyway; it is not typed again, and the other lists are.
func TestSameAddressBlockListOfAnUnrenderedLevel(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	d := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("aaa authorization commands 5 default local group TACACS-GROUP")
	}, Options{Scope: "lab"})
	got := regionStatements(d)
	const l5 = "no aaa authorization commands 5 default local group TACACS-GROUP"
	if n := strings.Count(strings.Join(got, "\n"), l5); n != 1 {
		t.Errorf("the level 5 list is removed %d times:\n%s", n, strings.Join(got, "\n"))
	}
	if indexOf(t, got, l5) > indexOf(t, got, "no tacacs server OLD-TACACS") {
		t.Errorf("the level 5 list is not taken off first:\n%s", strings.Join(got, "\n"))
	}
	if slices.Contains(got, "aaa authorization commands 5 default local group TACACS-GROUP") {
		t.Errorf("the list of an unrendered level is typed again:\n%s", strings.Join(got, "\n"))
	}
	for _, it := range d.Items {
		if strings.Contains(it.Statement, "commands 5") && !it.Fixed {
			t.Errorf("the item of the level 5 list is not answered: %+v", it)
		}
	}
	// the back-out types it again
	var back []string
	for _, l := range iosBackout(d) {
		if l.Op == OpLine {
			back = append(back, l.Text)
		}
	}
	if !slices.Contains(back, "aaa authorization commands 5 default local group TACACS-GROUP") {
		t.Errorf("the back-out does not give the list back: %q", back)
	}
}

// Without command lists on the device the region is the same without (a) and
// (d) of the lists; the plan types command authorization with the rest (the
// server is in use).
func TestSameAddressBlockWithoutCommandLists(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block-nocmd")
	d := planI(t, f, nil, Options{Scope: "lab", Device: "sw-lab-1"})
	got := regionStatements(d)
	if got[0] != "aaa group server tacacs+ TACACS-GROUP" || got[1] != " no server name OLD-TACACS" || got[2] != "no tacacs server OLD-TACACS" {
		t.Errorf("the region starts:\n%s", strings.Join(got, "\n"))
	}
	for _, s := range got[:indexOf(t, got, "tacacs server TACACS")] {
		if strings.HasPrefix(s, "no aaa authorization") {
			t.Errorf("command authorization taken off on a device that has none: %q", s)
		}
	}
	for _, w := range d.Warnings {
		if strings.Contains(w, "taken off first") {
			t.Errorf("the warning names command authorization: %q", w)
		}
	}
}

// Every statement of the old block, and the group entry, are the region's:
// the simulated device takes the region, ends with the standard and a group
// that names it, and the back-out gives back the old block, the group entry
// and the lists (the key is a note).
func TestSameAddressBlockAppliesAndBacksOut(t *testing.T) {
	for _, name := range []string{"cisco.same-address-block", "cisco.same-address-block-nocmd"} {
		f := fixtureNamed(t, name)
		exp, cur, plain := f.load(t)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		raw := capture(t, f.raw)
		c := ParseIOS(raw)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, d.Display())
		}
		after := c.Text()
		for _, want := range []string{"tacacs server TACACS\n", "aaa group server tacacs+ TACACS-GROUP\n server name TACACS\n"} {
			if !strings.Contains(after, want) {
				t.Errorf("%s: the device lacks %q:\n%s", name, want, after)
			}
		}
		if strings.Contains(after, "OLD-TACACS") {
			t.Errorf("%s: the old block is still there:\n%s", name, after)
		}
		// the device is consistent for aaa after the paste
		ex, err := devconf.Extract(f.vendor, after, exp...)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := Plan(f.vendor, exp, ex, ex, f.options())
		if err != nil {
			t.Fatal(err)
		}
		if lines(d2, "aaa") != nil {
			t.Errorf("%s: a second plan has lines: %q", name, lines(d2, "aaa"))
		}
		// the back-out
		var back []Line
		for _, l := range iosBackout(d) {
			if l.Op != OpComment {
				back = append(back, l)
			}
		}
		if err := c.Apply(back); err != nil {
			t.Fatalf("%s: back-out: %v", name, err)
		}
		restored := c.Text()
		for _, want := range []string{"tacacs server OLD-TACACS\n address ipv4 192.0.2.10\n", "aaa group server tacacs+ TACACS-GROUP\n server name OLD-TACACS\n"} {
			if !strings.Contains(restored, want) {
				t.Errorf("%s: the back-out does not give back %q:\n%s", name, want, restored)
			}
		}
		if strings.Contains(restored, "tacacs server TACACS\n") {
			t.Errorf("%s: the standard block is still there after the back-out", name)
		}
		bo, err := Backout(d, f.header(), Wrapper{})
		if err != nil {
			t.Fatal(err)
		}
		// the key of the old block is a note, never a value
		if !strings.Contains(bo, "! (type again with its original secret: tacacs server OLD-TACACS > key <secret>)") {
			t.Errorf("%s: the back-out has no note for the old key:\n%s", name, bo)
		}
		for _, v := range []string{"lab-secret-0123456789abcdef", "0703204E031A"} {
			if strings.Contains(bo, v) {
				t.Errorf("%s: the back-out holds a value %q", name, v)
			}
		}
		// the first back-out lines take command authorization off, when the
		// region had put it back
		if name == "cisco.same-address-block" {
			first := BackoutLines(d, f.header(), Wrapper{})[2].Text
			if !strings.HasPrefix(first, "no aaa authorization config-commands") {
				t.Errorf("the back-out does not start by taking command authorization off: %q", first)
			}
		}
	}
}

// The plan as first built typed the standard block beside the old one, then
// the group's entry and then removed the old entry: the simulated device
// refuses the second block (same address and key) and the group then names a
// block that does not exist.
func TestSimulatorRefusesTheSecondBlockAndTheDanglingEntry(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	asBuilt := []Line{
		{Op: OpLine, Context: []string{"tacacs server TACACS"}, Text: "address ipv4 192.0.2.10"},
		{Op: OpLine, Context: []string{"tacacs server TACACS"}, Text: "key lab-secret-0123456789abcdef"},
		{Op: OpLine, Context: []string{"tacacs server TACACS"}, Text: "single-connection"},
		{Op: OpLine, Context: []string{"aaa group server tacacs+ TACACS-GROUP"}, Text: "server name TACACS"},
		{Op: OpNo, Context: []string{"aaa group server tacacs+ TACACS-GROUP"}, Text: "server name OLD-TACACS"},
	}
	c := ParseIOS(capture(t, f.raw))
	err := c.Apply(asBuilt)
	if err == nil || !strings.Contains(err.Error(), "names no tacacs server block \"TACACS\"") {
		t.Errorf("the plan as first built: %v", err)
	}
	if strings.Contains(c.Text(), "tacacs server TACACS\n") {
		t.Errorf("the second block was taken:\n%s", c.Text())
	}
	// the same sequence with another key is another server: taken
	c = ParseIOS(capture(t, f.raw))
	other := slices.Clone(asBuilt)
	other[1].Text = "key another-key-0123456789"
	if err := c.Apply(other); err != nil {
		t.Errorf("a block with another key: %v", err)
	}
	// the old key written as type 7 is the same key: the value is compared
	c = ParseIOS(capture(t, f.raw))
	t7 := slices.Clone(asBuilt)
	t7[1].Text = "key 7 0703204E031A1C0605171F41547B79777C6663754B5E170102525C5E"
	if err := c.Apply(t7); err == nil {
		t.Errorf("the same key as type 7 was taken")
	}
	// a group entry left naming a block that was removed is an error at the end
	c = ParseIOS(capture(t, f.raw))
	err = c.Apply([]Line{{Op: OpNo, Text: "tacacs server OLD-TACACS"}})
	if err == nil || !strings.Contains(err.Error(), "does not exist after the paste") {
		t.Errorf("the entry left dangling: %v", err)
	}
	// removing the entry first, then the block, is the order the plan types
	c = ParseIOS(capture(t, f.raw))
	if err := c.Apply([]Line{
		{Op: OpNo, Context: []string{"aaa group server tacacs+ TACACS-GROUP"}, Text: "server name OLD-TACACS"},
		{Op: OpNo, Text: "tacacs server OLD-TACACS"}}); err != nil {
		t.Errorf("the entry first, then the block: %v", err)
	}
	// a legacy host line with the same address and key as a named block is
	// refused too
	c = ParseIOS(capture(t, f.raw))
	if err := c.Apply([]Line{{Op: OpLine, Text: "tacacs-server host 192.0.2.10 single-connection key 7 0703204E031A1C0605171F41547B79777C6663754B5E170102525C5E"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.Text(), "tacacs-server host 192.0.2.10") {
		t.Errorf("the legacy line beside the block was taken:\n%s", c.Text())
	}
}

func TestType7Decodes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0822455D0A16", "cisco"},
		{"0703204E031A1C0605171F41547B79777C6663754B5E170102525C5E", "lab-secret-0123456789abcdef"},
	} {
		if got, ok := decodeType7(tc.in); !ok || got != tc.want {
			t.Errorf("decodeType7(%q) = %q, %v", tc.in, got, ok)
		}
	}
	if _, ok := decodeType7("zz"); ok {
		t.Errorf("a malformed value decoded")
	}
}

// A group of another name than the standard's that names the old block keeps
// resolving: its entry is replaced by the standard block, by its own name.
func TestSameAddressBlockPointsAGroupOfAnotherName(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	d := planI(t, f, func(c *IOSConfig) {
		c.insertBlock(iosBlk{lines: []string{"aaa group server tacacs+ OLD-GROUP", " server name OLD-TACACS"}})
	}, Options{Scope: "lab"})
	got := regionStatements(d)
	for _, want := range []string{"aaa group server tacacs+ OLD-GROUP", " no server name OLD-TACACS", " server name TACACS"} {
		indexOf(t, got, want)
	}
	rm := indexOf(t, got, "no tacacs server OLD-TACACS")
	idx := slices.Index(got, "aaa group server tacacs+ OLD-GROUP")
	if idx < 0 || idx > rm {
		t.Errorf("the other group's entry is not removed before the block:\n%s", strings.Join(got, "\n"))
	}
	c := ParseIOS(capture(t, f.raw))
	c.insertBlock(iosBlk{lines: []string{"aaa group server tacacs+ OLD-GROUP", " server name OLD-TACACS"}})
	if err := c.Apply(d.Lines); err != nil {
		t.Fatalf("%v\n%s", err, d.Display())
	}
	if !strings.Contains(c.Text(), "aaa group server tacacs+ OLD-GROUP\n server name TACACS\n") {
		t.Errorf("the other group does not name the standard block:\n%s", c.Text())
	}
}

// With nothing that proves the pasting session (command authorization on, no
// list names a group) a named block at the address is refused with the steps
// by hand, as the legacy line is.
func TestSameAddressBlockUnprovenIsByHand(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	d := planI(t, f, func(c *IOSConfig) {
		c.noGlobal("aaa authentication login default")
		c.noGlobal("aaa authorization exec default")
	}, Options{Scope: "lab", Device: "sw-lab-1"})
	if st := d.Of("aaa"); st.State != StateSkipped || st.Kind != KindRefused {
		t.Fatalf("aaa: %+v", st)
	}
	steps := strings.Join(d.ByHand, "\n")
	for _, want := range []string{"    no tacacs server OLD-TACACS\n", "    aaa group server tacacs+ TACACS-GROUP\n     server name TACACS\n     no server name OLD-TACACS\n    exit\n"} {
		if !strings.Contains(steps, want) {
			t.Errorf("the steps lack %q:\n%s", want, steps)
		}
	}
	// the old block is an extra left alone, as before
	wantKept(t, d, "aaa", "tacacs server OLD-TACACS")
}

// The old block is replaced when the plan types the key only (the address is
// there): IOS refuses the key as the second copy.
func TestSameAddressBlockKeyOnly(t *testing.T) {
	f := fixtureNamed(t, "cisco.same-address-block")
	d := planI(t, f, func(c *IOSConfig) {
		// the standard's block exists with its address, and lacks the key
		c.insertBlock(iosBlk{lines: []string{"tacacs server TACACS", " address ipv4 192.0.2.10", " single-connection", " timeout 5"}})
	}, Options{Scope: "lab"})
	got := regionStatements(d)
	rm := indexOf(t, got, "no tacacs server OLD-TACACS")
	key := indexOf(t, got, " key lab-secret-0123456789abcdef")
	if rm > key {
		t.Errorf("the old block is removed after the key is typed:\n%s", strings.Join(got, "\n"))
	}
	// a block that has its address and key needs nothing: the old one is an
	// extra left to --converge
	d = planI(t, f, func(c *IOSConfig) {
		c.insertBlock(iosBlk{lines: []string{"tacacs server TACACS", " address ipv4 192.0.2.10", " key 7 0822455D0A16", " single-connection", " timeout 5"}})
	}, Options{Scope: "lab"})
	if slices.Contains(regionStatements(d), "no tacacs server OLD-TACACS") {
		t.Errorf("the old block is removed with nothing to add beside it")
	}
	wantKept(t, d, "aaa", "tacacs server OLD-TACACS")
}

// RADIUS: a named block of another name at the address and ports of the
// standard's is replaced the same way (no command authorization is involved).
func TestSameAddressRadiusBlock(t *testing.T) {
	f := fixtureNamed(t, "cisco.xe-reference-16")
	mut := func(c *IOSConfig) {
		for i := range c.blocks {
			switch {
			case c.blocks[i].lines[0] == "radius server RADIUS":
				c.blocks[i].lines[0] = "radius server OLD-RADIUS"
			case strings.HasPrefix(c.blocks[i].lines[0], "aaa group server radius "):
				c.blocks[i].lines = []string{c.blocks[i].lines[0], " server name OLD-RADIUS"}
			}
		}
	}
	d := planI(t, f, mut, Options{Scope: "lab"})
	got := regionStatements(d)
	ent := slices.IndexFunc(got, func(s string) bool { return s == " no server name OLD-RADIUS" })
	rm := indexOf(t, got, "no radius server OLD-RADIUS")
	blk := slices.Index(got, "radius server RADIUS")
	if ent < 0 || ent > rm || blk < rm {
		t.Errorf("the order (%d, %d, %d):\n%s", ent, rm, blk, strings.Join(got, "\n"))
	}
	c := ParseIOS(capture(t, f.raw))
	mut(c)
	if err := c.Apply(d.Lines); err != nil {
		t.Fatalf("%v\n%s", err, d.Display())
	}
	// another port is another server: kept
	d = planI(t, f, func(c *IOSConfig) {
		mut(c)
		for i := range c.blocks {
			if c.blocks[i].lines[0] == "radius server OLD-RADIUS" {
				for j, l := range c.blocks[i].lines {
					if strings.HasPrefix(strings.TrimSpace(l), "address ipv4 ") {
						c.blocks[i].lines[j] = " address ipv4 192.0.2.10 auth-port 11812 acct-port 11813"
					}
				}
			}
		}
	}, Options{Scope: "lab"})
	if slices.Contains(regionStatements(d), "no radius server OLD-RADIUS") {
		t.Errorf("a block on other ports was removed")
	}
}

// The ios12 standard is the legacy host line itself: a legacy line is no
// hazard and nothing of the old-form logic applies.
func TestSameAddressIOS12Untouched(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, func(c *IOSConfig) {
		c.noGlobal("tacacs-server host")
	}, Options{Scope: "lab"})
	for _, l := range regionStatements(d) {
		if strings.HasPrefix(l, "no tacacs-server") || strings.HasPrefix(l, "no aaa authorization") {
			t.Errorf("a removal on ios12: %q", l)
		}
	}
	if len(d.ByHand) != 0 {
		t.Errorf("by hand: %q", d.ByHand)
	}
}
