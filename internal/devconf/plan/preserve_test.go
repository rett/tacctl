package plan

// What a plan must not do, checked on the applied result (Opus review
// MEDIUM 8): the operator's statements survive (only what an owned row of
// the table says, or a replaced single-valued leaf, goes), no statement of a
// group is touched, and on IOS the back-out brings the managed sections
// back to what the device had.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// ownedJunosPath reports whether a statement path is inside an object an
// ownership row names: a '$' row needs the name the rendering sets, a row
// with a depth the statement's length.
func ownedJunosPath(exp []devices.Section, path []string) bool {
	for _, sec := range exp {
		for _, r := range junosRows(sec.Name, sec) {
			name, at, ok := matchPrefix(r.pat, path)
			if !ok {
				continue
			}
			if at >= 0 && !r.names[name] {
				continue
			}
			if r.Depth != 0 && len(path) != r.Depth {
				continue
			}
			return true
		}
	}
	return false
}

// checkJunosPreserved: every statement the plan took off the device is in an
// owned object, was named by a delete line (or replaced by a set of its
// single-valued leaf), and was not inherited.
func checkJunosPreserved(t *testing.T, f fixture, exp []devices.Section, before, after *JunosConfig, d Delta, inherited map[string]bool, label string) {
	t.Helper()
	have := map[string]bool{}
	for _, s := range after.stmts {
		have[s.text()] = true
	}
	for _, s := range before.stmts {
		if have[s.text()] {
			continue
		}
		if inherited[s.text()] {
			t.Errorf("%s %s: the plan changed a statement of a group: %s\n%s", f.name, label, s.text(), d.Display())
		}
		named := false
		for _, l := range d.Lines {
			tk := splitTokens(l.Text)
			switch {
			case l.Op == OpDelete && len(tk) > 1 && len(s.path) >= len(tk)-1 && slices.Equal(s.path[:len(tk)-1], tk[1:]):
				named = true
			case l.Op == OpSet && len(tk) > 2:
				// a line of several leaves (an NTP key's type and value) is
				// one statement per leaf on the device
				for _, lp := range splitLeaves(tk[1:]) {
					if n := singleKeyLen(s.path); n > 0 && len(lp) > n && slices.Equal(lp[:n], s.path[:n]) {
						named = true // replaced in place
					}
				}
			}
		}
		if !named {
			t.Errorf("%s %s: %s went and no line of the plan names it\n%s", f.name, label, s.text(), d.Display())
		}
		// a replaced leaf of a rendered user is owned by the pattern too;
		// everything else must be inside an owned object
		if !ownedJunosPath(exp, s.path) {
			t.Errorf("%s %s: %s is outside every owned object and the plan removed it\n%s", f.name, label, s.text(), d.Display())
		}
	}
}

// iosFlat lists a configuration as 'header > leaf' lines (a global line
// alone), normalised.
func iosFlat(c *IOSConfig) map[string]bool {
	out := map[string]bool{}
	for _, b := range c.blocks {
		h := norm(b.lines[0])
		if h == "" || strings.HasPrefix(h, "!") {
			continue
		}
		if len(b.lines) == 1 {
			out[h] = true
		}
		for _, l := range b.lines[1:] {
			ck := childKey(h, l)
			if !strings.Contains(ck, pathSep) {
				ck = h + pathSep + ck
			}
			out[ck] = true
		}
	}
	return out
}

// checkIOSPreserved: every line the plan took off was named by a 'no' of an
// owned object, or replaced by a typed line with the same key.
func checkIOSPreserved(t *testing.T, f fixture, exp []devices.Section, before, after *IOSConfig, d Delta, label string) {
	t.Helper()
	b, a := iosFlat(before), iosFlat(after)
	// a header with children on either side is no line of its own
	for _, c := range []*IOSConfig{before, after} {
		for _, blk := range c.blocks {
			if len(blk.lines) > 1 {
				h := norm(blk.lines[0])
				delete(b, h)
				delete(a, h)
			}
		}
	}
	st := &iosState{entries: map[string][]iosEntry{}, kinds: map[string]map[string]bool{}, levels: map[string]bool{},
		acls: map[string]bool{}, renderedKeys: map[string]bool{}}
	for _, s := range exp {
		for _, e := range parseIOSExpected(s) {
			st.entries[s.Name] = append(st.entries[s.Name], e)
			path := e.path()
			if len(path) > 1 {
				h := strings.Join(path[:len(path)-1], pathSep)
				if st.kinds[h] == nil {
					st.kinds[h] = map[string]bool{}
				}
				st.kinds[h][strings.Fields(path[len(path)-1])[0]] = true
				if isACLHeader(path[0]) {
					st.acls[path[0]] = true
				}
			} else if g := strings.Fields(path[0]); len(g) >= 4 && g[0] == "privilege" {
				if i := slices.Index(g, "level"); i >= 0 {
					st.levels[g[i+1]] = true
				}
			}
			if k, ok := iosKey(path); ok {
				st.renderedKeys[k] = true
			}
		}
	}
	// the server blocks the plan removes whole, by their header: only a block
	// of another name at the address the standard types (D117, amended)
	removedBlock := map[string]bool{}
	for _, l := range d.Lines {
		if l.Op == OpNo && len(l.Context) == 0 && (strings.HasPrefix(l.Text, "tacacs server ") || strings.HasPrefix(l.Text, "radius server ")) {
			removedBlock[norm(l.Text)] = true
		}
	}
	for line := range b {
		if a[line] {
			continue
		}
		// an ACL's retyped entry is a removal and an add of the same text
		if strings.HasPrefix(line, "line ") && strings.Contains(line, " > login") {
			continue // replaced by the rendered leaf under the same range
		}
		path := strings.Split(line, pathSep)
		ok := false
		for _, l := range d.Lines {
			full := append(slices.Clone(l.Context), norm(l.Text))
			switch l.Op {
			case OpNo:
				cand := strings.Join(full, pathSep)
				if cand == line || strings.HasPrefix(line, cand+" ") {
					ok = true
				}
				if len(l.Context) == 0 && norm(l.Text) == path[0] { // a block header
					ok = true
				}
			case OpLine:
				k1, ok1 := iosKey(path)
				k2, ok2 := iosKey(full)
				if ok1 && ok2 && k1 == k2 {
					ok = true
				}
			}
		}
		if !ok {
			t.Errorf("%s %s: %q went and no line of the plan names it\n%s", f.name, label, line, d.Display())
			continue
		}
		// owned: an ACL entry of a rendered ACL, a leaf of a rendered
		// server block or group, a privilege exec line of a rendered level,
		// a commands list the rendering lacks, a method list it types
		head := path[0]
		leaf := path[len(path)-1]
		lf := strings.Fields(leaf)
		switch {
		case len(path) == 2 && isACLHeader(head) && st.acls[head]:
		case len(path) == 2 && removedBlock[head]:
			// D117 (amended): a leaf of an old server block the region removes
			// whole, at the standard's address
		case len(path) == 2 && st.kinds[head] != nil && st.kinds[head][lf[0]]:
		case len(path) == 1 && lf[0] == "privilege" && len(lf) >= 5 && lf[1] == "exec" && st.levels[lf[slices.Index(lf, "level")+1]]:
		case len(path) == 1 && lf[0] == "aaa":
		case len(path) == 1 && lf[0] == "tacacs-server":
		case len(path) == 1 && lf[0] == "snmp-server" && len(lf) > 1 && (lf[1] == "location" || lf[1] == "contact"):
		default:
			t.Errorf("%s %s: %q is outside every owned object and the plan removed it\n%s", f.name, label, line, d.Display())
		}
	}
}

// checkIOSBackout applies the plan and then its back-out: the managed
// sections read as they did before (the 15.x privilege residue is not
// modelled by the editor).
func checkIOSBackout(t *testing.T, f fixture, exp []devices.Section, raw string, d Delta, label string) {
	t.Helper()
	// A device with aaa lines and no 'aaa new-model' does not exist on IOS
	// ('no aaa new-model' removes them): the fuzz makes such a device, and
	// 'no aaa new-model' cannot give back what it removes with it.
	if d.AddsAAA && strings.Contains("\n"+raw, "\naaa ") {
		return
	}
	c := ParseIOS(raw)
	if err := c.Apply(d.Lines); err != nil {
		t.Fatalf("%s %s: %v", f.name, label, err)
	}
	var back []Line
	for _, l := range iosBackout(d) {
		if l.Op != OpComment {
			back = append(back, l)
		}
	}
	for _, l := range back {
		if l.Op == OpNo && len(l.Context) == 0 && strings.HasPrefix(l.Text, "line ") {
			t.Errorf("%s %s: the back-out removes %q", f.name, label, l.Text)
		}
	}
	if err := c.Apply(back); err != nil {
		t.Fatalf("%s %s: %v", f.name, label, err)
	}
	orig, err := devconf.Extract(f.vendor, raw, exp...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := devconf.Extract(f.vendor, c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	// a line the plan removed whose key is the device's own (D117: the old
	// server entry) is given back by a note, never by a line: the back-out
	// cannot type a value tacctl does not hold
	noted := map[string]bool{}
	for _, l := range d.Lines {
		for _, u := range l.Undo {
			if s, ok := strings.CutPrefix(u.Text, "type again with its original secret: "); ok && u.Op == OpComment && l.Op == OpNo {
				noted[strings.TrimSuffix(s, " "+secretMark)] = true
			}
		}
	}
	for _, name := range []string{"aaa", "roles", "snmp", "mgmt-acl"} {
		o := slices.DeleteFunc(slices.Clone(orig.Sections[name].Lines), func(s string) bool { return noted[s] || noted[strings.TrimSuffix(s, " "+secretMark)] })
		g := slices.Clone(got.Sections[name].Lines)
		slices.Sort(o)
		slices.Sort(g)
		if !slices.Equal(o, g) {
			t.Errorf("%s %s [%s]: the back-out does not restore the section:\n before %q\n after  %q\n%s", f.name, label, name, o, g, d.Display())
		}
	}
}
