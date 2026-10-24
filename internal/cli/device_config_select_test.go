package cli

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// The selectors of the config verbs (D267): --differs, --name and --ip join
// names, --all, --scope, --vendor and --stale on pull, diff, plan and apply,
// and --name and --ip join list.

// selBox is a pullBox with devices in every state of a pull record: ok
// (core-sw1), differs (core-sw2), never (edge-r1), failed (lab-j) and, where
// the scope is served over TACACS+, a Cisco device whose syntax nothing says
// (lab-c, state pull).
func newSelBox(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.devices([3]string{"core-sw1", "10.20.0.1", "juniper"}, [3]string{"core-sw2", "10.20.0.2", "juniper"},
		[3]string{"edge-r1", "10.30.0.5", "juniper"}, [3]string{"lab-j", "192.168.1.20", "juniper"},
		[3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("juniper", b.expected("core-sw1"))
	b.run("device", "config", "pull", "core-sw1", "core-sw2")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	// core-sw2 is read again, missing a statement tacctl renders.
	var kept []string
	dropped := false
	for _, l := range strings.Split(strings.TrimSpace(b.expected("core-sw2")), "\n") {
		if !dropped && strings.HasPrefix(l, "set system authentication-order") {
			dropped = true
			continue
		}
		kept = append(kept, l)
	}
	if !dropped {
		t.Fatal("no authentication-order statement to drop")
	}
	b.serve("juniper", strings.Join(kept, "\n")+"\n")
	b.run("device", "config", "pull", "core-sw2")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	b.putRecord("lab-j", devconf.Record{Address: "192.168.1.20", Vendor: "juniper", Result: "timeout"})
	// A Cisco record whose version line was never read: the syntax is
	// unknown, so the state is pull, neither stale-by-differing nor ok.
	b.serve("cisco", b.expected("lab-c"))
	b.run("device", "config", "pull", "lab-c")
	recs := b.records()
	if rec, _ := recs.Of("lab-c"); rec != nil {
		rec.OS, rec.Syntax = "", ""
		b.putRecord("lab-c", *rec)
	}
	return b
}

// states are the devices of newSelBox by the state 'device config list' shows.
func (b *pullBox) states() map[string]string {
	b.t.Helper()
	out := b.run("device", "config", "list", "--json")
	var rows []listJSON
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		b.t.Fatalf("list --json: %v\n%s", err, out)
	}
	m := map[string]string{}
	for _, r := range rows {
		m[r.Name] = r.State
	}
	return m
}

// chosen is the names a verb's selector line picks, in the registry's order.
func (b *pullBox) chosen(verb string, args ...string) ([]string, error) {
	b.t.Helper()
	inv := b.invoke()
	p, err := Parse(deviceConfigSpecs[verb], args)
	if err != nil {
		return nil, err
	}
	sel, err := inv.parseSelection(p, verb)
	if err != nil {
		return nil, err
	}
	c, err := inv.chooseDevices(sel, "alice", true, verb, managedOptions{})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range c.entries {
		names = append(names, e.Name)
	}
	return names, nil
}

func TestParseSelectionTextFiltersAndDiffers(t *testing.T) {
	b := newPullBox(t)
	inv := b.invoke()
	for _, c := range []struct {
		args    []string
		differs bool
		names   []string
		addrs   []string
		stale   bool
		scope   string
		err     string
	}{
		{args: []string{"--differs"}, differs: true},
		{args: []string{"--name", "Core, edge"}, names: []string{"core", "edge"}},
		{args: []string{"--ip", "10.20.0.0/24,192.168.1."}, addrs: []string{"10.20.0.0/24", "192.168.1."}},
		{args: []string{"--stale", "--differs", "--scope", "prod", "--name", "sw", "--ip", "10."},
			stale: true, differs: true, scope: "prod", names: []string{"sw"}, addrs: []string{"10."}},
		{args: []string{"--name", "sw"}, names: []string{"sw"}},
		{args: []string{"--ip", "10.20.0.1"}, addrs: []string{"10.20.0.1"}},
		// the refusals, with the new flags among the words
		{args: []string{"core-sw1", "--differs"}, err: "--differs, --name or --ip, not both"},
		{args: []string{"core-sw1", "--name", "sw"}, err: "not both"},
		{args: []string{"core-sw1", "--ip", "10."}, err: "not both"},
		{args: []string{"--all", "--differs"}, err: "--all is every device; drop it to select with --scope, --vendor, --stale, --differs, --name or --ip"},
		{args: []string{"--all", "--name", "sw"}, err: "--all is every device"},
		{args: []string{"--all", "--ip", "10."}, err: "--all is every device"},
		{args: nil, err: "--stale, --differs, --name <text> or --ip <addr|cidr|text>"},
		{args: []string{"--name", ""}, err: "--name takes a text"},
		{args: []string{"--ip", ",,"}, err: "--ip takes a text"},
	} {
		p, err := Parse(deviceConfigSpecs["pull"], c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		sel, err := inv.parseSelection(p, "pull")
		if c.err != "" {
			if got := inv.app.Out.Stderr.(*bytes.Buffer).String(); err == nil || !strings.Contains(got, c.err) {
				t.Errorf("%v: err %v, stderr %q (want %q)", c.args, err, got, c.err)
			}
			inv.app.Out.Stderr.(*bytes.Buffer).Reset()
			continue
		}
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if sel.differs != c.differs || sel.stale != c.stale || sel.scope != c.scope ||
			!slices.Equal(sel.nameFilter, c.names) || !slices.Equal(sel.addrFilter, c.addrs) {
			t.Errorf("%v: %+v", c.args, sel)
		}
	}
}

// Each of the five verbs takes the three flags; the usage lines name them.
func TestSelectorsAreInEveryVerbsSpecAndUsage(t *testing.T) {
	for _, verb := range []string{"pull", "diff", "plan", "apply", "list"} {
		for _, f := range []string{"--name", "--ip", "--differs"} {
			if !slices.ContainsFunc(deviceConfigSpecs[verb].Flags, func(fl Flag) bool { return slices.Contains(fl.Names, f) }) {
				t.Errorf("device config %s does not take %s", verb, f)
			}
			if !strings.Contains(deviceConfigUse(verb), f) {
				t.Errorf("the usage of device config %s does not name %s: %s", verb, f, deviceConfigUse(verb))
			}
		}
	}
}

func TestChooseDevicesByNameIPAndDiffers(t *testing.T) {
	b := newSelBox(t)
	st := b.states()
	for name, want := range map[string]string{"core-sw1": "ok", "core-sw2": "differs", "edge-r1": "never", "lab-j": "failed"} {
		if st[name] != want {
			t.Fatalf("state of %s is %q, want %q (%v)", name, st[name], want, st)
		}
	}
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"--name", "core"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--name", "CORE"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--name", "sw2,edge"}, []string{"core-sw2", "edge-r1"}},
		{[]string{"--name", "nothing-like-it"}, nil},
		{[]string{"--ip", "10.20.0.0/24"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--ip", "10.20.0.2"}, []string{"core-sw2"}},
		{[]string{"--ip", "192.168.1."}, []string{"lab-c", "lab-j"}},
		{[]string{"--ip", "10.30.0.5,192.168.1.20"}, []string{"edge-r1", "lab-j"}},
		{[]string{"--ip", "198.51.100.0/24"}, nil},
		// --differs is the state differs alone: not never, failed or pull
		{[]string{"--differs"}, []string{"core-sw2"}},
		{[]string{"--differs", "--name", "core"}, []string{"core-sw2"}},
		{[]string{"--differs", "--name", "edge"}, nil},
		{[]string{"--differs", "--ip", "10.20.0.1"}, nil},
		{[]string{"--differs", "--scope", "prod"}, []string{"core-sw2"}},
		{[]string{"--differs", "--scope", "lab"}, nil},
		{[]string{"--differs", "--vendor", "cisco"}, nil},
		// --stale is never, failed, differs and pull; with --differs both hold
		{[]string{"--stale", "--name", "core"}, []string{"core-sw2"}},
		{[]string{"--stale", "--differs"}, []string{"core-sw2"}},
		{[]string{"--stale", "--ip", "10.0.0.0/8"}, []string{"core-sw2", "edge-r1"}},
		// the filters combine with --scope and --vendor
		{[]string{"--scope", "prod", "--name", "sw"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--scope", "lab", "--name", "sw"}, nil},
		{[]string{"--vendor", "cisco", "--ip", "192.168.1.0/24"}, []string{"lab-c"}},
		{[]string{"--vendor", "juniper", "--ip", "192.168.1.0/24", "--name", "lab"}, []string{"lab-j"}},
		{[]string{"--name", "lab", "--ip", "10.0.0.0/8"}, nil},
	} {
		var first []string
		for i, verb := range []string{"pull", "diff", "plan", "apply"} {
			got, err := b.chosen(verb, c.args...)
			if err != nil {
				t.Errorf("%s %v: %v", verb, c.args, err)
				continue
			}
			if i == 0 {
				first = got
				if sorted := slices.Sorted(slices.Values(got)); !slices.Equal(sorted, c.want) {
					t.Errorf("%v: %v, want %v", c.args, got, c.want)
				}
			} else if !slices.Equal(got, first) {
				t.Errorf("%s %v picks %v, pull picks %v", verb, c.args, got, first)
			}
		}
	}
}

// The state 'pull' (a Cisco device whose syntax nothing says) is --stale,
// never --differs, when its scope is served over TACACS+.
func TestDiffersLeavesOutThePullState(t *testing.T) {
	b := newSelBox(t)
	st := b.states()
	if st["lab-c"] != "pull" {
		t.Skipf("lab-c is %q here, not pull: the scope's syntax does not matter", st["lab-c"])
	}
	stale, err := b.chosen("pull", "--stale", "--vendor", "cisco")
	if err != nil || !slices.Equal(stale, []string{"lab-c"}) {
		t.Errorf("--stale: %v %v", stale, err)
	}
	differs, err := b.chosen("pull", "--differs", "--vendor", "cisco")
	if err != nil || len(differs) != 0 {
		t.Errorf("--differs: %v %v", differs, err)
	}
}

// A record whose sections cannot be read is never, not differs.
func TestDiffersLeavesOutAnUnreadableRecord(t *testing.T) {
	b := newSelBox(t)
	b.sb.write("var-lib/device-config/core-sw2.yaml", "aaa: [unclosed\n", 0o600)
	got, err := b.chosen("diff", "--differs")
	if err != nil || len(got) != 0 {
		t.Errorf("--differs: %v %v", got, err)
	}
	got, err = b.chosen("diff", "--stale", "--name", "core-sw2")
	if err != nil || !slices.Equal(got, []string{"core-sw2"}) {
		t.Errorf("--stale: %v %v", got, err)
	}
}

// applyStaleFilters is the step on its own: the entries it is given, filtered
// by the records, with no login.
func TestApplyStaleFiltersOnItsOwn(t *testing.T) {
	b := newSelBox(t)
	inv := b.invoke()
	logins := b.srv.Logins()
	c, err := inv.chooseDevices(selection{all: true}, "alice", true, "pull", managedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.entries) != 5 {
		t.Fatalf("--all picks %d devices", len(c.entries))
	}
	inv.applyStaleFilters(selection{all: true}, c)
	if len(c.entries) != 5 {
		t.Errorf("no filter left %d devices", len(c.entries))
	}
	inv.applyStaleFilters(selection{differs: true}, c)
	if len(c.entries) != 1 || c.entries[0].Name != "core-sw2" {
		t.Errorf("--differs left %v", c.entries)
	}
	if n := b.srv.Logins() - logins; n != 0 {
		t.Errorf("a selector made %d logins", n)
	}
}

func TestSelectorsMakeNoLogin(t *testing.T) {
	b := newSelBox(t)
	before := b.srv.Attempts()
	for _, verb := range []string{"pull", "diff", "plan", "apply"} {
		if _, err := b.chosen(verb, "--differs", "--name", "core", "--ip", "10.0.0.0/8"); err != nil {
			t.Errorf("%s: %v", verb, err)
		}
	}
	if b.srv.Attempts() != before {
		t.Error("a selector dialled a device")
	}
}

// diff, plan and pull end to end: the same set.
func TestVerbsRunOnTheSelectedSet(t *testing.T) {
	b := newSelBox(t)
	out := b.run("device", "config", "diff", "--differs", "--json")
	var docs []diffDeviceJSON
	if err := json.Unmarshal([]byte(out), &docs); err != nil || len(docs) != 1 || docs[0].Name != "core-sw2" {
		t.Errorf("diff --differs: %v\n%s", err, out)
	}
	out = b.run("device", "config", "diff", "--name", "core", "--ip", "10.20.0.1", "--json")
	if err := json.Unmarshal([]byte(out), &docs); err != nil || len(docs) != 1 || docs[0].Name != "core-sw1" || docs[0].Status != "ok" {
		t.Errorf("diff --name --ip: %v\n%s", err, out)
	}
	out = b.run("device", "config", "diff", "--name", "no-such", "--json")
	if b.sb.code != 0 || strings.TrimSpace(out) != "[]" {
		t.Errorf("diff, nothing selected: %d %q", b.sb.code, out)
	}
	out = b.run("device", "config", "plan", "--differs", "--plain")
	if b.sb.code != 0 || !strings.Contains(out, "set system authentication-order") {
		t.Errorf("plan --differs: %d\n%s", b.sb.code, out)
	}
	out = b.run("device", "config", "pull", "--differs")
	if b.sb.code != 0 || !strings.Contains(out, "core-sw2") || strings.Contains(out, "core-sw1") || strings.Contains(out, "edge-r1") {
		t.Errorf("pull --differs: %d\n%s", b.sb.code, out)
	}
}

func TestListNameAndIP(t *testing.T) {
	b := newSelBox(t)
	names := func(args ...string) []string {
		out := b.run(append([]string{"device", "config", "list", "--json"}, args...)...)
		var rows []listJSON
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		var got []string
		for _, r := range rows {
			got = append(got, r.Name)
		}
		return got
	}
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"--name", "core"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--name", "SW2,edge"}, []string{"core-sw2", "edge-r1"}},
		{[]string{"--ip", "10.20.0.0/24"}, []string{"core-sw1", "core-sw2"}},
		{[]string{"--ip", "192.168.1."}, []string{"lab-c", "lab-j"}},
		{[]string{"--ip", "10.30.0.5"}, []string{"edge-r1"}},
		{[]string{"--name", "lab", "--ip", "192.168.1.20"}, []string{"lab-j"}},
		{[]string{"--name", "lab", "--ip", "10.0.0.0/8"}, []string{}},
		// beside the state words, which stay alternatives of each other
		{[]string{"--differs", "--name", "core"}, []string{"core-sw2"}},
		{[]string{"--never", "--ip", "10.0.0.0/8"}, []string{"edge-r1"}},
		{[]string{"--failed", "--name", "core"}, []string{}},
		{[]string{"--stale", "--scope", "prod", "--name", "sw"}, []string{"core-sw2"}},
		{[]string{"--never", "--failed", "--ip", "10.30.0.5,192.168.1.20"}, []string{"edge-r1", "lab-j"}},
	} {
		if got := slices.Sorted(slices.Values(names(c.args...))); !slices.Equal(got, c.want) {
			t.Errorf("%v: %v, want %v", c.args, got, c.want)
		}
	}
	out := b.run("device", "config", "list", "--name", "no-such")
	if b.sb.code != 0 || !strings.Contains(out, "None: no device matches.") {
		t.Errorf("list, nothing matches: %d\n%s", b.sb.code, out)
	}
	for _, flag := range []string{"--name", "--ip"} {
		b.run("device", "config", "list", flag, ",")
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), flag+" takes a text") {
			t.Errorf("list %s ,: %d %q", flag, b.sb.code, b.sb.stderr())
		}
	}
}

// A filter given with no value is refused, not read as "every device"; a
// local login names one device and says which selectors it refuses.
func TestEmptyScopeIsRefused(t *testing.T) {
	b := newSelBox(t)
	for _, args := range [][]string{
		{"device", "config", "list", "--scope="},
		{"device", "config", "pull", "--scope="},
		{"device", "config", "apply", "--scope=", "--check"},
		{"device", "config", "apply", "--scope", "", "--check"},
	} {
		b.run(args...)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--scope takes a scope name.") {
			t.Errorf("%v: exit %d, stderr %q", args, b.sb.code, b.sb.stderr())
		}
	}
	b.run("device", "config", "pull", "--login", "root", "--all")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--differs, --name or --ip") {
		t.Errorf("--login with --all: exit %d, stderr %q", b.sb.code, b.sb.stderr())
	}
}
