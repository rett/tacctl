package cli

// The scope's snmp configuration block in what the verbs render (0.2.7): the
// walkthroughs and the managed sections of the batch verbs carry it, a block
// with an error is never rendered in part and the refusal says how to see
// what is wrong, and IOS devices are not touched.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

const cliBlockFile = "set snmp community nms-ro authorization read-only\n" +
	"set snmp community nms-ro clients 192.0.2.50/32\n" +
	"set snmp trap-group nms-traps targets 198.51.100.7\n"

func (sb *sandbox) putBlock(scope, text string) {
	sb.t.Helper()
	for _, d := range []string{"state/blocks", "state/blocks/" + scope, "state/blocks/" + scope + "/juniper"} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
	}
	sb.write("state/blocks/"+scope+"/juniper/snmp", text, 0o600)
	sb.write("state/tacctl.yaml", sb.overrides()+"blocks:\n  "+scope+":\n    juniper:\n    - snmp\n", 0o640)
}

func TestWalkthroughCarriesTheSNMPBlock(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	without := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	ciscoWithout := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "sw-c"}, route))
	sb.putBlock("lab", cliBlockFile)

	out := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	sb.expect(0, "Juniper Junos Configuration", "")
	for _, want := range []string{"set snmp community lab-community-9 authorization read-only",
		"# The snmp block of scope 'lab' (tacctl scope block lab juniper show snmp): its communities, trap groups and trap options.\n" +
			"set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 192.0.2.50/32\nset snmp trap-group nms-traps targets 198.51.100.7\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("the walkthrough lacks %q:\n%s", want, out)
		}
	}
	if out == without {
		t.Error("the block changed nothing")
	}
	// 'device config show' is the same code
	got := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-j"}, route))
	if !strings.HasSuffix(got, out) {
		t.Errorf("device config show does not end in the walkthrough:\n%s", got)
	}
	// IOS: blocks are the release after
	if got := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "sw-c"}, route)); got != ciscoWithout {
		t.Errorf("the IOS walkthrough changed:\n%s", got)
	}

	// A block with an error is not rendered in part: the refusal names the
	// scope and the verb, and no string.
	sb.putBlock("lab", cliBlockFile+"set snmp community short authorization read-only\nset snmp community nms-two\n")
	got = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	if sb.code != 1 || got != "" {
		t.Fatalf("a block with errors: %d %q", sb.code, got)
	}
	for _, want := range []string{"The snmp block of scope 'lab' has errors", "tacctl scope block lab juniper check snmp"} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, sb.stderr())
		}
	}
	for _, bad := range []string{"nms-ro", "nms-two", "short"} {
		if strings.Contains(sb.stderr(), bad) {
			t.Errorf("the refusal holds a string: %q\n%s", bad, sb.stderr())
		}
	}
	// the scope's own community as a block community
	sb.putBlock("lab", "set snmp community lab-community-9 authorization read-only\nset snmp community lab-community-9 clients 192.0.2.50/32\n")
	sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route)
	if sb.code != 1 || strings.Contains(sb.stderr(), "lab-community-9") || !strings.Contains(sb.stderr(), "Community 1 of the SNMP block of scope 'lab'") {
		t.Errorf("a block that names the scope's community: %d\n%s", sb.code, sb.stderr())
	}
}

func TestBatchRenderCarriesTheSNMPBlock(t *testing.T) {
	b := newPullBox(t)
	b.sb.dev("", "scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("lab-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.sb.dev("", "scope", "snmp", "prod", "version", "v2c")
	b.sb.cfgRun("prod-community-9\n", []string{"scope", "snmp", "prod", "community", "--stdin"}, route)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"})
	b.sb.putBlock("lab", cliBlockFile)
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	var entries []devreg.Entry
	for _, n := range []string{"lab-j1", "prod-j"} {
		e, ok := res.Lookup(n, devreg.ScopeFilter{})
		if !ok {
			t.Fatalf("no %s", n)
		}
		entries = append(entries, e)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	lab, err := r.Expected(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	var snmp devices.Section
	for _, sec := range lab {
		if sec.Name == "snmp" {
			snmp = sec
		}
	}
	if len(snmp.Block) != len(snmp.Lines) {
		t.Fatalf("Block %v for %v", snmp.Block, snmp.Lines)
	}
	var fromBlock []string
	for i, l := range snmp.Lines {
		if snmp.Block[i] {
			fromBlock = append(fromBlock, l)
			if !snmp.Secret[i] {
				t.Errorf("%q is not a secret", l)
			}
		}
	}
	if strings.Join(fromBlock, "\n") != strings.TrimSuffix(cliBlockFile, "\n") {
		t.Errorf("the block's statements:\n%s", strings.Join(fromBlock, "\n"))
	}
	// another scope carries none
	s, err := r.Expected(entries[1])
	if err != nil {
		t.Fatalf("%s: %v", entries[1].Name, err)
	}
	if strings.Contains(flat(s), "nms-ro") {
		t.Errorf("%s carries the block", entries[1].Name)
	}

	// An error in the block is the scope's Junos devices' problem and nobody
	// else's.
	b.sb.putBlock("lab", "set snmp community nms-ro authorization read-only\n")
	r = b.invoke().newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	_, err = r.Expected(entries[0])
	if err == nil {
		t.Fatal("a block with no clients was rendered")
	}
	for _, want := range []string{"scope 'lab'", "tacctl scope block lab juniper check snmp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the problem lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "nms-ro") {
		t.Errorf("the problem holds a string: %v", err)
	}
	if _, err := r.Expected(entries[1]); err != nil {
		t.Errorf("%s: %v", entries[1].Name, err)
	}
}
