package cli

// 'device block' and the device level of the resolution (0.2.7, B4 and B8):
// the verbs, the engineer's reach, and what the renderers make of a device's
// own block laid over its scope's.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

const (
	// the scope's block: one community with a client, and a trap group
	scopeLevelSNMP = "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 192.0.2.50/32\n" +
		"set snmp community poller-two authorization read-only\nset snmp community poller-two clients 192.0.2.60/32\n" +
		"set snmp trap-group nms-traps targets 198.51.100.7\n"
	// the device's: replaces nms-ro whole (another client) and adds one
	deviceLevelSNMP = "set snmp community nms-ro authorization read-write\nset snmp community nms-ro clients 198.51.100.0/24\n" +
		"set snmp community dev-extra authorization read-only\nset snmp community dev-extra clients 203.0.113.9/32\n"
)

// devb runs 'tacctl device block <args>' as the superuser.
func (sb *sandbox) devb(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"device", "block"}, args...), route))
}

func TestDeviceBlockSetShowListRemove(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "js1.lab.example.net", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	f := sb.blockFile("snmp.txt", verbSNMPFile)
	dir := "state/blocks/_devices/js1.lab.example.net/juniper/"

	out := sb.devb("", "js1.lab.example.net", "list")
	if sb.code != 0 || !strings.Contains(out, "none: device 'js1.lab.example.net' has no juniper block.") {
		t.Errorf("list: %d\n%s", sb.code, out)
	}
	n := sb.snapshots()
	out = sb.devb("", "JS1.lab.example.net", "set", "snmp", "--file", f, "-y")
	if sb.code != 0 || !strings.Contains(out, "The snmp block of device 'js1.lab.example.net' is set (") {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "set", out+sb.stderr(), "nms-ro-secret", "nms-traps-secret")
	if sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, sb.snapshots())
	}
	if got := sb.read(dir + "snmp"); got != verbSNMPFile {
		t.Errorf("file: %q", got)
	}
	if st, err := os.Stat(sb.path(dir + "snmp")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", st, err)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks_device:\n  js1~lab~example~net:\n    juniper:\n    - snmp\n") {
		t.Errorf("manifest:\n%s", o)
	}
	if sb.logged("block-set name=_devices/js1.lab.example.net/juniper/snmp bytes=") != 1 {
		t.Errorf("log: %q", sb.runner.Argvs())
	}
	if !strings.Contains(out, "tacctl device config pull js1.lab.example.net, then tacctl device config plan js1.lab.example.net.") {
		t.Errorf("hint:\n%s", out)
	}
	out = sb.devb("", "js1.lab.example.net", "show", "snmp")
	if sb.code != 0 || !strings.Contains(out, "set snmp community <secret:1> authorization read-only") {
		t.Errorf("show: %d\n%s", sb.code, out)
	}
	noneOf(t, "show", out, "nms-ro-secret", "nms-traps-secret")
	out = sb.devb("", "js1.lab.example.net", "show", "snmp", "--reveal")
	if !strings.Contains(out, verbSNMPFile) {
		t.Errorf("show --reveal:\n%s", out)
	}
	out = sb.devb("", "js1.lab.example.net", "list")
	for _, want := range []string{"Configuration blocks of device 'js1.lab.example.net' (juniper)", "snmp     in force", "1 community, 1 trap group"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// the vendor orphan is a finding of the device's list, and no one else's
	if err := os.MkdirAll(sb.path("state/blocks/_devices/js1.lab.example.net/cisco"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/_devices/js1.lab.example.net/cisco/snmp", "x\n", 0o600)
	out = sb.devb("", "js1.lab.example.net", "list")
	if !strings.Contains(out, "the device's vendor is not cisco (it is juniper in the registry), so these blocks are ignored") {
		t.Errorf("orphan vendor:\n%s", out)
	}
	if err := os.RemoveAll(sb.path("state/blocks/_devices/js1.lab.example.net/cisco")); err != nil {
		t.Fatal(err)
	}

	out = sb.devb("y\n", "js1.lab.example.net", "remove", "snmp")
	if sb.code != 0 || !strings.Contains(out, "The snmp block of device 'js1.lab.example.net' is removed.") {
		t.Errorf("remove: %d\n%s", sb.code, out)
	}
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("left: %v", err)
	}
	if strings.Contains(sb.overrides(), "blocks_device") {
		t.Errorf("manifest left:\n%s", sb.overrides())
	}
	if sb.logged("block-remove name=_devices/js1.lab.example.net/juniper/snmp by=") != 1 {
		t.Errorf("log: %q", sb.runner.Argvs())
	}
}

func TestDeviceBlockRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "ts-1", "192.168.1.8", "--vendor", "wti", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "stray-j", "100.64.0.9", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\n", 0o600)
	good := sb.blockFile("snmp.txt", verbSNMPFile)
	for _, c := range []struct {
		name string
		args []string
		err  string
	}{
		{"unknown device", []string{"nosuch", "list"}, "Device 'nosuch' not found."},
		{"a host", []string{"web1", "list"}, "is an enrolled Linux host"},
		{"cisco", []string{"sw-c", "set", "snmp", "--file", good, "-y"}, "IOS blocks come in the release after"},
		{"wti", []string{"ts-1", "list"}, "configuration blocks are for Junos devices"},
		{"no scope", []string{"stray-j", "set", "snmp", "--file", good, "-y"}, "is in no scope"},
		{"no scope list", []string{"stray-j", "list"}, "is in no scope"},
		{"unknown block", []string{"sw-j", "show", "banner"}, "Unknown block 'banner'"},
		{"unknown verb", []string{"sw-j", "frobnicate", "snmp"}, "Unknown subcommand: 'frobnicate'"},
		{"no source", []string{"sw-j", "set", "snmp", "-y"}, "Give the block's text with --file <path>, or - for standard input."},
		{"a bad block", []string{"sw-j", "set", "snmp", "--file", sb.blockFile("bad", "set snmp community aa authorization read-only\n"), "-y"}, "Nothing was written."},
		{"effective of set", []string{"sw-j", "set", "snmp", "--effective", "--file", good}, "Unknown option: '--effective'"},
		{"reveal of list", []string{"sw-j", "list", "--reveal"}, "Unknown option: '--reveal'"},
	} {
		sb.devb("", c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr()+plain(sb.out.String()), c.err) {
			t.Errorf("%s: exit %d\nstdout %s\nstderr %s", c.name, sb.code, plain(sb.out.String()), sb.stderr())
		}
	}
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("a refusal wrote the store: %v", err)
	}
	// a device that left every scope can have its blocks taken away
	sb.dev("", "add", "moved-j", "192.168.1.30", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.devb("", "moved-j", "set", "snmp", "--file", good, "-y")
	sb.expect(0, "is set", "")
	sb.dev("", "address", "moved-j", "100.64.0.30")
	sb.devb("", "moved-j", "show", "snmp")
	sb.expect(1, "", "is in no scope")
	sb.devb("", "moved-j", "remove", "snmp", "-y")
	sb.expect(0, "is removed", "")
}

func TestDeviceBlockEffective(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.putBlock("lab", scopeLevelSNMP)
	// nothing of the device's: the scope's
	out := sb.devb("", "sw-j", "show", "snmp", "--effective")
	if sb.code != 0 || strings.Count(out, "# from scope 'lab'") != 3 || strings.Contains(out, "# from device") {
		t.Errorf("scope only: %d\n%s", sb.code, out)
	}
	noneOf(t, "effective", out, "nms-ro", "poller-two", "nms-traps")
	sb.devb("", "sw-j", "show", "snmp")
	sb.expect(1, "", "Sw-j has no snmp block."[:0]+"has no snmp block.")

	f := sb.blockFile("dev.txt", deviceLevelSNMP)
	sb.devb("", "sw-j", "set", "snmp", "--file", f, "-y")
	sb.expect(0, "is set", "")
	out = sb.devb("", "sw-j", "show", "snmp", "--effective")
	want := "# from device 'sw-j'\nset snmp community <secret:1> authorization read-write\nset snmp community <secret:1> clients 198.51.100.0/24\n" +
		"# from scope 'lab'\nset snmp community <secret:2> authorization read-only\nset snmp community <secret:2> clients 192.0.2.60/32\n" +
		"# from device 'sw-j'\nset snmp community <secret:3> authorization read-only\nset snmp community <secret:3> clients 203.0.113.9/32\n" +
		"# from scope 'lab'\nset snmp trap-group <group:1> targets 198.51.100.7\n"
	if sb.code != 0 || !strings.Contains(out, want) {
		t.Errorf("effective:\n%s", out)
	}
	noneOf(t, "effective", out, "nms-ro", "poller-two", "dev-extra", "nms-traps", "192.0.2.50")
	out = sb.devb("", "sw-j", "show", "snmp", "--effective", "--reveal")
	for _, w := range []string{"# from device 'sw-j'\nset snmp community nms-ro authorization read-write\n", "# from scope 'lab'\nset snmp community poller-two authorization read-only\n"} {
		if !strings.Contains(out, w) {
			t.Errorf("effective --reveal lacks %q:\n%s", w, out)
		}
	}
	// the device's own, and the effective one with a broken layer
	sb.putBlock("lab", scopeLevelSNMP+"set snmp community short authorization read-only\n")
	sb.devb("", "sw-j", "show", "snmp", "--effective")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The snmp block of scope 'lab' has errors, so it cannot be resolved: run tacctl scope block lab juniper check snmp") {
		t.Errorf("a broken scope block: %d\n%s", sb.code, sb.stderr())
	}
}

// putDeviceBlock writes a device's own block and its manifest entry (the
// scope's manifest is kept).
func (sb *sandbox) putDeviceBlock(device, block, text string) {
	sb.t.Helper()
	dir := "state/blocks/_devices/" + strings.ToLower(device) + "/juniper"
	if err := os.MkdirAll(sb.path(dir), 0o700); err != nil {
		sb.t.Fatal(err)
	}
	sb.write(dir+"/"+block, text, 0o600)
	o, _, _ := strings.Cut(sb.overrides(), "blocks_device:\n")
	sb.write("state/tacctl.yaml", o+"blocks_device:\n  "+strings.ReplaceAll(strings.ToLower(device), ".", "~")+":\n    juniper:\n    - "+block+"\n", 0o640)
}

func TestWalkthroughCarriesTheDevicesOwnBlock(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.cfgRun("", []string{"config", "mgmt-acl", "add", "10.99.0.0/24"}, route)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-k", "192.168.1.7", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.putBlock("lab", scopeLevelSNMP)
	scopeOnly := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	if !strings.Contains(scopeOnly, "# The snmp block of scope 'lab' (tacctl scope block lab juniper show snmp): its communities") {
		t.Fatalf("the scope's walkthrough:\n%s", scopeOnly)
	}

	sb.putDeviceBlock("sw-j", "snmp", deviceLevelSNMP)
	out := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	want := "# The snmp block of scope 'lab' with the block of device 'sw-j' over it (tacctl device block sw-j show snmp --effective): its communities, trap groups and trap options.\n" +
		"set snmp community nms-ro authorization read-write\nset snmp community nms-ro clients 198.51.100.0/24\n" +
		"set snmp community poller-two authorization read-only\nset snmp community poller-two clients 192.0.2.60/32\n" +
		"set snmp community dev-extra authorization read-only\nset snmp community dev-extra clients 203.0.113.9/32\n" +
		"set snmp trap-group nms-traps targets 198.51.100.7\n"
	if !strings.Contains(out, want) {
		t.Errorf("the device's walkthrough:\n%s", out)
	}
	if strings.Contains(out, "192.0.2.50/32") {
		t.Errorf("the scope's replaced client is rendered:\n%s", out)
	}
	// 'device config show' is the same code
	if got := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-j"}, route)); !strings.HasSuffix(got, out) {
		t.Errorf("device config show does not end in the walkthrough:\n%s", got)
	}
	// the management filter's permit-snmp term permits the device's clients
	// too (and not the replaced one)
	for _, c := range []string{"198.51.100.0/24", "203.0.113.9/32", "192.0.2.60/32"} {
		if !strings.Contains(out, "set firewall family inet filter MGMT-ACL term permit-snmp from source-address "+c) {
			t.Errorf("permit-snmp lacks %s:\n%s", c, out)
		}
	}
	if strings.Contains(out, "permit-snmp from source-address 192.0.2.50/32") {
		t.Errorf("permit-snmp permits the replaced client:\n%s", out)
	}
	// another device of the scope has the scope's block, and the walkthrough
	// of the scope alone as well
	if got := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-k"}, route)); got == out ||
		strings.Contains(got, "device 'sw-j'") || !strings.Contains(got, "set snmp community nms-ro clients 192.0.2.50/32") {
		t.Errorf("sw-k:\n%s", got)
	}
	if got := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab"}, route)); strings.Contains(got, "device 'sw-j'") {
		t.Errorf("the scope's walkthrough names the device:\n%s", got)
	}

	// a device block alone (the scope has none)
	sb.putBlock("dmz", "set snmp community dmz-c authorization read-only\nset snmp community dmz-c clients 192.0.2.1/32\n")
	sb.write("state/tacctl.yaml", strings.Replace(sb.overrides(), "blocks:\n  dmz:\n    juniper:\n    - snmp\n", "", 1), 0o640)
	sb.putBlock("lab", "set snmp community scope-only authorization read-only\nset snmp community scope-only clients 192.0.2.9/32\n")
	sb.putDeviceBlock("sw-j", "system", "set system domain-name sw-j.lab.example.net\n")
	out = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	for _, w := range []string{
		"# The snmp block of scope 'lab' (tacctl scope block lab juniper show snmp): its communities",
		"# The system block of device 'sw-j' (tacctl device block sw-j show system): the login message, domain, time zone, name servers and NTP.\nset system domain-name sw-j.lab.example.net\n"} {
		if !strings.Contains(out, w) {
			t.Errorf("lacks %q:\n%s", w, out)
		}
	}

	// A device block with an error is refused by name: the device's verb,
	// the lines, no string; the scope's other devices are not affected.
	sb.putDeviceBlock("sw-j", "snmp", deviceLevelSNMP+"set snmp community dev-short authorization read-only\nset snmp trap-group TACCTL-SNMP targets 198.51.100.7\n")
	got := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	if sb.code != 1 || got != "" {
		t.Fatalf("a device block with errors: %d %q", sb.code, got)
	}
	for _, w := range []string{"The snmp block of device 'sw-j' has errors", "tacctl device block sw-j check snmp"} {
		if !strings.Contains(sb.stderr(), w) {
			t.Errorf("the refusal lacks %q:\n%s", w, sb.stderr())
		}
	}
	noneOf(t, "the refusal", sb.stderr(), "nms-ro", "dev-extra", "dev-short")
	if sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-k"}, route); sb.code != 0 {
		t.Errorf("sw-k: %d %s", sb.code, sb.stderr())
	}

	// the device block that names the scope's own community: refused by the
	// device's verb
	sb.putDeviceBlock("sw-j", "snmp", "set snmp community lab-community-9 authorization read-only\nset snmp community lab-community-9 clients 192.0.2.50/32\n")
	sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route)
	if sb.code != 1 || strings.Contains(sb.stderr(), "lab-community-9") ||
		!strings.Contains(sb.stderr(), "Community 1 of the SNMP block of device 'sw-j' is the community the scope's own SNMP settings render") ||
		!strings.Contains(sb.stderr(), "tacctl device block sw-j edit snmp") {
		t.Errorf("a device block that names the scope's community: %d\n%s", sb.code, sb.stderr())
	}
}

func TestBatchRenderCarriesTheDevicesOwnBlock(t *testing.T) {
	b := newPullBox(t)
	b.sb.dev("", "scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("lab-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.21", "juniper"})
	b.sb.putBlock("lab", scopeLevelSNMP)
	b.sb.putDeviceBlock("lab-j1", "snmp", deviceLevelSNMP)
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	var entries []devreg.Entry
	for _, n := range []string{"lab-j1", "lab-j2"} {
		e, ok := res.Lookup(n, devreg.ScopeFilter{})
		if !ok {
			t.Fatalf("no %s", n)
		}
		entries = append(entries, e)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	snmpLines := func(e devreg.Entry) string {
		t.Helper()
		secs, err := r.Expected(e)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		for _, s := range secs {
			if s.Name == "snmp" {
				return strings.Join(s.Lines, "\n")
			}
		}
		t.Fatalf("%s has no snmp section", e.Name)
		return ""
	}
	j1, j2 := snmpLines(entries[0]), snmpLines(entries[1])
	for _, w := range []string{"set snmp community nms-ro clients 198.51.100.0/24", "set snmp community nms-ro authorization read-write",
		"set snmp community dev-extra clients 203.0.113.9/32", "set snmp community poller-two clients 192.0.2.60/32", "set snmp trap-group nms-traps targets 198.51.100.7"} {
		if !strings.Contains(j1, w) {
			t.Errorf("lab-j1 lacks %q:\n%s", w, j1)
		}
	}
	if strings.Contains(j1, "192.0.2.50/32") {
		t.Errorf("lab-j1 keeps the replaced client:\n%s", j1)
	}
	if strings.Contains(j2, "dev-extra") || !strings.Contains(j2, "set snmp community nms-ro clients 192.0.2.50/32") || !strings.Contains(j2, "authorization read-only") {
		t.Errorf("lab-j2:\n%s", j2)
	}
	// a device whose own block has an error is its problem alone
	b.sb.putDeviceBlock("lab-j1", "snmp", "set snmp community nms-ro authorization read-only\n")
	r = b.invoke().newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	_, err = r.Expected(entries[0])
	if err == nil {
		t.Fatal("a device block with errors was rendered")
	}
	for _, w := range []string{"device 'lab-j1'", "tacctl device block lab-j1 check snmp"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the problem lacks %q: %v", w, err)
		}
	}
	if strings.Contains(err.Error(), "nms-ro") {
		t.Errorf("the problem holds a string: %v", err)
	}
	if _, err := r.Expected(entries[1]); err != nil {
		t.Errorf("lab-j2: %v", err)
	}
}

// An engineer reads the blocks of the devices of their own scopes only;
// their reveal of a device's block is logged under the device's path.
func TestDeviceBlockEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	head := "tier:\n  operator: engineer\n"
	for _, d := range []string{"lab-sw", "prod-sw"} {
		_ = d
	}
	sb.dev("", "add", "lab-j", "192.168.1.30", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "prod-j", "10.99.0.30", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.write("state/tacctl.yaml", head, 0o640)
	sb.putDeviceBlock("lab-j", "snmp", verbSNMPFile)
	sb.write("state/tacctl.yaml", head+"blocks_device:\n  lab-j:\n    juniper:\n    - snmp\n  prod-j:\n    juniper:\n    - snmp\n", 0o640)
	if err := os.MkdirAll(sb.path("state/blocks/_devices/prod-j/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/_devices/prod-j/juniper/snmp", verbSNMPFile, 0o600)

	out := sb.asEngineer("", "device", "block", "lab-j", "list")
	if sb.code != 0 || !strings.Contains(out, "snmp     in force") {
		t.Errorf("list: %d %q\n%s", sb.code, out, sb.stderr())
	}
	out = sb.asEngineer("", "device", "block", "lab-j", "show", "snmp")
	if sb.code != 0 || !strings.Contains(out, "<secret:1>") || strings.Contains(out, "nms-ro-secret") {
		t.Errorf("show: %d\n%s", sb.code, out)
	}
	if sb.logged("secret-read") != 0 {
		t.Errorf("an elided read was logged")
	}
	out = sb.asEngineer("", "device", "block", "lab-j", "show", "snmp", "--reveal")
	if sb.code != 0 || !strings.Contains(out, "nms-ro-secret") || sb.logged("secret-read kind=block name=_devices/lab-j/juniper/snmp by=bob") != 1 {
		t.Errorf("reveal: %d %q\n%s", sb.code, sb.runner.Argvs(), out)
	}
	f := sb.blockFile("e.txt", verbSNMPFile)
	for _, args := range [][]string{
		{"lab-j", "set", "snmp", "--file", f, "-y"}, {"lab-j", "set", "snmp", "-", "-y"}, {"lab-j", "remove", "snmp", "-y"},
	} {
		sb.asEngineer(verbSNMPFile, append([]string{"device", "block"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads the configuration blocks of device 'lab-j' (list, show, check); ") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	for _, args := range [][]string{{"prod-j", "list"}, {"prod-j", "show", "snmp", "--reveal"}, {"prod-j", "check", "snmp"}, {"prod-j", "remove", "snmp", "-y"}} {
		sb.asEngineer("", append([]string{"device", "block"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-j' not found.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
}

// 'check --against' plans the device from its last pull with the text in
// force and prints the statements of the block's section; nothing is written
// and no string is printed.
func TestBlockCheckAgainstADevice(t *testing.T) {
	b := planBoxJunos(t)
	text := "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 198.51.100.0/24\nset snmp trap-group nms-traps targets 198.51.100.7\n"
	f := b.sb.blockFile("d.txt", text)

	// no pull yet
	out := b.run("scope", "block", "lab", "juniper", "check", "snmp", "--file", f, "--against", "lab-j")
	if b.sb.code != 1 || !strings.Contains(out, "pull the device first: tacctl device config pull lab-j") {
		t.Errorf("no pull: %d\n%s", b.sb.code, out)
	}
	b.run("device", "config", "pull", "lab-j")
	records := b.sb.read("var-lib/devices-config.json")
	snaps := b.sb.snapshots()

	out = b.run("scope", "block", "lab", "juniper", "check", "snmp", "--file", f, "--against", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("against: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	for _, w := range []string{"Plan of lab-j with this text in force", "nothing was written and no device was reached", "Section snmp: planned, 3 statements",
		"set snmp community <secret:1> authorization read-only", "set snmp community <secret:1> clients 198.51.100.0/24", "set snmp trap-group <secret:2> targets 198.51.100.7"} {
		if !strings.Contains(out, w) {
			t.Errorf("against lacks %q:\n%s", w, out)
		}
	}
	// the planned lines name the strings only as marks (the findings and the
	// diff above them are elided too)
	if i := strings.Index(out, "Plan of lab-j"); strings.Contains(out[i:], "nms-ro") || strings.Contains(out[i:], "nms-traps") {
		t.Errorf("the plan holds a string:\n%s", out[i:])
	}
	noneOf(t, "check", out, "nms-ro ", "nms-traps ")
	// the same from the device's verb, with the device's own text
	out = b.run("device", "block", "lab-j", "check", "snmp", "--file", f, "--against")
	if b.sb.code != 0 || !strings.Contains(out, "The snmp block of device 'lab-j' (juniper)") || !strings.Contains(out, "Section snmp: planned, 3 statements") {
		t.Errorf("device against: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	// nothing was written: no record change, no snapshot, no back-out, no store
	if b.sb.read("var-lib/devices-config.json") != records || b.sb.snapshots() != snaps {
		t.Error("check --against changed the records or took a snapshot")
	}
	if _, err := os.Stat(b.sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("check --against wrote the store: %v", err)
	}
	if got := b.run("device", "config", "plan", "lab-j", "--backout"); strings.Contains(got, "nms-ro") {
		t.Errorf("a back-out was kept from the check:\n%s", got)
	}

	// refusals: another scope's device, another vendor, a host
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"}, [3]string{"lab-c", "192.168.1.5", "cisco"})
	b.run("scope", "block", "lab", "juniper", "check", "snmp", "--file", f, "--against", "prod-j")
	if !strings.Contains(b.sb.stderr(), "Device 'prod-j' is in scope 'prod', not in scope 'lab'") {
		t.Errorf("another scope's device: %q", b.sb.stderr())
	}
	b.run("scope", "block", "lab", "juniper", "check", "snmp", "--file", f, "--against", "lab-c")
	if !strings.Contains(b.sb.stderr(), "'lab-c' is not a Junos device") {
		t.Errorf("a Cisco device: %q", b.sb.stderr())
	}
	// a text with errors is not planned
	bad := b.sb.blockFile("bad.txt", "set snmp community short authorization read-only\n")
	out = b.run("scope", "block", "lab", "juniper", "check", "snmp", "--file", bad, "--against", "lab-j")
	if b.sb.code != 1 || strings.Contains(out, "Plan of lab-j") {
		t.Errorf("a bad text was planned: %d\n%s", b.sb.code, out)
	}
}

// A system block cannot be planned from a pull that was made before the
// block was in force: the check says what to do.
func TestBlockCheckAgainstSystemNeedsAPullWithTheBlock(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	f := b.sb.blockFile("s.txt", verbSystemFile)
	out := b.run("scope", "block", "lab", "juniper", "check", "system", "--file", f, "--against", "lab-j")
	if b.sb.code != 1 || !strings.Contains(out, "cannot be planned:") || !strings.Contains(out, "set the block, pull the device, then plan it") {
		t.Errorf("%d\n%s", b.sb.code, out)
	}
	noneOf(t, "check", out, "Authorized", "ntp-key-0123456789")

	// once the block is in force and the device pulled, the plan names the
	// section's statements, the message as its size
	b.run("scope", "block", "lab", "juniper", "set", "system", "--file", f, "-y")
	b.run("device", "config", "pull", "lab-j")
	out = b.run("scope", "block", "lab", "juniper", "check", "system", "--against", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "Section system: planned") {
		t.Errorf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	noneOf(t, "check", out, "Authorized", "ntp-key-0123456789")
}

func TestDevicesBlockLayerWords(t *testing.T) {
	// Blocks that carry no layer are the scope's alone (the zero value).
	if (devices.Blocks{}).SNMPLayer != devices.LayerScope {
		t.Error("the zero layer is not the scope's")
	}
}

// The system block's effective view: the login message is one unit (its
// heredoc, elided), single values and list entries say which layer they are
// from, and the device's delete lines are shown with their layer.
func TestDeviceBlockEffectiveSystem(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.putBlockSet(sb.overrides(), "lab", map[string]string{"system": verbSystemFile})
	sb.putDeviceBlock("sw-j", "system", "set system domain-name sw-j.lab.example.net\nset system name-server 192.0.2.54\ndelete system ntp\n")
	out := sb.devb("", "sw-j", "show", "system", "--effective")
	want := "# from scope 'lab'\nset system login message <<'EOF'\n<message: 2 lines, 62 characters>\nEOF\n" +
		"# from device 'sw-j'\nset system domain-name sw-j.lab.example.net\n" +
		"# from scope 'lab'\nset system name-server 192.0.2.53\n" +
		"# from device 'sw-j'\nset system name-server 192.0.2.54\n"
	if sb.code != 0 || !strings.Contains(out, want) {
		t.Errorf("effective:\n%s", out)
	}
	// 'delete system ntp' of the device takes the scope's ntp statements out
	noneOf(t, "effective", out, "ntp server", "authentication-key", "Authorized", "keep out")
	if !strings.Contains(out, "# from device 'sw-j'\ndelete system ntp\n") {
		t.Errorf("the delete line is not shown with its layer:\n%s", out)
	}
	out = sb.devb("", "sw-j", "show", "system", "--effective", "--reveal")
	if !strings.Contains(out, "# from scope 'lab'\nset system login message <<'EOF'\nAuthorized use of js1.lab.example.net only.\n  *** keep out ***\nEOF\n") {
		t.Errorf("effective --reveal:\n%s", out)
	}
}
