package cli

// The IOS snmp block through the verbs (0.2.7): scope and device level, the
// refusals that never echo a string, the walkthrough and the plan it reaches,
// the adoption from a live read, and the log line of every reveal.

import (
	"strings"
	"testing"
)

const (
	ciscoVerbFile = "# the monitoring system\nip access-list standard NMS-POLLERS\n permit host 192.0.2.50\n permit 198.51.100.0 0.0.0.255\n" +
		"snmp-server community nms-ro-secret RO NMS-POLLERS\n" +
		"snmp-server host 198.51.100.7 version 2c nms-traps-secret udp-port 162 config\nsnmp-server enable traps config\n"
	ciscoCmdSNMP = "show running-config | include ^snmp-server"
	ciscoCmdACL  = "show running-config | section ip access-list standard POLLERS"
)

func TestScopeBlockCiscoVerbs(t *testing.T) {
	sb := newSandbox(t, true)
	const secret, group = "nms-ro-secret", "nms-traps-secret"
	f := sb.blockFile("snmp.txt", ciscoVerbFile)

	out := sb.blk("", "lab", "cisco", "list")
	if sb.code != 0 || !strings.Contains(out, "none: scope 'lab' has no cisco block.") {
		t.Errorf("list of nothing: %d\n%s", sb.code, out)
	}
	out = sb.blk("", "lab", "cisco", "check", "snmp", "--file", f)
	for _, want := range []string{"Owned by tacctl once in force: 1 community, 1 access list, 1 trap host, 1 'enable traps' line",
		"Statements that carry a secret: 2", "No file in force: every statement is new.", "ok."} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noneOf(t, "check", out+sb.stderr(), secret, group)

	out = sb.blk("", "lab", "cisco", "set", "snmp", "--file", f, "-y")
	if sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "set", out+sb.stderr(), secret, group)
	if got := sb.read("state/blocks/lab/cisco/snmp"); got != ciscoVerbFile {
		t.Errorf("the file is not the text as given:\n%q", got)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks:\n  lab:\n    cisco:\n    - snmp\n") {
		t.Errorf("the manifest:\n%s", o)
	}
	if sb.logged("block-set name=lab/cisco/snmp bytes=") != 1 {
		t.Errorf("block-set not logged once: %q", sb.runner.Argvs())
	}

	// show: elided by marks, comments never; the structure keeps its lines
	out = sb.blk("", "lab", "cisco", "show", "snmp")
	want := "ip access-list standard NMS-POLLERS\n permit host 192.0.2.50\n permit 198.51.100.0 0.0.0.255\n" +
		"snmp-server community <secret:1> RO NMS-POLLERS\nsnmp-server host 198.51.100.7 version 2c <secret:2> udp-port 162 config\nsnmp-server enable traps config\n"
	if sb.code != 0 || !strings.Contains(out, want) {
		t.Errorf("show:\n%s", out)
	}
	noneOf(t, "show", out, secret, group, "the monitoring")
	if sb.logged("secret-read") != 0 {
		t.Errorf("an elided read was logged")
	}
	// every reveal is logged, the superuser's too, by name
	out = sb.blk("", "lab", "cisco", "show", "snmp", "--reveal")
	if sb.code != 0 || !strings.Contains(out, ciscoVerbFile) {
		t.Errorf("show --reveal:\n%s", out)
	}
	if sb.logged("secret-read kind=block name=lab/cisco/snmp") != 1 {
		t.Errorf("the reveal was not logged once: %q", sb.runner.Argvs())
	}
	noneOf(t, "the log", strings.Join(sb.runner.Argvs(), "\n"), secret, group)

	out = sb.blk("", "lab", "cisco", "list")
	for _, want := range []string{"Configuration blocks of scope 'lab' (cisco)", "snmp     in force", "1 community, 1 access list, 1 trap host, 1 'enable traps' line"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// the diff of a changed list: the access list is one unit
	f2 := sb.blockFile("snmp2.txt", strings.Replace(ciscoVerbFile, " permit host 192.0.2.50\n", " permit host 192.0.2.51\n", 1))
	out = sb.blk("", "lab", "cisco", "check", "snmp", "--file", f2)
	for _, want := range []string{"- ip access-list standard NMS-POLLERS", "-  permit host 192.0.2.50", "+  permit host 192.0.2.51", "3 unchanged"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check diff lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}

	// the other vendor's file and the Junos grammar are not this vendor's
	sb.blk("", "lab", "cisco", "check", "snmp", "--file", sb.blockFile("j.txt", "set snmp community x-community authorization read-only\n"))
	if sb.code != 1 {
		t.Errorf("a Junos text checked as IOS: %d", sb.code)
	}
	// the IOS snmp text is no system block's, and a WTI unit has none of either
	sb.blk("", "lab", "cisco", "check", "system", "--file", f)
	sb.expect(1, "word 2 is not one of domain, name-server", "")
	sb.blk("", "lab", "wti", "list")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A WTI unit has no configuration blocks") {
		t.Errorf("wti: %d %q", sb.code, sb.stderr())
	}

	out = sb.blk("y\n", "lab", "cisco", "remove", "snmp")
	if sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is removed.") {
		t.Errorf("remove: %d\n%s", sb.code, out)
	}
}

// Every refusal says where and why and holds no string of the text.
func TestScopeBlockCiscoRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	cases := []struct{ name, text, want string }{
		{"a read-write community with no list", "snmp-server community rw-secret-1 RW\n", "line 1: error: community 1 is read-write and names no access list"},
		{"any in the list of a read-write community", "ip access-list standard OPEN\n permit any\nsnmp-server community rw-secret-1 RW OPEN\n", "its access list permits any"},
		{"a numbered list", "snmp-server community ro-secret-1 RO 10\n", "a number: a numbered access list is not accepted"},
		{"tacctl's own list", "ip access-list standard TACCTL-SNMP\n permit 192.0.2.5\n", "a name tacctl renders itself"},
		{"contact", "snmp-server contact someone\n", "never part of a block"},
		{"an abbreviated trap-source", "snmp-server trap-source Lo0\n", "has its type abbreviated"},
		{"a user", "snmp-server user v3user G v3 auth sha xxxxxxxxxx\n", "SNMPv3"},
		{"a vrf host", "snmp-server host 192.0.2.5 vrf mgmt string-secret-1\n", "'vrf' is not in the grammar of a block"},
		{"a placeholder", "snmp-server community <secret:1> RO NMS\n", "a placeholder"},
		{"a tab", "snmp-server community tab-secret\tRO\n", "a tab at column"},
		{"a deny entry", "ip access-list standard L\n deny 192.0.2.5\n", "permit entries only"},
		{"host bits", "ip access-list standard L\n permit 192.0.2.5 0.0.0.255\n", "address bits set where its wildcard says any"},
		{"an empty list", "ip access-list standard L\nsnmp-server enable traps config\n", "has no entry"},
	}
	for _, c := range cases {
		f := sb.blockFile("bad.txt", c.text)
		out := sb.blk("", "lab", "cisco", "check", "snmp", "--file", f)
		if sb.code != 1 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, no %q:\n%s", c.name, sb.code, c.want, out)
		}
		for _, bad := range []string{"rw-secret-1", "ro-secret-1", "string-secret-1", "tab-secret", "v3user", "xxxxxxxxxx"} {
			if strings.Contains(out+sb.stderr(), bad) {
				t.Errorf("%s: the output holds %q:\n%s", c.name, bad, out)
			}
		}
		sb.blk("", "lab", "cisco", "set", "snmp", "--file", f, "-y")
		if sb.code != 1 {
			t.Errorf("%s: set accepted it", c.name)
		}
	}
	// a block community that is the scope's own is refused, by place
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	f := sb.blockFile("own.txt", "snmp-server community other-secret-9 RO\nsnmp-server community lab-own-community RO\n")
	out := sb.blk("", "lab", "cisco", "check", "snmp", "--file", f)
	if sb.code != 1 || !strings.Contains(out, "Community 2 of the SNMP block of scope 'lab' is the community the scope's own SNMP settings render") ||
		strings.Contains(out+sb.stderr(), "lab-own-community") {
		t.Errorf("own community: %d\n%s", sb.code, out)
	}
	// the scope's management list is a name the block may not define
	f = sb.blockFile("vty.txt", "ip access-list standard VTY-ACL\n permit 192.0.2.5\n")
	out = sb.blk("", "lab", "cisco", "check", "snmp", "--file", f)
	if sb.code != 1 || !strings.Contains(out, "is the scope's management access list (VTY-ACL)") {
		t.Errorf("mgmt list: %d\n%s", sb.code, out)
	}
}

// A device's own block over the scope's, the walkthrough and the managed
// sections that carry them, and the reveal of the device's block logged.
func TestDeviceBlockCisco(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	sb.dev("", "add", "rt1", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	without := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	f := sb.blockFile("snmp.txt", ciscoVerbFile)
	sb.blk("", "lab", "cisco", "set", "snmp", "--file", f, "-y")
	sb.expect(0, "is set", "")

	out := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	for _, want := range []string{
		"! The snmp block of scope 'lab' (tacctl scope block lab cisco show snmp): its communities, access lists, trap hosts and trap types.\n" +
			"ip access-list standard NMS-POLLERS\n  permit host 192.0.2.50\n  permit 198.51.100.0 0.0.0.255\nsnmp-server community nms-ro-secret RO NMS-POLLERS\n" +
			"snmp-server host 198.51.100.7 version 2c nms-traps-secret udp-port 162 config\nsnmp-server enable traps config\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("the walkthrough lacks %q:\n%s", want, out)
		}
	}
	if out == without {
		t.Error("the block changed nothing")
	}

	// the device's own block: its community replaces the scope's of the
	// same string whole; the vendor of a device decides which blocks it has
	dev := "snmp-server community nms-ro-secret RO\nsnmp-server enable traps snmp linkdown\n"
	sb.blk("", "lab", "cisco", "list")
	if sb.code != 0 {
		t.Fatalf("list: %d", sb.code)
	}
	sb.dev(dev, "block", "rt1", "set", "snmp", "-", "-y")
	sb.expect(0, "The snmp block of device 'rt1' is set", "")
	if got := sb.read("state/blocks/_devices/rt1/cisco/snmp"); got != dev {
		t.Errorf("the device's file:\n%q", got)
	}
	out = plain(sb.cfgRun("", []string{"device", "block", "rt1", "show", "snmp", "--effective", "--reveal"}, route))
	for _, want := range []string{"# from scope 'lab'", "# from device 'rt1'", "snmp-server community nms-ro-secret RO\n", "snmp-server enable traps snmp linkdown"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("effective lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	if strings.Contains(out, "snmp-server community nms-ro-secret RO NMS-POLLERS") {
		t.Errorf("the scope's community is not replaced:\n%s", out)
	}
	if sb.logged("secret-read kind=block name=lab/cisco/snmp") != 1 || sb.logged("secret-read kind=block name=_devices/rt1/cisco/snmp") != 1 {
		t.Errorf("the reveal of both layers is not logged: %q", sb.runner.Argvs())
	}
	// the walkthrough of the device carries both
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	if !strings.Contains(out, "The snmp block of scope 'lab' with the block of device 'rt1' over it (tacctl device block rt1 show snmp --effective)") ||
		!strings.Contains(out, "snmp-server enable traps snmp linkdown") {
		t.Errorf("the walkthrough of the device:\n%s", out)
	}
	// the Junos device has no Cisco block of its own
	sb.dev("", "block", "sw-j", "list")
	if sb.code != 0 {
		t.Errorf("list of a Junos device: %d", sb.code)
	}
	// a block with another vendor's syntax is an error for the device's vendor
	sb.dev("set snmp community x-community-1 authorization read-only\n", "block", "rt1", "check", "snmp", "-")
	if sb.code != 1 {
		t.Errorf("a Junos text for an IOS device: %d", sb.code)
	}
}

// 'check --against' plans the IOS device from its last pull with the text in
// force: the block's lines and nothing written.
func TestBlockCiscoCheckAgainstADevice(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"}, [3]string{"lab-j", "192.168.1.20", "juniper"})
	b.sb.scopeSNMP("", "lab", "version", "v2c")
	b.sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	b.serve("cisco", b.expected("lab-c"))
	f := b.sb.blockFile("c.txt", ciscoVerbFile)

	out := b.run("scope", "block", "lab", "cisco", "check", "snmp", "--file", f, "--against", "lab-c")
	if b.sb.code != 1 || !strings.Contains(out, "pull the device first: tacctl device config pull lab-c") {
		t.Errorf("no pull: %d\n%s", b.sb.code, out)
	}
	b.run("device", "config", "pull", "lab-c")
	records := b.sb.read("var-lib/devices-config.json")
	snaps := b.sb.snapshots()
	out = b.run("scope", "block", "lab", "cisco", "check", "snmp", "--file", f, "--against", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("against: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	for _, w := range []string{"Plan of lab-c with this text in force", "nothing was written and no device was reached", "Section snmp: planned, 5 statements",
		"    ip access-list standard NMS-POLLERS\n     permit host 192.0.2.50\n     permit 198.51.100.0 0.0.0.255\n", "snmp-server community <secret:2> RO NMS-POLLERS",
		"snmp-server host 198.51.100.7 version 2c <secret:3> config", "snmp-server enable traps config"} {
		if !strings.Contains(out, w) {
			t.Errorf("against lacks %q:\n%s", w, out)
		}
	}
	if i := strings.Index(out, "Plan of lab-c"); strings.Contains(out[i:], "nms-ro-secret") || strings.Contains(out[i:], "nms-traps-secret") {
		t.Errorf("the plan holds a string:\n%s", out[i:])
	}
	if b.sb.read("var-lib/devices-config.json") != records || b.sb.snapshots() != snaps {
		t.Error("check --against changed the records or took a snapshot")
	}
	// a Junos device is not planned from an IOS block
	b.run("scope", "block", "lab", "cisco", "check", "snmp", "--file", f, "--against", "lab-j")
	if !strings.Contains(b.sb.stderr(), "'lab-j' is not an IOS or IOS-XE device") {
		t.Errorf("a Junos device: %q", b.sb.stderr())
	}
	// once in force, the device's plan carries the block
	b.run("scope", "block", "lab", "cisco", "set", "snmp", "--file", f, "-y")
	out = b.run("device", "config", "plan", "lab-c", "--pull", "--no-secrets")
	for _, w := range []string{"access list NMS-POLLERS of the SNMP block of scope 'lab'", "ip access-list standard NMS-POLLERS"} {
		if !strings.Contains(out, w) {
			t.Errorf("the plan lacks %q:\n%s", w, out)
		}
	}
	noneOf(t, "the plan", out, "nms-ro-secret", "nms-traps-secret")
}

// adoptCiscoDevice is what the IOS device says to the two reads: its own
// community, the scope's, a poller with a list, a read-write one, a community
// that names a numbered list, a trap host and a trap line, and v3.
const (
	adoptCiscoSNMP = "snmp-server community lab-own-community RO TACCTL-SNMP\nsnmp-server community poller-string RO POLLERS\n" +
		"snmp-server community writer-string RW POLLERS\nsnmp-server community numbered-string RO 10\n" +
		"snmp-server location Rack 9\nsnmp-server host 192.0.2.61 version 2c poller-traps\nsnmp-server enable traps config\n" +
		"snmp-server user v3user TACCTL-GROUP v3 auth sha v3secretvalue\n"
	adoptCiscoACL = "ip access-list standard POLLERS\n 10 permit 192.0.2.60\n 20 permit 198.51.100.0 0.0.0.255\n"
)

func TestAdoptCiscoDraftFlow(t *testing.T) {
	a := newAdoptBox(t)
	a.serve(ciscoCmdSNMP, adoptCiscoSNMP)
	a.serve(ciscoCmdACL, adoptCiscoACL)
	ed := a.e.editor("ed-prune", `grep -v 'writer-string' "$f" > "$f.new" && mv "$f.new" "$f"`)
	n := a.sb.snapshots()
	out := a.runAs("y\n", ed, "scope", "block", "lab", "cisco", "adopt", "lab-ios", "snmp")
	if a.sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("adopt: %d\n%s%s\ncommands: %q", a.sb.code, out, a.sb.stderr(), a.srv.Commands())
	}
	if a.pw.asked != 1 || a.pw.accepted != 1 || a.pw.rejected != 0 {
		t.Errorf("password: asked %d accepted %d rejected %d", a.pw.asked, a.pw.accepted, a.pw.rejected)
	}
	var reads []string
	for _, c := range a.srv.Commands() {
		if strings.HasPrefix(c, "show running-config") {
			reads = append(reads, c)
		}
	}
	if len(reads) != 2 || reads[0] != ciscoCmdSNMP || reads[1] != ciscoCmdACL {
		t.Errorf("reads: %q", reads)
	}
	seed := a.e.recorded("seed1")
	for _, want := range []string{
		"# adopted from lab-ios at ", "# Remove what this block should not own",
		"ip access-list standard POLLERS\n permit host 192.0.2.60\n permit 198.51.100.0 0.0.0.255\n",
		"snmp-server community poller-string RO POLLERS\nsnmp-server community writer-string RW POLLERS\n",
		"snmp-server host 192.0.2.61 version 2c poller-traps\nsnmp-server enable traps config\n",
		"# left out: a community names a numbered access list, which a block cannot hold: not adopted.",
		"identity (contact, location, engine id), never part of a block: 1 statement, not adopted",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("the draft lacks %q:\n%s", want, seed)
		}
	}
	for _, bad := range []string{"lab-own-community", "numbered-string", "v3user", "v3secretvalue", "Rack 9", "TACCTL"} {
		if strings.Contains(seed, bad) {
			t.Errorf("the draft holds %q:\n%s", bad, seed)
		}
	}
	stored := a.sb.read("state/blocks/lab/cisco/snmp")
	if !strings.Contains(stored, "snmp-server community poller-string RO POLLERS\n") || strings.Contains(stored, "writer-string") {
		t.Errorf("stored:\n%s", stored)
	}
	if a.sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, a.sb.snapshots())
	}
	log := strings.Join(a.sb.runner.Argvs(), "\n")
	if a.sb.logged("secret-read kind=block-adopt name=lab/cisco/snmp by=alice") != 1 || a.sb.logged("block-adopt name=lab/cisco/snmp bytes=") != 1 ||
		a.sb.logged("block adopt-read user=alice device=lab-ios transport=ssh result=ok") != 1 {
		t.Errorf("log:\n%s", log)
	}
	for _, s := range []string{"poller-string", "writer-string", "poller-traps", "lab-own-community", "v3secretvalue"} {
		noneOf(t, "output, error and log", out+a.sb.stderr()+log, s)
		if f := a.storedOutside(s); len(f) != 0 && s != "lab-own-community" {
			t.Errorf("%q is stored in %v", s, f)
		}
	}
	// a Junos device is not read by an IOS block's adopt
	a.runAs("", ed, "scope", "block", "lab", "cisco", "adopt", "js1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "is not an IOS or IOS-XE device") {
		t.Errorf("a Junos device: %d %q", a.sb.code, a.sb.stderr())
	}
}
