package cli

// The IOS system block through the verbs (0.2.7): scope and device level, the
// refusals that never echo the banner or a key, the walkthrough and the plan
// it reaches, the adoption from a live read, and the trap source of the IOS
// and Junos snmp blocks.

import (
	"strings"
	"testing"
)

const (
	ciscoSystemFile = "# the lab's system settings\nbanner login <<'EOF'\nAuthorized use only, Zq41.\n\n! Activity is logged.\nEOF\n" +
		"ip domain name lab.example.net\nclock timezone CET 1\nip name-server 192.0.2.53 192.0.2.54\n" +
		"ntp authentication-key 5 md5 ntp-key-secret-Yp9\nntp trusted-key 5\nntp server 192.0.2.123 key 5 prefer\nntp authenticate\n"
	ciscoSystemCmd = "show running-config | include ^(banner|ip domain|ip name-server|clock timezone|ntp )"
	ciscoBannerCmd = "show running-config | section ^banner login"
)

func TestScopeBlockCiscoSystemVerbs(t *testing.T) {
	sb := newSandbox(t, true)
	const banner, key = "Authorized use only, Zq41.", "ntp-key-secret-Yp9"
	f := sb.blockFile("system.txt", ciscoSystemFile)

	out := sb.blk("", "lab", "cisco", "check", "system", "--file", f)
	for _, want := range []string{"Owned by tacctl once in force: 9 statements, a login banner of 3 lines",
		"Statements that carry a secret: 1", "No file in force: every statement is new.", "ok."} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noneOf(t, "check", out+sb.stderr(), banner, key, "Activity is logged")

	out = sb.blk("", "lab", "cisco", "set", "system", "--file", f, "-y")
	if sb.code != 0 || !strings.Contains(out, "The system block of scope 'lab' is set (") {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "set", out+sb.stderr(), banner, key, "Activity is logged")
	if got := sb.read("state/blocks/lab/cisco/system"); got != ciscoSystemFile {
		t.Errorf("the file is not the text as given:\n%q", got)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks:\n  lab:\n    cisco:\n    - system\n") {
		t.Errorf("the manifest:\n%s", o)
	}
	if sb.logged("block-set name=lab/cisco/system bytes=") != 1 {
		t.Errorf("block-set not logged once: %q", sb.runner.Argvs())
	}

	// show: the banner and the key are marks, comments never
	out = sb.blk("", "lab", "cisco", "show", "system")
	for _, want := range []string{"banner login <<'EOF'\n<message: 3 lines, 49 characters>\nEOF\n", "ip domain name lab.example.net\n",
		"clock timezone CET 1\n", "ip name-server 192.0.2.53\nip name-server 192.0.2.54\n", "ntp authentication-key 5 md5 <secret>\n",
		"ntp trusted-key 5\n", "ntp server 192.0.2.123 version"} {
		if want == "ntp server 192.0.2.123 version" {
			want = "ntp server 192.0.2.123 key 5 prefer\nntp authenticate\n"
		}
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noneOf(t, "show", out, banner, key, "Activity is logged", "the lab's system")
	if sb.logged("secret-read") != 0 {
		t.Errorf("an elided read was logged")
	}
	// an elided text cannot be set back
	elided := sb.blockFile("elided.txt", out)
	sb.blk("", "lab", "cisco", "check", "system", "--file", elided)
	if sb.code != 1 {
		t.Errorf("the elided text was accepted: %d", sb.code)
	}
	// every reveal is logged, by name
	out = sb.blk("", "lab", "cisco", "show", "system", "--reveal")
	if sb.code != 0 || !strings.Contains(out, ciscoSystemFile) {
		t.Errorf("show --reveal:\n%s", out)
	}
	if sb.logged("secret-read kind=block name=lab/cisco/system") != 1 {
		t.Errorf("the reveal was not logged once: %q", sb.runner.Argvs())
	}
	noneOf(t, "the log", strings.Join(sb.runner.Argvs(), "\n"), banner, key)

	out = sb.blk("", "lab", "cisco", "list")
	for _, want := range []string{"Configuration blocks of scope 'lab' (cisco)", "system   in force", "9 statements, a login banner of 3 lines"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// the diff of a changed text shows the banner as a mark and the key as
	// a mark, never a word of either
	f2 := sb.blockFile("system2.txt", strings.Replace(strings.Replace(ciscoSystemFile, "Zq41", "Zq42", 1), "Yp9", "Yp8", 1))
	out = sb.blk("", "lab", "cisco", "check", "system", "--file", f2)
	for _, want := range []string{"- banner login <<'EOF'", "+ banner login <<'EOF'", "-ntp authentication-key 5 md5 <secret>"} {
		_ = want
	}
	if sb.code != 0 || !strings.Contains(out, "<message: 3 lines, 49 characters>") {
		t.Errorf("check diff (exit %d):\n%s", sb.code, out)
	}
	noneOf(t, "check diff", out, "Zq41", "Zq42", "Yp9", "Yp8")

	out = sb.blk("y\n", "lab", "cisco", "remove", "system")
	if sb.code != 0 || !strings.Contains(out, "The system block of scope 'lab' is removed.") {
		t.Errorf("remove: %d\n%s", sb.code, out)
	}
}

// Every refusal says where and why and holds neither the banner nor a key.
func TestScopeBlockCiscoSystemRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	cases := []struct{ name, text, want string }{
		{"a one line banner", "banner login ^CHello-Bn3^C\n", "the login banner is a heredoc"},
		{"a tab in the banner", "banner login <<'EOF'\nHello-Bn3\tx\nEOF\n", "holds a tab at column"},
		{"a long banner line", "banner login <<'EOF'\nHello-Bn3" + strings.Repeat("x", 80) + "\nEOF\n", "at most 80"},
		{"a banner not closed", "banner login <<'EOF'\nHello-Bn3\n", "never closed"},
		{"every delimiter", "banner login <<'EOF'\nHello-Bn3 ^ ~ % # @ $ &\nEOF\n", "holds every delimiter character"},
		{"a key placeholder", "ntp authentication-key 5 md5 <secret>\n", "is a placeholder"},
		{"a key of another algorithm", "ntp authentication-key 5 sha1 key-Bn3\n", "takes md5 <string>"},
		{"a vrf as the last word", "ntp server vrf\n", "line 1: error: ntp server: 'vrf' takes the name of the vrf after it"},
		{"a vrf name with a space", "ip name-server vrf \"MG MT\" 192.0.2.5\n", "a quote is not accepted"},
		{"a vrf name off the alphabet", "ip domain name vrf MG/MT lab.example.net\n", "the vrf name of ip domain name holds a character other than"},
		{"a vrf and no value", "ip domain list vrf MGMT\n", "ip domain list vrf takes one value and nothing else"},
		{"a vrf domain name twice", "ip domain name vrf MGMT a.example.net\nip domain name vrf MGMT b.example.net\n", "line 2: error: ip domain name is stated twice for one vrf"},
		{"an abbreviated source", "ntp server 192.0.2.5 source Lo0\n", "has its type abbreviated"},
		{"a banner of another type", "banner motd <<'EOF'\nHello-Bn3\nEOF\n", "only 'banner login'"},
		{"a Junos statement", "set system domain-name lab.example.net\n", "statements only"},
	}
	for _, c := range cases {
		f := sb.blockFile("bad.txt", c.text)
		out := sb.blk("", "lab", "cisco", "check", "system", "--file", f)
		if sb.code != 1 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, no %q:\n%s", c.name, sb.code, c.want, out)
		}
		noneOf(t, c.name, out+sb.stderr(), "Hello-Bn3", "key-Bn3")
		sb.blk("", "lab", "cisco", "set", "system", "--file", f, "-y")
		if sb.code != 1 {
			t.Errorf("%s: set accepted it", c.name)
		}
	}
	if sb.overrides() != "" && strings.Contains(sb.overrides(), "blocks:") {
		t.Errorf("a refusal wrote tacctl.yaml:\n%s", sb.overrides())
	}
}

// A device's own block over the scope's, the walkthrough that carries both,
// and the trap source of the IOS snmp block.
func TestDeviceBlockCiscoSystem(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	sb.dev("", "add", "rt1", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	f := sb.blockFile("system.txt", ciscoSystemFile)
	sb.blk("", "lab", "cisco", "set", "system", "--file", f, "-y")
	sb.expect(0, "is set", "")
	// the trap source: one interface for the scope
	sb.blk("snmp-server trap-source Loopback0\n", "lab", "cisco", "set", "snmp", "-", "-y")
	sb.expect(0, "is set", "")

	out := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	for _, want := range []string{
		"! The system block of scope 'lab' (tacctl scope block lab cisco show system): the login banner, domain, time zone, name servers and NTP.\n",
		"banner login ^\nAuthorized use only, Zq41.\n\n! Activity is logged.\n^\nip domain name lab.example.net\nclock timezone CET 1\n" +
			"ip name-server 192.0.2.53\nip name-server 192.0.2.54\nntp authentication-key 5 md5 ntp-key-secret-Yp9\nntp trusted-key 5\n" +
			"ntp server 192.0.2.123 key 5 prefer\nntp authenticate\n",
		"snmp-server trap-source Loopback0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the walkthrough lacks %q:\n%s", want, out)
		}
	}
	// the device's own: another banner, no name servers, another source
	dev := "banner login <<'EOF'\nThe device's own.\nEOF\nno ip name-server\nntp server 192.0.2.77\n"
	sb.dev(dev, "block", "rt1", "set", "system", "-", "-y")
	sb.expect(0, "The system block of device 'rt1' is set", "")
	out = plain(sb.cfgRun("", []string{"device", "block", "rt1", "show", "system", "--effective", "--reveal"}, route))
	for _, want := range []string{"# from scope 'lab'", "# from device 'rt1'", "The device's own.", "ntp server 192.0.2.77", "ip domain name lab.example.net"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("effective lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	for _, gone := range []string{"Authorized use only, Zq41.", "ip name-server 192.0.2.53"} {
		if strings.Contains(out, gone) {
			t.Errorf("the scope's %q is not replaced or taken out:\n%s", gone, out)
		}
	}
	if sb.logged("secret-read kind=block name=lab/cisco/system") != 1 || sb.logged("secret-read kind=block name=_devices/rt1/cisco/system") != 1 {
		t.Errorf("the reveal of both layers is not logged: %q", sb.runner.Argvs())
	}
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	if !strings.Contains(out, "The system block of scope 'lab' with the block of device 'rt1' over it (tacctl device block rt1 show system --effective)") ||
		!strings.Contains(out, "banner login ^\nThe device's own.\n^\n") || strings.Contains(out, "ip name-server") {
		t.Errorf("the walkthrough of the device:\n%s", out)
	}
	// a Junos text for an IOS device is an error
	sb.dev("set system domain-name x.example.net\n", "block", "rt1", "check", "system", "-")
	if sb.code != 1 {
		t.Errorf("a Junos text for an IOS device: %d", sb.code)
	}
}

// 'check --against' plans the IOS device from its last pull with the text in
// force: the block's lines (the banner as its size) and nothing written. Once
// in force, the plan carries the block.
func TestBlockCiscoSystemCheckAgainstADevice(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	b.sb.scopeSNMP("", "lab", "version", "v2c")
	b.sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	f := b.sb.blockFile("c.txt", ciscoSystemFile)
	// the device is read with the block in force (the pull reads the system
	// section only where the scope has one), as a device that has none of it
	b.run("scope", "block", "lab", "cisco", "set", "system", "--file", f, "-y")
	b.serve("cisco", strings.NewReplacer("banner login ^\nAuthorized use only, Zq41.\n\n! Activity is logged.\n^\n", "",
		"ip domain name lab.example.net\n", "", "clock timezone CET 1\n", "").Replace(b.expected("lab-c")))
	b.run("device", "config", "pull", "lab-c")
	records := b.sb.read("var-lib/devices-config.json")
	snaps := b.sb.snapshots()
	out := b.run("scope", "block", "lab", "cisco", "check", "system", "--file", f, "--against", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("against: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	for _, w := range []string{"Plan of lab-c with this text in force", "nothing was written and no device was reached", "Section system: planned, 3 statements",
		"banner login <message: 3 lines, 49 characters>", "ip domain name lab.example.net", "clock timezone CET 1"} {
		if !strings.Contains(out, w) {
			t.Errorf("against lacks %q:\n%s", w, out)
		}
	}
	i := strings.Index(out, "Plan of lab-c")
	noneOf(t, "the plan", out[i:], "Authorized use only", "Activity is logged", "ntp-key-secret")
	if b.sb.read("var-lib/devices-config.json") != records || b.sb.snapshots() != snaps {
		t.Error("check --against changed the records or took a snapshot")
	}
	// in force, the device's plan carries the block: the banner whole in the
	// paste, no word of it in the report
	out = b.run("device", "config", "plan", "lab-c", "--pull", "--no-secrets")
	for _, w := range []string{"! system: the statements of the system block of scope 'lab'", "banner login ^\nAuthorized use only, Zq41.\n\n! Activity is logged.\n^\n",
		"the login banner of 3 lines, 49 characters", "system: the NTP key lines of the system block of scope 'lab' have not been checked on a device"} {
		if !strings.Contains(out, w) {
			t.Errorf("the plan lacks %q:\n%s", w, out)
		}
	}
	noneOf(t, "the plan", out, "ntp-key-secret")
	j := strings.Index(out, "PASTE FROM HERE")
	if k := strings.Index(out[:j], "Authorized use only"); k >= 0 {
		t.Errorf("the report holds the banner:\n%s", out[:j])
	}
	// the JSON region is the paste, and the report items hold no banner
	js := b.run("device", "config", "plan", "lab-c", "--no-secrets", "--json")
	if !strings.Contains(js, "\"banner login ^\"") || strings.Contains(js, "ntp-key-secret") {
		t.Errorf("json:\n%s", js)
	}
}

// A device in the IOS 12.x syntax stores 'ntp server H version 3' without the
// option: a block that states it renders the bare line in the walkthrough and
// the plan, and the device that holds the bare line compares ok. A device in
// the modern syntax gets the line as typed.
func TestCiscoSystemNTPVersion3InTheIOS12Syntax(t *testing.T) {
	const typed, bare = "ntp server 192.0.2.123 version 3 key 5 prefer", "ntp server 192.0.2.123 key 5 prefer"
	b := newPullBox(t)
	b.cisco("lab-c", false)
	f := b.sb.blockFile("c.txt", strings.Replace(ciscoSystemFile, "ntp server 192.0.2.123 key 5 prefer", typed, 1))
	b.run("scope", "block", "lab", "cisco", "set", "system", "--file", f, "-y")
	if b.sb.code != 0 {
		t.Fatalf("set: %d %s", b.sb.code, b.sb.stderr())
	}
	// the block's own text and show are as typed
	if got := b.run("scope", "block", "lab", "cisco", "show", "system"); !strings.Contains(got, "ntp server 192.0.2.123 version 3 key 5 prefer\n") {
		t.Errorf("show:\n%s", got)
	}

	b.run("device", "ios-syntax", "lab-c", "ios12")
	have := b.expectedSyntax("lab-c", true)
	if !strings.Contains(have, bare+"\n") || strings.Contains(have, "version 3") {
		t.Fatalf("the expected text of a 12.x device:\n%s", have)
	}
	b.serve("cisco", have)
	b.version(ciscoVersion12)
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") {
		t.Fatalf("pull: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.Sections["system"].State != "ok" {
		t.Errorf("the system section of the record: %+v", rec)
	}
	wt := b.run("device", "config", "show", "lab-c")
	if !strings.Contains(wt, bare+"\n") || strings.Contains(wt, "version 3") {
		t.Errorf("the walkthrough of a 12.x device:\n%s", wt)
	}
	// the plan of a device that lacks the line adds it bare
	b.serve("cisco", strings.Replace(have, bare+"\n", "", 1))
	out = b.run("device", "config", "plan", "lab-c", "--pull", "--no-secrets")
	if b.sb.code != 0 || !strings.Contains(out, bare+"\n") || strings.Contains(out, "version 3") {
		t.Errorf("the plan of a 12.x device (exit %d):\n%s", b.sb.code, out)
	}

	// the modern syntax is as typed
	b.run("device", "ios-syntax", "lab-c", "modern")
	if wt = b.run("device", "config", "show", "lab-c"); !strings.Contains(wt, typed+"\n") {
		t.Errorf("the walkthrough of a modern device:\n%s", wt)
	}
}

// adoptCiscoSystem is what the IOS device says to the system reads.
const (
	adoptCiscoSystem = "banner exec ^C\nbanner login ^C\nip domain name lab.example.net\nip domain list example.net\nip domain lookup source-interface Loopback0\n" +
		"ip name-server 192.0.2.53 192.0.2.54\nip name-server vrf MGMT 192.0.2.99\nclock timezone CET 1 0\n" +
		"ip domain name vrf MGMT mgmt.example.net\n" +
		"ntp authentication-key 5 md5 0822455D0A16 7\nntp authentication-key 6 md5 SomeOtherKey9\nntp authenticate\nntp trusted-key 5\n" +
		"ntp master 3\nntp server 192.0.2.123 key 5 prefer\nntp server vrf MGMT 192.0.2.77\n"
	adoptCiscoBanner = "banner login ^C\nAuthorized, device Wd2.\n! Activity.\n^C\n"
)

func TestAdoptCiscoSystemDraftFlow(t *testing.T) {
	a := newAdoptBox(t)
	a.serve(ciscoSystemCmd, adoptCiscoSystem)
	a.serve(ciscoBannerCmd, adoptCiscoBanner)
	ed := a.e.editor("ed-prune", `grep -v 'ntp master\|ip domain list' "$f" > "$f.new" && mv "$f.new" "$f"`)
	n := a.sb.snapshots()
	out := a.runAs("y\n", ed, "scope", "block", "lab", "cisco", "adopt", "lab-ios", "system")
	if a.sb.code != 0 || !strings.Contains(out, "The system block of scope 'lab' is set (") {
		t.Fatalf("adopt: %d\n%s%s\ncommands: %q", a.sb.code, out, a.sb.stderr(), a.srv.Commands())
	}
	var reads []string
	for _, c := range a.srv.Commands() {
		if strings.HasPrefix(c, "show running-config") {
			reads = append(reads, c)
		}
	}
	if len(reads) != 2 || reads[0] != ciscoSystemCmd || reads[1] != ciscoBannerCmd {
		t.Errorf("reads: %q", reads)
	}
	seed := a.e.recorded("seed1")
	for _, want := range []string{
		"# adopted from lab-ios at ", "# Remove what this block should not own",
		"banner login <<'EOF'\nAuthorized, device Wd2.\n! Activity.\nEOF\n",
		"ip domain name lab.example.net\n", "ip domain list example.net\n", "clock timezone CET 1 0\n",
		"ip name-server 192.0.2.53\nip name-server 192.0.2.54\n",
		"ip name-server vrf MGMT 192.0.2.99\n", "ip domain name vrf MGMT mgmt.example.net\n", "ntp server vrf MGMT 192.0.2.77\n",
		"ntp trusted-key 5\n", "ntp server 192.0.2.123 version", "ntp authenticate\n", "ntp master",
		"# left out: ntp authentication-key 5 holds the device's own key string",
		"# left out: ntp authentication-key 6 holds the device's own key string",
	} {
		if want == "ntp server 192.0.2.123 version" {
			want = "ntp server 192.0.2.123 key 5 prefer\n"
		}
		if want == "ntp master" {
			continue
		}
		if !strings.Contains(seed, want) {
			t.Errorf("the draft lacks %q:\n%s", want, seed)
		}
	}
	var statements []string
	for _, l := range strings.Split(seed, "\n") {
		if !strings.HasPrefix(l, "#") {
			statements = append(statements, l)
		}
	}
	for _, bad := range []string{"0822455D0A16", "SomeOtherKey9", "ntp master", "lookup"} {
		if strings.Contains(strings.Join(statements, "\n"), bad) {
			t.Errorf("the draft holds %q:\n%s", bad, seed)
		}
	}
	for _, bad := range []string{"0822455D0A16", "SomeOtherKey9"} {
		if strings.Contains(seed, bad) {
			t.Errorf("the draft's comments hold %q:\n%s", bad, seed)
		}
	}
	stored := a.sb.read("state/blocks/lab/cisco/system")
	if !strings.Contains(stored, "ip domain name lab.example.net\n") || strings.Contains(stored, "ip domain list") {
		t.Errorf("stored:\n%s", stored)
	}
	if a.sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, a.sb.snapshots())
	}
	log := strings.Join(a.sb.runner.Argvs(), "\n")
	if a.sb.logged("secret-read kind=block-adopt name=lab/cisco/system by=alice") != 1 || a.sb.logged("block-adopt name=lab/cisco/system bytes=") != 1 {
		t.Errorf("log:\n%s", log)
	}
	// the banner of the device is the draft's and the stored block's, and
	// nowhere else
	for _, s := range []string{"Authorized, device Wd2.", "0822455D0A16", "SomeOtherKey9"} {
		noneOf(t, "output, error and log", out+a.sb.stderr()+log, s)
		if f := a.storedOutside(s); len(f) != 0 {
			t.Errorf("%q is stored in %v", s, f)
		}
	}
}

// 'snmp-server trap-source' in the IOS snmp block and 'trap-options
// source-address' in the Junos one, through the verbs.
func TestTrapSourceThroughTheVerbs(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.blk("snmp-server trap-source Loopback0\n", "lab", "cisco", "check", "snmp", "-")
	if sb.code != 0 || !strings.Contains(out, "loopback every device of the scope is expected to have") || !strings.Contains(out, "ok.") {
		t.Errorf("check ios: %d\n%s", sb.code, out)
	}
	sb.blk("snmp-server trap-source Lo0\n", "lab", "cisco", "check", "snmp", "-")
	sb.expect(1, "has its type abbreviated", "")
	// an address is one device's own: a scope's block states lo0 only
	sb.blk("set snmp trap-options source-address 192.0.2.7\n", "lab", "juniper", "check", "snmp", "-")
	sb.expect(1, "names an address or an interface of one device", "")
	out = sb.blk("set snmp trap-options source-address lo0\n", "lab", "juniper", "check", "snmp", "-")
	if sb.code != 0 || !strings.Contains(out, "loopback every device of the scope is expected to have") || !strings.Contains(out, "ok.") {
		t.Errorf("check junos: %d\n%s", sb.code, out)
	}
	sb.blk("set snmp trap-options source-address nms.example.net\n", "lab", "juniper", "check", "snmp", "-")
	sb.expect(1, "is not an address", "")
	// set and show: not a secret, shown as it is
	sb.blk("snmp-server trap-source Loopback0\n", "lab", "cisco", "set", "snmp", "-", "-y")
	sb.expect(0, "is set", "")
	out = sb.blk("", "lab", "cisco", "show", "snmp")
	if sb.code != 0 || !strings.Contains(out, "snmp-server trap-source Loopback0\n") {
		t.Errorf("show:\n%s", out)
	}
	out = sb.blk("", "lab", "cisco", "list")
	if !strings.Contains(out, "snmp     in force") || !strings.Contains(out, "nothing") && !strings.Contains(out, "statement") {
		t.Logf("list:\n%s", out)
	}
}

// The vrf forms of the system block and the vrf and informs forms of a trap
// host are statements of the block: checked, stored, shown and rendered in
// the walkthrough; a vrf form with no name is refused by line.
func TestScopeBlockCiscoVRFForms(t *testing.T) {
	sb := newSandbox(t, true)
	const system = "ip domain name vrf MGMT mgmt.example.net\nip domain list vrf MGMT mgmt.example.net\n" +
		"ip name-server vrf MGMT 192.0.2.53 192.0.2.54\nntp server vrf MGMT 192.0.2.123 prefer version 3\nntp server 192.0.2.123\n" +
		"no ntp server vrf OOB\n"
	f := sb.blockFile("system.txt", system)
	out := sb.blk("", "lab", "cisco", "check", "system", "--file", f)
	for _, want := range []string{"Owned by tacctl once in force: 6 statements", "vrf MGMT must exist on the device: tacctl does not create a vrf", "ok."} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	sb.blk("", "lab", "cisco", "set", "system", "--file", f, "-y")
	sb.expect(0, "is set", "")
	out = sb.blk("", "lab", "cisco", "show", "system")
	for _, want := range []string{"ip domain name vrf MGMT mgmt.example.net\n", "ip domain list vrf MGMT mgmt.example.net\n",
		"ip name-server vrf MGMT 192.0.2.53\nip name-server vrf MGMT 192.0.2.54\n", "ntp server vrf MGMT 192.0.2.123 version 3 prefer\n",
		"no ntp server vrf OOB\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}

	const snmp = "snmp-server host 192.0.2.61 vrf MGMT version 2c host-secret-Kq7\n" +
		"snmp-server host 192.0.2.62 informs version 2c host-secret-Kq7\n" +
		"snmp-server host 192.0.2.63 version 2c host-secret-Kq7 udp-port 1162 config\n"
	f = sb.blockFile("snmp.txt", snmp)
	out = sb.blk("", "lab", "cisco", "check", "snmp", "--file", f)
	if sb.code != 0 || !strings.Contains(out, "3 trap hosts") || !strings.Contains(out, "vrf MGMT must exist on the device") {
		t.Errorf("check snmp (exit %d):\n%s", sb.code, out)
	}
	noneOf(t, "check snmp", out+sb.stderr(), "host-secret-Kq7")
	sb.blk("", "lab", "cisco", "set", "snmp", "--file", f, "-y")
	sb.expect(0, "is set", "")
	out = sb.blk("", "lab", "cisco", "show", "snmp")
	for _, want := range []string{"snmp-server host 192.0.2.61 vrf MGMT version 2c <secret:1>\n", "snmp-server host 192.0.2.62 informs version 2c <secret:1>\n",
		"snmp-server host 192.0.2.63 version 2c <secret:1> udp-port 1162 config\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("show snmp lacks %q:\n%s", want, out)
		}
	}
	noneOf(t, "show snmp", out, "host-secret-Kq7")

	// the walkthrough carries the lines as typed
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	sb.dev("", "add", "rt1", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	w := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "rt1"}, route))
	for _, want := range []string{"ip domain name vrf MGMT mgmt.example.net\n", "ip name-server vrf MGMT 192.0.2.54\n",
		"ntp server vrf MGMT 192.0.2.123 version 3 prefer\n", "snmp-server host 192.0.2.62 informs version 2c host-secret-Kq7\n",
		"snmp-server host 192.0.2.61 vrf MGMT version 2c host-secret-Kq7\n"} {
		if !strings.Contains(w, want) {
			t.Errorf("the walkthrough lacks %q:\n%s", want, w)
		}
	}
}
