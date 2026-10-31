package cli

import (
	"os"
	"strings"
	"testing"
)

// 'device rename <new> <name> --replace' (0.2.23, D308): the device registered
// at a bench address takes the place of the original, which is removed with
// its files; the staging /32 ends; a hold on the original is cleared, never
// moved.

// benchKey is the host key of the replacement, another one than the original's.
const benchKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqetQQZxbhY2eMxJy6V4Kz5mUqGzvYvpYbpRRUjoo"

func TestDeviceReplaceTakesTheOriginalsPlace(t *testing.T) {
	sb := cloneFixture(t)
	sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	// The replacement is a device of its own now: its host key, its own
	// community, a block of its own, a record of its own.
	sb.devSNMP("example-bench-community\n", cloneNew, "community", "--stdin")
	reg := sb.devices()
	i := strings.Index(reg, "  "+cloneNew+":")
	sb.write("state/devices.yaml", reg[:i]+strings.Replace(reg[i:], "    timeout_scale: 2\n", "    timeout_scale: 2\n    host_keys: ["+benchKey+"]\n", 1), 0o600)
	sb.write("state/blocks/_devices/"+cloneNew+"/juniper/system", "set system time-zone UTC\nset system host-name bench\n", 0o600)
	record := func(name, pulled string) string {
		return `"` + name + `":{"vendor":"juniper","transport":"ssh","pulled":"` + pulled + `","by":"alice","result":"ok","secrets_visible":true,"sections":{"aaa":{"state":"ok"}}}`
	}
	sb.write("var-lib/devices-config.json", `{"version":1,"updated":"2026-10-10T12:00:00Z","devices":{`+record(cloneSrc, "2026-10-09T12:00:00Z")+","+record(cloneNew, "2026-10-10T12:00:00Z")+"}}", 0o600)
	snaps := sb.snapshots()

	// Without the word, on a closed stdin, nothing happens; the plan is read.
	out := sb.dev("", "rename", cloneNew, cloneSrc, "--replace")
	if sb.code != 0 || !strings.Contains(out, "Aborted.") {
		t.Fatalf("closed stdin: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{"About to replace '" + cloneSrc + "' with '" + cloneNew + "'.",
		"Removed:  '" + cloneSrc + "' (192.168.1.20) from the registry, with its SNMP credentials file, 2 configuration block files, its configuration record, 1 acknowledged notice.",
		"Replaced: '" + cloneNew + "' (192.0.2.77) is renamed '" + cloneSrc + "' and moves to 192.168.1.20 (scope lab); it keeps its own host keys, and none of '" + cloneSrc + "' is carried.",
		"Staging:  192.0.2.77/32 ends in scope 'lab'."} {
		if !strings.Contains(plain(sb.out.String())+sb.stderr(), want) {
			t.Errorf("plan lacks %q:\n%s%s", want, sb.out.String(), sb.stderr())
		}
	}
	if sb.snapshots() != snaps || !strings.Contains(sb.devices(), "  "+cloneNew+":") || !sb.fileExists("state/staging") {
		t.Fatal("an aborted replacement changed something")
	}
	// Another answer is no either.
	if out = sb.dev("n\n", "rename", cloneNew, cloneSrc, "--replace"); !strings.Contains(out, "Aborted.") || sb.snapshots() != snaps {
		t.Errorf("n: %q", out)
	}

	out = sb.dev("y\n", "rename", cloneNew, cloneSrc, "--replace")
	if sb.code != 0 || !strings.Contains(out, "Device '"+cloneNew+"' replaces '"+cloneSrc+"': it is now '"+cloneSrc+"' at 192.168.1.20.") {
		t.Fatalf("replace: %d %q %q", sb.code, out, sb.stderr())
	}
	audited := auditLines(sb.runner)

	// The registry: one device, the replacement's fields at the original's
	// name and address; its own host key stays, the original's DNS name
	// (the replacement has none) and none of its notices come.
	reg = sb.devices()
	if strings.Contains(reg, cloneNew) || strings.Count(reg, "    address:") != 1 || !strings.Contains(reg, "  "+cloneSrc+":\n    address: 192.168.1.20\n    vendor: juniper\n    hostname: jsw1.example.net\n") ||
		!strings.Contains(reg, "host_keys: ["+benchKey+"]") || strings.Contains(reg, "ack:") {
		t.Errorf("devices.yaml:\n%s", reg)
	}
	// The files: the replacement's, under the original's name; none of the
	// original's left, none under the replacement's.
	if got := sb.read("state/snmp/devices/" + cloneSrc + ".yaml"); !strings.Contains(got, "example-bench-community") || strings.Contains(got, "example-community\n") {
		t.Errorf("credentials:\n%s", got)
	}
	if sb.fileExists("state/snmp/devices/" + cloneNew + ".yaml") {
		t.Error("the replacement's credentials file is left under its old name")
	}
	if got := sb.read("state/blocks/_devices/" + cloneSrc + "/juniper/system"); !strings.Contains(got, "host-name bench") {
		t.Errorf("blocks: %q", got)
	}
	if sb.fileExists("state/blocks/_devices/"+cloneNew) || strings.Contains(sb.overrides(), "jsw2~lab") || !strings.Contains(sb.overrides(), devBlocksKey) {
		t.Errorf("blocks of the replacement are left, or the original's list is gone:\n%s", sb.overrides())
	}
	rec := sb.read("var-lib/devices-config.json")
	if strings.Count(rec, `"result"`) != 1 || strings.Contains(rec, `"`+cloneNew+`"`) || !strings.Contains(rec, `"`+cloneSrc+`"`) || !strings.Contains(rec, "2026-10-10T12:00:00Z") {
		t.Errorf("records:\n%s", rec)
	}
	// The staging /32 ended, in the file and in the scope.
	if sb.fileExists("state/staging") {
		t.Errorf("staging:\n%s", sb.read("state/staging"))
	}
	if m := plain(sb.run("", []string{"scope", "show", "lab"})); strings.Contains(m, "192.0.2.77") {
		t.Errorf("the /32 stayed in the scope:\n%s", m)
	}
	// One snapshot for all the steps.
	if sb.snapshots() != snaps+1 {
		t.Errorf("snapshots %d, was %d", sb.snapshots(), snaps)
	}
	if !strings.Contains("\n"+strings.Join(audited, "\n"), "\ndevice replace old="+cloneSrc+" new="+cloneNew+" address=192.168.1.20 hold_cleared=no snmp_files=1 block_files=2 notices=1 count=1 by=") ||
		!strings.Contains(strings.Join(audited, "\n"), "scope staging done cidr=192.0.2.77/32 scope=lab device="+cloneSrc+" seen=192.168.1.20") {
		t.Errorf("audit lines %q", audited)
	}
	for _, s := range []string{cloneAuth, clonePriv, "example-community", "example-bench-community"} {
		if strings.Contains(out, s) || strings.Contains(strings.Join(audited, "\n"), s) {
			t.Errorf("%q is printed or logged", s)
		}
	}
}

func TestDeviceReplaceYesIsTheOnlyBypass(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	was := sb.devices() + sb.read("state/staging")
	// A terminal-less run, a bare newline and a refusal are all "no".
	for _, in := range []string{"", "\n", "no\n"} {
		sb.dev(in, "rename", "lab-sw2", "lab-sw", "--replace")
		if sb.code != 0 || !strings.Contains(sb.printed(), "Aborted.") || sb.devices()+sb.read("state/staging") != was {
			t.Errorf("stdin %q: %d %q", in, sb.code, sb.printed())
		}
	}
	// --yes goes with --replace only.
	sb.dev("", "rename", "lab-sw2", "lab-sw3", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "--yes goes with --replace") || sb.devices()+sb.read("state/staging") != was {
		t.Errorf("rename --yes: %d %q", sb.code, sb.stderr())
	}
	sb.dev("", "rename", "lab-sw2", "lab-sw", "--replace", "--allow-generic", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "--allow-generic does not go with --replace") || sb.devices()+sb.read("state/staging") != was {
		t.Errorf("--allow-generic: %d %q", sb.code, sb.stderr())
	}
	sb.dev("", "rename", "lab-sw2", "lab-sw", "--replace", "--yes")
	sb.expect(0, "Device 'lab-sw2' replaces 'lab-sw'", "")
	if strings.Contains(sb.devices(), "lab-sw2") || !strings.Contains(sb.devices(), "  lab-sw: {address: 192.168.1.1, vendor: cisco}\n") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
}

func TestDeviceReplaceRefusals(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	sb.dev("", "add", "lab-sw3", "192.168.1.3", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	state := func() string {
		return sb.devices() + "|" + sb.read("state/staging") + "|" + sb.overrides() + "|" + sb.read("state/store.yaml")
	}
	was, snaps := state(), sb.snapshots()
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"rename", "lab-sw2", "lab-sw2", "--replace", "--yes"}, "is the one device"},
		{[]string{"rename", "LAB-SW2", "lab-sw2", "--replace", "--yes"}, "is the one device"},
		{[]string{"rename", "lab-sw2", "nosuch", "--replace", "--yes"}, "Device 'nosuch' not found"},
		{[]string{"rename", "nosuch", "lab-sw", "--replace", "--yes"}, "Device 'nosuch' not found"},
		{[]string{"rename", "lab-sw2", "web1", "--replace", "--yes"}, "'web1' is an enrolled host"},
		// registered where the scope answers, so with no staging /32
		{[]string{"rename", "lab-sw3", "lab-sw", "--replace", "--yes"}, "'lab-sw3' is not staged"},
		{[]string{"rename", "lab-sw2", "lab-sw", "x", "--replace"}, "Usage: tacctl device rename"},
	} {
		sb.dev("", c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr()+sb.printed(), c.msg) {
			t.Errorf("%v: %d %q, want %q", c.args, sb.code, sb.printed(), c.msg)
		}
		if state() != was || sb.snapshots() != snaps {
			t.Errorf("%v changed something", c.args)
		}
	}
	// The refusal of a device that is not staged names how to stage one.
	sb.dev("", "rename", "lab-sw3", "lab-sw", "--replace", "--yes")
	if !strings.Contains(sb.stderr(), "tacctl device clone lab-sw lab-sw3 --staging <bench-ip>") {
		t.Errorf("no way out: %q", sb.stderr())
	}
}

// The replacement takes the scope its new address gives it; the plan says so
// when it is not the scope of its bench address, and the bench /32 ends in
// the scope that holds it.
func TestDeviceReplaceInAnotherScope(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "cisco", "--scope", "lab", "--staging", "192.0.2.88", "--name", "bench-sw"})
	// the device is registered at its bench address
	sb.dev("", "add", "bench-sw", "192.0.2.88", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	if !strings.Contains(sb.read("state/staging"), "192.0.2.88/32|lab|device|bench-sw|") {
		t.Fatalf("staging:\n%s", sb.read("state/staging"))
	}
	out := sb.dev("", "rename", "bench-sw", "prod-sw", "--replace")
	if !strings.Contains(out, "moves to 10.99.0.1 (scope prod, not scope lab of its bench address)") || !strings.Contains(out, "192.0.2.88/32 ends in scope 'lab'") {
		t.Errorf("plan:\n%s", out)
	}
	sb.dev("y\n", "rename", "bench-sw", "prod-sw", "--replace")
	sb.expect(0, "Device 'bench-sw' replaces 'prod-sw': it is now 'prod-sw' at 10.99.0.1.", "")
	if strings.Contains(sb.devices(), "bench-sw") || !strings.Contains(sb.devices(), "  prod-sw: {address: 10.99.0.1, vendor: cisco}\n") || sb.fileExists("state/staging") {
		t.Errorf("devices.yaml:\n%s\nstaging: %q", sb.devices(), sb.read("state/staging"))
	}
	if m := plain(sb.run("", []string{"scope", "show", "lab"})); strings.Contains(m, "192.0.2.88") {
		t.Errorf("the /32 stayed in scope lab:\n%s", m)
	}
}

// A hold of the original is shown, needs the superuser, is cleared (one
// render, the backend restarted) and is never moved to the replacement; a
// clone of a held device is not held either.
func TestDeviceReplaceClearsTheHold(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	sb.hold(t, "lab-sw", "console recovery after a failed paste", "lab-sw")
	sb.expect(0, "", "")
	sb.dev("", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	if !strings.Contains(sb.overrides(), "breakglass_hold:\n  lab-sw:\n") || strings.Contains(sb.overrides(), "lab-sw2:\n    address") {
		t.Fatalf("a clone of a held device is held:\n%s", sb.overrides())
	}
	was, snaps := sb.devices()+sb.read("state/staging")+sb.overrides(), sb.snapshots()

	// An engineer is refused, naming the hold; nothing changes.
	sb.asEngineer("y\n", "device", "rename", "lab-sw2", "lab-sw", "--replace", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw: replacing it clears the hold, which is the superuser's") ||
		sb.devices()+sb.read("state/staging")+sb.overrides() != was || sb.snapshots() != snaps {
		t.Fatalf("engineer: %d %q", sb.code, sb.stderr())
	}

	// The superuser sees the hold in the plan and, after the answer, the
	// hold is gone and the address is answered again, as the replacement's.
	out := sb.dev("n\n", "rename", "lab-sw2", "lab-sw", "--replace")
	if !strings.Contains(out, "Break-glass is held on lab-sw (192.168.1.1) since ") || !strings.Contains(out, "the hold is cleared, never moved to 'lab-sw2'") || !strings.Contains(out, "Aborted.") {
		t.Errorf("plan:\n%s", out)
	}
	out = sb.dev("y\n", "rename", "lab-sw2", "lab-sw", "--replace")
	if sb.code != 0 || !strings.Contains(out, "Device 'lab-sw2' replaces 'lab-sw': it is now 'lab-sw' at 192.168.1.1.") || !strings.Contains(out, "Break-glass on lab-sw (192.168.1.1) released; rendered: ") {
		t.Fatalf("replace: %d %q %q", sb.code, out, sb.stderr())
	}
	audited := strings.Join(auditLines(sb.runner), "\n")
	for _, want := range []string{"breakglass release device=lab-sw addr=192.168.1.1 held=", " result=ok", "device replace old=lab-sw new=lab-sw2 address=192.168.1.1 hold_cleared=yes "} {
		if !strings.Contains(audited, want) {
			t.Errorf("audit lines lack %q:\n%s", want, audited)
		}
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") {
		t.Errorf("the hold is left:\n%s", o)
	}
	if cfg := sb.renderedConfig(); strings.Contains(cfg, "break-glass held") || !strings.Contains(cfg, `"192.168.0.0/16"`) {
		t.Errorf("the rendered file still carves the address:\n%s", cfg)
	}
	if sb.restarts() == 0 {
		t.Error("no backend was restarted for the release")
	}
	if strings.Contains(sb.devices(), "lab-sw2") || sb.fileExists("state/staging") {
		t.Errorf("devices.yaml:\n%s\nstaging %q", sb.devices(), sb.read("state/staging"))
	}
}

// An engineer replaces within their own scopes, and only a device with no
// hold; a replacement whose SNMP settings are not the original's is the
// superuser's to bring in.
func TestEngineerReplaceInOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	sb.devSNMP("", "lab-sw", "port", "1161")
	sb.asEngineer("", "device", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	out := sb.asEngineer("", "device", "rename", "lab-sw2", "lab-sw", "--replace", "--yes")
	if sb.code != 0 || !strings.Contains(out, "Device 'lab-sw2' replaces 'lab-sw'") {
		t.Fatalf("replace: %d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.devices(), "  lab-sw:\n    address: 192.168.1.1\n    vendor: cisco\n    snmp: {port: 1161}\n") || sb.fileExists("state/staging") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
	if line := auditLine(sb.runner, "device replace old=lab-sw new=lab-sw2 address=192.168.1.1 hold_cleared=no "); line == "" || !strings.HasSuffix(line, " by=bob") {
		t.Errorf("audit lines: %q", auditLines(sb.runner))
	}

	// Another scope's device is not found, and a replacement with settings
	// of its own that the original lacks is refused.
	sb.asEngineer("", "device", "rename", "lab-sw", "prod-sw", "--replace", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found") {
		t.Errorf("another scope: %d %q", sb.code, sb.stderr())
	}
	sb.dev("", "add", "lab-sw4", "192.0.2.78", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.78/32"})
	sb.write("state/staging", "192.0.2.78/32|lab|device|lab-sw4|2026-10-01 10:00\n", 0o600)
	sb.devSNMP("", "lab-sw4", "port", "2161")
	was := sb.devices()
	sb.asEngineer("", "device", "rename", "lab-sw4", "lab-sw", "--replace", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A device's SNMP settings are not the engineer tier's to change") || sb.devices() != was {
		t.Errorf("settings of its own: %d %q", sb.code, sb.stderr())
	}
	if _, err := os.Stat(sb.path("state", "staging")); err != nil {
		t.Errorf("a refused replacement ended the staging: %v", err)
	}
}

// A hold on the replacement itself (it was held on the bench) would be left
// under a name it no longer has: it is released first.
func TestDeviceReplaceRefusesAHeldReplacement(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	sb.dev("", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	sb.hold(t, "lab-sw2", "console recovery on the bench", "lab-sw2")
	sb.expect(0, "", "")
	was := sb.devices() + sb.read("state/staging") + sb.overrides()
	sb.dev("", "rename", "lab-sw2", "lab-sw", "--replace", "--yes")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw2: release it first (tacctl breakglass release lab-sw2)") || sb.devices()+sb.read("state/staging")+sb.overrides() != was {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
}
