package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
)

// Fixes to 'host rename' found in review: the two races with the device
// registry, the wording of what the undo leaves, the scope question's
// premise, and the paths that carry a hold or no ssh target.

// addDeviceBehindTheBack registers the device name in devices.yaml directly,
// as another command would have.
func (sb *sandbox) addDeviceBehindTheBack(name, addr string) {
	sb.t.Helper()
	f, err := devreg.Load(sb.path("state", "devices.yaml"))
	if err != nil {
		sb.t.Fatal(err)
	}
	f.Devices = append(f.Devices, &devreg.Device{Name: name, Address: addr, Vendor: "cisco"})
	text, err := f.Text()
	if err != nil {
		sb.t.Fatal(err)
	}
	sb.write("state/devices.yaml", string(text), 0o600)
}

// A device registered under the new name between the checks and the write of
// the pins is found under the registry's lock: the registry line goes back,
// and a host and a device never share the name. It holds with no pin too.
func TestHostRenameFindsADeviceRegisteredMeanwhile(t *testing.T) {
	for _, pinned := range []bool{true, false} {
		sb := hostLab(t)
		if pinned {
			sb.seedPin("web1", "192.168.1.10")
		}
		sb.hooks.hostRenameStep = func(step string) {
			if step == "registry" {
				sb.addDeviceBehindTheBack("web7", "192.168.1.77")
			}
		}
		regBefore := sb.registryText()
		sb.run("", []string{"host", "rename", "web1", "web7"})
		sb.expect(1, "", "A device named 'web7' (192.168.1.77) was registered meanwhile")
		if !strings.Contains(sb.stderr(), "Host 'web1' was not renamed; nothing was changed.") {
			t.Errorf("pinned %v: stderr:\n%s", pinned, sb.stderr())
		}
		if sb.registryText() != regBefore {
			t.Errorf("pinned %v: registry %q, want %q", pinned, sb.registryText(), regBefore)
		}
		if hasAuditPrefix(sb.runner, "", "host rename ") {
			t.Errorf("pinned %v: a refused rename was logged", pinned)
		}
	}
}

// The other direction: a host enrolled (or renamed) under the name between
// the checks of 'device add' and 'device rename' and their write is found
// when the registry is written, and the device is not registered.
func TestDeviceWriteFindsAHostEnrolledMeanwhile(t *testing.T) {
	sb := hostLab(t)
	enrollBehindTheBack := func() {
		sb.write("state/linux-hosts", hostLines+"web7|root@192.168.1.77||lab|192.0.2.1|\n", 0o600)
	}
	sb.hooks.deviceWriteStep = enrollBehindTheBack
	before := sb.devices()
	sb.run("", []string{"device", "add", "web7", "192.168.1.90", "--vendor", "cisco", "--no-host-key"})
	sb.expect(1, "", "'web7' is an enrolled host")
	if sb.devices() != before {
		t.Errorf("a device was registered:\n%s", sb.devices())
	}

	sb.write("state/linux-hosts", hostLines, 0o600)
	sb.run("", []string{"device", "rename", "lab-sw", "web7"})
	sb.expect(1, "", "'web7' is an enrolled host")
	if sb.devices() != before {
		t.Errorf("a device was renamed:\n%s", sb.devices())
	}

	// The same checks without the race still pass for a free name.
	sb.hooks.deviceWriteStep = nil
	sb.run("", []string{"device", "add", "web8", "192.168.1.91", "--vendor", "cisco", "--no-host-key"})
	sb.expect(0, "", "")
}

// The undo that cannot put the pins back says that both registries name the
// new host; one that can, says what an earlier pin of the new name lost.
func TestHostRenameUndoWording(t *testing.T) {
	knownHosts := func(sb *sandbox) string { return sb.path("var-lib", "ssh", "known_hosts") }
	breakKnownHosts := func(sb *sandbox) {
		_ = os.Remove(knownHosts(sb))
		if err := os.Mkdir(knownHosts(sb), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// known_hosts fails after the pins were written, and the pins cannot be
	// written back (the registry's lock is out of reach).
	sb := renameLab(t)
	breakKnownHosts(sb)
	sb.hooks.hostRenameStep = func(step string) {
		if step == "undo" {
			sb.breakDeviceRegistryLock()
		}
	}
	sb.run("", []string{"host", "rename", "web1", "web7"})
	if sb.code != 1 {
		t.Fatalf("exit %d\n%s", sb.code, sb.printed())
	}
	for _, want := range []string{"The host registry and the device registry both name the host 'web7'", "may be stale", "tacctl backup restore"} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, sb.stderr())
		}
	}
	if strings.Contains(sb.stderr(), "pinned ssh keys and address are under") {
		t.Errorf("the wrong state was named:\n%s", sb.stderr())
	}

	// known_hosts fails once: the pins are written, then written back; the
	// pin a leftover of the new name had is gone, and the text says so.
	sb = renameLab(t)
	sb.seedPin("web7", "192.0.2.77")
	breakKnownHosts(sb)
	sb.hooks.hostRenameStep = func(step string) {
		if step == "undo" {
			_ = os.Remove(knownHosts(sb))
		}
	}
	regBefore := sb.registryText()
	sb.run("y\n", []string{"host", "rename", "web1", "web7"})
	if sb.code != 1 {
		t.Fatalf("exit %d\n%s", sb.code, sb.printed())
	}
	if !strings.Contains(sb.stderr(), "Host 'web1' was not renamed. The pinned ssh keys and address an earlier host of the name 'web7' left were replaced; the latest snapshot has them") ||
		strings.Contains(sb.stderr(), "nothing was changed") {
		t.Errorf("stderr:\n%s", sb.stderr())
	}
	if sb.registryText() != regBefore || sb.pin("web1") == nil || sb.pin("web7") != nil {
		t.Errorf("registry %q, pins web1 %v web7 %v", sb.registryText(), sb.pin("web1"), sb.pin("web7"))
	}
}

// The scope question's premise is that no other host uses the scope; a host
// enrolled into it after the question is met when the scope would move.
func TestHostRenameScopeQuestionPremiseHolds(t *testing.T) {
	sb := scopeRenameLab(t)
	sb.hooks.hostRenameStep = func(step string) {
		if step == "pins" {
			sb.write("state/linux-hosts", "web9|root@198.51.100.10||linux-web1|192.0.2.1|\nweb2|root@192.168.1.12||lab|192.0.2.1|\nweb3|root@198.51.100.11||linux-web1|192.0.2.1|\n", 0o600)
		}
	}
	sb.run("", []string{"host", "rename", "web1", "web9", "--yes"})
	sb.expect(0, "To rename the scope as well: tacctl scope rename linux-web1 linux-web9", "")
	if !strings.Contains(sb.printed(), "[WARN] Scope 'linux-web1' keeps its name: other enrolled hosts use it.") {
		t.Errorf("printed:\n%s", sb.printed())
	}
	if !sb.hasScope("linux-web1") || sb.hasScope("linux-web9") {
		t.Error("the scope was renamed")
	}
}

// The line that says the scope stays is printed when the rename goes on, not
// before a refusal of the lock.
func TestHostRenameScopeStaysLineFollowsTheLock(t *testing.T) {
	sb := scopeRenameLab(t)
	sb.write("state/linux-hosts", scopeLabHosts+"web3|root@198.51.100.11||linux-web1|192.0.2.1|\n", 0o600)
	unlock, err := hosts.LockHost(sb.path("state", "locks"), "web1")
	if err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"host", "rename", "web1", "web9"})
	sb.expect(1, "", "'web1' is locked by another tacctl command")
	if strings.Contains(sb.printed(), "keeps its name") {
		t.Errorf("printed before the lock:\n%s", sb.printed())
	}
	unlock()
	sb.run("", []string{"host", "rename", "web1", "web9"})
	sb.expect(0, "Scope 'linux-web1' keeps its name: other enrolled hosts use it.", "")
}

// A host enrolled with --local has no ssh target and no address to hold: it
// is renamed like another, and nothing goes over ssh.
func TestHostRenameOfTheLocalHost(t *testing.T) {
	sb := hostLab(t)
	sb.write("state/linux-hosts", hostLines+"here|local||lab|192.0.2.1|\n", 0o600)
	sb.write("state/hosts/here.json", renameRecord, 0o600)
	sb.run("", []string{"host", "rename", "here", "there"})
	sb.expect(0, "Host 'here' renamed to 'there'.", "")
	if !strings.Contains(sb.registryText(), "\nthere|local||lab|192.0.2.1|\n") || strings.Contains(sb.registryText(), "\nhere|") {
		t.Errorf("registry %q", sb.registryText())
	}
	if sb.fileExists("state/hosts/here.json") || !sb.fileExists("state/hosts/there.json") {
		t.Error("the record did not move")
	}
	if sb.sshCalls() != 0 {
		t.Errorf("%d ssh calls", sb.sshCalls())
	}
}

// A held host renamed only in its spelling (a name from before, with upper
// case, to lower case) keeps its hold on the same address, the rendered file
// names the new spelling, and the hold is no orphan.
func TestHostRenameSpellingOnlyOfAHeldHost(t *testing.T) {
	sb := renameLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	sb.legacyHostCase("web1", "WEB1")
	sb.run("", []string{"host", "rename", "WEB1", "web1"})
	sb.expect(0, "Host 'WEB1' renamed to 'web1'.", "")
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "# break-glass held: 192.168.1.10 (host web1)") || strings.Contains(cfg, "device WEB1") {
		t.Errorf("the rendered file:\n%s", cfg)
	}
	if got := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(got, "web1") || strings.Contains(got, "WEB1") || strings.Contains(got, "ORPHAN") {
		t.Errorf("breakglass list:\n%s", got)
	}
	if got := plain(sb.run("", []string{"host", "list"})); !strings.Contains(got, "BREAK-GLASS") {
		t.Errorf("host list:\n%s", got)
	}
}
