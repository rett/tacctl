package cli

import (
	"os"
	"strings"
	"testing"
)

// A device staged at a bench address keeps its staging /32 through
// 'device rename': the fourth field of the staging line follows the name, so
// that the sweep still finds the device and ends the /32 once the device is
// registered at an address its scope covers (D297).
func TestDeviceRenameCarriesTheStagingLine(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.dev("", "add", "other", "10.99.0.2", "--no-host-key")
	sb.run("", []string{"config", "cisco", "--scope", "lab", "--staging", "192.0.2.77", "--name", "core-sw1"})
	sb.expect(0, "", "")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.78/32,192.0.2.79/32"})
	sb.expect(0, "", "")
	sb.write("state/staging", sb.read("state/staging")+"192.0.2.78/32|lab|device|other|2026-01-01 10:00\n192.0.2.79/32|lab|host|core-sw1|2026-01-01 10:00\n", 0o600)
	if st := sb.read("state/staging"); !strings.HasPrefix(st, "192.0.2.77/32|lab|device|core-sw1|") {
		t.Fatalf("staging:\n%s", st)
	}
	since := strings.Split(strings.Split(sb.read("state/staging"), "\n")[0], "|")[4]

	out := sb.dev("", "rename", "core-sw1", "dc1-core1")
	if sb.code != 0 || !strings.Contains(out, "renamed to 'dc1-core1'") {
		t.Fatalf("rename: %d %q %q", sb.code, out, sb.stderr())
	}
	// The name follows; the /32, the scope and the date stay; the entries of
	// another device and of a host of the old name are not touched.
	want := "192.0.2.77/32|lab|device|dc1-core1|" + since + "\n192.0.2.78/32|lab|device|other|2026-01-01 10:00\n192.0.2.79/32|lab|host|core-sw1|2026-01-01 10:00\n"
	if got := sb.read("state/staging"); got != want {
		t.Errorf("staging %q, want %q", got, want)
	}
	if m := plain(sb.run("", []string{"scope", "staging", "list"})); !strings.Contains(m, "192.0.2.77") || !strings.Contains(m, "dc1-core1") {
		t.Errorf("scope staging list:\n%s", m)
	}
	// The sweep finds the renamed device: registered where its scope covers
	// it, the staging /32 ends.
	sb.dev("", "address", "dc1-core1", "172.16.0.5")
	sb.expect(0, "", "")
	if got := sb.read("state/staging"); strings.Contains(got, "192.0.2.77") || !strings.Contains(got, "192.0.2.78") {
		t.Errorf("staging after the device is in place:\n%s", got)
	}
	if m := plain(sb.run("", []string{"scope", "show", "lab"})); strings.Contains(m, "192.0.2.77") {
		t.Errorf("the /32 stayed in the scope:\n%s", m)
	}
}

// An entry that an earlier device of the new name left is dropped with the
// rename, as a host's is; a spelling-only rename keeps the entry; no staging
// file stays none.
func TestDeviceRenameStagingStrayAndSpelling(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.77/32,192.0.2.80/32"})
	sb.expect(0, "", "")
	sb.write("state/staging", "192.0.2.77/32|lab|device|core-sw1|2026-01-01 10:00\n192.0.2.80/32|lab|device|dc1-core1|2020-01-01 10:00\n", 0o600)
	sb.dev("", "rename", "core-sw1", "dc1-core1")
	sb.expect(0, "", "")
	if got, want := sb.read("state/staging"), "192.0.2.77/32|lab|device|dc1-core1|2026-01-01 10:00\n"; got != want {
		t.Errorf("staging %q, want %q", got, want)
	}
	// A spelling-only rename keeps the entry under the new spelling.
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "  dc1-core1:", "  DC1-Core1:", 1), 0o600)
	sb.write("state/staging", "192.0.2.77/32|lab|device|DC1-Core1|2026-01-01 10:00\n", 0o600)
	sb.dev("", "rename", "DC1-Core1", "dc1-core1")
	sb.expect(0, "", "")
	if got, want := sb.read("state/staging"), "192.0.2.77/32|lab|device|dc1-core1|2026-01-01 10:00\n"; got != want {
		t.Errorf("staging after the spelling %q, want %q", got, want)
	}
	// With no staging file there is nothing to do and none is made.
	sb2 := newSandbox(t, true)
	sb2.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb2.dev("", "rename", "core-sw1", "dc1-core1")
	sb2.expect(0, "", "")
	if sb2.fileExists("state/staging") {
		t.Error("a staging file was made")
	}
}

// The staging line holds the device name as typed to 'config <vendor>
// --staging --name', and the registry compares names without regard to case,
// so the line is the device's whatever its spelling. A rename of the spelling
// only keeps the line (it is not a stray of the new name) and the sweep still
// finds the device.
func TestDeviceRenameStagingLineOfAnotherSpelling(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.77/32"})
	sb.expect(0, "", "")
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "  core-sw1:", "  Core-SW1:", 1), 0o600)
	sb.write("state/staging", "192.0.2.77/32|lab|device|core-sw1|2026-01-01 10:00\n", 0o600)
	// (a) the registry spells the name with upper case, the line does not
	sb.dev("", "rename", "Core-SW1", "core-sw1")
	sb.expect(0, "", "")
	if got, want := sb.read("state/staging"), "192.0.2.77/32|lab|device|core-sw1|2026-01-01 10:00\n"; got != want {
		t.Fatalf("the line of a spelling-only rename: %q, want %q", got, want)
	}
	sb.dev("", "address", "core-sw1", "172.16.0.5")
	sb.expect(0, "", "")
	if sb.fileExists("state/staging") {
		t.Errorf("the sweep did not find the device:\n%s", sb.read("state/staging"))
	}

	// (b) the line is spelled with upper case, the device is not: a rename
	// to another name carries it
	sb = newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.77/32"})
	sb.expect(0, "", "")
	sb.write("state/staging", "192.0.2.77/32|lab|device|CORE-SW1|2026-01-01 10:00\n", 0o600)
	sb.dev("", "rename", "core-sw1", "dc1-core1")
	sb.expect(0, "", "")
	if got, want := sb.read("state/staging"), "192.0.2.77/32|lab|device|dc1-core1|2026-01-01 10:00\n"; got != want {
		t.Errorf("the line spelled with upper case: %q, want %q", got, want)
	}
}

// A line that cannot be saved is a warning that names every address it
// concerns, the dropped stray included, never an empty list; the rename
// stands.
func TestDeviceRenameStagingWarnsWithTheAddresses(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.run("", []string{"scope", "prefixes", "lab", "add", "192.0.2.80/32,192.0.2.81/32"})
	sb.expect(0, "", "")
	// only a stray of the new name: nothing to carry, one line to drop (a line
	// of another device stays, so the file is written, not removed)
	sb.write("state/staging", "192.0.2.80/32|lab|device|dc1-core1|2020-01-01 10:00\n192.0.2.81/32|lab|device|other|2026-01-01 10:00\n", 0o600)
	if err := os.Mkdir(sb.path("state", "staging.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.dev("", "rename", "core-sw1", "dc1-core1")
	sb.expect(0, "renamed to 'dc1-core1'", "")
	if w := sb.printed(); !strings.Contains(w, "dc1-core1: its staging lines still name 'core-sw1' or an earlier device of that name (192.0.2.80)") || strings.Contains(w, "()") {
		t.Errorf("warning:\n%s", w)
	}
	if !strings.Contains(sb.devices(), "dc1-core1:") {
		t.Error("the rename did not stand")
	}
}
