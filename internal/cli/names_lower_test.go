package cli

// New device, host, user and scope names are lower case; names from before
// keep working, are listed by 'config validate' and are fixed by a rename
// that changes only the spelling (docs/plans/0.2.14-plan.md D203, D204).

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// legacyHostCase rewrites the spelling of the enrolled host from, in every
// piece of state the host has, to to: the state of a host enrolled before new
// names were lower case. The registry line, the pin, the record, the staging
// addresses and the hold are renamed in place.
func (sb *sandbox) legacyHostCase(from, to string) {
	sb.t.Helper()
	replace := func(rel, old, new string) {
		sb.t.Helper()
		p := sb.path(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(b), old, new)), 0o600); err != nil {
			sb.t.Fatal(err)
		}
	}
	replace("state/linux-hosts", from+"|", to+"|")
	replace("state/devices.yaml", "  "+from+":", "  "+to+":")
	replace("state/tacctl.yaml", "  "+from+":\n    address", "  "+to+":\n    address")
	replace("state/staging", "|host|"+from+"|", "|host|"+to+"|")
	if err := os.Rename(sb.path("state/hosts", from+".json"), sb.path("state/hosts", to+".json")); err != nil && !os.IsNotExist(err) {
		sb.t.Fatal(err)
	}
}

// legacyStoreCase rewrites the spelling of a user or a scope in the store
// (and in the scope lists of the users), the way the store of an earlier
// release has it.
func (sb *sandbox) legacyStoreCase(from, to string) {
	sb.t.Helper()
	sb.write("state/store.yaml", strings.ReplaceAll(sb.store(), from, to), 0o600)
}

// A user, a scope, a device and a host are created lower case; a name with
// upper case is refused with its lower-case spelling, and nothing changes.
func TestNewUserAndScopeNamesAreLowerCase(t *testing.T) {
	sb := newSandbox(t, true)
	before := sb.store()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"user", "add", "Eve", "operator", "--scopes", "lab", "--hash", testHash}, "Names are lower case: use 'eve'. Nothing was changed."},
		{[]string{"user", "rename", "bob", "Bobby"}, "Names are lower case: use 'bobby'. Nothing was changed."},
		{[]string{"user", "rename", "bob", "BOB"}, "Names are lower case: use 'bob'. Nothing was changed."},
		{[]string{"scope", "add", "Staging", "--prefixes", "10.50.0.0/16", "--secret", "generate"}, "Names are lower case: use 'staging'. Nothing was changed."},
		{[]string{"scope", "rename", "dmz", "Edge"}, "Names are lower case: use 'edge'. Nothing was changed."},
		{[]string{"scope", "rename", "lab", "LAB"}, "Names are lower case: use 'lab'. Nothing was changed."},
	} {
		sb.run("", c.args)
		sb.expect(1, "", c.want)
		if sb.store() != before {
			t.Errorf("%v changed the store", c.args)
		}
	}
	// The lower-case spelling is accepted.
	sb.run("", []string{"user", "add", "eve", "operator", "--scopes", "lab", "--hash", testHash})
	sb.expect(0, "User 'eve' added", "")
	sb.run("", []string{"user", "rename", "eve", "eve2"})
	sb.expect(0, "User renamed: eve -> eve2", "")
	sb.run("", []string{"scope", "add", "staging", "--prefixes", "10.50.0.0/16", "--secret", "generate"})
	sb.expect(0, "", "")
	sb.run("", []string{"scope", "rename", "staging", "staging2"})
	sb.expect(0, "Scope renamed: staging -> staging2", "")
}

// A user from before keeps working with its name as it is, and the rename
// that changes only the spelling fixes it: the scope lists, the password and
// the group follow. The Linux UID is kept by name: the renamed user has none
// until a host is synced, and the old number stays reserved.
func TestUserWithUpperCaseKeepsWorkingAndIsRenamedToLowerCase(t *testing.T) {
	sb := newSandbox(t, true)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb.legacyStoreCase("  alice:", "  Alice:")
	sb.write("state/linux-uids", "Alice:80001\n", 0o600)
	sb.run("", []string{"user", "passwd", "Alice", "--hash", h})
	sb.expect(0, "Password changed for 'Alice'.", "")
	sb.run("CorrectHorse99\n", []string{"user", "verify", "Alice"})
	sb.expect(0, "Password is correct.", "")
	sb.run("", []string{"user", "show", "Alice"})
	sb.expect(0, "Alice", "")
	// Devices match the typed login exactly: 'alice' is not 'Alice'.
	sb.run("", []string{"user", "show", "alice"})
	sb.expect(1, "", "User 'alice' does not exist.")
	sb.run("", []string{"user", "disable", "Alice"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "enable", "Alice"})
	sb.expect(0, "", "")

	sb.run("", []string{"user", "rename", "Alice", "alice"})
	sb.expect(0, "User renamed: Alice -> alice", "")
	st := sb.store()
	if strings.Contains(st, "Alice") || !strings.Contains(st, "  alice:\n    group: superuser\n    scopes: [prod, lab]\n") || !strings.Contains(st, "hash: "+h) {
		t.Errorf("the store after the rename:\n%s", st)
	}
	sb.run("CorrectHorse99\n", []string{"user", "verify", "alice"})
	sb.expect(0, "Password is correct.", "")
	// The ledger is keyed by name and left alone.
	sb.run("", []string{"config", "linux", "uid", "alice"})
	sb.expect(1, "", "No UID assigned to 'alice' yet.")
	if !strings.Contains(sb.read("state/linux-uids"), "Alice:80001\n") || strings.Contains(sb.read("state/linux-uids"), "alice:") {
		t.Errorf("the ledger: %q", sb.read("state/linux-uids"))
	}
	// Renaming it to a name that exists in another case is refused by the
	// existing-name check.
	sb.legacyStoreCase("  carol:", "  Carol:")
	sb.run("", []string{"user", "add", "carol", "readonly", "--hash", testHash})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "rename", "Carol", "carol"})
	sb.expect(1, "", "User 'carol' already exists.")
}

// A scope from before, with upper case, is found as it is and its rename to
// lower case carries the users' scope lists, the keys of tacctl.yaml, the
// SNMP credentials file and the default marker.
func TestScopeWithUpperCaseIsRenamedToLowerCase(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{
		{"scope", "aaa-order", "dmz", "local-first"},
		{"scope", "exec-timeout", "dmz", "15"},
		{"scope", "default", "dmz"},
	} {
		sb.run("", args)
		sb.expect(0, "", "")
	}
	sb.scopeSNMP("dmz-comm\n", "dmz", "community", "--stdin")
	sb.legacyStoreCase("  dmz:", "  Dmz:")
	sb.legacyStoreCase(", dmz]", ", Dmz]")
	sb.write("state/tacctl.yaml", strings.ReplaceAll(sb.overrides(), "dmz", "Dmz"), 0o600)
	if err := os.Rename(sb.path("state/snmp/dmz.yaml"), sb.path("state/snmp/Dmz.yaml")); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"scope", "show", "Dmz"})
	sb.expect(0, "Dmz", "")
	sb.run("", []string{"scope", "show", "dmz"})
	sb.expect(1, "", "does not exist")

	sb.run("", []string{"scope", "rename", "Dmz", "dmz"})
	sb.expect(0, "Scope renamed: Dmz -> dmz (1 user(s) updated).", "")
	if st := sb.store(); strings.Contains(st, "Dmz") || !strings.Contains(st, "scopes: [lab, dmz]") || !strings.Contains(st, "\n  dmz:\n    prefixes: [203.0.113.0/24]") {
		t.Errorf("the store after the rename:\n%s", st)
	}
	o := sb.overrides()
	if strings.Contains(o, "Dmz") || !strings.Contains(o, "aaa:\n  order:\n    dmz: local-first") {
		t.Errorf("tacctl.yaml after the rename:\n%s", o)
	}
	if _, err := os.Stat(sb.path("state/snmp/dmz.yaml")); err != nil {
		t.Errorf("the credentials did not follow: %v", err)
	}
	if _, err := os.Stat(sb.path("state/snmp/Dmz.yaml")); !os.IsNotExist(err) {
		t.Errorf("the old credentials are left: %v", err)
	}
	sb.run("", []string{"scope", "default"})
	sb.expect(0, "Default scope: dmz", "")
}

// A device from before keeps its name; 'config validate' lists it with the
// verb that renames it; new devices are lower case in every path.
func TestNewDeviceNamesAreLowerCase(t *testing.T) {
	sb := newSandbox(t, true)
	before := sb.devices()
	sb.dev("", "add", "Core-SW1", "10.99.0.1", "--no-host-key", "--no-lookup")
	sb.expect(1, "", "Names are lower case: use 'core-sw1'. Nothing was changed.")
	sb.dev("Edge-FW,10.99.0.2,cisco\n", "import", "-")
	sb.expect(1, "", "Names are lower case: use 'edge-fw'.")
	if sb.devices() != before {
		t.Errorf("a refused name changed the registry:\n%s", sb.devices())
	}
	sb.dev("edge-fw,10.99.0.2,cisco\n", "import", "-")
	sb.expect(0, "Imported: 1 added", "")
	if strings.Contains(sb.out.String(), "upper case") {
		t.Errorf("a note without a mixed-case name: %q", sb.out.String())
	}
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
}

// A registry file is existing data: a device with upper case in it loads as
// it is, and the import says how many.
func TestDeviceImportOfAFileWithUpperCaseLoadsItAsItIs(t *testing.T) {
	sb := newSandbox(t, true)
	const file = "version: 1\ndevices:\n  Core-SW1:\n    address: 10.99.0.1\n    vendor: cisco\n  edge-fw:\n    address: 10.99.0.2\n    vendor: cisco\n"
	sb.dev(file, "import", "-", "--check")
	sb.expect(0, "Would import: 2 added", "")
	sb.expect(0, "1 device name(s) have upper case and are loaded as they are", "")
	sb.dev(file, "import", "-")
	sb.expect(0, "Imported: 2 added", "")
	sb.expect(0, "1 device name(s) have upper case and are loaded as they are", "")
	if !strings.Contains(sb.devices(), "  Core-SW1: ") {
		t.Errorf("the name was changed:\n%s", sb.devices())
	}
	// It is found by name, in any case, and shown as registered.
	sb.dev("", "show", "core-sw1")
	sb.expect(0, "Core-SW1", "")
	// A CSV row for it updates it; a CSV row for a new name is lower case.
	sb.dev("Core-SW1,10.99.0.1,cisco,,core\n", "import", "-")
	sb.expect(0, "1 updated", "")
	sb.expect(0, "1 device name(s) have upper case", "")
	// And the rename to lower case is how it is fixed.
	sb.dev("", "rename", "Core-SW1", "core-sw1")
	sb.expect(0, "renamed to 'core-sw1'", "")
	if strings.Contains(sb.devices(), "Core-SW1") {
		t.Errorf("the name was kept:\n%s", sb.devices())
	}
}

// Names with upper case are listed by 'config validate', each with the verb
// that renames it; the warning for a user says what the rename changes; an
// engineer is told nothing.
func TestConfigValidateListsNamesWithUpperCase(t *testing.T) {
	hs := newHostSandbox(t)
	hs.legacyStoreCase("  bob:", "  Bob:")
	hs.legacyStoreCase("  prod-inner:", "  Prod-Inner:")
	hs.write("state/linux-hosts", "Web1|root@192.168.1.10||lab|192.0.2.1|\nweb2|root@192.168.1.11||lab|192.0.2.1|\n", 0o600)
	hs.write("state/devices.yaml", "version: 1\ndevices:\n  Core-SW1:\n    address: 10.99.0.1\n    vendor: cisco\n  core-sw2:\n    address: 10.99.0.2\n    vendor: cisco\n", 0o600)
	out := plain(hs.run(nil, "config", "validate") + hs.err.String())
	for _, want := range []string{
		"Names:",
		"the user 'Bob' has upper case in its name; new names are lower case; devices match the typed login name exactly, so the rename changes what the person types at the device (tacctl user rename Bob bob)",
		"the scope 'Prod-Inner' has upper case in its name; new names are lower case (tacctl scope rename Prod-Inner prod-inner)",
		"the device 'Core-SW1' has upper case in its name; new names are lower case (tacctl device rename Core-SW1 core-sw1)",
		"the host 'Web1' has upper case in its name; new names are lower case (tacctl host rename Web1 web1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config validate lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "core-sw2' has upper") || strings.Contains(out, "'web2' has upper") {
		t.Errorf("a lower-case name was listed:\n%s", out)
	}
	// A lower-case spelling that another name has is not proposed.
	hs.legacyStoreCase("  carol:", "  Carol:")
	hs.run(nil, "user", "add", "carol", "readonly", "--hash", testHash)
	out = plain(hs.run(nil, "config", "validate") + hs.err.String())
	if !strings.Contains(out, "(tacctl user rename Carol <new>)") {
		t.Errorf("the taken spelling:\n%s", out)
	}
	// Nothing is listed when every name is lower case.
	clean := newHostSandbox(t)
	if out := plain(clean.run(nil, "config", "validate") + clean.err.String()); strings.Contains(out, "has upper case") {
		t.Errorf("a finding without a name:\n%s", out)
	}
}

// A host name worked out from a host name is lowercased (host names are not
// case-sensitive); one given with --name is refused with upper case; a host
// enrolled before under a name with upper case is enrolled again as it is.
func TestHostEnrollNamesAreLowerCase(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.runner()
	hs.run(r, "host", "enroll", "WEB5.example.net", "--scope", "lab")
	hs.expect(0, "Host 'web5' enrolled.", "")
	if !strings.HasPrefix(hs.registry(), "web5|") {
		t.Errorf("registry %q", hs.registry())
	}

	before := hs.registry()
	r = hs.runner()
	hs.run(r, "host", "enroll", "web6.example.net", "--name", "Web6", "--scope", "lab")
	hs.expect(1, "", "Names are lower case: use 'web6'. Nothing was changed.")
	if r.Called("ssh") || hs.registry() != before {
		t.Errorf("ssh %v, registry %q", r.Called("ssh"), hs.registry())
	}

	// A name from before: the host is enrolled again under its registered
	// spelling, derived from the host name or given.
	hs.write("state/linux-hosts", "Web7|root@Web7.example.net||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "enroll", "Web7.example.net", "--scope", "lab")
	hs.expect(0, "Host 'Web7' enrolled.", "")
	hs.run(nil, "host", "enroll", "web7.example.net", "--name", "Web7", "--scope", "lab")
	hs.expect(0, "Host 'Web7' enrolled.", "")
}

// 'host rename' to a name with upper case is refused, to the lower-case
// spelling of the host's own name is allowed (TestHostRenameSpellingOnly).
func TestHostRenameToUpperCaseIsRefused(t *testing.T) {
	sb := renameLab(t)
	before := sb.renameState()
	sb.run("", []string{"host", "rename", "web1", "Web9"})
	sb.expect(1, "", "Names are lower case: use 'web9'. Nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
}

// The findings are the superuser's: an engineer's view names none.
func TestEngineerIsToldNothingOfNamesWithUpperCase(t *testing.T) {
	sb := engineerSandbox(t)
	sb.legacyStoreCase("  carol:", "  Carol:")
	if out := sb.run("", []string{"config", "validate"}); !strings.Contains(plain(out+sb.err.String()), "has upper case") {
		t.Fatalf("the superuser's view lacks the finding:\n%s\n%s", out, sb.err.String())
	}
	got := sb.asEngineer("", "config", "validate") + plain(sb.err.String())
	if strings.Contains(got, "has upper case") || strings.Contains(got, "Carol") {
		t.Errorf("an engineer was told:\n%s", got)
	}
}
