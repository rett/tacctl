package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// cfgSNMP runs 'config snmp ...'.
func (sb *sandbox) cfgSNMP(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"config", "snmp"}, args...), nil))
}

const poolPass = "pool-auth-pass\npool-priv-pass\n"

// A device uses its own default user, else its scope's, else the config's,
// and may be told to use a user of its scope's pool or the config's. A name
// stands for one user across the pools it can see, a user a device chose
// cannot be removed, and a chosen user that is gone is an error that names
// the fix, never another user.
func TestSNMPPoolAcrossTheLevels(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.cfgSNMP(poolPass, "v3-user", "add", "alice", "--default", "--stdin")
	sb.cfgSNMP("", "version", "v3")
	sb.scopeSNMP(poolPass, "lab", "v3-user", "add", "carol", "--stdin")

	user := func() string {
		out := sb.devSNMP("", "lab-sw1")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "v3 user:") {
				return strings.Join(strings.Fields(l)[2:], " ")
			}
		}
		t.Fatalf("no v3 user line:\n%s", out)
		return ""
	}
	// No default in the scope or the device: the config's.
	if got := user(); got != "alice (default)" {
		t.Errorf("config default: %q", got)
	}
	// The scope's default wins over the config's.
	sb.scopeSNMP("", "lab", "v3-user", "default", "carol")
	if got := user(); got != "carol (scope lab)" {
		t.Errorf("scope default: %q", got)
	}
	// The device is told to use the config's user, then its own.
	sb.devSNMP("", "lab-sw1", "v3-user", "default", "alice")
	sb.said(0, "SNMPv3 user 'alice' (a user of the config) is the default of device 'lab-sw1'")
	if got := user(); got != "alice (default)" {
		t.Errorf("device told to use the config's: %q", got)
	}
	sb.devSNMP(poolPass, "lab-sw1", "v3-user", "add", "dave", "--default", "--stdin")
	if got := user(); got != "dave (device)" {
		t.Errorf("device's own: %q", got)
	}
	sb.devSNMP("", "lab-sw1", "v3-user", "default", "carol")
	if got := user(); got != "carol (scope lab)" {
		t.Errorf("device told to use its scope's: %q", got)
	}
	if out := sb.devSNMP("", "lab-sw1", "v3-user", "list"); !strings.Contains(out, "dave") || !strings.Contains(out, "may also use: carol (scope 'lab')") ||
		!strings.Contains(out, "may also use: alice (the config)") || !strings.Contains(out, "default: carol (a user of another level's pool)") || strings.Contains(out, "pool-auth-pass") {
		t.Errorf("list:\n%s", out)
	}
	// The JSON: the device's own pool and default, the effective user apart.
	var js struct {
		SNMP struct {
			User    string   `json:"v3_user"`
			Users   []string `json:"v3_users"`
			Default string   `json:"v3_default"`
		} `json:"snmp"`
	}
	if err := json.Unmarshal([]byte(sb.dev("", "show", "lab-sw1", "--json")), &js); err != nil {
		t.Fatal(err)
	}
	if js.SNMP.User != "carol" || strings.Join(js.SNMP.Users, ",") != "dave" || js.SNMP.Default != "carol" {
		t.Errorf("json: %+v", js.SNMP)
	}

	// Names are unique across the pools that can see each other.
	for _, c := range []struct {
		run  func(string, ...string) string
		args []string
		want string
	}{
		{sb.cfgSNMP, []string{"v3-user", "add", "carol", "--stdin"}, "The SNMPv3 user 'carol' is in the pool of scope 'lab' already"},
		{sb.cfgSNMP, []string{"v3-user", "add", "dave", "--stdin"}, "The SNMPv3 user 'dave' is in the pool of device 'lab-sw1' already"},
		{func(in string, a ...string) string { return sb.scopeSNMP(in, append([]string{"lab"}, a...)...) }, []string{"v3-user", "add", "alice", "--stdin"}, "The SNMPv3 user 'alice' is in the pool of the config already"},
		{func(in string, a ...string) string { return sb.scopeSNMP(in, append([]string{"lab"}, a...)...) }, []string{"v3-user", "add", "dave", "--stdin"}, "The SNMPv3 user 'dave' is in the pool of device 'lab-sw1' already"},
		{func(in string, a ...string) string { return sb.devSNMP(in, append([]string{"lab-sw1"}, a...)...) }, []string{"v3-user", "add", "carol", "--stdin"}, "The SNMPv3 user 'carol' is in the pool of scope 'lab' already"},
		{func(in string, a ...string) string { return sb.devSNMP(in, append([]string{"lab-sw1"}, a...)...) }, []string{"v3-user", "add", "alice", "--stdin"}, "The SNMPv3 user 'alice' is in the pool of the config already"},
	} {
		c.run(poolPass, c.args...)
		sb.expect(1, "", c.want)
	}
	// A device cannot choose a user nobody holds.
	sb.devSNMP("", "lab-sw1", "v3-user", "default", "nobody")
	sb.expect(1, "", "No SNMPv3 user 'nobody' to choose for device 'lab-sw1'")

	// The scope's user is chosen by the device: removing it is refused,
	// naming the device and the command.
	sb.scopeSNMP("", "lab", "v3-user", "remove", "carol")
	sb.expect(1, "", "The SNMPv3 user 'carol' is the default of device 'lab-sw1'")
	sb.cfgSNMP("", "v3-user", "remove", "alice")
	sb.expect(0, "", "")
	// (the config's user was chosen by nobody now: the device chose the scope's)

	// A pool that goes anyway (clear) leaves the choice dangling: an error
	// that names the fix, not the next default.
	sb.scopeSNMP("", "lab", "clear")
	sb.said(0, "These devices choose a user of scope 'lab'")
	sb.cfgSNMP("", "test", "lab-sw1")
	sb.expect(1, "", "Cannot test: the SNMPv3 user 'carol', the default of device lab-sw1, is in no pool it may use (device lab-sw1, scope lab, the config); "+
		"'tacctl device snmp lab-sw1 v3-user add carol' adds it, 'tacctl device snmp lab-sw1 v3-user default <user>' chooses another")
	sb.devSNMP("", "lab-sw1", "v3-user", "default", "--none")
	sb.devSNMP("", "lab-sw1", "v3-user", "remove", "dave")
	if _, err := os.Stat(sb.path("state", "snmp", "devices", "lab-sw1.yaml")); !os.IsNotExist(err) {
		t.Errorf("the device's file is left with nothing in it: %v", err)
	}
}

// Adding a user sets no version; a device that has a pool file and no snmp
// map reads with it (a version 2 file counts without the map that version 1
// needed), and the file the older form left stays ignored.
func TestSNMPPoolFileOfADeviceNeedsNoMap(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	file := "state/snmp/devices/lab-sw1.yaml"
	sb.devSNMP(poolPass, "lab-sw1", "v3-user", "add", "dave", "--default", "--stdin")
	if strings.Contains(sb.devices(), "snmp:") {
		t.Errorf("adding a user wrote a map:\n%s", sb.devices())
	}
	if out := sb.devSNMP("", "lab-sw1", "show"); !strings.Contains(out, "v3 user:    dave  (device)") || strings.Contains(out, "Note:") {
		t.Errorf("show:\n%s", out)
	}
	if got := sb.read(file); !strings.Contains(got, "version: 2") || !strings.Contains(got, "default: dave") {
		t.Errorf("file:\n%s", got)
	}
	// Another setting does not call the file ignored.
	sb.devSNMP("", "lab-sw1", "port", "1161")
	if strings.Contains(sb.stderr()+sb.plainOut(), "ignored") {
		t.Errorf("port: %q %q", sb.stderr(), sb.plainOut())
	}
	// A file of the older form with no map is ignored, as before.
	sb.devSNMP("", "lab-sw1", "clear")
	sb.write(file, "version: 1\nv3: {user: olduser, auth_passphrase: old-auth-pass, priv_passphrase: old-priv-pass}\n", 0o600)
	if out := sb.devSNMP("", "lab-sw1", "show"); !strings.Contains(out, "Note:") || strings.Contains(out, "olduser") {
		t.Errorf("a version 1 file with no map:\n%s", out)
	}
	// With a map it is a pool of one user that is the default.
	sb.devSNMP("", "lab-sw1", "version", "v3")
	if out := sb.devSNMP("", "lab-sw1", "show"); !strings.Contains(out, "v3 user:    olduser  (device)") {
		t.Errorf("a version 1 file with a map:\n%s", out)
	}
	if !strings.Contains(sb.read(file), "version: 1") {
		t.Error("reading rewrote the file")
	}
	// Adding a user writes it as version 2, the old user kept as the default.
	sb.devSNMP(poolPass, "lab-sw1", "v3-user", "add", "second", "--stdin")
	got := sb.read(file)
	if !strings.Contains(got, "version: 2") || !strings.Contains(got, "olduser") || !strings.Contains(got, "default: olduser") {
		t.Errorf("after an add:\n%s", got)
	}
}

// 'config snmp version' shows and sets the version; adding a user does not.
func TestConfigSNMPVersionVerb(t *testing.T) {
	sb := newSandbox(t, true)
	if out := sb.cfgSNMP("", "version"); !strings.Contains(out, "not set") {
		t.Errorf("version: %q", out)
	}
	sb.cfgSNMP(poolPass, "v3-user", "add", "alice", "--stdin")
	sb.said(0, "The SNMP version of the config is not set")
	if out := sb.cfgSNMP("", "version"); !strings.Contains(out, "not set") {
		t.Errorf("adding a user set the version: %q", out)
	}
	sb.cfgSNMP("", "version", "v3")
	sb.said(0, "Not usable yet: no SNMPv3 user is the default")
	sb.cfgSNMP("", "version", "v1")
	sb.expect(1, "", "Unknown version 'v1': v2c or v3.")
	sb.cfgSNMP("", "v3-user", "default", "alice")
	if out := sb.cfgSNMP("", "v3-user", "default"); strings.TrimSpace(out) != "alice" {
		t.Errorf("default: %q", out)
	}
	sb.cfgSNMP("", "v3-user", "default", "alice", "--none")
	sb.expect(1, "", "Give a user or --none, not both.")
	sb.cfgSNMP("", "v3-user", "remove", "alice")
	sb.said(0, "the config has no default user now")
	sb.cfgSNMP("", "v3-user", "list")
	sb.said(0, "none (tacctl config snmp v3-user add <user>)")
}

// A version 1 file is read as a pool of one default user and rewritten as
// version 2 only by a change.
func TestSNMPPoolReadsVersionOneFiles(t *testing.T) {
	sb := newSandbox(t, true)
	old := "version: 1\ncommunity: public-ish\nv3: {user: alice, auth_passphrase: auth-pass-1, priv_passphrase: priv-pass-1}\n"
	sb.write("state/snmp.yaml", old, 0o600)
	out := sb.cfgSNMP("", "v3-user", "list")
	if !strings.Contains(out, "alice  default  (passphrases set)") {
		t.Errorf("list:\n%s", out)
	}
	if sb.read("state/snmp.yaml") != old {
		t.Error("a read rewrote the file")
	}
	sb.cfgSNMP(poolPass, "v3-user", "add", "bob", "--stdin")
	got := sb.read("state/snmp.yaml")
	if !strings.Contains(got, "version: 2") || !strings.Contains(got, "default: alice") || !strings.Contains(got, "public-ish") || !strings.Contains(got, "bob") {
		t.Errorf("after the add:\n%s", got)
	}
}

// An engineer reveals the passphrases of a user of the level's own pool or
// of the user in force, never another user of the config's pool (it belongs to
// every scope): a refusal that says what a missing user is told. The
// superuser reveals any user of the pools the level sees. A default is not
// the engineer's to change.
func TestSNMPRevealOfOneUserIsLimitedForAnEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	pw := "pool-auth-pass\npool-priv-pass\n"
	sb.cfgSNMP(pw, "v3-user", "add", "alice", "--default", "--stdin")
	sb.cfgSNMP(pw, "v3-user", "add", "erin", "--stdin")
	sb.scopeSNMP(pw, "lab", "v3-user", "add", "carol", "--default", "--stdin")
	sb.devSNMP(pw, "lab-sw", "v3-user", "add", "dave", "--stdin")
	logged := func() int {
		n := 0
		for _, c := range auditCalls(sb.runner) {
			if strings.Contains(c.Line, "secret-read") && strings.Contains(c.Line, "user=erin") {
				n++
			}
		}
		return n
	}
	for _, args := range [][]string{{"scope", "snmp", "lab", "show", "--reveal", "erin"}, {"device", "snmp", "lab-sw", "show", "--reveal", "erin"},
		{"device", "snmp", "lab-sw", "show", "--reveal", "alice"}} {
		out := sb.asEngineer("", args...)
		if sb.code != 1 || strings.Contains(out, "pool-auth-pass") || !strings.Contains(sb.stderr(), "that you may read. Nothing was printed.") {
			t.Errorf("%v: %d %q %q", args, sb.code, out, sb.stderr())
		}
	}
	if logged() != 0 {
		t.Error("a refused reveal was logged")
	}
	// What an engineer may read: the level's own user, the user in force.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"scope", "snmp", "lab", "show", "--reveal", "carol"}, "auth pool-auth-pass"},
		{[]string{"device", "snmp", "lab-sw", "show", "--reveal", "dave"}, "auth pool-auth-pass"},
		// carol, the scope's default, is the user in force for lab-sw
		{[]string{"device", "snmp", "lab-sw", "show", "--reveal", "carol"}, "auth pool-auth-pass"},
	} {
		out := sb.asEngineer("", c.args...)
		if sb.code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%v: %d %q %q", c.args, sb.code, out, sb.stderr())
		}
	}
	// The superuser reads the config's other user through the scope or the device.
	out := sb.scopeSNMP("", "lab", "show", "--reveal", "erin")
	if sb.code != 0 || !strings.Contains(out, "auth pool-auth-pass") || logged() != 1 {
		t.Errorf("superuser: %d %q (logged %d)", sb.code, out, logged())
	}
	// A default is the superuser's.
	for _, args := range [][]string{{"scope", "snmp", "lab", "v3-user", "default", "--none"}, {"device", "snmp", "lab-sw", "v3-user", "default", "carol"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if out := sb.asEngineer("", "scope", "snmp", "lab", "v3-user", "default"); sb.code != 0 || strings.TrimSpace(out) != "carol" {
		t.Errorf("an engineer reads the default: %d %q", sb.code, out)
	}
}

// Below the engineer tier an error about the user a device chose does not name
// it: device check says that a chosen user cannot be used, as device show does.
func TestSNMPChosenUserErrorIsNotNamedBelowTheEngineer(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "127.0.0.1", "--no-host-key", "--no-lookup")
	sb.write("state/store.yaml", strings.Replace(sb.store(), "prefixes: [172.16.0.0/12, 192.168.0.0/16]", "prefixes: [172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8]", 1), 0o600)
	sb.cfgSNMP("", "version", "v3")
	sb.cfgSNMP("", "timeout", "1")
	sb.devSNMP(poolPass, "lab-sw1", "v3-user", "add", "dave", "--default", "--stdin")
	// the user the device chose is gone from the file by hand
	sb.write("state/snmp/devices/lab-sw1.yaml", strings.Replace(sb.read("state/snmp/devices/lab-sw1.yaml"), "default: dave", "default: carol", 1), 0o600)
	ops := plain(sb.cfgRun("", []string{"device", "check", "lab-sw1"}, idAs("bob", "tac-users"), "SUDO_USER=bob"))
	if strings.Contains(ops, "carol") || !strings.Contains(ops, "an SNMPv3 user is chosen that cannot be used") {
		t.Errorf("operator device check:\n%s", ops)
	}
	su := sb.dev("", "check", "lab-sw1")
	if !strings.Contains(su, "the SNMPv3 user 'carol', the default of device lab-sw1, is in no pool it may use") {
		t.Errorf("superuser device check:\n%s", su)
	}
}

// config validate warns of a user name two pools a device can see hold, under
// the scopes as they are now, and names the levels, never the user.
func TestConfigValidateWarnsOfASharedSNMPUserName(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.cfgSNMP(poolPass, "v3-user", "add", "alice", "--stdin")
	sb.devSNMP(poolPass, "lab-sw1", "v3-user", "add", "bob", "--stdin")
	if out := sb.run("", []string{"config", "validate"}); strings.Contains(out, "SNMPv3 users:") {
		t.Errorf("a clean state warns:\n%s", out)
	}
	// A file put in by hand (the verbs refuse the name) gives the device the config's name.
	dev := strings.Replace(sb.read("state/snmp/devices/lab-sw1.yaml"), "name: bob", "name: alice", 1)
	if dev == sb.read("state/snmp/devices/lab-sw1.yaml") {
		t.Fatalf("the device file has no bob:\n%s", dev)
	}
	sb.write("state/snmp/devices/lab-sw1.yaml", dev, 0o600)
	out := sb.run("", []string{"config", "validate"})
	if !strings.Contains(out, "SNMPv3 users:") || !strings.Contains(out, "device 'lab-sw1' and the config hold an SNMPv3 user of the same name; the device's pool is searched first (tacctl device snmp lab-sw1 v3-user list)") ||
		strings.Contains(out, "alice") {
		t.Errorf("config validate:\n%s", out)
	}
	js := sb.run("", []string{"config", "validate", "--json"})
	if !strings.Contains(js, `"section": "snmp_users"`) || !strings.Contains(js, `"level": "warning"`) {
		t.Errorf("config validate --json:\n%s", js)
	}
}
