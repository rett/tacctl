package cli

import (
	"strings"
	"testing"
)

// A community and one v3 user that is the default are saved in version 1:
// the real 0.2.22 and 0.2.21 read them with no rollback, and a rollback of
// such a state converts nothing (no step, no snapshot, no --yes). A second
// user is what version 1 cannot hold: the older release refuses the file
// until the rollback writes it in version 1 again.
func TestSNMPVersionOneWhenItFitsRealOldBinaries(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		flag *string
	}{{"0.2.22", old0222Flag}, {"0.2.21", old0221Flag}} {
		t.Run(tc.tag, func(t *testing.T) {
			bin := oldBinaryOf(t, tc.tag, tc.flag)
			hs := rollback0221State(t)
			pw := "pool-auth-pass\npool-priv-pass\n"
			hs.step("default-community-1\n", "config", "snmp", "community", "--stdin")
			hs.step(pw, "config", "snmp", "v3-user", "add", "alice", "--default", "--stdin")
			hs.step(pw, "scope", "snmp", "lab", "v3-user", "add", "carol", "--default", "--stdin")
			hs.step(pw, "device", "snmp", "sw1", "v3-user", "add", "dave", "--default", "--stdin")
			run := oldRunner(t, hs, bin)
			for _, args := range [][]string{{"config", "snmp", "show"}, {"scope", "snmp", "lab", "show"}, {"device", "snmp", "sw1", "show"}} {
				if out, code := run(args...); code != 0 || strings.Contains(out, "unsupported version") {
					t.Errorf("%s %v with no rollback: %d\n%s", tc.tag, args, code, out)
				}
			}
			if out, code := run("config", "snmp", "show", "--reveal"); code != 0 || !strings.Contains(out, "v3 user:    alice; auth passphrase: pool-auth-pass") || !strings.Contains(out, "community:  default-community-1") {
				t.Errorf("%s config snmp show --reveal: %d\n%s", tc.tag, code, out)
			}
			for _, f := range []string{"state/snmp.yaml", "state/snmp/lab.yaml", "state/snmp/devices/sw1.yaml"} {
				if got := hs.read(f); !strings.Contains(got, "version: 1") {
					t.Errorf("%s is not version 1:\n%s", f, got)
				}
			}
			// Nothing to convert: no step, no snapshot, no --yes, no file changes.
			hs.run(hs.runner(), "rollback", tc.tag)
			hs.expect(0, "This was a dry run", "")
			if strings.Contains(hs.all(), "credential files") || strings.Contains(hs.all(), "SNMPv3 users are dropped") {
				t.Errorf("the dry run converts SNMP files:\n%s", hs.all())
			}
			before, snaps := tree(t, hs.dir), hs.snapshots()
			hs.run(hs.runner(), "rollback", tc.tag, "--apply")
			hs.expect(0, "Nothing to convert", "")
			if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 || hs.snapshots() != snaps {
				t.Errorf("the rollback changed %q (snapshots %d, was %d)", got, hs.snapshots(), snaps)
			}

			// A second user: version 2, which the older release refuses.
			hs.step(pw, "config", "snmp", "v3-user", "add", "bob", "--stdin")
			if got := hs.read("state/snmp.yaml"); !strings.Contains(got, "version: 2") {
				t.Fatalf("snmp.yaml is not version 2:\n%s", got)
			}
			if out, code := run("config", "snmp", "show"); code == 0 || !strings.Contains(out, "unsupported version") {
				t.Errorf("%s config snmp show with two users: %d\n%s", tc.tag, code, out)
			}
			hs.run(hs.runner(), "rollback", tc.tag, "--apply", "--yes")
			hs.expect(0, "Applying.", "")
			if out, code := run("config", "snmp", "show", "--reveal"); code != 0 || !strings.Contains(out, "v3 user:    alice; auth passphrase: pool-auth-pass") {
				t.Errorf("%s config snmp show after the rollback: %d\n%s", tc.tag, code, out)
			}
		})
	}
}

// userInForce is the v3 user line of 'device snmp show' (the name and where it
// comes from).
func userInForce(sb *sandbox, device string) string {
	for _, l := range strings.Split(sb.devSNMP("", device, "show"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "v3 user:") {
			return strings.Join(strings.Fields(l)[2:], " ")
		}
	}
	return ""
}

// A device's own user is never replaced by another level's when its entry
// comes and goes (the file follows the entry, snmpReconcile): the user is saved
// in version 1 beside an entry made by a client range, and when the last range
// is removed the file becomes version 2, which counts without an entry, so the
// device keeps its own user and does not fall back to the config's.
func TestSNMPDeviceUserSurvivesTheEntryBeingEmptied(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	pw := "pool-auth-pass\npool-priv-pass\n"
	sb.cfgSNMP(pw, "v3-user", "add", "alice", "--default", "--stdin")
	sb.cfgSNMP("", "version", "v3")
	file := "state/snmp/devices/lab-sw1.yaml"
	sb.devSNMP("", "lab-sw1", "clients", "add", "198.51.100.0/24")
	sb.devSNMP(pw, "lab-sw1", "v3-user", "add", "bob", "--default", "--stdin")
	if got := sb.read(file); !strings.Contains(got, "version: 1") {
		t.Fatalf("a default user beside an entry is not version 1:\n%s", got)
	}
	if got := userInForce(sb, "lab-sw1"); got != "bob (device)" {
		t.Fatalf("before: %q", got)
	}
	sb.devSNMP("", "lab-sw1", "clients", "remove", "198.51.100.0/24")
	if strings.Contains(sb.devices(), "snmp:") {
		t.Fatalf("the entry is still there:\n%s", sb.devices())
	}
	if got := sb.read(file); !strings.Contains(got, "version: 2") {
		t.Errorf("the file is not version 2 without an entry:\n%s", got)
	}
	if got := userInForce(sb, "lab-sw1"); got != "bob (device)" {
		t.Errorf("after: the user in force is %q, want bob (device), never the config's alice", got)
	}
	// An entry again: version 1 again.
	sb.devSNMP("", "lab-sw1", "version", "v3")
	if got := sb.read(file); !strings.Contains(got, "version: 1") {
		t.Errorf("not version 1 once there is an entry:\n%s", got)
	}
	if got := userInForce(sb, "lab-sw1"); got != "bob (device)" {
		t.Errorf("with the entry back: %q", got)
	}
}

// With the real 0.2.22 and 0.2.21: a device that has no entry holds a version 2
// file (its user counts here, and the older release ignores such a file without
// reading it); once it has an entry the file fits version 1 and is that, and
// the older release reads it and uses the user.
func TestSNMPFileBecomesVersionOneWithAnEntryRealOldBinaries(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		flag *string
	}{{"0.2.22", old0222Flag}, {"0.2.21", old0221Flag}} {
		t.Run(tc.tag, func(t *testing.T) {
			bin := oldBinaryOf(t, tc.tag, tc.flag)
			hs := rollback0221State(t)
			run := oldRunner(t, hs, bin)
			// sw3 has no snmp: entry
			hs.step("pool-auth-pass\npool-priv-pass\n", "device", "snmp", "sw3", "v3-user", "add", "dave", "--default", "--stdin")
			if got := hs.read("state/snmp/devices/sw3.yaml"); !strings.Contains(got, "version: 2") {
				t.Fatalf("a device with no entry: not version 2:\n%s", got)
			}
			// the older release does not read the file of a device with no entry (it
			// ignores it, never parsing it): it neither refuses nor uses it
			if out, code := run("device", "snmp", "sw3", "show", "--reveal"); code != 0 || strings.Contains(out, "dave") || !strings.Contains(out, "credentials file present") {
				t.Errorf("%s device snmp sw3 show with no entry: %d\n%s", tc.tag, code, out)
			}
			hs.step("", "device", "snmp", "sw3", "version", "v3")
			if got := hs.read("state/snmp/devices/sw3.yaml"); !strings.Contains(got, "version: 1") {
				t.Fatalf("with an entry: not version 1:\n%s", got)
			}
			if out, code := run("device", "snmp", "sw3", "show", "--reveal"); code != 0 || !strings.Contains(out, "v3 user:    dave") {
				t.Errorf("%s device snmp sw3 show with an entry: %d\n%s", tc.tag, code, out)
			}
		})
	}
}
