package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/snmpcred"
)

// snmpPoolState puts a pool at all three levels of the rollback sandbox, as
// the files of this release hold it: the config with two users (alice the
// default), the scope lab with one (carol), sw1 with two (dave the default),
// sw2 choosing the config's bob (sw1 and sw2 have an snmp: entry), and sw3,
// which has none, with a user of its own (erin).
func snmpPoolState(hs *hostSandbox) {
	hs.t.Helper()
	user := func(n string) snmpcred.User {
		return snmpcred.User{Name: n, AuthPass: "pool-auth-pass", PrivPass: "pool-priv-pass"}
	}
	st := snmpcred.Store{File: hs.path("state", "snmp.yaml"), Dir: hs.path("state", "snmp")}
	for l, c := range map[snmpcred.Level]snmpcred.Creds{
		{Kind: snmpcred.LevelDefault}:             {Users: []snmpcred.User{user("alice"), user("bob")}, Default: "alice"},
		{Kind: snmpcred.LevelScope, Name: "lab"}:  {Users: []snmpcred.User{user("carol")}, Default: "carol"},
		{Kind: snmpcred.LevelDevice, Name: "sw1"}: {Users: []snmpcred.User{user("dave"), user("monitor")}, Default: "dave"},
		{Kind: snmpcred.LevelDevice, Name: "sw2"}: {Community: "sw2-community", Default: "bob"},
		{Kind: snmpcred.LevelDevice, Name: "sw3"}: {Users: []snmpcred.User{user("erin")}, Default: "erin"},
	} {
		if err := st.Save(l, c); err != nil {
			hs.t.Fatal(err)
		}
	}
}

// oldRunner runs a release's binary on the sandbox state with stubs for the
// commands it would call.
func oldRunner(t *testing.T, hs *hostSandbox, bin string) func(args ...string) (string, int) {
	stubs := t.TempDir()
	for _, name := range []string{"systemctl", "logger", "chown"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return func(args ...string) (string, int) {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: bin, Args: args,
			Env: append(append([]string(nil), hs.env...), "PATH="+stubs+":/usr/bin:/bin", "HOME="+t.TempDir(), "LANG=C.UTF-8")})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return plain(string(res.Stdout) + string(res.Stderr)), res.Code
	}
}

// The way there and back with the real releases: built from the tag, the
// strict parser of 0.2.22 and of 0.2.21 refuses the credential files of this
// release ("unsupported version") before the rollback and reads them after,
// each level with its default user. The way back, 'backup recover', is
// backup_recover_snmp_test.go.
func TestRollbackSNMPPoolRealOldBinaries(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		flag *string
	}{{"0.2.22", old0222Flag}, {"0.2.21", old0221Flag}} {
		t.Run(tc.tag, func(t *testing.T) {
			bin := oldBinaryOf(t, tc.tag, tc.flag)
			hs := rollback0221State(t)
			snmpPoolState(hs)
			run := oldRunner(t, hs, bin)
			for _, args := range [][]string{{"config", "snmp", "show"}, {"device", "snmp", "sw1", "show"}} {
				if out, code := run(args...); code == 0 || !strings.Contains(out, "unsupported version") {
					t.Errorf("%s %v before: %d\n%s", tc.tag, args, code, out)
				}
			}

			// The dry run names levels and counts, never a user; --apply needs --yes.
			before := tree(t, hs.dir)
			hs.run(hs.runner(), "rollback", tc.tag)
			hs.expect(0, "This was a dry run: nothing was changed.", "")
			out := hs.all()
			for _, want := range []string{"SNMPv3 users are dropped from the credential files", "3 users are dropped from 3 levels (the config (1), device sw1 (1), device sw3 (1))",
				"1 device chooses a user of its scope's or the config's pool", "1 device has credentials and no snmp: entry in devices.yaml (sw3)", "tacctl backup recover <snapshot> --only snmp-users", "To convert the state: tacctl rollback " + tc.tag + " --apply --yes"} {
				if !strings.Contains(out, want) {
					t.Errorf("the dry run lacks %q:\n%s", want, out)
				}
			}
			for _, secret := range []string{"bob", "carol", "dave", "monitor", "erin", "pool-auth-pass"} {
				if strings.Contains(out, secret) {
					t.Errorf("the dry run shows %q:\n%s", secret, out)
				}
			}
			if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
				t.Errorf("the dry run changed %q", got)
			}
			hs.run(hs.runner(), "rollback", tc.tag, "--apply")
			hs.expect(1, "", "The warnings above need your decision")

			r := hs.runner()
			hs.run(r, "rollback", tc.tag, "--apply", "--yes")
			hs.expect(0, "Applying.", "")
			id := filepath.Base(newestSnapshot(t, hs))
			after := hs.all()
			for _, want := range []string{"wrote 4 SNMP credential files in version 1", "3 SNMPv3 users were dropped from the credential files of 3 levels", "sw3) was removed: the device has no snmp: entry",
				"tacctl backup recover " + id + " --only snmp-users", "Until then, do not give a level a second or a non-default SNMPv3 user ('v3-user add')", "A community, and one v3 user that is the default, are saved in version 1 and are fine (for a device, once it has an snmp: entry)."} {
				if !strings.Contains(after, want) {
					t.Errorf("--apply lacks %q:\n%s", want, after)
				}
			}
			var line string
			for _, l := range auditLines(r) {
				if strings.Contains(l, "rollback target="+tc.tag) && strings.Contains(l, "result=ok") {
					line = l
				}
			}
			if !strings.Contains(line, "kept="+id) || !strings.Contains(line, "snmp-users=3 snmp-levels=3 snmp-choices=1 snmp-devices=1") {
				t.Errorf("the audit line: %q", line)
			}
			noLoggerHas(t, "rollback", r, "bob", "monitor", "erin", "pool-auth-pass")
			if info := snapshot.ReadKept(filepath.Join(hs.dir, "state", "backups-kept", id)).Note; !strings.Contains(info, "rollback to "+tc.tag+": dropped 3 SNMPv3 users in 3 levels; the choice of 1 device of another level's SNMPv3 user; the SNMP credentials of 1 device without an snmp: entry") {
				t.Errorf("the note of the kept copy: %q", info)
			}

			if out, code := run("config", "snmp", "show"); code != 0 || !strings.Contains(out, "v3 user:    set") {
				t.Errorf("%s config snmp show after: %d\n%s", tc.tag, code, out)
			}
			if out, code := run("config", "snmp", "show", "--reveal"); code != 0 || !strings.Contains(out, "v3 user:    alice; auth passphrase: pool-auth-pass") {
				t.Errorf("%s config snmp show --reveal after: %d\n%s", tc.tag, code, out)
			}
			if out, code := run("scope", "snmp", "lab", "show"); code != 0 || !strings.Contains(out, "v3 user:    carol") {
				t.Errorf("%s scope snmp show after: %d\n%s", tc.tag, code, out)
			}
			// sw3 had no snmp: entry: the older release ignores such a file, so the
			// rollback removed it rather than leave it to hand the device to another
			// level's credential; no orphan note, no user of its own.
			if out, code := run("device", "snmp", "sw3", "show"); code != 0 || strings.Contains(out, "erin") || strings.Contains(out, "credentials file present") {
				t.Errorf("%s device snmp sw3 show after: %d\n%s", tc.tag, code, out)
			}
			if _, err := os.Stat(hs.path("state", "snmp", "devices", "sw3.yaml")); !os.IsNotExist(err) {
				t.Errorf("%s: sw3's file is left: %v", tc.tag, err)
			}
			if out, code := run("device", "snmp", "sw1", "show"); code != 0 || !strings.Contains(out, "v3 user:    dave") {
				t.Errorf("%s device snmp show after: %d\n%s", tc.tag, code, out)
			}
			if out, code := run("config", "render"); code != 0 {
				t.Errorf("%s config render after: %d\n%s", tc.tag, code, out)
			}
			if out, code := run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") {
				t.Errorf("%s config validate after: %d\n%s", tc.tag, code, out)
			}

			// A second run has nothing to do.
			hs.run(hs.runner(), "rollback", tc.tag)
			hs.expect(0, "This was a dry run", "")
			if strings.Contains(hs.all(), "SNMPv3 users are dropped") {
				t.Errorf("a second plan:\n%s", hs.all())
			}
		})
	}
}

// The note of the kept snapshot and the audit line count what was dropped, and
// word a drop of a choice or of a device's file as such, never "0 users".
func TestSNMPPoolNoteWordsEachKindOfDrop(t *testing.T) {
	for _, c := range []struct {
		d    lifecycle.SNMPPoolDrop
		want string
	}{
		{lifecycle.SNMPPoolDrop{Users: 3, Levels: 2}, "dropped 3 SNMPv3 users in 2 levels"},
		{lifecycle.SNMPPoolDrop{Users: 1, Levels: 1}, "dropped 1 SNMPv3 user in 1 level"},
		{lifecycle.SNMPPoolDrop{Choices: 2}, "dropped the choice of 2 devices of another level's SNMPv3 user"},
		{lifecycle.SNMPPoolDrop{Orphans: 1}, "dropped the SNMP credentials of 1 device without an snmp: entry"},
		{lifecycle.SNMPPoolDrop{Users: 1, Levels: 1, Choices: 1, Orphans: 1}, "dropped 1 SNMPv3 user in 1 level; the choice of 1 device of another level's SNMPv3 user; the SNMP credentials of 1 device without an snmp: entry"},
	} {
		if got := snmpPoolNote(c.d); got != c.want {
			t.Errorf("%+v: %q, want %q", c.d, got, c.want)
		}
	}
}
