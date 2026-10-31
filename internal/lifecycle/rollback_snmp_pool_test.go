package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snmpcred"
)

// The pool of SNMPv3 users (0.2.23) is version 2 of the credential files,
// which every older release refuses. Every target writes them as version 1
// again after the snapshot: a level keeps its default user and drops the
// rest, and the plan names levels and counts, never a user.

func writePool(t *testing.T, s *rbSandbox, l snmpcred.Level, c snmpcred.Creds) {
	t.Helper()
	if err := (snmpcred.Store{File: s.p.SNMPFile, Dir: s.p.SNMPDir}).Save(l, c); err != nil {
		t.Fatal(err)
	}
}

func lvl(kind, name string) snmpcred.Level { return snmpcred.Level{Kind: kind, Name: name} }

func poolUser(name string) snmpcred.User {
	return snmpcred.User{Name: name, AuthPass: name + "-auth-pass", PrivPass: name + "-priv-pass"}
}

// poolState puts pools at all three levels on top of the sandbox: the config
// with two users (one the default), a scope with one, a device with two, a
// device (it has an snmp: entry) that only chooses its scope's user and a
// device with no snmp: entry that holds a user of its own.
func poolState(t *testing.T) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	writePool(t, s, lvl(snmpcred.LevelDefault, ""), snmpcred.Creds{Community: "default-community-1", Users: []snmpcred.User{poolUser("alice"), poolUser("bob")}, Default: "alice"})
	writePool(t, s, lvl(snmpcred.LevelScope, "lab"), snmpcred.Creds{Users: []snmpcred.User{poolUser("carol")}, Default: "carol"})
	writePool(t, s, lvl(snmpcred.LevelDevice, "core-sw1"), snmpcred.Creds{Users: []snmpcred.User{poolUser("dave"), poolUser("monitor")}, Default: "monitor"})
	writePool(t, s, lvl(snmpcred.LevelDevice, "oob-con1"), snmpcred.Creds{Default: "carol"})
	writePool(t, s, lvl(snmpcred.LevelDevice, "lab-rtr2"), snmpcred.Creds{Users: []snmpcred.User{poolUser("erin")}, Default: "erin"})
	return s
}

func TestPlanRollbackEveryTargetWritesTheCredentialFilesInVersionOne(t *testing.T) {
	for _, target := range allRollbackTargets {
		t.Run(target, func(t *testing.T) {
			s := poolState(t)
			s.in.Target = target
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if !p.PendingFiles() || !p.NeedsYes() {
				t.Errorf("files %v needs yes %v", p.PendingFiles(), p.NeedsYes())
			}
			// 3 users dropped (the config's extra, core-sw1's other, lab-rtr2's
			// only one), 3 levels; the device that chose its scope's user loses
			// the choice; lab-rtr2 has no snmp: entry, so its file goes whole.
			if d := p.SNMPPoolDropped(); d.Users != 3 || d.Levels != 3 || d.Choices != 1 || d.Orphans != 1 {
				t.Errorf("dropped %+v", d)
			}
			w := warnText(p)
			for _, want := range []string{"SNMPv3 users are dropped from the credential files", target + " reads one SNMPv3 user for each level: 3 users are dropped from 3 levels (the config (1), device core-sw1 (1), device lab-rtr2 (1))",
				"1 device chooses a user of its scope's or the config's pool", "1 device has credentials and no snmp: entry in devices.yaml (lab-rtr2)", "tacctl backup recover <snapshot> --only snmp-users"} {
				if !strings.Contains(w, want) {
					t.Errorf("the warning lacks %q:\n%s", want, w)
				}
			}
			st := stepText(p)
			for _, want := range []string{"write the SNMP credential files in version 1", "the config: keep the default user, drop 1 user",
				"device core-sw1: keep the default user, drop 1 user", "device oob-con1: no user; its default names a user of another level's pool", "nothing is left, the file goes",
				"device lab-rtr2: no snmp: entry in devices.yaml beside the file, which " + target + " ignores: the file goes (1 user)", "unsupported version"} {
				if !strings.Contains(st, want) {
					t.Errorf("the steps lack %q:\n%s", want, st)
				}
			}
			// not a name of a user, not a passphrase
			if all := st + w + strings.Join(p.Notes, "\n"); strings.Contains(all, "-pass") || strings.Contains(all, "alice") || strings.Contains(all, "bob") || strings.Contains(all, "dave") || strings.Contains(all, "carol") || strings.Contains(all, "erin") {
				t.Errorf("the plan shows a user:\n%s", all)
			}
			if after := s.snapshotOf(); !equalFiles(before, after) {
				t.Error("the plan wrote a file")
			}

			done, err := ApplyRollback(p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(done, "\n"), "wrote 4 SNMP credential files in version 1") {
				t.Errorf("done %q", done)
			}
			read := func(l snmpcred.Level) snmpcred.Creds {
				c, err := (snmpcred.Store{File: s.p.SNMPFile, Dir: s.p.SNMPDir}).Load(l)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			def := read(lvl(snmpcred.LevelDefault, ""))
			if def.Format != snmpcred.LegacyVersion || def.Community != "default-community-1" || len(def.Users) != 1 || def.Users[0] != poolUser("alice") || def.Default != "alice" {
				t.Errorf("default level: %+v", def)
			}
			dev := read(lvl(snmpcred.LevelDevice, "core-sw1"))
			if dev.Format != snmpcred.LegacyVersion || len(dev.Users) != 1 || dev.Users[0] != poolUser("monitor") {
				t.Errorf("device: %+v", dev)
			}
			// the scope's file holds one default user: it is version 1 already and
			// is not touched
			if lab := read(lvl(snmpcred.LevelScope, "lab")); lab.Format != snmpcred.LegacyVersion || lab.Default != "carol" {
				t.Errorf("scope: %+v", lab)
			}
			if strings.Contains(st, "scope lab") {
				t.Errorf("the scope's version 1 file is in the steps:\n%s", st)
			}
			for _, gone := range []string{"oob-con1", "lab-rtr2"} {
				if _, err := os.Stat(filepath.Join(s.p.SNMPDir, "devices", gone+".yaml")); !os.IsNotExist(err) {
					t.Errorf("%s: a file with nothing in it, or one the older release would ignore, is left: %v", gone, err)
				}
			}
			for _, f := range []string{s.p.SNMPFile, filepath.Join(s.p.SNMPDir, "lab.yaml"), filepath.Join(s.p.SNMPDir, "devices", "core-sw1.yaml")} {
				if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
					t.Errorf("%s: %v %v", f, fi, err)
				}
			}
			// the second plan has nothing of it to do
			s.reload()
			s.in.Target = target
			p, err = PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(stepText(p), "credential files") || strings.Contains(warnText(p), "SNMPv3") || p.SNMPPoolDropped() != (SNMPPoolDrop{}) {
				t.Errorf("second plan:\n%s\n%s", stepText(p), warnText(p))
			}
		})
	}
}

// Files that fit version 1 (a community, one default user) are what this
// release saves for them: a rollback of such a state has nothing of the SNMP
// credentials to convert, the targets that returned early included: no step,
// no warning, nothing dropped.
func TestPlanRollbackSNMPPoolLeavesFilesThatFitVersionOne(t *testing.T) {
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	writePool(t, s, lvl(snmpcred.LevelDefault, ""), snmpcred.Creds{Community: "default-community-1"})
	writePool(t, s, lvl(snmpcred.LevelScope, "lab"), snmpcred.Creds{Users: []snmpcred.User{poolUser("carol")}, Default: "carol"})
	for _, target := range []string{RollbackTarget0222, RollbackTarget} {
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stepText(p), "credential files") || strings.Contains(warnText(p), "SNMPv3") || p.SNMPPoolDropped() != (SNMPPoolDrop{}) {
			t.Errorf("%s:\n%s\n%s", target, stepText(p), warnText(p))
		}
	}
	for _, f := range []string{s.p.SNMPFile, filepath.Join(s.p.SNMPDir, "lab.yaml")} {
		if c, err := snmpcred.Load(f); err != nil || c.Format != snmpcred.LegacyVersion {
			t.Errorf("%s: %+v %v", f, c, err)
		}
	}
}

// A level with several users and none that is its default has no answer to
// which one stays: the rollback is refused, naming the level, and nothing is
// written.
func TestPlanRollbackSNMPPoolRefusesSeveralUsersWithoutADefault(t *testing.T) {
	for _, target := range allRollbackTargets {
		s := newRBSandbox(t)
		writePool(t, s, lvl(snmpcred.LevelScope, "lab"), snmpcred.Creds{Users: []snmpcred.User{poolUser("bob"), poolUser("dave")}})
		s.in.Target = target
		before := s.snapshotOf()
		_, err := PlanRollback(s.in)
		var ref *RollbackRefusal
		if !errors.As(err, &ref) {
			t.Fatalf("%s: %v", target, err)
		}
		msg := strings.Join(ref.Lines, "\n")
		if !strings.Contains(msg, "scope lab holds 2 SNMPv3 users and none of them is its default") || !strings.Contains(msg, "tacctl scope snmp lab v3-user default <user>") ||
			strings.Contains(msg, "bob") || strings.Contains(msg, "dave") || strings.Contains(msg, "-pass") {
			t.Errorf("%s: %s", target, msg)
		}
		if !equalFiles(before, s.snapshotOf()) {
			t.Errorf("%s: a file changed", target)
		}
	}
	// A default that names a user of another level does not help a device
	// with two users of its own.
	s := newRBSandbox(t)
	writePool(t, s, lvl(snmpcred.LevelDevice, "core-sw1"), snmpcred.Creds{Users: []snmpcred.User{poolUser("bob"), poolUser("dave")}, Default: "carol"})
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "device core-sw1 holds 2 SNMPv3 users and its default names a user of another level's pool, so none of its own is the default") {
		t.Errorf("foreign default: %v", err)
	}
	// One user that is not the default is not a question: it is dropped.
	s = newRBSandbox(t)
	writePool(t, s, lvl(snmpcred.LevelScope, "lab"), snmpcred.Creds{Users: []snmpcred.User{poolUser("bob")}})
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.SNMPPoolDropped(); d.Users != 1 || d.Levels != 1 {
		t.Errorf("dropped %+v", d)
	}
}

// Files of version 1 (or that cannot be read) are not this change's.
func TestPlanRollbackSNMPPoolLeavesVersionOneFiles(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.SNMPFile, "version: 1\nv3: {user: alice, auth_passphrase: a-pass-1, priv_passphrase: p-pass-1}\n", 0o600)
	s.write(filepath.Join(s.p.SNMPDir, "bad.yaml"), "version: 2\nusers: x\n", 0o600)
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stepText(p), "credential files") {
		t.Errorf("steps:\n%s", stepText(p))
	}
}

// Only a choice goes (a device with an snmp: entry that chose a user of its
// scope's pool, no user dropped): the drop is still something, so the warning,
// --yes and the kept snapshot apply, and the counts say so.
func TestPlanRollbackSNMPPoolDroppingOnlyAChoiceStillAsksAndCounts(t *testing.T) {
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	writePool(t, s, lvl(snmpcred.LevelScope, "lab"), snmpcred.Creds{Users: []snmpcred.User{poolUser("carol")}, Default: "carol"})
	writePool(t, s, lvl(snmpcred.LevelDevice, "oob-con1"), snmpcred.Creds{Default: "carol"})
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.SNMPPoolDropped(); d != (SNMPPoolDrop{Choices: 1}) || !d.Any() {
		t.Errorf("dropped %+v", d)
	}
	w := warnText(p)
	if !p.NeedsYes() || strings.Contains(w, "0 users") || !strings.Contains(w, "1 device chooses a user of its scope's or the config's pool") {
		t.Errorf("warning:\n%s", w)
	}
}
