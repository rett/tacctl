package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// rootLeafSections are the sections of a pull of a Junos device by 0.2.20:
// the breakglass section holds a local user and root's two statements, and
// the system section a leaf of 'system services ssh' that is the device's own.
func rootLeafSections() map[string]devices.Section {
	return map[string]devices.Section{
		"breakglass": {Name: "breakglass", Lines: []string{
			`set system login user bg-admin class super-user authentication encrypted-password "$6$examplesalt$EXAMPLEHASH"`,
			`set system root-authentication encrypted-password "$6$examplesalt$EXAMPLEROOTHASH"`,
			"set system services ssh root-login allow"}},
		"system": {Name: "system", Lines: []string{"set system time-zone UTC"}},
	}
}

func TestStripRootLeaves(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"version: 1\nbreakglass: |\n  set system login user bg-admin class super-user\n  set system root-authentication encrypted-password\n  set system services ssh root-login allow\nsystem: |\n  set system time-zone UTC\n",
			"version: 1\nbreakglass: |\n  set system login user bg-admin class super-user\nsystem: |\n  set system time-zone UTC\n"},
		{"version: 1\nbreakglass: |\n  set system root-authentication encrypted-password\n  deactivate system services ssh root-login\n",
			"version: 1\nbreakglass: \"\"\n"},
		{"version: 1\nbreakglass: |\n  set system root-authentication ssh-ed25519\nsnmp: \"\"\n", "version: 1\nbreakglass: \"\"\nsnmp: \"\"\n"},
		// Nothing of another section, and no other leaf, is touched.
		{"version: 1\nsystem: |\n  set system services ssh root-login deny\nbreakglass: |\n  set system services ssh protocol-version v2\n  set system root-authenticationx y\n",
			"version: 1\nsystem: |\n  set system services ssh root-login deny\nbreakglass: |\n  set system services ssh protocol-version v2\n  set system root-authenticationx y\n"},
	} {
		got, n := stripRootLeaves(c.in)
		if got != c.want {
			t.Errorf("%q:\n got %q (%d)\nwant %q", c.in, got, n, c.want)
		}
		if (n == 0) != (got == c.in) {
			t.Errorf("%q: n %d", c.in, n)
		}
	}
}

// Every target that reads the records takes root's statements out of the
// breakglass section of the stored pulls (the sections file and the plain
// view), keeps every other line, takes no snapshot for it, and is done on a
// second run; 0.2.3 never opens the files and leaves them.
func TestPlanRollbackTakesTheRootStatementsOutOfTheStoredPulls(t *testing.T) {
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.write(s.p.TierSudoersFile, "# edited\n", 0o640)
		s.write(s.p.SudoersFile, "# edited\n", 0o640)
		st := devconf.Store{Records: s.p.ConfigRecords, Dir: s.p.ConfigDir}
		if err := st.SaveSections("jsw1", "juniper", rootLeafSections()); err != nil {
			t.Fatal(err)
		}
		pulled := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
		if err := st.SavePlain("jsw1", "juniper", rootLeafSections(), pulled); err != nil {
			t.Fatal(err)
		}
		secs := filepath.Join(s.p.ConfigDir, "jsw1.yaml")
		plain := filepath.Join(s.p.ConfigDir, "jsw1.plain")
		before := s.snapshotOf()
		if !strings.Contains(before[secs], "root-login allow") || strings.Contains(before[secs], "EXAMPLEROOTHASH") {
			t.Fatalf("the fixture:\n%s", before[secs])
		}
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		stp := stepText(p)
		step := strings.Contains(stp, "take the Junos root statements out of the stored pulls")
		if step != (target != RollbackTarget) {
			t.Errorf("%s: the step %v:\n%s", target, step, stp)
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		after := s.snapshotOf()
		if target == RollbackTarget {
			if after[secs] != before[secs] || after[plain] != before[plain] {
				t.Errorf("0.2.3 changed a stored pull")
			}
			continue
		}
		for _, w := range []string{"take 2 statements out of the breakglass section of jsw1.yaml", "take 2 statements out of the breakglass section of jsw1.plain",
			"takes them for extra statements there", "never in a snapshot"} {
			if !strings.Contains(stp, w) {
				t.Errorf("%s: steps lack %q:\n%s", target, w, stp)
			}
		}
		if !p.Pending() || p.PendingFiles() {
			t.Errorf("%s: pending %v files %v", target, p.Pending(), p.PendingFiles())
		}
		if i := strings.Index(stp, "take the Junos root statements"); i > strings.Index(stp, "leave every other file untouched") {
			t.Errorf("%s: the step comes after the files left:\n%s", target, stp)
		}
		if !strings.Contains(strings.Join(done, "\n"), s.p.ConfigDir+": took the Junos root statements out of 2 stored pulls") {
			t.Errorf("%s: done %q", target, done)
		}
		for _, f := range []string{secs, plain} {
			if got, want := after[f], strings.NewReplacer("  set system root-authentication encrypted-password\n", "", "  set system services ssh root-login allow\n", "").Replace(before[f]); got != want || got == before[f] {
				t.Errorf("%s: %s after:\n%s\nwant:\n%s", target, filepath.Base(f), got, want)
			}
			if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %s mode %v %v", target, f, fi, err)
			}
		}
		// The files read back as this release's store reads them.
		if got, err := st.Sections("jsw1", "juniper"); err != nil || strings.Contains(strings.Join(got["breakglass"].Lines, "\n"), "root") ||
			!strings.Contains(strings.Join(got["breakglass"].Lines, "\n"), "login user bg-admin") || len(got["system"].Lines) != 1 {
			t.Errorf("%s: read back %v %v", target, got, err)
		}
		if got, err := st.Plain("jsw1", "juniper", pulled); err != nil || got == nil {
			t.Errorf("%s: the plain view lost its stamp: %v %v", target, got, err)
		}
		ents, _ := os.ReadDir(s.p.ConfigDir)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("%s: a temporary file is left: %s", target, e.Name())
			}
		}
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "root statements") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
	}
}
