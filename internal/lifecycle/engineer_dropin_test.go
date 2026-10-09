package lifecycle_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
)

// S1 of the review of WP10.2g: an engineer drop-in under its old name
// (tacctl-engineer.conf, read by sshd after the console's) is renamed by
// upgrade: the new file is written first, the old one goes, and a second
// upgrade changes nothing. Uninstall removes the old name too.
func TestUpgradeRenamesTheEngineerDropIn(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.run.On([]string{"sshd", "-t"}, execx.Result{})
	o.write(o.p.SSHDEngineerDropInOld, console.EngineerDropIn(false))
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if readFile(t, o.p.SSHDEngineerDropIn) != console.EngineerDropIn(false) {
		t.Errorf("no engineer drop-in under the new name:\n%s", o.text())
	}
	if _, err := os.Stat(o.p.SSHDEngineerDropInOld); err == nil {
		t.Errorf("the old name stayed:\n%s", o.text())
	}
	if !strings.Contains(o.text(), "Removed: sshd drop-in "+o.p.SSHDEngineerDropInOld) {
		t.Errorf("not reported:\n%s", o.text())
	}
	o.stdout.Reset()
	if code := upgrade(o); code != 0 || strings.Contains(o.text(), "Removed: sshd drop-in") || !strings.Contains(o.text(), "Unchanged: sshd drop-in for the engineer tier") {
		t.Errorf("second run: %d\n%s", code, o.text())
	}
}

func TestUninstallRemovesTheOldEngineerDropIn(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.write(o.p.SSHDEngineerDropInOld, console.EngineerDropIn(false))
	o.write(o.p.ShellsFile, "/bin/sh\n")
	o.run.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")})
	o.run.On([]string{"sshd", "-t"}, execx.Result{})
	if code := uninstall(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if _, err := os.Stat(o.p.SSHDEngineerDropInOld); err == nil {
		t.Error("the old engineer drop-in is left")
	}
}
