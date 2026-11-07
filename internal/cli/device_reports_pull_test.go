package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 'generate --pull' reads the devices as 'device config pull' does and makes
// the report from the fresh records.
func TestReportsGeneratePullReadsTheDevicesFirst(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"jsw1", "192.168.1.20", "juniper"})
	b.serve("juniper", "set version 25.4R1-S2.3\n"+b.expected("jsw1"))
	b.answer(junosChassisCmd, membersFixture(t, "synthetic-ex4300-hardware-vc.txt"))
	b.answer(junosVersionCmd, membersFixture(t, "synthetic-ex4300-version-vc.txt"))
	b.answer(junosVirtualChassisCmd, membersFixture(t, "synthetic-ex4300-vc-2.txt"))
	home := filepath.Join(b.sb.dir, "home")
	b.sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		return sshAccount{UID: 1000, GID: 1000, Home: filepath.Join(home, name)}, nil
	}

	// without --pull the report holds what is stored: nothing yet
	out := b.run("device", "reports", "generate", "--type", "members", "--format", "csv", "--stdout")
	if b.sb.code != 0 || strings.Contains(out, "SN000001") {
		t.Fatalf("before the pull: %d %q", b.sb.code, out)
	}
	if b.served(junosVirtualChassisCmd) != 0 {
		t.Fatal("a report without --pull read a device")
	}

	// --stdout: the pull's output goes to standard error, the report to
	// standard output alone
	out = b.run("device", "reports", "generate", "--type", "members", "--format", "csv", "--stdout", "--pull")
	if b.sb.code != 0 || !strings.HasPrefix(out, "device,member,role,model,serial,release,status,priority,pulled\n") ||
		!strings.Contains(out, "jsw1,0,master,EX4300-48T,SN000001") || !strings.Contains(out, "jsw1,1,backup,EX4300-48T,SN000002") {
		t.Fatalf("--pull --stdout: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(b.sb.stderr(), "ok via netconf") {
		t.Errorf("the pull's output is not on standard error: %q", b.sb.stderr())
	}

	// stored: the report is written after the pull
	out = b.run("device", "reports", "generate", "--type", "inventory", "--name", "after-pull", "--pull")
	if b.sb.code != 0 || !strings.Contains(out, "Report after-pull written: ") {
		t.Fatalf("--pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	body, err := os.ReadFile(filepath.Join(home, "alice", "reports", "devices", "after-pull.txt"))
	if err != nil || !strings.Contains(string(body), "SN000001") {
		t.Errorf("%v\n%s", err, body)
	}
}
