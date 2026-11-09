package cli

import (
	"github.com/rett/tacctl/internal/execx/fake"
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

// With --stdout the report is the only thing on standard output: the notices
// of an empty report and of a pull that has nothing to read go to standard
// error, whatever the format.
func TestReportsStdoutHoldsTheReportAlone(t *testing.T) {
	// no device matches: a warning
	b := newReportsBox(t)
	tool := b.pdfTool()
	out := b.asWith(pdfStub(tool), nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--vendor", "wti", "--stdout")
	if b.sb.code != 0 || !strings.HasPrefix(out, "%PDF-1.7\n") || strings.Contains(out, "[WARN]") || !strings.Contains(b.sb.stderr(), "[WARN] No device matches: the report has no rows.") {
		t.Errorf("pdf: exit %d out %.60q err %q", b.sb.code, out, b.sb.stderr())
	}
	for _, format := range []string{"json", "csv", "text"} {
		out = b.as("alice", asSuper, "generate", "--type", "inventory", "--format", format, "--vendor", "wti", "--stdout")
		if b.sb.code != 0 || strings.Contains(out, "[WARN]") || !strings.Contains(b.sb.stderr(), "[WARN] No device matches: the report has no rows.") {
			t.Errorf("%s: exit %d out %.60q err %q", format, b.sb.code, out, b.sb.stderr())
		}
	}
	if out = b.as("alice", asSuper, "generate", "--type", "inventory", "--format", "json", "--vendor", "wti", "--stdout"); !strings.HasPrefix(out, "{") {
		t.Errorf("json does not start the output: %.60q", out)
	}
	// stored, the warning stays on standard output with the other lines
	if out = b.as("alice", asSuper, "generate", "--type", "inventory", "--vendor", "wti"); !strings.Contains(out, "[WARN] No device matches") {
		t.Errorf("stored: %q", out)
	}

	// --pull with no device the pull reads: an information line
	p := newPullBox(t)
	p.devices([3]string{"ap1", "192.168.1.30", "other"})
	home := filepath.Join(p.sb.dir, "home")
	p.sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		return sshAccount{UID: 1000, GID: 1000, Home: filepath.Join(home, name)}, nil
	}
	out = p.run("device", "reports", "generate", "--type", "inventory", "--format", "json", "--stdout", "--pull")
	if p.sb.code != 0 || !strings.HasPrefix(out, "{") || strings.Contains(out, "[INFO]") || !strings.Contains(p.sb.stderr(), "[INFO] No device to read") {
		t.Errorf("--pull json: exit %d out %.60q err %q", p.sb.code, out, p.sb.stderr())
	}
	dir := t.TempDir()
	tool = filepath.Join(dir, "weasyprint")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.sb.hooks.pdfToolDirs = []string{dir}
	out = plain(p.sb.cfgRun("", []string{"device", "reports", "generate", "--type", "inventory", "--format", "pdf", "--stdout", "--pull"},
		func(r *fake.Runner) { route(r); pdfStub(tool)(r) }, "SUDO_USER=alice"))
	if p.sb.code != 0 || !strings.HasPrefix(out, "%PDF-1.7\n") || strings.Contains(out, "[INFO]") || !strings.Contains(p.sb.stderr(), "[INFO] No device to read") {
		t.Errorf("--pull pdf: exit %d out %.60q err %q", p.sb.code, out, p.sb.stderr())
	}
}
