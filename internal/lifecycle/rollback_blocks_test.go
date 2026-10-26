package lifecycle

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The lists of configuration blocks in force (0.2.7: blocks.<scope>.<vendor>
// and blocks_device.<device>.<vendor>) are keys 0.2.3 does not know: the
// rollback removes them and says so, and the block files stay where they are.
func TestRollbackRemovesTheBlockManifestsAndKeepsTheFiles(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"blocks:\n  lab:\n    juniper:\n    - snmp\n"+
		"blocks_device:\n  jsw1~lab~example~net:\n    juniper:\n    - snmp\n    - system\n", 0o640)
	scopeFile := filepath.Join(s.p.BlocksDir, "lab", "juniper", "snmp")
	deviceFile := filepath.Join(s.p.BlocksDir, "_devices", "jsw1.lab.example.net", "juniper", "system")
	s.write(scopeFile, "set snmp community lab-ro authorization read-only\n", 0o600)
	s.write(deviceFile, "set system time-zone UTC\n", 0o600)
	s.reload()

	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"blocks.lab.juniper", "blocks_device.jsw1~lab~example~net.juniper"} {
		if !slices.Contains(p.Keys(), k) {
			t.Errorf("keys %q lack %s", p.Keys(), k)
		}
	}
	var text string
	for _, w := range p.Warnings {
		text += strings.Join(w.Lines, "\n") + "\n"
	}
	for _, want := range []string{"The list of configuration blocks in force (", "blocks.lab.juniper", "blocks_device.jsw1~lab~example~net.juniper",
		"the block files stay in " + s.p.BlocksDir} {
		if !strings.Contains(text, want) {
			t.Errorf("the warning lacks %q:\n%s", want, text)
		}
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(s.p.Overrides)
	if strings.Contains(string(got), "blocks") {
		t.Errorf("tacctl.yaml after the rollback:\n%s", got)
	}
	for _, f := range []string{scopeFile, deviceFile} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("the block file went: %v", err)
		}
	}
}
