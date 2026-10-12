package lifecycle_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
)

// A RADIUS-only install has no tacquito migration, yet its devices are the
// ones the privilege lines decide: the upgrade drops the lists that are
// exactly what 0.2.3 shipped whatever backend is enabled, and says what a
// device configured earlier keeps, once, although nothing stale is left.
func TestUpgradeDropsPreviousOperatorDefaultsOnARadiusOnlyInstall(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	// An upgrade does not create VarLib; a host that has devices has it.
	o.write(filepath.Join(o.p.VarLib, "devices-seen.json"), "{}\n")
	o.write(o.p.Overrides, "backends:\n  enabled: [radius]\n"+operator023Privileges+operator023Commands)
	o.be.Conf.Reload()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	for _, k := range []string{"privileges.operator", "commands.operator", "commands.readonly"} {
		if !strings.Contains(o.text(), "[INFO] Dropped "+k+" override: it is the value an earlier release shipped; the shipped value now applies") {
			t.Errorf("%s not dropped:\n%s", k, o.text())
		}
	}
	y := readFile(t, o.p.Overrides)
	if strings.Contains(y, "exec all: ping") || strings.Contains(y, "monitor") || strings.Contains(y, "privileges:") || strings.Contains(y, "commands:") {
		t.Errorf("tacctl.yaml still holds the 0.2.3 lists:\n%s", y)
	}
	if !strings.Contains(y, "- radius") {
		t.Errorf("the backend setting was lost:\n%s", y)
	}
	// Nothing stale is left, but the devices configured earlier are told.
	for _, want := range []string{"no privilege exec all level 7 ping", "delete system login class OP-CLASS permissions clear", "tacctl device config plan <device>"} {
		if !strings.Contains(o.text(), want) {
			t.Errorf("no %q:\n%s", want, o.text())
		}
	}
	if strings.Contains(o.text(), "These stored settings") {
		t.Errorf("named a stored setting after dropping them:\n%s", o.text())
	}
	if !lifecycle.OperatorNoticeDone(o.p) {
		t.Error("no marker")
	}
	// The second upgrade is silent about both.
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("second exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "no privilege exec") || strings.Contains(o.text(), "Dropped") {
		t.Errorf("second run:\n%s", o.text())
	}
}
