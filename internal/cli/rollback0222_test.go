package cli

import (
	"strings"
	"testing"
)

// server.name (0.2.22) is a key every older release refuses, so every
// target's plan removes it, and --apply does.
func TestRollbackEveryTargetRemovesTheServerName(t *testing.T) {
	for _, v := range []string{"0.2.21", "0.2.20", "0.2.19", "0.2.18", "0.2.17", "0.2.16", "0.2.9", "0.2.3"} {
		hs := rollbackState(t)
		hs.step("", "server", "name", "core-1")
		hs.run(hs.runner(), "rollback", v)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if out := hs.all(); !strings.Contains(out, "remove server.name") {
			t.Errorf("%s dry run:\n%s", v, out)
		}
		hs.run(hs.runner(), "rollback", v, "--apply", "--yes")
		hs.expect(0, "Applying.", "")
		if strings.Contains(hs.overrides(), "name: core-1") {
			t.Errorf("%s: the key stayed:\n%s", v, hs.overrides())
		}
	}
}

// The timing scale (0.2.22) is in three places every older release refuses:
// the default of the whole server and a scope's in tacctl.yaml, a device's
// own in devices.yaml. Every target's plan removes all three, with a note and
// no warning of its own, --apply does, and the command ends by naming the
// verbs that write them again.
func TestRollbackEveryTargetRemovesTheTimeoutScale(t *testing.T) {
	for _, v := range []string{"0.2.21", "0.2.20", "0.2.19", "0.2.18", "0.2.17", "0.2.16", "0.2.9", "0.2.3"} {
		hs := rollback0221State(t)
		hs.step("", "config", "devices", "timeout-scale", "3")
		hs.step("", "scope", "timeout-scale", "lab", "2")
		hs.step("", "device", "timeout-scale", "sw1", "4")
		hs.step("", "device", "timeout-scale", "sw2", "10")
		if o := hs.read("state/devices.yaml"); strings.Count(o, "timeout_scale") != 2 {
			t.Fatalf("%s: devices.yaml:\n%s", v, o)
		}
		before := tree(t, hs.dir)
		hs.run(hs.runner(), "rollback", v)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		out := hs.all()
		for _, want := range []string{"remove device.timeout_scale", "remove timeout_scale_scope.lab", "devices.yaml: remove the timeout scale of the devices",
			"remove the timeout_scale key of sw1 (4)", "remove the timeout_scale key of sw2 (10)", "unknown key 'timeout_scale'",
			"The timing scale (tacctl device timeout-scale, scope timeout-scale and config devices timeout-scale) is removed"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s dry run lacks %q:\n%s", v, want, out)
			}
		}
		if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
			t.Errorf("%s: the dry run changed %q", v, got)
		}
		hs.run(hs.runner(), "rollback", v, "--apply", "--yes")
		hs.expect(0, "Applying.", "")
		after := hs.all()
		if !strings.Contains(after, "removed the timeout scale of 2 devices") ||
			!strings.Contains(after, "Until the upgrade, do not run 'tacctl device timeout-scale', 'tacctl scope timeout-scale' or 'tacctl config devices timeout-scale'") {
			t.Errorf("%s --apply:\n%s", v, after)
		}
		if o := hs.overrides(); strings.Contains(o, "timeout_scale") {
			t.Errorf("%s: tacctl.yaml keeps a key:\n%s", v, o)
		}
		if d := hs.read("state/devices.yaml"); strings.Contains(d, "timeout_scale") || !strings.Contains(d, "10.99.0.1") {
			t.Errorf("%s: devices.yaml:\n%s", v, d)
		}
		// a second run has nothing of it to do
		hs.run(hs.runner(), "rollback", v)
		hs.expect(0, "This was a dry run", "")
		if strings.Contains(hs.all(), "timeout_scale") {
			t.Errorf("%s: a second plan names the scale:\n%s", v, hs.all())
		}
	}
}

// withTimeoutScale puts the timing scale of 0.2.22 into the three places an
// older release refuses it (the server's and a scope's key in tacctl.yaml, a
// device's in devices.yaml), so that a real old binary run after the
// rollback shows that all three are gone.
func (hs *hostSandbox) withTimeoutScale() {
	hs.step("", "config", "devices", "timeout-scale", "3")
	hs.step("", "scope", "timeout-scale", "lab", "2")
	hs.step("", "device", "timeout-scale", "sw1", "4")
}
