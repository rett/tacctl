package cli

import (
	"strings"
	"testing"
)

// 'config cisco source-interface' (D119): show, set, unset, the schema's
// check, the per-scope show of 'config show', and the key following its scope.
func TestConfigCiscoSourceInterface(t *testing.T) {
	sb := newSandbox(t, true)
	// unset everywhere
	out := plain(sb.cfgRun("", []string{"config", "cisco", "source-interface"}, nil))
	for _, want := range []string{"Cisco source interface, per scope", "lab", "not set"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	out = plain(sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab"}, nil))
	if !strings.Contains(out, "Cisco source interface: not set") || sb.code != 0 {
		t.Errorf("show: %d\n%s", sb.code, out)
	}
	// set
	out = plain(sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab", "Loopback0"}, nil))
	if sb.code != 0 || !strings.Contains(out, "Scope 'lab' Cisco source interface set to Loopback0.") {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.err.String())
	}
	if got := sb.overrides(); !strings.Contains(got, "source_interface:") || !strings.Contains(got, "lab: Loopback0") {
		t.Errorf("tacctl.yaml:\n%s", got)
	}
	// shown by the walkthrough as the statement, and by config show
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, nil))
	if !strings.Contains(out, "\nip tacacs source-interface Loopback0\n") || strings.Contains(out, "Source interface not set") {
		t.Errorf("walkthrough:\n%s", out)
	}
	out = plain(sb.cfgRun("", []string{"config", "show"}, nil))
	if !strings.Contains(out, "Cisco source interface (per scope):\n    lab: Loopback0\n") {
		t.Errorf("config show:\n%s", out)
	}
	out = plain(sb.cfgRun("", []string{"config", "cisco", "source-interface"}, nil))
	if !strings.Contains(out, "lab") || !strings.Contains(out, "Loopback0") {
		t.Errorf("list after set:\n%s", out)
	}
	// the schema's check: a name that is no interface is refused, nothing set
	for _, bad := range []string{"loop back", "0", "Loop;0", "Loopback", "-Gi0/1"} {
		sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab", bad}, nil)
		if sb.code == 0 {
			t.Errorf("%q was taken", bad)
		}
	}
	if got := sb.overrides(); !strings.Contains(got, "lab: Loopback0") {
		t.Errorf("a refused value changed the setting:\n%s", got)
	}
	// a scope that does not exist, and too many arguments
	sb.cfgRun("", []string{"config", "cisco", "source-interface", "nosuch", "Loopback0"}, nil)
	sb.expect(1, "", "Scope 'nosuch' does not exist")
	sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab", "Loopback0", "extra"}, nil)
	sb.expect(1, "", "Unknown argument: 'extra'")
	// the unset
	out = plain(sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab", "none"}, nil))
	if sb.code != 0 || !strings.Contains(out, "Scope 'lab' Cisco source interface cleared.") {
		t.Errorf("none: %d\n%s", sb.code, out)
	}
	if got := sb.overrides(); strings.Contains(got, "Loopback0") {
		t.Errorf("still set:\n%s", got)
	}
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, nil))
	if strings.Contains(out, "ip tacacs source-interface Loopback0") || !strings.Contains(out, "Source interface not set for scope lab") {
		t.Errorf("walkthrough after the unset:\n%s", out)
	}
	// help
	out = plain(sb.cfgRun("", []string{"config", "cisco", "source-interface", "--help"}, nil))
	if !strings.Contains(out, "Usage:\n  tacctl config cisco source-interface [<scope> [<interface>|none]]") {
		t.Errorf("help:\n%s", out)
	}
}

// The key follows its scope: a rename moves it.
func TestConfigCiscoSourceInterfaceFollowsTheScope(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"config", "cisco", "source-interface", "lab", "Loopback7"}, nil)
	sb.run("", []string{"scope", "rename", "lab", "lab2"})
	if got := sb.overrides(); !strings.Contains(got, "lab2: Loopback7") || strings.Contains(got, "lab: Loopback7") {
		t.Errorf("after rename:\n%s", got)
	}
}
