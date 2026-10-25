package cli

import (
	"slices"
	"strings"
	"testing"
)

// 'device notice list [<name>] [--all]' and 'device notice <name>
// ack|unack <kind>' (docs/plans/0.2.18-plan.md D274): three words are the
// ack form, so a device named 'list' still takes it; the words before 0.2.18
// ('device notices', 'device ssh-config') are unknown subcommands.
func TestDeviceNoticeForms(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "list", "10.99.0.3", "--vendor", "cisco", "--no-host-key")
	if out := sb.dev("", "notice", "list"); sb.code != 0 || !strings.Contains(out, "list  hostkey-unpinned") {
		t.Errorf("notice list: %d %q", sb.code, out)
	}
	if out := sb.dev("", "notice", "list", "list"); sb.code != 0 || !strings.Contains(out, "list  hostkey-unpinned") {
		t.Errorf("notice list list: %d %q", sb.code, out)
	}
	sb.dev("", "notice", "list", "ack", "hostkey-unpinned")
	if sb.code != 0 || !strings.Contains(sb.devices(), "hostkey-unpinned") {
		t.Fatalf("ack of the device named list: %d %q\n%s", sb.code, sb.stderr(), sb.devices())
	}
	if out := sb.dev("", "notice", "list", "list"); !strings.Contains(out, "No open notices.") {
		t.Errorf("after the ack: %q", out)
	}
	if out := sb.dev("", "notice", "list", "list", "--all"); !strings.Contains(out, "hostkey-unpinned (acknowledged)") {
		t.Errorf("--all: %q", out)
	}
	// Wrong shapes: the usage names both forms.
	for _, args := range [][]string{{"notice"}, {"notice", "list", "a", "b", "c"}, {"notice", "list", "ack", "hostkey-unpinned", "--all"}, {"notice", "sw9"}} {
		sb.dev("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Usage: tacctl device notice list [<name>] [--all]") ||
			!strings.Contains(sb.stderr(), "tacctl device notice <name> ack|unack <kind>") {
			t.Errorf("%q: %d %q", args, sb.code, sb.stderr())
		}
	}
	for _, old := range []string{"notices", "ssh-config"} {
		sb.dev("", old)
		sb.expect(1, "", "Unknown subcommand: '"+old+"'")
	}
	if u := sb.dev("", "--help"); strings.Contains(u, "notices [") || strings.Contains(u, "ssh-config") ||
		!strings.Contains(u, "notice list [<name>] [--all]") || !strings.Contains(u, "client-config") {
		t.Errorf("the usage:\n%s", u)
	}
}

// Completion: 'list' and the device names after 'notice'; after 'list' the
// names and --all; after a name ack|unack, then the kinds.
func TestDeviceNoticeCompletion(t *testing.T) {
	for _, c := range []struct {
		words, want, not []string
	}{
		{[]string{"device", "notice", ""}, []string{"list", "jsw1", "sw1"}, []string{"--all"}},
		{[]string{"device", "notice", "list", ""}, []string{"jsw1", "sw1", "--all"}, []string{"ack"}},
		{[]string{"device", "notice", "sw1", ""}, []string{"ack", "unack"}, []string{"--all", "jsw1"}},
		{[]string{"device", "notice", "sw1", "ack", ""}, []string{"generic-name"}, []string{"--all"}},
		{[]string{"device", ""}, []string{"notice", "client-config"}, []string{"notices", "ssh-config"}},
	} {
		got, _ := completeWords(t, liveNames, c.words...)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: %q lacks %q", c.words, got, w)
			}
		}
		for _, w := range c.not {
			if slices.Contains(got, w) {
				t.Errorf("%q: %q offers %q", c.words, got, w)
			}
		}
	}
}

// The audit: 'device notice list' is a read, the ack form an action.
func TestDeviceNoticeAuditClass(t *testing.T) {
	e := auditTable["device notice"]
	if e.Class != classAction || e.ReadWhen == nil {
		t.Fatalf("device notice: %+v", e)
	}
	for _, c := range []struct {
		rest []string
		read bool
	}{
		{[]string{"list"}, true}, {[]string{"list", "sw1"}, true}, {[]string{"list", "--all"}, true}, {[]string{"list", "sw1", "--all"}, true},
		{[]string{"list", "ack", "generic-name"}, false}, {[]string{"sw1", "ack", "generic-name"}, false}, {nil, false},
	} {
		if got := e.ReadWhen(c.rest); got != c.read {
			t.Errorf("%q: read %v, want %v", c.rest, got, c.read)
		}
	}
}
