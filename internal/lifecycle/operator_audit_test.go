package lifecycle_test

// The operator audit of 0.2.5 (docs/plans/0.2.5-operator-audit.md, 6f): what
// an upgrade does with the operator and readonly settings an earlier release
// stored. A list that is exactly what 0.2.3 shipped is dropped; any other
// that still holds a removed command is named, and nothing else changes.

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
)

const operator023Privileges = `privileges:
  operator:
    - "exec all: ping"
    - "exec all: traceroute"
    - "exec all: monitor capture"
    - clear counters
    - clear line
    - clear ip arp
    - clear arp-cache
    - clear mac address-table dynamic
    - undebug all
`

const operator023Commands = `commands:
  operator:
    - { name: show,       action: deny,   match: ['^(running-config view full)( .*)?$'] }
    - { name: show,       action: permit }
    - { name: dir,        action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: terminal,   action: permit }
    - { name: ssh,        action: permit }
    - { name: telnet,     action: permit }
    - { name: monitor,    action: permit, match: ['^(capture)( .*)?$'] }
    - { name: clear,      action: permit, match: ['^(counters|line|(ip )?arp \S+|arp-cache \S+|mac address-table dynamic \S+)( .*)?$'] }
    - { name: undebug,    action: permit }
    - { name: exit,       action: permit }
    - { name: logout,     action: permit }
    - { name: "*",        action: deny }
  readonly:
    - { name: show,       action: deny,   match: ['^(running-config view full)( .*)?$'] }
    - { name: show,       action: permit }
    - { name: dir,        action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: terminal,   action: permit, match: ['^(length|width)( .*)?$'] }
    - { name: exit,       action: permit }
    - { name: logout,     action: permit }
    - { name: "*",        action: deny }
`

// What 0.2.3 wrote is dropped, with an info line each, and the shipped
// values apply; a second run does nothing.
func TestMigratePreviousOperatorDefaultsDropsWhatWasShipped(t *testing.T) {
	e := newTenv(t)
	e.overrides(operator023Privileges + operator023Commands)
	for _, k := range []string{"privileges.operator", "commands.operator", "commands.readonly"} {
		if !e.be.Conf.HasOverride(k) {
			t.Fatalf("setup: %s", k)
		}
	}
	if err := lifecycle.MigratePreviousOperatorDefaults(e.env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"privileges.operator", "commands.operator", "commands.readonly"} {
		has(t, e.output(), "[INFO] Dropped "+k+" override: it is the value an earlier release shipped; the shipped value now applies")
		if e.be.Conf.HasOverride(k) {
			t.Errorf("%s kept", k)
		}
	}
	e.reset()
	if err := lifecycle.MigratePreviousOperatorDefaults(e.env); err != nil || e.output() != "" {
		t.Errorf("second run: %v %q", err, e.output())
	}
}

// A list with one more entry is somebody's choice: nothing is dropped.
func TestMigratePreviousOperatorDefaultsKeepsAChoice(t *testing.T) {
	e := newTenv(t)
	e.overrides(strings.Replace(operator023Privileges, "    - undebug all\n", "    - undebug all\n    - show version\n", 1) +
		strings.Replace(operator023Commands, "    - { name: logout,     action: permit }\n    - { name: \"*\",        action: deny }\n  readonly:",
			"    - { name: logout,     action: permit }\n    - { name: debug,      action: permit }\n    - { name: \"*\",        action: deny }\n  readonly:", 1))
	if err := lifecycle.MigratePreviousOperatorDefaults(e.env); err != nil {
		t.Fatal(err)
	}
	hasNot(t, e.output(), "Dropped privileges.operator")
	hasNot(t, e.output(), "Dropped commands.operator")
	has(t, e.output(), "Dropped commands.readonly") // the viewer's list is what 0.2.3 shipped
	if !e.be.Conf.HasOverride("privileges.operator") || !e.be.Conf.HasOverride("commands.operator") {
		t.Error("a customised list was dropped")
	}
}
