package plan

import (
	"testing"
)

// The cases of the owned rows of the system block's closed table (0.2.19):
// syslog, the login announcement, the login retry options and the password
// policy. Each plans a device that holds another value of the same statement
// against a block that states one: the value is set (in place for a
// single-valued one), nothing is deleted, and what the block does not state is
// kept.
func systemRuleCase(block, device string, want []string, kept string) func(t *testing.T) {
	return func(t *testing.T) {
		f := systemFixture(t)
		sec := systemSectionOf(t, block)
		d, text := planSystem(t, add(device), withSystem(expectedSections(t, f.expected), sec), systemOpt)
		for _, w := range want {
			wantLine(t, d, "system", w)
		}
		noLine(t, d, "system", "delete")
		if kept != "" {
			wantKept(t, d, "system", kept)
		}
		// pasted, the section reads ok: the model replaces a single-valued leaf
		// as the device does
		systemConverges(t, f, withSystem(expectedSections(t, f.expected), sec), text, d)
	}
}

func init() {
	for id, c := range map[string]func(*testing.T){
		"junos.system.announcement": systemRuleCase(
			"set system login announcement <<'EOF'\nNotice.\nEOF\n", `set system login announcement "Other"`,
			[]string{`set system login announcement "Notice."`}, ""),
		"junos.system.syslog-host": systemRuleCase(
			"set system syslog host 192.0.2.50 any warning\n", "set system syslog host 192.0.2.50 any error",
			[]string{"set system syslog host 192.0.2.50 any warning"}, ""),
		"junos.system.syslog-facility-override": systemRuleCase(
			"set system syslog host 192.0.2.50 facility-override local7\n", "set system syslog host 192.0.2.50 facility-override local5",
			[]string{"set system syslog host 192.0.2.50 facility-override local7"}, ""),
		"junos.system.syslog-log-prefix": systemRuleCase(
			"set system syslog host 192.0.2.50 log-prefix lab\n", "set system syslog host 192.0.2.50 log-prefix other",
			[]string{"set system syslog host 192.0.2.50 log-prefix lab"}, ""),
		"junos.system.syslog-explicit-priority": systemRuleCase(
			"set system syslog host 192.0.2.50 explicit-priority\n", "set system syslog host 198.51.100.7 explicit-priority",
			[]string{"set system syslog host 192.0.2.50 explicit-priority"}, "system syslog host 198.51.100.7 explicit-priority"),
		"junos.system.syslog-time-format": systemRuleCase(
			"set system syslog time-format year\n", "set system syslog time-format millisecond",
			[]string{"set system syslog time-format year"}, "system syslog time-format millisecond"),
		"junos.system.syslog-source-address": systemRuleCase(
			"set system syslog source-address 192.0.2.9\n", "set system syslog source-address 198.51.100.9",
			[]string{"set system syslog source-address 192.0.2.9"}, ""),
		"junos.system.retry-option": systemRuleCase(
			"set system login retry-options tries-before-disconnect 4\n", "set system login retry-options tries-before-disconnect 7",
			[]string{"set system login retry-options tries-before-disconnect 4"}, ""),
		"junos.system.password-policy": systemRuleCase(
			"set system login password minimum-length 12\n", "set system login password minimum-length 8",
			[]string{"set system login password minimum-length 12"}, ""),
	} {
		junosRowCases[id] = c
	}
}
