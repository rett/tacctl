package policy

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// The preset's values are what D19 approved, fit their limits, and are
// valid for the schema and tacquito.
func TestRolePresetFitsAndValidates(t *testing.T) {
	sizes := map[string]int{
		"readonly " + conf.JunosDenyCommands:        219,
		"operator " + conf.JunosDenyCommands:        237,
		"engineer " + conf.JunosDenyCommands:        236,
		"engineer " + conf.JunosDenyConfiguration:   208,
		"engineer+f " + conf.JunosDenyConfiguration: 208 + len("firewall .*MGMT-FILTER|"),
	}
	s := conf.NewSchema(conf.DefaultBackends)
	for _, filter := range []string{"", "MGMT-FILTER"} {
		for _, r := range RolePreset(filter) {
			for attr, items := range r.Junos {
				key := r.Group + " " + attr
				if filter != "" && r.Group == "engineer" && attr == conf.JunosDenyConfiguration {
					key = "engineer+f " + attr
				}
				if got := len(conf.JunosValue(items)); got != sizes[key] {
					t.Errorf("%s: %d bytes, want %d", key, got, sizes[key])
				}
				list := make([]any, len(items))
				for i, it := range items {
					list[i] = it
				}
				if msg := s.Validate("junos."+r.Group+"."+attr, list, true); msg != "" {
					t.Errorf("%s: %s", key, msg)
				}
			}
			if r.WTI == "" || s.Validate("wti_level."+r.Group, r.WTI, false) != "" {
				t.Errorf("%s: WTI level %q", r.Group, r.WTI)
			}
			for _, line := range r.Commands {
				f := strings.SplitN(line, "|", 3)
				if len(f) != 3 || (f[1] != "permit" && f[1] != "deny") {
					t.Errorf("rule %q", line)
				}
				if strings.Contains(f[2], ",") {
					t.Errorf("rule %q: a comma would split the match list", line)
				}
				if _, err := regexp.Compile(f[2]); err != nil {
					t.Errorf("rule %q: %v", line, err)
				}
			}
		}
	}
	// A 16-byte filter name still fits.
	if v := engineerDenyConfiguration(strings.Repeat("F", 16)); len(conf.JunosValue([]string{v})) > conf.JunosLimit(conf.JunosDenyConfiguration) {
		t.Errorf("a 16-byte filter does not fit: %d", len(v)+2)
	}
	eng := RolePreset("")[2]
	if eng.Group != "engineer" || eng.Tier != "" || eng.Class != EngineerClass || eng.Commands[len(eng.Commands)-1] != Catchall+"|permit|" {
		t.Fatalf("engineer %+v", eng)
	}
}

// What engineer's Cisco rules decide for a few commands, top-down as
// tacquito evaluates them (the first rule whose name is the command and
// whose match, if any, matches the arguments).
func TestEngineerCiscoRules(t *testing.T) {
	decide := func(cmd, args string) string {
		for _, line := range engineerCommands {
			f := strings.SplitN(line, "|", 3)
			if f[0] != cmd && f[0] != Catchall {
				continue
			}
			if f[2] == "" || regexp.MustCompile(f[2]).MatchString(args) {
				return f[1]
			}
		}
		return "none"
	}
	for _, c := range []struct{ cmd, args, want string }{
		{"configure", "terminal", "permit"},
		{"configure", "replace flash:x", "deny"},
		{"copy", "running-config startup-config", "permit"},
		{"copy", "tftp: running-config", "deny"},
		{"username", "bob privilege 15", "deny"},
		{"no", "aaa new-model", "deny"},
		{"no", "shutdown", "permit"},
		{"interface", "GigabitEthernet1", "permit"},
		{"ip", "route 0.0.0.0 0.0.0.0 192.0.2.1", "permit"},
		{"ip", "ssh version 2", "deny"},
		{"do", "reload", "deny"},
		{"do", "show ip route", "permit"},
		{"reload", "", "deny"},
		{"debug", "all", "deny"},
		{"debug", "ip ospf events", "permit"},
	} {
		if got := decide(c.cmd, c.args); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.cmd, c.args, got, c.want)
		}
	}
}
