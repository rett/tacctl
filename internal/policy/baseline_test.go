package policy_test

// The baseline commands and privileges of the four roles
// (docs/plans/0.2.3-baseline-design.md, WP10.6c): the sample corpus of the
// design's section (D) decided by the tacquito-exact emulator for the
// shipped defaults and for the role preset, the nesting of the roles, the
// privilege lists, the Junos deny sets and their sizes, and the lint of
// every regex.

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/policy"
)

var roleNames = []string{"readonly", "operator", "engineer", "superuser"}

// shippedRules are what a group has without any override: defaults.yaml.
// engineer is not shipped (no rules, so every command is permitted).
func shippedRules(role string) []tqRule { return tqRules(policy.DefaultLines(role)) }

// presetRules are the rules after 'group preset roles'.
func presetRules(t *testing.T, role string) []tqRule {
	t.Helper()
	for _, r := range policy.RolePreset() {
		if r.Group == role {
			if r.Commands == nil {
				return shippedRules(role)
			}
			return tqRules(r.Commands)
		}
	}
	t.Fatalf("no role %s in the preset", role)
	return nil
}

// sample is one command line of a role and the answer in each regime:
// "PP" is permitted by the shipped defaults and by the preset, "PD"
// permitted by the defaults and denied by the preset, and so on.
type sample struct {
	role, line, want string
}

// corpus is every line of the design's section (D), plus the neighbours
// that pin the edges of each regex. The engineer lines the design denied
// for its configuration-mode trust boundary are PP here: engineers are
// unrestricted on Cisco (design, 'Decisions on the revision', 5).
var corpus = []sample{
	// readonly: the NCM / monitoring account.
	{"readonly", "terminal length 0", "PP"},
	{"readonly", "terminal width 0", "PP"},
	{"readonly", "show running-config", "PP"},
	{"readonly", "show version", "PP"},
	{"readonly", "show inventory", "PP"},
	{"readonly", "show interfaces", "PP"},
	{"readonly", "show cdp neighbors detail", "PP"},
	{"readonly", "show ip route", "PP"},
	{"readonly", "show logging", "PP"},
	{"readonly", "show ip bgp summary", "PP"},
	{"readonly", "show running-config | include hostname", "PP"},
	{"readonly", "dir flash:", "PP"},
	{"readonly", "exit", "PP"},
	{"readonly", "logout", "PP"},
	{"readonly", "ping 192.0.2.1", "PP"},
	{"readonly", "traceroute 192.0.2.1", "PP"},
	{"readonly", "show running-config view full", "DD"},
	{"readonly", "show running-config view full | include key", "DD"},
	{"readonly", "show running-config view", "PP"},
	{"readonly", "show running-config view-full", "PP"},
	{"readonly", "show tech-support", "PD"},
	{"readonly", "show startup-config", "PD"},
	{"readonly", "show derived-config", "PD"},
	{"readonly", "show key chain", "PD"},
	{"readonly", "show snmp community", "PD"},
	{"readonly", "show crypto session", "PD"},
	{"readonly", "show archive log config all", "PD"},
	{"readonly", "terminal monitor", "DD"},
	{"readonly", "terminal", "DD"},
	{"readonly", "enable", "DD"},
	{"readonly", "enable 15", "DD"},
	{"readonly", "copy running-config tftp://192.0.2.9/x", "DD"},
	{"readonly", "ssh -l x 192.0.2.1", "DD"},
	{"readonly", "telnet 192.0.2.1", "DD"},
	{"readonly", "clear counters", "DD"},
	{"readonly", "configure terminal", "DD"},
	{"readonly", "debug ip packet", "DD"},
	{"readonly", "undebug all", "DD"},
	{"readonly", "monitor capture CAP start", "DD"},
	{"readonly", "write memory", "DD"},
	{"readonly", "reload", "DD"},

	// operator: advanced troubleshooting, no changes.
	{"operator", "terminal length 0", "PP"},
	{"operator", "show running-config", "PP"},
	{"operator", "show version", "PP"},
	{"operator", "show ip ospf neighbor", "PP"},
	{"operator", "show ip route", "PP"},
	{"operator", "show crypto session", "PP"},
	{"operator", "dir flash:", "PP"},
	{"operator", "exit", "PP"},
	{"operator", "logout", "PP"},
	{"operator", "terminal monitor", "PP"},
	{"operator", "ping vrf MGMT 192.0.2.1 source Loopback0", "PP"},
	{"operator", "traceroute mpls ipv4 10.0.0.1/32", "PP"},
	{"operator", "monitor capture CAP interface Gi1 both", "PP"},
	{"operator", "monitor capture CAP export tftp://192.0.2.9/c.pcap", "PP"},
	{"operator", "clear counters", "PP"},
	{"operator", "clear counters GigabitEthernet1", "PP"},
	{"operator", "clear line vty 3", "PP"},
	{"operator", "clear ip arp 192.0.2.7", "PP"},
	{"operator", "clear arp-cache GigabitEthernet1", "PP"},
	{"operator", "clear mac address-table dynamic interface Gi1/0/1", "PP"},
	{"operator", "ssh -l oper 192.0.2.2", "PP"},
	{"operator", "telnet 192.0.2.2", "PP"},
	{"operator", "undebug all", "PP"},
	{"operator", "show running-config view full", "DD"},
	{"operator", "show running-config view full | include key", "DD"},
	{"operator", "show running-config view", "PP"},
	{"operator", "show running-config view-full", "PP"},
	{"operator", "show startup-config", "PD"},
	{"operator", "show derived-config", "PD"},
	{"operator", "show key chain", "PD"},
	{"operator", "show snmp user", "PD"},
	{"operator", "show crypto isakmp key", "PD"},
	{"operator", "show crypto key mypubkey rsa", "PD"},
	{"operator", "show archive log config all", "PD"},
	{"operator", "clear arp-cache", "DD"},
	{"operator", "clear ip arp", "DD"},
	{"operator", "clear mac address-table dynamic", "DD"},
	{"operator", "clear ip route *", "DD"},
	{"operator", "clear ip bgp *", "DD"},
	{"operator", "clear ip bgp 192.0.2.1 soft in", "DD"},
	{"operator", "clear logging", "DD"},
	{"operator", "debug ip ospf adj", "DD"},
	{"operator", "test aaa group tacacs+ u p legacy", "DD"},
	{"operator", "copy flash:c.pcap tftp://192.0.2.9/c.pcap", "DD"},
	{"operator", "monitor session 1 source interface Gi1", "DD"},
	{"operator", "monitor", "DD"},
	{"operator", "write memory", "DD"},
	{"operator", "reload in 5", "DD"},
	{"operator", "configure terminal", "DD"},
	{"operator", "enable", "DD"},

	// engineer: provisions and configures. Shipped, the group has no
	// rules (everything is permitted); the preset denies the exec-level
	// lifecycle, the shell escapes and the writes that load a config.
	{"engineer", "configure terminal", "PP"},
	{"engineer", "configure terminal revert timer 5", "PP"},
	{"engineer", "configure replace flash:backup.cfg list force", "PP"},
	{"engineer", "configure replace nvram:startup-config", "PP"},
	{"engineer", "configure confirm", "PP"},
	{"engineer", "copy running-config startup-config", "PP"},
	{"engineer", "copy running-config flash:backup.cfg", "PP"},
	{"engineer", "copy running-config tftp://192.0.2.9/x", "PP"},
	{"engineer", "copy flash:cap.pcap tftp://192.0.2.9/cap.pcap", "PP"},
	{"engineer", "clear ip bgp 192.0.2.1 soft in", "PP"},
	{"engineer", "clear counters", "PP"},
	{"engineer", "no shutdown", "PP"},
	{"engineer", "interface GigabitEthernet1", "PP"},
	{"engineer", "ip route 0.0.0.0 0.0.0.0 192.0.2.1", "PP"},
	{"engineer", "ip access-list extended EDGE-IN", "PP"},
	{"engineer", "crypto isakmp policy 10", "PP"},
	{"engineer", "key chain OSPF-KEYS", "PP"},
	{"engineer", "do show ip route", "PP"},
	{"engineer", "do write memory", "PP"},
	{"engineer", "ping vrf MGMT 192.0.2.1 source Loopback0", "PP"},
	{"engineer", "authentication port-control auto", "PP"},
	{"engineer", "snmp-server community c0mm RO TACCTL-SNMP", "PP"},
	{"engineer", "no snmp-server community old", "PP"},
	{"engineer", "logging host 192.0.2.50", "PP"},
	{"engineer", "no logging buffered", "PP"},
	{"engineer", "write memory", "PP"},
	{"engineer", "debug ip ospf adj", "PP"},
	{"engineer", "archive config", "PP"},
	// ... the lines the design denied for the configuration-mode trust
	// boundary, now permitted (engineers push tacctl's managed sections
	// with their own login in 0.2.5):
	{"engineer", "no logging host 192.0.2.50", "PP"},
	{"engineer", "no logging trap", "PP"},
	{"engineer", "netconf-yang", "PP"},
	{"engineer", "restconf", "PP"},
	{"engineer", "config-register 0x2142", "PP"},
	{"engineer", "aaa new-model", "PP"},
	{"engineer", "no aaa new-model", "PP"},
	{"engineer", "no aaa authorization config-commands", "PP"},
	{"engineer", "tacacs server TACACS", "PP"},
	{"engineer", "no tacacs server TACACS", "PP"},
	{"engineer", "no line vty 0 4", "PP"},
	{"engineer", "username bob privilege 15 secret x", "PP"},
	{"engineer", "no username admin", "PP"},
	{"engineer", "enable secret 9 $9$x", "PP"},
	{"engineer", "ip ssh version 2", "PP"},
	{"engineer", "ip http server", "PP"},
	{"engineer", "ip access-list standard VTY-ACL", "PP"},
	{"engineer", "no ip access-list standard VTY-ACL", "PP"},
	{"engineer", "key config-key password-encrypt master", "PP"},
	{"engineer", "alias exec sr show running-config", "PP"},
	{"engineer", "crypto key generate rsa", "PP"},
	{"engineer", "crypto pki trustpoint TP", "PP"},
	{"engineer", "boot system flash:image.bin", "PP"},
	{"engineer", "license boot level network-advantage", "PP"},
	{"engineer", "event manager applet X", "PP"},
	// ... and what stays denied:
	{"engineer", "reload", "PD"},
	{"engineer", "reload in 10", "PD"},
	{"engineer", "do reload in 5", "PD"},
	{"engineer", "configure replace tftp://192.0.2.9/x.cfg", "PD"},
	{"engineer", "configure network tftp://192.0.2.9/x.cfg", "PD"},
	{"engineer", "configure memory", "PD"},
	{"engineer", "copy tftp: running-config", "PD"},
	{"engineer", "copy tftp://192.0.2.9/x flash:y", "PD"},
	{"engineer", "copy flash:x running-config", "PD"},
	{"engineer", "do copy tftp: running-config", "PD"},
	{"engineer", "do configure replace tftp://192.0.2.9/x.cfg", "PD"},
	{"engineer", "test aaa group tacacs+ u p legacy", "PD"},
	{"engineer", "clear aaa counters servers all", "PD"},
	{"engineer", "clear logging", "PD"},
	{"engineer", "do clear logging", "PD"},
	{"engineer", "switch 1 priority 15", "PD"},
	{"engineer", "debug all", "PD"},
	{"engineer", "debug aaa authentication", "PD"},
	{"engineer", "debug tacacs", "PD"},
	{"engineer", "delete flash:x", "PD"},
	{"engineer", "erase startup-config", "PD"},
	{"engineer", "write erase", "PD"},
	{"engineer", "format flash:", "PD"},
	{"engineer", "request platform software x", "PD"},
	{"engineer", "install add file flash:x.bin", "PD"},
	{"engineer", "archive download-sw /overwrite tftp://192.0.2.9/x.tar", "PD"},
	{"engineer", "tclsh", "PD"},
	{"engineer", "guestshell enable", "PD"},
	{"engineer", "app-hosting install appid x package flash:y", "PD"},
	{"engineer", "hw-module slot 1 reload", "PD"},
	{"engineer", "redundancy force-switchover", "PD"},

	// superuser: everything.
	{"superuser", "reload", "PP"},
	{"superuser", "configure terminal", "PP"},
	{"superuser", "copy tftp: running-config", "PP"},
	{"superuser", "show tech-support", "PP"},
}

func ruleSet(t *testing.T, role string, preset bool) []tqRule {
	if preset {
		return presetRules(t, role)
	}
	return shippedRules(role)
}

// Every sample is decided as the design says, for the shipped defaults
// and for the preset, as tacquito evaluates the rendered rules.
func TestBaselineCorpus(t *testing.T) {
	for _, preset := range []bool{false, true} {
		regime := map[bool]string{false: "shipped", true: "preset"}[preset]
		for _, s := range corpus {
			want := s.want[0]
			if preset {
				want = s.want[1]
			}
			got := tqPermits(ruleSet(t, s.role, preset), true, s.line)
			if got != (want == 'P') {
				t.Errorf("%s %s: %q permitted=%v, want %c", regime, s.role, s.line, got, want)
			}
		}
	}
}

// The role preset's shipped half: the rules a group has without any
// override only permit what the design lists; the deny pairs are the
// preset's.
func TestShippedRulesOnlyPermitAndEndInDeny(t *testing.T) {
	for _, role := range []string{"readonly", "operator"} {
		rules := shippedRules(role)
		if len(rules) == 0 || rules[len(rules)-1].name != "*" || rules[len(rules)-1].action != "deny" {
			t.Errorf("%s: shipped rules %+v, want a deny catch-all last", role, rules)
		}
		for _, r := range rules[:len(rules)-1] {
			// The one deny the defaults carry: the unfiltered, key-bearing
			// running-config, in front of the permits of 'show'. Every
			// other deny pair belongs to the preset.
			if isViewFullDeny := r.name == "show" && slices.Equal(r.match, []string{"^(running-config view full)( .*)?$"}); r.action != "permit" && !isViewFullDeny {
				t.Errorf("%s: shipped rule %q denies; the deny pairs belong to the preset", role, r.name)
			}
		}
		if rules[0].name != "show" || rules[0].action != "deny" {
			t.Errorf("%s: the first shipped rule is %+v, want the show deny of 'running-config view full'", role, rules[0])
		}
	}
	if r := shippedRules("superuser"); len(r) != 1 || r[0].name != "*" || r[0].action != "permit" {
		t.Errorf("superuser: %+v", r)
	}
	if r := shippedRules("engineer"); len(r) != 0 {
		t.Errorf("engineer ships no rules: %+v", r)
	}
}

// Roles nest (design, role definitions): what readonly may run, operator
// may; what operator may run, engineer may; what engineer may run,
// superuser may. A lower role's explicit denies do not matter.
func TestRolesNest(t *testing.T) {
	var lines []string
	for _, s := range corpus {
		lines = append(lines, s.line)
	}
	lines = append(lines, "show version", "enable", "exit", "terminal width 80", "undebug all", "clear line vty 1")
	for _, preset := range []bool{false, true} {
		regime := map[bool]string{false: "shipped", true: "preset"}[preset]
		rules := map[string][]tqRule{}
		for _, role := range roleNames {
			rules[role] = ruleSet(t, role, preset)
		}
		for _, line := range lines {
			for i := 0; i+1 < len(roleNames); i++ {
				lo, hi := roleNames[i], roleNames[i+1]
				if tqPermits(rules[lo], true, line) && !tqPermits(rules[hi], true, line) {
					t.Errorf("%s: %q is permitted to %s but not to %s", regime, line, lo, hi)
				}
			}
		}
	}
}

// localFallbackExceptions are the shipped privilege entries whose BARE form
// the server does not permit: IOS lowers the verb with any arguments, the
// server permits only the single-entry form ('clear ip arp <address>'), so
// with `aaa authorization ... group X local` and the server unreachable the
// operator can clear a whole table. Decided and documented (the comment above
// the privilege lines of internal/conf/defaults.yaml and the README): the
// tables refill themselves, and the operator needs the single-entry forms.
// A new entry cannot slip in unnoticed: it is listed here with its reason or
// the test fails.
var localFallbackExceptions = map[string]string{
	"clear ip arp":                    "single-entry form only on the server; the ARP table refills",
	"clear arp-cache":                 "single-entry form only on the server; the ARP table refills",
	"clear mac address-table dynamic": "single-entry form only on the server; the MAC table relearns",
}

// Every shipped privilege entry is something the group's rules permit in
// its BARE form (what the `local` authorization fallback on a device
// allows), so the fallback gives a user no more than the server does,
// except the exceptions listed in localFallbackExceptions, which the server
// permits with an argument; and none is a command that is level 1 already
// (lowering it would move it up).
func TestPrivilegesArePermitted(t *testing.T) {
	level1 := []string{"show ip route", "show access-list", "show version", "ping", "traceroute"}
	usedException := map[string]bool{}
	for _, role := range roleNames {
		for _, preset := range []bool{false, true} {
			rules := ruleSet(t, role, preset)
			for _, entry := range policy.DefaultPrivileges(role) {
				cmd := entry
				if i := strings.Index(entry, ": "); i >= 0 {
					cmd = entry[i+2:]
				}
				switch _, exempt := localFallbackExceptions[cmd]; {
				case tqPermits(rules, true, cmd):
				case exempt:
					usedException[cmd] = true
					if !tqPermits(rules, true, cmd+" 192.0.2.1") {
						t.Errorf("%s (preset=%v): the exception %q is not permitted with an argument either", role, preset, entry)
					}
				default:
					t.Errorf("%s (preset=%v): privilege %q is not permitted by the group's rules in its bare form (the local fallback would allow more than the server); fix the rule or list it in localFallbackExceptions with a reason", role, preset, entry)
				}
				for _, l1 := range level1 {
					// 'exec all:' lowers the extended forms (ping vrf ...),
					// which are not level 1; a plain entry would be.
					if cmd == l1 && !strings.HasPrefix(entry, "exec all:") {
						t.Errorf("%s: privilege %q is level 1 already", role, entry)
					}
				}
			}
		}
	}
	for cmd := range localFallbackExceptions {
		if !usedException[cmd] {
			t.Errorf("localFallbackExceptions lists %q, which no shipped privilege entry needs any more or the rules permit bare", cmd)
		}
	}
	// Operator inherits readonly's level-1 line, so readonly's entries must
	// be permitted to operator as well (IOS levels are cumulative).
	for _, entry := range policy.DefaultPrivileges("readonly") {
		if !tqPermits(shippedRules("operator"), true, entry) || !tqPermits(presetRules(t, "operator"), true, entry) {
			t.Errorf("operator does not permit readonly's privilege %q", entry)
		}
	}
	if got := policy.DefaultPrivileges("superuser"); len(got) != 0 {
		t.Errorf("superuser: %q", got)
	}
}

// The Junos deny-commands of each role as the preset sets them.
func junosDenyCommands(t *testing.T) map[string]*regexp.Regexp {
	t.Helper()
	out := map[string]*regexp.Regexp{}
	for _, r := range policy.RolePreset() {
		items := r.Junos[conf.JunosDenyCommands]
		if len(items) == 0 {
			continue
		}
		if len(items) != 1 {
			t.Fatalf("%s: %d deny-commands items", r.Group, len(items))
		}
		out[r.Group] = regexp.MustCompile(items[0])
	}
	return out
}

// junosCorpus are operational command lines: each role's answer is "denied
// by its deny-commands" (true) or not.
var junosCorpus = []struct {
	line string
	deny map[string]bool // readonly, operator, engineer; a missing role is false
}{
	{"set cli screen-length 0", nil},
	{"show configuration | display set", nil},
	{"show chassis hardware", nil},
	{"show version", nil},
	{"show log messages", nil},
	{"ping 192.0.2.1", nil},
	{"traceroute 192.0.2.1", nil},
	{"request support information", map[string]bool{"readonly": true, "operator": true}},
	{"request system reboot", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"request system storage cleanup", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"request chassis routing-engine master switch", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"request vmhost reboot", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"ssh 192.0.2.1", map[string]bool{"readonly": true}},
	{"telnet 192.0.2.1", map[string]bool{"readonly": true}},
	{"clear interfaces statistics", map[string]bool{"readonly": true}},
	{"clear arp", map[string]bool{"readonly": true}},
	{"clear ethernet-switching table", map[string]bool{"readonly": true}},
	{"clear firewall all", map[string]bool{"readonly": true}},
	{"clear bgp neighbor 192.0.2.1 soft", map[string]bool{"readonly": true, "operator": true}},
	{"clear ospf neighbor all", map[string]bool{"readonly": true, "operator": true}},
	{"clear isis adjacency", map[string]bool{"readonly": true, "operator": true}},
	{"clear system login lockout user x", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"clear log messages", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"clear security flow session", map[string]bool{"readonly": true, "operator": true}},
	{"monitor traffic interface ge-0/0/0", map[string]bool{"readonly": true}},
	{"monitor traffic interface ge-0/0/0 write-file /var/tmp/x", map[string]bool{"readonly": true, "operator": true}},
	{"monitor start messages", map[string]bool{"readonly": true}},
	{"restart routing", map[string]bool{"readonly": true, "operator": true}},
	{"restart management", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"restart chassis-control", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"show system rollback 1", map[string]bool{"readonly": true, "operator": true}},
	{"show system rollback compare 1 2", map[string]bool{"readonly": true, "operator": true}},
	{"load set terminal", map[string]bool{"readonly": true, "operator": true}},
	{"load merge terminal", map[string]bool{"readonly": true, "operator": true}},
	{"load set /var/tmp/x.set", map[string]bool{"readonly": true, "operator": true}},
	{"load override /config/x.conf", map[string]bool{"readonly": true, "operator": true}},
	{"file delete-directory /var/tmp/x", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"file change-owner x /var/tmp/y", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"file change-permission 600 /var/tmp/y", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"file show /config/rescue.conf", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"file list /var/tmp", map[string]bool{"readonly": true, "operator": true}},
	{"file copy /a /b", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"start shell", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"op foo", map[string]bool{"readonly": true, "operator": true, "engineer": true}},
	{"test configuration", map[string]bool{"readonly": true, "operator": true}},
	{"configure", map[string]bool{"readonly": true, "operator": true}},
	{"edit", map[string]bool{"readonly": true, "operator": true}},
}

// The deny-commands decide the design's Junos samples as listed.
func TestJunosDenyCommandsSamples(t *testing.T) {
	re := junosDenyCommands(t)
	for _, role := range []string{"readonly", "operator", "engineer"} {
		if re[role] == nil {
			t.Fatalf("no deny-commands for %s", role)
		}
	}
	for _, s := range junosCorpus {
		for _, role := range []string{"readonly", "operator", "engineer"} {
			if got := re[role].MatchString(s.line); got != s.deny[role] {
				t.Errorf("%s: %q denied=%v, want %v", role, s.line, got, s.deny[role])
			}
		}
	}
}

// Junos nesting: what the engineer's deny-commands deny, the operator's
// deny too, and the viewer's deny what the operator's do, so the lower
// role never reads more than the higher one runs (a lower role's patterns
// cover everything the higher role's cover, for the corpus). No role has a
// deny-configuration but the engineer's cleared one, so nothing is hidden
// from reading.
func TestJunosDenyNest(t *testing.T) {
	re := junosDenyCommands(t)
	for _, s := range junosCorpus {
		if re["engineer"].MatchString(s.line) && !re["operator"].MatchString(s.line) {
			t.Errorf("%q is denied to engineer but not to operator", s.line)
		}
		if re["operator"].MatchString(s.line) && !re["readonly"].MatchString(s.line) {
			t.Errorf("%q is denied to operator but not to readonly", s.line)
		}
	}
	for _, r := range policy.RolePreset() {
		if items := r.Junos[conf.JunosDenyConfiguration]; len(items) != 0 {
			t.Errorf("%s: canonical deny-configuration must be empty, got %q", r.Group, items)
		}
	}
}

// The sizes of the Junos values with the preset's '( )' wrapper, within
// TACACS+'s 255-byte argument (limits 241 / 236).
func TestJunosSizes(t *testing.T) {
	want := map[string]int{"readonly": 112, "operator": 226, "engineer": 219}
	got := map[string]int{}
	for _, r := range policy.RolePreset() {
		for attr, items := range r.Junos {
			if attr == conf.JunosDenyConfiguration {
				continue
			}
			n := len(conf.JunosValue(items))
			got[r.Group] = n
			if n > conf.JunosLimit(attr) {
				t.Errorf("%s %s: %d bytes, over the limit %d", r.Group, attr, n, conf.JunosLimit(attr))
			}
		}
	}
	for g, n := range want {
		if got[g] != n {
			t.Errorf("%s deny-commands: %d bytes, want %d", g, got[g], n)
		}
	}
	// The opt-in hardening example fits with a 16-byte filter name.
	if n := len(conf.JunosValue([]string{policy.EngineerHardeningDenyConfiguration("")})); n != 206 {
		t.Errorf("hardening example: %d bytes, want 206", n)
	}
	if n := len(conf.JunosValue([]string{policy.EngineerHardeningDenyConfiguration(strings.Repeat("F", 16))})); n > conf.JunosLimit(conf.JunosDenyConfiguration) {
		t.Errorf("hardening example with a 16-byte filter: %d bytes", n)
	}
}

var junosForbidden = regexp.MustCompile(`\\[SdbwsDWS]|\(\?`)

// The anchor / comma / ERE lint over everything the baseline ships: every
// Cisco match (defaults and preset) starts with ^ and ends with $ and has
// no comma (the rule line form splits at it); every Junos value is POSIX
// ERE (no \S \d \b, no '(?'), anchored, and a valid regexp.
func TestBaselineLint(t *testing.T) {
	check := func(where, rx string) {
		t.Helper()
		if !strings.HasPrefix(rx, "^") || !strings.HasSuffix(rx, "$") {
			t.Errorf("%s: %q must start with ^ and end with $", where, rx)
		}
		if strings.Contains(rx, ",") {
			t.Errorf("%s: %q contains a comma, which would split the match list", where, rx)
		}
		if _, err := regexp.Compile(rx); err != nil {
			t.Errorf("%s: %q: %v", where, rx, err)
		}
	}
	for _, role := range roleNames {
		for _, r := range tqRulesAll(t, role) {
			for _, rx := range r.match {
				check(role+" "+r.name, rx)
			}
		}
	}
	for _, r := range policy.RolePreset() {
		for attr, items := range r.Junos {
			for _, it := range items {
				check("junos "+r.Group+" "+attr, it)
				if junosForbidden.MatchString(it) {
					t.Errorf("junos %s %s: %q uses a Perl-style escape or group; Junos is POSIX ERE", r.Group, attr, it)
				}
				if p := conf.JunosItemProblem(it); p != "" {
					t.Errorf("junos %s %s: %s", r.Group, attr, p)
				}
			}
		}
	}
	// The hardening example is held to the ERE rule as well (it is a
	// prefix match by design, so only the escapes are checked).
	if junosForbidden.MatchString(policy.EngineerHardeningDenyConfiguration("F")) {
		t.Error("hardening example uses a Perl-style escape")
	}
	// Every rule of the shipped defaults and the preset lints clean.
	for _, role := range roleNames {
		for _, preset := range []bool{false, true} {
			var lines []string
			if preset {
				for _, r := range policy.RolePreset() {
					if r.Group == role {
						lines = r.Commands
					}
				}
			} else {
				lines = policy.DefaultLines(role)
			}
			for _, f := range policy.LintRules(lines) {
				t.Errorf("%s (preset=%v) rule #%d %q: %s", role, preset, f.Pos, f.Line, f.Msg)
			}
		}
	}
}

// tqRulesAll are the shipped and preset rules of a role together.
func tqRulesAll(t *testing.T, role string) []tqRule {
	return append(shippedRules(role), presetRules(t, role)...)
}

// The preset's engineer list: the counts the docs state.
func TestEngineerPresetShape(t *testing.T) {
	var eng policy.Role
	for _, r := range policy.RolePreset() {
		if r.Group == "engineer" {
			eng = r
		}
	}
	if eng.Tier != "engineer" || eng.Class != policy.EngineerClass || eng.PrivLvl != 15 || eng.WTI != "superuser" {
		t.Fatalf("engineer %+v", eng)
	}
	if n := len(eng.Commands); n != 34 {
		t.Errorf("engineer has %d Cisco rules, want 34 (docs say so)", n)
	}
	if last := eng.Commands[len(eng.Commands)-1]; last != policy.Catchall+"|permit|" {
		t.Errorf("last rule %q", last)
	}
	// No configuration-mode block: none of these names has a rule.
	for _, name := range []string{"aaa", "username", "enable", "tacacs", "tacacs-server", "radius", "radius-server",
		"snmp-server", "line", "login", "password", "privilege", "transport", "access-class", "authorization",
		"accounting", "parser", "service", "key", "ip", "crypto", "boot", "license", "event", "kron", "alias",
		"shell", "netconf-yang", "netconf", "restconf", "config-register", "logging", "no", "default"} {
		for _, l := range eng.Commands {
			if policy.Field(l, 1) == name {
				t.Errorf("engineer has a rule for %q (%s); engineers are unrestricted in configuration mode", name, l)
			}
		}
	}
}

// The 0.2.2 engineer preset did not hold: through the emulator, even with
// the new renderer's wrapping, its prefix forms matched only the exact
// one-word argument.
func TestPreset022Failed(t *testing.T) {
	old := policy.Engineer022Commands()
	rules := tqRules(old)
	for _, line := range []string{
		"no aaa new-model", "no tacacs server TACACS", "no username admin", "no line vty 0 4",
		"enable secret 9 $9$x", "ip ssh version 2", "ip http server", "key config-key password-encrypt m",
		"test aaa group tacacs+ u p legacy", "clear aaa counters servers all", "do reload in 5",
		"do copy tftp: running-config", "debug all x",
	} {
		for _, wrap := range []bool{false, true} {
			if !tqPermits(rules, wrap, line) {
				t.Errorf("0.2.2 preset (wrap=%v) denies %q; the failure the notice is about is gone from the test", wrap, line)
			}
		}
	}
}
