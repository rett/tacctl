package blocks

// The text 'edit' opens for a block that does not exist yet (0.2.7, B5): the
// grammar of the block, what it may state and an example, all as '#' comment
// lines, so that a person who saves it unchanged has written a block that
// states nothing (which 'edit' refuses). The examples use documentation
// addresses and a string that is plainly a placeholder.

import "strings"

// Template is the commented text of a new block of the given name at the
// given layer.
func Template(block string, layer Layer) string {
	var l []string
	add := func(s ...string) { l = append(l, s...) }
	level := "scope"
	if layer == LayerDevice {
		level = "device"
	}
	switch block {
	case BlockSNMP:
		add(
			"# The snmp block of this "+level+" (Junos). One 'set' statement per line; blank lines and",
			"# lines that start with '#' are comments. Save to install it (the check runs",
			"# first); quit without saving to leave things as they are.",
			"#",
			"# What a snmp block states (a community, a trap group or a trap-options leaf",
			"# becomes an object tacctl owns: the plan sets it and removes the statements",
			"# of it that this block does not state):",
			"#",
			"#   set snmp community <string> authorization read-only|read-write",
			"#   set snmp community <string> clients <address/length> [restrict]",
			"#   set snmp community <string> client-list-name <list>",
			"#   set snmp trap-group <name> version v1|v2",
			"#   set snmp trap-group <name> categories <category>",
			"#   set snmp trap-group <name> targets <address>",
			"#   set snmp trap-options agent-address outgoing-interface",
			"#   set snmp trap-options source-address <address>|lo0   (one; a scope's block states lo0 only: an address is one device's own)",
			"#   delete snmp community <string>   (not managed on this device; kept, never removed)",
			"#",
			"# A community needs clients or a client-list-name. tacctl's own community and",
			"# names (TACCTL-SNMP, TACCTL-VIEW, TACCTL-GROUP) are the structured settings'.",
			"#",
			"# Example (remove the '# ' to use it):",
			"#",
			"# set snmp community change-me-community authorization read-only",
			"# set snmp community change-me-community clients 192.0.2.0/24",
			"# set snmp trap-group change-me-traps version v2",
			"# set snmp trap-group change-me-traps categories link",
			"# set snmp trap-group change-me-traps targets 192.0.2.50",
		)
	case BlockSystem:
		add(
			"# The system block of this "+level+" (Junos). One 'set' statement per line; blank lines and",
			"# lines that start with '#' are comments. Save to install it (the check runs",
			"# first); quit without saving to leave things as they are.",
			"#",
			"# What a system block states (additive: a statement is set when the device",
			"# lacks it, and what the device holds besides is kept and listed):",
			"#",
			"#   set system login message <<'EOF'              (the text shown after the login)",
			"#   <the text, one line per line; ASCII, no tabs>",
			"#   EOF",
			"#   set system login announcement <<'EOF'         (the text shown before the login; same form)",
			"#   <the text>",
			"#   EOF",
			"#   set system domain-name <name>",
			"#   set system domain-search <name>              (one line per entry)",
			"#   set system time-zone <Region/City | UTC>",
			"#   set system name-server <address>             (one line per entry)",
			"#   set system ntp server <address|name> [prefer] [version <1-4>] [key <n>] [routing-instance <name>]",
			"#   set system ntp boot-server <address|name>",
			"#   set system ntp source-address <address>   (a device's own block only: an address is one device's own)",
			"#   set system ntp authentication-key <n> type md5|sha1|sha256 value <secret>",
			"#   set system ntp trusted-key <n>",
			"#   set system syslog host <address|name> <facility> <level>   (facility: any authorization change-log conflict-log",
			"#                                       daemon external firewall ftp interactive-commands kernel ntp pfe security user;",
			"#                                       level: any alert critical emergency error info none notice warning)",
			"#   set system syslog host <address|name> facility-override <authorization|daemon|ftp|kernel|local0-local7|user>",
			"#   set system syslog host <address|name> log-prefix <word>",
			"#   set system syslog host <address|name> explicit-priority",
			"#   set system syslog time-format year|millisecond",
			"#   set system syslog source-address <address>   (a device's own block only)",
			"#   set system login retry-options tries-before-disconnect <1-10> | backoff-threshold <1-3> | backoff-factor <5-10>",
			"#       | minimum-time <20-60> | maximum-time <20-300> | lockout-period <1-43200>   (one leaf a line)",
			"#   set system login password minimum-length <6-20> | minimum-changes <1-128>",
			"#       | change-type character-sets|set-transitions | format md5|sha1|sha256|sha512   (one leaf a line)",
			"#   delete system <statement>        (not managed on this device; kept, never removed)",
			"#",
			"# Example (remove the '# ' to use it; the heredoc's lines are the message):",
			"#",
			"# set system login message <<'EOF'",
			"# Authorized use only.",
			"# Activity is logged.",
			"# EOF",
			"# set system domain-name lab.example.net",
			"# set system time-zone UTC",
			"# set system name-server 192.0.2.53",
			"# set system ntp server 192.0.2.123 prefer",
		)
	}
	return strings.Join(l, "\n") + "\n"
}

// TemplateFor is Template for a vendor's block: the IOS blocks' are their
// grammars and an example.
func TemplateFor(vendor, block string, layer Layer) string {
	if vendor != VendorCisco {
		return Template(block, layer)
	}
	level := "scope"
	if layer == LayerDevice {
		level = "device"
	}
	if block == BlockSystem {
		return iosSystemTemplate(level)
	}
	l := []string{
		"# The snmp block of this " + level + " (IOS and IOS-XE). One statement per line; blank lines and",
		"# lines that start with '#' or '!' are comments. Save to install it (the check runs",
		"# first); quit without saving to leave things as they are.",
		"#",
		"# What a snmp block states (a community or an access list becomes an object tacctl",
		"# owns: the plan sets its line, and removes the entries of a list that this block",
		"# does not state; a host and an 'enable traps' statement are only added):",
		"#",
		"#   snmp-server community <string> RO|RW [<acl-name>]",
		"#   snmp-server host <address> [vrf <name>] [informs|traps] [version 1|2c] <community> [udp-port <n>] [<type> ...]",
		"#   snmp-server enable traps [<type> [<subtype> ...]]",
		"#   snmp-server trap-source <interface>   (one, written in full: Loopback0; a scope's block states a loopback only)",
		"#   ip access-list standard <NAME>",
		"#    permit <address> [<wildcard>] | permit host <address> | permit any",
		"#   no snmp-server community <string>   (not managed on this device; kept, never removed)",
		"#",
		"# An access list the block defines is owned whole; one it only names is the",
		"# device's own and is kept. A read-write community needs a list without 'permit any'.",
		"# tacctl's own community and names (TACCTL-SNMP, TACCTL-VIEW, TACCTL-GROUP) are the",
		"# structured settings'; write an 'enable traps' line as the device prints it. A host is",
		"# one object per address, vrf, kind (traps or informs), udp-port and community: the",
		"# same address as traps and as informs is two hosts. Informs need 'version 2c'.",
		"# tacctl does not create a vrf: a host that names one the device lacks is refused by",
		"# the device when the plan is pasted.",
		"#",
		"# Example (remove the '# ' to use it):",
		"#",
		"# ip access-list standard POLLERS",
		"#  permit host 192.0.2.10",
		"#  permit 198.51.100.0 0.0.0.255",
		"# snmp-server community change-me-community RO POLLERS",
		"# snmp-server host 192.0.2.50 version 2c change-me-traps",
		"# snmp-server enable traps config",
	}
	return strings.Join(l, "\n") + "\n"
}

// iosSystemTemplate is the text 'edit' opens for a new IOS system block.
func iosSystemTemplate(level string) string {
	l := []string{
		"# The system block of this " + level + " (IOS and IOS-XE). One statement per line; blank lines and",
		"# lines that start with '#' or '!' are comments (inside the banner heredoc every line is text).",
		"# Save to install it (the check runs first); quit without saving to leave things as",
		"# they are.",
		"#",
		"# What a system block states (additive: a statement is set when the device lacks it,",
		"# and what the device holds besides is kept and listed):",
		"#",
		"#   banner login <<'EOF'",
		"#   <the text, one line per line; ASCII, no tabs, at most 20 lines of 80 characters>",
		"#   EOF",
		"#   ip domain name <name>",
		"#   ip domain name vrf <vrf> <name>              (one per vrf)",
		"#   ip domain list <name>                        (one line per entry)",
		"#   ip domain list vrf <vrf> <name>",
		"#   clock timezone <zone> <hours> [<minutes>]",
		"#   ip name-server <address> [<address> ...]",
		"#   ip name-server vrf <vrf> <address> [<address> ...]",
		"#   ntp server <address|name> [prefer] [version <1-4>] [key <n>] [source <interface>]   (source: a device's block, or a loopback)",
		"#   ntp server vrf <vrf> <address|name> [prefer] [version <1-4>] [key <n>] [source <interface>]   (source: a device's block, or a loopback)",
		"#   ntp authentication-key <n> md5 <string>      (typed only where the device lacks a key of that number)",
		"#   ntp trusted-key <n>",
		"#   ntp authenticate",
		"#   logging host <address|name> [vrf <vrf>]      (one line per host)",
		"#   logging trap <severity>",
		"#   logging buffered <4096-2147483647> [<severity>]",
		"#   logging origin-id hostname",
		"#   service timestamps log|debug datetime msec [localtime] [show-timezone]",
		"#   login on-failure log [every <1-65535>]",
		"#   login on-success log [every <1-65535>]",
		"#   login delay <1-10>",
		"#   security passwords min-length <1-16>",
		"#   security authentication failure rate <2-1024> log",
		"#   ip ssh version 2",
		"#   ip ssh time-out <1-120>",
		"#   ip ssh authentication-retries <0-5>",
		"#   clock summer-time <zone> [recurring [<week> <day> <month> <hh:mm> <week> <day> <month> <hh:mm> [<offset-minutes>]]]",
		"#   no <statement>                               (not managed on this device; kept, never removed)",
		"#",
		"# The banner is typed with a delimiter character tacctl picks from ^ ~ % # @ $ &",
		"# that the text does not contain. A statement with a vrf is another object than the",
		"# same statement without one. tacctl does not create a vrf: a block that names one",
		"# the device lacks is refused by the device when the plan is pasted. A key works only",
		"# with 'ntp authenticate' and 'ntp trusted-key' on the device.",
		"#",
		"# Example (remove the '# ' to use it; the heredoc's lines are the banner):",
		"#",
		"# banner login <<'EOF'",
		"# Authorized use only.",
		"# Activity is logged.",
		"# EOF",
		"# ip domain name lab.example.net",
		"# clock timezone UTC 0",
		"# ip name-server 192.0.2.53",
		"# ntp server 192.0.2.123 prefer",
		"# logging host 192.0.2.50",
		"# logging trap warnings",
		"# service timestamps log datetime msec localtime show-timezone",
		"# ip ssh version 2",
	}
	return strings.Join(l, "\n") + "\n"
}

// CommentOut is text with '# ' in front of every line (a blank line is just
// '#'): the objects of a layer shown beneath the block that may override
// them.
func CommentOut(text string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if l == "" {
			out = append(out, "#")
			continue
		}
		out = append(out, "# "+l)
	}
	return strings.Join(out, "\n") + "\n"
}
