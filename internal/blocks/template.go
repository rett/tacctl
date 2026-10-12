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
			"#   set system login message <<'EOF'",
			"#   <the text, one line per line; ASCII, no tabs>",
			"#   EOF",
			"#   set system domain-name <name>",
			"#   set system domain-search <name>              (one line per entry)",
			"#   set system time-zone <Region/City | UTC>",
			"#   set system name-server <address>             (one line per entry)",
			"#   set system ntp server <address|name> [prefer] [version <1-4>] [key <n>] [routing-instance <name>]",
			"#   set system ntp boot-server <address|name>",
			"#   set system ntp source-address <address>",
			"#   set system ntp authentication-key <n> type md5|sha1|sha256 value <secret>",
			"#   set system ntp trusted-key <n>",
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
