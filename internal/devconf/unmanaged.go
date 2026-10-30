package devconf

// The device's own statements (0.2.7): an extra statement of the 'snmp'
// section that the planner leaves on the device by rule is unmanaged, not a
// difference. A section that lacks nothing and differs only by such
// statements reads ok, with their number (SectionResult.Unmanaged).
//
// The principle is the planner's: a statement it leaves alone and that is
// about the device, not about who can log in or which method asks the
// server, is the device's own. A statement that decides who can
// authenticate stays a finding whether the planner removes it or leaves it.
//
// The shapes mirror the Kept column of the planner's ownership rows
// (plan/owned.go, named by Row; a test there keeps the two in step) and the
// statements of no row at all ('snmp name', the engine id, 'snmp-server
// host'). A trap group is the device's own unless a configuration block
// names it (0.2.7). The 'snmp', 'system', 'netconf' and 'aaa' sections have
// them; an extra of the other sections (a login class, a filter, a user
// nobody recorded) is a finding about who can log in, and stays a
// difference.
//
// In the 'aaa' section the device's own are the leaves under the server
// block tacctl renders that the rendering does not state (a source address,
// a timeout, a retry count, a routing instance) and the options of the
// client ('tacplus-options', 'radius-options') that do not decide who can
// log in or what they may do. A leaf the rendering states with another value
// is a difference, which the plan replaces in place. A TACACS+ port is never
// the device's own: the rendering states it only for a listener that is not
// on the default, so a port on the device against a server on the default is
// the device asking the wrong port. Another server or server block, another
// group, a method list or a login list of another name, the login leaf of a
// line and the options that change the service asked for or how a password
// is checked are findings: they decide who can authenticate, which method is
// asked or what the login gets. The source interface ('ip tacacs
// source-interface') and the other leaves of a line never reach the section
// when the rendering states none (the extraction leaves them out), so they
// need no shape.
//
// A WTI unit (wti.go) has its own: the system name and the trap settings of
// the snmp section, the RADIUS items the walkthrough leaves alone, the whole
// page of the protocol the scope does not use while the device has it off,
// and the tail of the IP tables list. A read/write community, a second
// server, the other protocol turned on and every local account are
// findings.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// keptShape is one shape of statement the planner keeps by rule.
type keptShape struct {
	// Row is the ownership row whose Kept column the shape is ("" for a
	// statement of no row).
	Row string
	// Pattern is the statement's first words, space separated; '$' is the
	// name of an object.
	Pattern string
	// keep reports whether a statement of the pattern is the device's own:
	// name is the word at '$' and prefix the pattern's words with it filled
	// in.
	keep func(name string, prefix []string, exp *renderedSet) bool
	// keepStmt, when set, decides instead of keep, from the statement's
	// whole words (a trap host is told by its community, which is not at
	// the pattern's '$').
	keepStmt func(words []string, exp *renderedSet) bool
}

// The tests of the shapes.
var (
	// another community: its label is '<other:N>' (the bare mark of an
	// older record cannot be told apart, so it is not), or the label of a
	// string the rendering names only as a trap group
	otherCommunity = func(name string, _ []string, exp *renderedSet) bool {
		return IsOtherLabel(name) || IsLabel(name) && !exp.community[name]
	}
	// a trap group the rendering (a block) does not name: another's label,
	// or the label of a string the rendering has as a community only. The
	// bare mark of an older record cannot be told apart, and is left alone
	// as it always was.
	otherTrapGroup = func(name string, _ []string, exp *renderedSet) bool {
		return name == secretMark || !exp.trapGroup[name]
	}
	// an object of a name the rendering does not set
	notRendered = func(_ string, prefix []string, exp *renderedSet) bool { return !exp.has(prefix) }
	// a statement the rendering has nothing of
	always = func(string, []string, *renderedSet) bool { return true }
	// an IOS trap host (an entry of an address, vrf, kind, udp-port and
	// community) the rendering (a block) does not state: a host the rendering
	// states with another version or other types is a difference, which the
	// plan replaces in place. The bare mark of an older record cannot be told
	// apart, and is left alone as it always was.
	otherHost = func(words []string, exp *renderedSet) bool {
		i := SNMPHostCommunity(words)
		if i < 0 {
			return true
		}
		return !exp.hosts[SNMPHostID(words, i, words[i])]
	}
	// an IOS NTP server the rendering (a system block) does not state: one
	// it states with other options is a difference, which the plan replaces
	// in place. A host in a vrf is another object than the same host without
	// one.
	otherNTPServer = func(words []string, exp *renderedSet) bool {
		id := ntpServerID(words)
		return id == "" || !exp.ntp[id]
	}
	// the IOS domain name: the device's own where the rendering states none
	// for the same vrf (the one without a vrf and each vrf's are objects of
	// their own: a rendering that states only a vrf's leaves the global one
	// to the device)
	otherDomainName = func(words []string, exp *renderedSet) bool {
		if len(words) >= 5 && words[3] == "vrf" {
			return !exp.has(words[:5])
		}
		return !slices.ContainsFunc(exp.words, func(w []string) bool {
			return len(w) >= 4 && w[0] == "ip" && w[1] == "domain" && w[2] == "name" && w[3] != "vrf"
		})
	}
	// a leaf under the server block tacctl renders (Junos 'system
	// tacplus-server <addr> <leaf>', IOS 'tacacs server <name> <leaf>') that
	// the rendering says nothing of: the device's own (a source address, a
	// timeout, a routing instance). The leaf keyword decides, as it does for
	// the planner; a leaf the rendering states, with another value, is a
	// difference, and every leaf of another server is a finding (that server
	// is not tacctl's). A TACACS+ 'port' is a finding when the rendering
	// states none: it states one only for a listener off the default port, so
	// the device's is then the wrong one and no login reaches the server. (The
	// RADIUS ports are always rendered.)
	ownServerLeaf = func(words []string, exp *renderedSet) bool {
		if len(words) < 4 || !exp.has(words[:3]) || exp.has(words[:4]) {
			return false
		}
		tacacs := words[0] == "tacacs" || words[1] == "tacplus-server"
		return !tacacs || words[3] != "port"
	}
	// a leaf of the client's options ('system tacplus-options <leaf>',
	// 'system radius-options <leaf>') the rendering says nothing of: the
	// device's own, but for the options that change the service asked for or
	// how a password is checked (below), which decide what a login gets.
	ownClientOption = func(words []string, exp *renderedSet) bool {
		if len(words) < 3 || exp.has(words[:3]) {
			return false
		}
		switch leaf := words[1] + " " + words[2]; leaf {
		case "tacplus-options service-name":
			// junos-exec is what tacctl's policy answers to, and what Junos
			// asks for with none set; another service is never answered
			return len(words) >= 4 && words[3] == "junos-exec"
		case "tacplus-options strict-authorization", "radius-options password-protocol":
			return false
		}
		return true
	}
)

// keptShapes are the shapes per family; the first whose pattern a statement
// starts with decides.
var keptShapes = map[string][]keptShape{
	FamilyJunos: {
		{Row: "junos.snmp.community", Pattern: "snmp community $", keep: otherCommunity},
		{Row: "junos.snmp.trap-group", Pattern: "snmp trap-group $", keep: otherTrapGroup},
		{Row: "junos.snmp.trap-options", Pattern: "snmp trap-options $", keep: notRendered},
		{Row: "junos.snmp.client-list", Pattern: "snmp client-list $", keep: notRendered},
		{Row: "junos.snmp.v3-user", Pattern: "snmp v3 usm local-engine user $", keep: notRendered},
		{Row: "junos.snmp.v3-group", Pattern: "snmp v3 vacm security-to-group security-model usm security-name $", keep: notRendered},
		{Row: "junos.snmp.v3-access", Pattern: "snmp v3 vacm access group $", keep: notRendered},
		{Row: "junos.snmp.view", Pattern: "snmp view $", keep: notRendered},
		{Row: "junos.snmp.location", Pattern: "snmp location", keep: notRendered},
		{Row: "junos.snmp.contact", Pattern: "snmp contact", keep: notRendered},
		{Row: "junos.snmp.description", Pattern: "snmp description", keep: notRendered},
		// no row: the name, the engine id, the rest of v3 and anything else
		// under 'snmp'
		{Pattern: "snmp", keep: always},
		// The aaa section: the leaves of tacctl's server the rendering says
		// nothing of, and the options of the client. Another server is a
		// finding.
		{Row: "junos.aaa.tacplus", Pattern: "system tacplus-server $ $", keepStmt: ownServerLeaf},
		{Row: "junos.aaa.tacplus", Pattern: "system tacplus-options $", keepStmt: ownClientOption},
		{Row: "junos.aaa.radius", Pattern: "system radius-server $ $", keepStmt: ownServerLeaf},
		{Row: "junos.aaa.radius", Pattern: "system radius-options $", keepStmt: ownClientOption},
		// The system section (0.2.7) is additive: what the device holds
		// beside the block's statements is its own, and a single value the
		// block states and the device holds otherwise is a difference (the
		// plan replaces it in place), so each shape keeps a statement only
		// where the rendering says nothing of the same object. The options of
		// an NTP server come before the server itself.
		{Row: "junos.system.login-message", Pattern: "system login message", keep: notRendered},
		{Row: "junos.system.announcement", Pattern: "system login announcement", keep: notRendered},
		// 0.2.19: syslog, the login retry options and the password policy. The
		// options of a host come before the host's facility lines, which
		// would match them; the device's other syslog statements (files,
		// console, users) are its own, and so are the other leaves of the
		// retry options and the password policy.
		{Row: "junos.system.syslog-facility-override", Pattern: "system syslog host $ facility-override", keep: notRendered},
		{Row: "junos.system.syslog-log-prefix", Pattern: "system syslog host $ log-prefix", keep: notRendered},
		{Row: "junos.system.syslog-explicit-priority", Pattern: "system syslog host $ explicit-priority", keep: notRendered},
		{Row: "junos.system.syslog-host", Pattern: "system syslog host $ $", keep: notRendered},
		{Row: "junos.system.syslog-time-format", Pattern: "system syslog time-format $", keep: notRendered},
		{Row: "junos.system.syslog-source-address", Pattern: "system syslog source-address", keep: notRendered},
		{Pattern: "system syslog", keep: always},
		{Row: "junos.system.retry-option", Pattern: "system login retry-options $", keep: notRendered},
		{Row: "junos.system.password-policy", Pattern: "system login password $", keep: notRendered},
		{Row: "junos.system.domain-name", Pattern: "system domain-name", keep: notRendered},
		{Row: "junos.system.time-zone", Pattern: "system time-zone", keep: notRendered},
		{Row: "junos.system.domain-search", Pattern: "system domain-search $", keep: notRendered},
		{Row: "junos.system.name-server", Pattern: "system name-server $", keep: notRendered},
		{Row: "junos.system.ntp-boot-server", Pattern: "system ntp boot-server", keep: notRendered},
		{Row: "junos.system.ntp-source-address", Pattern: "system ntp source-address", keep: notRendered},
		{Row: "junos.system.ntp-server-version", Pattern: "system ntp server $ version", keep: notRendered},
		{Row: "junos.system.ntp-server-key", Pattern: "system ntp server $ key", keep: notRendered},
		{Row: "junos.system.ntp-server-routing-instance", Pattern: "system ntp server $ routing-instance", keep: notRendered},
		{Row: "junos.system.ntp-server", Pattern: "system ntp server $ prefer", keep: notRendered},
		{Row: "junos.system.ntp-server", Pattern: "system ntp server $", keep: notRendered},
		{Row: "junos.system.ntp-key", Pattern: "system ntp authentication-key $", keep: notRendered},
		{Row: "junos.system.ntp-trusted-key", Pattern: "system ntp trusted-key $", keep: notRendered},
		// no row: the rest of 'system ntp' (threshold, interval-range, ...)
		{Pattern: "system ntp", keep: always},
		// The NETCONF service (0.2.10): a limit the setting states and the
		// device holds otherwise is a difference (the plan replaces it in
		// place); a limit the setting states none of, the bare 'ssh' and every
		// other statement under the service are the device's own.
		{Row: "junos.netconf.connection-limit", Pattern: "system services netconf ssh connection-limit", keep: notRendered},
		{Row: "junos.netconf.rate-limit", Pattern: "system services netconf ssh rate-limit", keep: notRendered},
		{Row: "junos.netconf.ssh", Pattern: "system services netconf ssh", keep: always},
		// no row: the rest of the service (a trace option, ...)
		{Pattern: "system services netconf", keep: always},
	},
	FamilyWTI: wtiShapes,
	FamilyIOS: {
		{Row: "ios.snmp.community", Pattern: "snmp-server community $", keep: otherCommunity},
		{Row: "ios.snmp.location", Pattern: "snmp-server location", keep: notRendered},
		{Row: "ios.snmp.contact", Pattern: "snmp-server contact", keep: notRendered},
		{Row: "ios.snmp.acl", Pattern: "ip access-list standard $", keep: notRendered},
		{Pattern: "snmp-server view $", keep: notRendered},
		{Pattern: "snmp-server group $", keep: notRendered},
		{Pattern: "snmp-server user $", keep: notRendered},
		// 0.2.7: the SNMP block's hosts and 'enable traps' lines are only
		// ever added (a host the block states with other options is replaced
		// in place); the device's others are its own
		{Row: "ios.snmp.block-host", Pattern: "snmp-server host $", keepStmt: otherHost},
		{Row: "ios.snmp.block-traps", Pattern: "snmp-server enable traps", keep: always},
		// the trap source: the device's own is kept while the rendering
		// states none, and replaced in place where it states one
		{Row: "ios.snmp.block-trap-source", Pattern: "snmp-server trap-source", keep: notRendered},
		// no row: the rest of 'snmp-server'
		{Pattern: "snmp-server", keep: always},
		// The aaa section: the leaves of tacctl's server block the rendering
		// says nothing of. Another server block, the legacy host lines, a
		// group's leaves and the login leaves of the lines are findings.
		{Row: "ios.aaa.server-block", Pattern: "tacacs server $ $", keepStmt: ownServerLeaf},
		{Row: "ios.aaa.radius-block", Pattern: "radius server $ $", keepStmt: ownServerLeaf},
		// The system section (0.2.7) is additive, as on Junos: what the
		// device holds beside the block's statements is its own, and a single
		// value the block states and the device holds otherwise is a
		// difference (the plan replaces it in place), so each shape keeps a
		// statement only where the rendering says nothing of the same object.
		{Row: "ios.system.banner", Pattern: "banner login", keep: notRendered},
		{Row: "ios.system.banner-motd", Pattern: "banner motd", keep: notRendered},
		{Row: "ios.system.banner-exec", Pattern: "banner exec", keep: notRendered},
		// 0.2.19: logging, the login and password policy, ssh, summer time
		{Row: "ios.system.logging-host", Pattern: "logging host $", keep: notRendered},
		{Row: "ios.system.logging-trap", Pattern: "logging trap", keep: notRendered},
		{Row: "ios.system.logging-buffered", Pattern: "logging buffered", keep: notRendered},
		{Row: "ios.system.logging-origin-id", Pattern: "logging origin-id", keep: notRendered},
		{Row: "ios.system.timestamps", Pattern: "service timestamps $", keep: notRendered},
		{Row: "ios.system.login-on-failure", Pattern: "login on-failure", keep: notRendered},
		{Row: "ios.system.login-on-success", Pattern: "login on-success", keep: notRendered},
		{Row: "ios.system.login-delay", Pattern: "login delay", keep: notRendered},
		{Row: "ios.system.passwords-min-length", Pattern: "security passwords min-length", keep: notRendered},
		{Row: "ios.system.auth-failure-rate", Pattern: "security authentication failure rate", keep: notRendered},
		{Row: "ios.system.ssh-version", Pattern: "ip ssh version", keep: notRendered},
		{Row: "ios.system.ssh-timeout", Pattern: "ip ssh time-out", keep: notRendered},
		{Row: "ios.system.ssh-retries", Pattern: "ip ssh authentication-retries", keep: notRendered},
		{Row: "ios.system.summer-time", Pattern: "clock summer-time", keep: notRendered},

		{Row: "ios.system.domain-name", Pattern: "ip domain name", keepStmt: otherDomainName},
		// a vrf form is an object of its own (the shape with the vrf comes
		// first, the pattern of the list without one would take its words)
		{Row: "ios.system.domain-list", Pattern: "ip domain list vrf $ $", keep: notRendered},
		{Row: "ios.system.domain-list", Pattern: "ip domain list $", keep: notRendered},
		{Row: "ios.system.timezone", Pattern: "clock timezone", keep: notRendered},
		{Row: "ios.system.name-server", Pattern: "ip name-server vrf $ $", keep: notRendered},
		{Row: "ios.system.name-server", Pattern: "ip name-server $", keep: notRendered},
		{Row: "ios.system.ntp-server", Pattern: "ntp server $", keepStmt: otherNTPServer},
		{Row: "ios.system.ntp-key", Pattern: "ntp authentication-key $", keep: notRendered},
		{Row: "ios.system.ntp-trusted-key", Pattern: "ntp trusted-key $", keep: notRendered},
		{Row: "ios.system.ntp-authenticate", Pattern: "ntp authenticate", keep: notRendered},
		// no row: the rest of 'ntp' (master, source, peer, access-group, ...)
		{Pattern: "ntp", keep: always},
	},
}

// KeptShape is one of the shapes as data, for the test that keeps them in
// step with the ownership rows.
type KeptShape struct {
	Row, Pattern string
}

// KeptShapes returns the shapes of a family.
func KeptShapes(family string) []KeptShape {
	var out []KeptShape
	for _, s := range keptShapes[family] {
		out = append(out, KeptShape{Row: s.Row, Pattern: s.Pattern})
	}
	return out
}

// renderedSet is what the rendering says, for the shapes: the words of its
// statements, and the labels of the names under the objects whose origin
// matters (a block's trap group is the plan's; so is no community that the
// rendering does not name as one).
type renderedSet struct {
	words [][]string
	// community are the labels of the names the rendering sets under
	// 'snmp community' (the structured settings' and a block's), trapGroup
	// those under 'snmp trap-group' that a configuration block sets (the
	// structured settings have no trap group).
	community, trapGroup map[string]bool
	// hosts are the trap hosts the rendering sets, by SNMPHostID (address, vrf,
	// kind, udp-port and the label of their community; IOS).
	hosts map[string]bool
	// ntp are the NTP servers the rendering sets, by host in lower case
	// (IOS).
	ntp map[string]bool
	// wtiInactive are the protocols (tacacs, radius) of a WTI unit that the
	// rendering does not use and the device has turned off: their whole
	// page is the device's own (wti.go).
	wtiInactive map[string]bool
	// wtiProto is the protocol the rendering is for.
	wtiProto string
}

// has reports whether a rendered statement starts with the words.
func (r *renderedSet) has(prefix []string) bool {
	return slices.ContainsFunc(r.words, func(w []string) bool { return len(w) >= len(prefix) && slices.Equal(w[:len(prefix)], prefix) })
}

// newRenderedSet is the rendering of a section as the shapes read it. lb is
// the comparison's labels (nil for a record of an older tacctl).
func newRenderedSet(fam string, section devices.Section, exp []stmt, lb *labels) *renderedSet {
	rs := &renderedSet{community: map[string]bool{}, trapGroup: map[string]bool{}, hosts: map[string]bool{}, ntp: map[string]bool{}}
	for _, e := range exp {
		rs.words = append(rs.words, stmtWords(fam, e))
	}
	if fam == FamilyWTI {
		return rs
	}
	if fam != FamilyJunos {
		for _, line := range section.Lines {
			f := strings.Fields(line)
			switch {
			case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
				rs.community[lb.of(f[2])] = true
			case SNMPHostCommunity(f) > 0:
				i := SNMPHostCommunity(f)
				rs.hosts[SNMPHostID(f, i, lb.of(f[i]))] = true
			case len(f) >= 3 && f[0] == "ntp" && f[1] == "server":
				rs.ntp[ntpServerID(f)] = true
			}
		}
		return rs
	}
	for i, line := range section.Lines {
		head, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		if head != "set" {
			continue
		}
		for _, ts := range expand(tokenize(rest)) {
			if len(ts) < 3 || ts[0].s != "snmp" {
				continue
			}
			switch ts[1].s {
			case "community":
				rs.community[lb.of(ts[2].s)] = true
			case "trap-group":
				if i < len(section.Block) && section.Block[i] {
					rs.trapGroup[lb.of(ts[2].s)] = true
				}
			}
		}
	}
	return rs
}

// stmtWords are a statement's words: the Junos path, or the IOS context and
// line split.
func stmtWords(fam string, x stmt) []string {
	if fam == FamilyJunos {
		return x.path
	}
	return strings.Fields(strings.Join(x.path, " "))
}

// unmanaged reports an extra statement of a section that is the device's
// own by rule. A deactivated statement is a finding of its own.
func unmanaged(fam, section string, x stmt, rs *renderedSet) bool {
	if fam == FamilyWTI {
		if section != SectionAAA && section != SectionSNMP && section != SectionMgmtACL {
			return false
		}
		if wtiKept(section, x, rs) {
			return true
		}
	} else if section != SectionSNMP && section != SectionSystem && section != SectionAAA && (fam != FamilyJunos || section != SectionNetconf) ||
		strings.HasPrefix(x.stem, "deactivate ") {
		return false
	}
	words := stmtWords(fam, x)
	for _, s := range keptShapes[fam] {
		pat := strings.Fields(s.Pattern)
		if len(words) < len(pat) {
			continue
		}
		name, ok := "", true
		for i, p := range pat {
			switch {
			case p == "$":
				name = words[i]
			case p != words[i]:
				ok = false
			}
		}
		if ok {
			if s.keepStmt != nil {
				return s.keepStmt(words, rs)
			}
			return s.keep(name, words[:len(pat)], rs)
		}
	}
	return false
}
