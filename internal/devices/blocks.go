package devices

// The configuration blocks of a scope as the renderers read them (0.2.7,
// docs/plans/0.2.7-blocks-plan.md B3). A block is vendor syntax that tacctl
// owns beside the structured settings; the CLI resolves the scope's blocks
// once (internal/policy, internal/blocks) and hands them over in Data.Blocks.
// Nothing here reads a file: the renderers stay pure, and a batch shares the
// resolved block between its devices.
//
// Only the Junos blocks exist in this release (snmp and system). A Cisco
// request ignores Data.Blocks (IOS blocks are the release after), whatever it
// holds.

import (
	"fmt"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/names"
)

// Blocks are a scope's configuration blocks in force, resolved for one
// device: the scope's layer today, the device's own over it in B8.
type Blocks struct {
	// Scope names the scope the blocks are of (the comment lines of the
	// walkthrough and the report's words name it).
	Scope string
	// SNMP is the Junos snmp block: other communities with their clients,
	// trap groups and trap options. Nil is "no block in force". It holds
	// community strings, which are secrets: nothing prints it but the
	// statements the walkthrough and the plan type.
	SNMP *blocks.SNMPBlock
	// System is the Junos system block: the login message, domain name and
	// search list, time zone, name servers and NTP. Nil is "no block in
	// force": the managed system section is then not rendered at all. It
	// holds a NTP key's value, which is a secret, and a login message, a
	// banner that names a site: nothing prints it but the statements the
	// walkthrough and the plan type.
	System *blocks.SystemBlock
}

// snmpStatements are the 'set' lines of the snmp block, in the order
// blocks.Statements gives them (none for no block).
func (b Blocks) snmpStatements() []string {
	if b.SNMP == nil {
		return nil
	}
	return blocks.Statements(b.SNMP)
}

// systemStatements are the 'set' lines of the system block, in the order
// blocks.SystemStatements gives them (none for no block).
func (b Blocks) systemStatements() []string {
	if b.System == nil {
		return nil
	}
	return blocks.SystemStatements(b.System)
}

// systemLines are the lines of the system block in the walkthrough: a comment
// that names the scope's block (never the message, never a key), then its
// statements as live lines. None when the scope has no system block.
func (b Blocks) systemLines(scope string) []string {
	st := b.systemStatements()
	if len(st) == 0 {
		return nil
	}
	if b.Scope != "" {
		scope = b.Scope
	}
	out := []string{"# The system block of scope '" + scope + "' (tacctl scope block " + scope + " juniper show system): the login message, domain, time zone, name servers and NTP."}
	return append(out, st...)
}

// systemHierarchies are the 'show configuration' arguments that read back
// what the system block states, in the order of its statements.
func systemHierarchies(b *blocks.SystemBlock) []string {
	if b == nil {
		return nil
	}
	var out []string
	add := func(on bool, h string) {
		if on {
			out = append(out, h)
		}
	}
	add(b.Message != nil, "system login message")
	add(b.DomainName != nil, "system domain-name")
	add(len(b.DomainSearch) > 0, "system domain-search")
	add(b.TimeZone != nil, "system time-zone")
	add(len(b.NameServers) > 0, "system name-server")
	add(len(b.NTPServers) > 0 || b.NTPBootServer != nil || b.NTPSourceAddress != nil || len(b.NTPKeys) > 0 || len(b.NTPTrustedKeys) > 0, "system ntp")
	return out
}

// snmpClientPermits are the filter's SNMP permits with the clients of the
// block's communities added: each unrestricted IPv4 client prefix once, after
// the structured ones, in the block's order ('restrict' entries and IPv6
// ones are no permit of an inet filter). The second result is true when a
// community names a client list, whose addresses live on the device and are
// not visible here.
func (b Blocks) snmpClientPermits(base []string) ([]string, bool) {
	if b.SNMP == nil {
		return base, false
	}
	out := append([]string(nil), base...)
	seen := make(map[string]bool, len(out))
	for _, e := range out {
		seen[e] = true
	}
	list := false
	for _, c := range b.SNMP.Communities {
		if c.ClientListName != "" {
			list = true
		}
		for _, cl := range c.Clients {
			if cl.Restrict || !cl.Prefix.Addr().Is4() {
				continue
			}
			if e := cl.Prefix.String(); !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out, list
}

// blockSNMPSet is the set of the snmp block's statements, to tell them from
// the structured settings' in the managed snmp section (the two never share
// a statement: a block may not name tacctl's own community or client list).
func (d Data) blockSNMPSet() map[string]bool {
	st := d.Blocks.snmpStatements()
	if len(st) == 0 {
		return nil
	}
	out := make(map[string]bool, len(st))
	for _, s := range st {
		out[s] = true
	}
	return out
}

// blockProblem is the refusal of a rendering that cannot be right: a block
// community whose string is the one the structured SNMP settings render
// (the device could not hold both, and the plan could not tell whose leaves
// are whose). The CLI verbs of the blocks refuse it earlier; this is the
// backstop, for a block file and a scope community that were both fine
// when written. The text names the community by its place in the block,
// never by its string.
func (d Data) blockProblem(req Request) error {
	if req.Vendor != "juniper" || d.Blocks.SNMP == nil {
		return nil
	}
	in := d.SNMP
	if in.Version != snmpV2c || in.Community == "" {
		return nil
	}
	scope := d.Blocks.Scope
	if scope == "" {
		scope = req.Scope
	}
	for i, c := range d.Blocks.SNMP.Communities {
		if c.String == in.Community {
			// one line: a batch keeps the first line of a refusal as the
			// device's reason
			return &names.Error{Msgs: []string{
				fmt.Sprintf("Community %d of the SNMP block of scope '%s' is the community the scope's own SNMP settings render, and a device cannot hold both: "+
					"remove it from the block (tacctl scope block %s juniper edit snmp) or give the scope another community (tacctl scope snmp %s community).",
					i+1, scope, scope, scope),
			}}
		}
	}
	return nil
}
