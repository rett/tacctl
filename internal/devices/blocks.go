package devices

// The configuration blocks of a scope as the renderers read them (0.2.7,
// docs/plans/0.2.7-blocks-plan.md B3). A block is vendor syntax that tacctl
// owns beside the structured settings; the CLI resolves the scope's blocks
// once (internal/policy, internal/blocks) and hands them over in Data.Blocks.
// Nothing here reads a file: the renderers stay pure, and a batch shares the
// resolved block between its devices.
//
// The Junos blocks are snmp and system (SNMP, System); the IOS blocks are
// snmp and system (CiscoSNMP, CiscoSystem). A request renders the blocks of
// its own vendor: a Cisco request reads CiscoSNMP and CiscoSystem and ignores
// the rest, a Junos request reads SNMP and System and ignores the IOS ones,
// whatever Data.Blocks holds.

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/names"
)

// BlockLayer says which layers of the resolution a resolved block was made
// of. The zero value is the scope's block alone, which is what a Blocks
// built without layers means.
type BlockLayer int

const (
	// LayerScope is the scope's block alone.
	LayerScope BlockLayer = iota
	// LayerScopeDevice is the scope's block with the device's own over it.
	LayerScopeDevice
	// LayerDevice is the device's own block, the scope having none.
	LayerDevice
)

// Blocks are the configuration blocks in force for one device, resolved: the
// scope's layer with the device's own over it (per object: a device's
// community replaces the scope's of the same string whole).
type Blocks struct {
	// Scope names the scope the blocks are of (the comment lines of the
	// walkthrough and the report's words name it).
	Scope string
	// Device names the device whose own blocks are laid over the scope's;
	// empty when none is (SNMPLayer and SystemLayer then are LayerScope).
	Device string
	// SNMPLayer and SystemLayer say which layers each block is made of, for
	// the comment above its statements and the refusals that name the verb
	// that shows it.
	SNMPLayer, SystemLayer BlockLayer
	// ScopeSNMP and DeviceSNMP are the snmp block's layers as they were
	// written, when the resolution had them: only for the words of a
	// refusal, which names the layer that holds a community and its place
	// there. Nil is "not known": the resolved block's own order is used.
	ScopeSNMP, DeviceSNMP *blocks.SNMPBlock
	// SNMP is the Junos snmp block: other communities with their clients,
	// trap groups and trap options. Nil is "no block in force". It holds
	// community strings, which are secrets: nothing prints it but the
	// statements the walkthrough and the plan type.
	SNMP *blocks.SNMPBlock
	// CiscoSNMP is the IOS snmp block: communities with their access
	// lists, trap hosts and 'enable traps' statements. Nil is "no block in
	// force". It holds community strings, which are secrets: nothing prints
	// it but the statements the walkthrough and the plan type. SNMPLayer
	// says which layers it is made of, as for the Junos block.
	CiscoSNMP *blocks.IOSSNMPBlock
	// ScopeCiscoSNMP and DeviceCiscoSNMP are the IOS block's layers as they
	// were written, for the words of a refusal (as ScopeSNMP, DeviceSNMP).
	ScopeCiscoSNMP, DeviceCiscoSNMP *blocks.IOSSNMPBlock
	// System is the Junos system block: the login message, domain name and
	// search list, time zone, name servers and NTP. Nil is "no block in
	// force": the managed system section is then not rendered at all. It
	// holds a NTP key's value, which is a secret, and a login message, a
	// banner that names a site: nothing prints it but the statements the
	// walkthrough and the plan type.
	System *blocks.SystemBlock
	// CiscoSystem is the IOS system block: the login banner, domain name and
	// list, time zone, name servers and NTP. Nil is "no block in force": the
	// managed system section is then not rendered at all. SystemLayer says
	// which layers it is made of, as for the Junos block. It holds an NTP
	// key's string, which is a secret, and a banner that names a site: nothing
	// prints it but the statements the walkthrough and the plan type.
	CiscoSystem *blocks.IOSSystemBlock
	// ScopeSystem and DeviceSystem are the Junos system block's layers as
	// they were written, ScopeCiscoSystem and DeviceCiscoSystem the IOS one's:
	// for the comment above each statement that names the block it comes from
	// (blockOrigin). Nil is "not known" or "that layer has none".
	ScopeSystem, DeviceSystem           *blocks.SystemBlock
	ScopeCiscoSystem, DeviceCiscoSystem *blocks.IOSSystemBlock
}

// blockOrigin names the block a statement was written in, for the comment
// above it in a plan or a walkthrough, in the words of the verb that edits it
// (add "tacctl " in front and the verb before the block's name):
// "scope block lab juniper system" (tacctl scope block lab juniper edit
// system) or "device block sw1 system" (tacctl device block sw1 edit system).
// name is the block's own name (snmp, system) and vendor the vendor's (juniper,
// cisco), which only a scope's verb has.
func blockOrigin(layer, who, vendor, name string) string {
	if layer == "device" {
		return "device block " + who + " " + name
	}
	return "scope block " + who + " " + vendor + " " + name
}

// originsOf maps each statement of the layers as written to the layer that
// states it; the device's own wins where both state it. A statement that
// neither states (a default's, or a resolved one made of both) has no entry.
func originsOf(scopeLines, deviceLines []string, scope, device, vendor, name string) map[string]string {
	out := map[string]string{}
	for _, l := range scopeLines {
		out[l] = blockOrigin("scope", scope, vendor, name)
	}
	for _, l := range deviceLines {
		out[l] = blockOrigin("device", device, vendor, name)
	}
	return out
}

// snmpOrigins, systemOrigins, ciscoSNMPOrigins and ciscoSystemOrigins are the
// statement-to-block maps of the four blocks (nil when a block has no layer
// as written).
func (b Blocks) snmpOrigins() map[string]string {
	if b.ScopeSNMP == nil && b.DeviceSNMP == nil {
		return nil
	}
	return originsOf(blocks.Statements(b.ScopeSNMP), blocks.Statements(b.DeviceSNMP), b.Scope, b.Device, blocks.VendorJuniper, blocks.BlockSNMP)
}

func (b Blocks) systemOrigins() map[string]string {
	if b.ScopeSystem == nil && b.DeviceSystem == nil {
		return nil
	}
	return originsOf(blocks.SystemStatements(b.ScopeSystem), blocks.SystemStatements(b.DeviceSystem), b.Scope, b.Device, blocks.VendorJuniper, blocks.BlockSystem)
}

func (b Blocks) ciscoSNMPOrigins() map[string]string {
	if b.ScopeCiscoSNMP == nil && b.DeviceCiscoSNMP == nil {
		return nil
	}
	return originsOf(Blocks{CiscoSNMP: b.ScopeCiscoSNMP}.ciscoSNMPStatements(), Blocks{CiscoSNMP: b.DeviceCiscoSNMP}.ciscoSNMPStatements(),
		b.Scope, b.Device, blocks.VendorCisco, blocks.BlockSNMP)
}

func (b Blocks) ciscoSystemOrigins(d blocks.IOSDialect) map[string]string {
	if b.ScopeCiscoSystem == nil && b.DeviceCiscoSystem == nil {
		return nil
	}
	return originsOf(Blocks{CiscoSystem: b.ScopeCiscoSystem}.ciscoSystemStatements(d), Blocks{CiscoSystem: b.DeviceCiscoSystem}.ciscoSystemStatements(d),
		b.Scope, b.Device, blocks.VendorCisco, blocks.BlockSystem)
}

// snmpStatements are the 'set' lines of the Junos snmp block, in the order
// blocks.Statements gives them (none for no block).
func (b Blocks) snmpStatements() []string {
	if b.SNMP == nil {
		return nil
	}
	return blocks.Statements(b.SNMP)
}

// ciscoSNMPStatements are the lines of the IOS snmp block, in the order
// blocks.IOSSNMPStatements gives them (an access list's header and entries
// first, the entries indented by two blanks as the walkthrough indents them);
// none for no block.
func (b Blocks) ciscoSNMPStatements() []string {
	if b.CiscoSNMP == nil {
		return nil
	}
	lines := blocks.IOSSNMPStatements(b.CiscoSNMP)
	for i, l := range lines {
		if strings.HasPrefix(l, " ") {
			lines[i] = " " + l
		}
	}
	return lines
}

// systemStatements are the 'set' lines of the system block, in the order
// blocks.SystemStatements gives them (none for no block).
func (b Blocks) systemStatements() []string {
	if b.System == nil {
		return nil
	}
	return blocks.SystemStatements(b.System)
}

// ciscoSystemStatements are the lines of the IOS system block, in the order
// blocks.IOSSystemStatementsIn gives them (the banner's lines are the lines
// typed, its delimiter chosen), as a device in dialect d stores them; none for
// no block.
func (b Blocks) ciscoSystemStatements(d blocks.IOSDialect) []string {
	if b.CiscoSystem == nil {
		return nil
	}
	return blocks.IOSSystemStatementsIn(b.CiscoSystem, d)
}

// dialectOf is the IOS dialect of a request: the 12.x syntax when legacy.
func dialectOf(legacy bool) blocks.IOSDialect {
	if legacy {
		return blocks.IOS12
	}
	return blocks.IOSModern
}

// withOrigins is lines with a comment ("# from scope block lab juniper
// system") before the first line of each run that one block states, so a
// walkthrough says whose statement it types when the scope's block and the
// device's own are laid together (a block of one layer is named by its head
// already). lead is the vendor's comment word. Lines with no known origin, and a text with no origins, are as they
// were.
func withOrigins(lines []string, origins map[string]string, lead string) []string {
	if len(origins) == 0 {
		return lines
	}
	out := make([]string, 0, len(lines)+2)
	last := ""
	for _, l := range lines {
		if o := origins[strings.TrimRight(l, " ")]; o != "" && o != last {
			last = o
			out = append(out, lead+" from "+o)
		}
		out = append(out, l)
	}
	return out
}

// head is what a comment says of a block: the layers it is made of and the
// verb that shows it, never a string.
func (b Blocks) head(block string, layer BlockLayer, scope string) string {
	if b.Scope != "" {
		scope = b.Scope
	}
	dev := b.Device
	switch {
	case dev != "" && layer == LayerDevice:
		return "The " + block + " block of device '" + dev + "' (tacctl device block " + dev + " show " + block + ")"
	case dev != "" && layer == LayerScopeDevice:
		return "The " + block + " block of scope '" + scope + "' with the block of device '" + dev + "' over it (tacctl device block " + dev + " show " + block + " --effective)"
	}
	return "The " + block + " block of scope '" + scope + "' (tacctl scope block " + scope + " juniper show " + block + ")"
}

// snmpHead is the head of the snmp block's comment.
func (b Blocks) snmpHead(scope string) string { return b.head(blocks.BlockSNMP, b.SNMPLayer, scope) }

// ciscoSNMPHead is the head of the IOS snmp block's comment: the same words
// with the IOS verb.
func (b Blocks) ciscoSNMPHead(scope string) string {
	h := b.head(blocks.BlockSNMP, b.SNMPLayer, scope)
	return strings.ReplaceAll(h, " juniper show ", " cisco show ")
}

// ciscoSystemHead is the head of the IOS system block's comment: the same
// words with the IOS verb.
func (b Blocks) ciscoSystemHead(scope string) string {
	h := b.head(blocks.BlockSystem, b.SystemLayer, scope)
	return strings.ReplaceAll(h, " juniper show ", " cisco show ")
}

// ciscoSystemLines are the lines of the IOS system block in the walkthrough:
// comments that name the block (never the banner, never a key), then its
// statements as live lines, as a device in dialect d stores them. None when
// there is no system block.
func (b Blocks) ciscoSystemLines(scope string, d blocks.IOSDialect) []string {
	st := b.ciscoSystemStatements(d)
	if len(st) == 0 {
		return nil
	}
	out := []string{"! " + b.ciscoSystemHead(scope) + ": the login banner, domain, time zone, name servers and NTP."}
	if b.SystemLayer == LayerScopeDevice {
		st = withOrigins(st, b.ciscoSystemOrigins(d), "!")
	}
	if delim, ok := blocks.BannerDelimiter(b.CiscoSystem.BannerBody()); ok && b.CiscoSystem.Banner != nil {
		out = append(out, "! The banner is typed with the delimiter "+delim+", the first of "+strings.Join(blocks.BannerDelimiters, " ")+
			" that its text does not contain; the NTP lines are in the order IOS needs (keys, trusted keys, servers, 'ntp authenticate').")
	}
	return append(out, st...)
}

// systemLines are the lines of the system block in the walkthrough: a comment
// that names the block (never the message, never a key), then its statements
// as live lines. None when there is no system block.
func (b Blocks) systemLines(scope string) []string {
	st := b.systemStatements()
	if len(st) == 0 {
		return nil
	}
	out := []string{"# " + b.head(blocks.BlockSystem, b.SystemLayer, scope) + ": the login message, domain, time zone, name servers and NTP."}
	if b.SystemLayer == LayerScopeDevice {
		st = withOrigins(st, b.systemOrigins(), "#")
	}
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

// BlockProblem is blockProblem for the CLI's check of a block text: nil when
// no block community is the one the scope's own SNMP settings render.
func (d Data) BlockProblem(req Request) error { return d.blockProblem(req) }

// blockProblem is the refusal of a rendering that cannot be right: a block
// community whose string is the one the structured SNMP settings render
// (the device could not hold both, and the plan could not tell whose leaves
// are whose). The CLI verbs of the blocks refuse it earlier; this is the
// backstop, for a block file and a scope community that were both fine
// when written. The text names the community by its place in the block,
// never by its string.
func (d Data) blockProblem(req Request) error {
	if req.Vendor == "cisco" {
		return d.blockProblemCisco(req)
	}
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
		if c.String != in.Community {
			continue
		}
		// the layer that holds it and its place there: the numbers of
		// 'check' are the file's own
		where, edit, n := fmt.Sprintf("the SNMP block of scope '%s'", scope), "tacctl scope block "+scope+" juniper edit snmp", i+1
		dev := d.Blocks.Device
		place := func(b *blocks.SNMPBlock) int {
			if b == nil {
				return -1
			}
			for k, x := range b.Communities {
				if x.String == in.Community {
					return k + 1
				}
			}
			return -1
		}
		switch {
		case dev != "" && place(d.Blocks.DeviceSNMP) > 0:
			where, edit, n = fmt.Sprintf("the SNMP block of device '%s'", dev), "tacctl device block "+dev+" edit snmp", place(d.Blocks.DeviceSNMP)
		case dev != "" && d.Blocks.DeviceSNMP == nil && d.Blocks.SNMPLayer == LayerDevice:
			where, edit = fmt.Sprintf("the SNMP block of device '%s'", dev), "tacctl device block "+dev+" edit snmp"
		case place(d.Blocks.ScopeSNMP) > 0:
			n = place(d.Blocks.ScopeSNMP)
		}
		// one line: a batch keeps the first line of a refusal as the
		// device's reason
		return &names.Error{Msgs: []string{
			fmt.Sprintf("Community %d of %s is the community the scope's own SNMP settings render, and a device cannot hold both: "+
				"remove it from the block (%s) or give the scope another community (tacctl scope snmp %s community).",
				n, where, edit, scope),
		}}
	}
	return nil
}

// blockProblemCisco is blockProblem for an IOS device: a block community
// that is the community the scope's own SNMP settings render, and a block
// access list that is the scope's management access list (it would be
// defined twice, with entries that are not the same). The texts name the
// object by its place in the block and never print a string.
func (d Data) blockProblemCisco(req Request) error {
	b := d.Blocks.CiscoSNMP
	if b == nil {
		return nil
	}
	scope := d.Blocks.Scope
	if scope == "" {
		scope = req.Scope
	}
	dev := d.Blocks.Device
	// where names the layer that holds an object and its place there: the
	// numbers of 'check' are the file's own
	where := func(n int, find func(*blocks.IOSSNMPBlock) int) (string, string, int) {
		at := func(x *blocks.IOSSNMPBlock) int {
			if x == nil {
				return -1
			}
			return find(x)
		}
		w, edit := fmt.Sprintf("the SNMP block of scope '%s'", scope), "tacctl scope block "+scope+" cisco edit snmp"
		switch {
		case dev != "" && at(d.Blocks.DeviceCiscoSNMP) > 0:
			return fmt.Sprintf("the SNMP block of device '%s'", dev), "tacctl device block " + dev + " edit snmp", at(d.Blocks.DeviceCiscoSNMP)
		case dev != "" && d.Blocks.DeviceCiscoSNMP == nil && d.Blocks.SNMPLayer == LayerDevice:
			return fmt.Sprintf("the SNMP block of device '%s'", dev), "tacctl device block " + dev + " edit snmp", n
		case at(d.Blocks.ScopeCiscoSNMP) > 0:
			return w, edit, at(d.Blocks.ScopeCiscoSNMP)
		}
		return w, edit, n
	}
	in := d.SNMP
	if in.Version == snmpV2c && in.Community != "" {
		for i, c := range b.Communities {
			if c.String != in.Community {
				continue
			}
			s := c.String
			w, edit, n := where(i+1, func(x *blocks.IOSSNMPBlock) int {
				for k, y := range x.Communities {
					if y.String == s {
						return k + 1
					}
				}
				return -1
			})
			return &names.Error{Msgs: []string{
				fmt.Sprintf("Community %d of %s is the community the scope's own SNMP settings render, and a device cannot hold both: "+
					"remove it from the block (%s) or give the scope another community (tacctl scope snmp %s community).", n, w, edit, scope),
			}}
		}
	}
	if d.ACL.Name != "" {
		for i, a := range b.ACLs {
			if a.Name != d.ACL.Name {
				continue
			}
			s := a.Name
			w, edit, n := where(i+1, func(x *blocks.IOSSNMPBlock) int {
				for k, y := range x.ACLs {
					if y.Name == s {
						return k + 1
					}
				}
				return -1
			})
			return &names.Error{Msgs: []string{
				fmt.Sprintf("Access list %d of %s is the scope's management access list (%s), which tacctl renders itself, and the SNMP block may not define it: "+
					"rename it in the block (%s).", n, w, a.Name, edit),
			}}
		}
	}
	return nil
}
