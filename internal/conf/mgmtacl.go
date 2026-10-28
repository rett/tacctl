package conf

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/mgmtacl"
	"github.com/rett/tacctl/internal/py"
)

// MgmtACLKey is the key of the global management ACL list, and
// ScopeMgmtACLPrefix the prefix of a scope's.
const (
	MgmtACLKey         = "mgmt_acl.permits"
	ScopeMgmtACLPrefix = "scope_mgmt_acl.permits."
)

// ScopeMgmtACLModePrefix starts the key of a scope's management filter mode
// (0.2.20, 'tacctl scope mgmt-acl <scope> mode'): scope_mgmt_acl.mode.<scope>.
// The mode only shapes the Junos filter. An absent key is MgmtModeSSHOnly,
// which is never stored, so a tacctl.yaml that never set a mode does not
// change, and a release before 0.2.20 reads every file that has none.
const ScopeMgmtACLModePrefix = "scope_mgmt_acl.mode."

// The modes of the Junos management filter. ssh-only restricts ssh, NETCONF
// and SNMP and ends in a default-accept term; strict accepts every protocol
// from the permit list only and has none.
const (
	MgmtModeSSHOnly = "ssh-only"
	MgmtModeStrict  = "strict"
)

// MgmtModes are the modes, in the order they are listed.
var MgmtModes = []string{MgmtModeSSHOnly, MgmtModeStrict}

// MgmtACLMode is the management filter mode of scope: MgmtModeStrict when the
// scope has it, else MgmtModeSSHOnly (also for scope "" and for a value the
// schema would refuse).
func (c *Config) MgmtACLMode(scope string) string {
	if scope == "" {
		return MgmtModeSSHOnly
	}
	if v, ok := c.Get(ScopeMgmtACLModePrefix+scope, ""); ok && v == MgmtModeStrict {
		return MgmtModeStrict
	}
	return MgmtModeSSHOnly
}

// MgmtACLStrictScopes are the scopes whose management filter mode is
// strict, sorted: what a rollback to a release that has no mode warns of.
func (c *Config) MgmtACLStrictScopes() []string {
	var out []string
	walkLeaves(c.Overrides(), "", func(p string, v any) {
		if s, ok := strings.CutPrefix(p, ScopeMgmtACLModePrefix); ok && v == MgmtModeStrict {
			out = append(out, s)
		}
	})
	slices.Sort(out)
	return out
}

// ACLServiceEntry is one element of a management ACL list that carries
// services (0.2.7): the list's key and the entry as the file has it.
type ACLServiceEntry struct {
	Key   string
	Entry string
}

// MgmtACLServiceEntries are the elements of the file's own management ACL
// lists (the global one and each scope's) that carry services, in file
// order. A release before 0.2.7 reads these lists as plain CIDRs and refuses
// such an element, and a rewrite to the plain CIDR would permit every
// protocol and port, so a rollback is refused while any is there.
func (c *Config) MgmtACLServiceEntries() []ACLServiceEntry {
	var out []ACLServiceEntry
	walkLeaves(c.Overrides(), "", func(p string, v any) {
		if p != MgmtACLKey && !strings.HasPrefix(p, ScopeMgmtACLPrefix) {
			return
		}
		items, ok := py.List(v)
		if !ok {
			return
		}
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				continue
			}
			if e, err := mgmtacl.ParseEntry(s); err == nil && !e.Plain() {
				out = append(out, ACLServiceEntry{p, s})
			} else if err != nil && strings.Contains(s, ":") && !strings.Contains(s, "::") && hasServiceColon(s) {
				// a malformed entry with services is still not a CIDR
				// to the older release
				out = append(out, ACLServiceEntry{p, s})
			}
		}
	})
	return out
}

// hasServiceColon reports an entry that has the colon of a service list.
func hasServiceColon(s string) bool {
	l := strings.ToLower(s)
	for _, w := range []string{":tcp/", ":udp/", ":icmp", ":*"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// MgmtACLList is the management permit list that applies to scope: the
// scope's own list when it has any element, else the global one (the same
// precedence every rendering reads). own says the scope's own list was used.
// Elements are as stored, blank ones dropped; scope "" is the global list.
func (c *Config) MgmtACLList(scope string) (list []string, own bool) {
	nonBlank := func(raw []string) []string {
		var out []string
		for _, l := range strings.Split(strings.Join(raw, "\n"), "\n") {
			if s := strings.TrimSpace(l); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if scope != "" {
		if l := nonBlank(c.GetList(ScopeMgmtACLPrefix + scope)); len(l) > 0 {
			return l, true
		}
	}
	return nonBlank(c.GetList(MgmtACLKey)), false
}
