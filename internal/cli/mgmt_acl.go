package cli

// The entries of the management ACL lists (mgmt_acl.permits and
// scope_mgmt_acl.permits.<scope>) as 'config mgmt-acl' and 'scope mgmt-acl'
// take, keep and print them (0.2.7): a CIDR, or a CIDR with the services it
// permits, <cidr>:tcp/22,udp/161,icmp (internal/mgmtacl). The two verbs
// families share what is here.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/mgmtacl"
	"github.com/rett/tacctl/internal/shellquote"
)

// parseACLEntries is parseCIDRList for the management ACL lists: the
// comma-separated entries of the first line, each trimmed by 'echo | xargs'
// (an unbalanced quote: xargs's complaint, and the entry is skipped), a
// service token (tcp/..., udp/..., icmp) attached to the entry before it,
// every entry validated (the first bad one is the error), canonicalised and
// deduplicated, in input order.
func (inv *invocation) parseACLEntries(input string) ([]string, error) {
	if i := strings.IndexByte(input, '\n'); i >= 0 {
		input = input[:i]
	}
	var tokens []string
	for _, raw := range strings.Split(input, ",") {
		entry, err := shellquote.XargsEcho(raw)
		if err != nil {
			inv.stderrLine("xargs: " + err.Error())
			continue
		}
		if entry != "" {
			tokens = append(tokens, entry)
		}
	}
	grouped, err := mgmtacl.Group(tokens)
	if err != nil {
		return nil, inv.usageErr(err.Error())
	}
	var out []string
	for _, g := range grouped {
		e, err := mgmtacl.ParseEntry(g)
		if err != nil {
			var inv2 *cidr.InvalidError
			if errors.As(err, &inv2) {
				return nil, inv.usageErr("Invalid CIDR: '" + inv2.Value + "'")
			}
			return nil, inv.usageErr(err.Error())
		}
		if s := e.String(); !contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// aclRemoveMatches are the stored entries that 'remove <req>' removes: the
// entry itself when it carries services, and every entry of the CIDR when it
// is a plain CIDR (whatever services they have).
func aclRemoveMatches(current []string, req string) []string {
	r, err := mgmtacl.ParseEntry(req)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range current {
		if r.Plain() {
			if e, err := mgmtacl.ParseEntry(c); err == nil && e.Net == r.Net {
				out = append(out, c)
			}
			continue
		}
		if c == req {
			out = append(out, c)
		}
	}
	return out
}

// aclChange applies add or remove of the requested (canonical) entries to
// current: the new list, the entries that changed it (added, or the stored
// ones removed), the requested ones that did nothing, and a note for each
// plain CIDR that removed more than one entry.
func aclChange(current []string, remove bool, requested []string) (next, changed, skipped, notes []string) {
	next = append([]string(nil), current...)
	for _, r := range requested {
		if !remove {
			if contains(next, r) {
				skipped = append(skipped, r)
				continue
			}
			changed = append(changed, r)
			next = append(next, r)
			continue
		}
		m := aclRemoveMatches(next, r)
		if len(m) == 0 {
			skipped = append(skipped, r)
			continue
		}
		for _, x := range m {
			changed = append(changed, x)
			next = without(next, x)
		}
		if len(m) > 1 || m[0] != r {
			notes = append(notes, fmt.Sprintf("%s without services removes every entry of that CIDR: %d removed", r, len(m)))
		}
	}
	return next, changed, skipped, notes
}

// aclLines prints a list's entries for 'list' (bash's 'echo "$list" | while
// read -r e; do [[ -z $e ]] && continue; echo "  - $e"; done' for plain
// entries): '  - <cidr>' and, for an entry with services, the services after the
// CIDR.
func (inv *invocation) aclLines(list []string) {
	var entries []mgmtacl.Entry
	var raw []string
	width := 0
	for _, l := range list {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		e, err := mgmtacl.ParseEntry(l)
		if err != nil {
			e = mgmtacl.Entry{Net: l}
		}
		if !e.Plain() && len(e.Net) > width {
			width = len(e.Net)
		}
		entries = append(entries, e)
		raw = append(raw, l)
	}
	for i, e := range entries {
		line := mgmtacl.Display(e, width)
		if e.Plain() {
			line = raw[i]
		}
		inv.echo("  - " + line)
	}
}

// aclCanonical is a stored list with each entry in its canonical form (an
// entry that is not one as it is).
func aclCanonical(list []string) []string {
	out := make([]string, 0, len(list))
	for _, l := range list {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}
		if c, ok := mgmtacl.Canonical(s); ok {
			s = c
		}
		out = append(out, s)
	}
	return out
}
