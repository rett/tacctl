package radius

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Note is one line of radius_notes: what the rendered state means for an
// operator. Kind is commands (groups with RADIUS users whose command rules
// restrict something; Detail is their names, ", "-joined), junos (groups
// with RADIUS users that have a Junos deny set, sent with the login class;
// Detail as for commands), secret (scopes
// whose secret is beyond the advice of the secret constraints, by name),
// filters (Detail "<n> allow, <n> deny") or vendors (Detail
// "<scopes that send a vendor attribute>|<scopes served>|<tagged addresses>").
type Note struct{ Kind, Detail string }

// String is the '<kind>|<detail>' line the bash program printed.
func (n Note) String() string { return n.Kind + "|" + n.Detail }

// restrictive is restrictive_rules: commands.<group> in the merged view has
// a deny rule.
func restrictive(merged *yamlpy.Map, group string) bool {
	cmds, _ := merged.Get("commands")
	cm, ok := cmds.(*yamlpy.Map)
	if !ok {
		return false
	}
	rules, _ := cm.Get(group)
	list, ok := rules.([]any)
	if !ok {
		return false
	}
	for _, r := range list {
		if rm, ok := r.(*yamlpy.Map); ok {
			if a, _ := rm.Get("action"); a == "deny" {
				return true
			}
		}
	}
	return false
}

// secretBeyondAdvice: longer than SecretMaxLen characters, or anything but
// printable ASCII without a space ('[!-~]+').
func secretBeyondAdvice(secret string) bool {
	if utf8.RuneCountInString(secret) > SecretMaxLen || secret == "" {
		return true
	}
	for _, r := range secret {
		if r < '!' || r > '~' {
			return true
		}
	}
	return false
}

// Notes is radius_notes. The model needs no validation; merged is the merged
// tacctl.yaml view.
func Notes(m *model.Model, merged *yamlpy.Map) []Note {
	var notes []Note
	scopes := servedScopes(m)
	seen := map[string]bool{}
	var groups, limited []string
	for _, e := range servedUsers(m) {
		if !seen[e.user.Group] {
			seen[e.user.Group] = true
			groups = append(groups, e.user.Group)
		}
	}
	sort.Strings(groups)
	for _, g := range groups {
		if restrictive(merged, g) {
			limited = append(limited, g)
		}
	}
	if len(limited) > 0 {
		notes = append(notes, Note{"commands", strings.Join(limited, ", ")})
	}
	var junos []string
	for _, g := range groups {
		for _, attr := range conf.JunosAttrs {
			if len(junosSet(merged, g, attr)) > 0 {
				junos = append(junos, g)
				break
			}
		}
	}
	if len(junos) > 0 {
		notes = append(notes, Note{"junos", strings.Join(junos, ", ")})
	}
	var odd []string
	for _, s := range scopes { // by name
		if secretBeyondAdvice(s.Secret) {
			odd = append(odd, s.Name)
		}
	}
	if len(odd) > 0 {
		notes = append(notes, Note{"secret", strings.Join(odd, ", ")})
	}
	if len(m.Filters.Allow) > 0 || len(m.Filters.Deny) > 0 {
		notes = append(notes, Note{"filters", fmt.Sprintf("%d allow, %d deny", len(m.Filters.Allow), len(m.Filters.Deny))})
	}
	enabling, tagged := 0, 0
	for _, s := range scopes {
		if len(s.VendorAttrs) > 0 {
			enabling++
		}
		tagged += len(s.Devices)
	}
	notes = append(notes, Note{"vendors", fmt.Sprintf("%d|%d|%d", enabling, len(scopes), tagged)})
	return notes
}
