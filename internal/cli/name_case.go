package cli

// The findings about names with upper case (docs/plans/0.2.14-plan.md D203,
// D204). New device, host, user and scope names are lower case; one that
// exists with upper case keeps working and is listed by 'config validate'
// with the verb that renames it. Nothing is migrated or folded.

import (
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/names"
)

// caseFindings are the names of devices, hosts, users and scopes with upper
// case, each with its fix, in that order and sorted within a kind. Only the
// superuser's view has them (a restricted caller is told nothing: what they
// would name is not theirs). A fix names the lower-case spelling, or <new>
// when another name of the namespace is equal to it ignoring case. A user
// whose name has a period is not among them (dottedUserFindings has it): its
// lower-case spelling would keep the period.
func (inv *invocation) caseFindings() []hostFinding {
	if inv.callerScopes().restricted {
		return nil
	}
	var out []hostFinding

	// Devices and hosts share one namespace (a host is named like no
	// device), compared ignoring case.
	taken := map[string]int{}
	var devs, hs []string
	if f, err := inv.hostDevices(); err == nil && f != nil {
		for _, d := range f.Devices {
			taken[strings.ToLower(d.Name)]++
			if names.HasUpper(d.Name) {
				devs = append(devs, d.Name)
			}
		}
	}
	if reg, err := inv.registry(); err == nil {
		for _, e := range reg.Entries() {
			taken[strings.ToLower(e.Name)]++
			if names.HasUpper(e.Name) {
				hs = append(hs, e.Name)
			}
		}
	}
	// target is the lower-case spelling, unless another name has it.
	target := func(name string, count map[string]int) string {
		if lower := strings.ToLower(name); count[lower] < 2 {
			return lower
		}
		return "<new>"
	}
	sort.Strings(devs)
	sort.Strings(hs)
	for _, n := range devs {
		out = append(out, hostFinding{
			Text: "the device '" + n + "' has upper case in its name; new names are lower case",
			Fix:  "tacctl device rename " + n + " " + target(n, taken),
			Kind: "device", Name: n, To: target(n, taken), Verb: "device rename",
		})
	}
	for _, n := range hs {
		out = append(out, hostFinding{
			Text:  "the host '" + n + "' has upper case in its name; new names are lower case",
			Fix:   "tacctl host rename " + n + " " + target(n, taken),
			Hosts: []string{n},
			Kind:  "host", Name: n, To: target(n, taken), Verb: "host rename",
		})
	}

	if m, err := inv.model(); err == nil {
		users, scopes := m.UserNames(), m.ScopeNames()
		for _, set := range []struct {
			kind, verb string
			all        []string
			note       string
		}{
			{"user", "user", users, "; devices match the typed login name exactly, so the rename changes what the person types at the device; on enrolled hosts the next sync renames the account and keeps its UID and home"},
			{"scope", "scope", scopes, ""},
		} {
			lowers := map[string]int{}
			for _, n := range set.all {
				lowers[strings.ToLower(n)]++
			}
			for _, n := range set.all {
				if names.HasUpper(n) && (set.kind != "user" || !strings.Contains(n, ".")) {
					out = append(out, hostFinding{
						Text: "the " + set.kind + " '" + n + "' has upper case in its name; new names are lower case" + set.note,
						Fix:  "tacctl " + set.verb + " rename " + n + " " + target(n, lowers),
						Kind: set.kind, Name: n, To: target(n, lowers), Verb: set.verb + " rename",
					})
				}
			}
		}
	}
	return out
}

// dottedUserFindings are the users whose name has a period, sorted, each an
// error with the verb that renames it. 0.2.20 and 0.2.21 allowed the period;
// a user name is letters, digits, '_' and '-' since 0.2.22 because every user
// has an account on the tacctl server and a period cannot be part of a Linux
// account name. Only the superuser's view has them, as for caseFindings.
func (inv *invocation) dottedUserFindings() []validateFinding {
	if inv.callerScopes().restricted {
		return nil
	}
	m, err := inv.model()
	if err != nil {
		return nil
	}
	var out []validateFinding
	for _, n := range m.UserNames() {
		if strings.Contains(n, ".") {
			out = append(out, validateFinding{
				Section: "names", Level: levelError,
				Text: "the user '" + n + "' has a period in its name; a user name is letters, digits, '_' and '-'",
				Fix:  "tacctl user rename " + n + " <new-name>",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Text < out[j].Text })
	return out
}
