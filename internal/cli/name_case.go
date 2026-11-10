package cli

// The findings about names with upper case (docs/plans/0.2.14-plan.md D203,
// D204). New device, host, user and scope names are lower case; one that
// exists with upper case keeps working and is listed by 'config validate'
// with the verb that renames it. Nothing is migrated or folded.

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
)

// caseFindings are the names of devices, hosts, users and scopes with upper
// case, each with its fix, in that order and sorted within a kind (a user whose
// lower-case spelling is no name for a new user is left to userNameFindings). Only the
// superuser's view has them (a restricted caller is told nothing: what they
// would name is not theirs). A fix names the lower-case spelling, or <new>
// when another name of the namespace is equal to it ignoring case.
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
				// A user whose lower-case spelling a new user could not have
				// (over names.UsernameMax, or not starting with a letter, or
				// reserved) is not offered it: 'user rename' would refuse it.
				// userNameFindings names the rename for such a user, once.
				if set.kind == "user" && names.CheckNewUsername(strings.ToLower(n)) != nil {
					continue
				}
				if names.HasUpper(n) {
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

// userNameFindings are the users from before whose name a new user could not
// have and for whom caseFindings offers no lower-case rename: a name longer
// than names.UsernameMax or one that starts with a digit or '-' (a Linux
// account name does not: the user keeps working but has no account, here or on
// a host; a long name that starts with '_' is told the letter rule as well, so
// that its replacement is not refused), and a name with upper case whose lower-case spelling 'user rename'
// would refuse (it starts with '_', which Linux would take but a new name does
// not, or is reserved). The rules are those of names.CheckNewUsername (the names
// are checked at 'user add' and 'user rename' only). They are warnings in
// 'config validate' with the verb that renames the user to a name of the
// person's choice, sorted by name, the superuser's view only. They carry no
// Kind, so 'config validate --fix-names' (case findings only) does not read
// them. A user that has several of these faults, upper case included, gets
// this one finding, which says so: the rename it names is the one that fixes
// all of them, and caseFindings leaves the user out, so that no finding
// proposes a rename that the creation rules refuse.
func (inv *invocation) userNameFindings() []hostFinding {
	if inv.callerScopes().restricted {
		return nil
	}
	m, err := inv.model()
	if err != nil {
		return nil
	}
	users := m.UserNames()
	sort.Strings(users)
	var out []hostFinding
	for _, n := range users {
		long := len(n) > names.UsernameMax
		digit := names.StartsWithNoAccountChar(n)
		// A name that starts with '_' has an account if it is short enough and
		// has no upper case; one that is over the length is told the letter rule
		// as well, or a natural replacement such as '_svc' would be refused.
		under := long && n[0] == '_'
		upper := names.HasUpper(n)
		var text string
		switch {
		case long || digit:
			var has, rules []string
			start := "starts with a digit"
			switch n[0] {
			case '-':
				start = "starts with '-'"
			case '_':
				start = "starts with '_'"
			}
			switch {
			case long:
				has = append(has, "has a name of "+strconv.Itoa(len(n))+" characters")
				rules = append(rules, "at most "+strconv.Itoa(names.UsernameMax))
				if digit || under {
					has = append(has, start)
				}
			default:
				has = append(has, "has a name that "+start)
			}
			if upper {
				has = append(has, "has upper case letters")
				rules = append(rules, "lower case")
			}
			var must []string
			if len(rules) > 0 {
				must = append(must, "are "+joinAnd(rules))
			}
			if digit || under {
				must = append(must, "start with a letter (a to z)")
			}
			text = "the user '" + n + "' " + strings.Join(has, " and ") + "; new user names " + strings.Join(must, " and ") +
				", and this user has no Linux account, here or on a host"
		case upper:
			// The name has upper case, so the user has no Linux account (a
			// Linux account name is lower case); only the lower-case spelling
			// can be refused here, and 'user rename' would refuse it.
			err := names.CheckNewUsername(strings.ToLower(n))
			if err == nil {
				continue
			}
			text = "the user '" + n + "' has upper case letters; new user names are lower case, but its lower-case spelling '" +
				strings.ToLower(n) + "' is not a name 'user rename' takes: " + strings.TrimSuffix(strings.SplitN(err.Error(), "\n", 2)[0], ".")
		default:
			continue
		}
		out = append(out, hostFinding{Text: text, Fix: "tacctl user rename " + n + " <new-name>"})
	}
	return out
}

// joinAnd joins phrases as "a", "a and b", "a, b and c".
func joinAnd(parts []string) string {
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}
