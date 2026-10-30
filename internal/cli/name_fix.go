package cli

// 'config validate --fix-names' (docs/plans/0.2.15-plan.md D226-D230): after
// the report, each name with upper case whose lower-case spelling is free is
// offered the rename that fixes it, one at a time. The rename is the verb
// that renames that kind of name, run as when typed.

import (
	"errors"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// fixNamesDenied is the refusal of a caller who is not the superuser.
const fixNamesDenied = "'config validate --fix-names' renames devices, hosts, users and scopes, which is the superuser's."

// fixNamesAllowed is nil when the caller is the superuser (the rename verbs
// are theirs); the refusal is printed and logged.
func (inv *invocation) fixNamesAllowed() error {
	t := inv.tierGate().Caller(inv.ctx)
	if t == tier.Unrestricted || t == tier.Superuser {
		return nil
	}
	inv.app.Audit().Raw("auth.warning", "tier DENY user="+inv.sudoUser()+" tier="+string(t)+" cmd=config validate --fix-names")
	return inv.deniedUsage(reasonSuperuser, fixNamesDenied)
}

// nameFixCounts are the outcomes the summary line states.
type nameFixCounts struct{ renamed, declined, notOffered, failed int }

// fixNames offers the renames and prints the summary. It reports whether
// the run leaves names behind or a rename failed (exit status 1): a decline
// is the person's choice and does not.
func (inv *invocation) fixNames(yes bool) (bool, error) {
	a := inv.app
	var n nameFixCounts
	userRenamed := false
	seen := map[string]bool{}
	for {
		// Every rename changes what the findings are: a scope a host
		// rename carried is gone from them, a name another rename freed is
		// determinate.
		inv.loaded = false
		var next *hostFinding
		for _, f := range inv.caseFindings() {
			if f.To != "<new>" && !seen[f.Kind+"/"+f.Name] {
				f := f
				next = &f
				break
			}
		}
		if next == nil {
			break
		}
		seen[next.Kind+"/"+next.Name] = true
		if !yes && !a.Prompter().Confirm("Rename "+next.Kind+" '"+next.Name+"' to '"+next.To+"'? [y/N]: ") {
			n.declined++
			continue
		}
		err := inv.fixRename(*next, yes)
		if errors.Is(err, ui.ErrInterrupted) {
			return true, err
		}
		// A host renamed whose carried scope was refused (D233): the host
		// counts as renamed, and the scope, which the same check would
		// refuse again, is not offered in this run.
		var kept *hostScopeKeptError
		if errors.As(err, &kept) {
			n.renamed++
			seen["scope/"+kept.Old] = true
			inv.loaded = false
			for _, f := range inv.caseFindings() {
				if f.Kind == "scope" && f.Name == kept.Old && f.To != "<new>" {
					n.notOffered++
					inv.echo(fixNamesScopeKept(kept))
					break
				}
			}
			continue
		}
		if exitCode(err, a.Out) != 0 {
			n.failed++
			continue
		}
		n.renamed++
		userRenamed = userRenamed || next.Kind == "user"
	}

	// What is left with no lower-case spelling to offer.
	inv.loaded = false
	findings := inv.caseFindings()
	for _, f := range findings {
		if f.To == "<new>" {
			n.notOffered++
			inv.echo(inv.fixNamesTaken(f))
		}
	}

	inv.echo("Names: renamed " + strconv.Itoa(n.renamed) + ", declined " + strconv.Itoa(n.declined) +
		", not offered " + strconv.Itoa(n.notOffered) + ", failed " + strconv.Itoa(n.failed) + ".")
	if userRenamed {
		if reg, err := inv.registry(); err == nil && !reg.Empty() {
			a.Out.Info("The accounts of renamed users are renamed on the enrolled hosts at the next sync: tacctl host sync --all")
		}
	}
	return n.failed > 0 || n.notOffered > 0, nil
}

// fixRename runs the verb that renames f's name to its lower-case spelling.
// --yes is given to 'host rename' only when the person gave it: otherwise the
// verb asks its own questions, after ours.
func (inv *invocation) fixRename(f hostFinding, yes bool) error {
	args := []string{f.Name, f.To}
	switch f.Kind {
	case "device":
		return inv.deviceRename(args)
	case "host":
		if yes {
			args = append(args, "--yes")
		}
		return inv.hostRename(args)
	case "user":
		return inv.userRename(args)
	}
	return inv.scopeRename(args)
}

// fixNamesScopeKept is the line for a scope that was to be renamed with its
// host and was refused: the question is not asked, the command is given.
func fixNamesScopeKept(k *hostScopeKeptError) string {
	return "'" + k.Old + "' is not offered: its rename was refused with the host's (" + k.reason() +
		"); retry: tacctl scope rename " + k.Old + " " + k.New
}

// fixNamesTaken is the line for a name that is not offered: its lower-case
// spelling is another name's, so the person picks one. For a host that is
// equal to another host ignoring case it also names the verb that drops a
// stray registration.
func (inv *invocation) fixNamesTaken(f hostFinding) string {
	lower := strings.ToLower(f.Name)
	line := "'" + f.Name + "' is not offered: '" + lower + "' is taken; pick a name: tacctl " + f.Kind + " rename " + f.Name + " <new>"
	if f.Kind != "host" {
		return line
	}
	if reg, err := inv.registry(); err == nil {
		for _, e := range reg.Entries() {
			if e.Name != f.Name && strings.EqualFold(e.Name, f.Name) {
				return line + ", or tacctl host forget <name> drops the stray registration"
			}
		}
	}
	return line
}
