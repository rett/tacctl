package lifecycle

// What a rollback gives back that 0.2.20 had taken away. The console.yaml the
// plan writes keeps the 'tiers' and 'users' mappings (the console switches
// this release ignores), and an older release reads them as it always did: a
// user or a tier switched off there gets /bin/bash at the older release's next
// host sync, a full system shell, where this release gave them the console.
// A system-shell setting of one user that takes the shell from a user of a
// tier that has it (settings.system_shell_users) is removed, so the older
// release gives that user the tier's. The password cache, which this release
// makes each user's choice, is on again for every user of the tiers that are
// allowed it. None of that changes a file the plan names as a change, so it
// is a warning: every user who would gain a system shell or the cache is
// listed with the reason, and --apply refuses without --yes while any is.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
)

// userTiers are the tiers of the users of the store, as the gate holds them
// (a member of an ambiguous group is held at the operator tier). It is nil
// when there is no store or it cannot be read; the warning then names the
// tiers and the settings it cannot map to users.
func (p *RollbackPlan) userTiers() map[string]tier.Tier {
	pa := p.in.Paths
	if !p.in.HasStore || model.Mode(pa.StoreFile) != "store" {
		return nil
	}
	_, m, _, err := model.Load(model.Paths{
		Store: pa.StoreFile, Config: pa.Config, DatesDir: pa.PWDatesDir,
		DisabledDir: pa.BackupDir + "/disabled",
	})
	if err != nil {
		return nil
	}
	ambiguous := policy.UnsetTierGroups(p.in.Conf, m)
	out := map[string]tier.Tier{}
	for _, name := range m.UserNames() {
		u := m.User(name)
		if u == nil {
			continue
		}
		t := tier.ForGroup(policy.GroupTier(p.in.Conf, u.Group), m.UserPrivLvl(name))
		if tier.Rank(t) > tier.Rank(tier.Operator) && slices.Contains(ambiguous, u.Group) {
			t = tier.Operator
		}
		out[name] = t
	}
	return out
}

// consoleWideningWarning lists the users (and tiers) who would gain a system
// shell or the password cache by the rollback, and why; nil when none would.
func (p *RollbackPlan) consoleWideningWarning() []RollbackWarning {
	f, err := console.Load(p.in.Paths.ConsoleFile)
	if err != nil {
		return nil
	}
	tiers := p.userTiers()
	var shell, cache []string
	names := func() []string {
		out := make([]string, 0, len(tiers))
		for n := range tiers {
			out = append(out, n)
		}
		slices.Sort(out)
		return out
	}

	// The console switches an older release reads: the console off gives a
	// plain bash login shell. The engineer tier always has the console.
	if tiers == nil {
		for _, u := range f.IgnoredUserNames() {
			if !f.IgnoredUsers[u] {
				shell = append(shell, "  users."+u+": disable   (a plain /bin/bash login shell for '"+u+"' at the older release's next host sync, if it is a user of a tier other than engineer)")
			}
		}
		for _, t := range console.Tiers {
			if on, ok := f.IgnoredTiers[t]; ok && !on && t != tier.Engineer {
				shell = append(shell, "  tiers."+string(t)+": disable   (a plain /bin/bash login shell for the users of the "+string(t)+" tier, but those with a users override of enable)")
			}
		}
	} else {
		for _, u := range names() {
			t := tiers[u]
			if t == tier.None || t == tier.Engineer {
				continue
			}
			if on, ok := f.IgnoredUsers[u]; ok {
				if !on {
					shell = append(shell, "  "+u+" ("+string(t)+"): users."+u+": disable gives a plain /bin/bash login shell")
				}
			} else if on, ok := f.IgnoredTiers[t]; ok && !on {
				shell = append(shell, "  "+u+" ("+string(t)+"): tiers."+string(t)+": disable gives a plain /bin/bash login shell")
			}
		}
	}

	// A system-shell setting of one user that takes the shell away is removed
	// (the key is unknown to the older release): the user has their tier's.
	for _, u := range f.SystemShellUserNames() {
		if f.SystemShellUsers[u] {
			continue
		}
		t, known := tiers[u]
		switch {
		case tiers != nil && !known:
			continue
		case known && (t == tier.Superuser || t == tier.Engineer || t == tier.None || !slices.Contains(f.SystemShellTiers, t)):
			continue
		case known:
			shell = append(shell, "  "+u+" ("+string(t)+"): its own system-shell disable is removed and the "+string(t)+" tier has the system shell")
		default:
			shell = append(shell, "  "+u+": its own system-shell disable is removed; if its tier has the system shell ("+tierList(f.SystemShellTiers)+"), it gets it")
		}
	}

	// The password cache is on again for every user of a tier that is allowed
	// it, as it was before each user chose (0.2.3 has no cache).
	if p.target() != RollbackTarget && len(f.PasswordCacheTiers) > 0 {
		if tiers == nil {
			cache = append(cache, "  every user of "+tierList(f.PasswordCacheTiers)+": the cache is on for the tier again, without their own choice")
		} else {
			for _, t := range f.PasswordCacheTiers {
				var who []string
				for _, u := range names() {
					if tiers[u] == t && !f.PasswordCacheUsers[u] {
						who = append(who, u)
					}
				}
				if len(who) > 0 {
					cache = append(cache, "  "+string(t)+": "+strings.Join(who, ", ")+" (the cache is on for the tier again, without their own choice)")
				}
			}
		}
	}

	if len(shell) == 0 && len(cache) == 0 {
		return nil
	}
	var lines []string
	if len(shell) > 0 {
		lines = append(lines, "These users get a system shell they do not have now (0.2.20 ignores the console switches of console.yaml and has a system shell only where it was opened; "+p.target()+" reads them as it always did, and the file keeps them):")
		lines = append(lines, shell...)
	}
	if len(cache) > 0 {
		lines = append(lines, "These users get the password cache they have not turned on (0.2.20 makes it each user's choice; "+p.target()+" has it on for every user of an allowed tier):")
		lines = append(lines, cache...)
	}
	lines = append(lines, "To keep them as they are, change console.yaml before the rollback: remove the 'tiers' and 'users' entries that switch the console off, and 'console password-cache tiers none'.")
	return []RollbackWarning{{Title: "Users who gain a system shell or the password cache", Lines: lines}}
}

// tierList is a comma list of tiers.
func tierList(l []tier.Tier) string {
	s := make([]string, len(l))
	for i, t := range l {
		s[i] = string(t)
	}
	return strings.Join(s, ",")
}
