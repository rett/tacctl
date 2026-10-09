package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// PinGroupTiers is the migration of the tier invariant (0.2.3), run by
// 'tacctl upgrade' and run ONCE: every group other than the superuser
// built-in at priv-lvl 15 or more has an explicit tier.<group> in
// tacctl.yaml. 0.2.2 treated such a group as a superuser group (its band),
// so the first upgrade to 0.2.3 writes exactly that for every one of them
// without a setting, one line each, after the snapshot (snapshot; nil:
// none), and records that it ran in the marker p.TierPinMarker (under the
// state directory /var/lib/tacctl, not in tacctl.yaml, which is what gets
// lost). Later upgrades find the marker and do nothing: a tier setting
// that is lost afterwards (an old tacctl.yaml copied back, a hand edit)
// leaves the group ambiguous, held at the operator tier by the gate, and
// is never silently made a superuser again; the repair is
// 'tacctl group edit <group> tier <tier>'. Nothing is done without a store.
// When tacctl.yaml cannot be read or written, or the snapshot cannot be
// made, it warns, writes nothing and leaves no marker (the next upgrade
// tries again; meanwhile the gate holds the members at the operator tier).
// It returns the groups written.
func PinGroupTiers(p paths.Paths, c *conf.Config, out ui.Output, snapshot func() error) []string {
	if model.Mode(p.StoreFile) != "store" || TierPinDone(p) {
		return nil
	}
	done, complete := pinGroups(p, c, out, snapshot, nil)
	if complete {
		if err := MarkTierPin(p); err != nil {
			out.Warn("Could not record that the tier settings of groups were migrated in " + p.TierPinMarker + ": " + strings.TrimSpace(err.Error()))
		}
	}
	return done
}

// PinImportedGroupTiers is the step after 'store import' and
// 'backup restore --legacy', whose groups come from elsewhere: the same
// pin as PinGroupTiers, for the groups that were NOT in the store before
// the import (before: the names the store held then), with or without the
// marker. A group the store already had keeps what tacctl.yaml says of it,
// also when that is nothing: a lost setting is not made a superuser's here
// either.
func PinImportedGroupTiers(p paths.Paths, c *conf.Config, out ui.Output, snapshot func() error, before []string) []string {
	if model.Mode(p.StoreFile) != "store" {
		return nil
	}
	done, _ := pinGroups(p, c, out, snapshot, before)
	return done
}

// TierPinDone reports whether the migration of PinGroupTiers has run.
func TierPinDone(p paths.Paths) bool {
	_, err := os.Stat(p.TierPinMarker)
	return err == nil
}

// MarkTierPin records that the migration has run (the marker, 0600, in
// VarLib).
func MarkTierPin(p paths.Paths) error {
	if err := paths.MkVarLib(filepath.Dir(p.TierPinMarker)); err != nil {
		return err
	}
	return os.WriteFile(p.TierPinMarker, []byte("tacctl 0.2.3 recorded the tier of every group at priv-lvl 15 once (tacctl upgrade). Delete this file only to run that migration again.\n"), 0o600)
}

// pinGroups writes the superuser tier for every ambiguous group of the
// store except those named in skip, and reports whether the work is
// complete: nothing was left unwritten for a reason that a later run could
// fix (an unreadable tacctl.yaml, a failed snapshot or write).
func pinGroups(p paths.Paths, c *conf.Config, out ui.Output, snapshot func() error, skip []string) (done []string, complete bool) {
	_, m, _, err := model.Load(model.Paths{
		Store: p.StoreFile, Config: p.Config, DatesDir: p.PWDatesDir,
		DisabledDir: filepath.Join(p.BackupDir, "disabled"),
	})
	if err != nil {
		return nil, false
	}
	var groups []string
	for _, g := range policy.UnsetTierGroups(c, m) {
		if !slices.Contains(skip, g) {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return nil, true
	}
	if prob := c.Problem(); prob != "" {
		out.Warn("Tier settings of groups not recorded: " + p.Overrides + " cannot be read (" + prob + ").")
		return nil, false
	}
	if prob := policy.TierProblem(c); prob != "" {
		out.Warn("Tier settings of groups not recorded: " + prob + " in " + p.Overrides + ".")
		return nil, false
	}
	done, err = policy.PinGroups(c, groups, snapshot)
	for _, g := range done {
		lvl := "15"
		if gr := m.Group(g); gr != nil && gr.PrivLvl != nil {
			lvl = strconv.Itoa(*gr.PrivLvl)
		}
		out.Info("Group '" + g + "' (priv-lvl " + lvl + "): tier recorded as superuser in " + p.Overrides +
			" (what 0.2.2 treated it as; change it with: tacctl group edit " + g + " tier <tier>).")
	}
	if err != nil {
		out.Warn("Tier settings of groups not recorded: " + strings.TrimSpace(err.Error()))
		return done, false
	}
	return done, true
}

// StaleRootMembers are the members of the local tac-superuser group that are
// accounts of the model whose tier is not superuser (a group's tier set or
// lowered, a user disabled): they still hold root on this server until the
// next 'tacctl host sync <server>'. Accounts that are no user of the model
// (a local administrator) are not tacctl's to flag, and root is neither.
// members are the group's members (getent group); c and m are the settings
// and the model as they stand.
func StaleRootMembers(c *conf.Config, m *model.Model, members []string) []string {
	var out []string
	for _, u := range members {
		if u == "root" || m.User(u) == nil {
			continue
		}
		t := tier.ForGroup(policy.GroupTier(c, m.User(u).Group), m.UserPrivLvl(u))
		if g := m.Group(m.User(u).Group); tier.Rank(t) > tier.Rank(tier.Operator) && g != nil &&
			policy.NeedsTier(m.User(u).Group, g.PrivLvl) && policy.GroupTier(c, m.User(u).Group) == "" {
			t = tier.Operator // ambiguous: held at the operator tier, as the gate does
		}
		if t != tier.Superuser {
			out = append(out, u)
		}
	}
	return out
}

// rootMembersNotice is the last word of an upgrade on an install whose
// tier settings changed it (0.2.2's 'group preset roles' wrote
// tier.engineer: engineer, which the first 0.2.3 gate takes at its word):
// when this server is enrolled and a member of tac-superuser is no longer a
// superuser, the accounts on it still hold root, and it says so with the
// sync that ends it. The upgrade only reads: a host sync prompts, may ask
// for an ssh agent and rewrites accounts, none of which belongs in the
// middle of an upgrade, so it prints the red line and leaves the sync to
// the operator, as 'console check' does.
func (h *Host) rootMembersNotice(ctx context.Context) {
	if model.Mode(h.Paths.StoreFile) != "store" {
		return
	}
	reg, err := hosts.LoadRegistry(h.Paths.LinuxHosts)
	if err != nil {
		return
	}
	server := ""
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local {
			server = e.Name
			break
		}
	}
	if server == "" {
		return
	}
	res, err := h.Runner.Run(ctx, execx.Cmd{Name: "getent", Args: []string{"group", tier.SuperuserGroup}})
	if err != nil || res.Code != 0 {
		return
	}
	var members []string
	if f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":"); len(f) >= 4 {
		for _, u := range strings.Split(f[3], ",") {
			if u != "" {
				members = append(members, u)
			}
		}
	}
	_, m, _, err := model.Load(model.Paths{
		Store: h.Paths.StoreFile, Config: h.Paths.Config, DatesDir: h.Paths.PWDatesDir,
		DisabledDir: filepath.Join(h.Paths.BackupDir, "disabled"),
	})
	if err != nil {
		return
	}
	stale := StaleRootMembers(h.Conf, m, members)
	if len(stale) == 0 {
		return
	}
	h.echo(ui.Red + "  Not superusers by tacctl's tiers, but still in " + tier.SuperuserGroup + " (root on this server): " + strings.Join(stale, ", ") + "." + ui.NC)
	h.echo(ui.Red + "  End it with: tacctl host sync " + server + ui.NC)
	h.echo("")
}

// pinGroupTiers is upgrade's call of PinGroupTiers.
func (h *Host) pinGroupTiers() {
	var snap func() error
	if h.Snapshots != nil {
		snap = func() error { _, err := h.Snapshots.Take(); return err }
	}
	PinGroupTiers(h.Paths, h.Conf, h.Out, snap)
}
