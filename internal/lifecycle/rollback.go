package lifecycle

// 'tacctl rollback <version>' (docs/plans/0.2.3-plan.md D50): the plan and
// the file conversions that prepare tacctl's state for the release before
// this one. The command (internal/cli/rollback.go) adds what needs the
// invocation: the snapshot, the re-render and the sync of the hosts.
//
// The target is 0.2.2 only. The formats 0.2.3 changed, and what a 0.2.2
// binary does with each (verified against the sources of the 0.2.2 tag):
//
//	store.yaml             not changed in 0.2.3; left alone.
//	tacctl.yaml            0.2.2's schema lacks linux.engineer_sudo,
//	                       snmp_scope.* and breakglass_scope.*: its
//	                       'config validate' reports them and its 'backup
//	                       restore' refuses a snapshot that has them. They
//	                       are removed (conf.Added023 and any other key it
//	                       does not know). tier.<group> is a key of 0.2.2
//	                       (the value 'engineer' too) and stays, but 0.2.2
//	                       takes a user's tier from the priv-lvl band alone.
//	console.yaml           0.2.2's parser rejects tiers.engineer and
//	                       settings.space_completion; both are removed
//	                       (console.Rollback).
//	devices.yaml           0.2.2's parser rejects the per-device 'location';
//	                       removed (devreg.RollbackLocations).
//	snmp/<scope>.yaml      a directory 0.2.2 never looks at; moved aside to
//	                       snmp.rolled-back-<timestamp>/, so a scope of the
//	                       same name created under 0.2.2 (or after the upgrade
//	                       to 0.2.3) does not pick the old credentials up. The
//	                       snapshot --apply takes first holds them as well.
//	hosts/<host>.json      the 'provisioner' entry of a record: a Go
//	                       json.Unmarshal into 0.2.2's Record ignores a key
//	                       it has no field for; left.
//	sshd drop-in           00-tacctl-engineer.conf: 0.2.2 does not know it
//	                       and never removes it; left (see the plan step).
//	tier-pinned            the marker of the one-shot tier migration; removed,
//	                       so the upgrade to 0.2.3 that follows 0.2.2 pins the
//	                       groups it finds at priv-lvl 15 (created or raised
//	                       under 0.2.2) once more. Left in place they would
//	                       stay held at the operator tier, unpinned.
//	tacquito.yaml          0.2.3 renders every command regex as ^(?:regex)$;
//	                       tacquito reads both forms the same way, and 0.2.2
//	                       re-renders the unwrapped form from the store at
//	                       its upgrade. Only 0.2.2's legacy importer, which
//	                       is not used on an install with a store, would not
//	                       unwrap what it reads.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
)

// RollbackTarget is the one release 'tacctl rollback' prepares for.
const RollbackTarget = "0.2.2"

// RollbackRefusal is a version the command does not take: Lines say why.
type RollbackRefusal struct{ Lines []string }

func (e *RollbackRefusal) Error() string { return strings.Join(e.Lines, " ") }

var reVersion = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// CheckRollbackVersion is the version a rollback is asked for ("0.2.2" or
// "v0.2.2"), or a *RollbackRefusal: an older release (0.2.2's own changes
// are not covered), this release or a newer one, or something that is not a
// release.
func CheckRollbackVersion(arg string) (string, error) {
	m := reVersion.FindStringSubmatch(arg)
	if m == nil {
		return "", &RollbackRefusal{Lines: []string{
			"'" + arg + "' is not a release this tacctl knows.",
			"Usage: tacctl rollback " + RollbackTarget + " [--apply] [--yes] [--hosts]"}}
	}
	v := strings.TrimPrefix(arg, "v")
	if v == RollbackTarget {
		return v, nil
	}
	n := func(i int) int { x, _ := strconv.Atoi(m[i]); return x }
	older := n(1) == 0 && (n(2) < 2 || (n(2) == 2 && n(3) < 2))
	if older {
		return "", &RollbackRefusal{Lines: []string{
			"Rolling back to " + v + " is not supported: this command converts what 0.2.3 changed, and " + v + " is older than 0.2.2.",
			"0.2.2 changed the state as well (the per-group junos, wti_level and tier settings of tacctl.yaml, the SNMP name hint, the",
			"facts in the host records) and those changes are not covered.",
			"Restore a snapshot with 'tacctl backup restore' (see 'tacctl backup list'), or reinstall from the backup you took before",
			"the upgrade to 0.2.2."}}
	}
	return "", &RollbackRefusal{Lines: []string{
		"'" + v + "' is not a release to roll back to: 'tacctl rollback' prepares the state for " + RollbackTarget + " only.",
		"Usage: tacctl rollback " + RollbackTarget + " [--apply] [--yes] [--hosts]"}}
}

// RollbackHost is one host of the registry.
type RollbackHost struct {
	Name, Scope string
	// Local: the entry is this tacctl server (enrolled with --local).
	Local bool
}

// RollbackInput is what a plan reads.
type RollbackInput struct {
	Paths paths.Paths
	Conf  *conf.Config
	// Model is the model (nil when it cannot be read: ModelErr says why).
	Model    *model.Model
	ModelErr error
	// HasStore: the install has a store, so tier settings exist and a
	// re-render is possible.
	HasStore bool
	// Hosts are the enrolled hosts the caller may sync, in registry order.
	Hosts []RollbackHost
	// AllHosts are every enrolled host (the warnings name the users who
	// become superusers on each).
	AllHosts []RollbackHost
	// WithHosts: the command was given --hosts.
	WithHosts bool
	// Now is the clock of the name the credentials directory is moved to
	// (nil: time.Now).
	Now func() time.Time
}

// RollbackStep is one line of the plan: what is done (Todo) or what is
// left, and why.
type RollbackStep struct {
	Title string
	Lines []string
	// Todo: --apply changes something for this step.
	Todo bool
}

// RollbackWarning needs a human: --apply refuses without --yes when any
// applies.
type RollbackWarning struct {
	Title string
	Lines []string
}

// RollbackPlan is the dry run: nothing in it has been written.
type RollbackPlan struct {
	Steps    []RollbackStep
	Warnings []RollbackWarning
	// Notes are things to know that do not need an answer.
	Notes []string

	in      RollbackInput
	keys    []string
	console console.RollbackPlan
	located []string
}

// Pending: there is a file to convert.
func (p *RollbackPlan) Pending() bool {
	return len(p.keys) > 0 || p.console.Text != nil || len(p.located) > 0 || p.markerPresent() || len(p.snmpFiles()) > 0
}

// markerPresent: the one-shot tier migration has run on this install.
func (p *RollbackPlan) markerPresent() bool { return TierPinDone(p.in.Paths) }

// NeedsYes: there are warnings that --yes must acknowledge.
func (p *RollbackPlan) NeedsYes() bool { return len(p.Warnings) > 0 }

// Keys are the tacctl.yaml keys that are removed.
func (p *RollbackPlan) Keys() []string { return slices.Clone(p.keys) }

// PlanRollback reads the state and says what a rollback does and what needs
// a human. It writes nothing. A file this tacctl cannot read is an error
// naming it: the rollback is refused before it changes anything.
func PlanRollback(in RollbackInput) (*RollbackPlan, error) {
	p := &RollbackPlan{in: in}
	pa := in.Paths

	// 1. tacctl.yaml
	if prob := in.Conf.Problem(); prob != "" {
		return nil, fmt.Errorf("%s cannot be read (%s); fix it first (tacctl config validate)", pa.Overrides, prob)
	}
	p.keys = in.Conf.RollbackKeys022()
	p.Steps = append(p.Steps, p.confStep())

	// 2. console.yaml
	cp, err := console.PlanRollback(pa.ConsoleFile)
	if err != nil {
		return nil, err
	}
	p.console = cp
	p.Steps = append(p.Steps, p.consoleStep())

	// 3. devices.yaml
	located, err := devreg.Located(pa.DevicesFile)
	if err != nil {
		return nil, err
	}
	p.located = located
	p.Steps = append(p.Steps, p.devicesStep())

	// 4 to 7: what stays.
	p.Steps = append(p.Steps, p.snmpFilesStep(), p.recordsStep(), p.sshdStep(), p.tierMarkerStep(), p.storeStep())

	// 8. The re-render.
	p.Steps = append(p.Steps, p.renderStep())

	// 9. The hosts.
	if in.WithHosts {
		p.Steps = append(p.Steps, p.hostsStep())
	}

	p.Warnings = p.warnings()
	p.Notes = p.notes()
	return p, nil
}

func (p *RollbackPlan) confStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys 0.2.2 does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (every key is one 0.2.2 has)"}
		return s
	}
	var added, other []string
	for _, k := range p.keys {
		if conf.Added023Key(k) {
			added = append(added, k)
		} else {
			other = append(other, k)
		}
	}
	for _, k := range added {
		s.Lines = append(s.Lines, "remove "+k)
	}
	for _, k := range other {
		s.Lines = append(s.Lines, "remove "+k+"  (no release knows this key; 0.2.2 refuses a file that has it)")
	}
	s.Lines = append(s.Lines, "keep every tier.<group> setting (0.2.2 has the key and the value engineer)")
	return s
}

func (p *RollbackPlan) consoleStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.ConsoleFile + ": write it the way 0.2.2 reads it", Todo: p.console.Text != nil}
	switch {
	case !p.console.Exists:
		s.Lines = []string{"no file (0.2.2 reads the defaults, as 0.2.3 does)"}
	case p.console.Text == nil:
		s.Lines = []string{"nothing to remove (neither tiers.engineer nor settings.space_completion is written)"}
	default:
		for _, k := range p.console.Remove {
			s.Lines = append(s.Lines, "remove "+k)
		}
		s.Lines = append(s.Lines, "(0.2.2's parser rejects both keys; every other setting is kept)")
	}
	return s
}

func (p *RollbackPlan) devicesStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.DevicesFile + ": remove the per-device location", Todo: len(p.located) > 0}
	if len(p.located) == 0 {
		s.Lines = []string{"no device has a location"}
		return s
	}
	s.Lines = []string{fmt.Sprintf("remove the location of %d %s: %s", len(p.located), plural(len(p.located), "device", "devices"), strings.Join(p.located, ", ")),
		"(0.2.2's parser refuses a device with a key it does not know: \"unknown key 'location'\")"}
	return s
}

// snmpFiles are the credential files of the per-scope SNMP settings.
func (p *RollbackPlan) snmpFiles() []string {
	matches, _ := filepath.Glob(filepath.Join(p.in.Paths.SNMPDir, "*.yaml"))
	sort.Strings(matches)
	return matches
}

// snmpAside is the directory the credentials are moved to: next to
// SNMPDir, snmp.rolled-back-<timestamp>, a number added when the name is
// taken.
func (p *RollbackPlan) snmpAside() string {
	now := time.Now
	if p.in.Now != nil {
		now = p.in.Now
	}
	base := filepath.Join(filepath.Dir(p.in.Paths.SNMPDir), "snmp.rolled-back-"+now().Format("20060102_150405"))
	name := base
	for n := 1; ; n++ {
		if _, err := os.Lstat(name); err != nil {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, n)
	}
}

func (p *RollbackPlan) snmpFilesStep() RollbackStep {
	files := p.snmpFiles()
	s := RollbackStep{Title: "move aside " + p.in.Paths.SNMPDir + " (the scopes' SNMP credentials) to " + filepath.Join(filepath.Dir(p.in.Paths.SNMPDir), "snmp.rolled-back-<timestamp>"),
		Todo: len(files) > 0}
	if len(files) == 0 {
		s.Lines = []string{"no file there"}
		return s
	}
	for _, f := range files {
		s.Lines = append(s.Lines, "moves "+f+" (mode 0600, kept)")
	}
	s.Lines = append(s.Lines, "(0.2.2 does not look in the directory, and a scope of the same name created from now on would pick the credentials up there;",
		" the snapshot --apply takes first holds them too: 'tacctl backup restore' of it, with 0.2.3, puts them back)")
	return s
}

// provisioned are the hosts whose record has a provisioner entry.
func (p *RollbackPlan) provisioned() []string {
	recs := hosts.Records{Dir: p.in.Paths.HostRecords}
	matches, _ := filepath.Glob(filepath.Join(recs.Dir, "*.json"))
	var out []string
	for _, f := range matches {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		if r, err := recs.Load(name); err == nil && r.Provisioner != nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (p *RollbackPlan) recordsStep() RollbackStep {
	s := RollbackStep{Title: "leave the host records in " + p.in.Paths.HostRecords}
	prov := p.provisioned()
	if len(prov) == 0 {
		s.Lines = []string{"no record has a provisioner entry"}
		return s
	}
	s.Lines = []string{fmt.Sprintf("%d %s a provisioner entry (the last 'host provisioner rotate'): %s", len(prov), plural(len(prov), "record has", "records have"), strings.Join(prov, ", ")),
		"0.2.2 decodes a record with a JSON decoder that ignores a key it has no field for, and its next sync of the host writes the record again without it"}
	return s
}

func (p *RollbackPlan) sshdStep() RollbackStep {
	pt := p.in.Paths
	s := RollbackStep{Title: "leave the engineer sshd drop-in"}
	if _, err := os.Stat(pt.SSHDEngineerDropIn); err == nil {
		s.Lines = append(s.Lines, "leaves "+pt.SSHDEngineerDropIn+": a 'Match Group tac-engineer' block that closes forwarding for members of that group; 0.2.2 does not know the file and never removes it",
			"(left on purpose: it only restricts, engineers keep the group until the hosts are synced, and removing it means an sshd reload in the middle of a rollback;",
			" to remove it later: delete the file, run 'sshd -t' and reload sshd)")
	} else {
		s.Lines = append(s.Lines, "no engineer sshd drop-in is installed")
	}
	return s
}

func (p *RollbackPlan) tierMarkerStep() RollbackStep {
	pt := p.in.Paths
	s := RollbackStep{Title: "remove the tier-pin marker so the next upgrade pins again", Todo: p.markerPresent()}
	if !s.Todo {
		s.Lines = []string{"no marker (the upgrade to 0.2.3 has not pinned the tiers of the groups, or the marker was removed)"}
		return s
	}
	s.Lines = []string{"removes " + pt.TierPinMarker + " (the marker of the one-shot tier migration; 0.2.2 ignores it)",
		"a group created or raised to priv-lvl 15 under 0.2.2 is then pinned (tier.<group>: superuser, what 0.2.2 gives it) by the upgrade to 0.2.3 that follows,",
		"instead of being held at the operator tier as an ambiguous group"}
	return s
}

func (p *RollbackPlan) storeStep() RollbackStep {
	return RollbackStep{Title: "leave " + p.in.Paths.StoreFile + " untouched",
		Lines: []string{"0.2.3 did not change the format of the store; the file is not read for writing and not written"}}
}

func (p *RollbackPlan) renderStep() RollbackStep {
	s := RollbackStep{Title: "re-render the enabled backends from the store (config render)", Todo: p.in.HasStore}
	if !p.in.HasStore {
		s.Lines = []string{"this install has no store (legacy read-only mode): nothing is rendered"}
		return s
	}
	s.Lines = []string{"nothing that is removed reaches tacquito.yaml or the RADIUS files, so this is a check that the converted state renders; a backend whose files change is restarted",
		"tacquito.yaml stays as 0.2.3 renders it (0.2.3's shipped command rules, every command regex wrapped as ^(?:regex)$): tacquito reads it, and the",
		"'tacctl upgrade' to 0.2.2 re-renders 0.2.2's form from the store; until then 0.2.2's 'config validate' says the rendered config is out of date",
		"(0.2.2's legacy importer, used only on an install without a store, does not unwrap the regexes it reads)"}
	return s
}

func (p *RollbackPlan) hostsStep() RollbackStep {
	s := RollbackStep{Title: "take the engineers' sudo off the enrolled Linux hosts (--hosts)"}
	var sync []string
	for _, h := range p.in.Hosts {
		if h.Local {
			s.Lines = append(s.Lines, h.Name+" (scope '"+h.Scope+"') is this tacctl server: not synced; engineers there have tacctl's own rows only, which the upgrade to 0.2.2 replaces")
			continue
		}
		sync = append(sync, h.Name)
		s.Lines = append(s.Lines, "sync "+h.Name+" (scope '"+h.Scope+"') with TAC_REVOKE_ENGINEER=1: the %tac-engineer line leaves its sudoers drop-in and engineer accounts leave tac-superuser and tac-engineer")
	}
	if len(p.in.Hosts) == 0 {
		s.Lines = []string{"no host is enrolled"}
	}
	s.Todo = len(sync) > 0
	if s.Todo {
		s.Lines = append(s.Lines, "(through 'host sync': scope rules, prompts for removed users' homes, the host's record; every other account is left alone)")
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// --- warnings ----------------------------------------------------------------

// tierChange is a group whose tier is not the one 0.2.2 gives it.
type tierChange struct {
	group        string
	privlvl      int
	now, under22 tier.Tier
}

// tierChanges are the groups whose tier setting differs from the band of
// their priv-lvl (0.2.2 derives the tier from the band alone), sorted by
// name; held: the group at priv-lvl 15 or more with no setting (ambiguous
// in 0.2.3, a superuser in 0.2.2).
func (p *RollbackPlan) tierChanges() []tierChange {
	m := p.in.Model
	if m == nil {
		return nil
	}
	var out []tierChange
	for _, name := range m.GroupNames() {
		g := m.Group(name)
		if g == nil || g.PrivLvl == nil {
			continue
		}
		lvl := strconv.Itoa(*g.PrivLvl)
		set := policy.GroupTier(p.in.Conf, name)
		now := tier.ForGroup(set, lvl)
		if p.in.HasStore && set == "" && policy.NeedsTier(name, g.PrivLvl) {
			now = tier.Operator
		}
		if under := tier.ForPrivLvl(lvl); under != now {
			out = append(out, tierChange{name, *g.PrivLvl, now, under})
		}
	}
	return out
}

func (p *RollbackPlan) warnings() []RollbackWarning {
	var out []RollbackWarning
	in := p.in

	if in.Model == nil {
		why := "the model cannot be read"
		if in.ModelErr != nil {
			why = strings.Join(strings.Fields(in.ModelErr.Error()), " ")
		}
		out = append(out, RollbackWarning{
			Title: "Who changes tier cannot be told",
			Lines: []string{why + ", so the groups whose tier changes and the users who become superusers are not listed."}})
	} else {
		if w, ok := p.superuserWarning(); ok {
			out = append(out, w)
		}
		if w, ok := p.tierWarning(); ok {
			out = append(out, w)
		}
	}
	if w, ok := p.droppedWarning(); ok {
		out = append(out, w)
	}
	if !in.HasStore && p.Pending() {
		out = append(out, RollbackWarning{
			Title: "No snapshot can be taken",
			Lines: []string{"This install has no store (legacy read-only mode) and snapshots are taken of the store, so --apply cannot back up the files it converts.",
				"Copy " + in.Paths.Overrides + ", " + in.Paths.ConsoleFile + " and " + in.Paths.DevicesFile + " yourself before you go on."}})
	}
	return out
}

// becomes lists, for a scope, the active users who are below the superuser
// tier now and superusers under 0.2.2.
func (p *RollbackPlan) becomes(scope string, changes map[string]tierChange) []string {
	m := p.in.Model
	var out []string
	for _, u := range m.Members(scope) {
		user := m.User(u)
		if user == nil || m.UserPrivLvl(u) == "" {
			continue
		}
		if c, ok := changes[user.Group]; ok && c.under22 == tier.Superuser {
			out = append(out, u+" (group "+user.Group+", "+string(c.now)+" now)")
		}
	}
	return out
}

func (p *RollbackPlan) superuserWarning() (RollbackWarning, bool) {
	changes := map[string]tierChange{}
	for _, c := range p.tierChanges() {
		changes[c.group] = c
	}
	var lines []string
	for _, h := range p.in.AllHosts {
		users := p.becomes(h.Scope, changes)
		if len(users) == 0 {
			continue
		}
		if h.Local {
			lines = append(lines, "This server (host "+h.Name+", scope '"+h.Scope+"'): "+strings.Join(users, ", ")+" become superusers of tacctl here, root in all but name (the superuser tier runs every tacctl verb as root), and join tac-superuser at the next sync.")
		} else {
			lines = append(lines, "Host "+h.Name+" (scope '"+h.Scope+"'): "+strings.Join(users, ", ")+" join tac-superuser (full sudo) at the next 0.2.2 sync, whatever --hosts did.")
		}
	}
	if len(lines) == 0 {
		return RollbackWarning{}, false
	}
	lines = append(lines, "0.2.2 takes a user's tier from the priv-lvl of the group alone (a group at priv-lvl 15 is a superuser group), not from tier.<group>.",
		"Take these groups out of the scope of the server (tacctl user scope <user> remove <scope>) or lower their priv-lvl before you go back.")
	return RollbackWarning{Title: "Engineers become superusers under 0.2.2", Lines: lines}, true
}

func (p *RollbackPlan) tierWarning() (RollbackWarning, bool) {
	changes := p.tierChanges()
	if len(changes) == 0 {
		return RollbackWarning{}, false
	}
	var lines []string
	for _, c := range changes {
		word := "higher"
		if tier.Rank(c.under22) < tier.Rank(c.now) {
			word = "lower"
		}
		lines = append(lines, fmt.Sprintf("group %s (priv-lvl %d): %s now, %s under 0.2.2 (%s)", c.group, c.privlvl, c.now, c.under22, word))
	}
	lines = append(lines, "0.2.2 keeps the tier.<group> settings but does not use them: a user's tier is the band of the priv-lvl (below 7 readonly, 7-14 operator, 15 superuser).")
	return RollbackWarning{Title: "Groups change tier", Lines: lines}, true
}

// dropped lists what leaves tacctl.yaml and the devices, and where it stays.
func (p *RollbackPlan) droppedWarning() (RollbackWarning, bool) {
	var lines []string
	c := p.in.Conf
	if es := c.GetList("linux.engineer_sudo"); len(es) > 0 && slices.Contains(p.keys, "linux.engineer_sudo") {
		lines = append(lines, "linux.engineer_sudo ("+strings.Join(es, ", ")+") is removed from tacctl.yaml: 0.2.2 gives its engineers (superusers there) every command.")
	}
	if scopes := snmpScopes(p.keys); len(scopes) > 0 {
		files := p.snmpFiles()
		var kept []string
		for _, f := range files {
			kept = append(kept, strings.TrimSuffix(filepath.Base(f), ".yaml"))
		}
		lines = append(lines, "Per-scope SNMP settings (version, port, timeout, v3 algorithms, contact, allowed clients) of "+strings.Join(scopes, ", ")+" are removed from tacctl.yaml, and the walkthroughs of 0.2.2 do not have the SNMP step.")
		if len(kept) > 0 {
			lines = append(lines, "  The credentials ("+strings.Join(kept, ", ")+".yaml, mode 0600) are moved from "+p.in.Paths.SNMPDir+"/ to a snmp.rolled-back-<timestamp> directory beside it, and are in the snapshot.")
		}
	}
	if bg := breakGlass(c, p.keys); len(bg) > 0 {
		lines = append(lines, "Break-glass users are removed from tacctl.yaml and are no longer rendered: "+strings.Join(bg, "; ")+".")
	}
	if len(p.located) > 0 {
		lines = append(lines, fmt.Sprintf("The location of %d %s is removed from the device registry (%s).", len(p.located), plural(len(p.located), "device", "devices"), strings.Join(p.located, ", ")))
	}
	if len(lines) == 0 {
		return RollbackWarning{}, false
	}
	lines = append(lines, "Everything removed from tacctl.yaml, console.yaml and devices.yaml stays in the snapshot --apply takes first (tacctl backup list); 'tacctl backup restore' of it, with this release, brings it back.")
	return RollbackWarning{Title: "Settings 0.2.2 cannot use are dropped", Lines: lines}, true
}

func snmpScopes(keys []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		if rest, ok := strings.CutPrefix(k, conf.SNMPScopePrefix); ok {
			s, _, _ := strings.Cut(rest, ".")
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func breakGlass(c *conf.Config, keys []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, "breakglass_scope.")
		if !ok {
			continue
		}
		s, _, _ := strings.Cut(rest, ".")
		if seen[s] {
			continue
		}
		seen[s] = true
		var names []string
		for _, e := range c.GetList(conf.BreakGlassPath(s)) {
			n, role, ok := conf.SplitBreakGlass(e)
			if ok {
				names = append(names, n+" ("+role+")")
			}
		}
		out = append(out, "scope '"+s+"': "+strings.Join(names, ", "))
	}
	return out
}

// --- notes ---------------------------------------------------------------------

func (p *RollbackPlan) notes() []string {
	var out []string
	if rules := p.alternations(); len(rules) > 0 {
		out = append(out, "Command rules with a top-level '|' match differently again under 0.2.2: tacquito tests an unwrapped 'a|b' as '^a|b$' (a prefix match on one branch, a suffix match on the other), and 0.2.2 renders it unwrapped. Review them with 'tacctl group commands list <group>':")
		for _, r := range rules {
			out = append(out, "  "+r)
		}
	}
	return out
}

// alternations are the stored command rules whose regex has a top-level
// alternation: "group g: rule <name> match <regex>".
func (p *RollbackPlan) alternations() []string {
	groups := map[string]bool{}
	if p.in.Model != nil {
		for _, g := range p.in.Model.GroupNames() {
			groups[g] = true
		}
	}
	for _, g := range p.in.Conf.GetKeys("commands") {
		groups[g] = true
	}
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)
	var out []string
	for _, g := range names {
		for _, line := range policy.Lines(p.in.Conf, g) {
			// A regex may hold '|': the line is name|action|matches.
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}
			name := parts[0]
			for _, rx := range strings.Split(parts[2], ",") {
				if rx != "" && TopLevelAlternation(rx) {
					out = append(out, "group "+g+": rule "+name+" match "+rx)
				}
			}
		}
	}
	return out
}

// TopLevelAlternation reports whether the regular expression has a '|'
// outside every group and character class.
func TopLevelAlternation(rx string) bool {
	depth, class := 0, false
	for i := 0; i < len(rx); i++ {
		switch c := rx[i]; {
		case c == '\\':
			i++
		case class:
			if c == ']' {
				class = false
			}
		case c == '[':
			class = true
			// A ']' right after '[' or '[^' is a member of the class.
			if i+1 < len(rx) && rx[i+1] == '^' {
				i++
			}
			if i+1 < len(rx) && rx[i+1] == ']' {
				i++
			}
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == '|' && depth == 0:
			return true
		}
	}
	return false
}

// --- apply ---------------------------------------------------------------------

// ApplyRollback converts the files of the plan: tacctl.yaml, console.yaml
// and devices.yaml, in this order, each in one write. The snapshot is the
// caller's, taken before. It returns one line for each file it changed. An
// error leaves the files already converted converted; running the same
// command again finishes (every step is idempotent).
func ApplyRollback(p *RollbackPlan) ([]string, error) {
	var done []string
	pt := p.in.Paths
	if len(p.keys) > 0 {
		if err := p.in.Conf.UnsetMany(p.keys); err != nil {
			return done, fmt.Errorf("%s: %w", pt.Overrides, err)
		}
		done = append(done, fmt.Sprintf("%s: removed %d %s", pt.Overrides, len(p.keys), plural(len(p.keys), "key", "keys")))
	}
	if p.console.Text != nil {
		changed, err := console.Rollback(pt.ConsoleFile, nil)
		if err != nil {
			return done, err
		}
		if changed {
			done = append(done, pt.ConsoleFile+": removed "+strings.Join(consoleKeys(p.console.Remove), " and "))
		}
	}
	if len(p.located) > 0 {
		cleared, err := devreg.RollbackLocations(pt.DevicesFile, nil)
		if err != nil {
			return done, err
		}
		if len(cleared) > 0 {
			done = append(done, fmt.Sprintf("%s: removed the location of %d %s", pt.DevicesFile, len(cleared), plural(len(cleared), "device", "devices")))
		}
	}
	if len(p.snmpFiles()) > 0 {
		aside := p.snmpAside()
		if err := os.Rename(pt.SNMPDir, aside); err != nil {
			return done, fmt.Errorf("%s: %w", pt.SNMPDir, err)
		}
		done = append(done, pt.SNMPDir+": moved to "+aside)
	}
	if p.markerPresent() {
		if err := os.Remove(pt.TierPinMarker); err != nil && !os.IsNotExist(err) {
			return done, fmt.Errorf("%s: %w", pt.TierPinMarker, err)
		}
		done = append(done, pt.TierPinMarker+": removed (the next upgrade pins the tiers of the groups at priv-lvl 15 again)")
	}
	return done, nil
}

func consoleKeys(remove []string) []string {
	out := make([]string, len(remove))
	for i, r := range remove {
		out[i], _, _ = strings.Cut(r, ":")
	}
	return out
}
