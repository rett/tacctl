package lifecycle

// 'tacctl rollback <version>' (docs/plans/0.2.3-plan.md D50 for the tool,
// docs/plans/0.2.4-plan.md D73 for this release's target): the plan and the
// file conversions that prepare tacctl's state for the release before this
// one. The command (internal/cli/rollback.go) adds what needs the
// invocation: the snapshot and the sudoers installer.
//
// The target is 0.2.3 only. A release's tool converts what that release
// changed and prepares the state for the one before it, so 0.2.2 is reached
// in two steps: this tool, the install of 0.2.3, then 0.2.3's own tool. The
// formats 0.2.4 changed, and what a 0.2.3 binary does with each (verified
// against the sources of the 0.2.3 tag):
//
//	store.yaml             not changed in 0.2.4; left alone.
//	tacctl.yaml            0.2.3's schema lacks device.config.max_concurrency,
//	                       .transport and .timeout: its 'config validate'
//	                       reports them and its 'backup restore' refuses a
//	                       snapshot that has them. They are removed
//	                       (conf.Added024 and any other key it does not
//	                       know).
//	console.yaml           0.2.3's parser rejects settings.password_cache;
//	                       removed (console.Rollback). 'tiers.engineer' and
//	                       'settings.space_completion' are 0.2.3's own.
//	devices.yaml           0.2.3's parser rejects the per-device 'snmp:' map;
//	                       removed (devreg.RollbackSNMP).
//	snmp/devices/*.yaml    the per-device credentials: 0.2.3 opens
//	                       snmp/<scope>.yaml by name and never lists the
//	                       directory, so it ignores the subdirectory; left.
//	                       (0.2.4 itself keeps them when a device goes, and
//	                       refuses a new device of that name: the rollback
//	                       does not delete a credential.)
//	VarLib records         devices-config.json and device-config/: files
//	                       0.2.3 never opens, derived and rebuilt by a pull;
//	                       left (the dry run lists them, 'tacctl device
//	                       config forget --all' deletes them before the
//	                       rollback).
//	sudoers drop-ins       the per-tier drop-in and the one 'config sudoers
//	                       install <group>' wrote carry the password cache's
//	                       Cmnd_Alias and env_keep line, and the tiers one
//	                       the rows of 'device config', 'device snmp' and
//	                       'console forget'. Sudo accepts both, but 0.2.3's
//	                       upgrade compares the tiers file with its own text
//	                       and its group drop-in is never refreshed: a file
//	                       that is exactly this release's text is rewritten
//	                       with 0.2.3's (tier.Sudoers023, GroupSudoers023,
//	                       through 'visudo -cf'); any other file is left.
//	hosts                  0.2.4 changed nothing on the enrolled Linux hosts;
//	                       '--hosts' is accepted and says so.
//
// What is not a rollback step: the rendered backend files (nothing 0.2.4
// changed reaches them), the sshd drop-ins, the tier-pin marker and the host
// records (all as 0.2.3 has them).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// RollbackTarget is the one release 'tacctl rollback' prepares for.
const RollbackTarget = "0.2.3"

// RollbackRefusal is a version the command does not take: Lines say why.
type RollbackRefusal struct{ Lines []string }

func (e *RollbackRefusal) Error() string { return strings.Join(e.Lines, " ") }

var reVersion = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

const rollbackUsage = "Usage: tacctl rollback " + RollbackTarget + " [--apply] [--yes] [--hosts]"

// CheckRollbackVersion is the version a rollback is asked for ("0.2.3" or
// "v0.2.3"), or a *RollbackRefusal: an older release (this tool converts what
// 0.2.4 changed, so 0.2.2 is two steps away), this release or a newer one,
// or something that is not a release.
func CheckRollbackVersion(arg string) (string, error) {
	m := reVersion.FindStringSubmatch(arg)
	if m == nil {
		return "", &RollbackRefusal{Lines: []string{
			"'" + arg + "' is not a release this tacctl knows.",
			rollbackUsage}}
	}
	v := strings.TrimPrefix(arg, "v")
	if v == RollbackTarget {
		return v, nil
	}
	n := func(i int) int { x, _ := strconv.Atoi(m[i]); return x }
	older := n(1) == 0 && (n(2) < 2 || (n(2) == 2 && n(3) < 3))
	if older {
		return "", &RollbackRefusal{Lines: []string{
			"Rolling back to " + v + " is not supported from this release: 'tacctl rollback' converts what 0.2.4 changed and prepares the state for " + RollbackTarget + " only (" + v + " is older).",
			"Go back one release at a time: run 'tacctl rollback " + RollbackTarget + " --apply', install it with 'tacctl upgrade --branch " + RollbackTarget + "', and run the rollback of that release",
			"(" + RollbackTarget + "'s prepares the state for 0.2.2). The fallback that needs no tool is 'tacctl backup restore' of a snapshot of the time (see 'tacctl backup list')."}}
	}
	return "", &RollbackRefusal{Lines: []string{
		"'" + v + "' is not a release to roll back to: 'tacctl rollback' prepares the state for " + RollbackTarget + " only.",
		rollbackUsage}}
}

// RollbackInput is what a plan reads.
type RollbackInput struct {
	Paths paths.Paths
	Conf  *conf.Config
	// HasStore: the install has a store, so snapshots can be taken.
	HasStore bool
	// WithHosts: the command was given --hosts.
	WithHosts bool
	// InstallSudoers writes a sudoers drop-in the way the commands do
	// ('visudo -cf', then install); nil: the drop-ins are listed and left.
	InstallSudoers func(body, dst string) error
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
	snmpDev []devSNMP
	sudoers []sudoersPlan
	// notWritten says, after ApplyRollback, which drop-ins could not be
	// rewritten and why (the apply goes on: 0.2.3's upgrade rewrites the
	// tiers one itself).
	notWritten []string
}

// devSNMP is a device with SNMP settings of its own, described.
type devSNMP struct {
	name, what string
}

// sudoersPlan is one drop-in the rollback may rewrite.
type sudoersPlan struct {
	label, file, body string
	// state: "rewrite" (todo), "done" (already 0.2.3's text), "left" (not
	// this release's text) or "absent".
	state string
}

// Pending: there is a file to convert.
func (p *RollbackPlan) Pending() bool {
	return len(p.keys) > 0 || p.console.Text != nil || len(p.snmpDev) > 0 || len(p.todoSudoers()) > 0
}

// PendingFiles: there is a file of tacctl's own to convert (the snapshot
// holds those; the sudoers drop-ins are not in it).
func (p *RollbackPlan) PendingFiles() bool {
	return len(p.keys) > 0 || p.console.Text != nil || len(p.snmpDev) > 0
}

func (p *RollbackPlan) todoSudoers() []sudoersPlan {
	var out []sudoersPlan
	for _, s := range p.sudoers {
		if s.state == "rewrite" {
			out = append(out, s)
		}
	}
	return out
}

// NeedsYes: there are warnings that --yes must acknowledge.
func (p *RollbackPlan) NeedsYes() bool { return len(p.Warnings) > 0 }

// Keys are the tacctl.yaml keys that are removed.
func (p *RollbackPlan) Keys() []string { return slices.Clone(p.keys) }

// NotWritten are the sudoers drop-ins ApplyRollback could not rewrite, one
// line each.
func (p *RollbackPlan) NotWritten() []string { return slices.Clone(p.notWritten) }

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
	p.keys = in.Conf.RollbackKeys023()
	p.Steps = append(p.Steps, p.confStep())

	// 2. console.yaml
	cp, err := console.PlanRollback(pa.ConsoleFile)
	if err != nil {
		return nil, err
	}
	p.console = cp
	p.Steps = append(p.Steps, p.consoleStep())

	// 3. devices.yaml
	reg, err := devreg.Load(pa.DevicesFile)
	if err != nil {
		return nil, err
	}
	for _, d := range reg.Devices {
		if !d.SNMP.Empty() {
			p.snmpDev = append(p.snmpDev, devSNMP{d.Name, describeSNMP(d.SNMP)})
		}
	}
	p.Steps = append(p.Steps, p.devicesStep())

	// 4. The sudoers drop-ins.
	p.sudoers = p.planSudoers()
	p.Steps = append(p.Steps, p.sudoersStep())

	// 5 to 7: what stays.
	p.Steps = append(p.Steps, p.credentialsStep(), p.recordsStep(), p.storeStep())

	// 8. The hosts.
	if in.WithHosts {
		p.Steps = append(p.Steps, p.hostsStep())
	}

	p.Warnings = p.warnings()
	p.Notes = p.notes()
	return p, nil
}

func describeSNMP(s devreg.SNMP) string {
	var w []string
	if s.Version != "" {
		w = append(w, "version "+s.Version)
	}
	if s.Port != 0 {
		w = append(w, "port "+strconv.Itoa(s.Port))
	}
	if s.Timeout != 0 {
		w = append(w, "timeout "+strconv.Itoa(s.Timeout)+" s")
	}
	if n := len(s.Clients); n > 0 {
		w = append(w, fmt.Sprintf("%d client %s", n, plural(n, "range", "ranges")))
	}
	return strings.Join(w, ", ")
}

func (p *RollbackPlan) confStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys 0.2.3 does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (every key is one 0.2.3 has)"}
		return s
	}
	var added, other []string
	for _, k := range p.keys {
		if conf.Added024Key(k) {
			added = append(added, k)
		} else {
			other = append(other, k)
		}
	}
	for _, k := range added {
		s.Lines = append(s.Lines, "remove "+k)
	}
	for _, k := range other {
		s.Lines = append(s.Lines, "remove "+k+"  (no release knows this key; 0.2.3 refuses a file that has it)")
	}
	s.Lines = append(s.Lines, "(a 'device config pull' of 0.2.4 reads these; every other key is one 0.2.3 has and stays)")
	return s
}

func (p *RollbackPlan) consoleStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.ConsoleFile + ": write it the way 0.2.3 reads it", Todo: p.console.Text != nil}
	switch {
	case !p.console.Exists:
		s.Lines = []string{"no file (0.2.3 reads the defaults, as 0.2.4 does)"}
	case p.console.Text == nil:
		s.Lines = []string{"nothing to remove (settings.password_cache is not written)"}
	default:
		for _, k := range p.console.Remove {
			s.Lines = append(s.Lines, "remove "+k)
		}
		s.Lines = append(s.Lines, "(0.2.3's parser rejects the key; every other setting is kept, the password cache is off again)")
	}
	return s
}

func (p *RollbackPlan) devicesStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.DevicesFile + ": remove the per-device SNMP settings", Todo: len(p.snmpDev) > 0}
	if len(p.snmpDev) == 0 {
		s.Lines = []string{"no device has SNMP settings of its own"}
		return s
	}
	for _, d := range p.snmpDev {
		s.Lines = append(s.Lines, "remove the snmp map of "+d.name+" ("+d.what+")")
	}
	s.Lines = append(s.Lines, "(0.2.3's parser refuses a device with a key it does not know: \"unknown key 'snmp'\")")
	return s
}

// planSudoers reads the two drop-ins.
func (p *RollbackPlan) planSudoers() []sudoersPlan {
	var out []sudoersPlan
	pt := p.in.Paths

	tiers := sudoersPlan{label: "the per-tier drop-in", file: pt.TierSudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.TierSudoersFile); err == nil {
		switch got := string(b); {
		case got == tier.Sudoers():
			tiers.state, tiers.body = "rewrite", tier.Sudoers023()
		case got == tier.Sudoers023():
			tiers.state = "done"
		default:
			tiers.state = "left"
		}
	}
	out = append(out, tiers)

	group := sudoersPlan{label: "the group drop-in", file: pt.SudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.SudoersFile); err == nil {
		name, kind := tier.ClassifyGroupSudoers(string(b))
		switch kind {
		case tier.GroupCurrent:
			group.label = "the drop-in of group " + name
			group.state, group.body = "rewrite", tier.GroupSudoers023(name)
		case tier.GroupOlder:
			group.label = "the drop-in of group " + name
			group.state = "done"
		default:
			group.state = "left"
		}
	}
	out = append(out, group)
	return out
}

func (p *RollbackPlan) sudoersStep() RollbackStep {
	s := RollbackStep{Title: "put back the sudoers drop-ins 0.2.3 writes", Todo: len(p.todoSudoers()) > 0}
	for _, d := range p.sudoers {
		switch d.state {
		case "rewrite":
			s.Lines = append(s.Lines, "rewrite "+d.file+" ("+d.label+": 0.2.3's text, after 'visudo -cf'; it loses the TACCTL_ASKPASS alias and env_keep line"+
				map[bool]string{true: " and the rows of 'device config', 'device snmp' and 'console forget'", false: ""}[d.label == "the per-tier drop-in"]+")")
			if p.in.InstallSudoers == nil {
				s.Lines[len(s.Lines)-1] += " [not rewritten: no installer]"
			}
		case "done":
			s.Lines = append(s.Lines, d.file+" ("+d.label+") is already the text 0.2.3 writes")
		case "left":
			s.Lines = append(s.Lines, "leaves "+d.file+": it is not the text this release writes (edited, or another release's)"+
				map[bool]string{true: "; 0.2.3's upgrade rewrites the per-tier drop-in with its own text", false: "; sudo accepts it, and 0.2.3 ignores the lines it does not use"}[d.label == "the per-tier drop-in"])
		}
	}
	if len(s.Lines) == 0 || !slices.ContainsFunc(p.sudoers, func(d sudoersPlan) bool { return d.state != "absent" }) {
		s.Lines = []string{"no tacctl sudoers drop-in is installed (" + p.in.Paths.TierSudoersFile + ", " + p.in.Paths.SudoersFile + ")"}
	}
	return s
}

// deviceCredentialFiles are the per-device credential files of 0.2.4.
func (p *RollbackPlan) deviceCredentialFiles() []string {
	matches, _ := filepath.Glob(filepath.Join(p.in.Paths.SNMPDir, "devices", "*.yaml"))
	sort.Strings(matches)
	return matches
}

func (p *RollbackPlan) credentialsStep() RollbackStep {
	dir := filepath.Join(p.in.Paths.SNMPDir, "devices")
	s := RollbackStep{Title: "leave " + dir + " (the devices' own SNMP credentials)"}
	files := p.deviceCredentialFiles()
	if len(files) == 0 {
		s.Lines = []string{"no file there"}
		return s
	}
	var names []string
	for _, f := range files {
		names = append(names, strings.TrimSuffix(filepath.Base(f), ".yaml"))
	}
	s.Lines = []string{fmt.Sprintf("%d %s (mode 0600, kept): %s", len(files), plural(len(files), "file", "files"), strings.Join(names, ", ")),
		"0.2.3 opens snmp/<scope>.yaml by name and never lists the directory, so it ignores the subdirectory; 0.2.4 finds the files again",
		"(a credential is not deleted by a rollback; 'tacctl device snmp <name> clear' of 0.2.4 removes one, and the snapshot --apply takes first holds them)"}
	return s
}

func (p *RollbackPlan) recordsStep() RollbackStep {
	pt := p.in.Paths
	s := RollbackStep{Title: "leave the configuration records in " + pt.VarLib}
	var found []string
	if fi, err := os.Stat(pt.ConfigRecords); err == nil && fi.Mode().IsRegular() {
		found = append(found, pt.ConfigRecords)
	}
	if ents, err := os.ReadDir(pt.ConfigDir); err == nil {
		n := 0
		for _, e := range ents {
			if e.Type().IsRegular() {
				n++
			}
		}
		if n > 0 {
			found = append(found, fmt.Sprintf("%s (%d %s)", pt.ConfigDir, n, plural(n, "file", "files")))
		}
	}
	if len(found) == 0 {
		s.Lines = []string{"no record of a configuration pull"}
		return s
	}
	for _, f := range found {
		s.Lines = append(s.Lines, "leaves "+f)
	}
	s.Lines = append(s.Lines, "(derived from the devices and the last pulls, never in a snapshot; 0.2.3 does not open them and 0.2.4 rebuilds them;",
		" 'tacctl device config forget --all' of 0.2.4, before the rollback, deletes them, or delete the files by hand)")
	return s
}

func (p *RollbackPlan) storeStep() RollbackStep {
	return RollbackStep{Title: "leave " + p.in.Paths.StoreFile + " untouched",
		Lines: []string{"0.2.4 did not change the format of the store; the file is not read for writing and not written",
			"(nor is the rendered tacquito.yaml or the RADIUS files: nothing that is removed reaches them, so nothing is re-rendered or restarted)"}}
}

func (p *RollbackPlan) hostsStep() RollbackStep {
	return RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
		Lines: []string{"nothing to do for " + RollbackTarget + ": 0.2.4 changed nothing on the hosts (the client script and the sudoers drop-ins there are the ones 0.2.3 writes); no host is synced"}}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// --- warnings and notes ---------------------------------------------------------

func (p *RollbackPlan) warnings() []RollbackWarning {
	var out []RollbackWarning
	in := p.in

	var lines []string
	if len(p.snmpDev) > 0 {
		lines = append(lines, "Devices read with SNMP settings of their own are read with their scope's (or the default's) settings by 0.2.3, and its walkthroughs and 'device check' use those:")
		for _, d := range p.snmpDev {
			lines = append(lines, "  "+d.name+": "+d.what)
		}
		if n := len(p.deviceCredentialFiles()); n > 0 {
			lines = append(lines, "  The devices' own credentials ("+strconv.Itoa(n)+" "+plural(n, "file", "files")+" in "+filepath.Join(in.Paths.SNMPDir, "devices")+") stay, unused by 0.2.3.")
		}
	}
	var dc []string
	for _, k := range p.keys {
		if conf.Added024Key(k) {
			v, _ := in.Conf.Get(k, "")
			dc = append(dc, k+"="+v)
		}
	}
	if len(dc) > 0 {
		lines = append(lines, "The settings of 'device config pull' ("+strings.Join(dc, ", ")+") are removed from tacctl.yaml; 0.2.3 has no such verb.")
	}
	if len(p.console.Remove) > 0 {
		lines = append(lines, "The password cache's settings of console.yaml are removed ("+strings.TrimPrefix(p.console.Remove[0], "settings.password_cache: ")+"): 0.2.3 has no cache, every login is asked for its password.")
	}
	if len(lines) > 0 {
		lines = append(lines, "Everything removed from tacctl.yaml, console.yaml and devices.yaml stays in the snapshot --apply takes first (tacctl backup list); 'tacctl backup restore' of it, with 0.2.4, brings it back.")
		out = append(out, RollbackWarning{Title: "Settings 0.2.3 cannot use are dropped", Lines: lines})
	}
	if !in.HasStore && p.PendingFiles() {
		out = append(out, RollbackWarning{
			Title: "No snapshot can be taken",
			Lines: []string{"This install has no store (legacy read-only mode) and snapshots are taken of the store, so --apply cannot back up the files it converts.",
				"Copy " + in.Paths.Overrides + ", " + in.Paths.ConsoleFile + " and " + in.Paths.DevicesFile + " yourself before you go on."}})
	}
	return out
}

func (p *RollbackPlan) notes() []string {
	var out []string
	if p.PendingFiles() {
		out = append(out, "The snapshot --apply takes holds the 0.2.4 form of these files: restore it with 0.2.4 ('tacctl backup restore'), not with 0.2.3, whose restore refuses a tacctl.yaml with a key it does not know.")
	}
	return out
}

// --- apply ---------------------------------------------------------------------

// ApplyRollback converts the files of the plan: tacctl.yaml, console.yaml
// and devices.yaml, in this order, each in one write, then the sudoers
// drop-ins. The snapshot is the caller's, taken before. It returns one line
// for each file it changed. An error leaves the files already converted
// converted; running the same command again finishes (every step is
// idempotent). A drop-in that cannot be rewritten is not an error: it is
// listed by NotWritten (0.2.3's upgrade rewrites the tiers one, and sudo
// accepts the other).
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
			done = append(done, pt.ConsoleFile+": removed settings.password_cache")
		}
	}
	if len(p.snmpDev) > 0 {
		cleared, err := devreg.RollbackSNMP(pt.DevicesFile, nil)
		if err != nil {
			return done, err
		}
		if len(cleared) > 0 {
			done = append(done, fmt.Sprintf("%s: removed the SNMP settings of %d %s", pt.DevicesFile, len(cleared), plural(len(cleared), "device", "devices")))
		}
	}
	p.notWritten = nil
	for _, d := range p.todoSudoers() {
		if p.in.InstallSudoers == nil {
			p.notWritten = append(p.notWritten, d.file+": no installer")
			continue
		}
		if err := p.in.InstallSudoers(d.body, d.file); err != nil {
			p.notWritten = append(p.notWritten, d.file+": "+strings.Join(strings.Fields(err.Error()), " "))
			continue
		}
		done = append(done, d.file+": rewritten with the text 0.2.3 writes")
	}
	return done, nil
}
