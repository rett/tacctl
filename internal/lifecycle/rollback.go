package lifecycle

// 'tacctl rollback <version>' (docs/plans/0.2.3-plan.md D50 for the tool,
// docs/plans/0.2.4-plan.md D73 for this release's target): the plan and the
// file conversions that prepare tacctl's state for the release before this
// one. The command (internal/cli/rollback.go) adds what needs the
// invocation: the snapshot and the sudoers installer.
//
// The targets are 0.2.19 (the release before this one: RollbackTarget0219;
// rollback0219.go: the tiers drop-in and the management filter mode), 0.2.18
// (RollbackTarget0218; rollback0218.go: the tiers drop-in, the lockdown record
// and a warning for the system blocks that hold 0.2.19's statements), 0.2.17
// (RollbackTarget0217, docs/plans/0.2.18-plan.md D273; rollback0217.go: the
// tiers drop-in), 0.2.16 (RollbackTarget0216, docs/plans/0.2.17-plan.md D257;
// rollback0216.go), 0.2.9 (RollbackTarget029,
// docs/plans/0.2.10-plan.md) and 0.2.3 (RollbackTarget). A release's tool
// converts what that release changed and prepares the state for the one
// before it, so 0.2.8 is not a target: the way is this tool for 0.2.9, the
// install of 0.2.9, then that release's own tool.
//
// What the rollback to 0.2.9 does (PlanRollback with Target 0.2.9) is the
// last section of this comment. The rest of it is the rollback to 0.2.3: the
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
//	                       A break-glass hold (0.2.5, breakglass_hold.<device>.*)
//	                       is not removed: the rollback is refused while one
//	                       stands (HeldRefusal), in the dry run and --apply
//	                       alike, because the older release would leave the
//	                       device unanswered until its first render and then
//	                       answer it without anyone releasing the hold.
//	                       A management ACL entry with services (0.2.7,
//	                       <cidr>:tcp/22,udp/161 in mgmt_acl.permits or
//	                       scope_mgmt_acl.permits.<scope>) is not removed or
//	                       rewritten either: 0.2.3 reads the lists as plain
//	                       CIDRs, so a rewrite would permit every protocol
//	                       and port from the source. The rollback is refused
//	                       while one stands (ACLServicesRefusal), in the dry
//	                       run and --apply alike, with each entry and the
//	                       command that removes it.
//	                       The management filter mode of a scope (0.2.20,
//	                       scope_mgmt_acl.mode.<scope>) is removed for this and
//	                       every other target (conf.Added0220), and a warning
//	                       names the scopes that were strict
//	                       (mgmtModeWarning): the older release renders and
//	                       plans the ssh-only filter for them. It is a
//	                       warning, not a refusal, as for the system blocks
//	                       that hold 0.2.19's statements: nothing here touches
//	                       a device, the key cannot stay, and the older
//	                       release's plan is read by a person.
//	console.yaml           0.2.3's parser rejects settings.password_cache;
//	                       removed (console.Rollback). 'tiers.engineer' and
//	                       'settings.space_completion' are 0.2.3's own.
//	                       Every target's parser rejects the settings 0.2.20
//	                       added, settings.color, settings.system_shell_users
//	                       (the system shell of single users),
//	                       settings.password_cache_users (the users who turned
//	                       the password cache on) and a list_max of -1 (never
//	                       ask): removed, and list_max written as 1000
//	                       (console.Keys0220; console.RollbackSince0220 for
//	                       the targets that have the cache).
//	devices.yaml           0.2.3's parser rejects the per-device 'snmp:' map
//	                       and the keys 'ios_syntax' and 'netconf';
//	                       removed (devreg.RollbackSNMP,
//	                       RollbackIOSSyntax, RollbackNetconf).
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
//	                       the rows of 'device config', 'device snmp',
//	                       'console forget', 'host list --json' and
//	                       'config validate --json'. Sudo
//	                       accepts both, but 0.2.3's upgrade compares the
//	                       tiers file with its own text and its group
//	                       drop-in is never refreshed: a file
//	                       that is exactly this release's text, or the one
//	                       0.2.4 to 0.2.19 wrote (tier.Sudoers0219,
//	                       Sudoers0218, Sudoers0217, Sudoers0216,
//	                       Sudoers0214, Sudoers0213, Sudoers028,
//	                       Sudoers027, GroupSudoers026, GroupSudoers027,
//	                       GroupSudoers028, GroupSudoers0216), is
//	                       rewritten with 0.2.3's
//	                       (tier.Sudoers023, GroupSudoers023, through
//	                       'visudo -cf'); any other file is left.
//	hosts                  0.2.4 changed nothing on the enrolled Linux hosts;
//	                       '--hosts' is accepted and says so.
//
// A break-glass entry of the Junos root account (0.2.20, root:admin) is one
// every target's schema accepts: it stays, and every target warns what the
// older release makes of it (rollback_rootbg.go). The root statements 0.2.20's
// pull keeps in the breakglass section of a Junos device's stored sections
// are taken out for every target but 0.2.3, which never opens them
// (rollback_rootleaves.go).
//
// What is not a rollback step: the rendered backend files (nothing 0.2.4
// changed reaches them), the sshd drop-ins, the tier-pin marker and the host
// records (all as 0.2.3 has them).
//
// Every target is refused while the store has a user name with a period
// (0.2.20; DottedUsersRefusal): the targets read letters, digits, '_' and '-'
// only, and fail on every store command with "user '<name>': invalid name".
// An override under such a name in console.yaml (the console switches of a
// user, ignored since 0.2.20) is taken out of the file by the plan; the other
// 'tiers' and 'users' entries stay, for the older release reads them.
//
// Every target is refused while a record of devices-config.json says an
// apply of 'device config apply' is pending or unknown (PendingRefusal): the
// confirmed commit on the device is a state of the device that no file
// conversion settles, and a rollback must not hide a window that is open.
//
// The rollback to 0.2.9 (0.2.10 changed no format 0.2.9 reads strictly except
// one family of settings, the NETCONF service setting of a scope, and one
// per-device key):
//
//	tacctl.yaml            0.2.9's schema lacks device.apply.transport and
//	                       the netconf_scope.<scope>.* keys (conf.Added0210):
//	                       they are removed. Every other key is one 0.2.9 has.
//	devices.yaml           0.2.9's parser rejects the per-device 'netconf:'
//	                       map (the NETCONF service setting of a device):
//	                       removed (devreg.RollbackNetconf).
//	devices-config.json    the 'applied.via' field of the last-pull records
//	                       (the transport an apply wrote through): 0.2.9
//	                       decodes the file without it (unknown JSON fields
//	                       are ignored); left, listed.
//	sudoers drop-ins       no step: sudo accepts them as they are; the tiers
//	                       file is left, and 0.2.9's upgrade rewrites it.
//
// console.yaml, the SNMP credentials, the blocks, the apply state directory
// and the hosts need no conversion (0.2.10 changed none of them).

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
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
)

// RollbackTarget is the oldest release 'tacctl rollback' prepares for;
// RollbackTarget029 is the one before the NETCONF service setting,
// RollbackTarget0216 the one before audit.strict, RollbackTarget0217 the
// one before the renamed verbs, RollbackTarget0218 the one before the
// emergency lockdown and RollbackTarget0219 the release before this one
// (0.2.10 to 0.2.16 changed no format 0.2.9 reads strictly, so 0.2.9 stays a
// target; 0.2.18 changed none 0.2.16 or 0.2.17 reads, so 0.2.16 stays one
// too).
const (
	RollbackTarget     = "0.2.3"
	RollbackTarget029  = "0.2.9"
	RollbackTarget0216 = "0.2.16"
	RollbackTarget0217 = "0.2.17"
	RollbackTarget0218 = "0.2.18"
	RollbackTarget0219 = "0.2.19"
)

// RollbackRefusal is a version the command does not take: Lines say why.
type RollbackRefusal struct{ Lines []string }

func (e *RollbackRefusal) Error() string { return strings.Join(e.Lines, " ") }

// HeldRefusal is the refusal of a rollback while any break-glass hold
// stands: each hold with its address, who held it and since when, why the
// older release cannot take it over and what to run first.
func HeldRefusal(holds []conf.Hold) *RollbackRefusal {
	var lines, release []string
	for _, h := range holds {
		line := "Break-glass is held on " + h.Device + " (" + h.Address
		if h.By != "" {
			line += ", by " + h.By
		}
		if t := h.SinceTime(); !t.IsZero() {
			line += " since " + t.Local().Format("2006-01-02 15:04")
		}
		lines = append(lines, line+").")
		release = append(release, "tacctl breakglass release "+h.Device)
	}
	lines = append(lines,
		RollbackTarget+" has no such record: the device would stay unanswered until "+RollbackTarget+"'s first render and then be answered without anyone releasing it.",
		"Release it first: "+strings.Join(release, "; ")+". Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}

// LockdownRefusal is the refusal of a rollback while any emergency lockdown
// stands: each scope with its groups, who began it and since when, why an
// older release cannot take it over and what to run first.
func LockdownRefusal(ls []conf.Lockdown) *RollbackRefusal {
	var lines, lift []string
	for _, l := range ls {
		line := "Scope " + l.Scope + " is locked down (groups " + strings.Join(l.Groups, ", ")
		if l.By != "" {
			line += ", by " + l.By
		}
		if t := l.SinceTime(); !t.IsZero() {
			line += " since " + t.Local().Format("2006-01-02 15:04")
		}
		lines = append(lines, line+").")
		lift = append(lift, "tacctl emergency lockdown "+l.Scope+" disable")
	}
	lines = append(lines,
		"Every release before 0.2.19 lacks the record: its next render would put the locked users back into the scope.",
		"Lift it first: "+strings.Join(lift, "; ")+". Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}

// ACLServicesRefusal is the refusal of a rollback while any management ACL
// entry carries services (0.2.7: 10.0.0.0/8:tcp/22,udp/161): the older
// release reads the lists as plain CIDRs, so it would refuse the file, and
// a rewrite to the plain CIDR would permit every protocol and port from the
// source. Each entry is listed with its key and the command that removes it.
func ACLServicesRefusal(entries []conf.ACLServiceEntry) *RollbackRefusal {
	var lines []string
	n := len(entries)
	lines = append(lines, "The management ACL has "+strconv.Itoa(n)+" "+pluralWord(n, "entry", "entries")+
		" with services (<cidr>:tcp/22,udp/161), which "+RollbackTarget+
		" does not know: it reads the lists as plain CIDRs, and rewriting an entry to its CIDR would permit every protocol and port from that source.")
	for _, e := range entries {
		cmd := "tacctl config mgmt-acl remove " + e.Entry
		if scope, ok := strings.CutPrefix(e.Key, conf.ScopeMgmtACLPrefix); ok {
			cmd = "tacctl scope mgmt-acl " + scope + " remove " + e.Entry
		}
		lines = append(lines, "  "+e.Key+": "+e.Entry+"   ("+cmd+")")
	}
	lines = append(lines, "Remove them first (or replace each with the plain CIDR you mean it to be, "+
		"knowing a plain entry permits every protocol and port), then run the rollback again. Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

var reVersion = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

const rollbackUsage = "Usage: tacctl rollback " + RollbackTarget0219 + "|" + RollbackTarget0218 + "|" + RollbackTarget0217 + "|" + RollbackTarget0216 + "|" + RollbackTarget029 + "|" + RollbackTarget + " [--apply] [--yes] [--hosts]"

// CheckRollbackVersion is the version a rollback is asked for ("0.2.19",
// "0.2.18", "0.2.17", "0.2.16", "0.2.9", "0.2.3" or any with a "v"), or a *RollbackRefusal: 0.2.4
// to 0.2.8 and older than 0.2.3 (a release's tool prepares the state for the
// releases it knows, so the way back is one release at a time), 0.2.10 to
// 0.2.15, this
// release or a newer one, or something that is not a release (the refusal of
// the last three names the targets and promises no way there).
func CheckRollbackVersion(arg string) (string, error) {
	m := reVersion.FindStringSubmatch(arg)
	if m == nil {
		return "", &RollbackRefusal{Lines: []string{
			"'" + arg + "' is not a release this tacctl knows.",
			rollbackUsage}}
	}
	v := strings.TrimPrefix(arg, "v")
	if v == RollbackTarget || v == RollbackTarget029 || v == RollbackTarget0216 || v == RollbackTarget0217 || v == RollbackTarget0218 || v == RollbackTarget0219 {
		return v, nil
	}
	n := func(i int) int { x, _ := strconv.Atoi(m[i]); return x }
	both := "'tacctl rollback' prepares the state for " + RollbackTarget0219 + " (the release before this one), " + RollbackTarget0218 + ", " + RollbackTarget0217 + ", " + RollbackTarget0216 + ", " + RollbackTarget029 + " and " + RollbackTarget + " only"
	fallback := "The fallback that needs no tool is 'tacctl backup restore' of a snapshot of the time (see 'tacctl backup list')."
	switch {
	case n(1) == 0 && n(2) == 2 && n(3) > 3 && n(3) < 9:
		return "", &RollbackRefusal{Lines: []string{
			"Rolling back to " + v + " is not supported from this release: " + both + " (" + v + " is further back).",
			"Go back one release at a time: run 'tacctl rollback " + RollbackTarget029 + " --apply', install it with 'tacctl upgrade --branch " + RollbackTarget029 + "', and run the rollback of that release",
			"(" + RollbackTarget029 + "'s prepares the state for 0.2.8 and " + RollbackTarget + "). " + fallback}}
	case n(1) == 0 && (n(2) < 2 || (n(2) == 2 && n(3) < 3)):
		return "", &RollbackRefusal{Lines: []string{
			"Rolling back to " + v + " is not supported from this release: " + both + " (" + v + " is older).",
			"Go back one release at a time: run 'tacctl rollback " + RollbackTarget + " --apply', install it with 'tacctl upgrade --branch " + RollbackTarget + "', and run the rollback of that release",
			"(" + RollbackTarget + "'s prepares the state for 0.2.2). " + fallback}}
	}
	return "", &RollbackRefusal{Lines: []string{
		"'" + v + "' is not a release to roll back to: " + both + ".",
		rollbackUsage}}
}

// PendingApply is a device whose record says an apply is not settled.
type PendingApply struct {
	Device string
	// Result is the record's result word: "pending" or "unknown".
	Result string
	ID, By string
	// Until ends a pending window; At is when the record was written.
	Until, At time.Time
}

// PendingRefusal is the refusal of a rollback while any device's record
// says a confirmed commit is pending or unknown: the device itself is in a
// state no file conversion settles, and the older release has no such
// record, so the window would be forgotten. Each device is listed with its
// time and what settles it.
func PendingRefusal(pend []PendingApply) *RollbackRefusal {
	n := len(pend)
	lines := []string{"An apply of 'tacctl device config apply' is not settled on " + strconv.Itoa(n) + " " + pluralWord(n, "device", "devices") +
		" (a confirmed commit is pending or its outcome is unknown):"}
	var first string
	for _, p := range pend {
		line := "  " + p.Device + ": " + p.Result
		if !p.Until.IsZero() {
			line += " until " + p.Until.Local().Format("2006-01-02 15:04")
		} else if !p.At.IsZero() {
			line += " since " + p.At.Local().Format("2006-01-02 15:04")
		}
		var w []string
		if p.ID != "" {
			w = append(w, p.ID)
		}
		if p.By != "" {
			w = append(w, "by "+p.By)
		}
		if len(w) > 0 {
			line += " (" + strings.Join(w, ", ") + ")"
		}
		lines = append(lines, line)
		if first == "" {
			first = p.Device
		}
	}
	lines = append(lines,
		"The state of the apply must be settled first: 'tacctl device config apply "+first+" --check' reads the device and reconciles the record (once the window has ended or the commit was confirmed),",
		"or 'tacctl device config forget "+first+"' drops the record when the device has been dealt with by hand. Then run the rollback again. Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}

// pendingApplies reads devices-config.json for records that are not
// settled. An absent file is none; a file that cannot be read is an error
// (a window that cannot be seen must not be hidden).
func pendingApplies(pa paths.Paths) ([]PendingApply, error) {
	st := devconf.Store{Records: pa.ConfigRecords, Dir: pa.ConfigDir}
	recs, err := st.Load()
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read, so a pending apply cannot be ruled out (%s); move the file aside if no apply is pending (it is derived: a pull rebuilds it), then run the rollback again",
			pa.ConfigRecords, strings.TrimSuffix(strings.Join(strings.Fields(err.Error()), " "), "."))
	}
	var out []PendingApply
	for _, name := range recs.Names() {
		rec, _ := recs.Of(name)
		if rec == nil || !rec.Applied.Pending() {
			continue
		}
		a := rec.Applied
		out = append(out, PendingApply{Device: name, Result: a.Result, ID: a.ID, By: a.By, Until: a.Until, At: a.At})
	}
	return out, nil
}

// RollbackInput is what a plan reads.
type RollbackInput struct {
	Paths paths.Paths
	Conf  *conf.Config
	// HasStore: the install has a store, so snapshots can be taken.
	HasStore bool
	// WithHosts: the command was given --hosts.
	WithHosts bool
	// Target is the release rolled back to: RollbackTarget0219,
	// RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029 or RollbackTarget (the zero value is 0.2.3, as
	// before 0.2.9).
	Target string
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

	// Target is the release the plan prepares for.
	Target string

	in      RollbackInput
	keys    []string
	console console.RollbackPlan
	// pwStore are the users of the store that carry the required password
	// change (0.2.20), which every older release refuses (rollback_pwchange.go).
	pwStore []pwFlag
	// rootLeaf are the stored pulls whose breakglass section holds the root
	// statements of 0.2.20's pull (rollback_rootleaves.go): taken out for
	// the targets that read the records.
	rootLeaf []rootLeafFile
	snmpDev  []devSNMP
	// syntaxDev are the devices with a configuration syntax setting
	// (D113, 0.2.5): an older parser refuses the key, so it goes like the
	// SNMP map does.
	syntaxDev []devSyntax
	// netconfDev are the devices with a NETCONF service setting of their
	// own (0.2.10, D145): removed like the syntax setting is.
	netconfDev []devNetconf
	// syntaxKeyDev are the devices whose configuration syntax setting is
	// written back under the key 0.2.5 to 0.2.17 read, config_syntax
	// (0.2.18, D273; the targets 0.2.17, 0.2.16 and 0.2.9).
	syntaxKeyDev []devSyntax
	sudoers      []sudoersPlan
	// notWritten says, after ApplyRollback, which drop-ins could not be
	// rewritten and why (the apply goes on: 0.2.3's upgrade rewrites the
	// tiers one itself).
	notWritten []string
}

// devSNMP is a device with SNMP settings of its own, described.
type devSNMP struct {
	name, what string
}

// devSyntax is a device with a configuration syntax setting.
type devSyntax struct {
	name, syntax string
}

// devNetconf is a device with a NETCONF service setting of its own,
// described.
type devNetconf struct {
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
	return p.PendingFiles() || len(p.todoSudoers()) > 0 || len(p.rootLeaf) > 0
}

// PendingFiles: there is a file of tacctl's own to convert (the snapshot
// holds those; the sudoers drop-ins and the stored pulls are not in it).
func (p *RollbackPlan) PendingFiles() bool {
	return len(p.keys) > 0 || len(p.pwStore) > 0 || p.console.Text != nil || len(p.snmpDev) > 0 || len(p.syntaxDev) > 0 || len(p.netconfDev) > 0 || len(p.syntaxKeyDev) > 0
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

// target is the release the plan prepares for (0.2.3 when none was named).
func (p *RollbackPlan) target() string {
	if p.Target == "" {
		return RollbackTarget
	}
	return p.Target
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
	if in.Target == "" {
		in.Target = RollbackTarget
	}
	p := &RollbackPlan{in: in, Target: in.Target}
	pa := in.Paths

	// 1. tacctl.yaml
	if prob := in.Conf.Problem(); prob != "" {
		return nil, fmt.Errorf("%s cannot be read (%s); fix it first (tacctl config validate)", pa.Overrides, prob)
	}
	// An apply that is not settled is refused for both targets, in the dry
	// run and --apply alike (PendingRefusal).
	pend, err := pendingApplies(pa)
	if err != nil {
		return nil, err
	}
	if len(pend) > 0 {
		return nil, PendingRefusal(pend)
	}
	// An emergency lockdown (0.2.19) is refused for every target before
	// 0.2.19, in the dry run and --apply alike: no older release has the
	// record, and the next render under it would put every locked user back
	// into the scope. 0.2.19 has the record as this release writes it, and
	// takes a lockdown over as it stands.
	if ls := in.Conf.Lockdowns(); len(ls) > 0 && in.Target != RollbackTarget0219 {
		return nil, LockdownRefusal(ls)
	}
	// A store user name with a period (0.2.20) is refused for every target:
	// no release a rollback goes to reads it (DottedUsersRefusal). An
	// override of such a name in console.yaml is taken out by the plan.
	if inStore, err := DottedUsers(pa, in.HasStore); err != nil {
		return nil, err
	} else if len(inStore) > 0 {
		return nil, DottedUsersRefusal(inStore)
	}
	// The required password change (0.2.20) is a key every older release
	// refuses in the store: it is removed for every target, after the
	// snapshot, with a warning that names the users who get their device
	// access back (rollback_pwchange.go).
	if err := p.planPasswordChange(); err != nil {
		return nil, err
	}
	// Every older release rejects the console settings 0.2.20 added (the
	// colour setting, a list_max that never asks): they are taken out for
	// every target (console.PlanRollbackSince0220; 0.2.3's plan below also
	// reads the file, for the password cache).
	targetPlan := map[string]func(*RollbackPlan) (*RollbackPlan, error){
		RollbackTarget029: planRollback029, RollbackTarget0216: planRollback0216,
		RollbackTarget0217: planRollback0217, RollbackTarget0218: planRollback0218,
		RollbackTarget0219: planRollback0219,
	}[in.Target]
	if targetPlan != nil {
		cp, err := console.PlanRollbackSince0220(pa.ConsoleFile)
		if err != nil {
			return nil, err
		}
		p.console = cp
		rp, err := targetPlan(p)
		if err != nil {
			return nil, err
		}
		rp.addConsoleStep()
		rp.addRootLeaves()
		rp.Warnings = append(rp.Warnings, rp.rootBreakGlassWarning()...)
		rp.addPasswordChange()
		return rp, nil
	}
	// A break-glass hold is refused, in the dry run and --apply alike: the
	// release being left has the record (docs/plans/0.2.5-plan.md D122), and
	// the older one does not, so a device held would stay unanswered until
	// that release's first render and then be answered without anyone
	// releasing it. The rollback would have to render and restart the
	// backends to do better, which no rollback step does.
	if holds := in.Conf.Holds(); len(holds) > 0 {
		return nil, HeldRefusal(holds)
	}
	// A management ACL entry with services (0.2.7) is refused the same way:
	// the older release has no such grammar.
	if entries := in.Conf.MgmtACLServiceEntries(); len(entries) > 0 {
		return nil, ACLServicesRefusal(entries)
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
		if d.IOSSyntax != "" {
			p.syntaxDev = append(p.syntaxDev, devSyntax{d.Name, d.IOSSyntax})
		}
		if !d.Netconf.Empty() {
			p.netconfDev = append(p.netconfDev, devNetconf{d.Name, describeNetconf(d.Netconf)})
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

	p.Warnings = append(append(append(p.warnings(), p.mgmtModeWarning(RollbackTarget)...), p.consoleWideningWarning()...), p.rootBreakGlassWarning()...)
	p.addPasswordChange()
	p.Notes = p.notes()
	return p, nil
}

// describeNetconf says a device's own NETCONF service setting in a few
// words: the state and the limits it states.
func describeNetconf(n devreg.Netconf) string {
	var w []string
	if n.State != "" {
		w = append(w, n.State)
	}
	if n.ConnectionLimit != 0 {
		w = append(w, "connection-limit "+strconv.Itoa(n.ConnectionLimit))
	}
	if n.RateLimit != 0 {
		w = append(w, "rate-limit "+strconv.Itoa(n.RateLimit))
	}
	return strings.Join(w, ", ")
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
		if conf.Added024Key(k) || conf.Added025Key(k) || conf.Added027Key(k) || conf.Added029Key(k) || conf.Added0210Key(k) || conf.Added0217Key(k) || conf.Added0220Key(k) || conf.Added0221Key(k) {
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
	s.Lines = append(s.Lines, "(the settings of 'device config pull' and 'plan', the Cisco source interface, the break-glass records, the list of configuration blocks in force and audit.strict are these; every other key is one 0.2.3 has and stays)")
	return s
}

func (p *RollbackPlan) consoleStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.ConsoleFile + ": write it the way 0.2.3 reads it", Todo: p.console.Text != nil}
	switch {
	case !p.console.Exists:
		s.Lines = []string{"no file (0.2.3 reads the defaults, as 0.2.5 does)"}
	case p.console.Text == nil:
		s.Lines = []string{"nothing to remove (settings.password_cache is not written)"}
	default:
		s.Lines = p.consoleChangeLines()
		s.Lines = append(s.Lines, "(0.2.3's parser rejects them; every other setting is kept"+map[bool]string{true: ", the password cache is off again", false: ""}[p.hasCacheRemoval()]+")")
	}
	return s
}

// consoleChangeLines are the lines of what the plan removes from console.yaml
// and sets in it.
func (p *RollbackPlan) consoleChangeLines() []string {
	var lines []string
	for _, k := range p.console.Remove {
		lines = append(lines, "remove "+k)
	}
	for _, k := range p.console.Set {
		lines = append(lines, "set "+k)
	}
	return lines
}

// hasCacheRemoval reports whether the console plan removes the password
// cache's settings.
func (p *RollbackPlan) hasCacheRemoval() bool {
	return slices.ContainsFunc(p.console.Remove, func(r string) bool { return strings.HasPrefix(r, "settings.password_cache: ") })
}

// addConsoleStep adds the step that takes the settings of 0.2.20 out of
// console.yaml to the plan of a target after 0.2.3, before the step that
// lists what is left alone, and takes the file out of that step's list.
func (p *RollbackPlan) addConsoleStep() {
	if p.console.Text == nil {
		return
	}
	cf := p.in.Paths.ConsoleFile
	s := RollbackStep{Title: cf + ": take out the settings " + p.target() + " does not know", Todo: true}
	s.Lines = append(p.consoleChangeLines(), "("+p.target()+"'s parser rejects what 0.2.20 added to console.yaml (the colour setting, the system shell and the password cache of single users, a list_max of -1) and an override of a user name with a period; everything else is kept)")
	at := len(p.Steps)
	for i := range p.Steps {
		if p.Steps[i].Title == "leave every other file untouched" {
			at = i
			if len(p.Steps[i].Lines) > 0 {
				p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], cf+", ", "", 1)
			}
			break
		}
	}
	p.Steps = slices.Insert(p.Steps, at, s)
}

func (p *RollbackPlan) devicesStep() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.DevicesFile + ": remove the per-device SNMP settings",
		Todo: len(p.snmpDev) > 0 || len(p.syntaxDev) > 0 || len(p.netconfDev) > 0}
	if len(p.syntaxDev) > 0 {
		s.Title += " and configuration syntax"
	}
	if len(p.netconfDev) > 0 {
		s.Title += " and NETCONF service"
	}
	if len(p.snmpDev) == 0 && len(p.syntaxDev) == 0 && len(p.netconfDev) == 0 {
		s.Lines = []string{"no device has SNMP settings of its own"}
		return s
	}
	for _, d := range p.snmpDev {
		s.Lines = append(s.Lines, "remove the snmp map of "+d.name+" ("+d.what+")")
	}
	for _, d := range p.syntaxDev {
		s.Lines = append(s.Lines, "remove the ios_syntax key of "+d.name+" ("+d.syntax+")")
	}
	for _, d := range p.netconfDev {
		s.Lines = append(s.Lines, "remove the netconf map of "+d.name+" ("+d.what+")")
	}
	s.Lines = append(s.Lines, "(0.2.3's parser refuses a device with a key it does not know: \"unknown key 'snmp'\", \"unknown key 'ios_syntax'\", \"unknown key 'netconf'\")")
	return s
}

// planSudoers reads the two drop-ins.
func (p *RollbackPlan) planSudoers() []sudoersPlan {
	var out []sudoersPlan
	pt := p.in.Paths

	tiers := sudoersPlan{label: "the per-tier drop-in", file: pt.TierSudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.TierSudoersFile); err == nil {
		switch got := string(b); {
		case got == tier.Sudoers(), got == tier.Sudoers0219(), got == tier.Sudoers0218(), got == tier.Sudoers0217(), got == tier.Sudoers0216(), got == tier.Sudoers0214(), got == tier.Sudoers0213(), got == tier.Sudoers028(), got == tier.Sudoers027():
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
			// the texts 0.2.4 to 0.2.7 wrote are put back as 0.2.3's; any
			// other older text is 0.2.3's or older already
			if got := string(b); got == tier.GroupSudoers026(name) || got == tier.GroupSudoers027(name) || got == tier.GroupSudoers028(name) ||
				got == tier.GroupSudoers0216(name) {
				group.state, group.body = "rewrite", tier.GroupSudoers023(name)
			} else {
				group.state = "done"
			}
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
				map[bool]string{true: " and the rows of 'device config', 'device snmp', 'console forget', 'host list --json' and 'config validate --json'", false: ""}[d.label == "the per-tier drop-in"]+")")
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
		"0.2.3 opens snmp/<scope>.yaml by name and never lists the directory, so it ignores the subdirectory; 0.2.5 finds the files again",
		"(a credential is not deleted by a rollback; 'tacctl device snmp <name> clear' of 0.2.5 removes one, and the snapshot --apply takes first holds them)"}
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
	if fi, err := os.Stat(pt.ApplyDir); err == nil && fi.IsDir() {
		found = append(found, pt.ApplyDir+" (the shape store and the device locks of 'device config apply')")
	}
	if len(found) == 0 {
		s.Lines = []string{"no record of a configuration pull"}
		return s
	}
	for _, f := range found {
		s.Lines = append(s.Lines, "leaves "+f)
	}
	s.Lines = append(s.Lines, "(derived from the devices and the last pulls, never in a snapshot; 0.2.3 does not open them and 0.2.5 rebuilds them;",
		" 'tacctl device config forget --all' of 0.2.5, before the rollback, deletes them, or delete the files by hand)")
	return s
}

func (p *RollbackPlan) storeStep() RollbackStep {
	return RollbackStep{Title: "leave " + p.in.Paths.StoreFile + " untouched",
		Lines: []string{"0.2.5 did not change the format of the store; the file is not read for writing and not written",
			"(nor is the rendered tacquito.yaml or the RADIUS files: nothing that is removed reaches them, so nothing is re-rendered or restarted)"}}
}

func (p *RollbackPlan) hostsStep() RollbackStep {
	return RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
		Lines: []string{"nothing to do for " + RollbackTarget + ": 0.2.5 changed nothing on the hosts (the client script and the sudoers drop-ins there are the ones 0.2.3 writes); no host is synced"}}
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
	var si []string
	for _, k := range p.keys {
		if conf.Added025Key(k) {
			v, _ := in.Conf.Get(k, "")
			si = append(si, k+"="+v)
		}
	}
	if len(si) > 0 {
		lines = append(lines, "The source interface of the Cisco devices of a scope ("+strings.Join(si, ", ")+") is removed from tacctl.yaml; the walkthroughs of 0.2.3 do not render it.")
	}
	var bl []string
	for _, k := range p.keys {
		if conf.Added027Key(k) {
			bl = append(bl, k)
		}
	}
	if len(bl) > 0 {
		lines = append(lines, "The list of configuration blocks in force ("+strings.Join(bl, ", ")+") is removed from tacctl.yaml; the block files stay in "+in.Paths.BlocksDir+", unused by 0.2.3, and nothing renders them.")
	}
	var ro []string
	for _, k := range p.keys {
		if conf.Added029Key(k) {
			v, _ := in.Conf.Get(k, "")
			ro = append(ro, k+"="+v)
		}
	}
	if len(ro) > 0 {
		lines = append(lines, "The settings of 'device config apply' ("+strings.Join(ro, ", ")+") are removed from tacctl.yaml; 0.2.3 has no such verb.")
	}
	if len(p.syntaxDev) > 0 {
		lines = append(lines, "The configuration syntax setting of a Cisco device (device ios-syntax) is removed: a release without it compares a legacy-ssh device as IOS 12.x again, and renders its walkthrough in the syntax of --legacy only:")
		for _, d := range p.syntaxDev {
			lines = append(lines, "  "+d.name+": "+d.syntax)
		}
	}
	var nc []string
	for _, k := range p.keys {
		if strings.HasPrefix(k, "netconf_scope.") {
			v, _ := in.Conf.Get(k, "")
			nc = append(nc, k+"="+v)
		}
	}
	if len(nc) > 0 || len(p.netconfDev) > 0 {
		lines = append(lines, "The NETCONF service setting (scope netconf, device netconf) is removed; a release without it neither plans nor compares the service, and what a device runs stays as it is:")
		for _, k := range nc {
			lines = append(lines, "  "+k)
		}
		for _, d := range p.netconfDev {
			lines = append(lines, "  "+d.name+": "+d.what)
		}
	}
	for _, r := range p.console.Remove {
		if w, ok := strings.CutPrefix(r, "settings.password_cache: "); ok {
			lines = append(lines, "The password cache's settings of console.yaml are removed ("+w+"): 0.2.3 has no cache, every login is asked for its password.")
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "Everything removed from tacctl.yaml, console.yaml and devices.yaml stays in the snapshot --apply takes first (tacctl backup list); 'tacctl backup restore' of it, with 0.2.5, brings it back.")
		out = append(out, RollbackWarning{Title: "Settings 0.2.3 cannot use are dropped", Lines: lines})
	}
	out = append(out, p.auditStrictWarning(RollbackTarget)...)
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
		out = append(out, "The snapshot --apply takes holds the 0.2.5 form of these files: restore it with 0.2.5 ('tacctl backup restore'), not with 0.2.3, whose restore refuses a tacctl.yaml with a key it does not know.")
	}
	return out
}

// --- apply ---------------------------------------------------------------------

// ApplyRollback converts the files of the plan: tacctl.yaml, the store,
// console.yaml and devices.yaml, in this order, each in one write, the stored
// pulls, then the sudoers drop-ins. The snapshot is the caller's, taken before. It returns one line
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
	if len(p.pwStore) > 0 {
		removed, _, err := store.RollbackPasswordChange(pt.StoreFile, nil)
		if err != nil {
			return done, fmt.Errorf("%s: %w", pt.StoreFile, err)
		}
		if len(removed) > 0 {
			done = append(done, fmt.Sprintf("%s: removed the required password change of %d %s", pt.StoreFile, len(removed), plural(len(removed), "user", "users")))
		}
	}
	if p.console.Text != nil {
		write := console.RollbackSince0220
		if p.target() == RollbackTarget {
			write = console.Rollback
		}
		changed, err := write(pt.ConsoleFile, nil)
		if err != nil {
			return done, err
		}
		if changed {
			done = append(done, pt.ConsoleFile+": "+p.console.Summary())
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
	if len(p.syntaxDev) > 0 {
		cleared, err := devreg.RollbackIOSSyntax(pt.DevicesFile, nil)
		if err != nil {
			return done, err
		}
		if len(cleared) > 0 {
			done = append(done, fmt.Sprintf("%s: removed the configuration syntax of %d %s", pt.DevicesFile, len(cleared), plural(len(cleared), "device", "devices")))
		}
	}
	if len(p.netconfDev) > 0 {
		cleared, err := devreg.RollbackNetconf(pt.DevicesFile, nil)
		if err != nil {
			return done, err
		}
		if len(cleared) > 0 {
			done = append(done, fmt.Sprintf("%s: removed the NETCONF service setting of %d %s", pt.DevicesFile, len(cleared), plural(len(cleared), "device", "devices")))
		}
	}
	// Last of the writes of devices.yaml: every other one writes the key
	// this release reads.
	if len(p.syntaxKeyDev) > 0 {
		names, err := devreg.RollbackIOSSyntaxKey(pt.DevicesFile, nil)
		if err != nil {
			return done, err
		}
		if len(names) > 0 {
			done = append(done, fmt.Sprintf("%s: wrote the configuration syntax of %d %s under %s", pt.DevicesFile, len(names), plural(len(names), "device", "devices"), devreg.OldSyntaxKey))
		}
	}
	if len(p.rootLeaf) > 0 {
		n, err := p.applyRootLeaves()
		if err != nil {
			return done, err
		}
		if n > 0 {
			done = append(done, fmt.Sprintf("%s: took the Junos root statements out of %d stored %s", pt.ConfigDir, n, plural(n, "pull", "pulls")))
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
		done = append(done, d.file+": rewritten with the text "+p.target()+" writes")
	}
	return done, nil
}

// planSyntaxKey fills syntaxKeyDev for a target that reads the setting
// under config_syntax only (0.2.5 to 0.2.17).
func (p *RollbackPlan) planSyntaxKey() error {
	devs, err := devreg.SyntaxKeyed(p.in.Paths.DevicesFile)
	if err != nil {
		return err
	}
	for _, d := range devs {
		p.syntaxKeyDev = append(p.syntaxKeyDev, devSyntax{d.Name, d.IOSSyntax})
	}
	return nil
}

// syntaxKeyStep is the step of devices.yaml for the targets 0.2.17, 0.2.16
// and 0.2.9: the configuration syntax setting under the key they read.
func (p *RollbackPlan) syntaxKeyStep() RollbackStep {
	t := p.target()
	s := RollbackStep{Title: p.in.Paths.DevicesFile + ": write the configuration syntax setting under the key " + t + " reads (" + devreg.OldSyntaxKey + ")",
		Todo: len(p.syntaxKeyDev) > 0}
	if len(p.syntaxKeyDev) == 0 {
		s.Lines = []string{"no device has a configuration syntax setting under ios_syntax"}
		return s
	}
	for _, d := range p.syntaxKeyDev {
		s.Lines = append(s.Lines, "write ios_syntax of "+d.name+" ("+d.syntax+") as "+devreg.OldSyntaxKey)
	}
	s.Lines = append(s.Lines, "("+t+"'s parser refuses a device with a key it does not know: \"unknown key 'ios_syntax'\"; the value and every other key stay)")
	return s
}
