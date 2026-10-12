package cli

// 'device config plan' (docs/plans/0.2.5-plan.md D94-D112): per device, from
// the last pull, the irregularity report, then ONE delimited paste region
// that can be pasted whole, then the follow-up and the back-out outside it.
// Nothing is written to a device and nothing is read from one unless --pull
// says so (it is the pull of 'device config diff --pull'). The planner is
// internal/devconf/plan; this file is the verb: the selection, the inputs
// from the record, the refusals, the formats and the files.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

// planSections are the sections a plan may name (--section): the other two
// are never planned (netconf and breakglass are the walkthrough's steps). The
// system section exists only for a scope with a system block (0.2.7).
var planSections = []string{"aaa", "roles", "mgmt-acl", "snmp", "system"}

// planOptions is what the command line asked of a plan.
type planOptions struct {
	sections                                    []string
	converge, secrets, noSecrets                bool
	plain, asJSON, backout, pull, force, exitOn bool
	out, outDir, from                           string
}

// planDevice is one device's result: the planner's delta and header, or the
// reason it could not be planned.
type planDevice struct {
	e      devreg.Entry
	h      plan.Header
	d      plan.Delta
	status plan.DeviceStatus
	// cannot is why the device could not be planned ("" when it was).
	cannot string
	// backout is the back-out kept from an earlier plan (--backout prints it,
	// whatever pull it was computed from: it is what was pasted).
	backout *devconf.StoredBackout
	// noBackout is why --backout prints nothing for a kept back-out that is
	// not this device's.
	noBackout string
	// backoutNote is a line about the back-out for standard error: one that
	// could not be saved, one that was kept, one that a plan replaced.
	backoutNote string
}

// planned reports whether the device has a plan.
func (r planDevice) planned() bool { return r.cannot == "" }

// secretsWord is what the output of a device holds, for the audit line:
// none, values (a secret typed in a line) or placeholders (--no-secrets).
func (r planDevice) secretsWord() string {
	switch {
	case !r.planned():
		return "none"
	case r.d.HoldsSecret():
		return "values"
	case r.d.Counts.Placeholders > 0:
		return "placeholders"
	}
	return "none"
}

// parsePlanOptions checks the arguments that need no device (exit 2).
func (inv *invocation) parsePlanOptions(p Parsed) (planOptions, error) {
	usage := "Usage: tacctl device config " + deviceConfigUse("plan")
	o := planOptions{
		converge: p.Has("--converge"), secrets: p.Has("--secrets"), noSecrets: p.Has("--no-secrets"),
		plain: p.Has("--plain"), asJSON: p.Has("--json"), backout: p.Has("--backout"), pull: p.Has("--pull"),
		force: p.Has("--force"), exitOn: p.Has("--exit-code"),
		out: p.Value("--out"), outDir: p.Value("--out-dir"), from: p.Value("--from"),
	}
	bad := func(msg string) (planOptions, error) { return o, inv.argErr(msg, usage) }
	switch {
	case o.secrets && o.noSecrets:
		return bad("--secrets and --no-secrets exclude each other.")
	case o.plain && o.noSecrets:
		return bad("--plain with --no-secrets: a plain file is loaded as it stands, and --no-secrets leaves each secret as a marked line for you to fill in. Drop one of them.")
	case o.plain && o.asJSON:
		return bad("--plain and --json are two formats; give one.")
	case o.backout && o.plain:
		return bad("--plain is the plan's own statements; the back-out is its own region (--backout), with notes a plain file cannot carry.")
	case o.backout && o.asJSON:
		return bad("--backout prints the back-out region; its lines are in the \"backout\" list of --json.")
	case o.backout && o.converge:
		return bad("--backout is the undo of the plan; the cleanup (--converge) has none of its own.")
	case o.backout && o.pull:
		return bad("--backout with --pull: a pull replaces the picture a back-out is computed from, so it would undo nothing. Leave --pull out: --backout prints the back-out tacctl kept from the plan.")
	case p.Has("--out") && o.out == "", p.Has("--out-dir") && o.outDir == "":
		return bad("--out and --out-dir take a path.")
	case o.out != "" && o.outDir != "":
		return bad("--out is one file for one device and --out-dir one file per device: give one.")
	case o.force && o.out == "" && o.outDir == "":
		return bad("--force replaces files that --out or --out-dir would write.")
	}
	if p.Has("--section") {
		for _, s := range strings.Split(p.Value("--section"), ",") {
			s = strings.TrimSpace(s)
			switch {
			case s == "netconf" || s == "breakglass":
				return bad("--section: '" + s + "' is never planned (it is a step of the walkthrough, 'tacctl device config show'); the sections are " +
					strings.Join(planSections, ", ") + ".")
			case !slices.Contains(planSections, s):
				return bad("--section takes sections of " + strings.Join(planSections, ", ") + ": '" + s + "'")
			case !slices.Contains(o.sections, s):
				o.sections = append(o.sections, s)
			}
		}
	}
	if !o.pull {
		for _, f := range []string{"--transport", "--concurrency", "--timeout", "--max-failures"} {
			if p.Has(f) {
				return bad(f + " is for --pull: the plan alone reads no device.")
			}
		}
	}
	if o.from != "" {
		norm, err := devreg.NormalizeAddress(o.from)
		if err != nil || strings.Contains(o.from, "/") {
			return bad("--from takes the address you are logged in to the device from (a single address, no prefix length): '" + o.from + "'")
		}
		o.from = norm
	}
	return o, nil
}

// planRun is what the planning of the devices of one run shares.
type planRun struct {
	inv    *invocation
	opt    planOptions
	render *managedRender
	store  devconf.Store
	user   string
	now    time.Time
	// stale is stale-days.
	stale int
	// failed are the devices a --pull could not read, with the reason.
	failed map[string]string
	wrap   plan.Wrapper
	// dry: the plan is made and nothing is kept (no back-out is saved or
	// removed): 'block check --against' looks at what a text would plan.
	dry bool
}

// header is the box and the "based on" facts of a device.
func (r *planRun) header(e devreg.Entry, rec *devconf.Record) plan.Header {
	proto := "TACACS+"
	if e.Scope != "" {
		choice, source := r.inv.scopeProtocolChoice(e.Scope)
		if p, _ := devices.ResolveProtocol("", choice, source); p == devices.RADIUS {
			proto = "RADIUS"
		}
	}
	h := plan.Header{Device: e.Name, Address: e.Address, Scope: e.Scope, Vendor: e.Vendor, Protocol: proto,
		Now: r.now, Version: r.inv.app.Version, User: r.user, StaleDays: r.stale}
	if h.Version == "" {
		h.Version = "unknown"
	}
	if rec != nil {
		h.Pulled, h.PulledBy, h.Transport, h.SecretsVisible = rec.Pulled, rec.By, rec.Transport, rec.SecretsVisible
		if e.Vendor == "wti" && rec.Unit != nil {
			h.Unit = &plan.UnitInfo{Version: rec.OS, SiteID: rec.Unit.SiteID, OtherSessions: rec.Unit.OtherSessions}
		}
	}
	return h
}

// planOne plans one device from its record.
func (r *planRun) planOne(e devreg.Entry) planDevice {
	out := planDevice{e: e}
	name := e.Name
	pullHint := "tacctl device config pull " + name + " (or --pull)"
	// One consistent read of the record, its sections, its plain view and its
	// stored back-out: a pull of another process writes them under the same
	// lock, and a plan must not mix two pulls.
	snap := r.snapshot(e)
	rec := snap.rec
	out.h = r.header(e, rec)
	cannot := func(why string) planDevice {
		out.cannot = why
		out.status = plan.CannotPlan(out.h, why)
		out.status.BreakglassHeld = r.inv.isHeld(e.Name, e.Address)
		// --backout needs none of the plan's prerequisites (a stale record, a
		// rendering that fails): what was kept is what was pasted
		if r.opt.backout && snap.backout != nil && e.Vendor != "wti" {
			r.keptBackout(&out, e, snap.backout)
			out.backoutNote = "the plan itself cannot be made (" + why + "); the back-out kept from an earlier plan is printed"
		}
		return out
	}
	switch {
	case r.failed[strings.ToLower(name)] != "":
		return cannot("the pull failed (" + r.failed[strings.ToLower(name)] + ")")
	case rec == nil || rec.Pulled.IsZero():
		return cannot("not pulled: " + pullHint)
	case rec.Result != "" && rec.Result != devconf.ResultOK:
		return cannot("the last pull failed (" + rec.Result + "): the picture is not current; pull again: " + pullHint)
	}
	days := int(r.now.Sub(rec.Pulled) / (24 * time.Hour))
	if r.stale > 0 && r.now.Sub(rec.Pulled) > time.Duration(r.stale)*24*time.Hour {
		return cannot("stale pull (" + strconv.Itoa(days) + " days old, stale-days is " + strconv.Itoa(r.stale) + "): " + pullHint)
	}
	expected, err := r.render.Expected(e)
	switch {
	case errors.Is(err, errSyntaxUnknown):
		return cannot("needs pull (the image's configuration syntax is not known): " + pullHint)
	case err != nil:
		return cannot("cannot build the expected configuration: " + strings.Join(msgs(err), " "))
	}
	stored, err := snap.sections, snap.sectionsErr
	if err != nil || len(stored) == 0 {
		return cannot("the stored sections of the last pull cannot be read: " + pullHint)
	}
	current := rec.Extracted(stored)
	var plainView devconf.Extracted
	if snap.plain != nil {
		plainView = rec.Extracted(snap.plain)
	}

	opt := plan.Options{Sections: r.opt.sections, Secrets: r.opt.secrets, NoSecrets: r.opt.noSecrets, From: r.opt.from,
		Scope: e.Scope, Device: name, Converge: r.opt.converge}
	if e.Vendor == "wti" {
		// the facts of the IP tables builder and of the pull that the plan's
		// guards read (the server's address, the other sessions)
		opt.WTI.Server, opt.WTI.ListWhy = r.render.wtiFacts(e)
		if rec.Unit != nil {
			n := rec.Unit.OtherSessions
			opt.WTI.OtherSessions = &n
		}
	}
	if e.Vendor == "cisco" {
		// The one resolution of the comparison and the walkthrough (D113);
		// a scope served over RADIUS has the one syntax. legacy-ssh is the
		// ssh client's and has no part here.
		if r.inv.syntaxMatters(e) {
			opt.Syntax = syntaxOf(e, rec).Syntax
		} else {
			opt.Syntax = plan.SyntaxModern
		}
		if opt.Syntax == "" {
			return cannot("needs pull (the image's configuration syntax is not known): " + pullHint)
		}
		opt.PolicyGaps = r.render.policyGaps(e)
	} else {
		opt.Class = r.inv.callerClass(expected)
	}
	// A device the server was told not to answer: the report says the check
	// cannot pass while the hold stands (the planner is given the fact, it
	// never reads the record).
	if h, held := r.inv.holdOf(e.Name, e.Address); held {
		opt.BreakglassHeld = &plan.BreakglassHold{Since: holdTime(h), By: h.By}
	}
	d, err := plan.Plan(e.Vendor, expected, current, plainView, opt)
	if err != nil {
		return cannot(err.Error())
	}
	out.d = d
	// The whole-paste check on every region the output holds, before any of
	// it is printed: a byte outside printable ASCII or a line of a shape the
	// planner does not make is no paste.
	if err := checkRegions(d, out.h, r.wrap); err != nil {
		out.d = plan.Delta{}
		return cannot("the region is not safe to paste whole: " + err.Error())
	}
	out.status = plan.StatusFor(d, out.h)
	// A refusal that leaves nothing to paste is a refusal (exit 1): the
	// report says why; a refusal beside lines that are pasted is in the
	// report and the cover.
	if out.status.State == plan.StatusCannotPlan {
		out.cannot = out.status.Reason
	}
	if r.dry {
		return out
	}
	// The back-out (D111, point 3). A plan with changes keeps its back-out
	// beside the record, stamped with the pull it was computed from: the
	// check pull the after-steps ask for replaces the picture a back-out is
	// computed from, and this is what --backout prints then. --backout
	// itself never replaces it.
	kept := snap.backout
	sameDevice := kept != nil && kept.Address == e.Address && kept.Vendor == e.Vendor
	switch {
	case r.opt.backout:
		// the one kept prints whatever pull it was computed from: it is what
		// was pasted (a recomputation from the record would be of another
		// plan's options)
		if kept != nil {
			r.keptBackout(&out, e, kept)
		}
	case !d.Empty() && plan.HasBackout(d):
		sections := d.Planned()
		switch {
		case sameDevice && kept.Pulled.Equal(rec.Pulled) && len(kept.Sections) > 0 && subsetOf(sections, kept.Sections):
			// a narrower plan from the same pull: the back-out kept covers
			// what was pasted, this plan's sections included
			out.backoutNote = "the back-out kept from this pull covers " + strings.Join(kept.Sections, ", ") +
				" and is kept: this plan covers " + strings.Join(sections, ", ") + " only"
		default:
			text, berr := plan.StoredBackout(d, out.h, r.wrap)
			if berr == nil {
				berr = r.store.SaveBackout(name, devconf.StoredBackout{Pulled: rec.Pulled, Vendor: e.Vendor, Address: e.Address,
					Sections: sections, Text: text})
			}
			if berr != nil {
				out.backoutNote = "the back-out of this plan could not be kept for later: " + strings.Join(msgs(berr), " ") +
					" Print it now: tacctl device config plan " + name + " --backout"
			} else if kept != nil && !kept.Pulled.Equal(rec.Pulled) {
				// the one kept is of an earlier pull: a plan that was pasted and
				// not undone loses its back-out here, so the report says so
				out.d.Warnings = append(slices.Clone(out.d.Warnings), "this plan replaces the kept back-out of the plan from the pull of "+
					kept.Pulled.UTC().Format("2006-01-02 15:04")+" (UTC); print it first with 'tacctl device config plan "+name+" --backout'")
			}
		}
	case !d.Empty() && kept != nil:
		// changes and no line tacctl can type to undo them: the one kept is of
		// another plan and would be taken for this one's
		if berr := r.store.RemoveBackout(name); berr != nil {
			out.backoutNote = "the back-out kept from an earlier plan could not be removed: " + strings.Join(msgs(berr), " ")
		} else {
			out.d.Warnings = append(slices.Clone(out.d.Warnings), "this plan has no lines tacctl can type to undo it and removes the kept back-out of the plan from the pull of "+
				kept.Pulled.UTC().Format("2006-01-02 15:04")+" (UTC); print it first with 'tacctl device config plan "+name+" --backout'")
		}
	}
	return out
}

// keptBackout sets the back-out --backout prints from the kept one, or says
// why it is not this device's: a name that moved to another address (or
// vendor) is another device.
func (r *planRun) keptBackout(out *planDevice, e devreg.Entry, b *devconf.StoredBackout) {
	out.cannot = ""
	if b.Address != e.Address || b.Vendor != e.Vendor {
		out.noBackout = "nothing to back out: the kept back-out is for another device address"
		return
	}
	out.backout = b
}

// subsetOf reports whether every section of a is in b.
func subsetOf(a, b []string) bool {
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	return true
}

// planSnapshot is what one device's plan reads of the store, in one read.
type planSnapshot struct {
	rec         *devconf.Record
	sections    map[string]devices.Section
	sectionsErr error
	plain       map[string]devices.Section
	backout     *devconf.StoredBackout
}

// snapshot reads a device's record, sections, plain view and stored back-out
// under the store's lock, as one picture.
func (r *planRun) snapshot(e devreg.Entry) planSnapshot {
	var s planSnapshot
	if _, err := os.Stat(r.store.Records); err != nil {
		// nothing was ever pulled: nothing to lock, nothing to create
		return s
	}
	unlock, err := r.store.Lock()
	if err != nil {
		s.sectionsErr = err
		return s
	}
	defer unlock()
	// the back-out of an earlier plan is read first: --backout prints it
	// whatever the rest of the plan finds, and a plan that has changes replaces
	// or keeps it by what it holds
	s.backout, _ = r.store.Backout(e.Name)
	recs, _ := r.store.Load()
	rec, ok := recs.Of(e.Name)
	if !ok {
		return s
	}
	c := *rec
	s.rec = &c
	if c.Pulled.IsZero() {
		return s
	}
	s.sections, s.sectionsErr = r.store.Sections(e.Name, e.Vendor)
	if pv, err := r.store.Plain(e.Name, e.Vendor, c.Pulled); err == nil {
		s.plain = pv
	}
	return s
}

// checkRegions runs plan.CheckRegion over the first region, the cleanup
// and the back-out of a delta.
func checkRegions(d plan.Delta, h plan.Header, w plan.Wrapper) error {
	texts := func(ls []plan.RegionLine) []string {
		var out []string
		for _, l := range ls {
			out = append(out, l.Text)
		}
		return out
	}
	if !d.Empty() {
		if err := plan.CheckRegion(d.Vendor, texts(plan.RegionLines(d, h, w))); err != nil {
			return err
		}
		if plan.HasBackout(d) {
			if err := plan.CheckRegion(d.Vendor, texts(plan.BackoutLines(d, h, w))); err != nil {
				return fmt.Errorf("the back-out: %w", err)
			}
		}
	}
	if !d.Cleanup.Empty() {
		if err := plan.CheckRegion(d.Vendor, texts(plan.CleanupLines(d, h, w))); err != nil {
			return fmt.Errorf("the cleanup: %w", err)
		}
	}
	return nil
}

// policyGaps are the policy values the standard needs that the device's
// scope has not set (D119): warnings of the report, never lines.
func (r *managedRender) policyGaps(e devreg.Entry) []string {
	legacy, _ := r.syntaxFor(e)
	b := r.base[managedKey{vendor: e.Vendor, scope: e.Scope, legacy: legacy}]
	if b == nil || b.problem != "" {
		// a device whose syntax is not known yet: either base has the same
		// scope settings
		for _, alt := range []bool{false, true} {
			if b2 := r.base[managedKey{vendor: e.Vendor, scope: e.Scope, legacy: alt}]; b2 != nil && b2.problem == "" {
				b = b2
				break
			}
		}
	}
	if b == nil || b.problem != "" {
		return nil
	}
	return devices.PolicyGaps(b.req, b.d)
}

// wtiFacts are the facts of a unit's IP tables builder for its scope: the
// address its list must permit and why it could not be built.
func (r *managedRender) wtiFacts(e devreg.Entry) (server, why string) {
	b := r.base[managedKey{vendor: e.Vendor, scope: e.Scope}]
	if b == nil || b.problem != "" {
		return "", ""
	}
	return devices.WTIListFacts(b.req, b.d)
}

// callerClass is the Junos login class the person who asked pastes under:
// their group's class as tacctl renders it (the template user of the group
// is bound to a local class of that name), with the permission bits of the
// rendering. nil when it cannot be told: everything is then planned.
func (inv *invocation) callerClass(expected []devices.Section) *plan.Class {
	m, err := inv.model()
	if err != nil {
		return nil
	}
	u := m.User(inv.sudoUser())
	if u == nil {
		return nil
	}
	g := m.Group(u.Group)
	if g == nil || g.JuniperClass == "" {
		return nil
	}
	var perms []string
	prefix := []string{"set", "system", "login", "class", g.JuniperClass, "permissions"}
	for _, s := range expected {
		if s.Name != "roles" {
			continue
		}
		for _, l := range s.Lines {
			f := strings.Fields(l)
			if len(f) <= len(prefix) || !slices.Equal(f[:len(prefix)], prefix) {
				continue
			}
			for _, w := range f[len(prefix):] {
				if w != "[" && w != "]" && !slices.Contains(perms, w) {
					perms = append(perms, w)
				}
			}
		}
	}
	if len(perms) == 0 {
		return nil
	}
	return &plan.Class{Name: g.JuniperClass, Permissions: perms}
}

// --- the output ----------------------------------------------------------------------

// cannotText is what a device that could not be planned prints in place of
// its output: comment lines, nothing to paste.
func cannotText(r planDevice) string {
	c := "#"
	if r.e.Vendor == "cisco" {
		c = "!"
	}
	addr := ""
	if r.e.Address != "" {
		addr = "  " + r.e.Address
	}
	return fmt.Sprintf("%s %s%s  scope %s  %s: CANNOT BE PLANNED: %s\n", c, r.e.Name, addr, dash(r.e.Scope), r.e.Vendor, cleanLine(r.cannot))
}

// deviceText is one device's output in the format asked for, and the
// second file a plain --converge makes (the cleanup's statements).
func (o planOptions) deviceText(r planDevice, w plan.Wrapper) (text, cleanup string, err error) {
	// a device with no plan at all (never pulled, stale, a read that failed)
	noPlan := r.d.Vendor == ""
	switch {
	case o.backout && r.backout != nil:
		// the one kept from the plan that was pasted, whatever pull replaced
		// the picture it was computed from
		return storedBackoutText(r), "", nil
	case o.backout && r.noBackout != "":
		return cannotNote(r, r.noBackout), "", nil
	case noPlan && o.asJSON:
		b, jerr := plan.CannotPlanJSON(r.h, r.cannot)
		return string(b) + "\n", "", jerr
	case noPlan && o.plain:
		// statements only: the reason is on standard error
		return "", "", nil
	case noPlan:
		return cannotText(r), "", nil
	case o.asJSON:
		b, jerr := plan.JSON(r.d, r.h, w)
		return string(b) + "\n", "", jerr
	case o.backout:
		if r.d.Empty() {
			return cannotNote(r, "nothing to back out: no plan was made from an earlier pull of "+r.e.Name), "", nil
		}
		return planBackout(r.d, r.h, w)
	case o.plain:
		if r.d.Empty() {
			return "", plan.CleanupPlain(r.d, r.h, w), nil
		}
		s, perr := plan.Plain(r.d, r.h, w)
		if perr != nil {
			return "", "", perr
		}
		return s, plan.CleanupPlain(r.d, r.h, w), nil
	}
	return plan.Block(r.d, r.h, w), "", nil
}

// storedBackoutText is the back-out kept from an earlier plan, with a first
// comment line that says which plan it undoes: its sections and the pull it
// was made from.
func storedBackoutText(r planDevice) string {
	c := "#"
	if r.backout.Vendor == "cisco" || strings.HasPrefix(r.backout.Text, "!") {
		c = "!"
	}
	what := "the plan"
	if len(r.backout.Sections) > 0 {
		what = "the plan of " + strings.Join(r.backout.Sections, ", ")
	}
	line := c + " This back-out undoes " + what + " made from the pull of " + r.backout.Pulled.UTC().Format("2006-01-02 15:04") + " (UTC)"
	if r.h.Pulled.After(r.backout.Pulled) {
		line += "; a later pull replaced that picture, so it is the one tacctl kept from that plan"
	} else {
		line += "; it is the one tacctl kept from that plan"
	}
	return line + ".\n" + r.backout.Text
}

// planBackout is the back-out region alone.
func planBackout(d plan.Delta, h plan.Header, w plan.Wrapper) (string, string, error) {
	b, err := plan.Backout(d, h, w)
	return b, "", err
}

// cannotNote is a comment line about a device that has nothing to print.
func cannotNote(r planDevice, why string) string {
	c := "#"
	if r.e.Vendor == "cisco" {
		c = "!"
	}
	return c + " " + r.e.Name + ": " + why + "\n"
}

// rule is the line between the outputs of two devices (a comment of the
// vendor of the one that follows: nothing is ever typed from it).
func rule(vendor string) string {
	c := "#"
	if vendor == "cisco" {
		c = "!"
	}
	return c + " " + strings.Repeat("-", 76) + "\n"
}

// fileName is the file a device's output goes to under --out-dir.
func (o planOptions) fileName(name string) string {
	switch {
	case o.asJSON:
		return name + ".json"
	case o.plain:
		return name + ".set"
	case o.backout:
		return name + ".backout.txt"
	}
	return name + ".txt"
}

// cleanupName is the second file of a plain --converge: name.cleanup.set,
// or the --out file's name with ".cleanup" before its extension.
func cleanupName(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".cleanup" + ext
}

// --- writing as the caller -----------------------------------------------------------

// callerIDs are the user and group of the person who ran sudo.
func (inv *invocation) callerIDs() (uid, gid int, ok bool) {
	u, err1 := strconv.Atoi(inv.app.Env.Get("SUDO_UID"))
	g, err2 := strconv.Atoi(inv.app.Env.Get("SUDO_GID"))
	if err1 != nil {
		return 0, 0, false
	}
	if err2 != nil {
		g = u
	}
	return u, g, true
}

// fsIdentity is what asCaller asks of the system: the thread's groups and
// its file-system user and group, each setter returning the previous value
// (the Linux idiom: setfsuid and setfsgid report no failure, so a second
// call that returns the value just set is the proof it took). A seam, so
// that the restore logic is tested without being root.
type fsIdentity struct {
	getgroups func() ([]int, error)
	setgroups func([]int) error
	setfsuid  func(int) (int, error)
	setfsgid  func(int) (int, error)
}

// systemFSIdentity is the calling thread's own.
var systemFSIdentity = fsIdentity{
	getgroups: unix.Getgroups,
	setgroups: unix.Setgroups,
	setfsuid:  unix.SetfsuidRetUid,
	setfsgid:  unix.SetfsgidRetGid,
}

// withFSIdentity runs fn with the file-system identity uid:gid and no
// supplementary groups, on the calling thread, and puts the thread's own
// identity back. Each change is proved by a second call that returns the
// previous value (a setfsuid that did not take is an error, not a silent
// root). restored is false when the thread's identity could not be put back
// and verified: the caller must then not release the thread.
func withFSIdentity(sys fsIdentity, uid, gid int, fn func() error) (err error, restored bool) {
	groups, gerr := sys.getgroups()
	if gerr != nil {
		return fmt.Errorf("cannot read the groups of this process: %w", gerr), true
	}
	if err := sys.setgroups([]int{gid}); err != nil {
		return fmt.Errorf("cannot write as you: %w", err), true
	}
	// the thread carries another identity from here: undo puts the thread's
	// own back and proves it, in the order that keeps the privilege to do it
	// (the user first: it is the one that holds the capabilities)
	var origUID, origGID int
	var uidSet, gidSet bool
	undo := func() bool {
		ok := true
		restore := func(f func(int) (int, error), was int, set bool) {
			if !set {
				return
			}
			if _, err := f(was); err != nil {
				ok = false
			}
			if prev, err := f(was); err != nil || prev != was {
				ok = false
			}
		}
		restore(sys.setfsuid, origUID, uidSet)
		restore(sys.setfsgid, origGID, gidSet)
		if err := sys.setgroups(groups); err != nil {
			ok = false
		}
		return ok
	}
	// change sets one id, remembers the thread's own (the previous value the
	// first call returns) and proves the change by a second call
	change := func(f func(int) (int, error), id int, orig *int, set *bool, what string) error {
		prev, err := f(id)
		if err != nil {
			return fmt.Errorf("cannot write as you: %w", err)
		}
		*orig, *set = prev, true
		if now, err := f(id); err != nil || now != id {
			return fmt.Errorf("cannot write as you: the %s was not changed", what)
		}
		return nil
	}
	if err := change(sys.setfsgid, gid, &origGID, &gidSet, "file-system group"); err != nil {
		return err, undo()
	}
	if err := change(sys.setfsuid, uid, &origUID, &uidSet, "file-system user"); err != nil {
		return err, undo()
	}
	err = fn()
	return err, undo()
}

// asCaller runs fn with the file-system identity of the person who ran sudo
// (fsuid, fsgid, no supplementary groups, on a thread of its own), so that
// what is created is theirs and is created only where they may create it:
// the verb runs as root, and a path a lower tier names must not be written
// with root's rights. A process that is not root, or has no SUDO_UID, runs
// fn as it is. When the thread's identity cannot be put back and proved the
// thread is not unlocked, and ends with the goroutine.
func (inv *invocation) asCaller(fn func() error) error {
	uid, gid, ok := inv.callerIDs()
	if !ok || os.Geteuid() != 0 {
		return fn()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err, restored := withFSIdentity(systemFSIdentity, uid, gid, fn)
		if restored {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}

// writePrivate writes data to path as a new file, 0600, through a temporary
// file in the same directory: an existing file is refused unless force
// (and then replaced whole, a symbolic link replaced rather than followed).
func writePrivate(path string, data []byte, force bool) error {
	tf, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp)
		}
	}()
	if err := tf.Chmod(0o600); err != nil {
		_ = tf.Close()
		return err
	}
	if _, err := tf.Write(data); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	if force {
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		done = true
		return nil
	}
	// link fails when the name exists, whatever it is
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists (--force replaces it)", path)
		}
		return err
	}
	return nil
}

// planFile is one file of --out or --out-dir.
type planFile struct {
	path string
	data string
}

// writePlanFiles writes the files as the caller: the directory is made 0700
// (an existing one must not be open to others), a name that exists is
// refused for all of them before any is written, unless --force. The stale
// files (regular files of an earlier plan beside a main file that was
// written) are removed after the write; the ones that were there are
// returned.
func (inv *invocation) writePlanFiles(dir string, files []planFile, stale []string, force bool) (removed []string, err error) {
	err = inv.asCaller(func() error {
		if dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("cannot create %s: %w", dir, err)
			}
			st, err := os.Stat(dir)
			if err != nil {
				return err
			}
			if !st.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
			if st.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("%s is open to other users (mode %04o): the files hold what a device runs; use a directory with mode 0700 (chmod 700)", dir, st.Mode().Perm())
			}
		}
		if !force {
			var exist []string
			for _, f := range files {
				if _, err := os.Lstat(f.path); err == nil {
					exist = append(exist, f.path)
				}
			}
			if len(exist) > 0 {
				return fmt.Errorf("%s exist(s) (--force replaces them); nothing was written", strings.Join(exist, ", "))
			}
		}
		for _, f := range files {
			if err := writePrivate(f.path, []byte(f.data), force); err != nil {
				return err
			}
		}
		for _, p := range stale {
			st, err := os.Lstat(p)
			if err != nil || !st.Mode().IsRegular() {
				continue // not there, or not a file of ours: left alone
			}
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("cannot remove %s, a file of an earlier plan: %w", p, err)
			}
			removed = append(removed, p)
		}
		return nil
	})
	return removed, err
}

// --- the verb ------------------------------------------------------------------------

// deviceConfigPlan is 'device config plan'.
func (inv *invocation) deviceConfigPlan(args []string) error {
	p, err := inv.deviceConfigParse("plan", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("plan"); err != nil {
		return err
	}
	usage := "Usage: tacctl device config " + deviceConfigUse("plan")
	opt, err := inv.parsePlanOptions(p)
	if err != nil {
		return err
	}
	pa, err := inv.pullArgsOf(p, "plan")
	if err != nil {
		return err
	}
	sel, err := inv.parseSelection(p, "plan")
	if err != nil {
		return err
	}
	user := inv.sudoUser()
	if opt.pull {
		if user, err = inv.configLogin("device config plan --pull"); err != nil {
			return err
		}
	}
	chosen, err := inv.chooseDevices(sel, user, opt.pull, "plan", pa.render)
	if err != nil {
		return err
	}
	if len(chosen.entries) == 0 {
		if opt.asJSON {
			return inv.printJSON([]any{})
		}
		inv.app.Out.Info("No devices to plan.")
		chosen.printSkippedFor(inv, "plan")
		return nil
	}
	// A WTI unit has no statements and no such sections: refused before
	// anything is read, naming the units.
	var units []string
	for _, e := range chosen.entries {
		if e.Vendor == "wti" {
			units = append(units, e.Name)
		}
	}
	if len(units) > 0 {
		names := strings.Join(units, ", ")
		switch {
		case opt.plain:
			return inv.argErr("--plain is a file of statements to load, and a WTI unit ("+names+") has none: its plan is menu steps to type and one IP tables block to paste. "+
				"Drop --plain, or name the other devices.", usage)
		case slices.ContainsFunc(opt.sections, func(s string) bool { return s == "roles" || s == "system" }):
			return inv.argErr("--section: a WTI unit ("+names+") has no roles or system section; it has aaa, snmp and mgmt-acl. Name the other devices, or leave those sections out.", usage)
		}
	}
	// what depends on how many devices there are
	switch {
	case opt.out != "" && len(chosen.entries) != 1:
		return inv.argErr("--out is one file for one device; "+strconv.Itoa(len(chosen.entries))+" devices are selected: name one, or use --out-dir.", usage)
	case opt.plain && len(chosen.entries) != 1 && opt.outDir == "":
		return inv.argErr("--plain is the statements of one device (a paste into the wrong device is the mistake the output is built to make hard): name one device, or use --out-dir for one file each.", usage)
	case opt.plain && opt.converge && opt.out == "" && opt.outDir == "":
		return inv.argErr("--plain --converge makes two files (the plan's statements and the cleanup's): give --out <file> or --out-dir <dir>.", usage)
	}

	// --pull: read the devices first, as 'diff --pull' does; the progress goes
	// to standard error so that what is redirected is the plan alone.
	failed := map[string]string{}
	interrupted := false
	toPull := chosen.entries
	if opt.pull && len(toPull) > 0 {
		if err := inv.refuseNetconfForCisco(toPull, pa.transport); err != nil {
			return err
		}
		saved := inv.app.Out.Stdout
		inv.app.Out.Stdout = inv.app.Out.Stderr
		view := inv.newPullView(toPull, false, user, opt.asJSON)
		sum, outs, rerr := inv.runPull(pullBatch{entries: toPull, render: chosen.render, args: pa, user: user, view: view})
		inv.app.Out.Stdout = saved
		if rerr != nil {
			return rerr
		}
		interrupted = sum.Interrupted
		for i, o := range outs {
			e := toPull[i]
			st := sum.Entries[i].Result
			switch {
			case o != nil && st.Status == batch.StatusOK:
			case o != nil && o.Reason != "":
				failed[strings.ToLower(e.Name)] = o.Reason
			default:
				failed[strings.ToLower(e.Name)] = st.Text()
			}
		}
		if !opt.asJSON {
			inv.stderrLine("")
		}
		// the record changed: what the render knows of it is read again
		chosen.render.prepare(chosen.entries)
	}

	store := inv.configStore()
	staleDays := devreg.DefaultStaleDays
	if f, _, err := inv.deviceLoad(); err == nil && f.StaleDays > 0 {
		staleDays = f.StaleDays
	}
	run := &planRun{inv: inv, opt: opt, render: chosen.render, store: store, user: user,
		now: inv.app.Knobs.Now(), stale: staleDays, failed: failed, wrap: plan.Wrapper{ConfirmMinutes: inv.confirmTimeout()}}
	var results []planDevice
	for _, e := range chosen.entries {
		results = append(results, run.planOne(e))
	}

	// the texts and the files
	type outText struct {
		text, cleanup string
	}
	texts := make([]outText, len(results))
	cannot, needs := 0, 0
	for i, r := range results {
		t, c, err := opt.deviceText(r, run.wrap)
		switch {
		case errors.Is(err, plan.ErrNoBackout):
			// a plan with lines and no line tacctl can type to undo it
			results[i].cannot = "there is nothing tacctl can type to undo this plan"
			results[i].status = plan.CannotPlan(r.h, results[i].cannot)
			t = cannotText(results[i])
		case err != nil:
			return err
		}
		texts[i] = outText{t, c}
		if !results[i].planned() {
			cannot++
		} else if results[i].status.State == plan.StatusNeedsChange {
			needs++
		}
	}

	written := map[string]string{}
	var files []planFile
	// companions are the files of an earlier run that sit beside a device's
	// main file and that this run may not write: the cleanup file of a plain
	// plan, the back-out of a text plan. When the main file is written they
	// are the old plan's, and a technician who loads the pair would run the
	// old cleanup beside the new statements (B1 through files).
	var companions []string
	switch {
	case opt.out != "":
		path, aerr := filepath.Abs(opt.out)
		if aerr != nil {
			return aerr
		}
		switch {
		case opt.plain && !results[0].planned():
			// a plain file of a device that could not be planned would read
			// as "nothing to load": there is none (the reason is above)
			inv.stderrLine(results[0].e.Name + ": no file written: it cannot be planned, and an empty plain file would read as 'nothing to load'.")
		default:
			files = append(files, planFile{path, texts[0].text})
			if opt.plain && opt.converge && texts[0].cleanup != "" {
				files = append(files, planFile{cleanupName(path), texts[0].cleanup})
			}
			if opt.plain {
				companions = append(companions, cleanupName(path))
			}
			written[strings.ToLower(results[0].e.Name)] = path
		}
	case opt.outDir != "":
		dir, aerr := filepath.Abs(opt.outDir)
		if aerr != nil {
			return aerr
		}
		// the cover is a file of the run only when there is more than one
		// device: a device named COVER is then fine for a single one
		seen := map[string]bool{}
		if len(results) > 1 {
			seen["COVER.txt"] = true
		}
		for i, r := range results {
			// A plain file of a device that could not be planned would read
			// as "nothing to load": there is none (the cover says why).
			if opt.plain && !r.planned() {
				inv.stderrLine(r.e.Name + ": no file written: it cannot be planned, and an empty plain file would read as 'nothing to load'.")
				continue
			}
			name := opt.fileName(r.e.Name)
			if seen[name] || filepath.Base(name) != name {
				return inv.argErr("the file name '"+name+"' of device '"+r.e.Name+"' is taken or is not a plain file name.", usage)
			}
			seen[name] = true
			files = append(files, planFile{filepath.Join(dir, name), texts[i].text})
			written[strings.ToLower(r.e.Name)] = filepath.Join(dir, name)
			switch {
			case opt.plain:
				// the file of this mode's own family that this run may not write
				companions = append(companions, filepath.Join(dir, cleanupName(name)))
			case !opt.asJSON && !opt.backout:
				companions = append(companions, filepath.Join(dir, r.e.Name+".backout.txt"))
			}
			if opt.plain && opt.converge && texts[i].cleanup != "" {
				// the cleanup's own name counts as a file of the run too: the
				// plain file of a device called x.cleanup is the same file
				cn := cleanupName(name)
				if seen[cn] {
					return inv.argErr("the file name '"+cn+"' of the cleanup of device '"+r.e.Name+"' is taken.", usage)
				}
				seen[cn] = true
				files = append(files, planFile{filepath.Join(dir, cn), texts[i].cleanup})
			}
			// The back-out of the plan is kept beside it: a pull made after
			// the paste replaces what it is computed from.
			if !opt.plain && !opt.asJSON && !opt.backout && r.planned() && !r.d.Empty() {
				if bo, berr := plan.Backout(r.d, r.h, run.wrap); berr == nil {
					bn := r.e.Name + ".backout.txt"
					if seen[bn] {
						return inv.argErr("the file name '"+bn+"' is taken.", usage)
					}
					seen[bn] = true
					files = append(files, planFile{filepath.Join(dir, bn), bo})
				}
			}
		}
		if len(results) > 1 {
			var sts []plan.DeviceStatus
			for _, r := range results {
				sts = append(sts, r.status)
			}
			files = append(files, planFile{filepath.Join(dir, "COVER.txt"), plan.Cover(sts)})
		}
	}
	if len(files) > 0 {
		dir := ""
		if opt.outDir != "" {
			dir, _ = filepath.Abs(opt.outDir)
		}
		// the companions this run does not write are removed with the main file
		var stale []string
		for _, c := range companions {
			if !slices.ContainsFunc(files, func(f planFile) bool { return f.path == c }) && !slices.Contains(stale, c) {
				stale = append(stale, c)
			}
		}
		removed, err := inv.writePlanFiles(dir, files, stale, opt.force)
		if err != nil {
			inv.app.Out.ErrorE(err.Error())
			return exit(1)
		}
		for _, f := range removed {
			inv.stderrLine("Removed " + f + " (a file of an earlier plan that this plan does not make).")
		}
	}
	// --plain --converge makes the cleanup file only for a device that has a
	// cleanup: for the others one line says why there is none
	if opt.plain && opt.converge {
		for i, r := range results {
			if !r.planned() || texts[i].cleanup != "" || r.d.Vendor == "" {
				continue
			}
			c := r.d.Cleanup
			switch {
			case c.Deferred != "":
				inv.stderrLine(r.e.Name + ": no cleanup file: " + c.Deferred)
			case c.Whole != "":
				inv.stderrLine(r.e.Name + ": no cleanup file: the cleanup is not offered: " + cleanLine(c.Whole))
			default:
				inv.stderrLine(r.e.Name + ": no cleanup file: nothing to remove")
			}
		}
	}

	// the audit lines: never a value
	for _, r := range results {
		out := "-"
		if w := written[strings.ToLower(r.e.Name)]; w != "" {
			out = auditValue(w)
		}
		status := r.status.State
		if status == "" {
			status = plan.StatusCannotPlan
		}
		sections := "-"
		if r.planned() {
			if ps := r.d.Planned(); len(ps) > 0 {
				sections = strings.Join(ps, ",")
			}
		}
		inv.app.Logger(inv.auditContext(), "auth.info", "device config plan user="+inv.sudoUser()+" device="+r.e.Name+
			" status="+status+" sections="+sections+" converge="+yesNo(opt.converge)+" secrets="+r.secretsWord()+" out="+out)
		// a secret by value is said on standard error too, so that a
		// redirected output still carries the warning (D98)
		if r.planned() && r.d.HoldsSecret() && !opt.asJSON {
			if s := plan.Sensitivity(r.d, r.h); s != "" {
				inv.stderrLine(r.e.Name + ": " + s)
			}
		}
		if !r.planned() {
			inv.app.Out.ErrorE(r.e.Name + " cannot be planned: " + cleanLine(r.cannot))
		}
		if r.backoutNote != "" {
			inv.stderrLine(r.e.Name + ": " + cleanLine(r.backoutNote))
		}
	}

	// stdout: the files' summary, or the outputs
	switch {
	case len(files) > 0:
		if len(results) > 1 {
			var sts []plan.DeviceStatus
			for _, r := range results {
				sts = append(sts, r.status)
			}
			inv.write(plan.Cover(sts))
		} else {
			inv.write(statusLine(results[0]))
		}
		for _, f := range files {
			inv.echo("Wrote " + f.path)
		}
	case opt.asJSON:
		var objs []json.RawMessage
		for _, t := range texts {
			objs = append(objs, json.RawMessage(strings.TrimSuffix(t.text, "\n")))
		}
		if err := inv.printJSON(objs); err != nil {
			return err
		}
	default:
		if len(results) > 1 {
			var sts []plan.DeviceStatus
			for _, r := range results {
				sts = append(sts, r.status)
			}
			inv.write(plan.Cover(sts))
		}
		for i, r := range results {
			if len(results) > 1 {
				inv.write(rule(r.e.Vendor))
			}
			inv.write(texts[i].text)
		}
	}
	// what a selection left out is said on standard error: standard output is
	// the plan alone, and may be redirected
	for _, l := range chosen.skipped.linesFor("plan") {
		inv.stderrLine("  " + l)
	}
	switch {
	case interrupted:
		return exit(batch.ExitInterrupted)
	case cannot > 0:
		return exit(1)
	case opt.exitOn && needs > 0:
		return exit(batch.ExitDiffers)
	}
	return nil
}

// auditValue is a value of the audit line: as it stands, or quoted when it
// holds a space, a quote, an equals sign or a byte that is not printable
// (so that a path keeps its field boundaries).
func auditValue(v string) string {
	for _, r := range v {
		if r <= ' ' || r == '"' || r == '=' || r == '\\' || r == 0x7f || r > '~' {
			return strconv.Quote(v)
		}
	}
	return v
}

// statusLine is the one line a single device prints when its output went to
// a file.
func statusLine(r planDevice) string {
	switch {
	case !r.planned():
		return r.e.Name + ": cannot be planned: " + cleanLine(r.cannot) + "\n"
	}
	switch r.status.State {
	case plan.StatusConsistent:
		return r.e.Name + ": consistent\n"
	case plan.StatusLeftAlone:
		return r.e.Name + ": not consistent, nothing to paste\n"
	}
	return r.e.Name + ": needs change\n"
}

// confirmTimeout is device.config.confirm_timeout (D104): the minutes of
// 'commit confirmed' (1-60, default 5); a value the schema would not accept
// is the default.
func (inv *invocation) confirmTimeout() int {
	if n, err := atoiIn(inv.confGet("device.config.confirm_timeout", "5"), 1, 60); err == nil {
		return n
	}
	return 5
}
