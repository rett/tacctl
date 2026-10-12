package cli

// 'device config diff' (D63, D64, D67): the managed sections of the last
// pull of each selected device against the statements tacctl renders for it
// today, per section; --pull reads the devices first. Nothing is written to
// a device, and a secret is compared by presence only: no output of this
// verb carries a device's encrypted key, community or hash.

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
)

// deviceDiffMeta is what a diff says of the pull it compares.
type deviceDiffMeta struct {
	Pulled    time.Time
	By        string
	Transport string
	Netconf   string
}

// diffDeviceJSON is one device of 'device config diff --json'.
type diffDeviceJSON struct {
	Name           string            `json:"name"`
	Scope          string            `json:"scope"`
	Vendor         string            `json:"vendor"`
	Status         string            `json:"status"`
	Reason         string            `json:"reason,omitempty"`
	Pulled         string            `json:"pulled,omitempty"`
	By             string            `json:"by,omitempty"`
	Transport      string            `json:"transport,omitempty"`
	Netconf        string            `json:"netconf,omitempty"`
	SecretsVisible *bool             `json:"secrets_visible,omitempty"`
	DiffersIn      []string          `json:"differs_in,omitempty"`
	Sections       []pullSectionJSON `json:"sections,omitempty"`
}

// diffText is the lines of one section's comparison that are worth reading:
// what is missing, extra, out of order or not visible, the statements a
// secret stands behind (present, not compared) and the section's notes.
func diffText(r devconf.SectionResult) []string {
	var out []string
	for _, l := range r.Lines {
		if l.Op == devconf.OpSame && !l.Secret {
			continue
		}
		out = append(out, string(l.Op)+" "+cleanLine(l.Text))
	}
	for _, n := range r.Notes {
		out = append(out, "note: "+cleanLine(n))
	}
	return out
}

// printDeviceDiff prints one device's comparison. only limits it to the
// named sections (nil: all six).
func (inv *invocation) printDeviceDiff(name, scope, vendor string, rs []devconf.SectionResult, only []string, secretsVisible bool, meta deviceDiffMeta) {
	head := "Device " + name + " (" + dash(scope) + ", " + vendor + ")"
	if !meta.Pulled.IsZero() {
		head += ": pulled " + seenTime(meta.Pulled)
		if meta.By != "" {
			head += " by " + meta.By
		}
		if meta.Transport != "" {
			head += " over " + meta.Transport
		}
	}
	inv.echo("")
	inv.write(head + "\n")
	if !secretsVisible {
		inv.write("  (the login could not see the device's secrets: a masked one is present, an omitted one is not visible)\n")
	}
	for _, r := range rs {
		if len(only) > 0 && !slices.Contains(only, r.Name) {
			continue
		}
		inv.write("  " + padRight(r.Name, 11) + " " + string(r.State) + "\n")
		if r.State == devconf.StateOK && len(r.Notes) == 0 && !slices.ContainsFunc(r.Lines, func(l devconf.DiffLine) bool { return l.Secret }) {
			continue
		}
		for _, l := range diffText(r) {
			inv.write("      " + l + "\n")
		}
	}
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// deviceConfigDiff is 'device config diff'.
func (inv *invocation) deviceConfigDiff(args []string) error {
	p, err := inv.deviceConfigParse("diff", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("diff"); err != nil {
		return err
	}
	var only []string
	if p.Has("--section") {
		for _, s := range strings.Split(p.Value("--section"), ",") {
			s = strings.TrimSpace(s)
			if !slices.Contains(devconf.SectionNames, s) {
				return inv.argErr("--section takes sections of "+strings.Join(devconf.SectionNames, ", ")+": '"+s+"'",
					"Usage: tacctl device config "+deviceConfigUse("diff"))
			}
			if !slices.Contains(only, s) {
				only = append(only, s)
			}
		}
	}
	pull := p.Has("--pull")
	if !pull {
		for _, f := range []string{"--transport", "--concurrency", "--timeout", "--max-failures"} {
			if p.Has(f) {
				return inv.argErr(f+" is for --pull: the diff alone reads no device.", "Usage: tacctl device config "+deviceConfigUse("diff"))
			}
		}
	}
	pa, err := inv.pullArgsOf(p, "diff")
	if err != nil {
		return err
	}
	sel, err := inv.parseSelection(p, "diff")
	if err != nil {
		return err
	}
	user := inv.sudoUser()
	if pull {
		if user, err = inv.configLogin("device config diff --pull"); err != nil {
			return err
		}
	}
	chosen, err := inv.chooseDevices(sel, user, pull, "diff", pa.render)
	if err != nil {
		return err
	}
	if len(chosen.entries) == 0 {
		return inv.nothingSelected(chosen, p.Has("--json"), true)
	}
	asJSON := p.Has("--json")
	if pull {
		if err := inv.refuseNetconfForCisco(chosen.entries, pa.transport); err != nil {
			return err
		}
	}

	// --pull: read the devices first; the diff then compares what was read.
	pulled := map[string]*pullOutcome{}
	pullFailed := map[string]string{}
	interrupted := false
	if pull {
		view := inv.newPullView(chosen.entries, false, user, asJSON)
		sum, outs, err := inv.runPull(pullBatch{entries: chosen.entries, render: chosen.render, args: pa, user: user, view: view})
		if err != nil {
			return err
		}
		interrupted = sum.Interrupted
		for i, o := range outs {
			e := chosen.entries[i]
			st := sum.Entries[i].Result
			switch {
			case o != nil && st.Status == batch.StatusOK:
				pulled[strings.ToLower(e.Name)] = o
			case o != nil && o.Reason != "":
				pullFailed[strings.ToLower(e.Name)] = o.Reason
			default:
				pullFailed[strings.ToLower(e.Name)] = st.Text()
			}
		}
		if !asJSON {
			inv.echo("")
		}
	}

	store := inv.configStore()
	recs, _ := store.Load()
	var (
		failed, differ int
		js             = []diffDeviceJSON{}
	)
	for _, e := range chosen.entries {
		key := strings.ToLower(e.Name)
		d := diffDeviceJSON{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor}
		meta := deviceDiffMeta{}
		var results []devconf.SectionResult
		var secrets bool
		why := ""
		switch {
		case e.Vendor == "wti":
			why = wtiUnsupported
		case pulled[key] != nil:
			o := pulled[key]
			results, secrets = o.Sections, o.SecretsVisible
			meta = deviceDiffMeta{Pulled: inv.app.Knobs.Now(), By: user, Transport: o.Transport, Netconf: o.Netconf}
		default:
			results, secrets, meta, why = inv.storedDiff(store, recs, chosen.render, e)
			if r := pullFailed[key]; r != "" {
				if results == nil {
					why = "the pull failed (" + r + ")"
				} else {
					why = "the pull failed (" + r + "); this is the last good pull"
				}
			}
		}
		if results == nil {
			failed++
			d.Status, d.Reason = "failed", why
			js = append(js, d)
			if !asJSON {
				inv.echo("")
				inv.write("Device " + e.Name + " (" + dash(e.Scope) + ", " + e.Vendor + "): " + cleanLine(why) + "\n")
				if e.Vendor != "wti" {
					inv.write("  Read it with: tacctl device config pull " + e.Name + "\n")
				}
			}
			continue
		}
		differs := differingSections(results)
		if len(only) > 0 {
			differs = slices.DeleteFunc(slices.Clone(differs), func(s string) bool { return !slices.Contains(only, s) })
		}
		d.Status = "ok"
		switch {
		case pullFailed[key] != "":
			// What is printed is the last good pull's: the device itself was
			// not read, so the run did not do what it was asked.
			d.Status = "failed"
			failed++
		case len(differs) > 0:
			d.Status = "differs"
			differ++
		}
		if why != "" {
			d.Reason = why
		}
		if !meta.Pulled.IsZero() {
			d.Pulled = meta.Pulled.UTC().Format(time.RFC3339)
		}
		d.By, d.Transport, d.Netconf = meta.By, meta.Transport, meta.Netconf
		d.SecretsVisible, d.DiffersIn = &secrets, differs
		for _, r := range results {
			if len(only) > 0 && !slices.Contains(only, r.Name) {
				continue
			}
			d.Sections = append(d.Sections, pullSectionJSON{Name: r.Name, State: string(r.State),
				Lines: diffLinesJSON(visibleLines(r)), Notes: r.Notes})
		}
		js = append(js, d)
		inv.app.Logger(inv.auditContext(), "auth.info", "device config diff user="+inv.sudoUser()+" device="+e.Name+
			" sections="+dash(strings.Join(differs, ",")))
		if !asJSON {
			inv.printDeviceDiff(e.Name, e.Scope, e.Vendor, results, only, secrets, meta)
			if why != "" {
				inv.write("  note: " + cleanLine(why) + "\n")
			}
		}
	}
	if asJSON {
		if err := inv.printJSON(js); err != nil {
			return err
		}
	} else {
		inv.echo("")
		summary := []string{}
		if n := len(chosen.entries) - failed - differ; n > 0 {
			summary = append(summary, strconv.Itoa(n)+" ok")
		}
		if differ > 0 {
			summary = append(summary, strconv.Itoa(differ)+" differ")
		}
		if failed > 0 {
			summary = append(summary, strconv.Itoa(failed)+" failed")
		}
		inv.echo("  " + strings.Join(summary, ", "))
		chosen.printSkipped(inv)
		inv.echo("")
	}
	switch {
	case interrupted:
		return exit(batch.ExitInterrupted)
	case failed > 0:
		return exit(1)
	case p.Has("--exit-code") && differ > 0:
		return exit(batch.ExitDiffers)
	}
	return nil
}

// visibleLines are the lines of a comparison a --json document carries: the
// same ones the text shows.
func visibleLines(r devconf.SectionResult) []devconf.DiffLine {
	var out []devconf.DiffLine
	for _, l := range r.Lines {
		if l.Op == devconf.OpSame && !l.Secret {
			continue
		}
		out = append(out, l)
	}
	return out
}

// storedDiff compares a device's stored sections with what tacctl renders
// for it today. results is nil with a reason when it cannot (never pulled,
// a stored file that cannot be read, nothing to render).
func (inv *invocation) storedDiff(store devconf.Store, recs *devconf.Records, render *managedRender, e devreg.Entry) (results []devconf.SectionResult, secrets bool, meta deviceDiffMeta, why string) {
	rec, ok := recs.Of(e.Name)
	if !ok || rec.Pulled.IsZero() {
		return nil, false, meta, "no configuration has been pulled"
	}
	stored := render.stored(store, e)
	if len(stored) == 0 {
		return nil, false, meta, "the stored sections of the last pull cannot be read"
	}
	expected, err := render.Expected(e)
	if err != nil {
		return nil, false, meta, "cannot build the expected configuration: " + err.Error()
	}
	results, err = devconf.CompareAll(expected, rec.Extracted(stored))
	if err != nil {
		return nil, false, meta, err.Error()
	}
	meta = deviceDiffMeta{Pulled: rec.Pulled, By: rec.By, Transport: rec.Transport, Netconf: rec.Netconf}
	if rec.Result != devconf.ResultOK && rec.Result != "" {
		why = "the last pull ended " + rec.Result + "; this is the last good pull"
	}
	return results, rec.SecretsVisible, meta, why
}
