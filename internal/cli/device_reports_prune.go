package cli

// 'device reports prune --older-than <age>' (docs/plans/0.2.26-plan.md D333):
// remove the reports older than an age. Nothing else deletes a report by age
// and nothing runs it by itself. The age of a report is its own 'generated'
// date in its metadata file, never the file's time; a file with no usable
// metadata (listed as 'other') is not a report of tacctl and is never
// removed, and nothing outside the reports directory is touched (the files
// are listed and removed by the store of device_reports_store.go, with the
// identity of the user whose directory it is, and a link is not followed).

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/rett/tacctl/internal/reports"
	"github.com/rett/tacctl/internal/ui"
)

// prunable is the reports of one user that are older than the cutoff: those
// with metadata and a generated date before it, newest first. A metadata file
// with no date (zero) names no age, so its report is kept.
func prunable(d reportDir, cutoff time.Time) (files []reportFile, size int64) {
	for _, f := range d.Files {
		if f.Meta == nil || f.Meta.Generated.IsZero() || !f.Meta.Generated.Before(cutoff) {
			continue
		}
		files = append(files, f)
		size += f.Size
	}
	return files, size
}

// deviceReportsPrune is 'device reports prune'.
func (inv *invocation) deviceReportsPrune(args []string) error {
	p, err := inv.deviceReportsParse("prune", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl device reports " + deviceReportsUse("prune")
	if !p.Has("--older-than") {
		return inv.argErr("--older-than is required: the age of the reports to remove, <n>h, <n>d or <n>w (for example 30d).", usage)
	}
	age := p.Value("--older-than")
	span, err := parseReportAge(age)
	if err != nil {
		return inv.argErr("--older-than: "+err.Error()+".", usage)
	}
	me := inv.sudoUser()
	pl, err := inv.reportPlaceOf(me)
	if err != nil {
		return inv.usageErr(err.Error() + ".")
	}
	d, err := pl.read()
	if err != nil {
		return inv.usageErr(err.Error())
	}
	a := inv.app
	cutoff := a.Knobs.Now().UTC().Add(-span)
	files, size := prunable(d, cutoff)
	if len(files) == 0 {
		a.Out.Info("Nothing to prune: no report of yours is older than " + age + ".")
		return nil
	}

	head := "Reports older than " + age + " (" + strconv.Itoa(len(files)) + ")"
	tb := ui.NewTable(head, ui.Left("NAME"), ui.Left("TYPE"), ui.Left("GENERATED"), ui.Right("SIZE"))
	for _, f := range files {
		tb.Add(cleanLine(f.Name), cleanLine(f.Meta.Type), f.Meta.Generated.UTC().Format(reports.DateFormat), reportSize(f.Size))
	}
	inv.write(tb.String())
	inv.echo("")
	inv.echo("  " + howMany(len(files), "report") + ", " + reportSize(size) + " in all")
	inv.echo("")
	if p.Has("--dry-run") {
		a.Out.Info("Dry run: nothing was removed.")
		return nil
	}
	a.Out.Warn("About to remove " + howMany(len(files), "report") + " (" + reportSize(size) + ") and their metadata.")
	if !p.Has("--yes") && !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}

	removed, failed := 0, 0
	var removedSize int64
	for _, f := range files {
		if err := pl.remove(f.File); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.Out.ErrorE("Cannot remove " + cleanLine(f.File) + ": " + err.Error())
			failed++
			continue
		}
		removed++
		removedSize += f.Size
	}
	if removed > 0 {
		inv.detail("device reports prune", kvp("older-than", age), kvp("removed", strconv.Itoa(removed)))
		a.Out.Info("Removed " + howMany(removed, "report") + " (" + reportSize(removedSize) + ").")
	}
	if failed > 0 {
		return inv.usageErr(howMany(failed, "report") + " could not be removed (see above); the others were.")
	}
	return nil
}
