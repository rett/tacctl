package cli

// 'device reports prune --older-than <age>' (docs/plans/0.2.26-plan.md D333):
// remove the reports older than an age. Nothing else deletes a report by age
// and nothing runs it by itself. The age of a report is its own 'generated'
// date in its metadata file, never the file's time; a file with no usable
// metadata (listed as 'other') is not a report of tacctl and is never
// removed, and nothing outside the reports directory is touched (the files
// are listed and removed by the store of device_reports_store.go, with the
// identity of the user whose directory it is, and a link is not followed).
// A superuser can prune the reports of another user (--user) or of every user
// (--all-users); the access to each such user's reports is one audit line,
// written before that user's directory is read (device_reports_super.go).

import (
	"errors"
	"os"
	"strconv"
	"strings"
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

// pruneSet is the reports of one user that a prune would remove.
type pruneSet struct {
	owner string
	// cross: the reports are another user's.
	cross bool
	pl    reportPlace
	files []reportFile
	size  int64
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
	if p.Has("--user") && p.Has("--all-users") {
		return inv.argErr("--user and --all-users are two ways to choose whose reports: give one.", usage)
	}
	if p.Has("--user") && p.Value("--user") == "" {
		return inv.argErr("--user takes a user name.", usage)
	}
	cross := (p.Has("--user") && p.Value("--user") != me) || p.Has("--all-users")
	if cross && !inv.reportsSuper() {
		return inv.reportsDenied("Pruning the reports of other users")
	}
	owners := []string{me}
	switch {
	case p.Has("--all-users"):
		if owners, err = inv.reportOwners(); err != nil {
			return err
		}
	case p.Has("--user"):
		owners = []string{p.Value("--user")}
	}

	// What would go, user by user. A user the server has no account for has
	// no reports; a directory that cannot be read is said and fails the run.
	// The access to another user's reports is audited before the directory is
	// read, for every such user, and all the lines are written before the
	// first directory is read: under audit.strict a line that cannot be
	// written refuses the whole run, with nothing read, listed or changed.
	a := inv.app
	cutoff := a.Knobs.Now().UTC().Add(-span)
	verb := "prune"
	if p.Has("--dry-run") {
		verb = "prune-dry-run"
	}
	var places []reportPlace
	for _, o := range owners {
		pl, err := inv.reportPlaceOf(o)
		if err != nil {
			if len(owners) == 1 {
				return inv.usageErr(err.Error() + ".")
			}
			continue
		}
		if o != me {
			inv.reportsAccess(verb, o, "*")
		}
		places = append(places, pl)
	}
	var sets []pruneSet
	unreadable := 0
	for _, pl := range places {
		d, err := pl.read()
		if err != nil {
			if len(owners) == 1 {
				return inv.usageErr(err.Error())
			}
			a.Out.ErrorE(err.Error() + " (skipped)")
			unreadable++
			continue
		}
		if files, size := prunable(d, cutoff); len(files) > 0 {
			sets = append(sets, pruneSet{owner: pl.user, cross: pl.user != me, pl: pl, files: files, size: size})
		}
	}
	if len(sets) == 0 {
		whose := "no report of yours"
		if cross {
			whose = "no report of the users asked for"
		}
		a.Out.Info("Nothing to prune: " + whose + " is older than " + age + ".")
		if unreadable > 0 {
			return inv.usageErr(howMany(unreadable, "directory") + " could not be read (see above).")
		}
		return nil
	}

	var count int
	var total int64
	for _, s := range sets {
		count += len(s.files)
		total += s.size
	}
	withUser := len(owners) > 1 || cross
	cols := []ui.Col{ui.Left("NAME"), ui.Left("TYPE"), ui.Left("GENERATED"), ui.Right("SIZE")}
	if withUser {
		cols = append([]ui.Col{ui.Left("USER")}, cols...)
	}
	tb := ui.NewTable("Reports older than "+age+" ("+strconv.Itoa(count)+")", cols...)
	for _, s := range sets {
		for _, f := range s.files {
			cells := []any{cleanLine(f.Name), cleanLine(f.Meta.Type), f.Meta.Generated.UTC().Format(reports.DateFormat), reportSize(f.Size)}
			if withUser {
				cells = append([]any{s.owner}, cells...)
			}
			tb.Add(cells...)
		}
	}
	inv.write(tb.String())
	inv.echo("")
	inv.echo("  " + howMany(count, "report") + ", " + reportSize(total) + " in all")
	inv.echo("")
	if p.Has("--dry-run") {
		a.Out.Info("Dry run: nothing was removed.")
		return nil
	}
	about := "About to remove " + howMany(count, "report") + " (" + reportSize(total) + ") and their metadata"
	if len(sets) > 1 || sets[0].cross {
		about += ", of " + howMany(len(sets), "user")
	}
	a.Out.Warn(about + ".")
	if !p.Has("--yes") && !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}

	removed, failed := 0, 0
	var removedSize int64
	for _, s := range sets {
		n := 0
		for _, f := range s.files {
			if err := s.pl.remove(f.File); err != nil && !errors.Is(err, os.ErrNotExist) {
				label := f.File
				if s.cross {
					label = s.owner + "/" + f.File
				}
				a.Out.ErrorE("Cannot remove " + cleanLine(label) + ": " + err.Error())
				failed++
				continue
			}
			n++
			removedSize += f.Size
		}
		removed += n
		if n > 0 && !s.cross {
			inv.detail("device reports prune", kvp("older-than", age), kvp("removed", strconv.Itoa(n)))
		}
	}
	if removed > 0 {
		a.Out.Info("Removed " + howMany(removed, "report") + " (" + reportSize(removedSize) + ").")
	}
	if failed > 0 || unreadable > 0 {
		var what []string
		if failed > 0 {
			what = append(what, howMany(failed, "report")+" could not be removed")
		}
		if unreadable > 0 {
			what = append(what, howMany(unreadable, "directory")+" could not be read")
		}
		msg := strings.Join(what, " and ") + " (see above)."
		if removed > 0 {
			msg += " The others were removed."
		}
		return inv.usageErr(msg)
	}
	return nil
}
