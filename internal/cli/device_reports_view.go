package cli

// 'device reports list|show|export|rename|remove': what is done with the
// reports that were made (device_reports.go makes them).

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/reports"
	"github.com/rett/tacctl/internal/ui"
)

// reportContentLines is how many lines 'show --content' prints.
const reportContentLines = 200

// listedReport is one row of 'list'.
type listedReport struct {
	owner string
	f     reportFile
}

// reportListJSON is a report in 'list --json'.
type reportListJSON struct {
	Owner      string            `json:"owner"`
	File       string            `json:"file"`
	Name       string            `json:"name"`
	Other      bool              `json:"other"`
	Type       string            `json:"type,omitempty"`
	Format     string            `json:"format,omitempty"`
	User       string            `json:"user,omitempty"`
	Command    string            `json:"command,omitempty"`
	Filters    map[string]string `json:"filters,omitempty"`
	Generated  string            `json:"generated,omitempty"`
	OldestData string            `json:"oldest_data,omitempty"`
	Size       int64             `json:"size"`
	Rows       *int              `json:"rows,omitempty"`
}

// deviceReportsList is 'device reports list'.
func (inv *invocation) deviceReportsList(args []string) error {
	p, err := inv.deviceReportsParse("list", args)
	if err != nil {
		return err
	}
	me := inv.sudoUser()
	usage := "Usage: tacctl device reports " + deviceReportsUse("list")
	if p.Has("--user") && p.Has("--all-users") {
		return inv.argErr("--user and --all-users are two ways to choose whose reports: give one.", usage)
	}
	if p.Has("--user") && p.Value("--user") == "" {
		return inv.argErr("--user takes a user name.", usage)
	}
	cross := (p.Has("--user") && p.Value("--user") != me) || p.Has("--all-users")
	if cross && !inv.reportsSuper() {
		return inv.reportsDenied("Listing the reports of other users")
	}
	owners := []string{me}
	switch {
	case p.Has("--all-users"):
		if owners, err = inv.reportOwners(); err != nil {
			return err
		}
		inv.reportsAccess("list", "*", "*")
	case p.Has("--user"):
		owners = []string{p.Value("--user")}
		if cross {
			inv.reportsAccess("list", owners[0], "*")
		}
	}
	var rows []listedReport
	for _, o := range owners {
		pl, err := inv.reportPlaceOf(o)
		if err != nil {
			if len(owners) == 1 {
				return inv.usageErr(err.Error() + ".")
			}
			continue // a user the server has no account for has no reports
		}
		d, err := pl.read()
		if err != nil {
			if len(owners) == 1 {
				return inv.usageErr(err.Error())
			}
			continue
		}
		for _, f := range d.Files {
			rows = append(rows, listedReport{o, f})
		}
	}
	if p.Has("--json") {
		out := []reportListJSON{}
		for _, r := range rows {
			// every string is cleaned as the text list cleans it: a file name
			// or a metadata field is the user's to write
			j := reportListJSON{Owner: cleanLine(r.owner), File: cleanLine(r.f.File), Name: cleanLine(r.f.Name), Other: r.f.Meta == nil, Size: r.f.Size}
			if m := r.f.Meta; m != nil {
				n := m.Count
				j.Type, j.Format, j.User, j.Command, j.Rows = cleanLine(m.Type), cleanLine(m.Format), cleanLine(m.User), cleanLine(m.Command), &n
				if m.Filters != nil {
					j.Filters = make(map[string]string, len(m.Filters))
					for k, v := range m.Filters {
						j.Filters[cleanLine(k)] = cleanLine(v)
					}
				}
				j.Generated = m.Generated.UTC().Format(time.RFC3339)
				if !m.OldestData.IsZero() {
					j.OldestData = m.OldestData.UTC().Format(time.RFC3339)
				}
			}
			out = append(out, j)
		}
		return inv.printJSON(out)
	}
	withUser := len(owners) > 1 || cross
	head := "Device reports (" + strconv.Itoa(len(rows)) + ")"
	if len(rows) == 0 {
		inv.echo("")
		inv.echoE(ui.Bold + head + ui.NC)
		inv.echo(ui.Rule(head))
		inv.echo("  None. Make one with: tacctl device reports generate --type inventory")
		inv.echo("")
		return nil
	}
	cols := []ui.Col{ui.Left("NAME"), ui.Left("TYPE"), ui.Left("FORMAT"), ui.Right("SIZE"), ui.Left("GENERATED")}
	if withUser {
		cols = append([]ui.Col{ui.Left("USER")}, cols...)
	}
	tb := ui.NewTable(head, cols...)
	var total int64
	for _, r := range rows {
		typ, format, when := "other", "-", "-"
		if m := r.f.Meta; m != nil {
			typ, format, when = m.Type, m.Format, m.Generated.UTC().Format(reports.DateFormat)
		} else if ext := filepath.Ext(r.f.File); ext != "" {
			format = ext[1:]
		}
		cells := []any{cleanLine(r.f.Name), cleanLine(typ), cleanLine(format), reportSize(r.f.Size), when}
		if withUser {
			cells = append([]any{cleanLine(r.owner)}, cells...)
		}
		tb.Add(cells...)
		total += r.f.Size
	}
	inv.write(tb.String())
	inv.echo("")
	inv.echo("  " + howMany(len(rows), "report") + ", " + reportSize(total) + " in all")
	inv.echo("")
	return nil
}

// deviceReportsShow is 'device reports show'.
func (inv *invocation) deviceReportsShow(args []string) error {
	p, err := inv.deviceReportsParse("show", args)
	if err != nil {
		return err
	}
	t, err := inv.reportTargetOf("show", p.Args[0])
	if err != nil {
		return err
	}
	f := t.f
	head := "Report " + f.Name
	inv.echo("")
	inv.echoE(ui.Bold + head + ui.NC)
	inv.echo(ui.Rule(head))
	row := func(k, v string) { inv.write("  " + k + strings.Repeat(" ", max(14-len(k), 1)) + v + "\n") }
	row("File:", cleanLine(filepath.Join(t.pl.dir, f.File)))
	if m := f.Meta; m != nil {
		filters := "none"
		if len(m.Filters) > 0 {
			keys := make([]string, 0, len(m.Filters))
			for k := range m.Filters {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, k+"="+m.Filters[k])
			}
			filters = strings.Join(parts, ", ")
		}
		row("Type:", cleanLine(m.Type))
		row("Generated:", m.Generated.UTC().Format(reports.DateFormat)+" UTC")
		row("User:", cleanLine(m.User))
		row("Command:", cleanLine(m.Command))
		row("Filters:", cleanLine(filters))
		row("Oldest data:", reportAge(m.OldestData))
		row("Format:", cleanLine(m.Format))
		row("Rows:", strconv.Itoa(m.Count))
	} else {
		row("Type:", "other (a file in the directory that tacctl did not make)")
		row("Modified:", f.Mod.Format(reports.DateFormat)+" UTC")
		if f.Note != "" {
			row("Metadata:", cleanLine(f.Note))
		}
	}
	row("Size:", reportSize(f.Size)+" ("+strconv.FormatInt(f.Size, 10)+" bytes)")
	server, _ := inv.serverNameNow()
	rel, err := filepath.Rel(t.pl.home, filepath.Join(t.pl.dir, f.File))
	if err == nil {
		row("Download:", "scp "+t.owner+"@"+server+":"+rel+" .")
	}
	inv.echo("")
	if !p.Has("--content") {
		return nil
	}
	if f.isPDF() {
		// binary: no line of it is shown
		inv.echo("binary PDF, " + strconv.FormatInt(f.Size, 10) + " bytes: use export")
		inv.echo("")
		return nil
	}
	shown, rest, err := t.pl.head(f.File, reportContentLines)
	if err != nil {
		return inv.usageErr("Cannot read the report: " + err.Error())
	}
	for _, l := range shown {
		inv.echo(cleanLine(l))
	}
	switch {
	case rest > 0:
		inv.echo("... " + howMany(rest, "more line") + "; 'tacctl device reports export " + p.Args[0] + "' prints all of it.")
	case rest < 0:
		inv.echo("... more; 'tacctl device reports export " + p.Args[0] + "' prints all of it.")
	}
	inv.echo("")
	return nil
}

// exportLimit is the most export reads of the report: the size limit in force
// for its owner, or reportReadMax when that is none or larger. A report made
// under a higher limit that was lowered since is read to the size its metadata
// records, so that lowering the limit does not lock a report away.
func (inv *invocation) exportLimit(t reportTarget) int64 {
	limit := int64(reportReadMax)
	if max, _ := reportLimits(inv, t.owner); max > 0 && max < limit {
		limit = max
	}
	if m := t.f.Meta; m != nil && m.Size > limit && m.Size <= reportReadMax {
		limit = m.Size
	}
	return limit
}

// deviceReportsExport is 'device reports export'.
func (inv *invocation) deviceReportsExport(args []string) error {
	p, err := inv.deviceReportsParse("export", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl device reports " + deviceReportsUse("export")
	if p.Has("--out") && p.Value("--out") == "" {
		return inv.argErr("--out takes a path.", usage)
	}
	if p.Has("--force") && !p.Has("--out") {
		return inv.argErr("--force replaces the file --out names.", usage)
	}
	t, err := inv.reportTargetOf("export", p.Args[0])
	if err != nil {
		return err
	}
	// a PDF is binary: it is never printed to a terminal, whatever it holds
	if !p.Has("--out") && t.f.isPDF() && inv.hooks.terminalWriter(inv.app.Out.Stdout) {
		return inv.usageErr(pdfBinaryExport)
	}
	b, err := t.pl.content(t.f.File, inv.exportLimit(t))
	if err != nil {
		return inv.usageErr("Cannot read the report: " + err.Error())
	}
	if !p.Has("--out") {
		if t.f.isPDF() {
			// not a terminal (checked above), so nothing here can move one;
			// the bytes go out as they are, past the colour filter
			inv.writeRaw(b)
			return nil
		}
		if t.cross {
			// What another user wrote is not trusted with the superuser's
			// terminal, whatever its metadata file says (the owner makes
			// that too): each line is cleaned as 'show --content' cleans it.
			// --out copies the bytes as they are.
			for rest := string(b); rest != ""; {
				line, after, found := strings.Cut(rest, "\n")
				inv.write(cleanLine(line))
				if found {
					inv.write("\n")
				}
				rest = after
			}
			return nil
		}
		inv.write(string(b))
		return nil
	}
	out := p.Value("--out")
	if err := inv.asCaller(func() error { return writePrivate(out, b, p.Has("--force")) }); err != nil {
		return inv.usageErr("Cannot write " + out + ": " + existsText(err, " (--force replaces it)"))
	}
	inv.app.Out.Info("Copied " + t.f.File + " to " + out + " (" + reportSize(int64(len(b))) + ", mode 0600).")
	return nil
}

// deviceReportsRename is 'device reports rename'.
func (inv *invocation) deviceReportsRename(args []string) error {
	p, err := inv.deviceReportsParse("rename", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl device reports " + deviceReportsUse("rename")
	newName := p.Args[1]
	if err := reports.ValidName(newName); err != nil {
		return inv.argErr("Invalid report name: "+err.Error()+".", usage)
	}
	t, err := inv.reportTargetOf("rename", p.Args[0])
	if err != nil {
		return err
	}
	if t.f.Meta == nil {
		return inv.usageErr("'" + t.f.File + "' is a file that tacctl did not make: it is not renamed. Nothing was changed.")
	}
	if t.dir.Bases[newName] {
		return inv.usageErr("A report or file named '" + newName + "' exists: a report is never overwritten. Nothing was changed.")
	}
	m := *t.f.Meta
	m.Name = newName
	mb, err := reports.MarshalMeta(m)
	if err != nil {
		return err
	}
	file, err := t.pl.rename(*t.f, newName, mb)
	if err != nil {
		return inv.usageErr("Cannot rename the report: " + existsText(err, " (give another new name)"))
	}
	if !t.cross {
		inv.detail("device reports rename", kvp("name", t.f.Name), kvp("new", newName))
	}
	inv.app.Out.Info("Report " + t.f.Name + " is now " + newName + " (" + file + ").")
	return nil
}

// deviceReportsRemove is 'device reports remove'.
func (inv *invocation) deviceReportsRemove(args []string) error {
	p, err := inv.deviceReportsParse("remove", args)
	if err != nil {
		return err
	}
	t, err := inv.reportTargetOf("remove", p.Args[0])
	if err != nil {
		return err
	}
	if t.f.Meta == nil {
		return inv.usageErr("'" + t.f.File + "' is a file that tacctl did not make: it is not removed. Nothing was changed.")
	}
	whose := ""
	if t.cross {
		whose = " of " + t.owner
	}
	a := inv.app
	a.Out.Warn("About to remove the report " + t.f.Name + whose + " (" + t.f.File + ", " + reportSize(t.f.Size) + ") and its metadata.")
	if !p.Has("--yes") && !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if err := t.pl.remove(t.f.File); err != nil && !os.IsNotExist(err) {
		return inv.usageErr("Cannot remove the report: " + err.Error())
	}
	if !t.cross {
		inv.detail("device reports remove", kvp("name", t.f.Name))
	}
	a.Out.Info("Removed the report " + t.f.Name + whose + ".")
	return nil
}

// reportNames are the caller's own reports, for completion: a name, or the
// file names where a name is ambiguous.
func (inv *invocation) reportNames([]string) []string {
	pl, err := inv.reportPlaceOf(inv.sudoUser())
	if err != nil {
		return nil
	}
	d, err := pl.read()
	if err != nil {
		return nil
	}
	count := map[string]int{}
	for _, f := range d.Files {
		count[f.Name]++
	}
	var out []string
	for _, f := range d.Files {
		if count[f.Name] > 1 {
			out = append(out, f.File)
		} else {
			out = append(out, f.Name)
		}
	}
	sort.Strings(out)
	return out
}
