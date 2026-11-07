package cli

// 'device reports' (docs/plans/0.2.26-plan.md D316 to D330): saved, dated
// documents about the registered devices, made on demand from the records
// tacctl already stores. 'generate' makes one (device_reports.go), 'list',
// 'show', 'export', 'rename' and 'remove' keep them (device_reports_view.go),
// 'prune' removes the old ones (device_reports_prune.go); a superuser reaches other users' reports (device_reports_super.go). The
// model, the renderers and the rules for names and limits are
// internal/reports; the files are device_reports_store.go.

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/reports"
	"github.com/rett/tacctl/internal/ui"
)

// deviceReportsSpecs are the arguments of each 'device reports' verb, for the
// parser and for completion (device.go's spec lookup).
var deviceReportsSpecs = map[string]Spec{
	"generate": {MaxArgs: 0, Flags: []Flag{
		{Names: []string{"--type"}, Value: true, Kind: "inventory|members|software|config", Arg: "inventory|members|software|config",
			Desc: "Make this type of report (required)",
			Long: "The type of report: inventory (one row per device), members (one row per chassis member), software (one row per device: model and release) or config (one row per device: the state of its last pull). A device that was never pulled is a row with empty facts, never left out"},
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes, Arg: "<scope>", Desc: "Only the devices that scope answers",
			Long: "Only the devices that scope answers. A scope that is not one of yours is refused"},
		{Names: []string{"--vendor"}, Value: true, Kind: KindVendors, Arg: "cisco|juniper|wti|other", Desc: "Only the devices of that vendor"},
		{Names: []string{"--format"}, Value: true, Kind: "text|csv|json", Arg: "text|csv|json", Desc: "Write the report in this format (default text)",
			Long: "The format: text (aligned columns, the default), csv (RFC 4180, a header line, UTF-8) or json (one object: schema, type, generated, filters, rows). It sets the extension of the file"},
		{Names: []string{"--name"}, Value: true, Arg: "<name>", Desc: "Name the report (default <type>-<yyyymmdd>)",
			Long: "The name of the report, without the extension: letters, digits, '.', '_' and '-', at most 64 bytes, no leading dot. The default is the type and the date (inventory-20261106); a second report of the same day gets -2. A name in use is refused, never overwritten"},
		{Names: []string{"--stdout"}, Desc: "Print the report and store nothing",
			Long: "Print the report on standard output and store nothing: no file, no metadata and no limit applies"},
		{Names: []string{"--pull"}, Desc: "Read the devices first, as 'device config pull' does",
			Long: "Read the devices first, as 'tacctl device config pull' does, with your own password (asked for once, never stored) and over the transport the pull chooses, then make the report from the fresh records. A device whose pull fails keeps its last good facts and its old date. It needs the engineer tier and reads the devices of your own scopes"}}},
	"list": {MaxArgs: 0, Flags: []Flag{
		{Names: []string{"--json"}, Desc: "Print the reports as JSON",
			Long: "Print the reports as a JSON array: each one's file, name, owner, type, format, user, command line, filters, dates, size and number of rows (a file tacctl did not make has the file, the name, the owner and the size only)"},
		{Names: []string{"--user"}, Value: true, Kind: KindUsers, Arg: "<name>", Desc: "List the reports of another user",
			Long: "List the reports of another user. It is the superuser's, and writes an audit line with who looked at whose reports"},
		{Names: []string{"--all-users"}, Alone: true, Desc: "List the reports of every user",
			Long: "List the reports of every user tacctl knows, one audit line for the whole listing. It is the superuser's"}}},
	"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindReports}, Flags: []Flag{
		{Names: []string{"--content"}, Desc: "Print the first 200 lines of the report as well",
			Long: "Print the report itself under the facts, its first 200 lines ('export' prints all of it)"}}},
	"export": {MinArgs: 1, MaxArgs: 1, Args: []string{KindReports}, Flags: []Flag{
		{Names: []string{"--out"}, Value: true, Kind: KindFile, Arg: "<file>", Desc: "Write to this file instead of standard output",
			Long: "Write the copy to this file, mode 0600, made as you; a file that exists is refused unless --force"},
		{Names: []string{"--force"}, Desc: "Replace the file --out names",
			Long: "Replace the file --out names, if there is one"}}},
	"rename": {MinArgs: 2, MaxArgs: 2, Args: []string{KindReports, ""}},
	"remove": {MinArgs: 1, MaxArgs: 1, Args: []string{KindReports}, Flags: []Flag{
		{Names: []string{"--yes"}, Desc: "Do not ask for confirmation"}}},
	"prune": {MaxArgs: 0, Flags: []Flag{
		{Names: []string{"--older-than"}, Value: true, Kind: "24h|7d|30d|4w", Arg: "<age>", Desc: "Remove reports older than this age: 12h, 30d or 4w (required)",
			Long: "Remove the reports made longer ago than this age: a whole number and one unit, h (hours), d (days) or w (weeks), for example 30d. There is no default and no zero. The age of a report is the date it was generated, which its metadata file holds, not the time of the file"},
		{Names: []string{"--user"}, Value: true, Kind: KindUsers, Arg: "<name>", Desc: "Prune the reports of another user",
			Long: "Prune the reports of another user. It is the superuser's, and writes an audit line with who pruned whose reports and how many, never their names"},
		{Names: []string{"--all-users"}, Desc: "Prune the reports of every user",
			Long: "Prune the reports of every user tacctl knows, one audit line for each user whose reports are listed or removed. It is the superuser's"},
		{Names: []string{"--dry-run"}, Desc: "List what would be removed and remove nothing",
			Long: "List what would be removed and remove nothing; --yes does not change that"},
		{Names: []string{"--yes"}, Desc: "Do not ask for confirmation"}}},
}

// deviceReportsWords are the verbs in the order of device.go's rows.
var deviceReportsWords = []string{"generate", "list", "show", "export", "rename", "remove", "prune"}

func init() {
	// The option lines of the usage are the flags' own text.
	for sub, spec := range deviceReportsSpecs {
		var rows [][2]string
		for _, f := range spec.Flags {
			name := f.Names[0]
			if f.Value && f.Arg != "" {
				name += " " + f.Arg
			}
			rows = append(rows, [2]string{name, f.Desc})
		}
		deviceOptions["reports "+sub] = rows
	}
	shellHelpBlocks["device reports"] = func(*invocation) string { return deviceReportsUsage() }
}

// deviceReportsUse is the usage of a 'device reports' verb after 'tacctl
// device reports '.
func deviceReportsUse(sub string) string {
	for _, v := range deviceVerbs {
		if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "reports" && f[1] == sub {
			return strings.TrimPrefix(v[0], "reports ")
		}
	}
	return sub
}

// deviceReportsParse parses a verb's arguments with its spec; a bad one is
// the error line and the verb's usage, exit 2 (argErr).
func (inv *invocation) deviceReportsParse(sub string, args []string) (Parsed, error) {
	p, err := Parse(deviceReportsSpecs[sub], args)
	if err == nil {
		return p, nil
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return p, inv.argErr(msg, "Usage: tacctl device reports "+deviceReportsUse(sub))
}

// deviceReportsUsage is the usage of 'device reports'.
func deviceReportsUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device Reports" + ui.NC + "\n\nUsage: tacctl device reports <subcommand> [arguments]\n\nSubcommands:\n")
	for _, w := range deviceReportsWords {
		short := ""
		for _, v := range deviceVerbs {
			if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "reports" && f[1] == w {
				short = v[1]
			}
		}
		b.WriteString("  " + deviceReportsUse(w) + "\n      " + short + "\n")
		for _, o := range deviceOptions["reports "+w] {
			fmt.Fprintf(&b, "      %-42s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
A report is a saved, dated document about the registered devices, made from
what tacctl stores of them: no device is contacted unless 'generate --pull'
reads them first. Four types: 'inventory' (name, address, vendor, scope,
model, serial, release, chassis members, location, description, pulled),
'members' (one row per chassis member; a standalone device is one row),
'software' (model and release) and 'config' (the state 'device config list'
shows, the pull and the apply). Every row has the date of the pull its facts
came from, 'never' for a device that was not pulled, and the report holds
only the devices your scopes cover. No secret is in any report.

A report is the file ~/reports/devices/<name>.<txt|csv|json> of your home,
mode 0600 in a directory of mode 0700, made as you, with <name>.<ext>.meta
beside it (when, by whom, the command line, the filters, the oldest datum).
'show' prints that and the line to copy it with scp; 'export' prints or copies
the report. A report is addressed by its name without the extension; when two
files share a name, give the extension. A file you put in the directory is
listed as 'other': 'rename' and 'remove' leave it alone.

At most reports.max_count reports of reports.max_size bytes each are kept for
each user (a generate over either is refused). Nothing deletes a report by
age unless you run 'prune --older-than <age>' (<n>h, <n>d or <n>w, no default):
it lists the reports whose generated date is older, asks once (--yes does not,
--dry-run only lists) and removes them with their metadata files. A file that
is listed as 'other' and anything outside the reports directory is never
removed.

A superuser reads other users' reports: 'list --user <name>', 'list
--all-users', '<user>/<report>' for show, export, rename and remove, and
'prune --user <name>' or '--all-users' for the old reports of others. Every
such access writes one audit line (who, whose, which report or how many for a
prune, never a name or a content). No verb writes into another user's home.

Examples:
  tacctl device reports generate --type inventory --format csv
  tacctl device reports generate --type members --scope site-a --stdout
  tacctl device reports list
  tacctl device reports show inventory-20261106
  tacctl device reports export inventory-20261106 --out inventory.csv
  tacctl device reports remove inventory-20261106
  tacctl device reports prune --older-than 30d --dry-run

`)
	return b.String()
}

// deviceReports dispatches 'device reports': no sub-command, help, -h and
// --help are the usage (exit 0); anything else unknown is an error.
func (inv *invocation) deviceReports(args []string) error {
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(deviceReportsUsage())
		return nil
	case "generate":
		return inv.deviceReportsGenerate(args[1:])
	case "list":
		return inv.deviceReportsList(args[1:])
	case "show":
		return inv.deviceReportsShow(args[1:])
	case "export":
		return inv.deviceReportsExport(args[1:])
	case "rename":
		return inv.deviceReportsRename(args[1:])
	case "remove":
		return inv.deviceReportsRemove(args[1:])
	case "prune":
		return inv.deviceReportsPrune(args[1:])
	default:
		return inv.unknownSub(sub)
	}
}

// --- generate ---------------------------------------------------------------------

// deviceReportsGenerate is 'device reports generate'.
func (inv *invocation) deviceReportsGenerate(args []string) error {
	p, err := inv.deviceReportsParse("generate", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl device reports " + deviceReportsUse("generate")
	typ := p.Value("--type")
	format := reports.FormatText
	if p.Has("--format") {
		format = p.Value("--format")
	}
	switch {
	case !p.Has("--type"):
		return inv.argErr("--type is required: "+strings.Join(reports.Types(), ", ")+".", usage)
	case !slices.Contains(reports.Types(), typ):
		return inv.argErr("Unknown report type '"+typ+"' (valid types: "+strings.Join(reports.Types(), ", ")+").", usage)
	case reports.Ext(format) == "":
		return inv.argErr("Unknown report format '"+format+"' (valid formats: "+strings.Join(reports.Formats(), ", ")+").", usage)
	case p.Has("--vendor") && !slices.Contains(strings.Split(KindVendors, "|"), p.Value("--vendor")):
		return inv.argErr("--vendor takes cisco, juniper, wti or other: '"+p.Value("--vendor")+"'", usage)
	case p.Has("--scope") && p.Value("--scope") == "":
		return inv.argErr("--scope takes a scope name.", usage)
	case p.Has("--stdout") && p.Has("--name"):
		return inv.argErr("--name names the stored report; --stdout stores nothing.", usage)
	}
	if p.Has("--name") {
		if err := reports.ValidName(p.Value("--name")); err != nil {
			return inv.argErr("Invalid report name: "+err.Error()+".", usage)
		}
	}
	if p.Has("--pull") {
		if t, ok := inv.deviceConfigPermits("pull"); !ok {
			return inv.deniedUsage(reasonSuperuser, "--pull runs 'tacctl device config pull', which is not permitted for the "+string(t)+" tier.")
		}
		if _, err := inv.configLogin("device reports generate --pull"); err != nil {
			return err
		}
	}
	user := inv.sudoUser()
	var pl reportPlace
	if !p.Has("--stdout") {
		if pl, err = inv.reportPlaceOf(user); err != nil {
			return inv.usageErr(err.Error() + ".")
		}
	}
	if p.Has("--scope") {
		if err := inv.scopeRequire(p.Value("--scope")); err != nil {
			return err
		}
		if err := inv.scopeNotFound(inv.callerScopes(), p.Value("--scope")); err != nil {
			return err
		}
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	var entries []devreg.Entry
	for _, e := range res.Visible(inv.deviceFilter()) {
		if e.Source != devreg.SourceDevice ||
			(p.Has("--scope") && e.Scope != p.Value("--scope")) || (p.Has("--vendor") && e.Vendor != p.Value("--vendor")) {
			continue
		}
		entries = append(entries, e)
	}
	var pullErr error
	if p.Has("--pull") {
		if pullErr = inv.reportsPull(entries, p.Has("--stdout")); pullErr != nil && exitStatus(pullErr) != 1 {
			return pullErr
		}
	}

	now := inv.app.Knobs.Now().UTC()
	rep, err := reports.Build(typ, inv.reportDevices(entries, typ == reports.TypeConfig), now)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	if err := reports.Render(&body, rep, format); err != nil {
		return err
	}
	if len(entries) == 0 {
		inv.app.Out.Warn("No device matches: the report has no rows.")
	}
	if p.Has("--stdout") {
		inv.write(body.String())
		return pullErr
	}

	dir, err := pl.read()
	if err != nil {
		return inv.usageErr(err.Error())
	}
	name := p.Value("--name")
	if p.Has("--name") {
		if dir.Bases[name] {
			return inv.usageErr("A report or file named '"+name+"' exists already. Choose another --name, or remove it with: tacctl device reports remove "+name+" (a file that is not a report is yours to remove).",
				"Nothing was written.")
		}
	} else {
		name = reports.DefaultName(typ, now, func(n string) bool { return dir.Bases[n] })
	}
	maxSize, maxCount := reportLimits(inv, user)
	if err := reports.CheckLimits(int64(body.Len()), dir.Count()+1, maxSize, maxCount); err != nil {
		return inv.usageErr(reportLimitText(err), "Nothing was written.")
	}
	file := name + reports.Ext(format)
	meta := reports.Meta{Name: name, Type: typ, Format: format, User: user,
		Command: "tacctl " + strings.Join(inv.app.Args, " "), Filters: map[string]string{},
		Generated: now, OldestData: rep.OldestData, Size: int64(body.Len()), Count: len(rep.Rows)}
	for _, f := range []string{"--scope", "--vendor"} {
		if p.Has(f) {
			meta.Filters[strings.TrimPrefix(f, "--")] = p.Value(f)
		}
	}
	mb, err := reports.MarshalMeta(meta)
	if err != nil {
		return err
	}
	if err := pl.write(file, body.Bytes(), mb); err != nil {
		return inv.usageErr("Cannot store the report: " + err.Error())
	}
	inv.detail("device reports generate", kvp("type", typ), kvp("name", name), kvp("format", format), kvp("rows", strconv.Itoa(len(rep.Rows))))
	inv.app.Out.Info("Report " + name + " written: " + pl.dir + "/" + file)
	inv.echo("  " + howMany(len(rep.Rows), "row") + ", " + reportSize(int64(body.Len())) + ". See it with: tacctl device reports show " + name)
	inv.echo("")
	return pullErr
}

// reportLimitText is the refusal of a report over a limit: the number, the
// setting that holds it and the way out.
func reportLimitText(err error) string {
	var le *reports.LimitError
	if !errors.As(err, &le) {
		return err.Error()
	}
	if le.Limit == "size" {
		return "Cannot save the report: " + le.Error() + " (the setting reports.max_size; a superuser changes it with: tacctl config reports max-size <bytes>). Narrow it with --scope or --vendor, print it with --stdout, or remove one you do not need with: tacctl device reports remove <name>"
	}
	return "Cannot save the report: " + le.Error() + " (the setting reports.max_count; a superuser changes it with: tacctl config reports max-count <n>). Remove one with: tacctl device reports remove <name>"
}

// reportSize is a size in bytes as the lists show it.
func reportSize(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return strconv.FormatInt(n, 10) + " B"
}

// reportsPull reads the devices a report is made of, as 'device config pull'
// does for the caller (the same selection, login and password, which this
// does not repeat). A device that is not read by a pull (vendor other, no
// scope) is left as it is. With stdout the pull's output goes to standard
// error, so that the report is the only thing on standard output.
func (inv *invocation) reportsPull(entries []devreg.Entry, stdout bool) error {
	var names []string
	for _, e := range entries {
		if e.Configured && slices.Contains(sortedVendors(), e.Vendor) {
			names = append(names, e.Name)
		}
	}
	if len(names) == 0 {
		inv.app.Out.Info("No device to read: none of the devices has a vendor the pull reads and a scope that covers it.")
		return nil
	}
	if stdout {
		out := inv.app.Out.Stdout
		inv.app.Out.Stdout = inv.app.Out.Stderr
		defer func() { inv.app.Out.Stdout = out }()
	}
	err := inv.deviceConfigPull([]string{strings.Join(names, ",")})
	if err != nil && exitStatus(err) == 1 {
		inv.app.Out.Warn("Some devices were not read: the report holds the facts of their last good pull, with its date.")
	}
	return err
}

// reportDevices are the entries as the report model has them, from the pull
// records (no login). needState also works out the state of the last pull
// against what tacctl renders now, which only the config report shows.
func (inv *invocation) reportDevices(entries []devreg.Entry, needState bool) []reports.Device {
	recs := inv.configRecords()
	var states map[string]configNowState
	if needState {
		states = inv.configNowStates(entries)
	}
	out := make([]reports.Device, 0, len(entries))
	for _, e := range entries {
		d := reports.Device{Name: e.Name, Address: e.Address, Vendor: e.Vendor, Scope: e.Scope,
			Location: cleanLine(e.Location), Description: cleanLine(e.Description)}
		rec, _ := recs.Of(e.Name)
		if rec != nil {
			d.Model, d.Serial, d.Release = cleanLine(rec.Model), cleanLine(rec.Serial), cleanLine(rec.Release)
			d.Pulled = rec.Pulled
			if a := rec.Applied; a != nil && a.Result == devconf.AppliedApplied {
				d.Applied = a.At
			}
			for _, m := range rec.Members {
				d.Members = append(d.Members, reports.Member{ID: cleanLine(m.ID), Role: cleanLine(m.Role), Model: cleanLine(m.Model),
					Serial: cleanLine(m.Serial), Release: cleanLine(m.Release), Status: cleanLine(m.Status), Priority: m.Priority})
			}
		}
		if needState {
			if st, ok := states[e.Name]; ok {
				d.ConfigState = st.state
			} else {
				d.ConfigState = inv.configStateOf(e, rec)
			}
		}
		out = append(out, d)
	}
	return out
}

// reportAge is the date of the oldest datum, as show prints it.
func reportAge(t time.Time) string {
	if t.IsZero() {
		return "none (no device was ever pulled)"
	}
	return t.UTC().Format("2006-01-02")
}
