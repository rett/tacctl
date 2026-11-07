package cli

// 'config reports' (docs/plans/0.2.26-plan.md D326): the limits of the stored
// reports of 'tacctl device reports', global to the server: the largest size of
// one report and the most reports one user keeps, reports.max_size and
// reports.max_count of tacctl.yaml. 0 is no cap. A user's own limit ('tacctl
// user reports-limit') wins over them. The verbs are the superuser's (no tier
// row names them), and a setting is checked by the schema, so an out-of-range
// value never reaches the file.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("reports", configReportsFamilySpec, configReportsCmd)
}

// configReportsFamilySpec is the spec of 'config reports' as registerConfigVerb
// takes it.
var configReportsFamilySpec = Spec{MaxArgs: 2, Args: []string{"show|max-size|max-count", ""}}

// configReportsSpecs are the arguments of each verb.
var configReportsSpecs = map[string]Spec{
	"show":      {MaxArgs: 0},
	"max-size":  {MaxArgs: 1, Args: []string{""}},
	"max-count": {MaxArgs: 1, Args: []string{""}},
}

// configReportsVerbs are the verbs ({Use, Short}), in usage order.
var configReportsVerbs = [][2]string{
	{"show", "The limits and where each stands"},
	{"max-size [<bytes|Ki|Mi|Gi>]", "Show or set the largest report, up to 1Gi (default 10Mi, 0: no cap)"},
	{"max-count [<n>]", "Show or set the most reports per user (default 100, 0: no cap)"},
}

const configReportsVerbUsage = "Usage: tacctl config reports [show|max-size|max-count] [<value>]"

func configReportsCmd(inv *invocation) *cobra.Command {
	c := verb("reports <subcommand>", "Limits of the stored reports (size of one, count per user)")
	c.RunE = inv.native(withPreflight, inv.configReports)
	for _, v := range configReportsVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.configReports(append([]string{word}, args...))
		})))
	}
	return c
}

// configReportsUsage is the usage of 'config reports'.
func configReportsUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Report limits" + ui.NC + "\n\n" + configReportsVerbUsage + "\n\n")
	for _, v := range configReportsVerbs {
		fmt.Fprintf(&b, "  %-28s  %s\n", v[0], v[1])
	}
	b.WriteString(`
These are the limits of the reports 'tacctl device reports generate' stores in
a user's home (in tacctl.yaml as reports.max_size and reports.max_count).
'max-size' is the largest report, in bytes or with the suffix Ki, Mi or Gi
(powers of 1024), from 0 to 1Gi; 'max-count' is the most reports one user
keeps, from 0 to 100000. 0 is no cap. A report over a limit is refused, with
the setting named; nothing deletes a report by age. A user's own limit
('tacctl user reports-limit') wins over these for that user.
The setters are for administrators.

Examples:
  tacctl config reports
  tacctl config reports max-size 20Mi
  tacctl config reports max-size 0
  tacctl config reports max-count 500

`)
	return b.String()
}

// configReports dispatches: no sub-command is 'show'; help, -h and --help are
// the usage (exit 0); an unknown one is an error, then the usage (exit 1).
func (inv *invocation) configReports(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "show":
		return inv.configReportsShow(rest)
	case "-h", "--help", "help":
		inv.write(configReportsUsage())
		return nil
	case "max-size":
		return inv.configReportsSetSize(rest)
	case "max-count":
		return inv.configReportsSetCount(rest)
	default:
		return inv.unknownSub(sub)
	}
}

// configReportsShow prints the settings.
func (inv *invocation) configReportsShow(rest []string) error {
	if len(rest) > 0 {
		return inv.usageErr("Unknown argument: '"+rest[0]+"'", configReportsVerbUsage)
	}
	size, count := inv.globalReportLimits()
	src := func(path string) string {
		if inv.app.Conf().HasOverride(path) {
			return "set"
		}
		return "default"
	}
	inv.echo("")
	inv.echo("  Stored reports ('tacctl device reports')")
	inv.echo("  max-size:  " + names.FormatReportSize(size) + "   (" + src(conf.ReportsMaxSizeKey) + "; 0-1Gi, the largest report; 0 is no cap)")
	inv.echo("  max-count: " + names.FormatReportCount(count) + "   (" + src(conf.ReportsMaxCountKey) + "; 0-100000, the most reports per user; 0 is no cap)")
	inv.echo("")
	inv.echo("  A user's own limit wins ('tacctl user reports-limit').")
	inv.echo("")
	return nil
}

// configReportsSetSize shows or sets reports.max_size: a number of bytes, or a
// number with Ki, Mi or Gi.
func (inv *invocation) configReportsSetSize(rest []string) error {
	const usage = "  Usage: tacctl config reports max-size <bytes|Ki|Mi|Gi>   (0 is no cap)"
	if len(rest) > 1 {
		return inv.usageErr("Unknown argument: '"+rest[1]+"'", strings.TrimSpace(usage))
	}
	size, _ := inv.globalReportLimits()
	if len(rest) == 0 {
		inv.echo("")
		inv.echo("  Largest report: " + names.FormatReportSize(size))
		inv.echo("")
		inv.echo(usage)
		inv.echo("")
		return nil
	}
	n, err := names.ParseReportSize(rest[0])
	if err != nil {
		return inv.usageErr(err.Error(), strings.TrimSpace(usage))
	}
	if err := inv.app.Conf().Set(conf.ReportsMaxSizeKey, strconv.FormatInt(n, 10)); err != nil {
		return err
	}
	inv.detail("config reports", kvp("key", "max_size"), kvp("from", strconv.FormatInt(size, 10)), kvp("to", strconv.FormatInt(n, 10)))
	inv.app.Out.InfoE("The largest report set to " + names.FormatReportSize(n) + ".")
	inv.echo("")
	return nil
}

// configReportsSetCount shows or sets reports.max_count.
func (inv *invocation) configReportsSetCount(rest []string) error {
	const usage = "  Usage: tacctl config reports max-count <n>   (0 is no cap)"
	if len(rest) > 1 {
		return inv.usageErr("Unknown argument: '"+rest[1]+"'", strings.TrimSpace(usage))
	}
	_, count := inv.globalReportLimits()
	if len(rest) == 0 {
		inv.echo("")
		inv.echo("  Most reports per user: " + names.FormatReportCount(count))
		inv.echo("")
		inv.echo(usage)
		inv.echo("")
		return nil
	}
	n, err := names.ParseReportCount(rest[0])
	if err != nil {
		return inv.usageErr(err.Error(), strings.TrimSpace(usage))
	}
	if err := inv.app.Conf().Set(conf.ReportsMaxCountKey, strconv.Itoa(n)); err != nil {
		return err
	}
	inv.detail("config reports", kvp("key", "max_count"), kvp("from", strconv.Itoa(count)), kvp("to", strconv.Itoa(n)))
	inv.app.Out.InfoE("The most reports per user set to " + names.FormatReportCount(n) + ".")
	inv.echo("")
	return nil
}
