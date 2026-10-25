package cli

// 'config devices' (docs/plans/0.2.4-plan.md D68, 0.2.9 D140): how 'device
// config pull|diff' read the devices, the device.config.* settings of
// tacctl.yaml, and how 'device config apply' runs, the two device.apply.*
// ones. The verbs are the superuser's (no tier row names them), and a
// setting is checked by the schema, so an out-of-range value never reaches
// the file.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("devices", configDevicesFamilySpec, configDevicesCmd)
}

// configDevicesFamilySpec is the spec of 'config devices' as
// registerConfigVerb takes it.
var configDevicesFamilySpec = Spec{MaxArgs: 2, Args: []string{"show|max-concurrency|transport|timeout|confirm-timeout|apply-confirm-timeout|apply-pause|apply-transport", ""}}

// configDevicesSpecs are the arguments of each verb.
var configDevicesSpecs = map[string]Spec{
	"show":            {MaxArgs: 0},
	"max-concurrency": {MaxArgs: 1, Args: []string{""}},
	"transport":       {MaxArgs: 1, Args: []string{"auto|netconf|ssh"}},
	"timeout":         {MaxArgs: 1, Args: []string{""}},
	"confirm-timeout": {MaxArgs: 1, Args: []string{""}},
	// The settings of 'device config apply' (0.2.9, D140).
	"apply-confirm-timeout": {MaxArgs: 1, Args: []string{""}},
	"apply-pause":           {MaxArgs: 1, Args: []string{""}},
	// How 'device config apply' reaches a device (0.2.10, D150).
	"apply-transport": {MaxArgs: 1, Args: []string{"cli|auto|netconf"}},
}

// The values of device.apply.transport and of --transport on 'device config
// apply' (D150), devapply's own words.
const (
	applyTransportAuto    = string(devapply.SettingAuto)
	applyTransportCLI     = string(devapply.SettingCLI)
	applyTransportNetconf = string(devapply.SettingNetconf)
)

// The defaults and the pause's range of the two device.apply.* settings
// (D140). The confirm window's range is devapply's (a window under three
// minutes cannot hold the verification); the pause is the seconds between the
// devices of a batch after the canary.
const (
	applyConfirmDefault = 10
	applyPauseDefault   = 60
	applyPauseMax       = 3600
)

// configDevicesVerbs are the verbs ({Use, Short}), in usage order.
var configDevicesVerbs = [][2]string{
	{"show", "The settings and where each stands"},
	{"max-concurrency [<n>]", "Show or set the most devices read at once, 1-64 (default 8)"},
	{"transport [auto|netconf|ssh]", "Show or set the default transport (auto: NETCONF where the device answers, else ssh)"},
	{"timeout [<seconds>]", "Show or set the time one device may take, connect included, 10-600 (default 90)"},
	{"confirm-timeout [<minutes>]", "Show or set the minutes of the 'commit confirmed' that ends a Junos plan, 1-60 (default 5)"},
	{"apply-confirm-timeout [<minutes>]", "Show or set the minutes of the 'commit confirmed' of 'device config apply', 3-60 (default 10)"},
	{"apply-pause [<seconds>]", "Show or set the seconds 'device config apply' waits between the devices of a batch after the canary, 0-3600 (default 60)"},
	{"apply-transport [cli|auto|netconf]", "Show or set how 'device config apply' reaches a Junos device (cli: the command line, the default; auto: NETCONF where the device answers and confirms, else the command line)"},
}

func configDevicesCmd(inv *invocation) *cobra.Command {
	c := verb("devices <subcommand>", "How 'device config pull' reads the devices (concurrency, transport, timeout), the confirm timeout of 'device config plan' and the confirm timeout and pause of 'device config apply'")
	c.RunE = inv.native(withPreflight, inv.configDevices)
	for _, v := range configDevicesVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.configDevices(append([]string{word}, args...))
		})))
	}
	return c
}

// configDevicesUsage is the usage of 'config devices'.
func configDevicesUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device reads" + ui.NC + "\n\nUsage: tacctl config devices [show|max-concurrency|transport|timeout|confirm-timeout|apply-confirm-timeout|apply-pause|apply-transport] [<value>]\n\n")
	for _, v := range configDevicesVerbs {
		fmt.Fprintf(&b, "  %-38s  %s\n", v[0], v[1])
	}
	b.WriteString(`
These are the defaults of 'tacctl device config pull', 'diff --pull' and
'plan --pull' (in tacctl.yaml as device.config.max_concurrency, .transport and
.timeout). --concurrency of one run can lower the concurrency, never raise it
above the setting; --transport and --timeout of one run replace the others for
that run. 'confirm-timeout' (device.config.confirm_timeout) is the N of the
'commit confirmed N' that ends the region of a Junos 'device config plan': the
switch undoes the paste by itself in N minutes unless the one word is typed.
'apply-confirm-timeout' (device.apply.confirm_timeout) is the N of the
'commit confirmed N' of every 'tacctl device config apply': 3 to 60 minutes,
the time the verification and the confirming commit have before the device
undoes the change by itself. 'apply-pause' (device.apply.pause) is the
seconds 'device config apply' waits between the devices of a batch after the
canary, 0 to 3600 (0 is none); --pause of one run replaces it.
'apply-transport' (device.apply.transport) is how 'device config apply'
reaches a Junos device: 'cli' (the default) is always the command line;
'auto' uses NETCONF where the device's last read found it answering and the
login may commit, else the command line and says why; 'netconf' never falls
back.
--transport of one run replaces it. A change to the NETCONF service itself
(see 'scope netconf') is always made over the command line.
The setters are for administrators.

Examples:
  tacctl config devices
  tacctl config devices max-concurrency 16
  tacctl config devices transport ssh
  tacctl config devices timeout 120
  tacctl config devices confirm-timeout 10
  tacctl config devices apply-confirm-timeout 15
  tacctl config devices apply-pause 120
  tacctl config devices apply-transport cli

`)
	return b.String()
}

// configDevices dispatches: no sub-command is 'show'; help, -h and --help
// are the usage (exit 0); an unknown one is an error, then the usage
// (exit 1).
func (inv *invocation) configDevices(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "show":
		return inv.configDevicesShow(rest)
	case "-h", "--help", "help":
		inv.write(configDevicesUsage())
		return nil
	case "max-concurrency":
		return inv.configDevicesSet(rest, "device.config.max_concurrency", "Devices read at once",
			"  Usage: tacctl config devices max-concurrency <1-64>", "The most devices read at once set to %v.")
	case "transport":
		return inv.configDevicesSet(rest, "device.config.transport", "Transport",
			"  Usage: tacctl config devices transport <auto|netconf|ssh>", "The default transport set to %v.")
	case "timeout":
		return inv.configDevicesSet(rest, "device.config.timeout", "Time per device",
			"  Usage: tacctl config devices timeout <10-600>", "The time one device may take set to %v s.")
	case "confirm-timeout":
		return inv.configDevicesSet(rest, "device.config.confirm_timeout", "Confirm timeout",
			"  Usage: tacctl config devices confirm-timeout <1-60>", "The confirm timeout of a Junos plan set to %v minutes.")
	case "apply-confirm-timeout":
		return inv.configDevicesSet(rest, "device.apply.confirm_timeout", "Apply confirm timeout",
			"  Usage: tacctl config devices apply-confirm-timeout <3-60>", "The confirm timeout of an apply set to %v minutes.")
	case "apply-pause":
		return inv.configDevicesSet(rest, "device.apply.pause", "Apply pause",
			"  Usage: tacctl config devices apply-pause <0-3600>", "The pause between the devices of an apply set to %v s.")
	case "apply-transport":
		return inv.configDevicesSet(rest, "device.apply.transport", "Apply transport",
			"  Usage: tacctl config devices apply-transport <auto|cli|netconf>", "The transport of an apply set to %v.")
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(configDevicesUsage())
		return exit(1)
	}
}

// configDevicesShow prints the settings.
func (inv *invocation) configDevicesShow(rest []string) error {
	if len(rest) > 0 {
		return inv.usageErr("Unknown argument: '"+rest[0]+"'", "Usage: tacctl config devices [show|max-concurrency|transport|timeout|confirm-timeout|apply-confirm-timeout|apply-pause|apply-transport] [<value>]")
	}
	s := inv.deviceConfigSettings()
	src := func(path string) string {
		if inv.app.Conf().HasOverride(path) {
			return "set"
		}
		return "default"
	}
	inv.echo("")
	inv.echo("  Device configuration reads ('tacctl device config pull|diff')")
	inv.echo("  max-concurrency: " + strconv.Itoa(s.maxConcurrency) + "   (" + src("device.config.max_concurrency") + "; 1-64: devices read at once)")
	inv.echo("  transport:       " + s.transport + "   (" + src("device.config.transport") + "; auto, netconf or ssh)")
	inv.echo("  timeout:         " + strconv.Itoa(int(s.timeout.Seconds())) + " s   (" + src("device.config.timeout") + "; 10-600, per device, connect included)")
	inv.echo("")
	inv.echo("  Device configuration plans ('tacctl device config plan')")
	inv.echo("  confirm-timeout: " + strconv.Itoa(inv.confirmTimeout()) + " min   (" + src("device.config.confirm_timeout") + "; 1-60, the N of 'commit confirmed N' that ends a Junos region)")
	inv.echo("")
	confirm, pause := inv.applySettings()
	inv.echo("  Device configuration apply ('tacctl device config apply')")
	inv.echo("  apply-confirm-timeout: " + strconv.Itoa(confirm) + " min   (" + src("device.apply.confirm_timeout") + "; 3-60, the N of 'commit confirmed N' of every apply)")
	inv.echo("  apply-pause:           " + strconv.Itoa(int(pause.Seconds())) + " s   (" + src("device.apply.pause") + "; 0-3600, between the devices of a batch after the canary)")
	inv.echo("  apply-transport:       " + inv.applyTransport() + "   (" + src("device.apply.transport") + "; auto, cli or netconf)")
	inv.echo("")
	return nil
}

// applySettings reads device.apply.* (D140): the minutes of the
// 'commit confirmed' of 'device config apply' and the pause between the
// devices of a batch. A value the schema would refuse (a hand-edited file)
// reads as the default, as deviceConfigSettings does; the file's own reader
// reports it.
func (inv *invocation) applySettings() (confirmMinutes int, pause time.Duration) {
	confirmMinutes, pause = applyConfirmDefault, applyPauseDefault*time.Second
	if n, err := atoiIn(inv.confGet("device.apply.confirm_timeout", strconv.Itoa(applyConfirmDefault)),
		devapply.MinConfirmMinutes, devapply.MaxConfirmMinutes); err == nil {
		confirmMinutes = n
	}
	if n, err := atoiIn(inv.confGet("device.apply.pause", strconv.Itoa(applyPauseDefault)), 0, applyPauseMax); err == nil {
		pause = time.Duration(n) * time.Second
	}
	return confirmMinutes, pause
}

// applyTransport reads device.apply.transport (D150): cli (the default),
// auto or netconf. A value the schema would refuse (a hand-edited file)
// reads as the default, as applySettings does.
func (inv *invocation) applyTransport() string {
	switch v := inv.confGet("device.apply.transport", applyTransportCLI); v {
	case applyTransportAuto, applyTransportCLI, applyTransportNetconf:
		return v
	}
	return applyTransportCLI
}

// configDevicesSet shows or sets one key through the schema.
func (inv *invocation) configDevicesSet(rest []string, path, label, usage, done string) error {
	if len(rest) > 1 {
		return inv.usageErr("Unknown argument: '"+rest[1]+"'", strings.TrimSpace(usage))
	}
	def := map[string]string{"device.config.max_concurrency": "8", "device.config.transport": transportAuto, "device.config.timeout": "90",
		"device.config.confirm_timeout": "5", "device.apply.confirm_timeout": strconv.Itoa(applyConfirmDefault),
		"device.apply.pause": strconv.Itoa(applyPauseDefault), "device.apply.transport": applyTransportCLI}[path]
	if len(rest) == 0 {
		inv.echo("")
		inv.echo("  " + label + ": " + inv.confGet(path, def))
		inv.echo("")
		inv.echo(usage)
		inv.echo("")
		return nil
	}
	was := inv.confGet(path, def)
	if err := inv.app.Conf().Set(path, rest[0]); err != nil {
		return err
	}
	inv.detail("config devices", kvp("key", strings.TrimPrefix(path, "device.")), kvp("from", was), kvp("to", rest[0]))
	inv.app.Out.InfoE(strings.ReplaceAll(done, "%v", rest[0]))
	inv.echo("")
	return nil
}
