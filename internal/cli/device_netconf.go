package cli

// 'device netconf' (D145 of docs/plans/0.2.10-plan.md): the NETCONF service
// setting of one Junos device, over its scope's ('tacctl scope netconf').
// enable, disable and leave are the device's own word (a device's leave
// overrides a scope's enable or disable); clear removes it, so the scope's
// decides again. A device's own value is the 'netconf:' map of its entry in
// devices.yaml (internal/devreg), written only when set.

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
)

const deviceNetconfUse = "netconf <name> [show|enable|disable|leave|clear] [--connection-limit <n>|none] [--rate-limit <n>|none]"

const deviceNetconfShort = "A Junos device's own NETCONF service setting over its scope's: enable, disable, leave or clear (--apply: then run 'device config apply' for the device)"

// deviceNetconfOptions are the option lines under the verb's row.
var deviceNetconfOptions = [][2]string{
	{"--connection-limit <n>|none", "(enable) The connection limit of the service, 1 to 250; none takes the scope's"},
	{"--rate-limit <n>|none", "(enable) The rate limit of the service, 1 to 250; none takes the scope's"},
}

// deviceNetconfFlags are the options of the verb (after the device's name).
var deviceNetconfFlags = []Flag{
	{Names: []string{"--connection-limit"}, Value: true, Kind: "<n>|none", Only: "enable"},
	{Names: []string{"--rate-limit"}, Value: true, Kind: "<n>|none", Only: "enable"},
	flagApply,
}

// deviceNetconfLines is how 'device netconf <name>' says the setting and
// where each value comes from.
func (inv *invocation) deviceNetconfLines(e devreg.Entry) []string {
	eff := inv.netconfOf(e.Scope, e.Netconf)
	lines := []string{"NETCONF service of device '" + e.Name + "': " + eff.words()}
	from := func(src, scope string) string {
		switch src {
		case netconfFromDevice:
			return "the device's own"
		case netconfFromScope:
			return "scope '" + scope + "'"
		}
		return "the default"
	}
	lines = append(lines, "  state:             "+from(eff.StateFrom, e.Scope))
	if !eff.Leave && eff.State == conf.NetconfEnable {
		lines = append(lines,
			"  connection limit:  "+limitText(eff.ConnectionLimit)+limitFrom(eff.ConnectionFrom, from, e.Scope),
			"  rate limit:        "+limitText(eff.RateLimit)+limitFrom(eff.RateFrom, from, e.Scope))
	}
	return lines
}

func limitFrom(src string, from func(string, string) string, scope string) string {
	if src == "" {
		return ""
	}
	return "  (" + from(src, scope) + ")"
}

// deviceNetconf is 'device netconf <name> [word]': no word, or 'show',
// prints the setting.
func (inv *invocation) deviceNetconf(args []string) error {
	const usage = "Usage: tacctl device " + deviceNetconfUse
	p, err := inv.deviceParse("netconf", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	word := "show"
	if len(p.Args) > 1 {
		word = p.Args[1]
	}
	if word != "enable" && (p.Has("--connection-limit") || p.Has("--rate-limit")) {
		return inv.usageErr("--connection-limit and --rate-limit go with enable: tacctl device netconf "+p.Args[0]+" enable --connection-limit <n>", usage)
	}
	if word == "show" {
		if p.Has("--apply") {
			return inv.usageErr("--apply goes with a value to set: tacctl device netconf <name> enable|disable|leave|clear --apply", usage)
		}
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		if e.Source == devreg.SourceHost {
			return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; it has no NETCONF service setting.")
		}
		if e.Vendor != "juniper" {
			return inv.usageErr("Device '" + e.Name + "' has vendor '" + e.Vendor + "'; the NETCONF service setting is a Junos setting.")
		}
		for _, l := range inv.deviceNetconfLines(e) {
			inv.echo(l)
		}
		return nil
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	if d.Vendor != "juniper" {
		return inv.usageErr("Device '" + d.Name + "' has vendor '" + d.Vendor + "'; the NETCONF service setting is a Junos setting.")
	}
	next := devreg.Netconf{}
	switch word {
	case "clear":
	case "leave", "disable":
		next.State = word
	case "enable":
		next = d.Netconf
		if next.State != conf.NetconfEnable {
			next = devreg.Netconf{State: conf.NetconfEnable}
		}
		for _, l := range []struct {
			flag string
			dst  *int
		}{{"--connection-limit", &next.ConnectionLimit}, {"--rate-limit", &next.RateLimit}} {
			if !p.Has(l.flag) {
				continue
			}
			n, err := parseNetconfLimit(l.flag, p.Value(l.flag))
			if err != nil {
				return inv.usageErr(err.Error(), usage)
			}
			*l.dst = n
		}
	}
	name := d.Name
	applyReq, changed := p.Has("--apply"), d.Netconf != next
	if applyReq && changed {
		e, err := inv.deviceFind(res, name)
		if err != nil {
			return err
		}
		if err := inv.applyPreflight(e); err != nil {
			return err
		}
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find(name).Netconf = next
		return nil
	}); err != nil {
		return err
	}
	inv.detail("device set", kvp("name", name), kvp("field", "netconf"), kvp("from", netconfWord(d.Netconf)), kvp("to", netconfWord(next)))
	if !changed {
		inv.app.Out.Info("Device '" + name + "' NETCONF service setting is " + word + " already; nothing was changed.")
	} else {
		switch word {
		case "clear":
			inv.app.Out.Info("Device '" + name + "' follows its scope's NETCONF service setting again.")
		case "disable":
			inv.app.Out.Info("Device '" + name + "' NETCONF service: disable.")
			inv.app.Out.Warn("Applying it deletes 'system services netconf' on the device: every NETCONF client of it loses the service, tacctl's own reads fall back to ssh.")
		default:
			inv.app.Out.Info("Device '" + name + "' NETCONF service: " + word + ".")
		}
	}
	return inv.afterSetter(name, "netconf", changed, applyReq)
}

// netconfWord is a device's NETCONF service setting as the audit line writes
// it: the state, with the limits when it has some.
func netconfWord(n devreg.Netconf) string {
	if n.State == "" {
		return "follows-scope"
	}
	w := n.State
	if n.ConnectionLimit > 0 {
		w += ",connection-limit=" + strconv.Itoa(n.ConnectionLimit)
	}
	if n.RateLimit > 0 {
		w += ",rate-limit=" + strconv.Itoa(n.RateLimit)
	}
	return w
}
