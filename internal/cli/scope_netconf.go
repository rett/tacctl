package cli

// 'scope netconf' (D145 of docs/plans/0.2.10-plan.md): the NETCONF service
// of the Junos devices of a scope. enable renders and plans 'set system
// services netconf ssh' (with the optional connection and rate limits),
// disable plans 'delete system services netconf', leave (the default) plans
// and compares nothing of the service. A device's own value
// ('tacctl device netconf') wins over the scope's. The values are
// tacctl.yaml's netconf_scope.<scope>.* (written only when set).
//
// The verb is the superuser's: enabling or disabling a management service on
// a fleet is no engineer's decision, and the gate has no row for it.

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

const scopeNetconfUse = "netconf <scope> [show|enable|disable|leave] [--connection-limit <n>|none] [--rate-limit <n>|none]"

const scopeNetconfShort = "NETCONF service of the scope's Junos devices: enable, disable or leave it alone (the default)"

const scopeNetconfWords = "show|enable|disable|leave"

// scopeNetconfFlags are the options of the verb.
var scopeNetconfFlags = []Flag{
	{Names: []string{"--connection-limit"}, Value: true, Kind: "<n>|none", Only: "enable"},
	{Names: []string{"--rate-limit"}, Value: true, Kind: "<n>|none", Only: "enable"},
}

func (inv *invocation) scopeNetconf(args []string) error {
	const usage = "Usage: tacctl scope " + scopeNetconfUse
	p, err := Parse(scopeSpecs["netconf"], args)
	if err != nil {
		return inv.usageErr(err.Error(), usage)
	}
	scope := p.Args[0]
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	word := "show"
	if len(p.Args) > 1 {
		word = p.Args[1]
	}
	if word != "enable" && (p.Has("--connection-limit") || p.Has("--rate-limit")) {
		return inv.usageErr("--connection-limit and --rate-limit go with enable: tacctl scope netconf "+scope+" enable --connection-limit <n>", usage)
	}
	c := inv.app.Conf()
	cur := policy.NetconfSettings(c, scope)
	switch word {
	case "show":
		inv.echo("NETCONF service of scope '" + scope + "': " + inv.scopeNetconfText(cur))
		if cur.State == "" {
			inv.echo("  Junos devices of the scope are not told anything of it ('tacctl scope netconf " + scope + " enable|disable' decides).")
		}
		return nil
	case "leave":
		if !policy.NetconfSet(c, scope) {
			inv.app.Out.Info("Scope '" + scope + "' leaves the NETCONF service alone already; nothing was changed.")
			return nil
		}
		if _, err := policy.MoveNetconfScope(c, scope, ""); err != nil {
			return err
		}
		inv.detail("scope netconf", kvp("scope", scope), kvp("from", inv.scopeNetconfText(cur)), kvp("to", "leave"))
		inv.app.Out.Info("Scope '" + scope + "' NETCONF service: leave. tacctl plans and compares nothing of it again.")
		return nil
	case "disable":
		if cur.State == conf.NetconfDisable && cur.ConnectionLimit == 0 && cur.RateLimit == 0 {
			inv.app.Out.Info("Scope '" + scope + "' disables the NETCONF service already; nothing was changed.")
			return nil
		}
		// the limits belong to an enabled service
		if _, err := policy.MoveNetconfScope(c, scope, ""); err != nil {
			return err
		}
		if err := policy.SetNetconfState(c, scope, conf.NetconfDisable); err != nil {
			return err
		}
		inv.detail("scope netconf", kvp("scope", scope), kvp("from", inv.scopeNetconfText(cur)), kvp("to", "disable"))
		inv.app.Out.Info("Scope '" + scope + "' NETCONF service: disable.")
		inv.app.Out.Warn("Applying it deletes 'system services netconf' on the Junos devices of the scope: every NETCONF client of them loses the service, tacctl's own reads fall back to ssh. A device's own setting wins ('tacctl device netconf').")
		return nil
	}
	// enable: the limits given replace the scope's; one not given stays
	next := cur
	next.State = conf.NetconfEnable
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
	if next == cur {
		inv.app.Out.Info("Scope '" + scope + "' NETCONF service is " + inv.scopeNetconfText(cur) + " already; nothing was changed.")
		return nil
	}
	if err := policy.SetNetconfState(c, scope, conf.NetconfEnable); err != nil {
		return err
	}
	for _, k := range []struct {
		key string
		n   int
	}{{conf.NetconfKeyConnectionLimit, next.ConnectionLimit}, {conf.NetconfKeyRateLimit, next.RateLimit}} {
		if err := policy.SetNetconfLimit(c, scope, k.key, k.n); err != nil {
			return err
		}
	}
	inv.detail("scope netconf", kvp("scope", scope), kvp("from", inv.scopeNetconfText(cur)), kvp("to", inv.scopeNetconfText(next)))
	inv.app.Out.Info("Scope '" + scope + "' NETCONF service: " + inv.scopeNetconfText(next) + ".")
	return nil
}

// scopeNetconfText is a scope's setting in a sentence.
func (inv *invocation) scopeNetconfText(s policy.NetconfScope) string {
	e := resolveNetconf(s, devreg.Netconf{})
	text := e.words()
	if s.State == "" && (s.ConnectionLimit > 0 || s.RateLimit > 0) {
		// limits of a scope that has no state of its own (a hand-edited
		// tacctl.yaml): they mean nothing until it enables the service
		text += "; limits stored but unused: connection " + strconv.Itoa(s.ConnectionLimit) + ", rate " + strconv.Itoa(s.RateLimit)
	}
	return text
}

// scopeNetconfMove follows a scope's rename (newName set) or removal (newName
// empty): its keys in tacctl.yaml. It says what could not be carried over.
func (inv *invocation) scopeNetconfMove(old, newName string) error {
	lost, err := policy.MoveNetconfScope(inv.app.Conf(), old, newName)
	if err != nil {
		return err
	}
	for _, l := range lost {
		ui.Output{Stdout: inv.app.Out.Stderr}.Warn(l + " holds a value tacctl.yaml does not take; it was not carried over to '" + newName + "'.")
	}
	return nil
}
