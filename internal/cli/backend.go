package cli

// The 'backend' family (lib/backend.sh cmd_backend at 0.1.16). Native since
// WP2.4d: list and status, which only read; since WP3.3c enable and disable
// (backend_enable.go, registered with registerFamilyVerb).

import (
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/ui"
)

// The _completion-names kinds of backend ids: every registered one
// ('backend enable <id>', '--backend <id>'), or the enabled ones ('backend
// disable <id>').
const (
	KindBackends        = "backends"
	KindEnabledBackends = "enabled-backends"
)

// backendSpecs are the arguments of each verb, for completion (args.go).
var backendSpecs = map[string]Spec{
	"list":    {},
	"status":  {MaxArgs: 1, Args: []string{KindBackends}},
	"enable":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindBackends}, Flags: []Flag{{Names: []string{"-y", "--yes"}}}},
	"disable": {MinArgs: 1, MaxArgs: 1, Args: []string{KindEnabledBackends}, Flags: []Flag{{Names: []string{"-y", "--yes"}}}},
}

func backendCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	c := verb("backend <subcommand>", "Auth backends: list, status, enable <id>, disable <id>",
		withRun(verb("list", "Every backend: protocol, implementation, installed, enabled, service"), n(inv.backendList)),
		withRun(verb("status [<id>]", "Service and listener state of every backend (or one)"), n(inv.backendStatus)),
		// Replaced by backend_enable.go's (registerFamilyVerb).
		verb("enable", "Install the backend if needed, enable it, render its config, start it"),
		verb("disable", "Stop and disable it, take it out of backends.enabled (confirms)"),
	)
	replaceRegistered(inv, c, backendVerbs)
	// No sub-command or an unknown one: the usage, exit 1.
	c.RunE = n(func([]string) error {
		inv.write(backendUsage(inv.app.Backends().IDs()))
		return exit(1)
	})
	return c
}

// backendVerbs are 'backend' verbs other files register (registerFamilyVerb).
var backendVerbs = map[string]func(inv *invocation) *cobra.Command{}

// backendUsage is _backend_usage.
func backendUsage(ids []string) string {
	return Usage("backend", UsageVars{"backends": strings.Join(ids, " ")})
}

// enabledOrFail is '_backends_load || return 1': the enabled backends, or
// the error printed and exit 1.
func (inv *invocation) enabledOrFail() ([]string, error) {
	ids, err := inv.app.Backends().Enabled()
	if err != nil {
		inv.app.Out.ErrorE(err.Error())
		return nil, exit(1)
	}
	return ids, nil
}

// backendKnown is _backend_known: the id names a registered backend, or
// the error naming the ones there are (exit 1).
func (inv *invocation) backendKnown(id string) error {
	ids := inv.app.Backends().IDs()
	switch {
	case id == "":
		return inv.usageErr("Missing backend id (known: " + strings.Join(ids, " ") + ").")
	case !slices.Contains(ids, id):
		return inv.usageErr("Unknown backend '" + id + "' (known: " + strings.Join(ids, " ") + ").")
	}
	return nil
}

// backendList is _backend_list: every registered backend with its
// protocol, implementation, whether it is installed and enabled, and its
// service state when installed.
func (inv *invocation) backendList([]string) error {
	enabled, err := inv.enabledOrFail()
	if err != nil {
		return err
	}
	set := inv.app.Backends()
	t := ui.NewTable("Backends", ui.Left("ID"), ui.Left("PROTOCOL"), ui.Left("IMPLEMENTATION"), ui.Left("INSTALLED"), ui.Left("ENABLED"), ui.Left("SERVICE"))
	for _, id := range set.IDs() {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		d := b.Describe()
		proto, impl := or(d.Protocol, "-"), or(d.Impl, "-")
		inst, enab, svc := "no", "no", "-"
		if b.Installed() {
			inst = "yes"
			svc, _ = b.Service(inv.ctx, backend.ServiceIsActive, "")
			svc = or(svc, "unknown")
		}
		if slices.Contains(enabled, id) {
			enab = "yes"
		}
		t.Add(id, proto, impl, inst, enab, svc)
	}
	inv.echo("")
	inv.write(t.String())
	inv.echo("")
	return nil
}

// or is "${v:-def}".
func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// backendStatus is _backend_status: per backend (every registered one, or
// the one named), whether it is installed and enabled, its service, each
// listener (probed with ss) and its summary.
func (inv *invocation) backendStatus(args []string) error {
	enabled, err := inv.enabledOrFail()
	if err != nil {
		return err
	}
	set := inv.app.Backends()
	ids := set.IDs()
	if len(args) > 0 {
		if err := inv.backendKnown(args[0]); err != nil {
			return err
		}
		ids = []string{args[0]}
	}
	B, G, R, NC := ui.Bold, ui.Green, ui.Red, ui.NC
	for _, id := range ids {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		inv.write(backend.Heading(b))
		isEnabled := slices.Contains(enabled, id)
		enab := "not enabled"
		if isEnabled {
			enab = "enabled"
		}
		if !b.Installed() {
			inv.echoE("  " + B + "State:" + NC + "                not installed, " + enab)
			continue
		}
		inv.echoE("  " + B + "State:" + NC + "                installed, " + enab)
		state, _ := b.Service(inv.ctx, backend.ServiceIsActive, "")
		state = or(state, "unknown")
		switch {
		case state == "active":
			inv.echoE("  " + B + "Service:" + NC + "              " + G + state + NC)
			if since, err := b.Service(inv.ctx, backend.ServiceSince, ""); err == nil && since != "" {
				inv.echoE("  " + B + "Since:" + NC + "                " + since)
			}
			if pid, err := b.Service(inv.ctx, backend.ServicePID, ""); err == nil && pid != "" && pid != "0" {
				inv.echoE("  " + B + "PID:" + NC + "                  " + pid)
			}
		case isEnabled:
			inv.echoE("  " + B + "Service:" + NC + "              " + R + state + NC)
		default:
			inv.echoE("  " + B + "Service:" + NC + "              " + state)
		}
		ls, _ := b.Listeners().List()
		for _, l := range ls {
			if l.Name == "" {
				continue
			}
			bound := inv.listenerProbe(l.Network, l.Address)
			ustate, _ := b.Service(inv.ctx, backend.ServiceIsActive, l.Name)
			ustate = or(ustate, "unknown")
			switch {
			case bound != "":
				bound = G + "listening on " + bound + NC
			case state == "active":
				bound = R + "port " + l.Address[strings.LastIndexByte(l.Address, ':')+1:] + " not detected" + NC
			default:
				bound = "not listening"
			}
			inv.echoE("  " + B + "Listener " + l.Name + ":" + NC + " " + l.Network + " " + l.Address + " — unit " + ustate + ", " + bound)
		}
		// Anything else the backend reports here (a count, never a table);
		// a backend without a summary says nothing.
		_ = b.Status(inv.ctx, backend.StatusSummary, inv.app.Out.Stdout)
	}
	inv.echo("")
	return nil
}

// backendNames is '_completion-names backends': every registered id.
func (inv *invocation) backendNames([]string) []string { return inv.app.Backends().IDs() }

// enabledBackendNames is '_completion-names enabled-backends'
// (backends_enabled 2>/dev/null || true): the enabled ids, or none.
func (inv *invocation) enabledBackendNames([]string) []string {
	ids, err := inv.app.Backends().Enabled()
	if err != nil {
		return nil
	}
	return ids
}

// stdout is the invocation's stdout, for a module's
// report.
func (inv *invocation) stdout() io.Writer { return inv.app.Out.Stdout }
