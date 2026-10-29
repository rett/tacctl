package cli

// 'tacctl server show [--json]' (0.2.22): what this server is, in one place.
// The address devices and hosts reach it at, the default method of new hosts,
// the metrics exporter, and for each backend whether it is enabled, its
// service and its listeners with their ports and units. It reads settings and
// asks systemd for the state of each unit; it changes nothing and writes no
// audit line. The superuser's, as the rest of the family (the tier table has
// no row for 'server').

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/ui"
)

const serverUseShow = "show [--json]"

// serverShowJSON is the document of 'server show --json'.
type serverShowJSON struct {
	// Addresses are the addresses devices and hosts reach this server at
	// (empty when none is recorded); AddressSource says where the first one
	// is read from: "setting" (server.addresses), "registry" (this server's
	// registry entry, from before the setting) or "".
	Addresses     []string `json:"addresses"`
	AddressSource string   `json:"address_source"`
	// DefaultMethod is the method 'host enroll' gives a host without --method.
	DefaultMethod string             `json:"default_method"`
	Metrics       serverMetricsJSON  `json:"metrics"`
	Backends      []serverBackendRow `json:"backends"`
}

// serverMetricsJSON is the Prometheus exporter of the TACACS+ backend's
// default listener: its address and what that address means ("enabled",
// "disabled" for the sink no scraper can reach).
type serverMetricsJSON struct {
	Address string `json:"address"`
	State   string `json:"state"`
	// Reach is "loopback" or "external" for an enabled exporter, "" for a
	// disabled one.
	Reach string `json:"reach"`
}

// serverBackendRow is one backend of 'server show --json'.
type serverBackendRow struct {
	ID        string              `json:"id"`
	Protocol  string              `json:"protocol"`
	Installed bool                `json:"installed"`
	Enabled   bool                `json:"enabled"`
	Service   string              `json:"service"`
	Listeners []serverListenerRow `json:"listeners"`
}

// serverListenerRow is one listener of a backend: its address and port, and
// the state of the unit that serves it.
type serverListenerRow struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Unit    string `json:"unit"`
}

// metricsMeaning is what a metrics address means: the sink is "disabled", a
// loopback address "enabled" and reachable from this machine only, any other
// "enabled" and external (the words of 'server metrics').
func metricsMeaning(addr string) (state, reach string) {
	switch {
	case addr == rtacacs.MetricsSink:
		return "disabled", ""
	case strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "[::1]") || strings.HasPrefix(addr, "localhost:"):
		return "enabled", "loopback"
	}
	return "enabled", "external"
}

// portOf is the port of a listener address (':49', '10.1.0.1:49', '[::]:49');
// 0 when it has none.
func portOf(addr string) int {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// serverShowData reads everything the overview shows.
func (inv *invocation) serverShowData() (*serverShowJSON, error) {
	reg, err := inv.registry()
	if err != nil {
		return nil, err
	}
	out := &serverShowJSON{Addresses: []string{}, Backends: []serverBackendRow{}, DefaultMethod: inv.linuxDefaultMethod()}
	c := inv.app.Conf()
	switch key, recorded := c.ServerAddress(), inv.recordedServer(reg); {
	case key != "":
		out.Addresses, out.AddressSource = []string{key}, "setting"
	case recorded != "":
		out.Addresses, out.AddressSource = []string{recorded}, "registry"
	}
	addr, _ := c.Get("backends.tacacs.metrics_address", rtacacs.MetricsDefault)
	out.Metrics.Address = addr
	out.Metrics.State, out.Metrics.Reach = metricsMeaning(addr)

	enabled, err := inv.enabledOrFail()
	if err != nil {
		return nil, err
	}
	set := inv.app.Backends()
	for _, id := range set.IDs() {
		b, err := set.Get(id)
		if err != nil {
			return nil, err
		}
		row := serverBackendRow{ID: id, Protocol: or(b.Describe().Protocol, "-"), Installed: b.Installed(),
			Enabled: slices.Contains(enabled, id), Service: "-", Listeners: []serverListenerRow{}}
		if row.Installed {
			svc, _ := b.Service(inv.ctx, backend.ServiceIsActive, "")
			row.Service = or(svc, "unknown")
		}
		// the listeners of a backend that is not in use are not interesting
		if row.Installed || row.Enabled {
			ls, _ := b.Listeners().List()
			for _, l := range ls {
				if l.Name == "" {
					continue
				}
				unit := "-"
				if row.Installed {
					u, _ := b.Service(inv.ctx, backend.ServiceIsActive, l.Name)
					unit = or(u, "unknown")
				}
				row.Listeners = append(row.Listeners, serverListenerRow{Name: l.Name, Network: l.Network, Address: l.Address, Port: portOf(l.Address), Unit: unit})
			}
		}
		out.Backends = append(out.Backends, row)
	}
	return out, nil
}

// serverShow is 'server show [--json]'.
func (inv *invocation) serverShow(args []string) error {
	p, err := Parse(serverSpecs["show"], args)
	if err != nil {
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			return inv.usageErr("Unknown option: '"+uf.Flag+"'", "Usage: tacctl server "+serverUseShow)
		}
		return inv.usageErr(err.Error(), "Usage: tacctl server "+serverUseShow)
	}
	if len(p.Args) > 0 {
		return inv.usageErr("Unknown argument: '"+p.Args[0]+"'", "Usage: tacctl server "+serverUseShow)
	}
	d, err := inv.serverShowData()
	if err != nil {
		return err
	}
	if p.Has("--json") {
		return inv.printJSON(d)
	}
	const title = "Server"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	switch {
	case len(d.Addresses) == 0:
		inv.echo("  Address:         (none — 'tacctl host enroll --local' records the address of this machine, or: tacctl server addresses add <ip>)")
	case d.AddressSource == "registry":
		inv.echo("  Address:         " + strings.Join(d.Addresses, ", ") + "  (this server's registry entry; the setting is written by the next 'host enroll --local')")
	default:
		inv.echo("  Address:         " + strings.Join(d.Addresses, ", "))
	}
	inv.echo("  Default method:  " + d.DefaultMethod + "  (for hosts enrolled without --method)")
	m := d.Metrics
	switch {
	case m.State == "disabled":
		inv.echoE("  Metrics:         " + ui.Red + "disabled" + ui.NC + "  (" + m.Address + ", a port no scraper can reach)")
	case m.Reach == "loopback":
		inv.echoE("  Metrics:         " + ui.Green + "enabled, loopback only" + ui.NC + "  (" + m.Address + ")")
	default:
		inv.echoE("  Metrics:         " + ui.Yellow + "enabled, externally reachable" + ui.NC + "  (" + m.Address + ")")
	}
	inv.echo("")

	t := ui.NewTable("Backends", ui.Left("ID"), ui.Left("PROTOCOL"), ui.Left("ENABLED"), ui.Left("SERVICE"))
	for _, b := range d.Backends {
		state := "not installed"
		if b.Installed {
			state = b.Service
		}
		t.Add(b.ID, b.Protocol, map[bool]string{true: "yes", false: "no"}[b.Enabled], state)
	}
	inv.write(t.String())
	inv.echo("")

	l := ui.NewTable("Listeners", ui.Left("BACKEND"), ui.Left("LISTENER"), ui.Left("NETWORK"), ui.Left("ADDRESS"), ui.Left("PORT"), ui.Left("UNIT"))
	for _, b := range d.Backends {
		for _, r := range b.Listeners {
			port := "-"
			if r.Port != 0 {
				port = strconv.Itoa(r.Port)
			}
			l.Add(b.ID, r.Name, r.Network, r.Address, port, r.Unit)
		}
	}
	inv.write(l.String())
	inv.echo("")
	return nil
}
