package cli

// 'tacctl server listen' and 'tacctl server metrics' (0.2.22): the listeners
// of the backends and the Prometheus exporter of the TACACS+ backend, which
// were 'config listen' and 'config metrics' until 0.2.21 (the stored keys,
// listeners.<backend>.<name> and backends.tacacs.metrics_address, are the
// same). The settings are applied by the backends (internal/backend); this
// file is the verbs' command line. The old forms are gone, with no alias:
// 'config' answers them as any word it does not have (unknownSub).

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/backend"
)

// serverMetrics is 'server metrics' (cmd_config_metrics until 0.2.21: 'config
// metrics'). An unknown subcommand is refused
// here, through 'error' (echo -e), before the module is asked.
func (inv *invocation) serverMetrics(args []string) error {
	sub := arg(args, 0)
	switch sub {
	case "", "show", "-h", "--help", "help", "enable", "disable", "address", "reset":
	default:
		return inv.unknownSub(sub)
	}
	b, err := inv.tacacsBackend()
	if err != nil {
		return err
	}
	switch sub {
	case "enable", "disable", "address", "reset":
		return inv.settingChange("server metrics", "backends.tacacs.metrics_address", "127.0.0.1:8080",
			func() error { return b.Metrics(inv.ctx, sub, arg(args, 1)) }, nil)
	}
	return b.Metrics(inv.ctx, sub, arg(args, 1))
}

// --- listen (lib/backend.sh cmd_config_listen until 0.2.21) -----------------

var reListenerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// serverListen is 'server listen' (cmd_config_listen until 0.2.21: 'config
// listen'): [--backend <id>] [--listener <name>]
// [show|reset|<network> <address>], the TACACS+ default listener without
// flags. Any other word, a dash-word included, is a positional.
func (inv *invocation) serverListen(args []string) error {
	a := inv.app
	id, listener := backend.TACACS, "default"
	var rest []string
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == "--backend" || w == "--listener":
			if arg(args, i+1) == "" {
				return inv.usageErr(w + " needs a value. Usage: tacctl server listen [--backend <id>] [--listener <name>] <show|<network> <address>|reset>")
			}
			if w == "--backend" {
				id = args[i+1]
			} else {
				listener = args[i+1]
			}
			i++
		case strings.HasPrefix(w, "--backend="):
			id = strings.TrimPrefix(w, "--backend=")
		case strings.HasPrefix(w, "--listener="):
			listener = strings.TrimPrefix(w, "--listener=")
		default:
			rest = append(rest, w)
		}
	}
	set := a.Backends()
	if !slices.Contains(set.IDs(), id) {
		return inv.usageErr("Unknown backend '" + id + "' (known: " + strings.Join(set.IDs(), " ") + ").")
	}
	if !reListenerName.MatchString(listener) {
		return inv.usageErr("Invalid listener name '" + listener + "': a lowercase letter, then up to 31 of [a-z0-9_-].")
	}
	b, err := set.Get(id)
	if err != nil {
		return err
	}
	ops := b.Listeners()
	switch sub := arg(rest, 0); sub {
	case "", "show":
		shown, err := ops.Show(inv.ctx, listener)
		if err != nil {
			return err
		}
		inv.echo("")
		inv.echo(strings.TrimRight(shown, "\n"))
		inv.echo("")
		if id != backend.TACACS {
			// Another backend's networks and listener names are its own.
			inv.echo("  Usage: tacctl server listen --backend " + id + " --listener <name> <network> <address>")
			inv.echo("         tacctl server listen --backend " + id + " --listener <name> reset")
			inv.echo("")
			return nil
		}
		inv.write(`  Usage: tacctl server listen [show|tcp|tcp6|reset] [<addr>]
  Examples:
    tacctl server listen tcp :49
    tacctl server listen tcp 10.1.0.1:49
    tacctl server listen tcp6 [::]:49
    tacctl server listen reset       # drop override, use template default

`)
		return nil
	case "reset":
		return inv.listenerChange(ops, id, listener, func() error { return ops.Reset(inv.ctx, listener) })
	default:
		// A network and an address; the backend says which networks it has.
		return inv.listenerChange(ops, id, listener, func() error { return ops.Set(inv.ctx, listener, sub, arg(rest, 1)) })
	}
}

// listenerChange runs set and writes 'server listen backend= listener= from=
// to=' (each "<network> <address>", '-' for none) when the listener is not
// what it was.
func (inv *invocation) listenerChange(ops backend.ListenerOps, id, name string, set func() error) error {
	text := func() string {
		ls, _ := ops.List()
		for _, l := range ls {
			if l.Name == name {
				return l.Network + " " + l.Address
			}
		}
		return ""
	}
	before := text()
	err := set()
	if after := text(); err == nil && before != after {
		inv.detail("server listen", kvp("backend", id), kvp("listener", name), kvp("from", before), kvp("to", after))
	}
	return err
}
