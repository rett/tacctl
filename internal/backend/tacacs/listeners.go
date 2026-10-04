package tacacs

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/yamlpy"
)

// readServiceOverride is read_service_override: the last non-empty
// Environment="<key>=<value>" value of the hand-managed drop-in ("" when
// there is none, or no file).
func (b *Backend) readServiceOverride(key string) string {
	data, err := os.ReadFile(b.overrideFile())
	if err != nil {
		return ""
	}
	prefix := `Environment="` + key + "="
	val := ""
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		v := line[len(prefix):]
		if i := strings.IndexByte(v, '"'); i >= 0 {
			v = v[:i]
		}
		if v != "" { // grep -o prints no empty match
			val = v
		}
	}
	return val
}

// overridesMention is 'grep -qs <word> tacctl.yaml': the cheap test that
// spares a read of the merged config when the file cannot set anything
// under that word.
func (b *Backend) overridesMention(word string) bool {
	data, err := os.ReadFile(b.env.Paths.Overrides)
	return err == nil && bytes.Contains(data, []byte(word))
}

// conf is the invocation's tacctl.yaml view, its warning written once as
// _conf_load_cache does when the file cannot be used.
func (b *Backend) conf() *conf.Config {
	b.env.Conf.WarnOnce(b.env.Out.Stderr)
	return b.env.Conf
}

// listenerLines is _tacacs_listener_lines: the listeners in effect, the
// default listener first. An install that is not converted has the one its
// hand-managed drop-in says; most installs have the default listener on its
// default address, which costs no read of tacctl.yaml.
func (b *Backend) listenerLines() []backend.Listener {
	if b.legacyUnits() {
		return []backend.Listener{{Name: "default", Network: or(b.readServiceOverride("TACQUITO_NETWORK"), "tcp"),
			Address: or(b.readServiceOverride("TACQUITO_ADDRESS"), ":49")}}
	}
	if !b.overridesMention("listeners") {
		return []backend.Listener{{Name: "default", Network: "tcp", Address: ":49"}}
	}
	var out []backend.Listener
	for _, l := range conf.ListenersEffective(b.conf().Merged(), rtacacs.Protocol) {
		out = append(out, backend.Listener{Name: l.Name, Network: l.Network, Address: l.Address})
	}
	return out
}

// effectiveListeners is backend_listeners tacacs: every listener with its
// role and metrics address.
func (b *Backend) effectiveListeners() []conf.Listener {
	return conf.ListenersEffective(b.conf().Merged(), rtacacs.Protocol)
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// setting is _tacacs_setting <level|metrics_address>: the value in effect
// and whether it is an override or the default.
func (b *Backend) setting(key string) (value string, override bool) {
	fallback := strconv.Itoa(rtacacs.LevelDefault)
	if key != "level" {
		fallback = rtacacs.MetricsDefault
	}
	switch {
	case b.legacyUnits():
		if key == "level" {
			value = b.readServiceOverride("TACQUITO_LEVEL")
		} else {
			value = b.readServiceOverride("TACQUITO_METRICS_ADDRESS")
		}
	case b.overridesMention("backends") && b.env.Conf.HasOverride("backends.tacacs."+key):
		value, _ = b.conf().Get("backends.tacacs."+key, "")
	}
	if value != "" {
		return value, true
	}
	return fallback, false
}

// journalUnits are the -u arguments of journalctl: the default listener's
// unit as it has always been named, then every other listener's.
func (b *Backend) journalUnits() []string {
	out := []string{"-u", Service}
	for _, l := range b.listenerLines() {
		if l.Name != "default" {
			out = append(out, "-u", rtacacs.Unit(l.Name))
		}
	}
	return out
}

// listenerGet is _tacacs_listener_get: a listener in effect and whether it
// is set (override) or the built-in default; ok false when there is none of
// that name.
func (b *Backend) listenerGet(want string) (l backend.Listener, override, ok bool) {
	for _, x := range b.listenerLines() {
		if x.Name == want {
			l = x
		}
	}
	if l.Network == "" {
		return l, false, false
	}
	if b.legacyUnits() {
		override = b.readServiceOverride("TACQUITO_NETWORK")+b.readServiceOverride("TACQUITO_ADDRESS") != ""
	} else {
		override = want != "default" || b.env.Conf.HasOverride("listeners.tacacs."+want)
	}
	return l, override, true
}

// Listeners is backend_tacacs_listeners: list, show, set and reset.
func (b *Backend) Listeners() backend.ListenerOps { return listenerOps{b} }

type listenerOps struct{ b *Backend }

func listenerName(name string) string { return or(name, "default") }

// List is 'listeners list'.
func (o listenerOps) List() ([]backend.Listener, error) { return o.b.listenerLines(), nil }

// Show is _tacacs_listener_show.
func (o listenerOps) Show(_ context.Context, name string) (string, error) {
	b := o.b
	want := listenerName(name)
	l, override, ok := b.listenerGet(want)
	if !ok {
		b.out().Error("No listener '" + want + "'. Create it: tacctl config listen --listener " + want + " tcp <address>")
		return "", backend.ErrFailed
	}
	if want != "default" {
		return "  Listener '" + want + "': " + l.Network + " " + l.Address + "\n" +
			"  (" + rtacacs.Unit(want) + "; set in " + b.env.Paths.Overrides + ")", nil
	}
	lines := []string{"  Current listener: " + l.Network + " " + l.Address}
	switch {
	case !override:
		lines = append(lines, "  (template default)")
	case b.legacyUnits():
		lines = append(lines, "  (override in "+b.overrideFile()+")")
	default:
		lines = append(lines, "  (override in "+b.env.Paths.Overrides+")")
	}
	for _, x := range b.listenerLines() {
		if x.Name != "default" {
			lines = append(lines, "  Listener '"+x.Name+"': "+x.Network+" "+x.Address+" ("+rtacacs.Unit(x.Name)+")")
		}
	}
	return strings.Join(lines, "\n"), nil
}

// listenerValue is _tacacs_listener_json: the listener's entry in
// tacctl.yaml with network and address set and its other keys kept.
func (b *Backend) listenerValue(name, network, address string) *yamlpy.Map {
	out := yamlpy.NewMap()
	if cur, ok := b.env.Conf.Value("listeners.tacacs." + name); ok {
		if m, isMap := cur.(*yamlpy.Map); isMap {
			for k, v := range m.All() {
				out.Set(k, v)
			}
		}
	}
	out.Set("network", network)
	out.Set("address", address)
	return out
}

// listenerCheck is _tacacs_listener_check: would listeners.tacacs.<name> =
// value collide with another listener or be refused by the schema? The
// reason, "" when it would not.
func (b *Backend) listenerCheck(name string, value *yamlpy.Map) string {
	doc := yamlpy.NewMap()
	for k, v := range b.conf().Merged().All() {
		doc.Set(k, v)
	}
	section := yamlpy.NewMap()
	if s, ok := doc.Get("listeners"); ok {
		if sm, isMap := s.(*yamlpy.Map); isMap {
			for k, v := range sm.All() {
				section.Set(k, v)
			}
		}
	}
	mine := yamlpy.NewMap()
	if s, ok := section.Get(rtacacs.Protocol); ok {
		if sm, isMap := s.(*yamlpy.Map); isMap {
			for k, v := range sm.All() {
				mine.Set(k, v)
			}
		}
	}
	mine.Set(name, value)
	section.Set(rtacacs.Protocol, mine)
	doc.Set("listeners", section)
	path := "listeners.tacacs." + name
	bad := conf.ListenersProblems(doc, path, true)
	if len(bad) == 0 {
		return ""
	}
	if len(bad[0]) < len(path)+2 {
		return ""
	}
	return bad[0][len(path)+2:]
}

// Set is _tacacs_listener_set: create or change a listener (tcp or tcp6),
// asking first when the change moves it to tcp6, then restart its unit;
// when the unit does not come up everything is put back.
func (o listenerOps) Set(ctx context.Context, name, network, address string) error {
	b := o.b
	name = listenerName(name)
	out := b.out()
	if network != "tcp" && network != "tcp6" {
		out.Error("Invalid subcommand: '" + network + "'. Use: show, tcp, tcp6, or reset")
		return backend.ErrFailed
	}
	if address == "" {
		out.Error("Missing address. Example: tacctl config listen " + network + " :49")
		return backend.ErrFailed
	}
	if conf.ListenAddressProblem(network, address) != "" {
		out.Error("Invalid " + network + " address: '" + address + "'")
		return backend.ErrFailed
	}

	cur, _, existed := b.listenerGet(name)
	if cur.Network == network && cur.Address == address {
		out.Info("Already listening on " + network + " " + address + ".")
		return nil
	}

	value := b.listenerValue(name, network, address)
	if why := b.listenerCheck(name, value); why != "" {
		out.Error("Cannot listen on " + network + " " + address + ": " + why)
		return backend.ErrFailed
	}

	if network == "tcp6" && cur.Network != "tcp6" {
		writeString(out.Stdout, "\n")
		out.Warn("tcp6 enables dual-stack sockets on most platforms.")
		out.Warn("IPv4 clients connect with mapped addresses (::ffff:a.b.c.d)")
		out.Warn("which do NOT match IPv4 rules in 'tacctl scope prefixes <name>',")
		out.Warn("'config allow', or 'config deny' -- effectively bypassing them.")
		writeString(out.Stdout, "\n")
		if !b.prompt().ConfirmPrefix("  Proceed with tcp6? [y/N]: ") {
			out.Info("Aborted.")
			return nil
		}
	}

	// A unit that does not come up with the new address gets the previous
	// settings back.
	if err := b.settingsApply(ctx, name, func() error {
		return b.env.Conf.SetValue("listeners.tacacs."+name, value)
	}); err != nil {
		return err
	}

	unit := rtacacs.Unit(name)
	switch {
	case name == "default":
		out.Info("Listener changed to " + network + " " + address + ". Service restarted.")
	case existed:
		out.Info("Listener '" + name + "' changed to " + network + " " + address + ". " + unit + " restarted.")
	default:
		out.Info("Listener '" + name + "' added on " + network + " " + address + ". " + unit + " enabled and started.")
		out.Info("It logs accounting to " + rtacacs.AcctLog(b.paths(), name) +
			" and exports no metrics unless listeners.tacacs." + name + ".metrics_address is set.")
	}
	writeString(out.Stdout, "\n")
	return nil
}

// Reset is _tacacs_listener_reset: the default listener back to its
// default address; any other listener is removed (its instance stopped and
// disabled).
func (o listenerOps) Reset(ctx context.Context, name string) error {
	b := o.b
	name = listenerName(name)
	out := b.out()
	cur, override, ok := b.listenerGet(name)
	if !ok {
		out.Error("No listener '" + name + "'.")
		return backend.ErrFailed
	}
	unset := func() error { return b.env.Conf.Unset("listeners.tacacs." + name) }
	if name != "default" {
		// Only the built-in listener has a default to go back to.
		if err := b.settingsApply(ctx, name, unset); err != nil {
			return err
		}
		out.Info("Listener '" + name + "' removed. " + rtacacs.Unit(name) + " stopped and disabled.")
		writeString(out.Stdout, "\n")
		return nil
	}
	if !override {
		out.Info("No listener override set. Already on template default (" + cur.Network + " " + cur.Address + ").")
		return nil
	}
	if err := b.settingsApply(ctx, "default", unset); err != nil {
		out.Error("tacquito failed to start after reset.")
		return err
	}
	out.Info("Listener override removed. Using template default. Service restarted.")
	writeString(out.Stdout, "\n")
	return nil
}
