package radius

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Listeners is backend_radius_listeners: the backend's listeners.radius of
// tacctl.yaml. There are two built-in ones, 'auth' (udp :1812) and 'acct'
// (udp :1813); any other is the operator's, and a listener answers
// authentication or accounting, never both.
func (m *Module) Listeners() backend.ListenerOps { return listenerOps{m} }

type listenerOps struct{ m *Module }

// effectiveListeners are the listeners in effect (listeners_effective), the
// built-in ones first.
func (m *Module) effectiveListeners() []conf.Listener {
	return conf.ListenersEffective(m.env.Conf.Merged(), "radius")
}

// listener is _radius_listener_get: the listener of that name in effect, and
// whether tacctl.yaml says anything about it (override) or it is the
// built-in default.
func (m *Module) listener(name string) (l conf.Listener, override, ok bool) {
	for _, e := range m.effectiveListeners() {
		if e.Name == name {
			l, ok = e, true
		}
	}
	if sec, found := m.env.Conf.Merged().Get("listeners"); found {
		if sm, isMap := sec.(*yamlpy.Map); isMap {
			if mine, found := sm.Get("radius"); found {
				if mm, isMap := mine.(*yamlpy.Map); isMap {
					override = mm.Has(name)
				}
			}
		}
	}
	return l, override, ok
}

func isBuiltin(name string) bool { return name == "auth" || name == "acct" }

// List is _radius_listener_lines: the listeners in effect, auth and acct
// first.
func (o listenerOps) List() ([]backend.Listener, error) {
	var out []backend.Listener
	for _, l := range o.m.effectiveListeners() {
		out = append(out, backend.Listener{Name: l.Name, Network: l.Network, Address: l.Address})
	}
	return out, nil
}

// Show is _radius_listener_show: the listener 'tacctl config listen' prints
// ("default" for every one of them), the lines ending in newlines. An unknown
// name is written as an error and ErrFailed.
func (o listenerOps) Show(_ context.Context, name string) (string, error) {
	m := o.m
	if name != "default" {
		if _, _, ok := m.listener(name); !ok {
			m.env.Out.Error("No RADIUS listener '" + name + "'. Create it: tacctl config listen --backend radius --listener " + name + " udp <address>")
			return "", backend.ErrFailed
		}
	}
	var b strings.Builder
	for _, l := range m.effectiveListeners() {
		if name != "default" && name != l.Name {
			continue
		}
		_, override, _ := m.listener(l.Name)
		src := "built-in default"
		if override {
			src = "set in " + m.env.Paths.Overrides
		}
		fmt.Fprintf(&b, "  RADIUS listener '%s' (%s): %s %s   (%s)\n", l.Name, l.Role, l.Network, l.Address, src)
	}
	return b.String(), nil
}

// problem is _radius_listener_check: would listeners.radius.<name> = value
// be refused by the schema, or collide with another listener? The first
// problem, without its path.
func (m *Module) problem(name string, value *yamlpy.Map) string {
	merged := m.env.Conf.Merged()
	doc := yamlpy.NewMap()
	for k, v := range merged.All() {
		doc.Set(k, v)
	}
	section := yamlpy.NewMap()
	if sv, ok := merged.Get("listeners"); ok {
		if sm, isMap := sv.(*yamlpy.Map); isMap {
			for k, v := range sm.All() {
				section.Set(k, v)
			}
		}
	}
	mine := yamlpy.NewMap()
	if mv, ok := section.Get("radius"); ok {
		if mm, isMap := mv.(*yamlpy.Map); isMap {
			for k, v := range mm.All() {
				mine.Set(k, v)
			}
		}
	}
	mine.Set(name, value)
	section.Set("radius", mine)
	doc.Set("listeners", section)
	path := "listeners.radius." + name
	if bad := conf.ListenersProblems(doc, path, true); len(bad) > 0 {
		return bad[0][len(path)+2:]
	}
	return ""
}

// Set is _radius_listener_set: create or change a listener, make the daemon
// follow (re-render, restart) and report; when the daemon does not stay up
// the previous listener is put back and the error says so. Messages are
// written; an error is ErrFailed (or what StoreApply reports).
func (o listenerOps) Set(ctx context.Context, name, network, address string) error {
	m := o.m
	out := m.env.Out
	if name == "default" {
		out.Error("The RADIUS backend has two built-in listeners; name one: --listener auth (udp :1812) or --listener acct (udp :1813).")
		return backend.ErrFailed
	}
	if network != "udp" && network != "udp6" {
		out.Error("Invalid network '" + network + "': the RADIUS backend listens on udp or udp6. Usage: tacctl config listen --backend radius --listener <name> <udp|udp6> <address>")
		return backend.ErrFailed
	}
	if address == "" {
		out.Error("Missing address. Example: tacctl config listen --backend radius --listener " + name + " " + network + " :1812")
		return backend.ErrFailed
	}
	if conf.ListenAddressProblem(network, address) != "" {
		out.Error("Invalid " + network + " address: '" + address + "'")
		return backend.ErrFailed
	}

	cur, _, existed := m.listener(name)
	if cur.Network == network && cur.Address == address {
		out.Info("RADIUS listener '" + name + "' already on " + network + " " + address + ".")
		return nil
	}
	// A listener answers authentication or accounting, never both. An
	// existing one keeps what it does; a new one is an accounting listener
	// when its name starts with 'acct', else an authentication listener.
	role := cur.Role
	if role == "" {
		role = "auth"
	}
	if !existed && strings.HasPrefix(name, "acct") {
		role = "acct"
	}

	value := yamlpy.NewMap("network", network, "address", address, "role", role)
	if why := m.problem(name, value); why != "" {
		out.Error("Cannot listen on " + network + " " + address + ": " + why)
		return backend.ErrFailed
	}
	if network == "udp6" && cur.Network != "udp6" {
		out.Warn("A udp6 listener serves IPv6 clients only; scope prefixes that are IPv4 are reached through a udp listener.")
	}
	path := "listeners.radius." + name
	if err := m.listenerApply(ctx, func() error { return m.env.Conf.SetValue(path, value) }); err != nil {
		return err
	}
	if existed {
		out.Info("RADIUS listener '" + name + "' changed to " + network + " " + address + ".")
	} else {
		out.Info("RADIUS listener '" + name + "' (" + role + ") added on " + network + " " + address + ".")
	}
	_, _ = fmt.Fprintln(out.Stdout)
	return nil
}

// Reset is _radius_listener_reset: a built-in listener goes back to its
// default, any other is removed, the daemon following as for Set.
func (o listenerOps) Reset(ctx context.Context, name string) error {
	m := o.m
	out := m.env.Out
	if name == "default" {
		out.Error("Name the listener: --listener auth or --listener acct.")
		return backend.ErrFailed
	}
	cur, override, ok := m.listener(name)
	if !ok {
		out.Error("No RADIUS listener '" + name + "'.")
		return backend.ErrFailed
	}
	if !override {
		out.Info("RADIUS listener '" + name + "' is already on its default (" + cur.Network + " " + cur.Address + ").")
		return nil
	}
	if err := m.listenerApply(ctx, func() error { return m.env.Conf.Unset("listeners.radius." + name) }); err != nil {
		return err
	}
	if isBuiltin(name) {
		out.Info("RADIUS listener '" + name + "' is back on its default.")
	} else {
		out.Info("RADIUS listener '" + name + "' removed.")
	}
	_, _ = fmt.Fprintln(out.Stdout)
	return nil
}

// apply is store_apply with this module's Set.
func (m *Module) apply(ctx context.Context, opts backend.ApplyOptions, writer func() error) (backend.Result, error) {
	if m.Apply != nil {
		return m.Apply(ctx, opts, writer)
	}
	return backend.NewSet(backend.Default(), m.env).StoreApply(ctx, opts, writer)
}

// serving is _radius_serving: the backend is in backends.enabled and its
// daemon is set up.
func (m *Module) serving() bool {
	ids := m.env.Conf.GetList("backends.enabled")
	if len(ids) == 0 {
		ids = backend.DefaultEnabled
	}
	return slices.Contains(ids, backend.RADIUS) && m.Installed()
}

// listenerApply is _radius_listener_apply: run a tacctl.yaml writer that
// changes listeners.radius through StoreApply (the listen{} blocks are part
// of the rendered config) with the restart deferred, restart, and require
// the unit to stay up; when it does not, tacctl.yaml and the artifacts go
// back and the unit is restarted on them. The error is ErrFailed (messages
// written) or StoreApply's, with everything as it was.
func (m *Module) listenerApply(ctx context.Context, writer func() error) error {
	out := m.env.Out
	keep, err := readKept(m.env.Paths.Overrides)
	if err != nil {
		out.Error("Cannot read " + m.env.Paths.Overrides + ": " + err.Error())
		return backend.ErrFailed
	}
	opts := backend.ApplyOptions{DeferRestart: []string{backend.RADIUS}}
	_, err = m.apply(ctx, opts, func() error {
		if err := writer(); err != nil {
			m.reportConfError(err)
			return err
		}
		return nil
	})
	if err != nil {
		if backend.Reported(err) {
			return err
		}
		return backend.ErrFailed
	}
	if !m.serving() {
		return nil
	}
	m.unitRestart(ctx)
	m.sleep(ctx, m.settle())
	if m.systemctl(ctx, true, "is-active", "--quiet", m.L.Unit) == 0 {
		return nil
	}
	out.Error(m.unitName() + " did not stay up with the new listener; putting the previous one back.")
	if _, err := m.apply(ctx, opts, func() error { return keep.restore(m.env.Paths.Overrides) }); err != nil {
		out.Warn("Could not put the previous listener back; fix listeners.radius in " + m.env.Paths.Overrides + " and run 'tacctl config render'.")
	}
	m.unitRestart(ctx)
	return backend.ErrFailed
}

// reportConfError prints a failed tacctl.yaml write as lib/conf.sh does.
func (m *Module) reportConfError(err error) {
	var pe *conf.ParseError
	var ve *conf.ValidationError
	switch {
	case errors.As(err, &pe):
		m.env.Out.ErrorLines(pe)
	case errors.As(err, &ve):
		_, _ = fmt.Fprintln(m.env.Out.Stderr, ve.Error())
	default:
		m.env.Out.Error(err.Error())
	}
}

// kept is tacctl.yaml as it was (the copy _radius_listener_apply keeps):
// its bytes, mode and owner, or that there was none.
type kept struct {
	exists   bool
	data     []byte
	mode     os.FileMode
	uid, gid int
}

func readKept(path string) (*kept, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &kept{}, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := &kept{exists: true, data: data, mode: st.Mode().Perm(), uid: -1, gid: -1}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		k.uid, k.gid = int(sys.Uid), int(sys.Gid)
	}
	return k, nil
}

// restore is _radius_overrides_put: tacctl.yaml becomes the kept copy
// again (absent: removed).
func (k *kept) restore(path string) error {
	if !k.exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tacctl-new.")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(k.data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(k.mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if k.uid >= 0 {
		_ = tmp.Chown(k.uid, k.gid)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
