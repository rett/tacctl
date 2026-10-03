package radius_test

import (
	"context"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/radius"
	"github.com/rett/tacctl/internal/conf"
)

// Ports of the listener tests of tests/integration/radius.bats and of
// tests/unit/render_radius.bats ("listeners: auth on udp :1812 ...").

func listenerLines(t *testing.T, r *renv) string {
	t.Helper()
	ls, err := r.m.Listeners().List()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Name + " " + l.Network + " " + l.Address + "\n")
	}
	return b.String()
}

// "listeners: auth on udp :1812 and acct on udp :1813 without anything
// written".
func TestListenersDefault(t *testing.T) {
	r := newEnv(t)
	if got := listenerLines(t, r); got != "auth udp :1812\nacct udp :1813\n" {
		t.Errorf("list: %q", got)
	}
	// A listener the operator wrote comes after the built-in ones; the
	// built-in one can be moved.
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	if err := r.env.Conf.SetJSON("listeners.radius.mgmt", `{"network": "udp", "address": "10.1.0.1:1900"}`); err != nil {
		t.Fatal(err)
	}
	if got := listenerLines(t, r); got != "auth udp :1812\nacct udp :1813\nmgmt udp 10.1.0.1:1900\n" {
		t.Errorf("list: %q", got)
	}
}

// "config listen --backend radius: shows both built-in listeners".
func TestListenersShow(t *testing.T) {
	r := newEnv(t)
	got, err := r.m.Listeners().Show(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	want := "  RADIUS listener 'auth' (auth): udp :1812   (built-in default)\n" +
		"  RADIUS listener 'acct' (acct): udp :1813   (built-in default)\n"
	if got != want {
		t.Errorf("show: %q", got)
	}
	if got, err := r.m.Listeners().Show(context.Background(), "acct"); err != nil || got != want[strings.Index(want, "  RADIUS listener 'acct'"):] {
		t.Errorf("show acct: %q %v", got, err)
	}
	// An override says where it is set.
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	if err := r.env.Conf.SetJSON("listeners.radius.auth", `{"network": "udp", "address": "10.1.1.1:11812", "role": "auth"}`); err != nil {
		t.Fatal(err)
	}
	got, _ = r.m.Listeners().Show(context.Background(), "auth")
	if got != "  RADIUS listener 'auth' (auth): udp 10.1.1.1:11812   (set in "+r.p.Overrides+")\n" {
		t.Errorf("show override: %q", got)
	}
	// An unknown name is an error, with how to create one.
	_, err = r.m.Listeners().Show(context.Background(), "nope")
	wantCode(t, err, 1)
	contains(t, r.out(), "No RADIUS listener 'nope'. Create it: tacctl config listen --backend radius --listener nope udp <address>")
}

// "config listen --backend radius: a change is written, rendered into a
// listen section, and the unit restarted".
func TestListenerSetRendersAndRestarts(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	ls := r.m.Listeners()
	if err := ls.Set(ctx, "auth", "udp", "10.1.1.1:11812"); err != nil {
		t.Fatalf("set: %v\n%s", err, r.stderr)
	}
	contains(t, r.out(), "RADIUS listener 'auth' changed to udp 10.1.1.1:11812.")
	conf := r.read(r.m.L.Conf)
	contains(t, conf, "\t# listeners.radius.auth\n\tlisten {\n\t\ttype = auth\n\t\tipaddr = 10.1.1.1\n\t\tport = 11812\n\t}\n")
	contains(t, r.read(r.p.Overrides), "10.1.1.1:11812")
	if r.restarts("freeradius.service") != 1 {
		t.Errorf("calls %v", r.calls())
	}
	if r.tac.Called("service restart") {
		t.Errorf("tacacs restarted: %v", r.tac.Calls())
	}
	// The message ends with an empty line, and the info lines are on stdout.
	if !strings.HasSuffix(r.stdout.String(), "\n\n") {
		t.Errorf("stdout %q", r.stdout.String())
	}
	if len(r.sleeps) != 1 || r.sleeps[0] != 0 {
		t.Errorf("settle waits: %v", r.sleeps)
	}

	// The accounting listener keeps its role when moved.
	if err := ls.Set(ctx, "acct", "udp", ":11813"); err != nil {
		t.Fatalf("set acct: %v\n%s", err, r.stderr)
	}
	conf = r.read(r.m.L.Conf)
	contains(t, conf, "\t# listeners.radius.acct\n\tlisten {\n\t\ttype = acct\n\t\tipaddr = *\n\t\tport = 11813\n\t}\n")

	// reset puts a built-in one back, and removes any other.
	r.reset()
	if err := ls.Reset(ctx, "auth"); err != nil {
		t.Fatalf("reset: %v\n%s", err, r.stderr)
	}
	contains(t, r.out(), "RADIUS listener 'auth' is back on its default.")
	r.reset()
	if err := ls.Set(ctx, "auth6", "udp6", "[::]:1812"); err != nil {
		t.Fatalf("set auth6: %v\n%s", err, r.stderr)
	}
	contains(t, r.out(), "RADIUS listener 'auth6' (auth) added on udp6 [::]:1812.")
	contains(t, r.out(), "A udp6 listener serves IPv6 clients only")
	if !strings.Contains(r.read(r.m.L.Conf), "ipv6addr = ::\n") {
		t.Errorf("no ipv6 listener:\n%s", r.read(r.m.L.Conf))
	}
	r.reset()
	if err := ls.Reset(ctx, "auth6"); err != nil {
		t.Fatalf("reset auth6: %v\n%s", err, r.stderr)
	}
	contains(t, r.out(), "RADIUS listener 'auth6' removed.")
	notContains(t, r.read(r.m.L.Conf), "ipv6addr = ::\n")
	r.noLeftovers()
}

// A new listener whose name starts with 'acct' is an accounting listener;
// asking for what is already there says so and changes nothing; reset of a
// listener on its default says so too.
func TestListenerRolesAndNoOps(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	ls := r.m.Listeners()
	if err := ls.Set(ctx, "acct2", "udp", ":1814"); err != nil {
		t.Fatalf("set: %v\n%s", err, r.stderr)
	}
	contains(t, r.out(), "RADIUS listener 'acct2' (acct) added on udp :1814.")
	contains(t, r.read(r.m.L.Conf), "\t# listeners.radius.acct2\n\tlisten {\n\t\ttype = acct\n")
	before := r.state()
	r.reset()
	if err := ls.Set(ctx, "acct2", "udp", ":1814"); err != nil {
		t.Fatal(err)
	}
	contains(t, r.out(), "RADIUS listener 'acct2' already on udp :1814.")
	if err := ls.Reset(ctx, "auth"); err != nil {
		t.Fatal(err)
	}
	contains(t, r.out(), "RADIUS listener 'auth' is already on its default (udp :1812).")
	if r.state() != before || len(r.calls()) != 0 {
		t.Errorf("a no-op changed something: %v", r.calls())
	}
}

// "config listen --backend radius: tcp, a taken port and a missing listener
// name are refused before anything is written".
func TestListenerRefusalsWriteNothing(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	ls := r.m.Listeners()
	before := r.state()
	for _, c := range []struct {
		name, net, addr, want string
	}{
		{"auth", "tcp", ":1812", "the RADIUS backend listens on udp or udp6"},
		{"auth", "udp", ":1813", "already used by listeners.radius.acct"},
		{"default", "udp", ":1900", "--listener auth"},
		{"auth", "udp", "", "Missing address. Example: tacctl config listen --backend radius --listener auth udp :1812"},
		{"auth", "udp", "nonsense", "Invalid udp address: 'nonsense'"},
		{"auth", "udp", "[::1]:1812", "Invalid udp address: '[::1]:1812'"},
	} {
		r.reset()
		err := ls.Set(ctx, c.name, c.net, c.addr)
		wantCode(t, err, 1)
		contains(t, r.out(), c.want)
		if r.stdout.Len() != 0 {
			t.Errorf("%v: refusal on stdout: %q", c, r.stdout)
		}
		if r.state() != before || len(r.calls()) != 0 {
			t.Errorf("%v changed something", c)
		}
	}
	// Reset: no name, an unknown listener.
	r.reset()
	wantCode(t, ls.Reset(ctx, "default"), 1)
	contains(t, r.out(), "Name the listener: --listener auth or --listener acct.")
	r.reset()
	wantCode(t, ls.Reset(ctx, "ghost"), 1)
	contains(t, r.out(), "No RADIUS listener 'ghost'.")
	if r.state() != before {
		t.Error("state changed")
	}
	r.noLeftovers()
}

// "config listen --backend radius: a daemon that does not stay up gets the
// previous listener back".
func TestListenerDaemonDoesNotStayUp(t *testing.T) {
	r := newEnv(t)
	r.up()
	before := r.state()
	r.setFailStart(true)
	err := r.m.Listeners().Set(context.Background(), "auth", "udp", "192.0.2.99:1812")
	wantCode(t, err, 1)
	contains(t, r.out(), "freeradius did not stay up with the new listener; putting the previous one back.")
	if r.state() != before {
		t.Errorf("state changed:\n%s\nwas\n%s", r.state(), before)
	}
	notContains(t, r.read(r.m.L.Conf), "192.0.2.99")
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift: %v", lines)
	}
	// The unit was restarted on the restored artifacts as well.
	if r.restarts("freeradius.service") != 2 {
		t.Errorf("restarts: %v", r.calls())
	}
	r.noLeftovers()
}

// A listener change while the backend is not enabled is written, nothing
// of RADIUS is rendered or restarted; while it is enabled but nothing of it
// is installed yet, the change renders the files (so there is a config, and
// the daemon is then restarted like any set-up one).
func TestListenerSetWhenNotServing(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("tacacs")
	if err := r.m.Listeners().Set(context.Background(), "auth", "udp", ":11812"); err != nil {
		t.Fatalf("set: %v\n%s", err, r.stderr)
	}
	contains(t, r.read(r.p.Overrides), ":11812")
	if r.called(`^systemctl restart`) || r.exists(r.m.L.Conf) || len(r.checks) != 0 {
		t.Errorf("a disabled backend was touched: %v", r.calls())
	}
}

// A tacctl.yaml that cannot be written to makes the setter fail with
// lib/conf.sh's message, and nothing is changed.
func TestListenerSetRefusedByUnparsableTacctlYaml(t *testing.T) {
	r := newEnv(t)
	r.up()
	writeFile(t, r.p.Overrides, "backends: [\n")
	r.env.Conf.Reload()
	before := r.state()
	err := r.m.Listeners().Set(context.Background(), "auth", "udp", ":11812")
	if err == nil {
		t.Fatal("accepted")
	}
	contains(t, r.stderr.String(), "tacctl.yaml: could not parse "+r.p.Overrides+": ")
	contains(t, r.stderr.String(), "Fix or remove the file ('tacctl config validate' checks it); nothing was written.")
	if r.state() != before {
		t.Error("state changed")
	}
}

// Without an Apply hook the module reaches StoreApply through a Set over the
// default registry with its own Env, which is what a production invocation
// has (the Env carries no Set): the listener setter works the same.
func TestListenerSetThroughTheDefaultRegistry(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	writeFile(t, r.p.Overrides, "backends:\n  enabled: [radius]\n")
	env := *r.env
	env.Conf = conf.Load(r.p.Overrides, backend.Default().IDs())
	env.Conf.Owner = nil
	m := radius.NewModule(&env, "debian")
	if m.Apply != nil {
		t.Fatal("NewModule set an Apply hook")
	}
	ctx := context.Background()
	if _, err := m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Listeners().Set(ctx, "acct", "udp", ":11813"); err != nil {
		t.Fatalf("set: %v\n%s", err, r.stderr)
	}
	contains(t, r.read(m.L.Conf), "\t\ttype = acct\n\t\tipaddr = *\n\t\tport = 11813\n")
	contains(t, r.read(r.p.Overrides), ":11813")
	if !r.run.Called("systemctl", "restart", "freeradius.service") {
		t.Errorf("calls %v", r.calls())
	}
}
