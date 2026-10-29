package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// installTacquito makes the TACACS+ backend installed, as a server that
// serves is.
func (hs *hostSandbox) installTacquito() {
	hs.write("bin/tacquito", "#!/bin/sh\n", 0o755)
	hs.write("systemd/tacquito.service", "[Unit]\n", 0o644)
}

// showRun runs args with systemctl is-active answering state ("" is the
// default answer of the sandbox: nothing).
func (hs *hostSandbox) showRun(state string, args ...string) {
	r := hs.runner()
	if state != "" {
		r.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte(state + "\n")})
	}
	hs.run(r, args...)
}

// 'server show' on a server with nothing recorded and no backend installed:
// every part says what it is, and nothing is written.
func TestServerShowNothingInstalled(t *testing.T) {
	hs := newHostSandbox(t)
	hs.showRun("", "server", "show")
	out := plain(hs.out.String())
	for _, want := range []string{
		"\nServer\n",
		"  Address:         (none — 'tacctl host enroll --local' records the address of this machine, or: tacctl server addresses add <ip>)\n",
		"  Name:            " + shortHostname() + "  (the host name; tacctl server name <label> sets one)\n",
		"  Default method:  tacplus  (for hosts enrolled without --method)\n",
		"  Metrics:         enabled, loopback only  (127.0.0.1:8080)\n",
		"Backends\n",
		"Listeners\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if hs.code != 0 || hs.err.String() != "" {
		t.Errorf("exit %d, stderr %q", hs.code, hs.err.String())
	}
	// tacquito is enabled but not installed: its listener is the setting's,
	// and no unit is asked
	rows := tableRows(out)
	if !containsRow(rows, "tacacs", "tacacs", "yes", "not", "installed") || !containsRow(rows, "radius", "radius", "no", "not", "installed") ||
		!containsRow(rows, "tacacs", "default", "tcp", ":49", "49", "-") {
		t.Errorf("tables:\n%s", out)
	}
	// a read: no start line
	if hasAuditPrefix(hs.sandbox.runner, "", "cmd start") {
		t.Error("show wrote a start line")
	}
}

// The recorded address, the default method, the metrics setting and the
// listeners with their ports and units are read from the settings and from
// systemd.
func TestServerShowSettingsAndListeners(t *testing.T) {
	hs := newHostSandbox(t)
	hs.installTacquito()
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	hs.run(nil, "host", "default-method", "radius")
	hs.run(nil, "server", "name", "core-1")
	hs.run(nil, "server", "metrics", "address", ":9090")
	hs.showRun("active", "server", "show")
	out := plain(hs.out.String())
	for _, want := range []string{
		"  Address:         203.0.113.9\n",
		"  Name:            core-1  (the setting server.name)\n",
		"  Default method:  radius  (for hosts enrolled without --method)\n",
		"  Metrics:         enabled, externally reachable  (:9090)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	rows := tableRows(out)
	if !containsRow(rows, "tacacs", "tacacs", "yes", "active") || !containsRow(rows, "radius", "radius", "no", "not", "installed") {
		t.Errorf("backends table:\n%s", out)
	}
	if !containsRow(rows, "tacacs", "default", "tcp", ":49", "49", "active") {
		t.Errorf("listeners table:\n%s", out)
	}
	hs.run(nil, "server", "metrics", "disable")
	hs.showRun("active", "server", "show")
	if got := plain(hs.out.String()); !strings.Contains(got, "  Metrics:         disabled  (127.0.0.1:0, a port no scraper can reach)\n") {
		t.Errorf("disabled:\n%s", got)
	}
}

// containsRow reports whether some row of a printed table holds cells as
// its first columns.
func containsRow(rows [][]string, cells ...string) bool {
	for _, r := range rows {
		if len(r) >= len(cells) && strings.Join(r[:len(cells)], "\x00") == strings.Join(cells, "\x00") {
			return true
		}
	}
	return false
}

// tableRows are the lines of out split on blanks.
func tableRows(out string) [][]string {
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			rows = append(rows, f)
		}
	}
	return rows
}

// --json is the same data as a document.
func TestServerShowJSON(t *testing.T) {
	hs := newHostSandbox(t)
	hs.installTacquito()
	hs.showRun("active", "server", "show", "--json")
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s%s", hs.code, hs.out.String(), hs.err.String())
	}
	var d serverShowJSON
	if err := json.Unmarshal(hs.out.Bytes(), &d); err != nil {
		t.Fatalf("%v\n%s", err, hs.out.String())
	}
	if d.Name.Value != shortHostname() || d.Name.Source != "host name" {
		t.Errorf("name %+v", d.Name)
	}
	if len(d.Addresses) != 0 || d.AddressSource != "" || d.DefaultMethod != "tacplus" ||
		d.Metrics.Address != "127.0.0.1:8080" || d.Metrics.State != "enabled" || d.Metrics.Reach != "loopback" {
		t.Errorf("document %+v", d)
	}
	if len(d.Backends) != 2 || d.Backends[0].ID != "tacacs" || !d.Backends[0].Enabled || !d.Backends[0].Installed || d.Backends[0].Service != "active" {
		t.Fatalf("backends %+v", d.Backends)
	}
	l := d.Backends[0].Listeners
	if len(l) != 1 || l[0] != (serverListenerRow{Name: "default", Network: "tcp", Address: ":49", Port: 49, Unit: "active"}) {
		t.Errorf("listeners %+v", l)
	}
	if d.Backends[1].ID != "radius" || d.Backends[1].Installed || d.Backends[1].Enabled || len(d.Backends[1].Listeners) != 0 {
		t.Errorf("radius %+v", d.Backends[1])
	}
	// the address of the setting, and the one of the registry before it
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	hs.showRun("active", "server", "show", "--json")
	if err := json.Unmarshal(hs.out.Bytes(), &d); err != nil || len(d.Addresses) != 1 || d.Addresses[0] != "203.0.113.9" || d.AddressSource != "setting" {
		t.Errorf("setting: %v %+v", err, d)
	}
}

// The registry's copy is shown, as 'server addresses' shows it, when the
// setting does not hold the address yet.
func TestServerShowRegistryCopy(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/linux-hosts", "authsrv|local||tacctl|192.0.2.10|\n", 0o600)
	hs.showRun("active", "server", "show")
	if got := plain(hs.out.String()); !strings.Contains(got, "  Address:         192.0.2.10  (this server's registry entry; the setting is written by the next 'host enroll --local')\n") {
		t.Errorf("registry copy:\n%s", got)
	}
	hs.showRun("active", "server", "show", "--json")
	var d serverShowJSON
	if err := json.Unmarshal(hs.out.Bytes(), &d); err != nil || len(d.Addresses) != 1 || d.AddressSource != "registry" {
		t.Errorf("json: %v %+v", err, d)
	}
}

// Arguments the verb does not take are refused with its usage.
func TestServerShowRefusals(t *testing.T) {
	hs := newHostSandbox(t)
	hs.showRun("active", "server", "show", "x")
	hs.expect(1, "", "Unknown argument: 'x'")
	hs.showRun("active", "server", "show", "--csv")
	hs.expect(1, "", "Unknown option: '--csv'")
	hs.showRun("active", "server")
	hs.expect(0, "show [--json]", "")
}
