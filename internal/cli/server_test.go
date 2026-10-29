package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

const serverFollowUpLine = "[INFO] Re-point the devices and hosts at the new address: tacctl host sync --all; the device walkthroughs name the new address\n"

// serverState is what a change of the address writes: the setting, the
// registry, the store (the managed scope's prefixes).
func (hs *hostSandbox) serverState() string {
	data, _ := os.ReadFile(hs.path("state", "tacctl.yaml"))
	return string(data) + "\n--\n" + hs.registry() + "\n--\n" + hs.store()
}

// 'server addresses' shows the recorded address, from the setting, else from
// this server's registry entry.
func TestServerAddressesList(t *testing.T) {
	hs := newHostSandbox(t)
	for _, args := range [][]string{{"server", "addresses"}, {"server", "addresses", "list"}} {
		hs.run(nil, args...)
		hs.expect(0, "  (none — 'tacctl host enroll --local' records the address of this machine, or: tacctl server addresses add <ip>)", "")
	}
	hs.write("state/linux-hosts", "authsrv|local||tacctl|192.0.2.10|\n", 0o600)
	hs.run(nil, "server", "addresses")
	hs.expect(0, "  - 192.0.2.10  (this server's registry entry; the setting is written by the next 'host enroll --local')", "")
	enrolLocal(t, hs, "--server", "203.0.113.9")
	hs.run(nil, "server", "addresses", "list")
	if got := plain(hs.out.String()); !strings.Contains(got, "Server addresses\n") || !strings.Contains(got, "\n  - 203.0.113.9\n") || strings.Contains(got, "registry entry") {
		t.Errorf("list:\n%s", got)
	}
	hs.run(nil, "server")
	hs.expect(0, "Usage: tacctl server <subcommand>", "")
	hs.run(nil, "server", "bogus")
	hs.expect(1, "", "[ERROR] Unknown subcommand: 'bogus'")
	if hs.out.Len() != 0 {
		t.Errorf("an unknown sub-command printed the usage: %q", hs.out.String())
	}
	hs.run(nil, "server", "addresses", "bogus")
	hs.expect(1, "", "Unknown subcommand: 'bogus'")
	hs.run(nil, "server", "addresses", "list", "x")
	hs.expect(1, "", "Usage: tacctl server addresses [list|add")
	// a read: no start line
	if hasAuditPrefix(hs.sandbox.runner, "", "cmd start") {
		t.Error("list wrote a start line")
	}
}

// With no login set up only the setting changes, after a snapshot, and the
// address is the one the enrolment then reads.
func TestServerAddressesAddWithNoLogin(t *testing.T) {
	hs := newHostSandbox(t)
	snaps := hs.snapshots()
	hs.run(nil, "server", "addresses", "add", "192.0.2.10")
	out := plain(hs.out.String())
	if hs.code != 0 || strings.Count(out, serverFollowUpLine) != 1 || !strings.Contains(out, "This machine's own login is not set up") {
		t.Fatalf("exit %d\n%s%s", hs.code, out, hs.err.String())
	}
	if got := hs.read("state/tacctl.yaml"); !strings.Contains(got, "server:\n  addresses:\n  - 192.0.2.10\n") || hs.registry() != "" {
		t.Errorf("tacctl.yaml:\n%s\nregistry %q", got, hs.registry())
	}
	if hs.snapshots() <= snaps {
		t.Error("no snapshot")
	}
	// the enrolment then takes it as the recorded address, with no detection
	hs.serverAddress = func() (string, string, error) { return "", "", os.ErrInvalid }
	enrolLocal(t, hs)
	if strings.Contains(hs.out.String(), "Using ") || !strings.Contains(hs.registry(), "|tacctl|192.0.2.10|") {
		t.Errorf("enrol: %q %q", hs.out.String(), hs.registry())
	}
}

// One address in this release: add while one is set, and remove of the only
// one, are refused with their words; a csv of more than one is refused as the
// setting refuses it; nothing is written by a refusal.
func TestServerAddressesTheOneAddressLimit(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs, "--server", "192.0.2.10")
	before := hs.serverState()
	for _, c := range []struct {
		args []string
		code int
		out  string
		err  string
	}{
		{[]string{"add", "198.51.100.7"}, 1, "", "only one server address is supported yet; use replace. Nothing was changed."},
		{[]string{"remove", "192.0.2.10"}, 1, "", "the server needs an address; use replace. Nothing was changed."},
		{[]string{"add", "198.51.100.7,198.51.100.8"}, 1, "", "only one server address is supported yet. Nothing was changed."},
		{[]string{"replace", "198.51.100.7,198.51.100.8"}, 1, "", "only one server address is supported yet. Nothing was changed."},
		{[]string{"remove", "192.0.2.10,198.51.100.8"}, 1, "", "only one server address is supported yet. Nothing was changed."},
		{[]string{"replace", "web1.example.net"}, 1, "", "'web1.example.net' is not an IP address (a host name is not taken). Nothing was changed."},
		{[]string{"replace", "127.0.0.1"}, 1, "", "'127.0.0.1' is a loopback address"},
		{[]string{"replace", "0.0.0.0"}, 1, "", "'0.0.0.0' is the unspecified address"},
		{[]string{"add", "169.254.1.1"}, 1, "", "'169.254.1.1' is a link-local or multicast address"},
		{[]string{"add"}, 1, "", "Usage: tacctl server addresses add <ip>[,<ip>...]"},
		{[]string{"remove"}, 1, "", "Usage: tacctl server addresses remove <ip>[,<ip>...]"},
		{[]string{"replace", " , "}, 1, "", "No server address given. Nothing was changed."},
		// the same address again, and an address that is not there: no change, no error
		{[]string{"add", "192.0.2.10"}, 0, "No new address (already present: 192.0.2.10).", ""},
		{[]string{"remove", "198.51.100.7"}, 0, "Nothing to remove (not present: 198.51.100.7).", ""},
		{[]string{"replace", "192.0.2.10"}, 0, "The server address is 192.0.2.10 already. Nothing was changed.", ""},
		{[]string{"replace", "192.0.2.10,192.0.2.10"}, 0, "The server address is 192.0.2.10 already.", ""},
	} {
		r := hs.runner()
		hs.run(r, append([]string{"server", "addresses"}, c.args...)...)
		hs.expect(c.code, c.out, c.err)
		if r.Called("bash") || hs.serverState() != before || strings.Contains(hs.out.String()+hs.err.String(), "Re-point") {
			t.Errorf("%v: changed or ran\n%s%s", c.args, hs.out.String(), hs.err.String())
		}
	}
}

// replace moves the setting, the registry copy, the managed scope's prefixes
// and the server's own login in one run, after one snapshot, and says what is
// left to do once. 'host enroll --local --server' with another address is the
// same change.
func TestServerAddressesReplaceMovesEverything(t *testing.T) {
	for _, via := range []string{"server addresses replace", "host enroll --local --server"} {
		t.Run(via, func(t *testing.T) {
			hs := newHostSandbox(t)
			enrolLocal(t, hs, "--server", "192.0.2.10")
			snaps := hs.snapshots()
			r := hs.runner()
			if via == "server addresses replace" {
				hs.run(r, "server", "addresses", "replace", "198.51.100.7")
			} else {
				hs.run(r, "host", "enroll", "--local", "--name", "authsrv", "--server", "198.51.100.7", "--build-on-host")
			}
			out := plain(hs.out.String())
			if hs.code != 0 || !r.Called("bash") || strings.Count(out, serverFollowUpLine) != 1 || !strings.Contains(out, "Repaired the managed server login.") {
				t.Fatalf("exit %d, ran %v\n%s%s", hs.code, r.Called("bash"), out, hs.err.String())
			}
			if got := hs.registry(); got != "authsrv|local||tacctl|198.51.100.7|\n" {
				t.Errorf("registry %q", got)
			}
			if st := hs.store(); !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 198.51.100.7/32]") {
				t.Errorf("store:\n%s", st)
			}
			if got := hs.read("state/tacctl.yaml"); !strings.Contains(got, "- 198.51.100.7\n") || strings.Contains(got, "192.0.2.10") {
				t.Errorf("tacctl.yaml:\n%s", got)
			}
			if hs.snapshots() <= snaps {
				t.Error("no snapshot")
			}
			hs.run(nil, "server", "addresses")
			hs.expect(0, "  - 198.51.100.7\n", "")
			// the same address again is no change and no follow-up
			hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--server", "198.51.100.7", "--build-on-host")
			if hs.code != 0 || strings.Contains(plain(hs.out.String()), "Re-point") {
				t.Errorf("again: exit %d\n%s", hs.code, hs.out.String())
			}
		})
	}
}

// add sets the address when the list is empty, with a login set up too (the
// setting was cleared by hand): the same change as replace.
func TestServerAddressesAddAfterTheSettingIsGone(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs, "--server", "192.0.2.10")
	hs.write("state/tacctl.yaml", "", 0o600)
	hs.run(nil, "server", "addresses", "add", "198.51.100.7")
	out := plain(hs.out.String())
	if hs.code != 0 || strings.Count(out, serverFollowUpLine) != 1 || !strings.Contains(hs.registry(), "|tacctl|198.51.100.7|") ||
		!strings.Contains(hs.read("state/tacctl.yaml"), "- 198.51.100.7\n") {
		t.Fatalf("exit %d\n%s%s\nregistry %q", hs.code, out, hs.err.String(), hs.registry())
	}
}

// A failure of the server's own setup leaves nothing half applied: the
// setting, the registry entry and the managed scope are as they were, and
// no follow-up is printed.
func TestServerAddressesReplaceFailureLeavesEverything(t *testing.T) {
	for _, via := range []string{"server addresses replace", "host enroll --local --server"} {
		t.Run(via, func(t *testing.T) {
			hs := newHostSandbox(t)
			enrolLocal(t, hs, "--server", "192.0.2.10")
			before := hs.serverState()
			r := hs.runner()
			r.On([]string{"bash"}, execx.Result{Code: 1})
			if via == "server addresses replace" {
				hs.run(r, "server", "addresses", "replace", "198.51.100.7")
			} else {
				hs.run(r, "host", "enroll", "--local", "--name", "authsrv", "--server", "198.51.100.7", "--build-on-host")
			}
			if hs.code != 1 || hs.serverState() != before || strings.Contains(hs.out.String()+hs.err.String(), "Re-point") {
				t.Errorf("exit %d, changed: %v\n%s%s", hs.code, hs.serverState() != before, hs.out.String(), hs.err.String())
			}
		})
	}
}

// The audit lines: the pair of the command for a change, nothing for the list.
func TestServerAddressesAudit(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs, "--server", "192.0.2.10")
	r := hs.runner()
	hs.run(r, "server", "addresses", "list")
	if hasAuditPrefix(r, "", "cmd start") {
		t.Error("list wrote a start line")
	}
	r = hs.runner()
	hs.run(r, "server", "addresses", "replace", "198.51.100.7")
	lines := auditLines(r)
	var start, end, own bool
	for _, l := range lines {
		start = start || strings.Contains(l, "cmd start") && strings.Contains(l, `cmd="server addresses"`)
		end = end || strings.Contains(l, "cmd end") && strings.Contains(l, "result=ok")
		own = own || strings.Contains(l, "server addresses op=replace address=198.51.100.7")
	}
	if !start || !end || !own {
		t.Errorf("start %v end %v own %v:\n%s", start, end, own, strings.Join(lines, "\n"))
	}
}

// The verb is the superuser's whole (the tier table has no row for it, as for
// 'scope prefixes'): no sudoers line is granted, so the drop-in is as 0.2.20
// wrote it and a rollback has nothing to take out.
func TestServerIsTheSuperusersAlone(t *testing.T) {
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		for _, sub := range []string{"", "addresses", "list", "show"} {
			if tier.Permits(tr, "server", sub) {
				t.Errorf("%s may run 'server %s'", tr, sub)
			}
		}
	}
	for _, r := range tier.Rules {
		if r.Cmd == "server" {
			t.Errorf("the tier table has a row for server: %+v", r)
		}
	}
	if !tier.Permits(tier.Superuser, "server", "addresses") {
		t.Error("the superuser may not run it")
	}
}
