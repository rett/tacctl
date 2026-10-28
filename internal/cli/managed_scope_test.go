package cli

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// programWord are the words of the outputs that hold 'tacctl' as the program
// (a command, a file, the console), not as the scope.
var programWord = regexp.MustCompile(`tacctl( [a-z]|[./-]|>)`)

// enrolLocal enrols this server and fails the test when it is refused.
func enrolLocal(t *testing.T, hs *hostSandbox, args ...string) {
	t.Helper()
	hs.run(nil, append([]string{"host", "enroll", "--local", "--name", "authsrv", "--build-on-host"}, args...)...)
	if hs.code != 0 {
		t.Fatalf("enroll --local: %d\n%s%s", hs.code, hs.out.String(), hs.err.String())
	}
}

// A fresh 'host enroll --local' makes the managed scope (the login addresses,
// a secret of its own) and registers the server in it; every user is in it
// for the rendered TACACS+ file and the server's accounts, with nothing
// written to the users' own scopes; the setting holds the address.
func TestManagedScopeFreshEnrol(t *testing.T) {
	hs := newHostSandbox(t)
	before := hs.store()
	enrolLocal(t, hs)
	if out := plain(hs.out.String()); !strings.Contains(out, "Using 192.0.2.10 as the server address (the address of eth0); pass --server to use another.") {
		t.Errorf("no detection line:\n%s", out)
	}
	if got := hs.registry(); got != "authsrv|local||tacctl|192.0.2.10|\n" {
		t.Errorf("registry %q", got)
	}
	st := hs.store()
	if !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]\n    secret: ") {
		t.Errorf("store:\n%s", st)
	}
	// the users' own scopes are as they were
	for _, u := range []string{"scopes: [prod, lab]", "scopes: [lab, dmz]"} {
		if strings.Contains(before, u) && !strings.Contains(st, u) {
			t.Errorf("a user's scopes changed (%s):\n%s", u, st)
		}
	}
	if users := strings.SplitN(strings.SplitN(st, "\nusers:", 2)[1], "\nscopes:", 2)[0]; strings.Contains(users, "tacctl") {
		t.Errorf("a user has the managed scope in the store:\n%s", st)
	}
	if got := hs.read("state/tacctl.yaml"); !strings.Contains(got, "server:\n  addresses:\n  - 192.0.2.10\n") {
		t.Errorf("tacctl.yaml:\n%s", got)
	}
	hs.run(nil, "config", "get-list", "server.addresses")
	if hs.code != 0 || hs.out.String() != "192.0.2.10\n" {
		t.Errorf("config get: %d %q %q", hs.code, hs.out.String(), hs.err.String())
	}
	hs.run(nil, "config", "validate")
	if out := plain(hs.out.String() + hs.err.String()); strings.Contains(out, "server.addresses") || strings.Contains(out, "tacctl'") {
		t.Errorf("config validate:\n%s", out)
	}
	r := hs.read("etc/tacquito.yaml")
	for _, u := range []string{"alice", "bob", "carol"} {
		i := strings.Index(r, "- name: "+u+"\n")
		if i < 0 || !strings.Contains(r[i:i+200], `"tacctl"`) {
			t.Errorf("%s is not in the managed scope of the rendered file:\n%s", u, r)
		}
	}
	// the recorded address wins over the detection, which is not asked
	hs.serverAddress = func() (string, string, error) { return "", "", errors.New("not asked") }
	enrolLocal(t, hs)
	if strings.Contains(hs.out.String(), "Using ") || hs.registry() != "authsrv|local||tacctl|192.0.2.10|\n" {
		t.Errorf("recorded address: %q %q", hs.out.String(), hs.registry())
	}
}

// --server is an IP address devices and hosts reach the server at: one that
// is not on this machine (NAT) is taken, a name, the unspecified, loopback
// and link-local addresses are not; --scope is not taken with --local; no
// address to detect is a refusal that names --server.
func TestManagedScopeServerAddress(t *testing.T) {
	hs := newHostSandbox(t)
	for _, bad := range []string{"authsrv.example.net", "0.0.0.0", "::", "127.0.0.1", "::1", "169.254.1.1", "fe80::1"} {
		hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--server", bad, "--build-on-host")
		hs.expect(1, "", "--server '"+bad+"' ")
		if hs.registry() != "" {
			t.Fatalf("%s: registered", bad)
		}
	}
	hs.run(nil, "host", "enroll", "--local", "--scope", "lab")
	hs.expect(1, "", "--local takes no --scope: tacctl sets up this server's own login itself.")
	hs.serverAddress = func() (string, string, error) { return "", "", errors.New("none") }
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	hs.expect(1, "", "No address of this machine can be the server address: give --server <address>. Nothing was changed.")
	// an address behind NAT, not on this machine
	enrolLocal(t, hs, "--server", "203.0.113.9")
	if got := hs.registry(); got != "authsrv|local||tacctl|203.0.113.9|\n" || !strings.Contains(hs.store(), "prefixes: [127.0.0.1/32, 203.0.113.9/32]") {
		t.Errorf("registry %q store\n%s", got, hs.store())
	}
	// and another one moves the prefixes and the setting in the same run
	enrolLocal(t, hs, "--server", "198.51.100.20")
	if !strings.Contains(hs.store(), "prefixes: [127.0.0.1/32, 198.51.100.20/32]") || !strings.Contains(hs.read("state/tacctl.yaml"), "- 198.51.100.20\n") ||
		!strings.Contains(plain(hs.out.String()), "Repaired the managed server login.") {
		t.Errorf("store\n%s\n%s", hs.store(), hs.out.String())
	}
}

// An install from before: the server registered in a scope that serves it
// alone is taken over by the next sync of the server (renamed, its secret
// kept, the users' stored scopes renamed with it), in one line.
func TestManagedScopeAdoptsADedicatedScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "add", "srv", "--prefixes", "127.0.0.1/32", "--secret", "srv-secret-0123456789abcdef")
	hs.run(nil, "user", "scope", "bob", "add", "srv")
	hs.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1|\n", 0o600)
	hs.run(nil, "host", "sync", "authsrv")
	if hs.code != 0 {
		t.Fatalf("sync: %d %s", hs.code, hs.err.String())
	}
	if out := plain(hs.out.String()); !strings.Contains(out, "Scope 'srv' served this server's own login only: tacctl manages it from now on, with its secret kept.") {
		t.Errorf("no adoption line:\n%s", out)
	}
	st := hs.store()
	if !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32]\n    secret: srv-secret-0123456789abcdef") || strings.Contains(st, "\n  srv:") {
		t.Errorf("store:\n%s", st)
	}
	if got := hs.registry(); !strings.HasPrefix(got, "authsrv|local|22|tacctl|") {
		t.Errorf("registry %q", got)
	}
	// bob's stored copy is renamed with the scope, and hidden
	hs.run(nil, "user", "show", "bob")
	if out := plain(hs.out.String()); strings.Contains(out, "tacctl") {
		t.Errorf("user show names the managed scope:\n%s", out)
	}
	// it goes at bob's next change, and only bob's
	carol := strings.Contains(st, "carol")
	hs.run(nil, "user", "disable", "bob")
	if st := hs.store(); strings.Contains(userBlock(st, "bob"), "tacctl") || !carol {
		t.Errorf("bob's stored copy stays:\n%s", userBlock(st, "bob"))
	}
}

// userBlock is the store text of one user: its line and the deeper ones.
func userBlock(st, name string) string {
	var out []string
	in := false
	for _, l := range strings.Split(st, "\n") {
		switch {
		case l == "  "+name+":":
			in = true
		case in && !strings.HasPrefix(l, "    "):
			return strings.Join(out, "\n")
		}
		if in {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// An install from before whose server scope also serves devices: the sync
// leaves it and names the enrolment, which gives the server a new scope and
// leaves the old one to the devices (without the server's own prefix).
func TestManagedScopeLeavesASharedScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.loopback()
	hs.write("state/linux-hosts", "authsrv|local|22|lab|127.0.0.1|\n", 0o600)
	hs.run(nil, "host", "sync", "authsrv")
	if out := plain(hs.out.String()); !strings.Contains(out, "authsrv: to set up this server's own login for every user: tacctl host enroll --local") {
		t.Errorf("sync:\n%s", out)
	}
	if hs.registry() != "authsrv|local|22|lab|127.0.0.1|\n" || strings.Contains(hs.store(), "tacctl:") {
		t.Fatalf("the sync changed the registration: %q", hs.registry())
	}
	lab := hs.store()
	enrolLocal(t, hs)
	if out := plain(hs.out.String()); !strings.Contains(out, "Scope 'lab' also serves prefix 172.16.0.0/12, prefix 192.168.0.0/16 and stays for them; this server's own login gets its own, set up by this enrolment.") {
		t.Errorf("enrol:\n%s", out)
	}
	st := hs.store()
	if !strings.Contains(st, "lab:\n    prefixes: [172.16.0.0/12, 192.168.0.0/16]") || !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]") ||
		strings.Contains(st, "secret: lab-secret-0123456789abcdef") != strings.Contains(lab, "secret: lab-secret-0123456789abcdef") {
		t.Errorf("store:\n%s", st)
	}
}

// A scope of the operator's that has the reserved name is not taken over.
func TestManagedScopeNameClash(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/store.yaml", strings.Replace(hs.store(), "  dmz:\n", "  tacctl:\n    prefixes: [198.51.100.0/24]\n    secret: tacctl-secret-0123456789abcdef\n  dmz:\n", 1), 0o600)
	before := hs.store()
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	hs.expect(1, "", "Scope 'tacctl' is reserved. Rename the scope of that name first: tacctl scope rename tacctl <new-name>. Nothing was changed.")
	if hs.store() != before || hs.registry() != "" {
		t.Error("changed")
	}
	// it is the operator's: it is listed, and can be renamed
	hs.run(nil, "scope", "list")
	hs.expect(0, "tacctl", "")
	hs.run(nil, "scope", "rename", "tacctl", "other")
	hs.expect(0, "Scope renamed: tacctl -> other", "")
	enrolLocal(t, hs)
}

// Every verb that names the managed scope is refused while the server is in
// it, and nobody makes a scope of that name.
func TestManagedScopeReservedName(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "add", "tacctl", "--prefixes", "198.51.100.0/24")
	hs.expect(1, "", "Scope 'tacctl' is reserved. Pick another name. Nothing was changed.")
	hs.run(nil, "scope", "rename", "lab", "tacctl")
	hs.expect(1, "", "Scope 'tacctl' is reserved. Pick another name.")
	enrolLocal(t, hs)
	before := hs.store()
	for _, args := range [][]string{
		{"scope", "show", "tacctl"}, {"scope", "remove", "tacctl"}, {"scope", "rename", "tacctl", "other"},
		{"scope", "prefixes", "tacctl", "add", "198.51.100.0/24"}, {"scope", "prefixes", "lab", "move", "192.168.0.0/16", "tacctl"},
		{"scope", "secret", "tacctl", "show"}, {"scope", "protocols", "tacctl", "set", "tacacs"},
		{"scope", "mgmt-acl", "tacctl", "list"}, {"scope", "breakglass", "tacctl", "list"},
		{"user", "scope", "bob", "add", "tacctl"}, {"user", "scope", "bob", "replace", "lab,tacctl"},
		{"user", "add", "dave", "operator", "--hash", testHash, "--scopes", "tacctl"},
		{"host", "enroll", "admin@web1.example.net", "--scope", "tacctl", "--build-on-host"},
	} {
		hs.run(nil, args...)
		hs.expect(1, "", "Scope 'tacctl' is reserved.")
		if hs.store() != before {
			t.Errorf("%v changed the store", args)
		}
	}
}

// No listing names the managed scope while the server is in it: the scopes,
// the routing, the users and their scopes, the completion of scope names, the
// status counts and the host list.
func TestManagedScopeIsHidden(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs)
	for _, args := range [][]string{
		{"scope", "list"}, {"scope", "routing"}, {"user", "list"}, {"user", "show", "bob"}, {"user", "scope", "bob", "list"},
		{"_completion-names", "scopes"}, {"status"}, {"host", "list"}, {"host", "show", "authsrv"},
	} {
		hs.run(nil, args...)
		if out := programWord.ReplaceAllString(plain(hs.out.String()), ""); regexp.MustCompile(`\btacctl\b`).MatchString(out) {
			t.Errorf("%v names the managed scope:\n%s", args, out)
		}
	}
	hs.run(nil, "_completion-names", "scopes")
	if got := hs.out.String(); got != "dmz\nlab\nprod\nprod-inner\n" {
		t.Errorf("completion %q", got)
	}
	// a user whose scopes are all gone still logs in to the server: the
	// listing does not alarm in red
	hs.stdin = "y\n"
	hs.run(nil, "user", "scope", "carol", "remove", "--all")
	hs.stdin = ""
	hs.run(nil, "user", "show", "carol")
	if out := hs.out.String(); !strings.Contains(out, "(none — cannot authenticate on any device)") || strings.Contains(out, "\x1b[0;31m(none") {
		t.Errorf("user show carol:\n%q", out)
	}
}

// Unenrolling the server takes the managed scope with it.
func TestManagedScopeGoesWithTheRegistration(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs)
	hs.run(nil, "host", "forget", "authsrv", "--yes")
	hs.expect(0, "Host 'authsrv' forgotten.", "")
	if strings.Contains(hs.store(), "tacctl:") || hs.registry() != "" {
		t.Errorf("store\n%s", hs.store())
	}
}

// A scope whose only prefixes are the server's login addresses would be left
// with none when the managed scope takes them: the enrolment says which scope
// and what to do, and changes nothing.
func TestManagedScopeRefusesToEmptyAScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "add", "srvlab", "--prefixes", "192.0.2.10/32,127.0.0.1/32", "--secret", "srvlab-secret-0123456789abcdef")
	hs.expect(0, "", "")
	before := hs.store()
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--server", "192.0.2.10", "--build-on-host")
	hs.expect(1, "", "Scope 'srvlab' has no prefix but the addresses of this server's own login (127.0.0.1/32, 192.0.2.10/32), which the managed scope takes.")
	if !strings.Contains(plain(hs.err.String()), "tacctl scope prefixes srvlab add <cidr>") || hs.store() != before || hs.registry() != "" {
		t.Errorf("changed or no way out:\n%s", hs.err.String())
	}
	// with another prefix it goes through, and the scope keeps it
	hs.run(nil, "scope", "prefixes", "srvlab", "add", "198.51.100.0/24")
	enrolLocal(t, hs, "--server", "192.0.2.10")
	if st := hs.store(); !strings.Contains(st, "srvlab:\n    prefixes: [198.51.100.0/24]") {
		t.Errorf("store:\n%s", st)
	}
}
