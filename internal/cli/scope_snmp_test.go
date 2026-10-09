package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/snmp"
)

// 'scope snmp' (D41, D46 of docs/plans/0.2.3-plan.md) on the sandbox of
// native_test.go. The bats file config_snmp.bats pins the command lines.

// scopeSNMP runs 'tacctl scope snmp <args>' as the superuser.
// said checks the exit status and that msg was printed, on either stream
// (an info line is on stdout, an error on stderr).
func (sb *sandbox) said(code int, msg string) {
	sb.t.Helper()
	if all := plain(sb.out.String()) + plain(sb.err.String()); sb.code != code || !strings.Contains(all, msg) {
		sb.t.Errorf("exit %d (want %d), want %q in:\n%s", sb.code, code, msg, all)
	}
}

func (sb *sandbox) scopeSNMP(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"scope", "snmp"}, args...), nil))
}

func TestScopeSNMPSettingsAndSecrets(t *testing.T) {
	sb := newSandbox(t, true)
	const secret = "scope-community-9"
	// Reading changes nothing on disk.
	out := sb.scopeSNMP("", "lab", "show")
	for _, want := range []string{"SNMP for scope 'lab'", "version:    not set", "port:       161  (built-in)", "timeout:    2 s, one retry  (built-in)",
		"community:  not set", "contact:    not set", "the scope lists no ranges: only the tacctl server may query"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	if sb.overrides() != "" {
		t.Errorf("a read wrote tacctl.yaml:\n%s", sb.overrides())
	}
	// The community: a file of its own (0600, in a 0700 directory), the
	// version in tacctl.yaml.
	sb.scopeSNMP(secret+"\n", "lab", "community", "--stdin")
	sb.said(0, "SNMP community of scope 'lab' set")
	if fi, err := os.Stat(sb.path("state", "snmp", "lab.yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lab.yaml: %v %v", fi, err)
	}
	if fi, err := os.Stat(sb.path("state", "snmp")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v %v", fi, err)
	}
	if _, err := os.Stat(sb.path("state", "snmp.yaml")); !os.IsNotExist(err) {
		t.Errorf("the default file was written: %v", err)
	}
	if o := sb.overrides(); !strings.Contains(o, "snmp_scope") || !strings.Contains(o, "version: v2c") || strings.Contains(o, secret) {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	// Plain show never prints it; --reveal does, labelled.
	out = sb.scopeSNMP("", "lab", "show")
	if strings.Contains(out, secret) || !strings.Contains(out, "version:    v2c (the community)  (scope)") || !strings.Contains(out, "community:  set  (scope)") {
		t.Errorf("show:\n%s", out)
	}
	out = sb.scopeSNMP("", "lab", "show", "--reveal")
	if !strings.Contains(out, "community:  "+secret+"  (scope)") {
		t.Errorf("show --reveal:\n%s", out)
	}
	// Another scope is untouched and inherits the default (here: nothing).
	if out = sb.scopeSNMP("", "prod", "show"); !strings.Contains(out, "version:    not set") {
		t.Errorf("prod:\n%s", out)
	}
	// The default beneath: a scope that sets nothing inherits, and says so.
	sb.cfgRun("def-community-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.cfgRun("", []string{"config", "snmp", "port", "1161"}, nil)
	out = sb.scopeSNMP("", "prod", "show", "--reveal")
	for _, want := range []string{"version:    v2c (the community)  (default)", "port:       1161  (default)", "community:  def-community-1  (default)"} {
		if !strings.Contains(out, want) {
			t.Errorf("prod inherits: lacks %q:\n%s", want, out)
		}
	}
	// The scope's own value wins over the default's, per setting.
	out = sb.scopeSNMP("", "lab", "show", "--reveal")
	if !strings.Contains(out, "community:  "+secret+"  (scope)") || !strings.Contains(out, "port:       1161  (default)") {
		t.Errorf("lab over default:\n%s", out)
	}
	sb.scopeSNMP("", "lab", "port", "2161")
	sb.scopeSNMP("", "lab", "timeout", "4")
	if out = sb.scopeSNMP("", "lab", "port"); !strings.Contains(out, "2161  (scope)") {
		t.Errorf("port: %q", out)
	}
	if out = sb.scopeSNMP("", "lab", "timeout"); !strings.Contains(out, "4  (scope)") {
		t.Errorf("timeout: %q", out)
	}
	sb.scopeSNMP("", "lab", "port", "0")
	sb.said(1, "Invalid UDP port '0': expected 1-65535.")
	sb.scopeSNMP("", "lab", "timeout", "11")
	sb.said(1, "Invalid timeout '11': expected 1-10.")
	// The default's own show does not show the scope's.
	out = plain(sb.cfgRun("", []string{"config", "snmp", "show", "--reveal"}, nil))
	if !strings.Contains(out, "def-community-1") || strings.Contains(out, secret) {
		t.Errorf("config snmp show --reveal:\n%s", out)
	}
	out = plain(sb.cfgRun("", []string{"config", "snmp", "show"}, nil))
	if strings.Contains(out, "def-community-1") || !strings.Contains(out, "community:  set") {
		t.Errorf("config snmp show:\n%s", out)
	}
	// clear: the scope's file and keys go; the default stays.
	sb.scopeSNMP("", "lab", "clear")
	sb.said(0, "removed: the default applies again")
	if _, err := os.Stat(sb.path("state", "snmp", "lab.yaml")); !os.IsNotExist(err) {
		t.Errorf("lab.yaml left: %v", err)
	}
	if _, err := os.Stat(sb.path("state", "snmp")); !os.IsNotExist(err) {
		t.Errorf("empty directory left: %v", err)
	}
	if strings.Contains(sb.overrides(), "snmp_scope") {
		t.Errorf("keys left:\n%s", sb.overrides())
	}
	if _, err := os.Stat(sb.path("state", "snmp.yaml")); err != nil {
		t.Errorf("the default was cleared: %v", err)
	}
	sb.scopeSNMP("", "lab", "clear")
	sb.said(0, "no SNMP settings of its own")
}

func TestScopeSNMPV3(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("auth-pass-1\npriv-pass-1\n", "lab", "v3-user", "alice", "--auth", "sha256", "--stdin")
	sb.said(0, "SNMPv3 user and passphrases of scope 'lab' set")
	o := sb.overrides()
	for _, want := range []string{"version: v3", "sha256"} {
		if !strings.Contains(o, want) {
			t.Errorf("tacctl.yaml lacks %q:\n%s", want, o)
		}
	}
	if strings.Contains(o, "auth-pass-1") || strings.Contains(o, "alice") {
		t.Errorf("a credential in tacctl.yaml:\n%s", o)
	}
	out := sb.scopeSNMP("", "lab", "show")
	if strings.Contains(out, "alice") && !strings.Contains(out, "v3 user:    alice") || strings.Contains(out, "auth-pass-1") {
		t.Errorf("show:\n%s", out)
	}
	out = sb.scopeSNMP("", "lab", "show", "--reveal")
	for _, want := range []string{"v3 user:    alice  (scope)", "auth auth-pass-1, priv priv-pass-1  (scope)", "v3 auth:    sha256  (scope); priv: aes128  (built-in)"} {
		if !strings.Contains(out, want) {
			t.Errorf("reveal lacks %q:\n%s", want, out)
		}
	}
	for _, c := range []struct {
		stdin string
		args  []string
		err   string
	}{
		{"short\nshort\n", []string{"v3-user", "alice", "--stdin"}, "at least 8 characters"},
		{"", []string{"v3-user", "alice", "--auth", "md5", "--stdin"}, "Unknown --auth 'md5': sha or sha256."},
		{"", []string{"v3-user", "bad name", "--stdin"}, "Invalid SNMPv3 user 'bad name'"},
		{"", []string{"v3-user", "--stdin"}, "Usage: tacctl scope snmp lab v3-user <user>"},
		{"", []string{"version", "v1"}, "Unknown version 'v1': v2c or v3."},
		{"", []string{"frob"}, "Unknown subcommand: 'frob'"},
		{"", []string{"show", "--bogus"}, "Unknown option: '--bogus'"},
		{"", []string{"community"}, "No terminal to ask for the community on"},
	} {
		sb.scopeSNMP(c.stdin, append([]string{"lab"}, c.args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr()+plain(sb.out.String()), c.err) {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	sb.scopeSNMP("", "nosuch", "show")
	sb.said(1, "Scope 'nosuch' does not exist. Available:")
	sb.scopeSNMP("")
	sb.said(1, "Usage: tacctl scope snmp <scope>")
	if out = sb.scopeSNMP("", "lab"); sb.code != 0 || !strings.Contains(out, "Usage: tacctl scope snmp lab <subcommand>") {
		t.Errorf("usage: %d %q", sb.code, out)
	}
}

func TestScopeSNMPClientsAndContact(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24,10.0.0.0/8,192.0.2.7")
	sb.said(0, "Added 3 allowed SNMP client range(s) to scope 'lab': 198.51.100.0/24 10.0.0.0/8 192.0.2.7/32")
	// The order given is the order kept; the server and the restrict frame it.
	out := sb.scopeSNMP("", "lab", "clients", "list")
	want := "  1. the tacctl server's own /32"
	for _, l := range []string{want, "  2. 198.51.100.0/24", "  3. 10.0.0.0/8", "  4. 192.0.2.7/32", "  5. 0.0.0.0/0 refused (always last, never stored)"} {
		if !strings.Contains(out, l) {
			t.Errorf("list lacks %q:\n%s", l, out)
		}
	}
	if o := sb.overrides(); !strings.Contains(o, "198.51.100.0/24") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	sb.scopeSNMP("", "lab", "clients", "add", "10.0.0.0/8")
	sb.said(0, "No new ranges to add to scope 'lab' (already present: 10.0.0.0/8).")
	// An overlap is a note, not a refusal.
	sb.scopeSNMP("", "lab", "clients", "add", "10.1.0.0/16")
	sb.said(0, "10.0.0.0/8 already contains 10.1.0.0/16 (both stay).")
	// What may not be stored.
	for _, c := range []struct{ arg, err string }{
		{"0.0.0.0/0", "would allow every address"},
		{"2001:db8::/32", "IPv6 network"},
		{"203.0.113.0/24,0.0.0.0/0", "would allow every address"},
		{"junk", "Invalid CIDR"},
	} {
		before := sb.overrides()
		sb.scopeSNMP("", "lab", "clients", "add", c.arg)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) || sb.overrides() != before {
			t.Errorf("add %q: %d %q", c.arg, sb.code, sb.stderr())
		}
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, "172.20."+strconv.Itoa(i)+".0/24")
	}
	before := sb.overrides()
	sb.scopeSNMP("", "lab", "clients", "add", strings.Join(many, ","))
	if sb.code != 1 || !strings.Contains(sb.stderr(), "at most 32 client ranges") || sb.overrides() != before {
		t.Errorf("too many: %d %q", sb.code, sb.stderr())
	}
	sb.scopeSNMP("", "lab", "clients", "remove", "10.0.0.0/8,203.0.113.0/24")
	sb.said(0, "Removed 1 SNMP client range(s) from scope 'lab': 10.0.0.0/8")
	sb.scopeSNMP("", "lab", "clients", "remove", "203.0.113.0/24")
	sb.said(0, "Nothing to remove (not in the list: 203.0.113.0/24).")
	sb.scopeSNMP("", "prod", "clients", "remove", "203.0.113.0/24")
	sb.said(0, "Nothing to remove: scope 'prod' lists no SNMP client ranges.")
	sb.scopeSNMP("", "lab", "clients", "frob")
	sb.said(1, "Unknown action 'frob'")
	sb.scopeSNMP("", "lab", "clients", "add")
	sb.said(1, "Usage: tacctl scope snmp lab clients add <cidr>")

	// The contact.
	if out = sb.scopeSNMP("", "lab", "contact"); strings.TrimSpace(out) != "not set" {
		t.Errorf("contact: %q", out)
	}
	sb.scopeSNMP("", "lab", "contact", "NOC", "<noc@example.net>")
	sb.said(0, "Contact of scope 'lab' set to 'NOC <noc@example.net>'.")
	if out = sb.scopeSNMP("", "lab", "contact"); strings.TrimSpace(out) != "NOC <noc@example.net>" {
		t.Errorf("contact: %q", out)
	}
	for _, bad := range []string{"help?", "line\nbreak", strings.Repeat("x", 121)} {
		sb.scopeSNMP("", "lab", "contact", bad)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The contact ") {
			t.Errorf("contact %q: %d %q", bad, sb.code, sb.stderr())
		}
	}
	out = sb.scopeSNMP("", "lab", "show")
	if !strings.Contains(out, "contact:    NOC <noc@example.net>  (scope)") || !strings.Contains(out, "              198.51.100.0/24") {
		t.Errorf("show:\n%s", out)
	}
	sb.scopeSNMP("", "lab", "contact", "--clear")
	sb.said(0, "Contact of scope 'lab' removed.")
	sb.scopeSNMP("", "lab", "contact", "--clear")
	sb.said(0, "has no contact; nothing was changed.")
	// Cleared in full, the file has no trace of the scope.
	sb.scopeSNMP("", "lab", "clients", "remove", strings.Join(sb.listClients("lab"), ","))
	if _, err := os.Stat(sb.path("state", "tacctl.yaml")); !os.IsNotExist(err) && strings.Contains(sb.overrides(), "snmp_scope") {
		t.Errorf("tacctl.yaml keeps keys:\n%s", sb.overrides())
	}
}

func (sb *sandbox) listClients(scope string) []string {
	var out []string
	for _, l := range strings.Split(sb.scopeSNMP("", scope, "clients", "list"), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.HasSuffix(f[0], ".") && strings.Contains(f[1], "/") && f[1] != "0.0.0.0/0" {
			out = append(out, f[1])
		}
	}
	return out
}

// A scope's settings and file follow its rename and go with its removal.
func TestScopeSNMPFollowsRenameAndRemove(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("lab-comm-1\n", "dmz", "community", "--stdin")
	sb.scopeSNMP("", "dmz", "contact", "NOC")
	sb.scopeSNMP("", "dmz", "clients", "add", "192.0.2.0/24")
	sb.run("", []string{"scope", "rename", "dmz", "edge"})
	sb.said(0, "Scope renamed: dmz -> edge")
	if _, err := os.Stat(sb.path("state", "snmp", "edge.yaml")); err != nil {
		t.Errorf("credentials did not follow: %v", err)
	}
	if _, err := os.Stat(sb.path("state", "snmp", "dmz.yaml")); !os.IsNotExist(err) {
		t.Errorf("old credentials left: %v", err)
	}
	if o := sb.overrides(); strings.Contains(o, "dmz") || !strings.Contains(o, "edge") || !strings.Contains(o, "192.0.2.0/24") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	out := sb.scopeSNMP("", "edge", "show", "--reveal")
	if !strings.Contains(out, "lab-comm-1") || !strings.Contains(out, "contact:    NOC") {
		t.Errorf("after rename:\n%s", out)
	}
	// Removal (the members go with --force) takes the file and the keys.
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.said(0, "Scope 'edge' removed.")
	if _, err := os.Stat(sb.path("state", "snmp", "edge.yaml")); !os.IsNotExist(err) {
		t.Errorf("credentials left after removal: %v", err)
	}
	if strings.Contains(sb.overrides(), "edge") || strings.Contains(sb.overrides(), "snmp_scope") {
		t.Errorf("keys left after removal:\n%s", sb.overrides())
	}
}

// The sysName lookup of 'device add' and 'device check' uses the credentials
// of the device's scope (derived from its address); a device in no scope uses
// the default (D46). Against the agent on 127.0.0.1.
func TestSNMPLookupUsesTheDevicesScope(t *testing.T) {
	sb := newSandbox(t, true)
	a := &snmp.Agent{SysName: "sw1.site-a.example", Community: "scope-right"}
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
	// The loopback is in scope dmz; the default has the wrong community.
	store := strings.Replace(sb.store(), "prefixes: [203.0.113.0/24]", "prefixes: [203.0.113.0/24, 127.0.0.0/8]", 1)
	sb.write("state/store.yaml", store, 0o600)
	sb.cfgRun("default-wrong\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.cfgRun("", []string{"config", "snmp", "port", port}, nil)
	sb.cfgRun("", []string{"config", "snmp", "timeout", "1"}, nil)
	hint := func() string {
		out := plain(sb.cfgRun("", []string{"device", "add", "sw1", "127.0.0.1", "--no-host-key"}, nil))
		sb.cfgRun("y\n", []string{"device", "remove", "sw1", "-y"}, nil)
		return out
	}
	// Scope credentials win over the default's.
	sb.scopeSNMP("scope-right\n", "dmz", "community", "--stdin")
	if out := hint(); !strings.Contains(out, "The device calls itself 'sw1.site-a.example' (SNMP sysName).") {
		t.Errorf("scope credentials: %q", out)
	}
	// device check reads it with the scope's too.
	sb.cfgRun("", []string{"device", "add", "sw1", "127.0.0.1", "--no-host-key"}, nil)
	if out := plain(sb.cfgRun("", []string{"device", "check", "sw1"}, nil)); !strings.Contains(out, "sw1.site-a.example") {
		t.Errorf("device check:\n%s", out)
	}
	// scope snmp test uses the scope's; config snmp test the default's.
	sb.scopeSNMP("", "dmz", "test", "127.0.0.1")
	sb.said(0, "127.0.0.1 calls itself 'sw1.site-a.example'")
	sb.cfgRun("", []string{"config", "snmp", "test", "127.0.0.1"}, nil)
	sb.said(1, "No answer from 127.0.0.1")
	// Without the scope's credentials the default's apply (and fail here).
	sb.scopeSNMP("", "dmz", "clear")
	sb.cfgRun("y\n", []string{"device", "remove", "sw1", "-y"}, nil)
	if out := hint(); !strings.Contains(out, "No SNMP answer from 127.0.0.1") {
		t.Errorf("default credentials: %q", out)
	}
	// A device in no scope uses the default: take the loopback out of dmz,
	// and make the default the right one.
	sb.write("state/store.yaml", strings.Replace(sb.store(), ", 127.0.0.0/8", "", 1), 0o600)
	sb.cfgRun("scope-right\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	if out := hint(); !strings.Contains(out, "The device calls itself 'sw1.site-a.example' (SNMP sysName).") {
		t.Errorf("no scope: %q", out)
	}
}

// An engineer reads the SNMP settings of the scopes of their own, with
// --reveal logged, and changes nothing (D45); another scope does not exist
// for them.
func TestScopeSNMPEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	sb.scopeSNMP("lab-comm-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24")
	sb.scopeSNMP("prod-comm-1\n", "prod", "community", "--stdin")
	sb.cfgRun("def-comm-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	logged := func(scope string) int {
		return sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=snmp name="+scope+" by=bob")
	}
	out := sb.asEngineer("", "scope", "snmp", "lab", "show")
	if sb.code != 0 || strings.Contains(out, "lab-comm-1") || logged("lab") != 0 {
		t.Errorf("show: %d %q (logged %d)", sb.code, out, logged("lab"))
	}
	out = sb.asEngineer("", "scope", "snmp", "lab", "show", "--reveal")
	if sb.code != 0 || !strings.Contains(out, "community:  lab-comm-1  (scope)") || logged("lab") != 1 {
		t.Errorf("show --reveal: %d %q (logged %d)", sb.code, out, logged("lab"))
	}
	for _, argv := range sb.runner.Argvs() {
		if strings.Contains(argv, "lab-comm-1") {
			t.Errorf("the secret reached a command: %q", argv)
		}
	}
	// Inherited values are labelled as the default's.
	sb.scopeSNMP("", "lab", "clear")
	out = sb.asEngineer("", "scope", "snmp", "lab", "show", "--reveal")
	if sb.code != 0 || !strings.Contains(out, "community:  def-comm-1  (default)") {
		t.Errorf("inherited: %d %q", sb.code, out)
	}
	// Reads that are plain.
	for _, args := range [][]string{{"clients", "list"}, {"clients"}, {"contact"}, {"version"}, {"port"}, {"timeout"}} {
		sb.asEngineer("", append([]string{"scope", "snmp", "lab"}, args...)...)
		if sb.code != 0 {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// Another scope is not found, with or without --reveal; nothing is logged.
	for _, args := range [][]string{{"show"}, {"show", "--reveal"}, {"clients", "list"}} {
		sb.asEngineer("", append([]string{"scope", "snmp", "prod"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'prod' does not exist.") || strings.Contains(sb.stderr(), "Available") {
			t.Errorf("prod %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if logged("prod") != 0 {
		t.Error("a refused reveal was logged as a read")
	}
	// Everything that changes anything, and test, is refused; nothing changes.
	before := sb.overrides()
	for _, args := range [][]string{{"community", "--stdin"}, {"v3-user", "x", "--stdin"}, {"version", "v3"}, {"clients", "add", "192.0.2.0/24"},
		{"clients", "remove", "198.51.100.0/24"}, {"contact", "x"}, {"contact", "--clear"}, {"port", "162"}, {"timeout", "3"}, {"clear"},
		{"test", "127.0.0.1"}} {
		sb.asEngineer("x\n", append([]string{"scope", "snmp", "lab"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads a scope's SNMP settings") || sb.overrides() != before {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// The default's credentials are the superuser's.
	sb.asEngineer("", "config", "snmp", "show", "--reveal")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
		t.Errorf("config snmp show --reveal: %d %q", sb.code, sb.stderr())
	}
	// device location is the engineer's, in their own scopes.
	if sb.asEngineer("", "device", "location", "lab-sw", "Rack 4"); sb.code != 0 || !strings.Contains(sb.devices(), "location: Rack 4") {
		t.Errorf("device location: %d %q", sb.code, sb.stderr())
	}
	sb.asEngineer("", "device", "location", "prod-sw", "Rack 9")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found.") {
		t.Errorf("device location in prod: %d %q", sb.code, sb.stderr())
	}
}

// 'config cisco|juniper|wti' print the effective credentials of an
// engineer's own scope, log the reveal, and show the ranges and contact.
func TestEngineerWalkthroughShowsSNMP(t *testing.T) {
	sb := engineerSandbox(t)
	sb.cfgRun("def-comm-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24,10.0.0.0/8")
	sb.scopeSNMP("", "lab", "contact", "NOC")
	route := func(r *fake.Runner) {
		r.On([]string{"ip", "-4", "route", "get", "1.0.0.0"}, execx.Result{Stdout: []byte("1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0\n")})
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
	}
	for _, vendor := range []string{"cisco", "juniper", "wti"} {
		out := plain(sb.cfgRun("", []string{"config", vendor, "--scope", "lab"}, route, "SUDO_USER=bob"))
		if sb.code != 0 || !strings.Contains(out, "def-comm-1") || !strings.Contains(out, "198.51.100.0") || !strings.Contains(out, "NOC") ||
			!strings.Contains(out, "inherited from the default") {
			t.Errorf("%s: %d\n%s", vendor, sb.code, out)
		}
		if !strings.Contains(out, "Unfilled SNMP values: location (tacctl device location <name> '<text>')") {
			t.Errorf("%s: no Unfilled line:\n%s", vendor, out)
		}
	}
	if n := sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=snmp name=lab by=bob"); n != 1 {
		t.Errorf("snmp reveal logged %d times in the last run", n)
	}
	// A superuser's walkthrough logs nothing.
	sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route)
	if sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=snmp") {
		t.Error("a superuser's walkthrough was logged")
	}
}

// --- device location ---------------------------------------------------------------------

func TestDeviceLocation(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	before := sb.devices()
	if strings.Contains(before, "location") {
		t.Fatalf("a location without one set:\n%s", before)
	}
	if out := sb.dev("", "location", "core-sw1"); strings.TrimSpace(out) != "-" {
		t.Errorf("show: %q", out)
	}
	sb.dev("", "location", "core-sw1", "Rack", "4,", "DC1")
	sb.said(0, "Device 'core-sw1' location set to Rack 4, DC1.")
	if !strings.Contains(sb.devices(), "location: 'Rack 4, DC1'") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
	if out := sb.dev("", "location", "core-sw1"); strings.TrimSpace(out) != "Rack 4, DC1" {
		t.Errorf("show: %q", out)
	}
	if out := sb.dev("", "show", "core-sw1"); !strings.Contains(out, "Location:") || !strings.Contains(out, "Rack 4, DC1") {
		t.Errorf("device show:\n%s", out)
	}
	if out := sb.dev("", "export", "--json"); !strings.Contains(out, `"location": "Rack 4, DC1"`) {
		t.Errorf("export --json:\n%s", out)
	}
	for _, bad := range []string{"where?", "a\x01b", strings.Repeat("x", 121)} {
		sb.dev("", "location", "core-sw1", bad)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The location ") {
			t.Errorf("%q: %d %q", bad, sb.code, sb.stderr())
		}
	}
	// '' and clear remove it, and the registry is as it was.
	sb.dev("", "location", "core-sw1", "")
	sb.said(0, "Device 'core-sw1' location cleared.")
	if sb.devices() != before {
		t.Errorf("devices.yaml after clearing:\n%s\nwas:\n%s", sb.devices(), before)
	}
	sb.dev("", "location", "core-sw1", "Rack 4")
	sb.dev("", "location", "core-sw1", "clear")
	sb.said(0, "location cleared.")
	if sb.devices() != before {
		t.Errorf("devices.yaml after clear:\n%s", sb.devices())
	}
	// device add --snmp-location.
	sb.dev("", "add", "core-sw2", "10.99.0.2", "--no-host-key", "--snmp-location", "Rack 5")
	sb.said(0, "registered")
	if !strings.Contains(sb.devices(), "location: Rack 5") {
		t.Errorf("add --snmp-location:\n%s", sb.devices())
	}
	sb.dev("", "add", "core-sw3", "10.99.0.3", "--no-host-key", "--snmp-location", "why?")
	sb.said(1, "The location may not contain '?'")
	if strings.Contains(sb.devices(), "core-sw3") {
		t.Error("a refused add registered the device")
	}
	sb.dev("", "location", "nosuch", "x")
	sb.said(1, "Device 'nosuch' not found.")
}

// --- --server, --source, --name, --snmp-location ------------------------------------------

func TestDeviceConfigServerSourceAndName(t *testing.T) {
	sb := newSandbox(t, true)
	sb.resolve = func(_ context.Context, name string) ([]string, error) {
		if name == "tacacs.example.net" {
			return []string{"2001:db8::9", "203.0.113.9"}, nil
		}
		return nil, errors.New("no such host")
	}
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--snmp-location", "Rack 4", "--description", "Lab switch")
	sb.scopeSNMP("lab-comm-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "contact", "NOC")
	out := sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--server", "203.0.113.9", "--source", "198.51.100.77"}, route)
	out = plain(out)
	for _, want := range []string{"  address ipv4 203.0.113.9\n", "Two server addresses:", "authenticate against 203.0.113.9 (--server)",
		"tacctl reaches the device from 198.51.100.77 (--source)", "  permit host 198.51.100.77\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "permit host 203.0.113.9") || strings.Contains(out, "permit host 10.0.0.42") {
		t.Errorf("wrong first client:\n%s", out)
	}
	// A host name that resolves to an IPv4 address.
	out = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--server", "tacacs.example.net"}, route))
	if sb.code != 0 || !strings.Contains(out, "set system tacplus-server 203.0.113.9 secret") || !strings.Contains(out, "(--server: resolved from tacacs.example.net)") ||
		!strings.Contains(out, "client-list TACCTL-SNMP 10.0.0.42/32\n") {
		t.Errorf("host name: %d\n%s", sb.code, out)
	}
	// --source alone.
	out = plain(sb.cfgRun("", []string{"config", "wti", "--scope", "lab", "--source", "198.51.100.77"}, route))
	if sb.code != 0 || !strings.Contains(out, "allow  198.51.100.77/32") || !strings.Contains(out, "Primary Host/Address       : 10.0.0.42") ||
		!strings.Contains(out, "tacctl reaches the device from 198.51.100.77 (--source)") {
		t.Errorf("--source alone: %d\n%s", sb.code, out)
	}
	// Neither flag is stored.
	if o := sb.overrides(); strings.Contains(o, "203.0.113.9") || strings.Contains(o, "198.51.100.77") {
		t.Errorf("a flag was stored:\n%s", o)
	}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"--server", "2001:db8::1"}, "--server takes the IPv4 address"},
		{[]string{"--server", "10.0.0.0/8"}, "--server takes the IPv4 address"},
		{[]string{"--server", "nosuch.example.net"}, "--server 'nosuch.example.net' does not resolve to an IPv4 address."},
		{[]string{"--server", "bad name"}, "--server takes the IPv4 address"},
		{[]string{"--source", "tacacs.example.net"}, "--source takes the IPv4 address"},
		{[]string{"--source", "10.0.0.0/8"}, "--source takes the IPv4 address"},
		{[]string{"--source", "::1"}, "--source takes the IPv4 address"},
		{[]string{"--server"}, "Usage: tacctl config cisco"},
		{[]string{"--snmp-location"}, "Usage: tacctl config cisco"},
		{[]string{"--snmp-location", "where?"}, "may not contain '?'"},
		{[]string{"--name", "nosuch"}, "Device 'nosuch' not found."},
		{[]string{"--name", "lab-sw1", "--scope", "prod"}, "Device 'lab-sw1' is in scope 'lab', not in 'prod'."},
	} {
		args := append([]string{"config", "cisco"}, c.args...)
		if c.args[0] != "--name" {
			args = append(args, "--scope", "lab")
		}
		got := sb.cfgRun("", args, route)
		if sb.code != 1 || got != "" || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%v: %d %q %q", c.args, sb.code, got, sb.stderr())
		}
	}
	// --name picks the registered device's location, description and sysName;
	// --snmp-location overrides the location for one paste.
	out = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "lab-sw1"}, route))
	for _, want := range []string{`set snmp location "Rack 4"`, `set snmp description "Lab switch"`, `(expects sysName 'lab-sw1')`} {
		if !strings.Contains(out, want) {
			t.Errorf("--name lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Unfilled SNMP values") {
		t.Errorf("unfilled with everything set:\n%s", out)
	}
	out = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "lab-sw1", "--snmp-location", "Rack 9"}, route))
	if !strings.Contains(out, `set snmp location "Rack 9"`) || strings.Contains(out, "Rack 4") {
		t.Errorf("--snmp-location:\n%s", out)
	}
	if strings.Contains(sb.devices(), "Rack 9") {
		t.Error("--snmp-location was stored")
	}
	// --staging combined with --server: the staged /32 is the device's bench address.
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--staging", "192.0.2.77", "--server", "203.0.113.9"}, route))
	if sb.code != 0 || !strings.Contains(out, "  address ipv4 203.0.113.9\n") {
		t.Errorf("--staging --server: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	if m := plain(sb.run("", []string{"scope", "staging", "list"})); !strings.Contains(m, "192.0.2.77") {
		t.Errorf("staged address:\n%s", m)
	}
}

// An unreadable credentials file leaves the SNMP step out with a warning;
// the rest of the walkthrough is as it was.
func TestWalkthroughSurvivesBrokenSNMPFile(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/snmp/lab.yaml", "version: 9\n", 0o600)
	out := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route))
	if sb.code != 0 || !strings.Contains(out, "tacacs server TACACS") || !strings.Contains(sb.stderr(), "The SNMP step is left out:") ||
		!strings.Contains(sb.stderr(), "lab.yaml") {
		t.Errorf("%d %q\n%s", sb.code, sb.stderr(), out)
	}
}

// A tacctl.yaml and a devices.yaml written without the new keys are the bytes
// they were: reading, and every walkthrough, leave them alone.
func TestNoNewKeysUnlessSet(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "scope:\n  default: lab\n", 0o600)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	conf0, dev0 := sb.overrides(), sb.devices()
	for _, args := range [][]string{{"config", "cisco"}, {"config", "juniper"}, {"config", "wti"}, {"scope", "snmp", "lab", "show"},
		{"scope", "snmp", "lab", "clients", "list"}, {"scope", "snmp", "lab", "clear"}, {"device", "location", "core-sw1"},
		{"device", "location", "core-sw1", "clear"}, {"device", "list"}, {"device", "check", "core-sw1"}} {
		sb.cfgRun("", args, route)
	}
	if sb.overrides() != conf0 || sb.devices() != dev0 {
		t.Errorf("a file changed:\n%s\n%s", sb.overrides(), sb.devices())
	}
	for _, p := range []string{"snmp", "snmp.yaml"} {
		if _, err := os.Stat(filepath.Join(sb.dir, "state", p)); !os.IsNotExist(err) {
			t.Errorf("%s was created: %v", p, err)
		}
	}
}
