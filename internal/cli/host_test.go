package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/paths"
)

// hostSandbox is a sandbox with the multiscope store, a stand-in
// pam_tacplus tarball, and a runner scripted like host.bats's stubs: getent
// resolves everything to 192.0.2.50, ip says the source is 192.0.2.1, the
// ssh copy step keeps the script and names /tmp/tacctl.AbCd1234, the run
// step succeeds unless runFails.
type hostSandbox struct {
	*sandbox
	pushed   string
	runFails bool
}

func newHostSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	sb := newSandbox(t, true)
	linux := filepath.Join(sb.dir, "linux")
	if err := os.MkdirAll(linux, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linux, "pam_tacplus-1.7.0.tar.gz"), []byte("not really a tarball\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.env = append(sb.env, "TACCTL_LINUX_DIR="+linux)
	hs := &hostSandbox{sandbox: sb}
	// Rendered once, so preflight finds tacquito.yaml and says nothing.
	hs.run(nil, "config", "render")
	hs.expect(0, "", "")
	return hs
}

func (hs *hostSandbox) runner() *fake.Runner {
	r := &fake.Runner{}
	r.On([]string{"systemctl"}, execx.Result{})
	r.On([]string{"logger"}, execx.Result{})
	r.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	r.On([]string{"getent"}, execx.Result{Stdout: []byte("192.0.2.50 STREAM web1\n192.0.2.50 DGRAM\n")})
	fakePasswd(r)
	r.On([]string{"ip"}, execx.Result{Stdout: []byte("192.0.2.50 dev eth0 src 192.0.2.1 uid 0\n")})
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		joined := strings.Join(c.Args, " ")
		switch {
		case strings.Contains(joined, "mktemp"):
			b, _ := io.ReadAll(c.Stdin)
			hs.pushed = string(b)
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		case hs.runFails && strings.Contains(joined, "rm -f"):
			return execx.Result{Code: 1}, nil
		}
		return execx.Result{}, nil
	})
	return r
}

// run runs tacctl with r (a fresh scripted runner when nil).
func (hs *hostSandbox) run(r *fake.Runner, args ...string) string {
	hs.t.Helper()
	if r == nil {
		r = hs.runner()
	}
	hs.out.Reset()
	hs.err.Reset()
	hs.sandbox.runner = r
	a := app.New(args, paths.NewEnv(hs.env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &hs.out, Stderr: &hs.err}, r)
	hs.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test"}), a.Out)
	if n := len(r.Execs()); n != 0 {
		hs.t.Errorf("%q: exec'd", args)
	}
	return hs.out.String()
}

func (hs *hostSandbox) registry() string {
	data, _ := os.ReadFile(filepath.Join(hs.dir, "state", "linux-hosts"))
	return string(data)
}

func TestHostFamilyUsage(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "host")
	hs.expect(0, "Host Commands", "")
	for _, w := range []string{"help", "-h", "bogus"} {
		hs.run(nil, "host", w)
		hs.expect(1, "Usage: tacctl host <subcommand>", "[ERROR] Unknown subcommand: '"+w+"'")
	}
	hs.run(nil, "config", "linux")
	hs.expect(0, "Linux host TACACS+ or RADIUS login", "")
	hs.run(nil, "config", "linux", "bogus")
	hs.expect(1, "Usage: tacctl config linux <subcommand>", "")
	if hs.err.Len() != 0 {
		t.Errorf("config linux bogus: stderr %q", hs.err.String())
	}
	hs.run(nil, "config", "linux", "builds", "bogus")
	hs.expect(1, "", "Usage: tacctl config linux builds [list|clear]")
	hs.run(nil, "host", "list")
	hs.expect(0, "None. Enroll one with", "")
}

func TestHostEnrollSyncUnenroll(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.runner()
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if got := hs.registry(); got != "web1|admin@web1.example.net||lab|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	for _, w := range []string{"TAC_METHOD=tacplus\n", "TAC_SERVER=192.0.2.1\n", "TAC_SECRET=lab-secret-0123456789abcdef\n",
		"TAC_USERS=$'alice:superuser:80000\\nbob:operator:80001\\ncarol:readonly:80002'\nTAC_INACTIVE=''\nTAC_REMOVE_HOMES=\\*\nTAC_UID_FIRST=80000\nTAC_UID_LAST=89999\nTAC_UID_PREVIOUS=''\nTAC_PROTOCOL=3\n",
		"# tacctl Linux client installer for scope 'lab'. Generated "} {
		if !strings.Contains(hs.pushed, w) {
			t.Errorf("pushed script lacks %q", w)
		}
	}
	if !r.CalledRegexp(`^ssh .*-T admin@web1.example.net .*rm -f /tmp/tacctl.AbCd1234.*sudo -n bash /tmp/tacctl.AbCd1234 --allow-uid-mismatch;`) ||
		!r.CalledRegexp(`^ssh .*-O exit admin@web1.example.net$`) {
		t.Errorf("ssh calls %q", r.Argvs())
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "host enroll name=web1 target=admin@web1.example.net scope=lab method=tacplus by=root") {
		t.Errorf("no audit line: %q", r.Argvs())
	}
	if r.Called("getent") && r.CalledRegexp(`os-release`) {
		t.Error("--build-on-host probed the host")
	}
	// --remove-home: nothing to ask, so the host's accounts are not read.
	if r.CalledRegexp(`^ssh .*getent passwd`) {
		t.Errorf("--remove-home read the host's accounts: %q", r.Argvs())
	}

	out := hs.run(nil, "host", "list")
	if !strings.Contains(plain(out), "  web1  admin@web1.example.net  lab    192.0.2.1  tacplus  3\n") {
		t.Errorf("list %q", plain(out))
	}
	// A disabled user is inactive (expired on the host, never deleted).
	// Without a terminal nothing is asked and no home is deleted.
	hs.run(nil, "user", "disable", "carol")
	r = hs.runner()
	hs.run(r, "host", "sync", "--all")
	hs.expect(0, "web1: synced (2 users).", "")
	if !strings.HasSuffix(hs.pushed, "exit 0\n") {
		t.Error("sync pushed the tarball")
	}
	if !strings.Contains(hs.pushed, "TAC_USERS=$'alice:superuser:80000\\nbob:operator:80001'\nTAC_INACTIVE=carol\nTAC_REMOVE_HOMES=''\nTAC_UID_FIRST=80000\nTAC_UID_LAST=89999\nTAC_UID_PREVIOUS=''\nTAC_PROTOCOL=3\n") {
		t.Errorf("sync header:\n%s", strings.SplitN(hs.pushed, "# --- tacctl", 2)[0])
	}
	if r.CalledRegexp(`getent passwd`) {
		t.Errorf("no terminal, but the host's accounts were read: %q", r.Argvs())
	}
	hs.run(nil, "user", "enable", "carol")
	// An enrolment whose provisioning account is a tacctl user is synced,
	// with a warning to re-enrol.
	hs.write("state/linux-hosts", "web1|carol@web1.example.net||lab|192.0.2.1|\n", 0o600)
	out = hs.run(nil, "host", "sync", "web1")
	if hs.code != 0 || !strings.Contains(plain(out)+hs.stderr(), "web1: the provisioning account 'carol' is a tacctl user; re-enrol with a local account") {
		t.Errorf("sync warning: %d %q %q", hs.code, out, hs.stderr())
	}
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.runFails = true
	hs.run(nil, "host", "sync", "web1")
	hs.expect(1, "", "web1: sync failed")
	hs.run(nil, "host", "unenroll", "web1")
	hs.expect(1, "", "Removal on web1 failed; it is still registered.")
	hs.run(nil, "host", "unenroll", "web1", "--force")
	hs.expect(0, "forgetting the host anyway (--force)", "")
	if !strings.Contains(hs.pushed, "tacctl Linux client: remove") || strings.Contains(hs.pushed, "lab-secret") {
		t.Error("unenroll pushed the wrong script")
	}
	if hs.registry() != "" {
		t.Errorf("registry %q", hs.registry())
	}
	if !strings.Contains(hs.out.String(), "tacctl scope remove lab") {
		t.Errorf("scope hint: %q", hs.out.String())
	}
}

func TestHostEnrollCreatesScopeQuietly(t *testing.T) {
	hs := newHostSandbox(t)
	out := hs.run(nil, "host", "enroll", "web1", "--build-on-host")
	hs.expect(0, "Creating scope 'linux-web1' for 192.0.2.50/32...", "")
	if strings.Contains(out, "Generated secret") || strings.Contains(out, "added.") {
		t.Errorf("scope add was not silenced: %q", out)
	}
	if !strings.Contains(hs.store(), "linux-web1:\n    prefixes: [192.0.2.50/32]") || !strings.Contains(hs.store(), "protocols: [tacacs]") {
		t.Errorf("store:\n%s", hs.store())
	}
	if !strings.Contains(out, "No users are in scope 'linux-web1' yet.") {
		t.Errorf("no-users hint: %q", out)
	}
	// The registered server address is kept on a re-enroll.
	if err := os.WriteFile(filepath.Join(hs.dir, "state", "linux-hosts"), []byte("web1|web1||linux-web1|198.51.100.7|\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.run(nil, "host", "enroll", "web1", "--build-on-host")
	hs.expect(0, "Using existing scope 'linux-web1'.", "")
	if hs.registry() != "web1|web1||linux-web1|198.51.100.7|\n" {
		t.Errorf("registry %q", hs.registry())
	}
}

func TestHostEnrollRefusals(t *testing.T) {
	hs := newHostSandbox(t)
	for _, c := range []struct {
		args       []string
		code       int
		out, errIs string
	}{
		{[]string{"web1;reboot"}, 1, "", "Usage: tacctl host enroll <[user@]host> | --local  [options]"},
		{[]string{"-oProxyCommand=x"}, 1, "Host Commands", "Unknown option: '-oProxyCommand=x'"},
		{[]string{"web1", "web2"}, 1, "", "Only one host per enroll."},
		{[]string{"--local", "web1"}, 1, "", "--local takes no host argument."},
		{[]string{"web1", "--adopt", "bob"}, 1, "Host Commands", "Unknown option: '--adopt'"},
		{[]string{"web1", "--method"}, 1, "", "--method needs a method: tacplus, radius"},
		{[]string{"web1", "--method", "ldap"}, 1, "", "Unknown method 'ldap'. Methods: tacplus, radius"},
		{[]string{"web1", "--method", "radius"}, 1, "", "needs the RADIUS backend, which is not enabled"},
		{[]string{"web1", "--name", "9x"}, 1, "", "Invalid host name '9x'."},
		{[]string{"web1", "--port", "x"}, 1, "", "Invalid --port 'x'."},
		{[]string{"web1", "--identity", "/no/such/key"}, 1, "", "Identity file '/no/such/key' not found."},
		{[]string{"web1", "--scope", "nope"}, 1, "", "Scope 'nope' does not exist."},
		// The provisioning account is local and never a tacctl user.
		{[]string{"carol@web1", "--scope", "lab"}, 1, "", "The provisioning account 'carol' (the ssh login for carol@web1) is a tacctl user."},
		// A value flag at the end of the line: 0.1.16 never returned.
		{[]string{"web1", "--scope"}, 1, "", ""},
	} {
		r := hs.runner()
		hs.run(r, append([]string{"host", "enroll"}, c.args...)...)
		hs.expect(c.code, c.out, c.errIs)
		if c.errIs == "" && hs.err.Len() != 0 {
			t.Errorf("%q: stderr %q", c.args, hs.err.String())
		}
		if r.Called("ssh") {
			t.Errorf("%q reached ssh", c.args)
		}
	}
	// ssh's default login is the invoking user: a tacctl user is refused too.
	env := hs.env
	hs.env = append(append([]string(nil), env...), "SUDO_USER=alice", "SUDO_UID=1001")
	hs.run(nil, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(1, "", "The provisioning account defaults to your username 'alice', which is a tacctl user.")
	if !strings.Contains(hs.err.String(), "tacctl host enroll <account>@web1") {
		t.Errorf("no remedy: %q", hs.err.String())
	}
	hs.env = env
	// getent failing: the name cannot be resolved, exit 1.
	r := hs.runner()
	r.On([]string{"getent"}, execx.Result{Code: 2})
	hs.run(r, "host", "enroll", "ghost", "--scope", "lab")
	hs.expect(1, "", "[ERROR] Cannot resolve 'ghost'\n")
	r = hs.runner()
	r.On([]string{"ip"}, execx.Result{Code: 2})
	hs.run(r, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(1, "", "Could not determine this server's address for web1 (ip route failed); pass --server <address>")
	// ip answering without a source address.
	r = hs.runner()
	r.On([]string{"ip"}, execx.Result{Stdout: []byte("unreachable\n")})
	hs.run(r, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(1, "", "Could not work out which address web1 should use for this server. Pass --server.")
	// No tarball.
	if err := os.Remove(filepath.Join(hs.dir, "linux", "pam_tacplus-1.7.0.tar.gz")); err != nil {
		t.Fatal(err)
	}
	hs.run(nil, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(1, "", "pam_tacplus tarball not found. Run 'tacctl config linux build' first.")
	// sync and unenroll.
	for _, c := range []struct {
		args  []string
		errIs string
	}{
		{[]string{"sync"}, "Usage: tacctl host sync <name> | --all  [--allow-uid-mismatch] [--remove-home]"},
		{[]string{"sync", "web1", "--adopt", "bob"}, "Unknown option: '--adopt'"},
		{[]string{"sync", "--bogus"}, "Unknown option: '--bogus'"},
		{[]string{"sync", "ghost"}, "No enrolled host named 'ghost'. See 'tacctl host list'."},
		{[]string{"unenroll"}, "Usage: tacctl host unenroll <name> [--force]"},
		{[]string{"unenroll", "ghost"}, "No enrolled host named 'ghost'."},
		{[]string{"unenroll", "-x"}, "Unknown option: '-x'"},
		{[]string{"default-method", "ldap"}, "Unknown method 'ldap'. Methods: tacplus, radius"},
	} {
		hs.run(nil, append([]string{"host"}, c.args...)...)
		hs.expect(1, "", c.errIs)
	}
	hs.run(nil, "host", "sync", "--all")
	hs.expect(0, "No hosts enrolled.", "")
}

func TestHostEnrollPrebuiltAndPlatform(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "os-release")
	},
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte("ID=fedora\n\nTACCTL_ARCH=" + archHere() + "\n")}, nil
		})
	hs.run(r, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(0, "No container image is known for this host's OS", "")
	r = hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "os-release")
	},
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte("ID=debian\nVERSION_CODENAME=bookworm\n\nTACCTL_ARCH=riscv64\n")}, nil
		})
	hs.run(r, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(0, "The host is riscv64 and this server is "+archHere()+"; pam_tacplus will be compiled on the host.", "")
	r = hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "os-release")
	},
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte("ID=debian\nVERSION_CODENAME=bookworm\n\nTACCTL_ARCH=" + archHere() + "\n")}, nil
		})
	r.Missing("podman")
	hs.run(r, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(0, "pam_tacplus will be compiled on the host instead.", "")
	if !strings.Contains(hs.out.String(), "podman is not installed here") {
		t.Errorf("out %q", hs.out.String())
	}
	hs.run(nil, "config", "linux", "builds")
	hs.expect(0, "None yet. 'tacctl host enroll' builds one", "")
	hs.run(nil, "config", "linux", "builds", "clear")
	hs.expect(0, "Prebuilt modules removed", "")
}

func archHere() string { return hosts.Machine() }

func TestHostDefaultMethod(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "host", "default-method")
	hs.expect(0, "Default method for new hosts: tacplus", "")
	hs.run(nil, "host", "default-method", "radius")
	hs.expect(0, "New hosts are enrolled with method 'radius' unless --method says otherwise.", "")
	if !strings.Contains(hs.out.String(), "The RADIUS backend is not enabled yet: tacctl backend enable radius") {
		t.Errorf("out %q", hs.out.String())
	}
	hs.run(nil, "host", "default-method")
	hs.expect(0, "Default method for new hosts: radius", "")
	hs.run(nil, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(1, "", "tacctl backend enable radius")
}

func TestConfigLinuxScriptAndUID(t *testing.T) {
	hs := newHostSandbox(t)
	out := filepath.Join(hs.dir, "x.sh")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	hs.expect(0, "Wrote "+out+" (mode 0600; contains the shared secret for scope 'lab').", "")
	if !strings.Contains(hs.out.String(), "  Users:   alice(superuser) bob(operator) carol(readonly) \n") ||
		!strings.Contains(hs.out.String(), "    bash x.sh                   # install\n") {
		t.Errorf("out %q", hs.out.String())
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	// No --server: ip's source address; ip failing is an error naming --server.
	r := hs.runner()
	hs.run(r, "config", "linux", "script", "--scope", "lab", "-o", out)
	hs.expect(0, "Server:  192.0.2.1 port 49", "")
	r = hs.runner()
	r.On([]string{"ip"}, execx.Result{Code: 2})
	hs.run(r, "config", "linux", "script", "--scope", "lab", "-o", out)
	hs.expect(1, "", "Could not determine this server's address (ip route failed); pass --server <address>")
	// An output that cannot be written: an error, no "Wrote".
	bad := filepath.Join(hs.dir, "no", "such", "x.sh")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", bad)
	hs.expect(1, "", "[ERROR] Cannot write "+bad+": No such file or directory\n")
	if strings.Contains(hs.out.String(), "Wrote") {
		t.Errorf("reported as written: %q", hs.out.String())
	}
	hs.run(nil, "config", "linux", "script", "--bogus")
	hs.expect(1, "", "Unknown argument: '--bogus'")
	hs.run(nil, "config", "linux", "script", "--scope")
	hs.expect(1, "", "")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--method", "radius")
	hs.expect(1, "", "needs the RADIUS backend")

	rm := filepath.Join(hs.dir, "rm.sh")
	hs.run(nil, "config", "linux", "remove-script", "-o", rm)
	hs.expect(0, "Wrote "+rm+" (no secrets).", "")
	hs.run(nil, "config", "linux", "remove-script", "-o", filepath.Join(hs.dir, "no", "rm.sh"))
	hs.expect(1, "", "install: cannot create regular file")
	hs.run(nil, "config", "linux", "remove-script", "bogus")
	hs.expect(1, "", "Usage: tacctl config linux remove-script [--output <file>]")

	hs.run(nil, "config", "linux", "uid")
	hs.expect(0, "  alice     80000\n", "")
	hs.run(nil, "config", "linux", "uid", "bob")
	hs.expect(0, "80001\n", "")
	hs.run(nil, "config", "linux", "uid", "dave")
	hs.expect(1, "", "No UID assigned to 'dave' yet.")
	hs.run(nil, "config", "linux", "uid", "bad name")
	hs.expect(1, "", "Username must contain only letters")
	hs.run(nil, "config", "linux", "uid", "dave", "90000")
	hs.expect(1, "", "User 'dave' does not exist.")
	// Only the range: 80000-89999 (the legacy range is not it).
	for _, bad := range []string{"500", "1001", "20000", "29999", "79999", "90000", "65534", "080000", "x80000"} {
		hs.run(nil, "config", "linux", "uid", "bob", bad)
		hs.expect(1, "", "UID must be a number from 80000 to 89999: tacctl gives out UIDs (and the matching GIDs) in that range only.")
	}
	hs.run(nil, "config", "linux", "uid", "bob", "80000")
	hs.expect(1, "", "UID 80000 is already assigned to 'alice'.")
	hs.run(nil, "config", "linux", "uid", "bob", "89999")
	hs.expect(0, "usermod -u 89999 bob && groupmod -g 89999 bob", "")
	// A legacy entry outside the range (before 0.2.1) is listed as unused
	// on hosts, and its user is left out of the script (expired there, not
	// deleted).
	uids := filepath.Join(hs.dir, "state", "linux-uids")
	data, _ := os.ReadFile(uids)
	if err := os.WriteFile(uids, []byte(strings.Replace(string(data), "carol:80002", "carol:1500", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.run(nil, "config", "linux", "uid")
	hs.expect(0, "  carol     1500   outside 80000-89999: not used on hosts\n", "")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	hs.expect(0, "", "Skipping 'carol': its UID 1500 is outside 80000-89999, so no host gets an account for it. Assign one in the range: tacctl config linux uid carol <uid>")
	script, _ := os.ReadFile(out)
	if !strings.Contains(string(script), "TAC_USERS=$'alice:superuser:80000\\nbob:operator:89999'\nTAC_INACTIVE=carol\n") {
		t.Errorf("script header:\n%s", strings.SplitN(string(script), "# --- tacctl", 2)[0])
	}
}

// The range runs out at 89999: the next user is refused with the way out,
// and nothing is written.
func TestConfigLinuxScriptUIDRangeFull(t *testing.T) {
	hs := newHostSandbox(t)
	uids := filepath.Join(hs.dir, "state", "linux-uids")
	if err := os.WriteFile(uids, []byte("alice:89999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(hs.dir, "x.sh")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	hs.expect(1, "", "[ERROR] No UID left for 'bob': every number of 80000-89999 has been given out (UIDs are never reused).")
	if !strings.Contains(hs.err.String(), "Give it a free number of the range by hand: tacctl config linux uid bob <uid>") {
		t.Errorf("stderr %q", hs.err.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a script was written")
	}
	if data, _ := os.ReadFile(uids); string(data) != "# range 80000-89999\nalice:89999\n" {
		t.Errorf("uid file %q", data)
	}
}

func TestHostAndLinuxSpecs(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	check := func(family string, specs map[string]Spec, cmds []*cobra.Command) {
		t.Helper()
		if len(cmds) != len(specs) {
			t.Errorf("%s: %d verbs, %d specs", family, len(cmds), len(specs))
		}
		for _, c := range cmds {
			spec, ok := specs[c.Name()]
			if !ok || c.RunE == nil {
				t.Errorf("%s %s: spec %v, RunE %v", family, c.Name(), ok, c.RunE != nil)
				continue
			}
			kinds := append([]string(nil), spec.Args...)
			for _, f := range spec.Flags {
				kinds = append(kinds, f.Kind)
			}
			for _, k := range kinds {
				_, native := completionKinds[k]
				_, nativeArg := completionArgKinds[k]
				if k != "" && !native && !nativeArg && !strings.Contains(k, "|") && k != KindFile {
					t.Errorf("%s %s: kind %q is no completion kind", family, c.Name(), k)
				}
			}
		}
	}
	check("host", hostSpecs, hostCmd(inv).Commands())
	check("config linux", configLinuxSpecs, configLinuxCmd(inv).Commands())
	if configVerbs["linux"] == nil {
		t.Error("config linux is not registered")
	}
	if _, ok := configSpecs["linux"]; !ok {
		t.Error("config linux has no spec")
	}
}

func TestHostHelpers(t *testing.T) {
	if got := srcAddresses("a src 1.2.3.4 x\nb src 5.6.7.8\nsrc"); strings.Join(got, ",") != "1.2.3.4,5.6.7.8," {
		t.Errorf("srcAddresses %q", got)
	}
	if cutField("a|b|c", 2) != "b" || cutField("abc", 5) != "abc" || cutField("a|b", 5) != "" {
		t.Error("cutField")
	}
	if baseName("a/b/c.sh") != "c.sh" || baseName("dir/") != "" || baseName("x") != "x" {
		t.Error("baseName")
	}
}

func TestConfigLinuxBuildBuildsAndOwner(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.runner()
	r.Missing("gnulib-tool")
	hs.run(r, "config", "linux", "build")
	hs.expect(1, "", "'gnulib-tool' not found. Install the build tools first:")

	// A cached module is listed.
	dir := filepath.Join(hs.dir, "linux", "builds", "debian-bookworm-x86_64")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info := "image=docker.io/library/debian:bookworm\ndigest=sha256:feedface\narch=x86_64\nbuilt=2026-10-03T12:00:00Z\n"
	if err := os.WriteFile(filepath.Join(dir, "info"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	out := hs.run(nil, "config", "linux", "builds")
	if !strings.Contains(out, "  debian:bookworm  x86_64  2026-10-03T12:00:00Z  sha256:feedface\n") {
		t.Errorf("builds %q", out)
	}

	// Under sudo the script is handed to the caller (here: ourselves).
	uid, gid := os.Getuid(), os.Getgid()
	p := filepath.Join(hs.dir, "mine.sh")
	hs.env = append(hs.env, "SUDO_UID="+strconv.Itoa(uid), "SUDO_GID="+strconv.Itoa(gid), "SUDO_USER=tester")
	r = hs.runner()
	r.On([]string{"getent", "passwd", strconv.Itoa(uid)}, execx.Result{Stdout: []byte("tester:x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) + "::/home/tester:/bin/sh\n")})
	hs.run(r, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", p)
	hs.expect(0, "Wrote "+p, "")
	// A secret that cannot go on a PAM line: refused, nothing written.
	if err := os.WriteFile(filepath.Join(hs.dir, "state", "store.yaml"),
		[]byte(strings.Replace(hs.store(), "lab-secret-0123456789abcdef", "REPLACE_ME_0123456789", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.run(r, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", p+".2")
	hs.expect(1, "", "Regenerate it: tacctl scope secret lab generate")
	if _, err := os.Stat(p + ".2"); !os.IsNotExist(err) {
		t.Error("written anyway")
	}
	if shortHostname() == "" || padTo("ab", 4) != "ab  " || padTo("abcde", 4) != "abcde" {
		t.Error("helpers")
	}
}

// The host's account summary is what enroll and sync report: the accounts
// tacctl manages there and the users it refused; without one, the count
// of users sent.
func TestHostSyncReportsTheHostsSummary(t *testing.T) {
	hs := newHostSandbox(t)
	summary := ""
	r := func() *fake.Runner {
		r := hs.runner()
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "rm -f") },
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(summary)}, nil })
		return r
	}
	summary = "[INFO] Accounts: 2 managed by tacctl here; refused: carol.\n"
	hs.run(r(), "host", "enroll", "web1", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled (2 users; 1 refused: carol).", "")
	hs.run(r(), "host", "sync", "web1")
	hs.expect(0, "web1: synced (2 users; 1 refused: carol).", "")
	summary = "[INFO] Accounts: 3 managed by tacctl here.\n"
	hs.run(r(), "host", "sync", "web1")
	hs.expect(0, "web1: synced (3 users).", "")
	summary = ""
	hs.run(r(), "host", "enroll", "web1", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.\n", "")
}
