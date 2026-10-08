package cli

import (
	"context"
	"github.com/rett/tacctl/internal/tier"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// rootRun is cfgRun with tacctl's fixed host locations (the console's
// symlink among them) moved into the sandbox; it returns stdout and stderr,
// colour codes taken out.
func (sb *sandbox) rootRun(args []string, script func(*fake.Runner)) string {
	sb.t.Helper()
	sb.out.Reset()
	sb.err.Reset()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	sb.runner.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(sb.runner)
	if script != nil {
		script(sb.runner)
	}
	a := app.New(args, paths.NewEnv(sb.env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, sb.runner)
	a.Paths = a.Paths.Reroot(sb.dir)
	sb.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.1-test", Commit: "c", Date: "d"}), a.Out)
	return plain(sb.out.String() + sb.err.String())
}

// consoleInstallSandbox is consoleSandbox with the console's symlink and an
// sshd_config that includes the drop-ins.
func consoleInstallSandbox(t *testing.T) (*sandbox, string) {
	sb := consoleSandbox(t)
	link := sb.path("usr", "local", "bin", "tacctl-console")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sb.path("usr", "local", "bin", "tacctl"), link); err != nil {
		t.Fatal(err)
	}
	sb.write("sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n", 0o644)
	return sb, link
}

func sshdOK(link string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.On([]string{"sshd", "-t"}, execx.Result{})
		r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding no\nforcecommand " + link + "\npubkeyauthentication no\n")})
	}
}

func passwdWith(link string, users ...string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		text := "root:x:0:0:root:/root:/bin/bash\n"
		for _, u := range users {
			text += u + ":x:80000:80000:" + u + " (TACACS+):/home/" + u + ":" + link + "\n"
		}
		r.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte(text)})
	}
}

func both(fs ...func(*fake.Runner)) func(*fake.Runner) {
	return func(r *fake.Runner) {
		for _, f := range fs {
			f(r)
		}
	}
}

func TestConsoleInstallRemoveCheck(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	dropin := sb.path("sshd_config.d", "tacctl-console.conf")
	out := sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 0 {
		t.Fatalf("install: %d\n%s", sb.code, out)
	}
	for _, want := range []string{"Installed: " + sb.path("shells") + " lists " + link, "Installed: sshd drop-in " + dropin,
		"sshd drop-in " + dropin + ": present, current", "includes " + sb.path("sshd_config.d") + "/*.conf",
		"sshd for alice: allowtcpforwarding no, allowagentforwarding no, forcecommand " + link,
		"The console's sshd settings are in effect."} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if data, _ := os.ReadFile(dropin); string(data) != console.DropIn(link, false, false, []tier.Tier{tier.Superuser}) {
		t.Errorf("drop-in %q", data)
	}
	if data, _ := os.ReadFile(sb.path("shells")); string(data) != "# /etc/shells\n/bin/sh\n/bin/bash\n"+link+"\n" {
		t.Errorf("shells %q", data)
	}
	if !sb.runner.Called("systemctl", "reload", "ssh.service") || !sb.runner.CalledRegexp("^logger .*console provision shells=installed dropin=installed") {
		t.Errorf("calls %q", sb.runner.Argvs())
	}
	// Again: nothing changes, sshd is not reloaded.
	out = sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 0 || !strings.Contains(out, "Unchanged: sshd drop-in") || sb.runner.Called("systemctl", "reload") {
		t.Errorf("again: %d\n%s", sb.code, out)
	}

	// check: sshd not applying the drop-in is the red warning, exit 1.
	out = sb.rootRun([]string{"console", "check"}, both(passwdWith(link, "alice"), func(r *fake.Runner) {
		r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("allowtcpforwarding yes\nallowagentforwarding no\nforcecommand none\npubkeyauthentication yes\n")})
	}))
	if sb.code != 1 || !strings.Contains(out, "WARNING: a console user can do more over ssh than the console allows") ||
		!strings.Contains(out, "forcecommand is 'none'") || !strings.Contains(out, "pubkeyauthentication is 'yes'") {
		t.Errorf("check: %d\n%s", sb.code, out)
	}
	sb.write("sshd_config", "Port 22\n", 0o644)
	out = sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 1 || !strings.Contains(out, "does not include "+sb.path("sshd_config.d")+"/*.conf, so sshd never reads the drop-in") {
		t.Errorf("no Include: %d\n%s", sb.code, out)
	}
	sb.write("sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n", 0o644)

	// remove: refused while alice has the console.
	out = sb.rootRun([]string{"console", "remove"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 1 || !strings.Contains(out, "These accounts still have the console as their login shell: alice. Nothing was removed.") ||
		!strings.Contains(out, "tacctl host sync authsrv") {
		t.Errorf("remove refused: %d\n%s", sb.code, out)
	}
	if _, err := os.Stat(dropin); err != nil {
		t.Error("removed anyway")
	}
	out = sb.rootRun([]string{"console", "remove"}, both(sshdOK(link), passwdWith(link)))
	if sb.code != 0 || !strings.Contains(out, "Removed: sshd drop-in") || !strings.Contains(out, "Removed: "+link+" in "+sb.path("shells")) {
		t.Errorf("remove: %d\n%s", sb.code, out)
	}
	if _, err := os.Stat(dropin); err == nil {
		t.Error("drop-in left")
	}
	if data, _ := os.ReadFile(sb.path("shells")); string(data) != "# /etc/shells\n/bin/sh\n/bin/bash\n" {
		t.Errorf("shells %q", data)
	}
}

// sshd refusing the drop-in: the old file stays, exit 1, no reload. No
// symlink: install refuses before anything changes.
func TestConsoleInstallRefusals(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	dropin := sb.path("sshd_config.d", "tacctl-console.conf")
	sb.write("sshd_config.d/tacctl-console.conf", "old\n", 0o644)
	out := sb.rootRun([]string{"console", "install"}, func(r *fake.Runner) {
		r.Fail([]string{"sshd", "-t"}, 255, "line 6: Bad configuration option: DisableForwarding")
	})
	if sb.code != 1 || !strings.Contains(out, "sshd refused the console's drop-in; "+dropin+" was put back as it was:") ||
		!strings.Contains(out, "Bad configuration option: DisableForwarding") || sb.runner.Called("systemctl", "reload") {
		t.Errorf("refused: %d\n%s", sb.code, out)
	}
	if data, _ := os.ReadFile(dropin); string(data) != "old\n" {
		t.Errorf("drop-in %q", data)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	sb.write("shells", "/bin/bash\n", 0o644)
	out = sb.rootRun([]string{"console", "install"}, sshdOK(link))
	if sb.code != 1 || !strings.Contains(out, link+" is missing: the console is installed with tacctl itself. Run: tacctl upgrade") ||
		sb.runner.Called("sshd") {
		t.Errorf("no symlink: %d\n%s", sb.code, out)
	}
	if data, _ := os.ReadFile(sb.path("shells")); string(data) != "/bin/bash\n" {
		t.Errorf("shells changed: %q", data)
	}
}

// 'host enroll --local', its sync and unenroll: the shell field, the
// server's pieces before the script, the check after it, and the pieces
// gone at unenroll once the accounts have bash again.
func TestHostLocalConsole(t *testing.T) {
	hs := newHostSandbox(t)
	hs.reroot = true
	hs.loopback()
	hs.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	link := hs.path("usr", "local", "bin", "tacctl-console")
	dropin := hs.path("sshd_config.d", "tacctl-console.conf")
	script := ""
	runner := func(passwd string) *fake.Runner {
		r := hs.runner()
		sshdOK(link)(r)
		r.OnFunc([]string{"bash"}, func(c execx.Cmd) (execx.Result, error) {
			b, _ := os.ReadFile(c.Args[0])
			script = string(b)
			return execx.Result{Stdout: []byte("[INFO] Accounts: 3 managed by tacctl here; console: 2.\n")}, nil
		})
		r.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte(passwd)})
		return r
	}
	consoleUsers := "root:x:0:0::/root:/bin/bash\nalice:x:80000:80000:alice (TACACS+):/home/alice:" + link + "\n"

	// No symlink: nobody gets the console, and the command says so.
	hs.run(runner(""), "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, link+" is missing, so no account gets the login console now") ||
		!strings.Contains(script, "TAC_USERS=$'alice:superuser:80000:/bin/bash\\nbob:operator:80001:/bin/bash\\ncarol:readonly:80002:/bin/bash'") ||
		!strings.Contains(script, "\nTAC_LOCAL=1\nTAC_ENGINEER_SUDO=ALL\nTAC_PROTOCOL=") {
		t.Fatalf("no symlink: %d\n%s\n%s", hs.code, all, head(script))
	}
	if _, err := os.Stat(dropin); err == nil {
		t.Error("a drop-in without the console")
	}

	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hs.path("usr", "local", "bin", "tacctl"), link); err != nil {
		t.Fatal(err)
	}
	hs.cfgRun("", []string{"console", "user", "bob", "disable"}, nil)
	r := runner(consoleUsers)
	hs.run(r, "host", "sync", "authsrv")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(script, "TAC_USERS=$'alice:superuser:80000:"+link+"\\nbob:operator:80001:/bin/bash\\ncarol:readonly:80002:"+link+"'") {
		t.Fatalf("sync: %d\n%s\n%s", hs.code, all, head(script))
	}
	for _, want := range []string{"Installed: " + hs.path("shells") + " lists " + link, "Installed: sshd drop-in " + dropin,
		"authsrv: synced (3 users; 2 with the console).", "sshd for alice:", "The console's sshd settings are in effect."} {
		if !strings.Contains(all, want) {
			t.Errorf("sync lacks %q:\n%s", want, all)
		}
	}
	// The pieces before the script: sshd -t, the reload, then bash.
	order := []string{}
	for _, c := range r.Argvs() {
		if strings.HasPrefix(c, "sshd -t") || strings.HasPrefix(c, "systemctl reload") || strings.HasPrefix(c, "bash ") {
			order = append(order, strings.Fields(c)[0])
		}
	}
	if strings.Join(order, " ") != "sshd systemctl bash" {
		t.Errorf("order %v", order)
	}
	// Other hosts keep three fields.
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	if !strings.Contains(hs.pushed, "TAC_USERS=$'alice:superuser:80000\\nbob:operator:80001\\ncarol:readonly:80002'") {
		t.Errorf("remote host: %s", head(hs.pushed))
	}

	// Unenroll: the remove script ran; while an account keeps the console the
	// pieces stay (said); once none does, they go.
	r = runner(consoleUsers)
	hs.run(r, "host", "unenroll", "authsrv")
	all = plain(hs.out.String() + hs.err.String())
	if !strings.Contains(all, "These accounts still have the console as their login shell: alice") {
		t.Errorf("unenroll with a console account:\n%s", all)
	}
	if _, err := os.Stat(dropin); err != nil {
		t.Error("drop-in removed while alice has the console")
	}
	hs.run(runner(""), "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	hs.run(runner("root:x:0:0::/root:/bin/bash\n"), "host", "unenroll", "authsrv")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Removed: sshd drop-in") {
		t.Errorf("unenroll: %d\n%s", hs.code, all)
	}
	if _, err := os.Stat(dropin); err == nil {
		t.Error("drop-in left")
	}
}

func head(script string) string { return strings.SplitN(script, "# --- tacctl", 2)[0] }
