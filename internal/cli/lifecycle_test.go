package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/paths"
)

// lifecycleSandbox is a sandbox for install, upgrade and uninstall through
// the CLI: every TACCTL_* path under it (sandboxPathEnv), tacctl's fixed
// host locations too (sandbox.run reroots them).
func lifecycleSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, false)
	sb.env = append(sb.env, sandboxPathEnv(sb.dir)...)
	return sb
}

// install, upgrade and uninstall are native: the plan and the prompt, a
// closed stdin cancels with exit 0, nothing run; -y is accepted where it
// exists; an unknown argument, or --branch without a value, is refused with
// the usage before anything runs.
func TestLifecycleVerbsThroughTheCLI(t *testing.T) {
	sb := lifecycleSandbox(t)
	out := sb.run("", []string{"install", "--branch", "feature/x"})
	sb.expect(0, "  tacctl Installer", "")
	deploy, command := filepath.Join(sb.dir, "opt", "tacctl"), filepath.Join(sb.dir, "usr", "local", "bin", "tacctl")
	if !strings.Contains(out, "Install tacctl ("+deploy+", "+command+") and its state directory ("+sb.path("state")+")") ||
		!strings.HasSuffix(plain(out), "[INFO] Cancelled.\n") || len(sb.runner.Calls()) != 0 {
		t.Errorf("install: %q calls %q", out, sb.runner.Argvs())
	}
	for _, c := range []struct {
		args       []string
		bad, usage string
	}{
		{[]string{"install", "--branch"}, "--branch", "Usage: tacctl install [--branch <name>] [-y|--yes]"},
		{[]string{"install", "-y", "extra", "--branch", "x"}, "extra", "Usage: tacctl install [--branch <name>] [-y|--yes]"},
		{[]string{"upgrade", "--branch"}, "--branch", "Usage: tacctl upgrade [--branch <name>]"},
		{[]string{"upgrade", "--branch", "x", "--branch"}, "--branch", "Usage: tacctl upgrade [--branch <name>]"},
		{[]string{"upgrade", "-y"}, "-y", "Usage: tacctl upgrade [--branch <name>]"},
		{[]string{"upgrade", "--yes"}, "--yes", "Usage: tacctl upgrade [--branch <name>]"},
		{[]string{"uninstall", "--branch", "x"}, "--branch", "Usage: tacctl uninstall [-y|--yes]"},
		{[]string{"uninstall", "-y", "now"}, "now", "Usage: tacctl uninstall [-y|--yes]"},
	} {
		sb.run("", c.args)
		want := "[ERROR] Unknown argument: '" + c.bad + "'\n[ERROR] " + c.usage + "\n"
		if sb.code != 1 || sb.out.Len() != 0 || plain(sb.err.String()) != want || len(sb.runner.Calls()) != 0 {
			t.Errorf("%q: exit %d %q %q %q", c.args, sb.code, sb.out.String(), sb.err.String(), sb.runner.Argvs())
		}
	}
	out = sb.run("n\n", []string{"uninstall"})
	sb.expect(0, "tacctl Uninstaller", "")
	if !strings.Contains(out, "  - Management repo ("+deploy+")") || !strings.HasSuffix(plain(out), "[INFO] Cancelled.\n") {
		t.Errorf("uninstall: %q", out)
	}
}

// A whole 'uninstall -y' through the CLI on a sandboxed install: the real
// TACACS+ module's phases, every file of tacctl's gone, nothing outside.
func TestUninstallThroughTheCLI(t *testing.T) {
	sb := lifecycleSandbox(t)
	p := paths.Resolve(paths.NewEnv(sb.env), "", nil).Reroot(sb.dir)
	for _, f := range []string{p.Command, p.Completion, p.ManPage, p.SudoersFile, filepath.Join(p.Deploy, "bin", "tacctl.sh"),
		filepath.Join(p.LinuxDir, "pam_tacplus-1.7.0.tar.gz"), p.StoreFile, filepath.Join(p.Etc, "tacquito.yaml")} {
		sb.write(strings.TrimPrefix(f, sb.dir+"/"), "x\n", 0o600)
	}
	sb.run("", []string{"uninstall", "-y"})
	sb.expect(0, "  Uninstall Complete", "")
	for _, f := range []string{p.Command, p.Completion, p.ManPage, p.SudoersFile, p.Deploy, p.LinuxDir, p.StateDir, p.Etc} {
		if _, err := os.Lstat(f); err == nil {
			t.Errorf("%s left", f)
		}
	}
	if !sb.runner.Called("systemctl", "daemon-reload") {
		t.Errorf("the TACACS+ phases did not run: %q", sb.runner.Argvs())
	}
	for _, c := range sb.runner.Calls() {
		if c.Name == "userdel" || c.Name == "tar" {
			continue
		}
		for _, a := range c.Args {
			if strings.HasPrefix(a, "/") && !strings.HasPrefix(a, sb.dir) && a != "/usr/sbin/nologin" {
				t.Errorf("%q reaches outside the sandbox", c.Argv())
			}
		}
	}
}
