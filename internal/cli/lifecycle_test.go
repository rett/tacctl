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
// closed stdin cancels with exit 0, nothing run; -y is accepted; --branch
// without a value is the silent exit 1 of 0.1.16.
func TestLifecycleVerbsThroughTheCLI(t *testing.T) {
	sb := lifecycleSandbox(t)
	out := sb.run("", []string{"install", "--branch", "feature/x", "extra"})
	sb.expect(0, "  tacctl Installer", "")
	deploy, command := filepath.Join(sb.dir, "opt", "tacctl"), filepath.Join(sb.dir, "usr", "local", "bin", "tacctl")
	if !strings.Contains(out, "Install tacctl ("+deploy+", "+command+") and its state directory ("+sb.path("state")+")") ||
		!strings.HasSuffix(plain(out), "[INFO] Cancelled.\n") || len(sb.runner.Calls()) != 0 {
		t.Errorf("install: %q calls %q", out, sb.runner.Argvs())
	}
	for _, args := range [][]string{{"install", "--branch"}, {"upgrade", "--branch"}, {"upgrade", "--branch", "x", "--branch"}} {
		sb.run("", args)
		if sb.code != 1 || sb.out.Len() != 0 || sb.err.Len() != 0 || len(sb.runner.Calls()) != 0 {
			t.Errorf("%q: exit %d %q %q %q", args, sb.code, sb.out.String(), sb.err.String(), sb.runner.Argvs())
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
