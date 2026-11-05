package lifecycle_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/gitx/gitxtest"
)

// The network git commands of tacctl's own clone (the clone, the fetch and
// the pull of 'upgrade' and of 'install') cannot wait for an operator who is
// not there, as those of the tacquito source: no prompt on the terminal, no
// passphrase prompt, a transfer that stalls is dropped (gitx.Net). The
// commands are looked at as they were made (fake.Runner.Raw), and none may
// be a bare 'git fetch', 'git pull' or 'git clone'.
const batch = "ssh -o BatchMode=yes"

// deployGit is the commands of raw that are about the clone at deploy (run in
// it, or naming it): the stand-in backend of the matrix host fetches the
// tacquito source bare, which is not what is looked at here.
func deployGit(raw []execx.Cmd, deploy string) []execx.Cmd {
	var out []execx.Cmd
	for _, c := range raw {
		if c.Dir == deploy || slices.Contains(c.Args, deploy) {
			out = append(out, c)
		}
	}
	return out
}

func TestUpgradeNetworkGitCannotPrompt(t *testing.T) {
	t.Run("clone", func(t *testing.T) {
		o := newOhost(t)
		_ = os.MkdirAll(o.p.Deploy, 0o755)
		o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "")
		_ = os.RemoveAll(o.p.Deploy)
		upgrade(o)
		gitxtest.Check(t, deployGit(o.run.Raw(), o.p.Deploy), batch, "clone")
	})
	t.Run("fetch and pull", func(t *testing.T) {
		h := newMatrixHost(t)
		h.remote["develop"] = commitNew
		if err := h.upgrade(); err != nil {
			t.Fatalf("upgrade: %v\n%s", err, h.stderr)
		}
		gitxtest.Check(t, deployGit(h.Run.Raw(), h.Deploy), batch, "fetch", "pull")
	})
	t.Run("branch", func(t *testing.T) {
		h := newMatrixHost(t)
		if err := h.upgrade("--branch", "feature/x"); err != nil {
			t.Fatalf("upgrade: %v\n%s", err, h.stderr)
		}
		gitxtest.Check(t, deployGit(h.Run.Raw(), h.Deploy), batch, "fetch", "fetch")
	})
	t.Run("fetch alone", func(t *testing.T) {
		h := newMatrixHost(t)
		if err := h.upgrade(); err != nil {
			t.Fatalf("upgrade: %v\n%s", err, h.stderr)
		}
		gitxtest.Check(t, deployGit(h.Run.Raw(), h.Deploy), batch, "fetch")
	})
	t.Run("configured remote shell", func(t *testing.T) {
		h := newMatrixHost(t)
		h.Run.On([]string{"git", "config", "--get", "core.sshCommand"}, execx.Result{Stdout: []byte("ssh -i /etc/tacctl/deploy-key\n")})
		if err := h.upgrade(); err != nil {
			t.Fatalf("upgrade: %v\n%s", err, h.stderr)
		}
		gitxtest.Check(t, deployGit(h.Run.Raw(), h.Deploy), "ssh -i /etc/tacctl/deploy-key -o BatchMode=yes", "fetch")
	})
	t.Run("a failed fetch ends the upgrade as before", func(t *testing.T) {
		h := newMatrixHost(t)
		h.remote["develop"] = commitNew
		h.Run.When(func(c execx.Cmd) bool { return slices.Contains(gitIn(c, h.Deploy), "fetch") },
			execx.Result{Code: 128, Stderr: []byte(fetchOffline)}, nil)
		if err := h.upgrade(); matrixCode(err) != 1 {
			t.Fatalf("exit %d", matrixCode(err))
		}
		h.errHas("[ERROR] git fetch failed. Check network / credentials.")
		gitxtest.Check(t, deployGit(h.Run.Raw(), h.Deploy), batch, "fetch")
	})
}

func TestInstallNetworkGitCannotPrompt(t *testing.T) {
	t.Run("clone", func(t *testing.T) {
		o := newOhost(t)
		if code := install(o, "--branch", "develop", "--yes"); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
		}
		gitxtest.Check(t, deployGit(o.run.Raw(), o.p.Deploy), batch, "clone")
	})
	t.Run("pull", func(t *testing.T) {
		o := newOhost(t)
		o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "#!/bin/bash\n")
		_ = os.MkdirAll(filepath.Join(o.p.Deploy, ".git"), 0o755)
		if code := install(o, "--branch", "develop", "--yes"); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
		}
		gitxtest.Check(t, deployGit(o.run.Raw(), o.p.Deploy), batch, "pull")
	})
	t.Run("configured remote shell", func(t *testing.T) {
		o := newOhost(t)
		o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "#!/bin/bash\n")
		_ = os.MkdirAll(filepath.Join(o.p.Deploy, ".git"), 0o755)
		o.run.On([]string{"git", "config", "--get", "core.sshCommand"}, execx.Result{Stdout: []byte("ssh -i /etc/tacctl/deploy-key\n")})
		if code := install(o, "--yes"); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
		}
		gitxtest.Check(t, deployGit(o.run.Raw(), o.p.Deploy), "ssh -i /etc/tacctl/deploy-key -o BatchMode=yes", "pull")
	})
}
