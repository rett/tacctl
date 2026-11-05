package gitx_test

import (
	"context"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/gitx"
	"github.com/rett/tacctl/internal/gitx/gitxtest"
)

// A network git command ends a prompt (no terminal, no askpass, no ssh
// askpass), runs ssh in BatchMode and drops a stalled transfer; the rest of
// the command is as it was.
func TestNetCannotPrompt(t *testing.T) {
	var f fake.Runner
	in := execx.Cmd{Name: "git", Args: []string{"fetch", "--tags", "--force"}, Dir: "/srv/clone", Stdout: &strings.Builder{}}
	c := gitx.Net(context.Background(), &f, in)
	want := []string{"env", "-u", "SSH_ASKPASS", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=false",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes", "git", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60", "fetch", "--tags", "--force"}
	if got := c.Argv(); !slices.Equal(got, want) {
		t.Errorf("argv %q, want %q", got, want)
	}
	if c.Dir != "/srv/clone" || c.Stdout != in.Stdout {
		t.Errorf("dir %q, stdout kept %v", c.Dir, c.Stdout == in.Stdout)
	}
	// The remote shell is looked up in the clone, once.
	if got := f.Argvs(); !slices.Equal(got, []string{"git config --get core.sshCommand"}) || f.Calls()[0].Dir != "/srv/clone" {
		t.Errorf("lookup %q in %q", got, f.Calls()[0].Dir)
	}
	if lacks := gitxtest.Lacks(c, "ssh -o BatchMode=yes"); len(lacks) != 0 {
		t.Errorf("lacks %v", lacks)
	}
}

// The core.sshCommand of the clone is the remote shell, with BatchMode after
// it; an empty one, or a lookup that fails, is plain ssh. With '-C <dir>' the
// lookup is made there too.
func TestNetRemoteShell(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		code      int
		args      []string
		verb      string
		lookup    string
		want      string
	}{
		{"configured", "ssh -i /etc/tacctl/deploy-key\n", 0, []string{"fetch"}, "fetch", "git config --get core.sshCommand", "ssh -i /etc/tacctl/deploy-key -o BatchMode=yes"},
		{"empty", "\n", 0, []string{"fetch"}, "fetch", "git config --get core.sshCommand", "ssh -o BatchMode=yes"},
		{"unset", "", 1, []string{"fetch"}, "fetch", "git config --get core.sshCommand", "ssh -o BatchMode=yes"},
		{"-C dir", "ssh -i /k\n", 0, []string{"-C", "/srv/clone", "pull", "--quiet"}, "pull", "git -C /srv/clone config --get core.sshCommand", "ssh -i /k -o BatchMode=yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f fake.Runner
			f.On([]string{"git"}, execx.Result{Stdout: []byte(tc.out), Code: tc.code})
			c := gitx.Net(context.Background(), &f, execx.Cmd{Name: "git", Args: tc.args})
			if got := f.Argvs(); !slices.Equal(got, []string{tc.lookup}) {
				t.Errorf("lookup %q, want %q", got, tc.lookup)
			}
			if !slices.Contains(c.Args, "GIT_SSH_COMMAND="+tc.want) {
				t.Errorf("%q: want GIT_SSH_COMMAND=%q", c.Args, tc.want)
			}
			if got := gitxtest.Verb(c); got != tc.verb {
				t.Errorf("verb %q", got)
			}
		})
	}
}

// A clone has no '-C' and no Dir: the remote shell is not read in tacctl's
// working directory (a checkout the operator stands in would leak its local
// configuration into the clone) but from "/", where only the global and system
// configuration apply. A command with a Dir, or with '-C', keeps looking there.
func TestNetCloneLookupIsNotInTheWorkingDirectory(t *testing.T) {
	var f fake.Runner
	gitx.Net(context.Background(), &f, execx.Cmd{Name: "git", Args: []string{"clone", "--quiet", "https://git.example.net/tacctl.git", "/srv/clone"}})
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Dir != "/" || !slices.Equal(calls[0].Argv(), []string{"git", "config", "--get", "core.sshCommand"}) {
		t.Fatalf("lookup %q in %q", f.Argvs(), calls[0].Dir)
	}
	var g fake.Runner
	gitx.Net(context.Background(), &g, execx.Cmd{Name: "git", Args: []string{"-C", "/srv/clone", "pull"}})
	if d := g.Calls()[0].Dir; d != "" {
		t.Errorf("-C lookup in %q, want it left to -C", d)
	}
}

// Unwrap undoes Net, and leaves any other command alone.
func TestUnwrap(t *testing.T) {
	var f fake.Runner
	in := execx.Cmd{Name: "git", Args: []string{"-C", "/srv/clone", "pull", "--ff-only"}, Dir: "/x"}
	if got := gitx.Unwrap(gitx.Net(context.Background(), &f, in)); got.Name != "git" || !slices.Equal(got.Args, in.Args) || got.Dir != "/x" {
		t.Errorf("unwrapped %q", got.Argv())
	}
	// Every other field of the command survives, for the rules of a fake.
	cred := &syscall.Credential{Uid: 1}
	full := execx.Cmd{Name: "git", Args: []string{"fetch"}, Stdin: strings.NewReader("x"), Env: []string{"A=1"},
		Dir: "/x", AsUser: "tester", UserEnv: []string{"B=2"}, Credential: cred, Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Detach: true}
	got := gitx.Unwrap(gitx.Net(context.Background(), &f, full))
	if got.Name != "git" || !slices.Equal(got.Args, full.Args) || got.Stdin != full.Stdin || !slices.Equal(got.Env, full.Env) ||
		got.Dir != full.Dir || got.AsUser != full.AsUser || !slices.Equal(got.UserEnv, full.UserEnv) || got.Credential != cred ||
		got.Stdout != full.Stdout || got.Stderr != full.Stderr || !got.Detach {
		t.Errorf("unwrapped %+v lost a field of %+v", got, full)
	}
	for _, c := range []execx.Cmd{{Name: "git", Args: []string{"status"}}, {Name: "env", Args: []string{"A=1", "ls"}}} {
		if got := gitx.Unwrap(c); got.Name != c.Name || !slices.Equal(got.Args, c.Args) {
			t.Errorf("%q changed to %q", c.Argv(), got.Argv())
		}
	}
}

// The check a call site is held to: bare, unguarded and missing commands
// are found.
func TestCheckFindsABypass(t *testing.T) {
	var f fake.Runner
	good := gitx.Net(context.Background(), &f, execx.Cmd{Name: "git", Args: []string{"fetch"}})
	var rec recorder
	gitxtest.Check(&rec, []execx.Cmd{good}, "ssh -o BatchMode=yes", "fetch")
	if rec.n != 0 {
		t.Fatalf("a guarded fetch fails: %v", rec.msgs)
	}
	for name, raw := range map[string][]execx.Cmd{
		"bare fetch":   {{Name: "git", Args: []string{"fetch", "--tags"}}},
		"bare -C pull": {{Name: "git", Args: []string{"-C", "/srv/clone", "pull"}}},
		"bare clone":   {{Name: "git", Args: []string{"clone", "--quiet", "x", "y"}}},
		"env without":  {{Name: "env", Args: []string{"A=1", "git", "fetch"}}},
		"missing":      nil,
	} {
		rec = recorder{}
		gitxtest.Check(&rec, raw, "ssh -o BatchMode=yes", "fetch")
		if rec.n == 0 {
			t.Errorf("%s: not found", name)
		}
	}
}

// recorder is a testing.TB that counts failures.
type recorder struct {
	testing.TB
	n    int
	msgs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(f string, a ...any) {
	r.n++
	r.msgs = append(r.msgs, f)
}
