package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

type harness struct {
	app      *app.App
	runner   *fake.Runner
	out, err bytes.Buffer
}

// newHarness is an invocation as the bats suite makes it: TACCTL_SKIP_SUDO=1,
// not root.
func newHarness(t *testing.T, args []string, extraEnv ...string) *harness {
	t.Helper()
	h := &harness{runner: &fake.Runner{}}
	env := append([]string{"TACCTL_SKIP_SUDO=1", "PATH=/usr/bin"}, extraEnv...)
	h.app = app.New(args, paths.NewEnv(env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &h.out, Stderr: &h.err}, h.runner)
	return h
}

func (h *harness) run() error {
	return Run(context.Background(), h.app, BuildInfo{Version: "0.2.0-test", Commit: "abc123", Date: "2026-10-03T00:00:00Z"})
}

// commandPaths lists every command of the tree as its argv words.
func commandPaths(c *cobra.Command, prefix []string, out *[][]string) {
	for _, sub := range c.Commands() {
		p := append(append([]string(nil), prefix...), sub.Name())
		*out = append(*out, p)
		commandPaths(sub, p, out)
	}
}

// Every command of the tree has a Go handler: dispatch calls the RunE of
// the command it resolves.
func TestEveryCommandHasAHandler(t *testing.T) {
	var all [][]string
	root := newRoot(&invocation{app: newHarness(t, nil).app})
	commandPaths(root, nil, &all)
	if len(all) < 100 {
		t.Fatalf("tree has %d commands; the families of 1.2 are missing", len(all))
	}
	for _, p := range append(all, nil) {
		c, _ := resolve(root, p)
		if c.RunE == nil {
			t.Errorf("%q has no handler", p)
		}
	}
}

// The top-level dispatch of bin/tacctl.sh ('*) usage; exit 1'): no
// command, help, -h, --help and any word that is no command print the
// top-level usage on stdout and exit 1; cobra's defaults (help command,
// -h/--help, suggestions, completion) never intercept.
func TestTopLevelUsage(t *testing.T) {
	want := Usage("top", UsageVars{"version": "0.2.0-test"})
	for _, args := range [][]string{
		{}, {""}, {"help"}, {"-h"}, {"--help"}, {"bogus"}, {"-x", "user", "list"},
		{"--x=1", "user", "list"}, {"--", "version"}, {"Version"}, {"help", "version"}, {"User", "list"}, {"Hash"},
	} {
		h := newHarness(t, args)
		if code := exitCode(h.run(), h.app.Out); code != 1 || h.out.String() != want || h.err.Len() != 0 ||
			len(h.runner.Execs()) != 0 || len(h.runner.Calls()) != 0 {
			t.Errorf("%q: exit %d stdout %q stderr %q calls %q", args, code, h.out.String(), h.err.String(), h.runner.Argvs())
		}
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}, {"version", "extra"}, {"-v", "--long", "x"}} {
		h := newHarness(t, args)
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		want := "tacctl 0.2.0-test\n"
		if len(args) > 1 && args[1] == "--long" {
			want += "commit:     abc123\nbuilt:      2026-10-03T00:00:00Z (commit date)\ngo:         " +
				runtime.Version() + "\ntest knobs: " + map[bool]string{true: "on", false: "off"}[app.TestKnobs] + "\n"
		}
		if h.out.String() != want || h.err.Len() != 0 || len(h.runner.Execs()) != 0 {
			t.Errorf("%q: stdout %q stderr %q execs %d", args, h.out.String(), h.err.String(), len(h.runner.Execs()))
		}
	}
}

// 'version' is native behind the Go tier gate: a tier-managed caller
// (SUDO_USER in tac-users) with no tacctl user is denied, as bash denies
// it; anyone else gets the version.
func TestVersionTierCaller(t *testing.T) {
	h := newHarness(t, []string{"version"}, "SUDO_USER=bob")
	h.runner.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-operator\n")})
	h.runner.On([]string{"logger"}, execx.Result{})
	if code := exitCode(h.run(), h.app.Out); code != 1 || h.out.Len() != 0 || len(h.runner.Execs()) != 0 {
		t.Errorf("tier member without a user: exit %d, %q, %d execs", code, h.out.String(), len(h.runner.Execs()))
	}
	if !strings.Contains(h.err.String(), "'bob' has no active tacctl user") ||
		!h.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=bob tier=none cmd=version ") {
		t.Errorf("denial: %q %q", h.err.String(), h.runner.Argvs())
	}

	for _, c := range []struct {
		env  string
		res  execx.Result
		runs int
	}{
		{"SUDO_USER=bob", execx.Result{Stdout: []byte("bob adm sudo\n")}, 1},
		{"SUDO_USER=bob", execx.Result{Code: 1}, 1}, // no such user: unrestricted, as in bash
		{"SUDO_USER=root", execx.Result{}, 0},
		{"SUDO_USER=", execx.Result{}, 0},
	} {
		h := newHarness(t, []string{"version"}, c.env)
		h.runner.On([]string{"id"}, c.res)
		if err := h.run(); err != nil || h.out.String() != "tacctl 0.2.0-test\n" || len(h.runner.Execs()) != 0 {
			t.Errorf("%s %+v: %v %q", c.env, c.res, err, h.out.String())
		}
		if len(h.runner.Calls()) != c.runs {
			t.Errorf("%s: %d calls", c.env, len(h.runner.Calls()))
		}
	}
}

func TestReexecUnderSudo(t *testing.T) {
	mk := func(args []string, euid int, env ...string) *harness {
		h := &harness{runner: &fake.Runner{}}
		h.app = app.New(args, paths.NewEnv(env), "/usr/local/bin/tacctl", euid,
			app.Stdio{Stdout: &h.out, Stderr: &h.err}, h.runner)
		return h
	}
	cases := []struct {
		args []string
		env  []string
		want []string // sudo argv; nil: no re-exec
	}{
		{[]string{"user", "list"}, nil, []string{"sudo", "/usr/local/bin/tacctl", "user", "list"}},
		{nil, nil, []string{"sudo", "/usr/local/bin/tacctl"}},
		{[]string{"version"}, nil, []string{"sudo", "/usr/local/bin/tacctl", "version"}},
		{[]string{"host", "enroll", "h"}, []string{"SSH_AUTH_SOCK=/run/a.sock"}, []string{"sudo", "SSH_AUTH_SOCK=/run/a.sock", "/usr/local/bin/tacctl", "host", "enroll", "h"}},
		{[]string{"host", "list"}, []string{"SSH_AUTH_SOCK="}, []string{"sudo", "/usr/local/bin/tacctl", "host", "list"}},
		{[]string{"user", "list"}, []string{"SSH_AUTH_SOCK=/run/a.sock"}, []string{"sudo", "/usr/local/bin/tacctl", "user", "list"}},
		{[]string{"user", "list"}, []string{"TACCTL_SKIP_SUDO=0"}, []string{"sudo", "/usr/local/bin/tacctl", "user", "list"}},
		{[]string{"hash", "generate"}, nil, nil},
		{[]string{"completion", "bash"}, nil, nil},
		{[]string{"__complete", "user", ""}, nil, nil},
		{[]string{"__completeNoDesc", ""}, nil, nil},
		{[]string{"user", "list"}, []string{"TACCTL_SKIP_SUDO=1"}, nil},
	}
	for _, c := range cases {
		h := mk(c.args, 1000, c.env...)
		err := h.run()
		execs := h.runner.Execs()
		if c.want == nil {
			for _, e := range execs {
				if e.Argv[0] == "sudo" {
					t.Errorf("%q: re-exec'd under sudo", c.args)
				}
			}
			continue
		}
		if err != nil || len(execs) != 1 || execs[0].Path != "/fake/bin/sudo" || !reflect.DeepEqual(execs[0].Argv, c.want) {
			t.Errorf("%q: %v %+v, want %q", c.args, err, execs, c.want)
		}
		if len(execs) == 1 && !reflect.DeepEqual(execs[0].Env, h.app.Env.Environ()) {
			t.Errorf("%q: environment changed", c.args)
		}
	}
	// Root never re-execs.
	h := mk([]string{"version"}, 0)
	if err := h.run(); err != nil || len(h.runner.Execs()) != 0 || h.out.String() != "tacctl 0.2.0-test\n" {
		t.Errorf("root re-exec'd: %v %+v", err, h.runner.Execs())
	}
	// No sudo on PATH; exec failure; unknown executable.
	h = mk([]string{"host", "list"}, 1000)
	h.runner.Missing("sudo")
	if code := exitCode(h.run(), h.app.Out); code != 127 || !strings.Contains(h.err.String(), "sudo not found") {
		t.Errorf("missing sudo: %d %q", code, h.err.String())
	}
	h = mk([]string{"host", "list"}, 1000)
	h.runner.ExecErr = errors.New("EACCES")
	if code := exitCode(h.run(), h.app.Out); code != 126 {
		t.Errorf("sudo exec failure: %d", code)
	}
	h = mk([]string{"host", "list"}, 1000)
	h.app.Exe = ""
	if code := exitCode(h.run(), h.app.Out); code != 1 || len(h.runner.Execs()) != 0 {
		t.Errorf("unknown exe: %d", code)
	}
}

func TestComplete(t *testing.T) {
	h := newHarness(t, []string{"__complete", ""})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{}
	for _, l := range strings.Split(h.out.String(), "\n") {
		words[strings.SplitN(l, "\t", 2)[0]] = true
	}
	for _, w := range []string{"user", "group", "scope", "config", "host", "backend", "store", "log", "backup", "hash", "version", "install", "upgrade", "uninstall", "status", "passwd"} {
		if !words[w] {
			t.Errorf("top-level completion lacks %q:\n%s", w, h.out.String())
		}
	}
	for _, w := range []string{"help", "_completion-names", "completion", "--version", "-v"} {
		if words[w] {
			t.Errorf("top-level completion offers %q", w)
		}
	}
	if len(h.runner.Execs()) != 0 || len(h.runner.Calls()) != 0 {
		t.Error("completion ran something")
	}

	h = newHarness(t, []string{"__completeNoDesc", "config", "sudoers", ""})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(h.out.String()); !reflect.DeepEqual(got[:4], []string{"install", "remove", "show", "tiers"}) {
		t.Errorf("config sudoers completion = %q", got)
	}
}

// Assumption 15 (docs/plans/go-rewrite.md 11.2): with DisableFlagParsing on
// the root and the leaf, cobra's __complete still reaches the leaf's
// ValidArgsFunction and hands it the flags as plain arguments.
func TestCompleteReachesValidArgsWithFlagParsingOff(t *testing.T) {
	var gotArgs []string
	var gotToComplete string
	leaf := &cobra.Command{Use: "add", Hidden: false,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			gotArgs, gotToComplete = args, toComplete
			return []cobra.Completion{"ops", "admins"}, cobra.ShellCompDirectiveNoFileComp
		}}
	root := &cobra.Command{Use: "tacctl"}
	root.AddCommand(&cobra.Command{Use: "user"})
	root.Commands()[0].AddCommand(leaf)
	root.CompletionOptions.DisableDefaultCmd = true
	ran := func(*cobra.Command, []string) error { return errors.New("ran") }
	root.RunE, root.Commands()[0].RunE, leaf.RunE = ran, ran, ran
	configure(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"__complete", "user", "add", "alice", "--hash", "x", "-y", "o"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotArgs, []string{"alice", "--hash", "x", "-y"}) || gotToComplete != "o" {
		t.Errorf("ValidArgsFunction got %q, %q", gotArgs, gotToComplete)
	}
	if !strings.HasPrefix(out.String(), "ops\nadmins\n:4\n") {
		t.Errorf("completion output %q", out.String())
	}
}

func TestExitCode(t *testing.T) {
	var out, errb bytes.Buffer
	o := app.New(nil, paths.NewEnv(nil), "", 0, app.Stdio{Stdout: &out, Stderr: &errb}, &fake.Runner{}).Out
	cases := []struct {
		err  error
		code int
		msg  string
	}{
		{nil, 0, ""},
		{&ExitError{Code: 3}, 3, ""},
		{&ExitError{Code: 2, Err: errors.New("Unknown backend 'x'")}, 2, "\033[0;31m[ERROR]\033[0m Unknown backend 'x'\n"},
		{errors.New("boom"), 1, "\033[0;31m[ERROR]\033[0m boom\n"},
		{errorsJoin(&ExitError{Code: 20}), 20, ""},
		{ui.ErrInterrupted, 130, ""},
		{ui.ErrReported, 1, ""},
		{tier.ErrDenied, 1, ""},
		{backend.ErrRefused, 3, ""},
		{backend.ErrFailed, 1, ""},
		{&backend.UnknownError{ID: "x"}, 2, "\033[0;31m[ERROR]\033[0m Unknown backend 'x'.\n"},
		{store.ImportNotProven, 3, ""},
		{store.ErrNotInitialised, 1, "\033[0;31m[ERROR]\033[0m " + store.NotInitialisedMsg + "\n"},
		{&store.ExistsError{Path: "/s"}, 1, "\033[0;31m[ERROR]\033[0m Store already exists at /s.\n"},
		{&store.NotFoundError{Path: "/s"}, 1, "\033[0;31m[ERROR]\033[0m Store not found at /s.\n"},
		{store.ErrSeedUsage, 1, "\033[0;31m[ERROR]\033[0m " + store.SeedUsage + "\n"},
		{&model.NoSourceError{Store: "/s", Config: "/c"}, 1, "\033[0;31m[ERROR]\033[0m No store at /s and no config at /c.\n"},
		{&names.Error{Msgs: []string{"a", "b"}}, 1, "\033[0;31m[ERROR]\033[0m a\n\033[0;31m[ERROR]\033[0m b\n"},
		{&store.Error{Msg: "bad"}, 1, "tacctl store: bad\n"},
		{&conf.ValidationError{Path: "x.y", Msg: "no"}, 1, ""}, // its plain line: set below
		{&conf.ParseError{Path: "/o", Why: "bad"}, 1, ""},      // its [ERROR] lines: set below
	}
	for _, c := range cases {
		errb.Reset()
		switch e := c.err.(type) {
		case *conf.ValidationError:
			c.msg = e.Error() + "\n"
		case *conf.ParseError:
			c.msg = ""
			for _, l := range e.Lines() {
				c.msg += "\033[0;31m[ERROR]\033[0m " + l + "\n"
			}
		}
		if got := exitCode(c.err, o); got != c.code || errb.String() != c.msg {
			t.Errorf("%v: %d %q, want %d %q", c.err, got, errb.String(), c.code, c.msg)
		}
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q", out.String())
	}
	if (&ExitError{Code: 4}).Error() != "exit status 4" || (&ExitError{Code: 1, Err: errors.New("x")}).Error() != "x" {
		t.Error("ExitError.Error")
	}
	if !errors.Is(&ExitError{Code: 1, Err: context.Canceled}, context.Canceled) {
		t.Error("ExitError does not unwrap")
	}
}

func errorsJoin(err error) error { return errors.Join(errors.New("context"), err) }

func TestSudoArgv(t *testing.T) {
	sock := func(v string) func(string) string {
		return func(name string) string {
			if name == "SSH_AUTH_SOCK" {
				return v
			}
			return "other"
		}
	}
	if got := sudoArgv("/x", []string{"host", "sync", "--all"}, sock("/s")); !reflect.DeepEqual(got, []string{"sudo", "SSH_AUTH_SOCK=/s", "/x", "host", "sync", "--all"}) {
		t.Errorf("host: %q", got)
	}
	if got := sudoArgv("/x", []string{"host", "list"}, sock("")); !reflect.DeepEqual(got, []string{"sudo", "/x", "host", "list"}) {
		t.Errorf("host without a socket: %q", got)
	}
	if got := sudoArgv("/x", []string{"scope", "host"}, sock("/s")); !reflect.DeepEqual(got, []string{"sudo", "/x", "scope", "host"}) {
		t.Errorf("not host: %q", got)
	}
	if got := sudoArgv("/x", nil, sock("/s")); !reflect.DeepEqual(got, []string{"sudo", "/x"}) {
		t.Errorf("no args: %q", got)
	}
}

func TestBuildInfoResolved(t *testing.T) {
	stamped := BuildInfo{Version: "0.2.0", Commit: "c", Date: "d"}
	if got := stamped.resolved(func() (*debug.BuildInfo, bool) { t.Error("read build info needlessly"); return nil, false }); got != stamped {
		t.Errorf("stamped: %+v", got)
	}
	vcs := func(modified string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "62adc79aaaabbbb"}, {Key: "vcs.time", Value: "2026-10-03T01:02:03Z"}, {Key: "vcs.modified", Value: modified},
			}}, true
		}
	}
	if got := (BuildInfo{}).resolved(vcs("true")); got != (BuildInfo{Version: "62adc79-dirty", Commit: "62adc79aaaabbbb", Date: "2026-10-03T01:02:03Z"}) {
		t.Errorf("vcs dirty: %+v", got)
	}
	if got := (BuildInfo{Version: "v"}).resolved(vcs("false")); got != (BuildInfo{Version: "v", Commit: "62adc79aaaabbbb", Date: "2026-10-03T01:02:03Z"}) {
		t.Errorf("vcs partial: %+v", got)
	}
	none := func() (*debug.BuildInfo, bool) { return nil, false }
	if got := (BuildInfo{}).resolved(none); got != (BuildInfo{Version: "unknown", Commit: "unknown", Date: "unknown"}) {
		t.Errorf("nothing: %+v", got)
	}
}

// Main end to end, in-process: 'version' needs neither sudo nor bash.
func TestMain(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"tacctl", "version"}, []string{"TACCTL_SKIP_SUDO=1"}, app.Stdio{Stdout: &out, Stderr: &errb}, BuildInfo{Version: "9.9.9", Commit: "c", Date: "d"})
	if code != 0 || out.String() != "tacctl 9.9.9\n" || errb.Len() != 0 {
		t.Errorf("Main: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	// (A word that runs nothing: Main runs programs for real.)
	code = Main([]string{"tacctl", "bogus"}, []string{"TACCTL_SKIP_SUDO=1"}, app.Stdio{Stdout: &out, Stderr: &errb}, BuildInfo{Version: "9.9.9"})
	if code != 1 || out.String() != Usage("top", UsageVars{"version": "9.9.9"}) || errb.Len() != 0 {
		t.Errorf("Main usage: %d %q", code, errb.String())
	}
}
