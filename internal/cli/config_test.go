package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// The config family in-process. The bytes are pinned against 0.1.16 by
// tests/diff/corpus/config.txt and the bats files (config_setters,
// config_metrics_sudoers, config_render, listeners, characterisation); these
// pin the wiring: which verbs are native, preflight, the runner calls,
// files written, exit codes, and the new 'render --dry-run'.

// cfgRun is sandbox.run with a hook that scripts the fake runner first.
func (sb *sandbox) cfgRun(stdin string, args []string, script func(*fake.Runner), extraEnv ...string) string {
	sb.t.Helper()
	sb.out.Reset()
	sb.err.Reset()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	sb.runner.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	if script != nil {
		script(sb.runner)
	}
	a := app.New(args, paths.NewEnv(append(append([]string(nil), sb.env...), extraEnv...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(stdin), Stdout: &sb.out, Stderr: &sb.err}, sb.runner)
	sb.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}), a.Out)
	if n := len(sb.runner.Execs()); n != 0 {
		sb.t.Errorf("%q: exec'd (%d execs)", args, n)
	}
	return sb.out.String()
}

func (sb *sandbox) path(p ...string) string { return filepath.Join(append([]string{sb.dir}, p...)...) }

// Every config verb has a handler; the family itself prints its usage and
// exits 1.
func TestConfigVerbsAllNative(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	native := map[string]bool{}
	for _, c := range configCmd(inv).Commands() {
		if c.RunE == nil {
			t.Errorf("config %s has no handler", c.Name())
		}
		native[c.Name()] = true
	}
	for _, w := range []string{"show", "validate", "render", "dump", "defaults", "get", "get-list", "loglevel", "listen",
		"metrics", "sudoers", "password-age", "bcrypt-cost", "password-min-length", "secret-min-length", "branch",
		"diff", "restore", "allow", "deny", "mgmt-acl", "cisco", "juniper", "wti", "linux"} {
		if !native[w] {
			t.Errorf("config %s is missing", w)
		}
	}
	for _, args := range [][]string{{"config"}, {"config", "help"}, {"config", "-h"}, {"config", "--help"}, {"config", "bogus", "x"}} {
		sb := newSandbox(t, true)
		// (stderr has preflight's warning that tacquito.yaml is missing)
		if out := sb.run("", args); out != configUsage() || sb.code != 1 || strings.Contains(sb.err.String(), "[ERROR]") {
			t.Errorf("%q: exit %d %q %q", args, sb.code, out, sb.err.String())
		}
	}
}

// registerConfigVerb is the hook for a family file of its own (allow, deny,
// mgmt-acl, the device verbs): the registered command joins the family (or
// replaces a declared word of the same name), keeps the family's preflight
// and brings its Spec.
func TestRegisterConfigVerb(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	before := len(configCmd(inv).Commands())
	const name = "test-verb"
	registerConfigVerb(name, Spec{MaxArgs: 1, Args: []string{"list|add"}}, func(inv *invocation) *cobra.Command {
		c := verb(name, "a test verb")
		c.RunE = inv.native(withPreflight, func(args []string) error {
			inv.write(name + " " + strings.Join(args, " ") + "\n")
			return nil
		})
		return c
	})
	t.Cleanup(func() {
		delete(configVerbs, name)
		delete(configSpecs, name)
	})
	if n := len(configCmd(inv).Commands()); n != before+1 {
		t.Errorf("%d config verbs after registering one, %d before", n, before)
	}
	sb := newSandbox(t, true)
	if out := sb.run("", []string{"config", name, "list"}); out != name+" list\n" || sb.code != 0 {
		t.Errorf("registered verb: %d %q %q", sb.code, out, sb.err.String())
	}
	// Preflight still runs: no store and no tacquito.yaml is refused.
	sb = newSandbox(t, false)
	sb.run("", []string{"config", name, "list"})
	sb.expect(1, "", "Config not found")
}

// Every native config verb has a Spec, and every kind it names is one
// completion can answer.
func TestConfigSpecs(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	n := 0
	for _, c := range configCmd(inv).Commands() {
		if c.RunE == nil {
			continue
		}
		n++
		spec, ok := configSpecs[c.Name()]
		if !ok {
			t.Errorf("config %s has no spec", c.Name())
			continue
		}
		kinds := append([]string(nil), spec.Args...)
		for _, f := range spec.Flags {
			kinds = append(kinds, f.Kind)
		}
		for _, k := range kinds {
			k = strings.TrimSuffix(k, KindList)
			_, model := completionKinds[k]
			_, other := completionArgKinds[k]
			if k != "" && !model && !other && !strings.Contains(k, "|") && k != KindFile {
				t.Errorf("config %s: kind %q is no completion kind", c.Name(), k)
			}
		}
	}
	if n != len(configSpecs) {
		t.Errorf("%d specs for %d native verbs", len(configSpecs), n)
	}
}

func TestConfigPreflight(t *testing.T) {
	// No store and no tacquito.yaml: every verb is refused by preflight,
	// render included (it skips preflight only when the store exists).
	for _, args := range [][]string{{"config", "show"}, {"config", "render"}, {"config", "get", "bcrypt.cost"}, {"config"}} {
		sb := newSandbox(t, false)
		sb.run("", args)
		sb.expect(1, "", "Config not found: no store at")
	}
	// A store and no tacquito.yaml: render runs no preflight (no warning),
	// the others warn that the file is missing.
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	if sb.code != 0 || strings.Contains(sb.err.String(), "is missing") {
		t.Errorf("render: %d %q", sb.code, sb.err.String())
	}
	sb = newSandbox(t, true)
	sb.run("", []string{"config", "get", "bcrypt.cost"})
	sb.expect(0, "12", "is missing; 'tacctl config render' writes it again.")
}

func TestConfigGetAndTunables(t *testing.T) {
	sb := newSandbox(t, true)
	cases := []struct {
		args      []string
		code      int
		out, errs string
	}{
		{[]string{"config", "get"}, 1, "", "Usage: tacctl config get <dotted.path> [fallback]"},
		{[]string{"config", "get-list"}, 1, "", "Usage: tacctl config get-list <dotted.path>"},
		{[]string{"config", "get", "bcrypt.cost"}, 0, "12\n", ""},
		{[]string{"config", "get", "no.such", "fb"}, 0, "fb\n", ""},
		{[]string{"config", "bcrypt-cost", "11"}, 0, "Bcrypt cost set to 11.", ""},
		{[]string{"config", "bcrypt-cost"}, 0, "Bcrypt cost factor: 11", ""},
		{[]string{"config", "bcrypt-cost", "15"}, 1, "", "must be <= 14"},
		{[]string{"config", "password-age", "30"}, 0, "Password age warning threshold set to 30 days.", ""},
		{[]string{"config", "password-min-length", "9"}, 0, "Password minimum length set to 9.", ""},
		{[]string{"config", "secret-min-length", "20"}, 0, "Shared-secret minimum length set to 20.", ""},
		{[]string{"config", "secret-min-length"}, 0, "Shared-secret minimum length: 20", ""},
		{[]string{"config", "defaults"}, 0, "# tacctl canonical defaults", ""},
		{[]string{"config", "dump"}, 0, "--- Effective (merged) ---", ""},
	}
	for _, c := range cases {
		out := sb.run("", c.args)
		if sb.code != c.code || !strings.Contains(plain(out), c.out) || !strings.Contains(plain(sb.err.String()), c.errs) {
			t.Errorf("%q: exit %d %q %q", c.args, sb.code, out, sb.err.String())
		}
	}
	if got := sb.run("", []string{"config", "get-list", "bcrypt.cost"}); got != "" {
		t.Errorf("get-list of a scalar: %q", got)
	}
	// A tacctl.yaml that does not parse: the setter refuses with the two
	// [ERROR] lines and writes nothing.
	if err := os.WriteFile(sb.path("state", "tacctl.yaml"), []byte("a: [1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "bcrypt-cost", "10"})
	sb.expect(1, "", "nothing was written")
}

func TestConfigLoglevelMetricsListen(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "Rendered", "")
	out := sb.run("", []string{"config", "loglevel"})
	sb.expect(0, "Current log level: info (20)", "")
	sb.run("", []string{"config", "loglevel", "debug"})
	sb.expect(0, "Log level changed to debug (30). Service restarted.", "")
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("loglevel restarts nothing: %q", sb.runner.Argvs())
	}
	sb.run("", []string{"config", "loglevel", `tr\tace`})
	if sb.code != 1 || !strings.Contains(sb.err.String(), "Invalid level: tr\tace.") {
		t.Errorf("bad level: %d %q (%q)", sb.code, sb.err.String(), out)
	}
	sb.run("", []string{"config", "metrics", "bogus"})
	sb.expect(1, "", "Run 'tacctl config metrics' with no arguments for usage.")
	sb.run("", []string{"config", "metrics", "address", "10.1.0.1:9090"})
	sb.expect(0, "Metrics listen address set to 10.1.0.1:9090.", "")
	sb.run("", []string{"config", "metrics"})
	sb.expect(0, "10.1.0.1:9090  (override)", "")

	sb.run("", []string{"config", "listen"})
	sb.expect(0, "Current listener: tcp :49", "")
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"config", "listen", "--backend"}, "--backend needs a value. Usage:"},
		{[]string{"config", "listen", "--listener", ""}, "--listener needs a value."},
		{[]string{"config", "listen", "--backend=ldap"}, "Unknown backend 'ldap' (known: tacacs radius)."},
		{[]string{"config", "listen", "--listener=Bad"}, "Invalid listener name 'Bad'"},
		{[]string{"config", "listen", "--bogus"}, "Invalid subcommand: '--bogus'. Use: show, tcp, tcp6, or reset"},
	} {
		sb.run("", c.args)
		sb.expect(1, "", c.err)
	}
	sb.run("", []string{"config", "listen", "--listener", "mgmt", "tcp", "127.0.0.1:4949"})
	sb.expect(0, "", "")
	if got := sb.run("", []string{"_completion-names", "listeners", "tacacs"}); got != "default\nmgmt\n" || sb.code != 0 {
		t.Errorf("listener names: %d %q", sb.code, got)
	}
	got := sb.run("", []string{"_completion-names", "listeners"})
	if !strings.Contains(got, "acct\n") || !strings.Contains(got, "auth\n") || !strings.Contains(got, "mgmt\n") {
		t.Errorf("every backend's listener names: %q", got)
	}
	if got := sb.run("", []string{"_completion-names", "listeners", "ldap"}); got != "" || sb.code != 0 {
		t.Errorf("unknown backend: %d %q", sb.code, got)
	}
	sb.run("", []string{"config", "listen", "--backend=radius", "--listener=auth"})
	sb.expect(0, "Usage: tacctl config listen --backend radius --listener <name> <network> <address>", "")
}

func TestConfigSudoers(t *testing.T) {
	sb := newSandbox(t, true)
	file := sb.path("sudoers.d", "tacctl")
	tiers := sb.path("sudoers.d", "tacctl-tiers")
	env := []string{"TACCTL_SUDOERS_FILE=" + file, "TACCTL_TIER_SUDOERS_FILE=" + tiers}
	// 'install' copies its source to its target, as the bats stub does.
	install := func(r *fake.Runner) {
		r.OnFunc([]string{"install"}, func(c execx.Cmd) (execx.Result, error) {
			data, err := os.ReadFile(c.Args[len(c.Args)-2])
			if err == nil {
				_ = os.MkdirAll(filepath.Dir(c.Args[len(c.Args)-1]), 0o700)
				err = os.WriteFile(c.Args[len(c.Args)-1], data, 0o600)
			}
			return execx.Result{}, err
		})
	}
	sb.cfgRun("", []string{"config", "sudoers"}, nil, env...)
	sb.expect(0, "Status: not installed", "")
	sb.cfgRun("n\n", []string{"config", "sudoers", "install", "%wheel"}, install, env...)
	sb.expect(0, "Aborted.", "")
	sb.cfgRun("y\n", []string{"config", "sudoers", "install", "bad group"}, install, env...)
	sb.expect(1, "", "Invalid group name: 'bad group'")
	sb.cfgRun("y\n", []string{"config", "sudoers", "install", "wheel"}, func(r *fake.Runner) {
		install(r)
		r.On([]string{"visudo"}, execx.Result{Code: 1})
	}, env...)
	sb.expect(1, "", "visudo validation failed. Not installed.")
	sb.cfgRun("y\n", []string{"config", "sudoers", "install", "%wheel"}, install, env...)
	sb.expect(0, "Installed "+file+" for group '%wheel'.", "")
	if !sb.runner.CalledRegexp(`^visudo -cf .*/tmp/tmp\.`) || !sb.runner.CalledRegexp(`^install -m 0440 -o root -g root .*/tmp/tmp\.\S+ `+file+`$`) {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	if data, _ := os.ReadFile(file); !strings.Contains(string(data), "%wheel ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl\n") {
		t.Errorf("drop-in: %q", data)
	}
	out := sb.cfgRun("", []string{"config", "sudoers", "show"}, nil, env...)
	if !strings.Contains(out, "  Contents:\n    # Managed by tacctl.") {
		t.Errorf("show: %q", out)
	}
	sb.cfgRun("", []string{"config", "sudoers", "remove"}, nil, env...)
	sb.expect(0, "Removed "+file+".", "")
	sb.cfgRun("", []string{"config", "sudoers", "remove"}, nil, env...)
	sb.expect(0, "Not installed. Nothing to remove.", "")
	sb.cfgRun("", []string{"config", "sudoers", "frob"}, nil, env...)
	sb.expect(1, "", "Invalid subcommand: 'frob'. Use: show, install, or remove")

	out = sb.cfgRun("", []string{"config", "sudoers", "tiers"}, nil, env...)
	if want := "\n  Status: not installed. 'tacctl config sudoers tiers install' would write:\n\n" + indentLines(tier.Sudoers()) + "\n"; out != want {
		t.Errorf("tiers show:\n%q\nwant\n%q", out, want)
	}
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "install"}, install, env...)
	sb.expect(0, "Tiers apply to members of tac-readonly, tac-operator and tac-superuser.", "")
	if data, _ := os.ReadFile(tiers); string(data) != tier.Sudoers() {
		t.Errorf("tiers file: %q", data)
	}
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "remove"}, nil, env...)
	sb.expect(0, "Removed "+tiers+".", "")
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "x"}, nil, env...)
	sb.expect(1, "", "Use: tiers show, tiers install, or tiers remove")
	// A failed install exits with its status; no temp file is left.
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "install"}, func(r *fake.Runner) {
		r.On([]string{"install"}, execx.Result{Code: 1})
	}, env...)
	if sb.code != 1 {
		t.Errorf("failed install: exit %d", sb.code)
	}
	if left, _ := os.ReadDir(sb.path("tmp")); len(left) != 0 {
		t.Errorf("TMPDIR not empty: %v", left)
	}
}

func TestConfigBranch(t *testing.T) {
	sb := newSandbox(t, true)
	tree := sb.path("deploy")
	env := "TACCTL_TREE=" + tree
	sb.cfgRun("", []string{"config", "branch"}, nil, env)
	sb.expect(1, "", "Deploy directory not found at "+tree+".")
	for _, d := range []string{".git", "bin", "lib"} {
		if err := os.MkdirAll(filepath.Join(tree, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"bin/tacctl.sh", "lib/x.sh"} {
		if err := os.WriteFile(filepath.Join(tree, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(r *fake.Runner) {
		r.On([]string{"git", "-C", tree, "branch", "--show-current"}, execx.Result{Stdout: []byte("develop\n")})
		r.On([]string{"git", "-C", tree, "branch", "-r"}, execx.Result{Stdout: []byte(
			"  origin/HEAD -> origin/develop\n  origin/develop\n  origin/master\n  origin/'odd\n")})
		r.On([]string{"git", "-C", tree, "rev-parse"}, execx.Result{Code: 1})
		r.On([]string{"git", "-C", tree, "rev-parse", "--verify", "origin/master"}, execx.Result{})
	}
	out := sb.cfgRun("", []string{"config", "branch"}, git, env)
	if want := "\n  \x1b[1mCurrent branch:\x1b[0m develop\n\n  Available remote branches:\n    \x1b[0;32m* develop\x1b[0m\n      master\n"; out != want ||
		sb.code != 1 || !strings.Contains(sb.err.String(), "xargs: ") {
		t.Errorf("list: %d %q %q", sb.code, out, sb.err.String())
	}
	sb.cfgRun("", []string{"config", "branch", "develop"}, git, env)
	sb.expect(0, "Already on branch 'develop'.", "")
	sb.cfgRun("", []string{"config", "branch", "nope"}, git, env)
	sb.expect(1, "", "Branch 'nope' does not exist on remote.")
	sb.cfgRun("", []string{"config", "branch", "master"}, git, env)
	sb.expect(0, "Switched to branch 'master'.", "")
	want := []string{"branch --show-current", "fetch --quiet", "rev-parse --verify origin/master", "checkout -- .", "checkout master", "pull --quiet"}
	var got []string
	for _, a := range sb.runner.Argvs() {
		if strings.HasPrefix(a, "git -C "+tree+" ") {
			got = append(got, strings.TrimPrefix(a, "git -C "+tree+" "))
		}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("git calls %q", got)
	}
	for f, mode := range map[string]os.FileMode{"bin/tacctl.sh": 0o755, "lib/x.sh": 0o644, "lib": 0o755, ".": 0o755} {
		if st, err := os.Stat(filepath.Join(tree, f)); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", f, st.Mode(), err)
		}
	}
	// Neither checkout works: the command ends with the second one's status.
	sb.cfgRun("", []string{"config", "branch", "master"}, func(r *fake.Runner) {
		git(r)
		r.On([]string{"git", "-C", tree, "checkout", "master"}, execx.Result{Code: 1})
		r.On([]string{"git", "-C", tree, "checkout", "-b"}, execx.Result{Code: 128})
	}, env)
	if sb.code != 128 || sb.out.Len() != 0 {
		t.Errorf("failed checkout: %d %q", sb.code, sb.out.String())
	}
}

// Without TACCTL_TREE the clone is /opt/tacctl, never the checkout a dev
// binary was built in (whose local edits a switch would discard).
func TestConfigBranchIgnoresTheDevCheckout(t *testing.T) {
	sb := newSandbox(t, true)
	dev := sb.path("dev")
	for _, d := range []string{".git", "dist"} {
		if err := os.MkdirAll(filepath.Join(dev, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dev, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fake.Runner{}
	var out, errs strings.Builder
	a := app.New([]string{"config", "branch", "x"}, paths.NewEnv(sb.env), filepath.Join(dev, "dist", "tacctl"), 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errs}, r)
	if a.Paths.Tree != dev {
		t.Fatalf("tree %q, want the dev checkout", a.Paths.Tree)
	}
	exitCode(Run(context.Background(), a, BuildInfo{Version: "t"}), a.Out)
	for _, argv := range r.Argvs() {
		if strings.Contains(argv, dev) {
			t.Errorf("ran %q on the dev checkout", argv)
		}
	}
	if !strings.Contains(errs.String(), "Deploy directory not found at /opt/tacctl.") && !r.Called("git", "-C", "/opt/tacctl") {
		t.Errorf("not /opt/tacctl: %q %q", errs.String(), r.Argvs())
	}
}

func TestConfigRenderDryRun(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.path("preview")
	cfg := sb.path("etc", "tacquito.yaml")
	dropIn := sb.path("systemd", "tacquito.service.d", "tacctl.conf")
	sb.run("", []string{"config", "render", "--dry-run", "--out", out})
	sb.expect(0, "Dry run: rendered into "+out, "")
	for _, live := range []string{cfg, dropIn, sb.path("state", "rendered.json")} {
		if _, err := os.Stat(live); err == nil {
			t.Errorf("dry run wrote %s", live)
		}
	}
	if sb.runner.Count("systemctl") != 0 {
		t.Errorf("dry run ran systemctl: %q", sb.runner.Argvs())
	}
	preview := map[string][]byte{}
	for _, live := range []string{cfg, dropIn} {
		p := filepath.Join(out, live)
		data, err := os.ReadFile(p)
		st, serr := os.Stat(p)
		if err != nil || serr != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, err, serr)
		}
		preview[live] = data
	}
	if left, _ := os.ReadDir(sb.path("tmp")); len(left) != 0 {
		t.Errorf("TMPDIR not empty: %v", left)
	}
	// What a real render then writes is what the preview showed.
	sb.run("", []string{"config", "render"})
	sb.expect(0, "Rendered", "")
	for live, want := range preview {
		if got, _ := os.ReadFile(live); string(got) != string(want) {
			t.Errorf("%s differs from its preview", live)
		}
	}
	// A hand edit does not stop a dry run.
	if err := os.WriteFile(cfg, []byte("# edited\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	out2 := sb.path("preview2")
	sb.run("", []string{"config", "render", "--out=" + out2, "--dry-run"})
	sb.expect(0, "tacacs: "+filepath.Join(out2, cfg), "")
	if got, _ := os.ReadFile(cfg); string(got) != "# edited\n" {
		t.Errorf("dry run replaced an edited file")
	}

	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"config", "render", "--dry-run"}, "Usage: tacctl config render --dry-run --out <dir>"},
		{[]string{"config", "render", "--dry-run", "--out"}, "Usage: tacctl config render --dry-run --out <dir>"},
		{[]string{"config", "render", "--dry-run", "--out", out2, "x"}, "Usage: tacctl config render --dry-run --out <dir>"},
		{[]string{"config", "render", "--dry-run", "--out", out}, "is not empty"},
		{[]string{"config", "render", "--dry-run", "--out", "/"}, "is not empty"},
		{[]string{"config", "render", "--out", out}, "Usage: tacctl config render [--force]"},
	} {
		sb.run("", c.args)
		sb.expect(1, "", c.err)
	}
	// Without a store: the store requirement, after preflight.
	sb = newSandbox(t, false)
	if err := os.WriteFile(sb.path("etc", "tacquito.yaml"), []byte("users: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "render", "--dry-run", "--out", sb.path("p")})
	sb.expect(1, "", "store not initialised")
}

func TestConfigShowAndValidate(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.cfgRun("", []string{"config", "show"}, func(r *fake.Runner) {
		r.On([]string{"ss", "-tlnp"}, execx.Result{Stdout: []byte("LISTEN 0 128 0.0.0.0:49 0.0.0.0:*\n")})
		r.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte("active\n")})
	})
	sb.expect(0, "prod-inner", "")
	for _, want := range []string{"Listening on:\x1b[0m         0.0.0.0:49", "Service status:\x1b[0m       active", "Cisco ACL:          VTY-ACL"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "is missing — run 'tacctl config render'", "Validation failed with 1 error(s).")
	sb.run("", []string{"config", "render"})
	sb.run("", []string{"config", "validate"})
	sb.expect(0, "Configuration is valid.", "")
	if err := os.WriteFile(sb.path("etc", "tacquito.yaml"), []byte("# edited\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "DRIFT:                "+sb.path("etc", "tacquito.yaml")+" — edited since tacctl rendered it", "Validation failed")
	// A store that does not load: reported once, then the report goes on.
	if err := os.WriteFile(sb.path("state", "store.yaml"), []byte("users: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "users, groups and scopes could not be read (see above)", "tacctl store: ")
	if n := strings.Count(sb.err.String(), "tacctl store: "); n != 1 {
		t.Errorf("store error printed %d times: %q", n, sb.err.String())
	}
}

func TestCfgHelpers(t *testing.T) {
	if got := indentLines("a\nb"); got != "    a\n    b" {
		t.Errorf("indentLines: %q", got)
	}
	dir := t.TempDir()
	reg := filepath.Join(dir, "linux-hosts")
	if err := os.WriteFile(reg, []byte("h1|t|22|lab|s|i\nh2|t|22|lab\nh3|t|22| \nh4|t\nloose\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cfgHostCounts(reg)
	if got["lab"] != 2 || got["loose"] != 1 || len(got) != 2 {
		t.Errorf("cfgHostCounts: %v", got)
	}
	if len(cfgHostCounts(filepath.Join(dir, "none"))) != 0 {
		t.Error("missing registry")
	}
}
