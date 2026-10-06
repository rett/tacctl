package cli

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/shell"
)

const testExe = "/opt/x/dist/tacctl"

// shellHarness is 'tacctl shell <args>' with stdin (not a terminal).
func shellHarness(t *testing.T, stdin string, args []string, env ...string) *harness {
	t.Helper()
	h := newHarness(t, append([]string{"shell"}, args...), append([]string{"HOME=" + t.TempDir()}, env...)...)
	h.app.Stdin = strings.NewReader(stdin)
	return h
}

// lines are the argvs of the lines the shell ran (sudo or the binary).
func lines(r *fake.Runner) []string {
	var out []string
	for _, a := range r.Argvs() {
		if strings.HasPrefix(a, "sudo ") || strings.HasPrefix(a, testExe) {
			out = append(out, a)
		}
	}
	return out
}

func TestShellArgv(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		groups string
		env    []string
		want   string
	}{
		{"admin", "user list", "admin adm sudo", nil, "sudo " + testExe + " user list"},
		{"tier user", "user list", "u tac-users tac-readonly", nil, "sudo -n " + testExe + " user list"},
		{"quoted word", "user show 'a b'", "", nil, "sudo " + testExe + " user show a b"},
		{"metacharacters are words", "user list; id | sh $(id) `id` > /tmp/x", "", nil,
			"sudo " + testExe + " user list; id | sh $(id) `id` > /tmp/x"},
		{"ssh does not carry the agent", "ssh core1", "u tac-users tac-operator", []string{"SSH_AUTH_SOCK=/tmp/agent.1"},
			"sudo -n " + testExe + " ssh core1"},
		{"host carries the agent", "host list", "", []string{"SSH_AUTH_SOCK=/tmp/agent.1"},
			"sudo SSH_AUTH_SOCK=/tmp/agent.1 " + testExe + " host list"},
		{"user does not", "user list", "", []string{"SSH_AUTH_SOCK=/tmp/agent.1"}, "sudo " + testExe + " user list"},
		{"hash runs without sudo", "hash commands", "u tac-users", nil, testExe + " hash commands"},
		// A superuser's lines may ask for the network password (their
		// write verbs are '(ALL:ALL) ALL'); readonly, operator and a
		// tac-users member with no tier group keep -n.
		{"superuser asks", "user add bob ops", "u tac-users tac-superuser", nil, "sudo " + testExe + " user add bob ops"},
		{"operator -n", "log tail", "u tac-users tac-operator", nil, "sudo -n " + testExe + " log tail"},
		{"no tier -n", "user list", "u tac-users", nil, "sudo -n " + testExe + " user list"},
		{"superuser not managed", "user list", "u tac-superuser", nil, "sudo " + testExe + " user list"},
	}
	for _, c := range cases {
		h := shellHarness(t, "", []string{"-c", c.line}, c.env...)
		h.runner.On([]string{"id", "-nG"}, execx.Result{Stdout: []byte(c.groups + "\n")})
		if err := h.run(); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if got := lines(h.runner); len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: ran %q, want %q", c.name, got, c.want)
		}
	}
}

func TestShellStatusAndBatch(t *testing.T) {
	// -c returns the line's status.
	h := shellHarness(t, "", []string{"-c", "user show x"})
	h.runner.Fail([]string{"sudo", testExe, "user", "show"}, 3, "")
	if code := exitCode(h.run(), h.app.Out); code != 3 {
		t.Errorf("-c status %d, want 3", code)
	}
	// A batch stops at the first non-zero status and returns it.
	h = shellHarness(t, "user list\nbogus\nuser list\n", nil)
	h.runner.Fail([]string{"sudo", testExe, "bogus"}, 1, "")
	if code := exitCode(h.run(), h.app.Out); code != 1 {
		t.Errorf("batch status %d, want 1", code)
	}
	want := []string{"sudo " + testExe + " user list", "sudo " + testExe + " bogus"}
	if got := lines(h.runner); !slices.Equal(got, want) {
		t.Errorf("batch ran %q, want %q", got, want)
	}
	for _, r := range h.runner.Records() {
		if r.Cmd.Name == "sudo" && r.Stdin != nil {
			t.Errorf("a batch line got stdin %q", r.Stdin)
		}
	}
	// No history for a batch.
	if _, err := os.Stat(filepath.Join(h.app.Env.Get("HOME"), ".local")); err == nil {
		t.Error("a batch wrote a history")
	}
}

func TestShellTierDenial(t *testing.T) {
	cases := []struct {
		groups, line string
		denied       bool
	}{
		{"u tac-users tac-readonly", "user add bob ops", true},
		{"u tac-users tac-readonly", "user list", false},
		{"u tac-users tac-readonly", "log tail", true},
		{"u tac-users tac-operator", "log tail", false},
		{"u tac-users tac-superuser", "user add bob ops", false},
		{"u adm", "user add bob ops", false},
	}
	for _, c := range cases {
		h := shellHarness(t, "", []string{"-c", c.line})
		h.runner.On([]string{"id", "-nG"}, execx.Result{Stdout: []byte(c.groups)})
		h.runner.Fail([]string{"sudo"}, 1, "sudo: a password is required")
		if code := exitCode(h.run(), h.app.Out); code != 1 {
			t.Errorf("%q %q: status %d", c.groups, c.line, code)
		}
		got := strings.Contains(h.err.String(), "is not permitted for the")
		if got != c.denied {
			t.Errorf("%q %q: denial printed %v, want %v (%q)", c.groups, c.line, got, c.denied, h.err.String())
		}
		// sudo's own message goes only when the shell prints the denial.
		if sudoMsg := strings.Contains(h.err.String(), "sudo: a password is required"); sudoMsg == c.denied {
			t.Errorf("%q %q: sudo's message printed %v with the denial %v (%q)", c.groups, c.line, sudoMsg, c.denied, h.err.String())
		}
	}
}

func TestSudoLineFilter(t *testing.T) {
	var b strings.Builder
	f := &sudoLineFilter{w: &b}
	for _, chunk := range []string{"sudo: a pass", "word is required\n", "sudo: a", "nother\n", "sudo: a password is required too\n", "tail"} {
		_, _ = f.Write([]byte(chunk))
	}
	f.flush()
	if want := "sudo: another\nsudo: a password is required too\ntail"; b.String() != want {
		t.Errorf("filtered %q, want %q", b.String(), want)
	}
	f.restore()
	if !strings.HasSuffix(b.String(), "tail"+sudoNoPassword) {
		t.Errorf("restored %q", b.String())
	}
}

func TestShellHistory(t *testing.T) {
	h := shellHarness(t, "", []string{"-c", "scope secret lab set x"})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.app.Env.Get("HOME"), ".local", "state", "tacctl", "history")
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "scope secret lab set …(redacted)\n" {
		t.Errorf("history %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("history mode %v", fi.Mode().Perm())
	}
	h = shellHarness(t, "", []string{"--no-history", "-c", "user list"})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.app.Env.Get("HOME"), ".local")); err == nil {
		t.Error("--no-history wrote a history")
	}
}

func TestShellUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--idle", "x"}, {"--idle", "-1"}, {"--idle", "1441"}, {"--idle"}, {"--bogus"}, {"extra"}, {"-c"},
	} {
		h := shellHarness(t, "", args)
		if code := exitCode(h.run(), h.app.Out); code != 1 || !strings.Contains(h.err.String(), shellUsage) {
			t.Errorf("%q: status %d, stderr %q", args, code, h.err.String())
		}
		if len(lines(h.runner)) != 0 {
			t.Errorf("%q ran a line", args)
		}
	}
}

func shellTestInv(t *testing.T) (*invocation, *cobra.Command, *fake.Runner) {
	t.Helper()
	h := newHarness(t, nil)
	h.runner.OnFunc([]string{"sudo", "-n", "tacctl", "_completion-names"}, func(c execx.Cmd) (execx.Result, error) {
		switch c.Args[len(c.Args)-1] {
		case "users":
			return execx.Result{Stdout: []byte("alice\nalbert\nbob\n")}, nil
		case "scopes":
			return execx.Result{Stdout: []byte("lab\nprod\n")}, nil
		}
		return execx.Result{}, nil
	})
	inv := &invocation{ctx: t.Context(), app: h.app, build: BuildInfo{Version: "0.2.1-test"}}
	h.app.Runner = &namesCache{Runner: h.runner, ttl: time.Hour, now: time.Now}
	return inv, newRoot(inv), h.runner
}

func words(cs []shell.Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Word)
	}
	return out
}

func TestShellCompletion(t *testing.T) {
	inv, root, runner := shellTestInv(t)
	complete := inv.shellCompleter(root)
	cases := []struct {
		words   []string
		partial string
		has     []string
		hasNot  []string
	}{
		{nil, "", []string{"user", "scope", "device", "completion", "version"}, []string{"help", "shell", "_completion-names", "__complete"}},
		{[]string{"user"}, "", []string{"list", "show", "add"}, nil},
		{[]string{"user", "show"}, "al", []string{"alice", "albert"}, []string{"bob"}},
		{[]string{"user", "add", "x", "ops"}, "--", []string{"--hash", "--scopes"}, nil},
		{[]string{"shell"}, "-", []string{"--no-history", "--idle", "-c"}, nil},
		{[]string{"bogus"}, "", nil, []string{"user"}},
	}
	for _, c := range cases {
		got := words(complete(c.words, c.partial))
		for _, w := range c.has {
			if !slices.Contains(got, w) {
				t.Errorf("%q %q: %q lacks %q", c.words, c.partial, got, w)
			}
		}
		for _, w := range c.hasNot {
			if slices.Contains(got, w) {
				t.Errorf("%q %q: %q has %q", c.words, c.partial, got, w)
			}
		}
	}
	// Sub-commands carry their descriptions.
	for _, c := range complete([]string{"user"}, "li") {
		if c.Word == "list" && !strings.Contains(c.Desc, "List all users") {
			t.Errorf("user list description %q", c.Desc)
		}
	}
	// A comma list goes on without a blank.
	for _, c := range complete([]string{"user", "add", "x", "ops", "--scopes"}, "la") {
		if !c.NoSpace {
			t.Errorf("--scopes %q completes with a blank", c.Word)
		}
	}
	// The live names were asked once for the two 'users' completions.
	if n := runner.Count("sudo", "-n", "tacctl", "_completion-names", "users"); n != 1 {
		t.Errorf("users asked %d times, want 1 (cached)", n)
	}
}

func TestNamesCacheExpires(t *testing.T) {
	r := &fake.Runner{}
	r.On([]string{"sudo"}, execx.Result{Stdout: []byte("a\n")})
	now := time.Unix(1000, 0)
	c := &namesCache{Runner: r, ttl: 5 * time.Second, now: func() time.Time { return now }}
	q := execx.Cmd{Name: "sudo", Args: []string{"-n", "tacctl", "_completion-names", "users"}}
	for range 3 {
		_, _ = c.Run(t.Context(), q)
	}
	now = now.Add(6 * time.Second)
	_, _ = c.Run(t.Context(), q)
	_, _ = c.Run(t.Context(), execx.Cmd{Name: "sudo", Args: []string{"-n", "tacctl", "_completion-names", "groups"}})
	_, _ = c.Run(t.Context(), execx.Cmd{Name: "sudo", Args: []string{testExe, "user", "list"}})
	_, _ = c.Run(t.Context(), execx.Cmd{Name: "sudo", Args: []string{testExe, "user", "list"}})
	if got := r.Count("sudo", "-n", "tacctl", "_completion-names", "users"); got != 2 {
		t.Errorf("users asked %d times, want 2", got)
	}
	if got := r.Count("sudo", testExe); got != 2 {
		t.Errorf("a command was cached: %d runs", got)
	}
}

func TestShellHelp(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	help := inv.shellHelp(root, false)
	cases := []struct {
		words []string
		want  string
	}{
		{nil, shellTop("0.2.1-test", false)},
		{[]string{"user"}, userUsage()},
		{[]string{"user", "add"}, userUsage()},
		{[]string{"group", "commands", "list"}, groupCommandsUsage(inv.app.Paths.Overrides)},
		{[]string{"device"}, deviceRegUsage()},
		{[]string{"hash", "generate"}, hashUsage()},
	}
	for _, c := range cases {
		if got, ok := help(c.words); !ok || got != c.want {
			t.Errorf("help %q = %q, %v", c.words, got, ok)
		}
	}
	for _, c := range []struct {
		words []string
		has   []string
	}{
		{[]string{"scope"}, []string{"tacctl scope list", "tacctl scope add"}},
		{[]string{"scope", "secret", "lab"}, []string{"tacctl scope secret <scope> set <value>"}},
		{[]string{"backend"}, []string{"Backends: tacacs"}},
		{[]string{"config", "deny"}, []string{"tacctl config deny list"}},
		{[]string{"shell"}, []string{"Usage: tacctl shell [--no-history] [--idle <min>] [-c <line>]"}},
	} {
		got, ok := help(c.words)
		for _, w := range c.has {
			if !ok || !strings.Contains(got, w) {
				t.Errorf("help %q = %q, lacks %q", c.words, got, w)
			}
		}
		if strings.Contains(got, "{{") || strings.Contains(got, "\n\n\n") {
			t.Errorf("help %q has an unfilled slot or a gap: %q", c.words, got)
		}
	}
	for _, w := range [][]string{{"bogus"}, {"_completion-names"}} {
		if _, ok := help(w); ok {
			t.Errorf("help %q answered", w)
		}
	}
}

// 'help <command>' prints what 'tacctl <command>' prints, for every family
// that prints a block with no arguments.
func TestShellHelpIsTheCLIUsage(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	help := inv.shellHelp(root, false)
	sb := newSandbox(t, true)
	for _, fam := range []string{"user", "group", "host", "device", "backend", "store", "config", "log", "backup", "hash", "ssh"} {
		out := sb.run("", []string{fam})
		if out == "" {
			t.Fatalf("tacctl %s printed nothing (stderr %q)", fam, sb.err.String())
		}
		got, ok := help([]string{fam})
		if !ok || got != out {
			t.Errorf("help %s differs from 'tacctl %s':\n%q\n%q", fam, fam, got, out)
		}
	}
}

// The shell's top-level help is the usage of 'tacctl' with the program's
// name left out of its usage line, hint and examples, and a Shell section.
func TestShellTopHelp(t *testing.T) {
	got := shellTop("v", false)
	top := Usage("top", UsageVars{"version": "v"})
	for _, want := range []string{
		top[:strings.Index(top, "Usage:")],
		top[strings.Index(top, "Commands:\n"):strings.Index(top, "\nRun any command")],
		"Usage: <command> [arguments]\n",
		"Type help <command> for detailed help, e.g.:\n  help user\n",
		"\nExamples:\n  install\n  upgrade\n  user add jsmith superuser\n",
		"\nShell:\n  help [<command>]  ",
		"\n  exit | quit ",
		"\n  Tab ", "\n  ? ", "\n  Ctrl-R ", "\n  Ctrl-C ", "\n  Ctrl-D ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("shell help lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "tacctl user") || strings.Contains(got, "tacctl install") {
		t.Errorf("shell help names the program in a command:\n%s", got)
	}
	// The Shell section's descriptions start in the usage's column.
	col := strings.Index(got, "Install tacctl") - strings.Index(got, "  install")
	if i := strings.Index(got, "Leave the shell"); i-strings.LastIndex(got[:i], "\n")-1 != col {
		t.Errorf("Shell section column: %d, usage column %d", i-strings.LastIndex(got[:i], "\n")-1, col)
	}
}

// Every command's description, in the cobra tree (bash, zsh and fish
// completion; the shell) and in 'tacctl' with no arguments, is one text.
func TestTopShortsAreTheUsage(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	rows := topRows()
	if len(rows) < 20 {
		t.Fatalf("top usage has %d command rows", len(rows))
	}
	top := Usage("top", UsageVars{"version": "x"})
	for _, r := range rows {
		c := child(root, r.Name)
		if c == nil {
			t.Errorf("usage lists %q, the tree has no such command", r.Name)
			continue
		}
		if c.Short != r.Desc {
			t.Errorf("%s: Short %q, usage %q", r.Name, c.Short, r.Desc)
		}
		ok := false
		for _, line := range strings.Split(top, "\n") {
			ok = ok || (strings.HasPrefix(line, "  "+r.Left+" ") && strings.HasSuffix(line, "  "+r.Desc))
		}
		if !ok {
			t.Errorf("%s: row %q not in the usage", r.Name, r.Left)
		}
	}
	for _, c := range root.Commands() {
		if c.Hidden && c.Name() != "completion" {
			continue
		}
		found := false
		for _, r := range rows {
			found = found || r.Name == c.Name()
		}
		if !found {
			t.Errorf("command %q has no row in the usage", c.Name())
		}
	}
	// 'tacctl shell' completes nothing of its own descriptions: the tree
	// and the usage agree for the whole shell listing.
	for _, cand := range inv.shellCompleter(root)(nil, "") {
		if c := child(root, cand.Word); c == nil || c.Short != cand.Desc {
			t.Errorf("listing %q: %q", cand.Word, cand.Desc)
		}
	}
}

// The '?' listing of a family's verbs takes its argument column and its
// descriptions from the family's usage.
func TestShellVerbDescriptionsFromUsage(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	got := map[string]shell.Candidate{}
	for _, c := range inv.shellCompleter(root)([]string{"user"}, "") {
		got[c.Word] = c
	}
	if c := got["list"]; c.Desc != "List all users (name, group, status, pw age, scopes)" || c.Label != "list" {
		t.Errorf("user list: %+v", c)
	}
	if c := got["add"]; c.Label != "add <username> <group>" || c.Desc != "Add a new user; lands in default scope" {
		t.Errorf("user add: %+v", c)
	}
}

// '?' after a command that takes arguments: its usage rows, its flags with
// their descriptions from the usage block, and what comes next.
func TestShellExplain(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	explain := inv.shellExplain(root)
	cases := []struct {
		words []string
		want  []string
	}{
		{[]string{"user", "add"}, []string{
			"Usage:\n  add <username> <group>  ",
			"\n  add <username> <group> --hash <hash>  ",
			"Options:\n",
			"\n  --hash <hash>  ", "Add with pre-generated bcrypt hash\n",
			"Next: <username> <group>\n",
		}},
		{[]string{"user", "add", "bob"}, []string{"Next: <group>\n"}},
		{[]string{"user", "add", "bob", "ops"}, []string{"Next: <Enter> to run\n"}},
		{[]string{"ssh", "core1"}, []string{
			"Usage:\n  ssh <name|address> [-p <port>] [-X|-Y] [-g] [-L|-R|-D <spec>]... [-- <ssh args>]\n",
			"\n  -p <port>  ", "Connect to <port>",
			"Next: <Enter> to run\n",
		}},
		{[]string{"device", "add", "x"}, []string{"Usage:\n  add <name> <address> [options]", "  --vendor cisco|juniper|wti|other", "  --port <n>                        Its ssh port (default 22)\n", "  --host-key SHA256:<fp>            Register only if the device offers this key; pin it alone\n", "Next: <address>\n"}},
		{[]string{"device", "address", "x"}, []string{"Next: [<address>], or <Enter> to run\n"}},
		{[]string{"version"}, []string{"Usage:\n  version [--long]\n", "Next: <Enter> to run\n"}},
	}
	for _, c := range cases {
		got, ok := explain(c.words)
		if !ok {
			t.Errorf("%q: no explanation", c.words)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: lacks %q:\n%s", c.words, w, got)
			}
		}
	}
	// A flag already on the line is not offered again.
	if got, _ := explain([]string{"user", "add", "--hash", "x"}); strings.Contains(got[strings.Index(got, "Options:"):], "--hash") {
		t.Errorf("a typed flag offered again:\n%s", got)
	}
	// Words that name a family, or no command, have no explanation.
	for _, w := range [][]string{nil, {"user"}, {"bogus"}} {
		if got, ok := explain(w); ok {
			t.Errorf("%q: %q", w, got)
		}
	}
}

func TestSSHWithoutTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	file, err := os.CreateTemp(t.TempDir(), "cmds")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	over := paths.NewEnv([]string{"SSH_CONNECTION=192.0.2.1 50000 192.0.2.2 22"})
	withTTY := paths.NewEnv([]string{"SSH_CONNECTION=192.0.2.1 50000 192.0.2.2 22", "SSH_TTY=/dev/pts/3"})
	local := paths.NewEnv(nil)
	for _, c := range []struct {
		name  string
		env   paths.Env
		stdin io.Reader
		want  bool
	}{
		{"ssh, no terminal, a pipe", over, r, true},
		{"ssh with a terminal", withTTY, r, false},
		{"not over ssh", local, r, false},
		{"commands redirected from a file", over, file, false},
		{"not a file at all", over, strings.NewReader("user list\n"), false},
	} {
		if got := sshWithoutTerminal(c.env, c.stdin); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The kind a long list asks about: the next positional's or a pending
// flag value's, plural; options for flags, commands for verbs.
func TestShellListKinds(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	complete := inv.shellCompleter(root)
	kindOf := func(words []string, partial string) string {
		cs := complete(words, partial)
		if len(cs) == 0 {
			return ""
		}
		return cs[0].Kind
	}
	if got := kindOf(nil, ""); got != "commands" {
		t.Errorf("top: %q", got)
	}
	if got := kindOf([]string{"user"}, ""); got != "commands" {
		t.Errorf("verbs: %q", got)
	}
	if got := kindOf([]string{"user", "add", "bob"}, "--"); got != "options" {
		t.Errorf("flags: %q", got)
	}
	for _, c := range []struct {
		spec Spec
		rest []string
		want string
	}{
		{Spec{Args: []string{KindDevices}}, nil, "devices"},
		{Spec{Args: []string{"", KindScopes + KindList}}, []string{"x"}, "scopes"},
		{Spec{Args: []string{"a|b"}}, nil, "choices"},
		{Spec{Args: []string{""}, Flags: []Flag{{Names: []string{"--scope"}, Value: true, Kind: KindScopes}}}, []string{"--scope"}, "scopes"},
		{Spec{Args: []string{KindUsers}, Flags: []Flag{{Names: []string{"--scope"}, Value: true, Kind: KindScopes}}}, []string{"--scope", "lab"}, "users"},
		{Spec{Args: []string{"", After("set", KindHosts)}}, []string{"set"}, "hosts"},
		{Spec{Args: []string{KindEnabledBackends}}, nil, "backends"},
	} {
		if got := listKindName(c.spec, c.rest); got != c.want {
			t.Errorf("%+v %q: %q, want %q", c.spec, c.rest, got, c.want)
		}
	}
}

// '?' after a dash describes every flag of every command: each flag has an
// option line (or a row) in its usage block.
func TestEveryFlagHasADescription(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	complete := inv.shellCompleter(root)
	var all [][]string
	commandPaths(root, nil, &all)
	for _, p := range all {
		c, _ := resolve(root, p)
		if len(c.Commands()) > 0 {
			continue
		}
		for _, cand := range complete(p, "-") {
			if strings.HasPrefix(cand.Word, "-") && cand.Desc == "" {
				t.Errorf("tacctl %s %s: no description for '?'", strings.Join(p, " "), cand.Word)
			}
		}
	}
}
