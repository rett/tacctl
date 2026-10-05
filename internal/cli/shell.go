package cli

// 'tacctl shell': the interactive shell (internal/shell). It runs as the
// invoking user (noSudo, reexec.go) and runs each line as
//
//	sudo [-n] [SSH_AUTH_SOCK=<socket>] <exe> <words>
//
// with the terminal attached: '-n' for a tier-managed caller (a member of
// tac-users, who has no password for sudo), the agent socket for the first
// words keepEnv names (as the re-exec passes it), <exe> the running
// executable (the path the sudoers rules name). The words of noSudo (hash,
// completion) run as '<exe> <words>' without sudo. So every line meets
// sudo's policy and tacctl's tier gate exactly as it does from bash, and
// sudo logs each one. 'ssh <name>' is such a line too.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/tier"
)

func init() {
	registerFamily(shellCmd)
	registerSpecFunc("shell", func(path []string) (Spec, bool) {
		return shellSpec, len(path) == 1
	})
}

// shellSpec is 'tacctl shell [--no-history] [--idle <min>] [-c <line>]'.
var shellSpec = Spec{MaxArgs: 0, Flags: []Flag{
	{Names: []string{"--no-history"}},
	{Names: []string{"--idle"}, Value: true},
	{Names: []string{"-c"}, Value: true, Alone: true},
}}

const shellUsage = "Usage: tacctl shell [--no-history] [--idle <min>] [-c <line>]"

// shellNamesTTL is how long the shell keeps the live names of a kind.
const shellNamesTTL = 5 * time.Second

// shellIdleMax is the largest --idle, in minutes (a day).
const shellIdleMax = 1440

var reMinutes = regexp.MustCompile(`^[0-9]{1,4}$`)

func shellCmd(inv *invocation) *cobra.Command {
	c := verb("shell [--no-history] [--idle <min>] [-c <line>]",
		"Interactive shell: one tacctl command per line, with completion and history")
	c.RunE = inv.native(noPreflight, inv.shell)
	return c
}

// shell is 'tacctl shell'.
func (inv *invocation) shell(args []string) error {
	a := inv.app
	p, err := Parse(shellSpec, args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, shellUsage)
	}
	idle := 0
	if p.Has("--idle") {
		v := p.Value("--idle")
		n, convErr := strconv.Atoi(v)
		if !reMinutes.MatchString(v) || convErr != nil || n > shellIdleMax {
			return inv.usageErr("--idle takes minutes, 0 to "+strconv.Itoa(shellIdleMax)+" (0: no idle timeout)", shellUsage)
		}
		idle = n
	}
	exe := a.Exe
	if exe == "" || !strings.HasPrefix(exe, "/") {
		return &ExitError{Code: 1, Err: errors.New("cannot locate the tacctl executable to run commands with")}
	}

	f, isFile := a.Stdin.(*os.File)
	interactive := !p.Has("-c") && isFile && term.IsTerminal(int(f.Fd()))
	if interactive {
		// Ctrl-C during a command cancels the invocation's context (Main);
		// the session carries on, so nothing of it may depend on that.
		inv.ctx = context.WithoutCancel(inv.ctx)
	}
	// Live names are asked of 'sudo -n tacctl _completion-names' at most
	// once per kind every shellNamesTTL.
	a.Runner = &namesCache{Runner: a.Runner, ttl: shellNamesTTL, now: time.Now}

	groups := inv.callerGroups()
	managed := slices.Contains(groups, tier.UsersGroup)
	root := newRoot(inv)
	o := shell.Options{
		Out:      a.Out,
		Idle:     time.Duration(idle) * time.Minute,
		Complete: inv.shellCompleter(root),
		Help:     inv.shellHelp(root),
		Exec:     inv.shellExec(exe, managed, sudoTier(groups)),
	}
	if interactive || p.Has("-c") {
		path := ""
		if home := a.Env.Get("HOME"); home != "" && !p.Has("--no-history") {
			path = filepath.Join(home, ".local", "state", "tacctl", "history")
		}
		o.History = shell.NewHistory(path, a.Out.Stderr)
	}
	sh := shell.New(o)
	if !interactive && !p.Has("-c") && sshWithoutTerminal(a.Env, a.Stdin) {
		// 'ssh host tacctl shell' runs without a terminal unless ssh is given
		// -t; batch mode then waits on stdin, which looks like a hang.
		_, _ = fmt.Fprintln(a.Out.Stderr, "tacctl shell: no terminal, so commands are read from standard input, one per line (Ctrl-D ends).\n"+
			"For the interactive shell over ssh, ask for a terminal: ssh -t <host> tacctl shell")
	}
	var status int
	switch {
	case p.Has("-c"):
		status = sh.Command(inv.ctx, p.Value("-c"), a.Stdin)
	case interactive:
		status = sh.Interactive(inv.ctx, f)
	default:
		status = sh.Batch(inv.ctx, a.Stdin)
	}
	if status != 0 {
		return exit(status)
	}
	return nil
}

// callerGroups are the invoking user's groups ('id -nG'); none when id
// fails.
func (inv *invocation) callerGroups() []string {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "id", Args: []string{"-nG"}})
	if err != nil || res.Code != 0 {
		return nil
	}
	return strings.Fields(string(res.Stdout))
}

// sudoTier is the tier whose sudoers rules a managed caller's groups give
// them: the operator or readonly aliases (tier.Sudoers), superuser for
// tac-superuser (every command, with a password), none otherwise.
func sudoTier(groups []string) tier.Tier {
	switch {
	case slices.Contains(groups, tier.SuperuserGroup):
		return tier.Superuser
	case slices.Contains(groups, tier.OperatorGroup):
		return tier.Operator
	case slices.Contains(groups, tier.ReadonlyGroup):
		return tier.Readonly
	}
	return tier.None
}

// sudoGrants reports whether the sudoers drop-in lets tier t run the words
// without a password (the rows of tier.Rules that have sudoers patterns).
func sudoGrants(t tier.Tier, words []string) bool {
	cmd, sub := words[0], ""
	if len(words) > 1 {
		sub = words[1]
	}
	for _, r := range tier.Rules {
		if len(r.Sudoers) == 0 || (r.Tier == tier.Operator && t != tier.Operator) {
			continue
		}
		if r.Cmd == cmd && (r.AnySub || r.Sub == sub) {
			return true
		}
	}
	return false
}

// shellArgv is the argv a line runs as.
func shellArgv(exe string, words []string, managed bool, env func(string) string) []string {
	if noSudo[words[0]] {
		return append([]string{exe}, words...)
	}
	argv := sudoArgv(exe, words, env)
	if managed {
		argv = append([]string{"sudo", "-n"}, argv[1:]...)
	}
	return argv
}

// shellExec runs a line with the terminal attached. A managed caller's
// line that sudo refused (status 1) and that the tier's sudoers rules do
// not cover is reported as the tier denial.
func (inv *invocation) shellExec(exe string, managed bool, t tier.Tier) func(context.Context, []string, io.Reader) int {
	a := inv.app
	return func(ctx context.Context, words []string, stdin io.Reader) int {
		if words[0] == "shell" {
			a.Out.Error("already in the tacctl shell")
			return 1
		}
		argv := shellArgv(exe, words, managed, a.Env.Get)
		c := execx.Cmd{Name: argv[0], Args: argv[1:]}
		code, _, err := execx.Attached(ctx, a.Runner, c, stdin, a.Out.Stdout, a.Out.Stderr)
		if err != nil {
			if code == 0 {
				code = 1
			}
			if code == 127 {
				a.Out.Error("cannot run " + argv[0] + ": " + err.Error())
			}
		}
		if code == 1 && managed && (t == tier.Readonly || t == tier.Operator) && !sudoGrants(t, words) {
			sub := ""
			if len(words) > 1 {
				sub = " " + words[1]
			}
			a.Out.ErrorE("'tacctl " + words[0] + sub + "' is not permitted for the " + string(t) + " tier.")
		}
		return code
	}
}

// shellCompleter completes from the command tree (sub-commands with their
// descriptions) and the verbs' Specs (inv.completeSpec: flags, fixed words
// and live names).
func (inv *invocation) shellCompleter(root *cobra.Command) shell.Completer {
	inv.shellMode = true
	return func(words []string, partial string) []shell.Candidate {
		cmd, rest := root, words
		var path []string
		for len(rest) > 0 {
			next := child(cmd, rest[0])
			if next == nil {
				break
			}
			cmd, rest, path = next, rest[1:], append(path, next.Name())
		}
		var out []shell.Candidate
		if len(rest) == 0 && cmd == root {
			// The rows of the usage (argument column and description);
			// the list is alphabetical. 'shell' is not offered in the shell.
			for _, r := range topRows() {
				if r.Name != "shell" && child(root, r.Name) != nil {
					out = append(out, shell.Candidate{Word: r.Name, Label: r.Left, Desc: r.Desc})
				}
			}
			return out
		}
		if len(rest) == 0 && len(cmd.Commands()) > 0 {
			var rows []usageRow
			if len(path) == 1 {
				rows = inv.familyRows(path[0])
			}
			for _, sub := range cmd.Commands() {
				if sub.Hidden {
					continue
				}
				c := shell.Candidate{Word: sub.Name(), Desc: sub.Short}
				for i, r := range rows {
					if r.Name == sub.Name() {
						c.Desc, c.Order = r.Desc, i+1
						break
					}
				}
				out = append(out, c)
			}
			return out
		}
		if len(path) == 0 {
			return nil
		}
		spec, ok := specFor(path)
		if !ok {
			return nil
		}
		comps, dir := inv.completeSpec(spec, rest, partial)
		noSpace := dir&cobra.ShellCompDirectiveNoSpace != 0
		for _, c := range comps {
			w, d, _ := strings.Cut(c, "\t")
			out = append(out, shell.Candidate{Word: w, Desc: d, NoSpace: noSpace})
		}
		return out
	}
}

// shellHelpBlocks are the usage blocks 'help <command>' prints, by command
// path. The blocks whose command fills in a value from the store get a
// neutral one (the shell cannot read the store).
var shellHelpBlocks = map[string]func(inv *invocation) string{
	"user":            func(*invocation) string { return userUsage() },
	"group":           func(*invocation) string { return groupUsage() },
	"group commands":  func(inv *invocation) string { return groupCommandsUsage(inv.app.Paths.Overrides) },
	"group privilege": func(*invocation) string { return groupPrivilegeUsage() },
	"scope":           func(*invocation) string { return usageNoCurrent("scope", nil) },
	"scope prefixes":  func(*invocation) string { return usageNoCurrent("scope-prefixes", UsageVars{"scope": "<scope>"}) },
	"scope secret":    func(*invocation) string { return usageNoCurrent("scope-secret", UsageVars{"scope": "<scope>"}) },
	"scope mgmt-acl":  func(*invocation) string { return usageNoCurrent("scope-mgmt-acl", UsageVars{"scope": "<scope>"}) },
	"config":          func(*invocation) string { return configUsage() },
	"config linux":    func(*invocation) string { return configLinuxUsage() },
	"config allow":    func(*invocation) string { return usageNoCurrent("config-filter", UsageVars{"label": "allow"}) },
	"config deny":     func(*invocation) string { return usageNoCurrent("config-filter", UsageVars{"label": "deny"}) },
	"config mgmt-acl": func(*invocation) string { return usageNoCurrent("config-mgmt-acl", nil) },
	"host":            func(*invocation) string { return hostUsage() },
	"backend":         func(*invocation) string { return backendUsage(backend.Default().IDs()) },
	"store":           func(*invocation) string { return storeUsage() },
	"log":             func(*invocation) string { return Usage("log", nil) },
	"backup":          func(*invocation) string { return Usage("backup", nil) },
	"hash":            func(*invocation) string { return hashUsage() },
	"device":          func(*invocation) string { return deviceRegUsage() },
	"ssh":             func(*invocation) string { return sshUsage() },
}

// usageNoCurrent is a usage block with its {{current}} line left out.
func usageNoCurrent(id string, vars UsageVars) string {
	if vars == nil {
		vars = UsageVars{}
	}
	vars["current"] = ""
	s := Usage(id, vars)
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return s
}

// shellHelp is 'help [<command>]': the top-level usage, or the usage block
// of the command's family (the nearest one up the path); a command without
// a block gets its sub-commands or its usage line from the tree.
func (inv *invocation) shellHelp(root *cobra.Command) func([]string) (string, bool) {
	return func(words []string) (string, bool) {
		if len(words) == 0 {
			return shellTop(inv.build.Version), true
		}
		cmd, _ := resolve(root, words)
		if cmd == root || cmd.Hidden {
			return "", false
		}
		var path []string
		for c := cmd; c != root; c = c.Parent() {
			path = append([]string{c.Name()}, path...)
		}
		for n := len(path); n > 0; n-- {
			if f, ok := shellHelpBlocks[strings.Join(path[:n], " ")]; ok {
				return f(inv), true
			}
		}
		return treeUsage(cmd), true
	}
}

// treeUsage is the usage of a command from the tree: its sub-commands
// with their descriptions, or its usage line.
func treeUsage(cmd *cobra.Command) string {
	parent := strings.TrimSuffix(cmd.CommandPath(), cmd.Name())
	var b strings.Builder
	b.WriteString("\nUsage: " + parent + cmd.Use + "\n")
	if cmd.Short != "" {
		b.WriteString("\n" + cmd.Short + "\n")
	}
	var subs []*cobra.Command
	for _, s := range cmd.Commands() {
		if !s.Hidden {
			subs = append(subs, s)
		}
	}
	if len(subs) > 0 {
		b.WriteString("\nSubcommands:\n")
		width := 0
		for _, s := range subs {
			width = max(width, len(s.Use))
		}
		for _, s := range subs {
			b.WriteString("  " + s.Use + strings.Repeat(" ", width-len(s.Use)) + "  " + s.Short + "\n")
		}
	}
	return b.String() + "\n"
}

// namesCache is the runner of the shell: it keeps the answer of each
// 'sudo -n tacctl _completion-names <kind> ...' for ttl, so Tab does not
// run sudo on every key; everything else goes to the runner as it is.
type namesCache struct {
	execx.Runner
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex
	m  map[string]cachedNames
}

type cachedNames struct {
	at  time.Time
	res execx.Result
	err error
}

// Run answers a names query from the cache while it is fresh.
func (c *namesCache) Run(ctx context.Context, cmd execx.Cmd) (execx.Result, error) {
	if cmd.Name != "sudo" || !slices.Contains(cmd.Args, "_completion-names") {
		return c.Runner.Run(ctx, cmd)
	}
	key := strings.Join(cmd.Argv(), "\x00")
	c.mu.Lock()
	if e, ok := c.m[key]; ok && c.now().Sub(e.at) < c.ttl {
		c.mu.Unlock()
		return e.res, e.err
	}
	c.mu.Unlock()
	res, err := c.Runner.Run(ctx, cmd)
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]cachedNames{}
	}
	c.m[key] = cachedNames{at: c.now(), res: res, err: err}
	c.mu.Unlock()
	return res, err
}

// sshWithoutTerminal reports whether this process came in over ssh with no
// terminal allocated (SSH_CONNECTION set, SSH_TTY not) and reads its commands
// from a pipe or socket rather than a file someone redirected on purpose.
func sshWithoutTerminal(env interface{ Get(string) string }, stdin io.Reader) bool {
	if env.Get("SSH_CONNECTION") == "" || env.Get("SSH_TTY") != "" {
		return false
	}
	f, ok := stdin.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && !st.Mode().IsRegular()
}
