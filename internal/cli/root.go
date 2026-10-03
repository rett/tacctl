package cli

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
)

// The command tree. Each family has a file (user.go, scope.go, ...) that
// declares its verbs; a verb without a RunE of its own is delegated to the
// bash implementation (delegate.go) until its cut-over package gives it one.
//
// Dispatch is bash's, not cobra's: the first argument is the command word,
// the next ones name sub-commands only while they match one exactly
// (resolve). cobra's Execute runs only for its completion protocol
// (__complete), so none of its defaults (help command, -h/--help, "did you
// mean", argument validation, error text) can reach the CLI contract; they
// are switched off as well (configure), for the completion path and for
// whoever calls Execute later.

// verb declares a command named name with sub-commands.
func verb(name, short string, subs ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: name, Short: short}
	c.AddCommand(subs...)
	return c
}

// hidden declares a command that completion does not offer.
func hidden(name string) *cobra.Command {
	return &cobra.Command{Use: name, Hidden: true}
}

// newRoot builds the tree for one invocation; commands without a RunE of
// their own delegate to bash.
func newRoot(inv *invocation) *cobra.Command {
	run := func(*cobra.Command, []string) error { return delegate(inv.app) }
	root := &cobra.Command{Use: "tacctl", Short: "TACACS+ (tacquito) and RADIUS (FreeRADIUS) from one store"}
	root.AddCommand(lifecycleCmds()...)
	root.AddCommand(
		userCmd(), groupCmd(), scopeCmd(), hostCmd(), backendCmd(), storeCmd(),
		configCmd(), logCmd(), backupCmd(), hashCmd(), versionCmd(inv),
		// Bash completion's bridge to live names (sudo -n tacctl _completion-names <kind>).
		hidden("_completion-names"),
	)
	// 'help' is not a command of tacctl ('tacctl help' prints the usage and
	// exits 1, as any unknown word does); this hidden stand-in only keeps
	// cobra from adding its own help command when Execute runs.
	help := hidden("help")
	root.SetHelpCommand(help)
	root.CompletionOptions.DisableDefaultCmd = true
	root.DisableSuggestions = true
	root.DisableAutoGenTag = true
	configure(root, run)
	configure(help, run)
	return root
}

// configure switches cobra's parsing and output off on every command and
// gives every command without one the default handler.
func configure(c *cobra.Command, run func(*cobra.Command, []string) error) {
	c.DisableFlagParsing = true
	c.Args = cobra.ArbitraryArgs
	c.SilenceErrors = true
	c.SilenceUsage = true
	if c.RunE == nil && c.Run == nil {
		c.RunE = run
	}
	for _, sub := range c.Commands() {
		configure(sub, run)
	}
}

// resolve finds the command args name, bash style: walk down while the next
// argument is exactly a sub-command's name, return it and the rest.
func resolve(root *cobra.Command, args []string) (*cobra.Command, []string) {
	cmd := root
	for len(args) > 0 {
		next := child(cmd, args[0])
		if next == nil {
			break
		}
		cmd, args = next, args[1:]
	}
	return cmd, args
}

func child(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}

// isComplete reports whether args are cobra's completion protocol.
func isComplete(args []string) bool {
	return len(args) > 0 && (args[0] == cobra.ShellCompRequestCmd || args[0] == cobra.ShellCompNoDescRequestCmd)
}

// complete runs cobra's __complete over the tree. It never delegates and
// never reads tacctl's state; live names will come through
// 'sudo -n tacctl _completion-names' from ValidArgsFunction (Decision 3).
func complete(ctx context.Context, a *app.App, root *cobra.Command) error {
	var buf bytes.Buffer
	root.SetArgs(a.Args)
	root.SetIn(a.Stdin)
	root.SetOut(&buf)
	root.SetErr(a.Out.Stderr)
	err := root.ExecuteContext(ctx)
	out := buf.String()
	// cobra offers its help command among the top-level words even when it
	// is hidden; tacctl has no 'help' command (the hand-written completion
	// does not offer it either).
	if len(a.Args) == 2 {
		var kept []string
		for _, l := range strings.SplitAfter(out, "\n") {
			if w, _, _ := strings.Cut(strings.TrimSuffix(l, "\n"), "\t"); w != "help" {
				kept = append(kept, l)
			}
		}
		out = strings.Join(kept, "")
	}
	if _, werr := io.WriteString(a.Out.Stdout, out); err == nil {
		err = werr
	}
	return err
}
