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
// declares its verbs and gives each one a RunE (native.go).
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

// newRoot builds the tree for one invocation.
func newRoot(inv *invocation) *cobra.Command {
	root := &cobra.Command{Use: "tacctl", Short: "TACACS+ (tacquito) and RADIUS (FreeRADIUS) from one store"}
	root.AddCommand(lifecycleCmds(inv)...)
	root.AddCommand(passwdCmd(inv), statusCmd(inv))
	root.AddCommand(
		userCmd(inv), groupCmd(inv), scopeCmd(inv), hostCmd(inv), backendCmd(inv), storeCmd(inv),
		configCmd(inv), logCmd(inv), backupCmd(inv), hashCmd(inv), versionCmd(inv),
		// Bash completion's bridge to live names (sudo -n tacctl _completion-names <kind>).
		completionNamesCmd(inv),
		// The generated shell completion script (completion.go).
		completionCmd(inv),
		// One lifecycle phase of one backend, for drivers and tests (phase.go).
		phaseCmd(inv),
	)
	// 'help' is not a command of tacctl ('tacctl help' prints the usage and
	// exits 1, as any unknown word does); this hidden stand-in only keeps
	// cobra from adding its own help command when Execute runs.
	help := hidden("help")
	root.SetHelpCommand(help)
	root.CompletionOptions.DisableDefaultCmd = true
	root.DisableSuggestions = true
	root.DisableAutoGenTag = true
	// No command, 'help', '-h', '--help' or a word that is no command: the
	// top-level usage on stdout, exit 1 (bin/tacctl.sh's '*) usage; exit 1',
	// after the tier gate as every command).
	topUsage := inv.native(noPreflight, func([]string) error {
		inv.write(Usage("top", UsageVars{"version": inv.build.Version}))
		return exit(1)
	})
	root.RunE, help.RunE = topUsage, topUsage
	attachCompletion(inv, root)
	configure(root)
	configure(help)
	return root
}

// configure switches cobra's parsing and output off on every command.
func configure(c *cobra.Command) {
	c.DisableFlagParsing = true
	c.Args = cobra.ArbitraryArgs
	c.SilenceErrors = true
	c.SilenceUsage = true
	for _, sub := range c.Commands() {
		configure(sub)
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

// complete runs cobra's __complete over the tree. It never reads tacctl's
// state; live names come through 'sudo -n tacctl _completion-names' from
// the verbs' ValidArgsFunction (completion.go).
func complete(ctx context.Context, a *app.App, root *cobra.Command) error {
	var buf bytes.Buffer
	root.SetArgs(a.Args)
	root.SetIn(a.Stdin)
	root.SetOut(&buf)
	root.SetErr(a.Out.Stderr)
	err := root.ExecuteContext(ctx)
	out := buf.String()
	// cobra offers its help command among the top-level words even when it
	// is hidden; tacctl has no 'help' command.
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
