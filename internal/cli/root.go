package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/shell"
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

// families are the command families added after the ones newRoot lists: a
// family file appends its constructor in init() (registerFamily) and needs
// no edit of root.go. A family's arguments for completion are registered the
// same way (registerSpecs, completion.go); its names for completion with
// registerDeviceNames or a new kind in completion_names.go.
var families []func(*invocation) *cobra.Command

// registerFamily adds a command family to the tree.
func registerFamily(f func(*invocation) *cobra.Command) { families = append(families, f) }

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
	root := &cobra.Command{Use: "tacctl", Short: "Pluggable network-device AAA management"}
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
	for _, f := range families {
		root.AddCommand(f(inv))
	}
	// 'help' is not a command of tacctl ('tacctl help' prints the usage and
	// exits 1, as any unknown word does); this hidden stand-in only keeps
	// cobra from adding its own help command when Execute runs.
	help := hidden("help")
	root.SetHelpCommand(help)
	root.CompletionOptions.DisableDefaultCmd = true
	root.DisableSuggestions = true
	root.DisableAutoGenTag = true
	// No command, 'help', '-h' or '--help': the top-level usage on stdout,
	// exit 1 (after the tier gate as every command). A word that is no
	// command is an error that names it (unknownCommand), exit 1. 'help'
	// reaches the root's RunE: the stand-in is no child of it.
	root.RunE = inv.native(noPreflight, func(args []string) error {
		if w := arg(args, 0); w != "" && w != "help" && w != "-h" && w != "--help" {
			return inv.unknownCommand(root, w)
		}
		inv.writeTopUsage()
		return exit(1)
	})
	help.RunE = inv.native(noPreflight, func([]string) error {
		inv.writeTopUsage()
		return exit(1)
	})
	attachCompletion(inv, root)
	applyTopShorts(root)
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
	if len(a.Args) == 2 {
		out = withoutHelp(out)
	}
	if a.Args[0] == cobra.ShellCompRequestCmd {
		out = capDescriptions(out, summaryMax)
	}
	if _, werr := io.WriteString(a.Out.Stdout, out); err == nil {
		err = werr
	}
	return err
}

// withoutHelp is the answer of cobra's __complete without the line of its
// help command: cobra offers it among the top-level words even when it is
// hidden, and tacctl has no 'help' command.
func withoutHelp(out string) string {
	var kept []string
	for _, l := range strings.SplitAfter(out, "\n") {
		if w, _, _ := strings.Cut(strings.TrimSuffix(l, "\n"), "\t"); w != "help" {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "")
}

// summaryMax is the longest description of a command or a flag (style
// rule, docs/development/README.md): the zsh and fish menus show the
// descriptions of 'tacctl __complete' and have no room for more; a longer
// one (the lists of the shell wrap it) is cut there, at a blank, and ends
// in "...".
const summaryMax = 72

// capDescriptions cuts the description of each 'word<TAB>description' line
// of cobra's answer to max characters.
func capDescriptions(out string, max int) string {
	lines := strings.SplitAfter(out, "\n")
	for i, l := range lines {
		body := strings.TrimSuffix(l, "\n")
		if w, d, ok := strings.Cut(body, "\t"); ok && utf8.RuneCountInString(d) > max {
			lines[i] = w + "\t" + shell.Cap(d, max) + l[len(body):]
		}
	}
	return strings.Join(lines, "")
}

// writeTopUsage prints the top-level usage, as 'tacctl' with no arguments
// does (and a pasted line that is only 'tacctl' in the shell).
func (inv *invocation) writeTopUsage() {
	inv.write(Usage("top", UsageVars{"version": inv.build.Version}))
}
