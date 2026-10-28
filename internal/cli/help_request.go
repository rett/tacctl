package cli

// '-h' and '--help' after the words of a command: the help of that command,
// the same text '?' prints in the shell and the console, from the same code
// (shell.HelpText). A command that has sub-commands lists them with their
// argument columns and descriptions; any other prints its usage lines, its
// options with their values, and what comes next. The text is written with
// its colours; a stream that is not a terminal, NO_COLOR and TACCTL_COLOR
// take them out (app.New, ui.Colour), so a pipe gets plain text.
//
// The help runs as the invoking user, before the tier gate and sudo: it
// reads no state of tacctl, and the live names that '?' would list are not
// asked for ('--help' is the command's help, not the list of its values).
// In 'tacctl shell' and the console the same text is written in the shell
// itself, with the tier's view (shellExec). A bare 'tacctl --help' is the
// top-level usage as before (root.go).

import (
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/ui"
)

// helpFlags are the words that ask for help.
var helpFlags = []string{"-h", "--help"}

// helpRequest reports whether args are the words of a command followed by
// -h or --help, and gives the words. The flag is the last word, there is no
// '--' before it, and it is not the value of a flag that waits for one; the
// words name a command of the tree (not a hidden one) and no flag of the
// command is -h or --help itself.
func helpRequest(root *cobra.Command, args []string) (words []string, ok bool) {
	n := len(args)
	if n < 2 || !slices.Contains(helpFlags, args[n-1]) || slices.Contains(args[:n-1], "--") {
		return nil, false
	}
	words = args[:n-1]
	cmd, path, rest := shellCommand(root, words)
	if cmd == root || cmd.Hidden || strings.HasPrefix(path[0], "_") {
		return nil, false
	}
	if spec, has := specFor(path); has {
		if waitsForValue(spec, rest) {
			return nil, false
		}
		for _, f := range spec.Flags {
			if slices.ContainsFunc(f.Names, func(n string) bool { return slices.Contains(helpFlags, n) }) {
				return nil, false
			}
		}
	}
	return words, true
}

// helpOnlyCmd is '__help [--] <word>...': the help of the command the words
// name, as '?' prints it, for the bash help key (completion_bashkey.go). It
// is the only thing the key runs. The words are plain words: no flag is read
// or acted on (a flag that waits for a value is a word of the path, as it is
// for '?'), nothing is dispatched, and the status is 0. It runs as the
// invoking user, with no sudo, no gate and no state (noSudo).
func helpOnlyCmd(inv *invocation) *cobra.Command {
	c := hidden("__help")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		inv.helpList(cmd.Root(), args)
		return nil
	}
	return c
}

// helpList writes the help of the command words name. It runs no command:
// it reads the tree and the usage blocks only. A hidden command, or one under
// a hidden one, has no help to show.
func (inv *invocation) helpList(root *cobra.Command, words []string) {
	for c, rest := root, words; len(rest) > 0; rest = rest[1:] {
		if c = child(c, rest[0]); c == nil {
			break
		} else if c.Hidden {
			_, _ = io.WriteString(inv.app.Out.Stdout, shell.HelpText(nil, "", false, false, 0))
			return
		}
	}
	complete := inv.shellCompleter(root)
	cmd, _, rest := shellCommand(root, words)
	var cands []shell.Candidate
	if len(rest) == 0 && slices.ContainsFunc(cmd.Commands(), func(c *cobra.Command) bool { return !c.Hidden }) {
		cands = shell.Candidates(complete, words, "")
	}
	var explained string
	var ok bool
	if len(cands) == 0 {
		explained, ok = inv.shellExplain(root)(words)
	}
	width := 0
	if f, isFile := ui.File(inv.app.Out.Stdout); isFile && term.IsTerminal(int(f.Fd())) {
		if w, _, err := term.GetSize(int(f.Fd())); err == nil {
			width = w
		}
	}
	// Written with its colours: the stream takes them out when it is not
	// a terminal, NO_COLOR or TACCTL_COLOR=never. In a console session the
	// console's color setting decides instead: off writes none, on writes
	// them past the stream's filter.
	out := inv.app.Out.Stdout
	if inv.shellColor == console.ColorOn {
		if f, isFile := ui.File(out); isFile {
			out = f
		}
	}
	_, _ = io.WriteString(out, shell.HelpText(cands, explained, ok, inv.shellColor != console.ColorOff, width))
}
