package cli

// An unknown top-level word (0.2.18 D277): one error line that names it, a
// suggestion when one fits, and the pointer to the list of commands; not
// the whole usage. A word below the first that is none of the sub-commands
// of its command (0.2.22) is answered the same way (unknownSub): the error,
// the closest verbs of that level, and one line that points at the help of
// the command.

import (
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// notACommand reports whether w, the first word of a line, is a top-level
// word the root answers with unknownCommand: it is no command (hidden ones
// count), and not 'help', '-h' or '--help' (the usage). The sudo re-exec and
// the shell ask it before they run 'sudo', so a word no tier could run does
// not ask for a password first (0.2.19); the tier gate and the sudoers check
// stay the authority for every other word.
func notACommand(root *cobra.Command, w string) bool {
	if w == "" || w == "help" || w == "-h" || w == "--help" || noSudo[w] {
		return false
	}
	return child(root, w) == nil
}

// unknownSub is the answer of a command to a word sub that is none of its
// sub-commands, whichever file dispatches it: the error line, the closest
// verbs of that level, one line that points at the help of the command, exit
// 1; not the usage. The command is the deepest one the words typed name, so a
// verb that dispatches a word after a name ('scope secret <scope> <verb>')
// names itself. verbs are the words of the level where they are not
// sub-commands of the tree; none, they are its sub-commands.
func (inv *invocation) unknownSub(sub string, verbs ...string) error {
	return inv.unknownSubNote("", sub, verbs...)
}

// unknownSubNote is unknownSub for a verb whose error line says more than
// that the word is unknown: note follows the word on the same line.
func (inv *invocation) unknownSubNote(note, sub string, verbs ...string) error {
	root := inv.root
	if root == nil {
		root = newRoot(inv)
	}
	_, path, _ := shellCommand(root, inv.app.Args)
	return inv.unknownSubAtNote(root, path, sub, verbs, note)
}

// unknownSubAt is unknownSub for the command at path (the words after
// 'tacctl'), for a caller that has the path already.
func (inv *invocation) unknownSubAt(root *cobra.Command, path []string, sub string, verbs []string) error {
	return inv.unknownSubAtNote(root, path, sub, verbs, "")
}

func (inv *invocation) unknownSubAtNote(root *cobra.Command, path []string, sub string, verbs []string, note string) error {
	inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'" + note)
	if s := subSuggestions(root, path, sub, verbs, inv.viewFilter(root)); len(s) > 0 {
		_, _ = io.WriteString(inv.app.Out.Stderr, "Did you mean: "+strings.Join(s, ", ")+"?\n")
	}
	if len(path) == 0 {
		_, _ = io.WriteString(inv.app.Out.Stderr, "Run 'tacctl' for the commands.\n")
	} else {
		_, _ = io.WriteString(inv.app.Out.Stderr, "Run 'tacctl "+strings.Join(path, " ")+" -h' for usage.\n")
	}
	return exit(1)
}

// viewFilter tells whether the caller's tier can run the command at a path,
// as far as the tier is known: in the shell and the console it is the view of
// the lists, in a command run under sudo the tier the gate held the caller
// to, and before sudo (nothing is read then) it is unknown, so everything is
// shown.
func (inv *invocation) viewFilter(root *cobra.Command) func([]string) bool {
	eff, all, active := inv.currentView()
	if !active {
		eff, all = viewOf(inv.callerTier)
	}
	return func(p []string) bool { return viewShows(root, eff, all, p) }
}

// plainWord reports whether w is a word a command with sub-commands answers
// as an unknown one: not empty, not 'help' and not a flag. A command whose
// usage was its whole answer to anything else keeps that for those words (a
// flag may come before the verb: 'log --backend tacacs tail').
func plainWord(w string) bool { return w != "" && w != "help" && !strings.HasPrefix(w, "-") }

// specVerbs are the verbs a table of Specs holds, by name.
func specVerbs(specs map[string]Spec) []string {
	out := make([]string, 0, len(specs))
	for v := range specs {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// choiceWord is a word of a choice the verb's first argument names
// ('list|seed').
var choiceWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// subSuggestions are the commands a mistyped word w below the command at
// path may have meant, at most maxSuggestions. A word that is a verb further
// down the command (a sub-command of one of its sub-commands, or a word of
// the choice a verb's first argument names: 'device config seed' is
// 'device config shapes seed') is answered with the commands that have it,
// the shorter paths first, then by name; else the sub-commands within two
// edits of it (closestWords), by name. The commands the caller's tier cannot
// run are not named (shown). The words of a leaf command's own verbs (verbs)
// are given as they are: the command that dispatches them is the one typed.
func subSuggestions(root *cobra.Command, path []string, w string, verbs []string, shown func([]string) bool) []string {
	if w == "" || strings.HasPrefix(w, "-") {
		return nil
	}
	if len(verbs) > 0 {
		return closestWords(w, verbs)
	}
	node, _, _ := shellCommand(root, path)
	var below [][]string
	var walk func(c *cobra.Command, p []string)
	walk = func(c *cobra.Command, p []string) {
		for _, sub := range c.Commands() {
			q := append(slices.Clone(p), sub.Name())
			if sub.Hidden || !shown(q) {
				continue
			}
			if sub.Name() == w && len(q) > len(path)+1 {
				below = append(below, q)
			}
			if spec, ok := specFor(q); ok && len(spec.Args) > 0 {
				if words := strings.Split(spec.Args[0], "|"); len(words) > 1 && slices.Contains(words, w) &&
					!slices.ContainsFunc(words, func(x string) bool { return !choiceWord.MatchString(x) }) {
					below = append(below, append(slices.Clone(q), w))
				}
			}
			walk(sub, q)
		}
	}
	walk(node, slices.Clone(path))
	prefix := strings.Join(append([]string{"tacctl"}, path...), " ") + " "
	var out []string
	if len(below) > 0 {
		slices.SortFunc(below, func(a, b []string) int {
			if len(a) != len(b) {
				return len(a) - len(b)
			}
			return strings.Compare(strings.Join(a, " "), strings.Join(b, " "))
		})
		for _, q := range below[:min(len(below), maxSuggestions)] {
			out = append(out, "tacctl "+strings.Join(q, " "))
		}
		return out
	}
	var names []string
	for _, sub := range node.Commands() {
		if !sub.Hidden && shown(append(slices.Clone(path), sub.Name())) {
			names = append(names, sub.Name())
		}
	}
	for _, n := range closestWords(w, names) {
		out = append(out, prefix+n)
	}
	return out
}

// maxSuggestions is how many commands a suggestion names at most.
const maxSuggestions = 4

// unknownCommand prints the error of a top-level word w that is no command
// and returns exit 1. A word that is a verb of a family is answered with
// the commands that have it ('enroll': device enroll, host enroll); else a
// command within two edits of it ('devce': device).
func (inv *invocation) unknownCommand(root *cobra.Command, w string) error {
	if strings.HasPrefix(w, "-") {
		inv.app.Out.ErrorE("Unknown option: '" + w + "'")
	} else {
		inv.app.Out.ErrorE("Unknown command: '" + w + "'")
	}
	if s := commandSuggestions(root, w); len(s) > 0 {
		for i := range s {
			s[i] = "tacctl " + s[i]
		}
		_, _ = io.WriteString(inv.app.Out.Stderr, "Did you mean: "+strings.Join(s, ", ")+"?\n")
	}
	_, _ = io.WriteString(inv.app.Out.Stderr, "Run 'tacctl' for the commands.\n")
	return exit(1)
}

// commandSuggestions are the commands a mistyped top-level word w may have
// meant, at most maxSuggestions, in a fixed order: the visible commands
// below the top level whose last word is w (the shorter paths first, then
// by name); when there is none, the visible top-level commands closest to
// w within two edits (letter case ignored), by name. A word that starts
// with '-' has none.
func commandSuggestions(root *cobra.Command, w string) []string {
	if w == "" || strings.HasPrefix(w, "-") {
		return nil
	}
	var verbs [][]string
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		for _, sub := range c.Commands() {
			if sub.Hidden {
				continue
			}
			p := append(slices.Clone(path), sub.Name())
			if len(p) > 1 && sub.Name() == w {
				verbs = append(verbs, p)
			}
			walk(sub, p)
		}
	}
	walk(root, nil)
	if len(verbs) > 0 {
		slices.SortFunc(verbs, func(a, b []string) int {
			if len(a) != len(b) {
				return len(a) - len(b)
			}
			return strings.Compare(strings.Join(a, " "), strings.Join(b, " "))
		})
		var out []string
		for _, p := range verbs[:min(len(verbs), maxSuggestions)] {
			out = append(out, strings.Join(p, " "))
		}
		return out
	}
	var names []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			names = append(names, c.Name())
		}
	}
	return closestWords(w, names)
}

// closestWords are the words of cands closest to w within two edits (letter
// case of w ignored), at most maxSuggestions, by name. A candidate as far
// from w as from nothing is not close.
func closestWords(w string, cands []string) []string {
	best, out := 3, []string(nil)
	lw := strings.ToLower(w)
	for _, c := range cands {
		d := editDistance(lw, c)
		if d > 2 || (d >= len(lw) && lw != c) {
			continue // too far, or as far from w as from nothing
		}
		switch {
		case d < best:
			best, out = d, []string{c}
		case d == best:
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out[:min(len(out), maxSuggestions)]
}

// editDistance is the Levenshtein distance of a and b (by byte).
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
