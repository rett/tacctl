package cli

// An unknown top-level word (0.2.18 D277): one error line that names it, a
// suggestion when one fits, and the pointer to the list of commands; not
// the whole usage.

import (
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

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
	best, out := 3, []string(nil)
	lw := strings.ToLower(w)
	for _, c := range root.Commands() {
		if c.Hidden {
			continue
		}
		d := editDistance(lw, c.Name())
		if d > 2 || (d >= len(lw) && lw != c.Name()) {
			continue // too far, or as far from w as from nothing
		}
		switch {
		case d < best:
			best, out = d, []string{c.Name()}
		case d == best:
			out = append(out, c.Name())
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
