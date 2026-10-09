package cli

// The text of 'tacctl shell' that comes from the usage text: its help, the
// Tab listing of the commands, and the descriptions every completion shows.
// The top-level usage block (help_text.go) is the one source of the
// commands' order, argument column and descriptions: cobra's Short of each
// top-level command is set from it (applyTopShorts), so bash, zsh and fish
// completion, the shell and 'tacctl' with no arguments cannot differ.

import (
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/tier"
)

// usageRow is one row of a usage block: the left column (the command with
// its arguments), its first word and the description.
type usageRow struct{ Left, Name, Desc string }

// reProg is the program prefix some blocks put before each row's verb.
var reProg = regexp.MustCompile(`^tacctl [a-z-]+ `)

// splitRow splits a usage line at its widest run of blanks (the last one
// of equal width): the argument column from the description.
func splitRow(line string) (left, desc string, ok bool) {
	body := strings.TrimPrefix(line, "  ")
	bestAt, bestLen := -1, 1
	for i := 0; i < len(body); {
		if body[i] != ' ' {
			i++
			continue
		}
		j := i
		for j < len(body) && body[j] == ' ' {
			j++
		}
		if j-i >= 2 && j-i >= bestLen && j < len(body) {
			bestAt, bestLen = i, j-i
		}
		i = j
	}
	if bestAt < 0 {
		return "", "", false
	}
	return body[:bestAt], strings.TrimSpace(body[bestAt+bestLen:]), true
}

// usageRows are the rows of a block's list: the lines after the heading
// line (the line that ends in ':') up to the next blank line.
func usageRows(block, heading string) []usageRow {
	_, after, ok := strings.Cut(block, "\n"+heading+"\n")
	if !ok {
		return nil
	}
	var rows []usageRow
	lines := strings.Split(after, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			// A blank line ends the list unless the list goes on.
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  ") && !strings.HasPrefix(lines[i+1], "   ") {
				continue
			}
			break
		}
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		left, desc, ok := splitRow(line)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(reProg.ReplaceAllString(left, ""), " ")
		rows = append(rows, usageRow{Left: left, Name: name, Desc: desc})
	}
	return rows
}

// topRows are the rows of the top-level usage's command list.
func topRows() []usageRow { return usageRows(usageBlocks["top"], "Commands:") }

// applyTopShorts sets the Short of each top-level command to its row's
// description in the top-level usage.
func applyTopShorts(root *cobra.Command) {
	for _, r := range topRows() {
		if c := child(root, r.Name); c != nil {
			c.Short = r.Desc
		}
	}
}

// familyRows are the rows of the usage block of a command family (the
// block 'help <family>' prints), in the order of the block, by verb: the
// first row of each verb wins.
func (inv *invocation) familyRows(family string) []usageRow {
	f, ok := shellHelpBlocks[family]
	if !ok {
		return nil
	}
	block := f(inv)
	var rows []usageRow
	seen := map[string]bool{}
	for _, heading := range []string{"Subcommands:", "Usage:"} {
		for _, r := range usageRows(block, heading) {
			if !seen[r.Name] && !strings.ContainsAny(r.Name[:1], "-[<(") {
				seen[r.Name] = true
				rows = append(rows, r)
			}
		}
	}
	return rows
}

// shellTop is the top-level usage as 'help' prints it in the shell: the
// block of 'tacctl' with the words that name the program left out, and the
// Shell section after it (with system-shell in the console).
func shellTop(version string, console bool) string {
	return shellTopFor(version, console, nil, "")
}

// shellTopFor is shellTop for a caller whose tier is eff: only the commands
// (and the hint and example lines) that tier can run are listed (D56), with
// a sentence saying so. A nil root lists everything.
func shellTopFor(version string, console bool, root *cobra.Command, eff tier.Tier) string {
	text := Usage("top", UsageVars{"version": version})
	text = strings.Replace(text, "Usage: tacctl <command> [arguments]", "Usage: <command> [arguments]", 1)
	text = strings.Replace(text, "Run any command without arguments for detailed help, e.g.:\n  tacctl user\n  tacctl config\n  tacctl backend",
		"Type help <command> for detailed help, e.g.:\n  help user\n  help config\n  help backend", 1)
	head, examples, ok := strings.Cut(text, "\nExamples:\n")
	if ok {
		text = head + "\nExamples:\n" + strings.ReplaceAll("\n"+examples, "\n  tacctl ", "\n  ")[1:]
	}
	if root != nil {
		text = filterTop(root, eff, text)
		text = strings.Replace(text, "\nType help <command> for detailed help", "\n"+viewNote(eff)+"\nType help <command> for detailed help", 1)
	}
	return text + shellSection(console)
}

// keyRows are the rows of the Shell section for the keys.
var keyRows = [][2]string{
	{"Tab", "Complete the word; twice: list the names"},
	{"?", "Show the choices with descriptions, or the usage of the command typed so far"},
	{"Ctrl-R", "Search the history"},
	{"Ctrl-C", "Cancel the line, or stop the running command"},
	{"Ctrl-D", "Leave the shell"},
}

// shellRows are the rows of the Shell section: the shell's own words
// (the rows the Tab listing shows; system-shell in the console) and the
// keys.
func shellRows(console bool) [][2]string {
	var rows [][2]string
	for _, r := range shell.Rows(console) {
		rows = append(rows, [2]string{r.Left, r.Desc})
	}
	return append(rows, keyRows...)
}

// shellSection is the Shell section, in the columns of the command list.
func shellSection(console bool) string {
	width := 0
	for _, r := range topRows() {
		width = max(width, len(r.Left))
	}
	var b strings.Builder
	b.WriteString("Shell:\n")
	for _, r := range shellRows(console) {
		b.WriteString("  " + r[0] + strings.Repeat(" ", max(width-len(r[0]), 0)) + "  " + r[1] + "\n")
	}
	return b.String() + "\n"
}
