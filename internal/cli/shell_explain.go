package cli

// What '?' prints in 'tacctl shell' where no word can be offered (free
// text, or nothing more): the usage lines of the command typed so far, its
// flags and what comes next. Everything is read from the usage blocks that
// 'tacctl <family>' prints and from the verbs' Specs, so the descriptions
// have one source.

import (
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// shellCommand is the deepest command words name, its path below the root
// and the words after it.
func shellCommand(root *cobra.Command, words []string) (cmd *cobra.Command, path, rest []string) {
	cmd, rest = root, words
	for len(rest) > 0 {
		next := child(cmd, rest[0])
		if next == nil {
			break
		}
		cmd, rest, path = next, rest[1:], append(path, next.Name())
	}
	return cmd, path, rest
}

// helpBlock is the usage block that covers path ('help <path>' prints it)
// and how many words of path name it: a family's block covers its verbs.
func (inv *invocation) helpBlock(cmd *cobra.Command, path []string) (string, int) {
	for n := len(path); n > 0; n-- {
		if f, ok := shellHelpBlocks[strings.Join(path[:n], " ")]; ok {
			return f(inv), n
		}
	}
	return treeUsage(cmd), len(path)
}

// blockBody is the block's lines up to its Examples.
func blockBody(block string) []string {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		if l == "Examples:" {
			return lines[:i]
		}
	}
	return lines
}

// verbRows are the rows of block for verb, in the block's order: a row
// whose description is on the next line (a long argument column) is one
// row too.
func verbRows(block, verb string) []usageRow {
	lines := blockBody(block)
	var rows []usageRow
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		first, _, _ := strings.Cut(reProg.ReplaceAllString(strings.TrimPrefix(line, "  "), ""), " ")
		if first != verb {
			continue
		}
		left, desc, ok := splitRow(line)
		if !ok {
			left = strings.TrimSpace(line)
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "   ") {
				desc = strings.TrimSpace(lines[i+1])
			}
		}
		rows = append(rows, usageRow{Left: left, Name: verb, Desc: desc})
	}
	return rows
}

// ownUsage are the 'Usage: tacctl <path> ...' lines of a command's own
// block, as rows without a description.
func ownUsage(block string) []usageRow {
	var rows []usageRow
	for _, line := range blockBody(block) {
		if u, ok := strings.CutPrefix(line, "Usage: "); ok {
			rows = append(rows, usageRow{Left: strings.TrimPrefix(u, "tacctl ")})
		}
	}
	return rows
}

// shellUsage is the usage rows of the command at path, and the block they
// come from.
func (inv *invocation) shellUsage(cmd *cobra.Command, path []string) ([]usageRow, string) {
	block, n := inv.helpBlock(cmd, path)
	if n < len(path) {
		return verbRows(block, path[n]), block
	}
	return ownUsage(block), block
}

var reFlagValue = regexp.MustCompile(`^(<[^>]*>(?:\[[^\]]*\])?|[A-Za-z0-9]+:<[^>]*>|[a-z0-9]+(?:\|[a-z0-9]+)+)`)

// flagHelp is what the block says of a flag: its value's placeholder (for
// a flag that takes one) and its description. An option line ('  -p <port>
// Connect ...') gives both; else a row of the verb that adds the flag to
// the first row ('add <username> <group> --hash <hash>  Add with ...'); the
// placeholder may also come from anywhere the block names the flag.
func flagHelp(block string, rows []usageRow, f Flag) (value, desc string) {
	findValue := func(text string) string {
		for _, n := range f.Names {
			for i := strings.Index(text, n); i >= 0; {
				end := i + len(n)
				before := i == 0 || strings.ContainsRune(" \t\n[(,", rune(text[i-1]))
				if before && end < len(text) && (text[end] == ' ' || text[end] == '=') {
					if m := reFlagValue.FindString(text[end+1:]); m != "" {
						return m
					}
				}
				j := strings.Index(text[end:], n)
				if j < 0 {
					break
				}
				i = end + j
			}
		}
		return ""
	}
	for _, line := range blockBody(block) {
		body := strings.TrimSpace(line)
		if !strings.HasPrefix(line, "  ") || !strings.HasPrefix(body, "-") {
			continue
		}
		left, d, ok := splitRow(line)
		// An option line is indented deeper than a row, and may name more
		// than one flag ('--port <n>, --identity <file>'): each is the first
		// word of a comma-separated part.
		left = strings.TrimSpace(left)
		names := false
		for _, part := range strings.Split(left, ", ") {
			if first, _, _ := strings.Cut(part, " "); slices.Contains(f.Names, first) {
				names = true
			}
		}
		if ok && names {
			desc = d
			if f.Value {
				value = findValue(left)
			}
			break
		}
	}
	if desc == "" {
		for i, r := range rows {
			if i > 0 && slices.ContainsFunc(strings.Fields(r.Left), func(w string) bool { return slices.Contains(f.Names, w) }) {
				desc = r.Desc
				if f.Value && value == "" {
					value = findValue(r.Left)
				}
				break
			}
		}
	}
	if f.Value && value == "" {
		value = findValue(strings.Join(blockBody(block), "\n"))
		if value == "" {
			value = "<value>"
		}
	}
	return value, desc
}

// flagLabel is a flag as the lists show it: its spellings and its value.
func flagLabel(f Flag, value string) string {
	l := strings.Join(f.Names, ", ")
	if value != "" {
		l += " " + value
	}
	return l
}

// placeholders are the positional arguments a usage row names after the
// command words: up to the first flag, option group or alternative.
func placeholders(row usageRow, skip int) []string {
	f := strings.Fields(reProg.ReplaceAllString(row.Left, ""))
	if skip > len(f) {
		return nil
	}
	var out []string
	for _, w := range f[skip:] {
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[-") || w == "|" || w == "[options]" {
			break
		}
		out = append(out, w)
	}
	return out
}

// positionals counts the positional words of rest under spec (a value
// flag's value is not one; '--' ends them).
func positionals(spec Spec, rest []string) int {
	pos := 0
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		switch {
		case w == "--":
			return pos
		case strings.HasPrefix(w, "-") && len(w) > 1:
			name, _, hasValue := strings.Cut(w, "=")
			for _, f := range spec.Flags {
				if f.Value && !hasValue && slices.Contains(f.Names, name) {
					i++
				}
			}
		default:
			pos++
		}
	}
	return pos
}

// alignRows is rows as '  <left>  <desc>' lines, the descriptions aligned.
func alignRows(rows [][2]string) string {
	width := 0
	for _, r := range rows {
		if r[1] != "" {
			width = max(width, len(r[0]))
		}
	}
	var b strings.Builder
	for _, r := range rows {
		if r[1] == "" {
			b.WriteString("  " + r[0] + "\n")
			continue
		}
		b.WriteString("  " + r[0] + strings.Repeat(" ", max(width-len(r[0]), 0)) + "  " + r[1] + "\n")
	}
	return b.String()
}

// shellExplain is the shell's Explainer: for words that name a command
// that takes no further sub-command, its usage rows, its flags not on the
// line yet, and what comes next.
func (inv *invocation) shellExplain(root *cobra.Command) func([]string) (string, bool) {
	return func(words []string) (string, bool) {
		cmd, path, rest := shellCommand(root, words)
		if cmd == root || cmd.Hidden || (len(rest) == 0 && slices.ContainsFunc(cmd.Commands(), func(c *cobra.Command) bool { return !c.Hidden })) {
			return "", false
		}
		rows, block := inv.shellUsage(cmd, path)
		var b strings.Builder
		var lines [][2]string
		for _, r := range rows {
			lines = append(lines, [2]string{r.Left, r.Desc})
		}
		if len(lines) > 0 {
			b.WriteString("Usage:\n" + alignRows(lines))
		}
		spec, hasSpec := specFor(path)
		var flags [][2]string
		for _, f := range spec.Flags {
			typed := slices.ContainsFunc(rest, func(w string) bool {
				name, _, _ := strings.Cut(w, "=")
				return slices.Contains(f.Names, name)
			})
			if typed || (f.Only != "" && !slices.Contains(rest, f.Only)) {
				continue
			}
			value, desc := flagHelp(block, rows, f)
			flags = append(flags, [2]string{flagLabel(f, value), desc})
		}
		if len(flags) > 0 {
			b.WriteString("Options:\n" + alignRows(flags))
		}
		var args []string
		if len(rows) > 0 {
			skip := 1
			if _, n := inv.helpBlock(cmd, path); n == len(path) {
				skip = len(path)
			}
			args = placeholders(rows[0], skip)
		}
		pos := positionals(spec, rest)
		next := "<Enter> to run"
		switch remaining := args[min(pos, len(args)):]; {
		case len(remaining) == 0 || (hasSpec && spec.MaxArgs >= 0 && pos >= spec.MaxArgs):
		case hasSpec && pos < spec.MinArgs:
			next = strings.Join(remaining, " ")
		default:
			next = strings.Join(remaining, " ") + ", or " + next
		}
		b.WriteString("Next: " + next + "\n")
		return b.String(), true
	}
}

// flagDescs gives the flag candidates of a verb their descriptions from
// the verb's usage block.
func (inv *invocation) flagDescs(cmd *cobra.Command, path []string, spec Spec, cands []string) map[string]string {
	if !slices.ContainsFunc(cands, func(c string) bool { return strings.HasPrefix(c, "-") }) {
		return nil
	}
	rows, block := inv.shellUsage(cmd, path)
	out := map[string]string{}
	for _, f := range spec.Flags {
		_, desc := flagHelp(block, rows, f)
		if desc == "" && len(path) == 1 {
			// A top-level command without a block of its own: the option
			// lines of tacctl's usage.
			top := Usage("top", UsageVars{"version": inv.build.Version})
			_, desc = flagHelp(top, verbRows(top, path[0]), f)
		}
		for _, n := range f.Names {
			out[n] = desc
		}
	}
	return out
}

// listKindName is what the word completed after rest is, plural, for the
// question before a long list: the kind of the value a flag waits for, or
// of the next positional (as completeSpec finds them); "choices" for a
// fixed word list or free text.
func listKindName(spec Spec, rest []string) string {
	kind, pos := "", 0
	var words []string
	pending := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			return "choices"
		}
		name, _, hasVal := strings.Cut(a, "=")
		var flag *Flag
		for j := range spec.Flags {
			if slices.Contains(spec.Flags[j].Names, name) {
				flag = &spec.Flags[j]
			}
		}
		switch {
		case flag == nil && len(a) >= 2 && a[0] == '-':
		case flag == nil:
			words = append(words, a)
			pos++
		case flag.Value && !hasVal && i+1 < len(rest):
			i++
		case flag.Value && !hasVal:
			kind, pending = flag.Kind, true
		}
	}
	if !pending && pos < len(spec.Args) {
		kind = spec.Args[pos]
		if r, ok := strings.CutPrefix(kind, "@"); ok {
			word, k, _ := strings.Cut(r, ":")
			kind = ""
			if slices.Contains(words, word) {
				kind = k
			}
		}
	}
	kind = strings.TrimSuffix(kind, KindList)
	switch kind {
	case KindUsers, KindGroups, KindScopes, KindHosts, KindDevices, KindBackups, KindBackends, KindListeners:
		return kind
	case KindEnabledBackends:
		return KindBackends
	case KindFile:
		return "files"
	}
	return "choices"
}
