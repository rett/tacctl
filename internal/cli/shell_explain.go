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

	"github.com/rett/tacctl/internal/ui"
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
	lines := strings.Split(plainBlock(block), "\n")
	for i, l := range lines {
		if l == "Examples:" {
			return lines[:i]
		}
	}
	return lines
}

// oneBlank is s with every run of blanks made one: a usage block pads its
// argument column to line up with its neighbours, a list does not.
func oneBlank(s string) string { return strings.Join(strings.Fields(s), " ") }

// joinContinued is desc, the description that ends line, with the lines of
// next that continue it: the block goes on with a long description on the
// lines below, indented to the column where it starts. A line there that is
// an option of its own (a flag, then its description) is no continuation.
func joinContinued(desc, line string, next []string) string {
	line = strings.TrimRight(plainBlock(line), " ")
	col := len(line) - len(desc)
	if desc == "" || col <= 0 || !strings.HasSuffix(line, desc) {
		return desc
	}
	pad := strings.Repeat(" ", col)
	for _, n := range next {
		n = strings.TrimRight(plainBlock(n), " ")
		if !strings.HasPrefix(n, pad) || len(n) <= col || n[col] == ' ' {
			break
		}
		if left, _, ok := splitRow(n); ok && strings.HasPrefix(strings.TrimSpace(left), "-") {
			break
		}
		desc += " " + strings.TrimSpace(n)
	}
	return desc
}

// rowLeft is a row's argument column as the lists show it: the program
// and the command words before the verb left out ('tacctl config allow
// add <cidr>' under 'config allow' is 'add <cidr>'), one blank between
// the words.
func rowLeft(left string, prefix []string) string {
	w := strings.Fields(left)
	if len(w) > 0 && w[0] == "tacctl" {
		w = w[1:]
		for _, p := range prefix {
			if len(w) == 0 || w[0] != p {
				break
			}
			w = w[1:]
		}
	}
	return strings.Join(w, " ")
}

// verbRows are the rows of block for verb, the command words of prefix
// before it ('config allow' for 'add'), in the block's order: a row whose
// description is on the next line (a long argument column) is one row too,
// and a description goes on over the lines that continue it.
func verbRows(block string, prefix []string, verb string) []usageRow {
	lines := blockBody(block)
	var rows []usageRow
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		left, desc, ok := splitRow(line)
		descLine, after := line, lines[i+1:]
		if !ok {
			left, desc = line, ""
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "   ") {
				desc, descLine, after = strings.TrimSpace(lines[i+1]), lines[i+1], lines[i+2:]
			}
		}
		left = rowLeft(left, prefix)
		if first, _, _ := strings.Cut(left, " "); first != verb {
			continue
		}
		rows = append(rows, usageRow{Left: left, Name: verb, Desc: joinContinued(desc, descLine, after), At: i})
	}
	return rows
}

// ownUsage are the rows of a command's own block: its 'Usage: tacctl
// <path> ...' lines (without a description), else the rows of its list
// that begin with its own word ('tacctl scope prefixes <scope> list').
func ownUsage(block string, path []string) []usageRow {
	prefix, leaf := path[:len(path)-1], path[len(path)-1]
	var rows []usageRow
	for i, line := range blockBody(block) {
		if u, ok := strings.CutPrefix(line, "Usage: "); ok {
			rows = append(rows, usageRow{Left: rowLeft(u, prefix), Name: leaf, At: i, Own: true})
		}
	}
	if len(rows) == 0 {
		rows = verbRows(block, prefix, leaf)
	}
	return rows
}

// shellUsage is the usage rows of the command at path, and the block they
// come from. A top-level command without a block of its own has its row
// of tacctl's usage; any other command the tree alone describes, its usage
// line and its description.
func (inv *invocation) shellUsage(cmd *cobra.Command, path []string) ([]usageRow, string) {
	block, n := inv.helpBlock(cmd, path)
	var rows []usageRow
	switch _, own := shellHelpBlocks[strings.Join(path, " ")]; {
	case n < len(path):
		rows = verbRows(block, path[:n], path[n])
	case own:
		// Its 'Usage:' line says what it is as the command's own
		// description does.
		rows = ownUsage(block, path)
		for i := range rows {
			if rows[i].Desc == "" {
				rows[i].Desc = cmd.Short
			}
		}
		return rows, block
	case len(path) == 1:
		top := Usage("top", UsageVars{"version": inv.build.Version})
		if rows = verbRows(top, nil, path[0]); len(rows) > 0 {
			return rows, top
		}
	}
	if len(rows) == 0 {
		// The lines are the tree's, not the block's: no section of it.
		rows = ownUsage(treeUsage(cmd), path)
		for i := range rows {
			rows[i].Desc, rows[i].At, rows[i].Own = cmd.Short, -1, false
		}
	}
	return rows, block
}

var reFlagValue = regexp.MustCompile(`^(<[^>]*>(?:\[[^\]]*\])?|[A-Za-z0-9]+:<[^>]*>|[a-z0-9]+(?:\|[a-z0-9]+)+)`)

// verbsNamed reports whether desc opens with a list of the verbs it is
// about ('(add, remove) ...', '(enroll and sync) ...'), and whether verb is
// among them.
func verbsNamed(desc, verb string) (listed, named bool) {
	if !strings.HasPrefix(desc, "(") {
		return false, false
	}
	end := strings.Index(desc, ")")
	if end < 0 {
		return false, false
	}
	return true, slices.Contains(strings.Fields(strings.ReplaceAll(desc[1:end], ",", " ")), verb)
}

// flagHelp is what a flag says of itself (Desc, and Arg for the value it
// takes), else what the block says of it: its value's placeholder (for a
// flag that takes one) and its description. An option line ('  -p <port>
// Connect ...') gives both, with the lines that continue it; else a row of
// the verb that adds the flag to the first row ('add <username> <group>
// --hash <hash>  Add with ...'); the placeholder may also come from
// anywhere the block names the flag. A block may describe a flag of the
// same name for several verbs: the option line under the verb's own rows
// (rows) that names the verb in its '(verbs)' opening wins, then one under
// its rows, one elsewhere that names it, one that names no verb, and last
// one about other verbs.
func flagHelp(block string, rows []usageRow, f Flag) (value, desc string) {
	// A flag that carries its own text (Flag.Desc, and Flag.Arg for the value
	// it takes) needs nothing of the block.
	if f.Desc != "" && !f.Value {
		return "", f.Desc
	}
	if f.Desc != "" && f.Arg != "" {
		return f.Arg, f.Desc
	}
	defer func() {
		if f.Desc != "" {
			desc = f.Desc
		}
		if f.Arg != "" && f.Value {
			value = f.Arg
		}
	}()
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
				// '--name[=<value>]': a value that may be left out
				if before && end+1 < len(text) && text[end] == '[' && text[end+1] == '=' {
					if m := reFlagValue.FindString(text[end+2:]); m != "" {
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
	verb, own := "", false
	ats := map[int]bool{}
	for _, r := range rows {
		verb, own = r.Name, own || r.Own
		ats[r.At] = true
	}
	lines := blockBody(block)
	best, bestLeft, bestScore := "", "", -1
	row := -1 // the row line above the line at hand
	for i, line := range lines {
		body := strings.TrimSpace(line)
		if !strings.HasPrefix(line, "  ") || body == "" {
			continue
		}
		if !strings.HasPrefix(body, "-") {
			if !strings.HasPrefix(line, "   ") {
				row = i
			}
			continue
		}
		left, d, ok := splitRow(line)
		// An option line is indented deeper than a row, and may name more
		// than one flag ('--port <n>, --identity <file>'): each is the first
		// word of a comma-separated part.
		left = strings.TrimSpace(left)
		names := false
		for _, part := range strings.Split(left, ", ") {
			if first, _, _ := strings.Cut(part, " "); slices.Contains(f.Names, flagWord(first)) {
				names = true
			}
		}
		if !ok || !names {
			continue
		}
		listed, named := verbsNamed(d, verb)
		// Under a row of another verb's sub-verbs ('config pull ...'), the
		// verbs named are that verb's ('(pull, diff, plan, apply, list)').
		if row >= 0 && named {
			if w := strings.Fields(lines[row]); len(w) > 1 && w[0] != verb {
				if _, sub := verbsNamed(d, w[1]); sub {
					named = false
				}
			}
		}
		inSection := own || (row >= 0 && ats[row])
		score := 0
		switch {
		case named && inSection:
			score = 4
		case inSection:
			score = 3
		case named:
			score = 2
		case !listed:
			score = 1
		}
		if score > bestScore {
			best, bestLeft, bestScore = joinContinued(d, line, lines[i+1:]), left, score
		}
	}
	if bestScore >= 1 {
		desc = best
		if f.Value {
			value = findValue(bestLeft)
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
	if desc == "" && bestScore == 0 {
		desc = best
		if f.Value {
			value = findValue(bestLeft)
		}
	}
	if f.Value && value == "" {
		value = findValue(strings.Join(lines, "\n"))
		if value == "" {
			value = "<value>"
		}
	}
	return value, desc
}

// flagWord is the flag itself of a usage word: '--name[=<value>]' is
// '--name'.
func flagWord(s string) string {
	if i := strings.IndexAny(s, "[="); i > 0 {
		return s[:i]
	}
	return s
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
		// An option group or alternative ('[list | remove <address>]')
		// opens with a word that has no closing bracket: '[<name>]' is an
		// optional positional and stays.
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[-") || w == "|" || w == "[options]" ||
			(strings.HasPrefix(w, "[") && !strings.Contains(w, "]")) {
			break
		}
		out = append(out, w)
	}
	return out
}

// positionalWords are the positional words of rest under spec (a value
// flag's value is not one; '--' ends them).
func positionalWords(spec Spec, rest []string) []string {
	var out []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		switch {
		case w == "--":
			return out
		case strings.HasPrefix(w, "-") && len(w) > 1:
			name, _, hasValue := strings.Cut(w, "=")
			for _, f := range spec.Flags {
				if f.Value && !f.Optional && !hasValue && slices.Contains(f.Names, name) {
					i++
				}
			}
		default:
			out = append(out, w)
		}
	}
	return out
}

// typedWords are the words typed after the verb its usage rows begin
// with: the command words below it ('install' of 'config sudoers install',
// whose rows are the 'sudoers' rows of 'config'), then the positionals.
func (inv *invocation) typedWords(cmd *cobra.Command, path []string, spec Spec, rest []string) []string {
	var out []string
	if _, n := inv.helpBlock(cmd, path); n+1 < len(path) {
		out = slices.Clone(path[n+1:])
	}
	return append(out, positionalWords(spec, rest)...)
}

// positionals counts the positional words of rest under spec.
func positionals(spec Spec, rest []string) int { return len(positionalWords(spec, rest)) }

// fixedWords are the words a placeholder of a usage row stands for when it
// is a fixed word or a choice of them ('list', 'list|add', 'cisco|juniper');
// nil for a value typed by hand ('<name>', 'auto|<tier>') or an optional
// one ('[<n>]', '[show|tcp]'), which any word fits.
func fixedWords(p string) []string {
	if strings.ContainsAny(p, "<[") {
		return nil
	}
	return strings.Split(strings.Trim(p, "{}"), "|")
}

// fitRows are the rows whose placeholders the positional words typed so
// far fit (rows itself when none does): the forms of the verb still open.
func fitRows(rows []usageRow, words []string) []usageRow {
	var out []usageRow
	for _, r := range rows {
		ph := placeholders(r, 1)
		fits := true
		for i, w := range words {
			if i < len(ph) {
				if fw := fixedWords(ph[i]); fw != nil && !slices.Contains(fw, w) {
					fits = false
				}
			}
		}
		if fits {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return rows
	}
	return out
}

// nextWords is what the rows say comes after the first pos positionals:
// the placeholders they share, then the choice of words where they part
// ('<scope> list|add|remove|move ...').
func nextWords(rows []usageRow, pos int) []string {
	var rests [][]string
	for _, r := range rows {
		ph := placeholders(r, 1)
		rests = append(rests, ph[min(pos, len(ph)):])
	}
	var out []string
	for i := 0; ; i++ {
		var at []string
		more := false
		for _, r := range rests {
			if i < len(r) {
				if !slices.Contains(at, r[i]) {
					at = append(at, r[i])
				}
				more = more || i+1 < len(r)
			}
		}
		switch len(at) {
		case 0:
			return out
		case 1:
			out = append(out, at[0])
			continue
		}
		// The words of the choices, once each ('list|add|remove' and
		// 'remove' are 'list|add|remove').
		// An optional choice ('[show|install|remove]' beside 'tiers') makes
		// the whole choice optional.
		var choice []string
		optional := false
		for _, a := range at {
			if inner, ok := strings.CutPrefix(a, "["); ok && strings.HasSuffix(inner, "]") && fixedWords(inner[:len(inner)-1]) != nil {
				a, optional = inner[:len(inner)-1], true
			}
			ws := fixedWords(a)
			if ws == nil {
				ws = []string{a}
			}
			for _, w := range ws {
				if !slices.Contains(choice, w) {
					choice = append(choice, w)
				}
			}
		}
		if optional {
			out = append(out, "["+strings.Join(choice, "|")+"]")
		} else {
			out = append(out, strings.Join(choice, "|"))
		}
		if more {
			out = append(out, "...")
		}
		return out
	}
}

// alignRows is rows as '  <left>  <desc>' lines, the descriptions aligned.
func alignRows(rows [][2]string) string { return alignRowsWith(rows, nil) }

// alignRowsWith is alignRows with the left column in colour: paintLeft
// gives the left column as it is shown (nil: as it is). The columns are
// counted on the plain text.
func alignRowsWith(rows [][2]string, paintLeft func(string) string) string {
	width := 0
	for _, r := range rows {
		if r[1] != "" {
			width = max(width, len(r[0]))
		}
	}
	var b strings.Builder
	for _, r := range rows {
		left := r[0]
		if paintLeft != nil {
			left = paintLeft(left)
		}
		if r[1] == "" {
			b.WriteString("  " + left + "\n")
			continue
		}
		b.WriteString("  " + left + strings.Repeat(" ", max(width-len(r[0]), 0)) + "  " + r[1] + "\n")
	}
	return b.String()
}

// paintUsage is a usage row's left column in the palette of the lists: the
// verb (the command's name at the top level) and the options and fixed
// words after it, all teal; placeholders as they are.
func paintUsage(left string) string {
	toks := strings.Split(left, " ")
	for i, t := range toks {
		switch {
		case i == 0, isOptionWord(t), isFixedToken(t):
			toks[i] = ui.Paint(ui.Teal, t)
		}
	}
	return strings.Join(toks, " ")
}

// paintOptions is the left column of an option row: its spellings and
// teal, the value it takes as it is ('-y, --yes', '--hash <hash>').
func paintOptions(left string) string {
	toks := strings.Split(left, " ")
	for i, t := range toks {
		if isOptionWord(strings.TrimSuffix(t, ",")) {
			toks[i] = ui.Paint(ui.Teal, strings.TrimSuffix(t, ",")) + t[len(strings.TrimSuffix(t, ",")):]
		}
	}
	return strings.Join(toks, " ")
}

// isOptionWord reports whether a word of a usage row is a flag
// ('--hash', '-y', '[--long]').
func isOptionWord(t string) bool {
	return strings.HasPrefix(t, "-") || strings.HasPrefix(t, "[-")
}

// isFixedToken reports whether a word of a usage row is a fixed word or a
// choice of them ('list', 'list|add|remove'), not a placeholder, a bar or the
// dots.
func isFixedToken(t string) bool {
	return t != "" && t != "|" && t != "..." && fixedWords(t) != nil
}

// paintNext is a word of the 'Next:' line: a fixed word or a choice of them
// is teal ('list|add|remove'), a placeholder as it is.
func paintNext(w string) string {
	if isFixedToken(w) {
		return ui.Paint(ui.Teal, w)
	}
	return w
}

// shellExplain is the shell's Explainer: for words that name a command
// that takes no further sub-command, its usage rows, its flags not on the
// line yet, and what comes next.
func (inv *invocation) shellExplain(root *cobra.Command) func([]string) (string, bool) {
	return func(words []string) (string, bool) {
		cmd, path, rest := shellCommand(root, words)
		if cmd == root || cmd.Hidden {
			return "", false
		}
		if len(rest) == 0 && slices.ContainsFunc(cmd.Commands(), func(c *cobra.Command) bool { return !c.Hidden }) {
			// A family the view hides lists nothing to complete: say why,
			// and where its verbs are described (D56).
			if eff, all, active := inv.currentView(); active && !viewShows(root, eff, all, path) {
				return "Needs the " + string(familyTier(root, path)) + " tier. help " + strings.Join(path, " ") + " describes it.\n", true
			}
			return "", false
		}
		rows, block := inv.shellUsage(cmd, path)
		spec, hasSpec := specFor(path)
		typedWords := inv.typedWords(cmd, path, spec, rest)
		pos := len(typedWords)
		forms := fitRows(rows, typedWords)
		shown := forms
		// A command whose block lists its own forms ('scope snmp <scope>
		// <subcommand>', then 'show [--reveal]' and so on): the rows of the
		// words typed so far as well.
		if len(rows) > 0 && rows[0].Own {
			shown = slices.Clone(forms)
			for _, w := range typedWords {
				shown = append(shown, verbRows(block, path, w)...)
			}
		}
		var b strings.Builder
		var lines [][2]string
		for _, r := range shown {
			lines = append(lines, [2]string{r.Left, r.Desc})
		}
		if len(lines) > 0 {
			b.WriteString("Usage:\n" + alignRowsWith(lines, paintUsage))
		}
		var flags [][2]string
		for _, f := range spec.Flags {
			typed := slices.ContainsFunc(rest, func(w string) bool {
				name, _, _ := strings.Cut(w, "=")
				return slices.Contains(f.Names, name)
			})
			if typed || !f.offeredAfter(rest) {
				continue
			}
			value, desc := flagHelp(block, rows, f)
			flags = append(flags, [2]string{flagLabel(f, value), desc})
		}
		if len(flags) > 0 {
			b.WriteString("Options:\n" + alignRowsWith(flags, paintOptions))
		}
		next := "<Enter> to run"
		args := positionals(spec, rest)
		remaining := nextWords(forms, pos)
		for i := range remaining {
			remaining[i] = paintNext(remaining[i])
		}
		switch {
		case len(remaining) == 0 || (hasSpec && spec.MaxArgs >= 0 && args >= spec.MaxArgs):
		case hasSpec && args < spec.MinArgs:
			next = strings.Join(remaining, " ")
		default:
			next = strings.Join(remaining, " ") + ", or " + next
		}
		// A verb the caller's tier cannot run is not listed (D56); typed by
		// hand its usage is still shown, with the tier it needs.
		if eff, all, active := inv.currentView(); active && !viewShows(root, eff, all, path) {
			b.WriteString("Needs the " + string(pathTier(path)) + " tier.\n")
		}
		b.WriteString("Next: " + next + "\n")
		return b.String(), true
	}
}

// flagDescs gives the flag candidates of a verb their descriptions from
// the verb's usage block.
func (inv *invocation) flagDescs(cmd *cobra.Command, path []string, spec Spec, cands []string) map[string]string {
	out := map[string]string{}
	for n, h := range inv.flagHelps(cmd, path, spec, cands) {
		out[n] = h[1]
	}
	return out
}

// flagHelps is flagDescs with the value each flag takes ("" for a switch):
// {value, description} by flag name.
func (inv *invocation) flagHelps(cmd *cobra.Command, path []string, spec Spec, cands []string) map[string][2]string {
	if !slices.ContainsFunc(cands, func(c string) bool { return strings.HasPrefix(c, "-") }) {
		return nil
	}
	rows, block := inv.shellUsage(cmd, path)
	out := map[string][2]string{}
	for _, f := range spec.Flags {
		value, desc := flagHelp(block, rows, f)
		for _, n := range f.Names {
			out[n] = [2]string{value, desc}
		}
	}
	return out
}

// listKindName is what the word completed after rest is, plural, for the
// question before a long list: the kind of the value a flag waits for, or
// of the next positional (as completeSpec finds them); "choices" for a
// fixed word list or free text.
func listKindName(spec Spec, rest []string) string {
	kind := strings.TrimSuffix(specKind(spec, rest), KindList)
	switch kind {
	case KindUsers, KindGroups, KindScopes, KindHosts, KindDevices, KindBackups, KindBackends, KindListeners:
		return kind
	case KindEnabledBackends:
		return KindBackends
	case KindCiscoDevices, KindJuniperDevices:
		return KindDevices
	case KindFile:
		return "files"
	}
	return "choices"
}

// hintKinds are word lists that only hint at what is typed (a prefix of a
// longer word, or a start the operator goes on from): not fixed.
var hintKinds = map[string]bool{configPaths: true, privModeWords: true}

// fixedKind reports whether the words of a kind are fixed ones: a list
// 'a|b|c', as against free text, a single word that is only the usual
// value of a free-text position ('clear'), a hint list (hintKinds), a comma
// list, a file and the live names of a store (users, hosts ...). Only
// fixed words complete on a typed space.
func fixedKind(kind string) bool {
	return strings.Contains(kind, "|") && !hintKinds[kind] && !strings.HasSuffix(kind, KindList)
}

// specKind is the kind of the word completed after rest: of the value a
// flag waits for, else of the next positional (as completeSpec finds
// them); "" for free text, and after '--'.
func specKind(spec Spec, rest []string) string {
	kind, pos := "", 0
	var words []string
	pending := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			return ""
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
		case flag.Optional && !hasVal:
		case flag.Value && !hasVal && i+1 < len(rest):
			i++
		case flag.Value && !hasVal:
			kind, pending = flag.Kind, true
		}
	}
	if !pending && pos < len(spec.Args) {
		kind = resolveKind(spec.Args[pos], words)
	}
	return kind
}

// waitsForValue reports whether the last word of rest is a flag of spec
// that waits for its value.
func waitsForValue(spec Spec, rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	name, _, hasVal := strings.Cut(rest[len(rest)-1], "=")
	if hasVal {
		return false
	}
	return slices.ContainsFunc(spec.Flags, func(f Flag) bool {
		return f.Value && !f.Optional && slices.Contains(f.Names, name)
	})
}

// choiceWordDescs are the descriptions of the words of a choice, by command
// path and the kind of the position ('cisco|juniper'): '?' lists them beside
// the words, which the verb's rows do not (they describe the verb).
var choiceWordDescs = map[string]map[string]map[string]string{
	"scope block": {"cisco|juniper": rowsMap(scopeBlockVendors)},
}

// rowsMap is a list of {word, description} as a map.
func rowsMap(rows [][2]string) map[string]string {
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r[0]] = r[1]
	}
	return m
}

// wordDescs describes the fixed words that can come as the next
// positional after rest: by the usage row of the verb that has the word
// alone in that place ('group edit <name> priv-lvl <0-15>' describes
// priv-lvl), else by the row of the command's own block that begins with
// it ('scope snmp <scope> show': 'show [--reveal]'). A word of a choice
// ('list|add|remove') is not described: its row is about the verb.
func (inv *invocation) wordDescs(cmd *cobra.Command, path []string, spec Spec, rest []string) map[string]string {
	if waitsForValue(spec, rest) {
		return nil
	}
	rows, block := inv.shellUsage(cmd, path)
	typed := inv.typedWords(cmd, path, spec, rest)
	out := map[string]string{}
	inChoice := map[string]bool{}
	for _, r := range fitRows(rows, typed) {
		ph := placeholders(r, 1)
		if len(typed) >= len(ph) {
			continue
		}
		switch fw := fixedWords(ph[len(typed)]); {
		case len(fw) > 1:
			for _, w := range fw {
				inChoice[w] = true
			}
		case len(fw) == 1 && r.Desc != "":
			if _, ok := out[fw[0]]; !ok {
				out[fw[0]] = r.Desc
			}
		}
	}
	// A word that is also one of a choice ('scope <user> list|add|remove'
	// beside 'scope <user> remove --all') has more forms than the one row.
	for w := range inChoice {
		delete(out, w)
	}
	// The words of a choice that a command describes itself, because its
	// rows are about the verb ('scope block <scope> cisco|juniper').
	for w, d := range choiceWordDescs[strings.Join(path, " ")][specKind(spec, rest)] {
		out[w] = d
	}
	if kind := specKind(spec, rest); len(rows) > 0 && rows[0].Own && fixedKind(kind) {
		for _, w := range inv.kindWords(kind, nil) {
			if _, ok := out[w]; !ok && !inChoice[w] {
				if rs := verbRows(block, path, w); len(rs) > 0 && rs[0].Desc != "" {
					out[w] = rs[0].Desc
				}
			}
		}
	}
	return out
}
