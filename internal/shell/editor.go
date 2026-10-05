package shell

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/term"
)

// Candidate is one completion: the word, a description shown in the list
// (may be empty), and NoSpace when no blank is to follow it (a comma list).
// Label is what the '?' list shows in the word's place (the usage's
// argument column: 'version [--long]'); empty for the word. Unlisted keeps
// a word out of the lists when another candidate shows the same row ('quit'
// under 'exit | quit'); unlisted words are listed only when no other
// candidate is. Lists are alphabetical.
type Candidate struct {
	Word, Desc string
	Label      string
	NoSpace    bool
	Unlisted   bool
	// Kind is what the word is, plural ('devices', 'commands'), for the
	// question before a long list; empty: 'choices'.
	Kind string
}

// The descriptions of the shell's own words, also used by the 'help' text.
const (
	DescHelp    = "Show the usage of tacctl, or of a command"
	DescHistory = "List the lines entered (secrets redacted)"
	DescExit    = "Leave the shell"
)

// Completer answers what can come after words (the complete words before
// the cursor) for the word being typed, partial. The shell filters the
// answer by partial again.
type Completer func(words []string, partial string) []Candidate

// Explainer is what '?' prints where no word can be offered: the usage of
// the command words name so far and what comes next; false when words name
// no command.
type Explainer func(words []string) (string, bool)

// Row is a row of the shell's own words in the help and in the list: the
// left column, the description and the words it stands for.
type Row struct {
	Left, Desc string
	Words      []string
}

// BuiltinRows are the shell's own words.
var BuiltinRows = []Row{
	{"help [<command>]", DescHelp, []string{"help"}},
	{"history", DescHistory, []string{"history"}},
	{"exit | quit", DescExit, []string{"exit", "quit"}},
}

// builtins are the shell's own words, offered at the start of a line.
var builtins = func() []Candidate {
	var out []Candidate
	for _, r := range BuiltinRows {
		for _, w := range r.Words {
			c := Candidate{Word: w, Desc: r.Desc, Unlisted: true}
			if r.Left != w {
				c.Label = r.Left
			}
			out = append(out, c)
		}
	}
	return out
}()

// editor is the state of the line editor's key callback (term.Terminal's
// AutoCompleteCallback, which gets every key the Terminal does not handle
// itself): Tab completion, the Ctrl-R search and the interrupt marker.
type editor struct {
	t        *term.Terminal
	prompt   string
	hist     *History
	complete Completer
	explain  Explainer
	// width and height are the terminal's size (setSize; 0: unknown).
	width, height atomic.Int32
	// out writes to the terminal past the Terminal, and readKey reads one
	// key from it, for the question before a long list and the pager (nil
	// in tests of the editor alone: lists are shown whole).
	out     io.Writer
	readKey func() (byte, error)
	// listMax is the longest list shown without asking (ListMax).
	listMax int

	// lastTab: the previous key was a Tab that completed nothing more (a
	// second Tab lists). input clears it on any other key.
	lastTab bool
	// searching is set by input when it passes Ctrl-R on, and cleared when
	// it ends the search; search is the callback's side of it.
	searching bool
	search    searchState
	// interrupted: the line being returned was ended by Ctrl-C.
	interrupted bool
	// shown is the prompt last set by the search.
	shown string
}

type searchState struct {
	on               bool
	query            []rune
	idx              int // the history index of the match, -1 for none
	failed           bool
	orig, match      string
	origPos, matchAt int
}

// key is the AutoCompleteCallback.
func (e *editor) key(line string, pos int, key rune) (string, int, bool) {
	switch {
	case key == markInterrupt:
		e.endSearch()
		e.interrupted = true
		return line + "^C", len(line) + 2, true
	case key == 0x12 || key == markBackspace || key == markAccept || key == markCancel:
		return e.searchKey(line, pos, key)
	case e.search.on && key >= 0x20 && (key < 0xd800 || key > 0xdfff) && key != utf8.RuneError:
		return e.searchKey(line, pos, key)
	case key == '\t':
		return e.tab(line, pos)
	case key == '?':
		return e.question(line, pos)
	}
	return "", 0, false
}

// --- Ctrl-R ------------------------------------------------------------------

// searchKey is a key of the reverse incremental search: Ctrl-R starts it or
// looks further back, a character extends the query, Backspace shortens
// it, markAccept keeps the match (the key that ended the search then acts
// on it, Enter runs it), markCancel goes back to the line as it was.
func (e *editor) searchKey(line string, pos int, key rune) (string, int, bool) {
	s := &e.search
	switch key {
	case 0x12:
		if !s.on {
			*s = searchState{on: true, idx: -1, orig: line, origPos: pos, match: line, matchAt: pos}
		} else if len(s.query) > 0 {
			e.find(s.idx + 1)
		}
	case markAccept:
		if !s.on {
			return line, pos, true
		}
		e.endSearch()
		return line, pos, true
	case markCancel:
		if !s.on {
			return line, pos, true
		}
		e.endSearch()
		return s.orig, s.origPos, true
	case markBackspace:
		if !s.on {
			return line, pos, true
		}
		if len(s.query) > 0 {
			s.query = s.query[:len(s.query)-1]
		}
		s.idx, s.failed, s.match, s.matchAt = -1, false, s.orig, s.origPos
		if len(s.query) > 0 {
			e.find(0)
		}
	default:
		s.query = append(s.query, key)
		e.find(max(s.idx, 0))
	}
	label := "reverse-i-search"
	if s.failed {
		label = "failed reverse-i-search"
	}
	e.setPrompt(fmt.Sprintf("(%s)`%s': ", label, string(s.query)))
	return s.match, s.matchAt, true
}

// find looks for the query in the history from index from (0 is the
// newest) back; when nothing matches the previous match stays and the
// search is marked failed.
func (e *editor) find(from int) {
	s := &e.search
	q := string(s.query)
	for i := from; e.hist != nil && i < e.hist.Len(); i++ {
		h := e.hist.At(i)
		if j := strings.Index(h, q); j >= 0 {
			s.idx, s.failed, s.match, s.matchAt = i, false, h, j
			return
		}
	}
	s.failed = true
}

// endSearch puts the normal prompt back.
func (e *editor) endSearch() {
	if e.search.on {
		e.search.on = false
		e.setPrompt(e.prompt)
	}
}

// setPrompt changes the prompt and repaints it (the callback runs with the
// Terminal unlocked; Write repaints prompt and line, the callback's answer
// then repaints the line).
func (e *editor) setPrompt(p string) {
	e.shown = p
	e.t.SetPrompt(p)
	_, _ = e.t.Write(nil)
}

// --- Tab ----------------------------------------------------------------------

// word is the completion context of the cursor: the words before the one
// being typed, that word so far and where it starts, and the tokenizer's
// state there.
func word(line string, pos int) (words []string, partial string, start int, st scanState) {
	words, st = scan(line[:pos])
	partial, start = "", pos
	if st.inWord {
		if st.quote == 0 && !st.escape {
			words = words[:len(words)-1]
		}
		partial, start = st.partial, st.wordStart
	}
	return words, partial, start, st
}

// question is the '?' key (as on Junos): it inserts nothing and prints
// help for the cursor's position below the line. Where words can come, it
// lists them with their argument column and description ('Possible
// completions:'); where none can (free text, or nothing more), the usage
// of the command typed so far and what comes next (Explainer). Inside an
// open quote, or right after a backslash, it is an ordinary character: the
// Terminal inserts it.
func (e *editor) question(line string, pos int) (string, int, bool) {
	words, partial, _, st := word(line, pos)
	if st.quote != 0 || st.escape {
		return "", 0, false
	}
	e.lastTab = false
	if cands := e.candidates(words, partial); len(cands) > 0 {
		e.present(line, pos, partial, cands, "Possible completions:\n"+listing(cands), true)
		return line, pos, true
	}
	text := "No valid completions\n"
	if e.explain != nil {
		if t, ok := e.explain(words); ok {
			text = t
		}
	}
	e.present(line, pos, partial, nil, text, true)
	return line, pos, true
}

// show prints text below the typed line. Terminal.Write clears the prompt
// and the line before it prints and redraws them after; the line is
// printed again at the start of what is written, so it stays above the
// text (as in bash), and the redraw puts the cursor back where it was,
// wrapped or not.
func (e *editor) show(line, text string) {
	p := e.shown
	if p == "" {
		p = e.prompt
	}
	_, _ = e.t.Write([]byte(p + line + "\n" + text))
}

// tab completes the word before the cursor: one candidate is inserted
// (with a blank after it), several insert their common prefix; when there
// is nothing more to insert, the next Tab lists the words, in columns as
// bash does.
func (e *editor) tab(line string, pos int) (string, int, bool) {
	words, partial, start, _ := word(line, pos)
	cands := e.candidates(words, partial)
	switch {
	case len(cands) == 0:
		e.lastTab = false
		return line, pos, true
	case len(cands) == 1:
		e.lastTab = false
		ins := Quote(cands[0].Word)
		if !cands[0].NoSpace {
			ins += " "
		}
		return line[:start] + ins + line[pos:], start + len(ins), true
	}
	words2 := make([]string, len(cands))
	for i, c := range cands {
		words2[i] = c.Word
	}
	if cp := commonPrefix(words2); len(cp) > len(partial) {
		e.lastTab = true
		ins := cp
		if Quote(cp) != cp {
			ins = Quote(cp)
		}
		return line[:start] + ins + line[pos:], start + len(ins), true
	}
	if e.lastTab {
		e.present(line, pos, partial, cands, columns(cands, e.size().w), false)
	}
	e.lastTab = true
	return line, pos, true
}

// candidates are the completions of partial after words, sorted, once each.
func (e *editor) candidates(words []string, partial string) []Candidate {
	var all []Candidate
	switch {
	case len(words) == 0:
		all = append(all, builtins...)
		if e.complete != nil {
			all = append(all, e.complete(nil, partial)...)
		}
	case words[0] == "help":
		if e.complete != nil {
			for _, c := range e.complete(words[1:], partial) {
				if !strings.HasPrefix(c.Word, "-") {
					all = append(all, c)
				}
			}
		}
	case words[0] == "history" || words[0] == "exit" || words[0] == "quit":
	default:
		if e.complete != nil {
			all = e.complete(words, partial)
		}
	}
	var out []Candidate
	seen := map[string]bool{}
	for _, c := range all {
		if strings.HasPrefix(c.Word, partial) && c.Word != "" && !seen[c.Word] {
			seen[c.Word] = true
			out = append(out, c)
		}
	}
	slices.SortStableFunc(out, func(a, b Candidate) int { return strings.Compare(a.Word, b.Word) })
	return out
}

// listed are the candidates a list shows: the unlisted ones only when
// nothing else is.
func listed(cands []Candidate) []Candidate {
	if !slices.ContainsFunc(cands, func(c Candidate) bool { return !c.Unlisted }) {
		return cands
	}
	return slices.DeleteFunc(slices.Clone(cands), func(c Candidate) bool { return c.Unlisted })
}

// columns is the Tab list: the words alone, in columns down then across,
// as many as fit width (bash's listing); one column when none fit.
func columns(cands []Candidate, width int) string {
	cands = listed(cands)
	if len(cands) == 0 {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	colw := 0
	for _, c := range cands {
		colw = max(colw, utf8.RuneCountInString(c.Word)+2)
	}
	ncols := max(1, width/colw)
	nrows := (len(cands) + ncols - 1) / ncols
	var b strings.Builder
	for r := range nrows {
		var row strings.Builder
		for c := range ncols {
			i := c*nrows + r
			if i >= len(cands) {
				break
			}
			w := cands[i].Word
			row.WriteString(w + strings.Repeat(" ", colw-utf8.RuneCountInString(w)))
		}
		b.WriteString(strings.TrimRight(row.String(), " ") + "\n")
	}
	return b.String()
}

// listing is the '?' list: the candidates one per line, the label (or the
// word) and the description aligned.
func listing(cands []Candidate) string {
	label := func(c Candidate) string {
		if c.Label != "" {
			return c.Label
		}
		return c.Word
	}
	width := 0
	for _, c := range listed(cands) {
		width = max(width, utf8.RuneCountInString(label(c)))
	}
	var b strings.Builder
	for _, c := range listed(cands) {
		l := label(c)
		if c.Desc == "" {
			b.WriteString("  " + l + "\n")
			continue
		}
		pad := width - utf8.RuneCountInString(l)
		b.WriteString("  " + l + strings.Repeat(" ", pad) + "  " + c.Desc + "\n")
	}
	return b.String()
}

// commonPrefix is the longest prefix of every word (whole runes).
func commonPrefix(words []string) string {
	if len(words) == 0 {
		return ""
	}
	p := words[0]
	for _, w := range words[1:] {
		for !strings.HasPrefix(w, p) {
			_, size := utf8.DecodeLastRuneInString(p)
			p = p[:len(p)-size]
		}
	}
	return p
}

// --- long lists ------------------------------------------------------------------

// DefaultListMax is the longest list Tab or '?' shows without asking first.
const DefaultListMax = 40

// morePrompt is the pager's last row.
const morePrompt = "-- more (Space: page, Enter: line, q: quit) --"

type size struct{ w, h int }

// size is the terminal's size, 80x24 when it is not known.
func (e *editor) size() size {
	w, h := int(e.width.Load()), int(e.height.Load())
	if w <= 0 || h <= 0 {
		return size{80, 24}
	}
	return size{w, h}
}

// listKind is what a list holds, for the question: the candidates' Kind
// when they share one, else "choices".
func listKind(cands []Candidate) string {
	kind := ""
	for i, c := range cands {
		if i > 0 && c.Kind != kind {
			return "choices"
		}
		kind = c.Kind
	}
	if kind == "" {
		return "choices"
	}
	return kind
}

// narrowExample is the start of a word that narrows the list: the
// candidates' common prefix when it is longer than what is typed, else the
// first one's next letter.
func narrowExample(partial string, cands []Candidate) string {
	words := make([]string, len(cands))
	for i, c := range cands {
		words[i] = c.Word
	}
	if cp := commonPrefix(words); len(cp) > len(partial) {
		return cp
	}
	first := words[0]
	if !strings.HasPrefix(first, partial) || len(first) == len(partial) {
		return first
	}
	_, n := utf8.DecodeRuneInString(first[len(partial):])
	return first[:len(partial)+n]
}

// present shows text below the typed line. A list of more than listMax
// entries asks first ('Show all <n> <kind>? [y/N]'; anything but y shows
// a hint instead); with page, text taller than the terminal is shown a
// screenful at a time. Without a key reader it is show.
func (e *editor) present(line string, pos int, partial string, cands []Candidate, text string, page bool) {
	n := len(listed(cands))
	ask := e.listMax >= 0 && n > e.listMax
	sz := e.size()
	rows := wrapRows(text, sz.w)
	tall := page && len(rows) > sz.h-1
	if e.readKey == nil || e.out == nil || (!ask && !tall) {
		e.show(line, text)
		return
	}
	p := e.shown
	if p == "" {
		p = e.prompt
	}
	// The Terminal prints the line and redraws prompt and line below it;
	// the redrawn rows are cleared, and the question, the list or the
	// pages go there. At the end prompt and line are drawn again up to the
	// cursor, where the Terminal has it (it then redraws the line itself).
	_, _ = e.t.Write([]byte(p + line + "\n"))
	var b strings.Builder
	b.WriteString("\r")
	if up := cursorRow(p+line[:pos], sz.w); up > 0 {
		b.WriteString("\x1b[" + strconv.Itoa(up) + "A")
	}
	b.WriteString("\x1b[J")
	e.write(b.String())
	if ask {
		e.write("Show all " + strconv.Itoa(n) + " " + listKind(cands) + "? [y/N] ")
		if k, err := e.readKey(); err == nil && (k == 'y' || k == 'Y') {
			e.write("y\r\n")
		} else {
			e.write("\r\ntype more letters to narrow it (e.g. " + narrowExample(partial, cands) + "…<Tab>)\r\n")
			rows, tall = nil, false
		}
	}
	if tall {
		e.pager(rows, sz.h)
	} else {
		for _, r := range rows {
			e.write(r + "\r\n")
		}
	}
	draw := p + line[:pos]
	if c := utf8.RuneCountInString(draw); c > 0 && c%sz.w == 0 {
		draw += "\r\n"
	}
	e.write(draw)
}

// pager writes rows a screenful (h-1 rows) at a time with the more prompt
// on the last row: Space shows the next screenful, Enter the next row, q,
// Ctrl-C (or a failed read) stops.
func (e *editor) pager(rows []string, h int) {
	next := max(h-1, 1)
	for len(rows) > 0 {
		k := min(next, len(rows))
		for _, r := range rows[:k] {
			e.write(r + "\r\n")
		}
		rows = rows[k:]
		if len(rows) == 0 {
			return
		}
		e.write(morePrompt)
		for {
			key, err := e.readKey()
			switch {
			case err != nil || key == 'q' || key == 'Q' || key == 0x03:
				e.write("\r\x1b[K")
				return
			case key == ' ':
				next = max(h-1, 1)
			case key == '\r' || key == '\n':
				next = 1
			default:
				continue
			}
			break
		}
		e.write("\r\x1b[K")
	}
}

func (e *editor) write(s string) { _, _ = io.WriteString(e.out, s) }

// wrapRows are the terminal rows text takes at width w: each line cut
// every w runes (an empty line is one row); the last newline ends the
// last line.
func wrapRows(text string, w int) []string {
	var rows []string
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		r := []rune(l)
		if len(r) == 0 {
			rows = append(rows, "")
			continue
		}
		for len(r) > 0 {
			k := min(w, len(r))
			rows = append(rows, string(r[:k]))
			r = r[k:]
		}
	}
	return rows
}

// cursorRow is the row (from 0) the cursor is on after s is written from
// the start of a row at width w, as the Terminal counts it (a row filled
// to the last column moves the cursor to the next).
func cursorRow(s string, w int) int { return utf8.RuneCountInString(s) / w }
