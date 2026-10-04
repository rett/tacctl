package shell

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Candidate is one completion: the word, a description shown in the list
// (may be empty), and NoSpace when no blank is to follow it (a comma list).
type Candidate struct {
	Word, Desc string
	NoSpace    bool
}

// Completer answers what can come after words (the complete words before
// the cursor) for the word being typed, partial. The shell filters the
// answer by partial again.
type Completer func(words []string, partial string) []Candidate

// builtins are the shell's own words, offered at the start of a line.
var builtins = []Candidate{
	{Word: "help", Desc: "Show the usage of tacctl or of a command (help <command>)"},
	{Word: "history", Desc: "List the lines entered (redacted as stored)"},
	{Word: "exit", Desc: "Leave the shell"},
	{Word: "quit", Desc: "Leave the shell"},
}

// editor is the state of the line editor's key callback (term.Terminal's
// AutoCompleteCallback, which gets every key the Terminal does not handle
// itself): Tab completion, the Ctrl-R search and the interrupt marker.
type editor struct {
	t        *term.Terminal
	prompt   string
	hist     *History
	complete Completer

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

// tab completes the word before the cursor: one candidate is inserted
// (with a blank after it), several insert their common prefix; when there
// is nothing more to insert, the next Tab lists them, one per line with
// its description.
func (e *editor) tab(line string, pos int) (string, int, bool) {
	words, st := scan(line[:pos])
	partial, start := "", pos
	if st.inWord {
		if st.quote == 0 && !st.escape {
			words = words[:len(words)-1]
		}
		partial, start = st.partial, st.wordStart
	}
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
		_, _ = e.t.Write([]byte(listing(cands)))
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

// listing is the candidates one per line, descriptions aligned.
func listing(cands []Candidate) string {
	width := 0
	for _, c := range cands {
		width = max(width, utf8.RuneCountInString(c.Word))
	}
	var b strings.Builder
	for _, c := range cands {
		if c.Desc == "" {
			b.WriteString("  " + c.Word + "\n")
			continue
		}
		pad := width - utf8.RuneCountInString(c.Word)
		b.WriteString("  " + c.Word + strings.Repeat(" ", pad) + "  " + c.Desc + "\n")
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
