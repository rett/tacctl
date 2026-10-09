package shell

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/term"
)

// screen is a terminal for the editor's output.
type screen struct{ bytes.Buffer }

func (s *screen) Read([]byte) (int, error) { return 0, nil }

// testCompleter answers like the cli's completer for a small tree.
func testCompleter(words []string, partial string) []Candidate {
	switch strings.Join(words, " ") {
	case "":
		return []Candidate{
			{Word: "user", Desc: "User management", Fixed: true}, {Word: "group", Desc: "Group management", Fixed: true},
			{Word: "scope", Desc: "Scope management", Fixed: true}, {Word: "store", Desc: "The canonical store", Fixed: true},
			{Word: "device", Desc: "Device management", Fixed: true},
		}
	case "user":
		return []Candidate{{Word: "list", Desc: "List all users", Fixed: true}, {Word: "show", Desc: "Show a user", Fixed: true}}
	case "user show":
		return []Candidate{{Word: "alice"}, {Word: "albert"}, {Word: "bob"}, {Word: "o'neil"}}
	case "user add bob":
		return []Candidate{{Word: "lab,", NoSpace: true}}
	case "many":
		var out []Candidate
		for i := 1; i <= 45; i++ {
			out = append(out, Candidate{Word: fmt.Sprintf("n%02d", i), Desc: "device", Kind: "devices"})
		}
		return out
	}
	return nil
}

// spaceCompleter is what the space tests complete from: fixed words
// (commands, a choice, a flag), a word that is the start of another, live
// names, a comma list, and a list longer than ListMax.
func spaceCompleter(words []string, partial string) []Candidate {
	fixed := func(ws ...string) []Candidate {
		var out []Candidate
		for _, w := range ws {
			out = append(out, Candidate{Word: w, Desc: "the " + w, Fixed: true})
		}
		return out
	}
	switch strings.Join(words, " ") {
	case "":
		return fixed("user", "user-x", "group", "scope", "store", "fx")
	case "user":
		return fixed("list", "show", "mode", "add")
	case "user mode":
		return fixed("on", "off")
	case "é":
		return fixed("list", "show")
	case "user add":
		return append(fixed("--force"), Candidate{Word: "alice"}, Candidate{Word: "albert"})
	case "user show":
		return []Candidate{{Word: "alice"}, {Word: "albert"}, {Word: "o'neil"}}
	case "user add bob":
		return []Candidate{{Word: "lab,", NoSpace: true}}
	case "fx":
		var out []Candidate
		for i := 1; i <= 45; i++ {
			out = append(out, Candidate{Word: fmt.Sprintf("f%02d", i), Fixed: true})
		}
		return out
	}
	return nil
}

// newSpaceEditor is an editor with space completion on, spaceCompleter and
// a key reader that fails the test: a space never asks or pages.
func newSpaceEditor(t *testing.T) (*editor, *screen) {
	e, sc := newTestEditor()
	e.spaces, e.listMax, e.complete = true, DefaultListMax, spaceCompleter
	e.out = sc
	e.readKey = func() (byte, error) {
		t.Error("a typed space read a key")
		return 0, io.EOF
	}
	return e, sc
}

func newTestEditor() (*editor, *screen) {
	sc := &screen{}
	e := &editor{prompt: DefaultPrompt, complete: testCompleter, hist: NewHistory("", nil)}
	e.t = term.NewTerminal(sc, DefaultPrompt)
	return e, sc
}

func TestTabCompletion(t *testing.T) {
	cases := []struct {
		line    string
		want    string
		wantPos int // -1: end of want
	}{
		{"us", "user ", -1},
		{"user l", "user list ", -1},
		{"user show b", "user show bob ", -1},
		{"user show al", "user show al", -1}, // common prefix is the word: nothing to add
		{"user show a", "user show al", -1},
		{"user show o", `user show 'o'\''neil' `, -1},
		{"user show 'o", `user show 'o'\''neil' `, -1},
		{"user add bob l", "user add bob lab,", -1},
		{"he", "help ", -1},
		{"hi", "history ", -1},
		{"help us", "help user ", -1},
		{"q", "quit ", -1},
		{"exit x", "exit x", -1},
		{"bogus x", "bogus x", -1},
		{"s", "s", -1},
		{"st", "store ", -1},
	}
	for _, c := range cases {
		e, _ := newTestEditor()
		got, pos, ok := e.key(c.line, len(c.line), '\t')
		want := c.wantPos
		if want < 0 {
			want = len(c.want)
		}
		if !ok || got != c.want || pos != want {
			t.Errorf("Tab on %q = %q,%d,%v; want %q,%d", c.line, got, pos, ok, c.want, want)
		}
	}
}

func TestTabInTheMiddle(t *testing.T) {
	e, _ := newTestEditor()
	got, pos, _ := e.key("us list", 2, '\t')
	if got != "user  list" || pos != 5 {
		t.Errorf("got %q,%d", got, pos)
	}
}

func TestSecondTabLists(t *testing.T) {
	e, sc := newTestEditor()
	e.key("user ", 5, '\t')
	if strings.Contains(sc.String(), "show") {
		t.Fatal("the first Tab listed")
	}
	got, _, _ := e.key("user ", 5, '\t')
	if got != "user " {
		t.Errorf("line changed: %q", got)
	}
	// The words alone, in columns.
	if out := sc.String(); !strings.Contains(out, "\r\nlist  show\r\n") || strings.Contains(out, "List all users") {
		t.Errorf("listing %q", out)
	}
	// The top level lists the shell's own words too.
	e, sc = newTestEditor()
	e.key("", 0, '\t')
	e.key("", 0, '\t')
	for _, want := range []string{"user", "group"} {
		if !strings.Contains(sc.String(), want) {
			t.Errorf("top listing lacks %q: %q", want, sc.String())
		}
	}
}

// '?' lists the words with descriptions where words can come; where none
// can it prints the Explainer's text, or says there is nothing; inside
// quotes and after a backslash it is a character. It never changes the line.
func TestQuestionKey(t *testing.T) {
	e, sc := newTestEditor()
	got, pos, ok := e.key("user ", 5, '?')
	if !ok || got != "user " || pos != 5 {
		t.Errorf("got %q,%d,%v", got, pos, ok)
	}
	if out := sc.String(); !strings.Contains(out, "Possible completions:\r\n  list  List all users\r\n  show  Show a user\r\n") {
		t.Errorf("? listing %q", out)
	}
	var asked []string
	e, sc = newTestEditor()
	e.explain = func(words []string) (string, bool) {
		asked = words
		return "Usage:\n  add <username> <group>\nNext: <username> <group>\n", true
	}
	if got, _, _ := e.key("user add ", 9, '?'); got != "user add " {
		t.Errorf("line changed: %q", got)
	}
	if !slices.Equal(asked, []string{"user", "add"}) || !strings.Contains(sc.String(), "Next: <username> <group>") {
		t.Errorf("explain asked %q, printed %q", asked, sc.String())
	}
	e, sc = newTestEditor()
	e.key("bogus ", 6, '?')
	if !strings.Contains(sc.String(), "No valid completions") {
		t.Errorf("no completion: %q", sc.String())
	}
	for _, line := range []string{`echo "a `, "echo 'a ", `echo a\`} {
		if _, _, ok := e.key(line, len(line), '?'); ok {
			t.Errorf("%q: '?' was taken", line)
		}
	}
}

func TestOtherKeysPassThrough(t *testing.T) {
	e, _ := newTestEditor()
	if _, _, ok := e.key("x", 1, 'a'); ok {
		t.Error("a printable key was taken")
	}
	if _, _, ok := e.key("x", 1, 0x1a); ok {
		t.Error("Ctrl-Z was taken")
	}
}

func TestInterruptMarker(t *testing.T) {
	e, _ := newTestEditor()
	got, pos, ok := e.key("user li", 3, markInterrupt)
	if !ok || got != "user li^C" || pos != len(got) || !e.interrupted {
		t.Errorf("got %q,%d,%v interrupted=%v", got, pos, ok, e.interrupted)
	}
}

func TestReverseSearch(t *testing.T) {
	e, _ := newTestEditor()
	for _, l := range []string{"user list", "scope list", "user show bob", "scope show lab"} {
		e.hist.Add(l)
	}
	line, pos := "draft", 5
	step := func(k rune) {
		t.Helper()
		var ok bool
		line, pos, ok = e.key(line, pos, k)
		if !ok {
			t.Fatalf("key %q not taken", k)
		}
	}
	step(0x12)
	if line != "draft" || !e.search.on {
		t.Fatalf("Ctrl-R: %q on=%v", line, e.search.on)
	}
	step('u')
	if line != "user show bob" || pos != 0 {
		t.Errorf("'u': %q,%d", line, pos)
	}
	step('s')
	if line != "user show bob" {
		t.Errorf("'us': %q", line)
	}
	step(0x12) // older
	if line != "user list" {
		t.Errorf("Ctrl-R again: %q", line)
	}
	step(0x12) // nothing older: stays, failed
	if line != "user list" || !e.search.failed {
		t.Errorf("Ctrl-R past the end: %q failed=%v", line, e.search.failed)
	}
	if e.shown != "(failed reverse-i-search)`us': " {
		t.Errorf("prompt %q", e.shown)
	}
	step(markBackspace)
	step(markBackspace)
	if line != "draft" {
		t.Errorf("empty query: %q", line)
	}
	step('l')
	step('i')
	if line != "scope list" || pos != 6 {
		t.Errorf("'li': %q,%d", line, pos)
	}
	step(markAccept)
	if e.search.on || line != "scope list" {
		t.Errorf("accept: %q on=%v", line, e.search.on)
	}
	// Cancel goes back to the line before the search.
	line, pos = "draft", 5
	step(0x12)
	step('s')
	step(markCancel)
	if line != "draft" || pos != 5 || e.search.on {
		t.Errorf("cancel: %q,%d", line, pos)
	}
	if e.shown != DefaultPrompt {
		t.Errorf("prompt not restored: %q", e.shown)
	}
}

func TestInputRewrite(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"plain", []string{"user list\r"}, "user list\r"},
		{"esc-b esc-f", []string{"a\x1bb\x1bf"}, "a\x1b[1;3D\x1b[1;3C"},
		{"esc split", []string{"a\x1b", "b"}, "a\x1b[1;3D"},
		{"ctrl-z ctrl-backslash", []string{"a\x1a\x1cb"}, "ab"},
		{"ctrl-c drops the rest", []string{"abc\x03def\r"}, "abc\r"},
		{"paste", []string{"\x1b[200~user\nlist\r\tx\x07\x1b[201~\r"}, "\x1b[200~user list  x\x1b[201~\r"},
		{"paste split", []string{"\x1b[200~a\n", "b\x1b[20", "1~c"}, "\x1b[200~a b\x1b[201~c"},
		{"paste ctrl-c is dropped", []string{"\x1b[200~a\x03b\x1b[201~"}, "\x1b[200~ab\x1b[201~"},
		{"markers are dropped", []string{"ab"}, "ab"},
		{"ctrl-r turns search on", []string{"\x12us\x7f\r"}, "\x12us\r"},
		{"ctrl-g cancels", []string{"\x12u\x07x"}, "\x12ux"},
		{"ctrl-c in search", []string{"\x12u\x03"}, "\x12u\r"},
		{"arrow ends search", []string{"\x12u\x1b[A"}, "\x12u\x1b[A"},
	}
	for _, c := range cases {
		in := &input{fd: -1, ed: &editor{}, wake: -1}
		var got []byte
		for _, chunk := range c.in {
			got = append(got, in.rewrite([]byte(chunk))...)
		}
		if string(got) != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A paste is as it was before space completion: newlines and tabs become
// spaces, other control characters are dropped, runs of blanks stay, and
// nothing is held back, with the setting on or off.
func TestPasteIsUnchanged(t *testing.T) {
	const start, end = "\x1b[200~", "\x1b[201~"
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"repeated blanks", []string{start + "a  b\n\n\tc" + end + "\r"}, start + "a  b   c" + end + "\r"},
		{"quote and backslash", []string{start + `echo 'a  b'  c\  d` + end}, start + `echo 'a  b'  c\  d` + end},
		{"control characters", []string{start + "a\x07b\x01c\x1ad" + end}, start + "abcd" + end},
		{"split paste", []string{start + "a  ", " b", end + "z"}, start + "a   b" + end + "z"},
		{"typed blanks", []string{"a  b" + start + "c" + end + "  d"}, "a  b" + start + "c" + end + "  d"},
	}
	for _, spaces := range []bool{true, false} {
		for _, c := range cases {
			in := &input{fd: -1, ed: &editor{spaces: spaces}, wake: -1}
			var got []byte
			for _, chunk := range c.in {
				got = append(got, in.rewrite([]byte(chunk))...)
			}
			if string(got) != c.want || len(in.carry) != 0 {
				t.Errorf("%s (spaces %v): %q, carry %q, want %q", c.name, spaces, got, in.carry, c.want)
			}
		}
		// The start of a paste is passed on at once, not held.
		in := &input{fd: -1, ed: &editor{spaces: spaces}, wake: -1}
		if got := in.rewrite([]byte(start + "a  b")); string(got) != start+"a  b" || len(in.carry) != 0 {
			t.Errorf("spaces %v: the start of a paste: got %q, carry %q", spaces, got, in.carry)
		}
	}
}

func TestPasteIsCapped(t *testing.T) {
	in := &input{fd: -1, ed: &editor{}, wake: -1}
	got := in.rewrite([]byte("\x1b[200~" + strings.Repeat("a\n", PasteMax) + "\x1b[201~z"))
	body := strings.TrimSuffix(strings.TrimPrefix(string(got), "\x1b[200~"), "\x1b[201~z")
	if len(body) != PasteMax {
		t.Errorf("paste of %d bytes kept", len(body))
	}
	if !strings.HasSuffix(string(got), "\x1b[201~z") {
		t.Errorf("paste end lost: %q", got[len(got)-10:])
	}
}

func TestCommonPrefix(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"alice", "albert"}, "al"},
		{[]string{"é1", "é2"}, "é"},
		{[]string{"ab", "c"}, ""},
	}
	for _, c := range cases {
		if got := commonPrefix(c.in); got != c.want {
			t.Errorf("commonPrefix(%q) = %q", c.in, got)
		}
	}
	if got := listing([]Candidate{{Word: "a", Desc: "x"}, {Word: "bbb"}}); got != "  a    x\n  bbb\n" {
		t.Errorf("listing = %q", got)
	}
}

// The Tab list is the words alone, down then across in as many columns as
// fit, as bash lists them; one column when none fit.
func TestColumns(t *testing.T) {
	var cs []Candidate
	for _, w := range []string{"ar1", "dev", "web1", "core-sw1", "edge"} {
		cs = append(cs, Candidate{Word: w, Desc: "ignored", Label: w + " <x>"})
	}
	// Width 10 per column (8 + 2): 3 columns in 30, 2 rows.
	if got, want := columns(cs, 30), "ar1       web1      edge\ndev       core-sw1\n"; got != want {
		t.Errorf("columns(30) = %q, want %q", got, want)
	}
	if got, want := columns(cs, 5), "ar1\ndev\nweb1\ncore-sw1\nedge\n"; got != want {
		t.Errorf("columns(5) = %q, want %q", got, want)
	}
	cs = append(cs, Candidate{Word: "quit", Unlisted: true})
	if strings.Contains(columns(cs, 80), "quit") {
		t.Error("an unlisted word was listed with others")
	}
	if got := columns(nil, 80); got != "" {
		t.Errorf("columns(nil) = %q", got)
	}
}

// The '?' list is alphabetical, a Label standing for the word; the
// shell's own words are not listed with others, and are when alone.
func TestListingOrderLabels(t *testing.T) {
	e, _ := newTestEditor()
	e.complete = func([]string, string) []Candidate {
		return []Candidate{
			{Word: "zed", Label: "zed [-x]", Desc: "Last"},
			{Word: "amy", Desc: "First"},
			{Word: "bob", Desc: "Middle"},
		}
	}
	lines := strings.Split(listing(e.candidates(nil, "")), "\n")
	for i, p := range []string{"  amy ", "  bob ", "  zed [-x] "} {
		if !strings.HasPrefix(lines[i], p) {
			t.Errorf("line %d %q, want prefix %q", i, lines[i], p)
		}
	}
	if len(lines) != 4 {
		t.Errorf("lines %q", lines)
	}
	if got := listing(e.candidates(nil, "hi")); !strings.HasPrefix(got, "  history ") {
		t.Errorf("alone: %q", got)
	}
}

func TestLongListHelpers(t *testing.T) {
	if got := wrapRows("abcde\n\nxy\n", 2); !slices.Equal(got, []string{"ab", "cd", "e", "", "xy"}) {
		t.Errorf("wrapRows = %q", got)
	}
	for s, want := range map[string]int{"": 0, "abc": 0, "abcd": 1, "abcdefgh": 2} {
		if got := cursorRow(s, 4); got != want {
			t.Errorf("cursorRow(%q) = %d, want %d", s, got, want)
		}
	}
	cs := []Candidate{{Word: "core01", Kind: "devices"}, {Word: "core02", Kind: "devices"}}
	if got := narrowExample("", cs); got != "core0" {
		t.Errorf("narrowExample common = %q", got)
	}
	if got := narrowExample("core0", cs); got != "core01" {
		t.Errorf("narrowExample next letter = %q", got)
	}
	if got := listKind(cs); got != "devices" {
		t.Errorf("listKind = %q", got)
	}
	if got := listKind(append(cs, Candidate{Word: "x", Kind: "hosts"})); got != "choices" {
		t.Errorf("mixed listKind = %q", got)
	}
	if got := listKind([]Candidate{{Word: "x"}}); got != "choices" {
		t.Errorf("no kind = %q", got)
	}
}

// A typed space, rule by rule (D32). taken is whether the editor took the
// key (false: the Terminal inserts the blank as typed).
func TestSpaceRules(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		pos     int // -1: the end
		want    string
		wantPos int // -1: the end of want
		taken   bool
	}{
		{"unique command completes", "gr", -1, "group ", -1, true},
		{"unique sub-command", "user l", -1, "user list ", -1, true},
		{"unique fixed choice", "user mode of", -1, "user mode off ", -1, true},
		{"unique flag", "user add --f", -1, "user add --force ", -1, true},
		{"closed quotes in the word", "gr'o'", -1, "group ", -1, true},
		{"the shell's own words", "he", -1, "help ", -1, true},
		{"quit", "q", -1, "quit ", -1, true},
		{"help completes the command", "help gr", -1, "help group ", -1, true},
		{"exact match with a longer one", "user", -1, "", 0, false},
		{"exact and unique", "user list", -1, "", 0, false},
		{"none: free text", "zzz", -1, "", 0, false},
		{"live names are not completed", "user show al", -1, "", 0, false},
		{"live name, exact", "user show alice", -1, "", 0, false},
		{"a comma list is not completed", "user add bob l", -1, "", 0, false},
		{"flag name, live names after it", "user add al", -1, "", 0, false},
		{"a lone dash is the blank as typed (standard input)", "user add -", -1, "", 0, false},
		{"two dashes end the options: the blank as typed", "user add --", -1, "", 0, false},
		{"three dashes too", "user add ---", -1, "", 0, false},
		{"a flag's start still completes", "user add --f", -1, "user add --force ", -1, true},
		{"inside double quotes", `echo "gr`, -1, "", 0, false},
		{"inside single quotes", "echo 'gr", -1, "", 0, false},
		{"after a backslash", `gr\`, -1, "", 0, false},
		{"at the start of the line", "group", 0, "group", 0, true},
		{"after a blank", "user ", -1, "user ", -1, true},
		{"after a tab", "user\t", -1, "user\t", -1, true},
		{"before a blank", "user list", 4, "user list", 4, true},
		{"at a word's end before a blank", "gr list", 2, "gr list", 2, true},
		{"in the middle of a word", "group", 2, "", 0, false},
		{"in the middle, past a blank", "user group", 7, "", 0, false},
		{"at the start of a word", "user group", 5, "user group", 5, true},
		{"an empty line", "", 0, "", 0, true},
		{"multibyte word, free text", "é", -1, "", 0, false},
		{"a fixed word completes after a multibyte word", "é li", -1, "é list ", -1, true},
		{"a multibyte character before a blank", "é gr", 2, "é gr", 2, true},
		{"after a multibyte word and a blank", "é ", -1, "é ", -1, true},
		{"in the middle of a word with a multibyte character", "grü", 2, "", 0, false},
		{"a live name position, multibyte partial", "user show é", -1, "", 0, false},
	}
	for _, c := range cases {
		e, sc := newSpaceEditor(t)
		pos := c.pos
		if pos < 0 {
			pos = len(c.line)
		}
		got, gotPos, ok := e.key(c.line, pos, ' ')
		if ok != c.taken {
			t.Errorf("%s: %q at %d: taken = %v", c.name, c.line, pos, ok)
			continue
		}
		if ok {
			want := c.wantPos
			if want < 0 {
				want = len(c.want)
			}
			if got != c.want || gotPos != want {
				t.Errorf("%s: %q at %d = %q,%d; want %q,%d", c.name, c.line, pos, got, gotPos, c.want, want)
			}
		}
		if sc.Len() != 0 {
			t.Errorf("%s: printed %q", c.name, sc.String())
		}
	}
}

// Several fixed words are listed once, without a question and without
// changing the line; a list over ListMax prints nothing; the rest of the
// line, the live names and a mixed list are left out of it.
func TestSpaceListsAmbiguousWords(t *testing.T) {
	e, sc := newSpaceEditor(t)
	got, pos, ok := e.key("s", 1, ' ')
	if !ok || got != "s" || pos != 1 {
		t.Errorf("got %q,%d,%v", got, pos, ok)
	}
	want := "tacctl> s\r\nPossible completions:\r\n  scope  the scope\r\n  store  the store\r\n"
	if !strings.Contains(sc.String(), want) {
		t.Errorf("listing %q; want it to hold %q", sc.String(), want)
	}
	if strings.Contains(sc.String(), "Show all") {
		t.Errorf("asked: %q", sc.String())
	}

	// Fixed words and live names after a flag-less position: only the
	// fixed ones.
	e, sc = newSpaceEditor(t)
	e.key("user add -", 10, ' ')
	if strings.Contains(sc.String(), "alice") {
		t.Errorf("a live name was listed: %q", sc.String())
	}

	// Over ListMax: nothing printed, nothing inserted, nothing asked.
	e, sc = newSpaceEditor(t)
	got, pos, ok = e.key("fx f", 4, ' ')
	if !ok || got != "fx f" || pos != 4 || sc.Len() != 0 {
		t.Errorf("over ListMax: %q,%d,%v printed %q", got, pos, ok, sc.String())
	}
	// At ListMax it is listed; a negative ListMax has no limit.
	e, sc = newSpaceEditor(t)
	e.listMax = 45
	e.key("fx f", 4, ' ')
	if !strings.Contains(sc.String(), "  f45\r\n") || len(strings.Split(sc.String(), "\n")) < 45 {
		t.Errorf("a list of ListMax words was not shown: %q", sc.String())
	}
	e, sc = newSpaceEditor(t)
	e.listMax = -1
	e.key("fx f", 4, ' ')
	if !strings.Contains(sc.String(), "  f45\r\n") {
		t.Errorf("an unlimited list was not shown")
	}
}

// With the setting off a blank is a blank.
func TestSpaceOff(t *testing.T) {
	for _, line := range []string{"gr", "s", "", "user "} {
		e, sc := newSpaceEditor(t)
		e.spaces = false
		if _, _, ok := e.key(line, len(line), ' '); ok || sc.Len() != 0 {
			t.Errorf("%q: taken=%v, printed %q", line, ok, sc.String())
		}
	}
}

// During a Ctrl-R search a space is part of the query, wherever the line
// stands.
func TestSpaceInSearch(t *testing.T) {
	e, _ := newSpaceEditor(t)
	e.hist.Add("user show bob")
	line, pos := "gr", 2
	for _, k := range []rune{0x12, 's', 'h', 'o', 'w', ' '} {
		var ok bool
		line, pos, ok = e.key(line, pos, k)
		if !ok {
			t.Fatalf("key %q not taken", k)
		}
	}
	if string(e.search.query) != "show " || line != "user show bob" || pos != 5 {
		t.Errorf("query %q, line %q,%d", string(e.search.query), line, pos)
	}
	// Once the search is over the next space completes again.
	e.key(line, pos, markAccept)
	if e.search.on {
		t.Fatal("the search is still on")
	}
	if _, _, ok := e.key("gr", 2, ' '); !ok {
		t.Error("the space after the search was not handled")
	}
}

// Tab, '?' and the other keys keep their meaning with the setting on.
func TestSpaceKeepsOtherKeys(t *testing.T) {
	e, _ := newSpaceEditor(t)
	if got, _, ok := e.key("gr", 2, '\t'); !ok || got != "group " {
		t.Errorf("Tab: %q,%v", got, ok)
	}
	if _, _, ok := e.key("x", 1, 'a'); ok {
		t.Error("a letter was taken")
	}
	if _, _, ok := e.key("x", 1, '?'); !ok {
		t.Error("? was not taken")
	}
}

// A Ctrl-C inside a paste is part of the paste and dropped: it never
// interrupts, so what comes after it in the paste is never run as typed
// keys, with the setting on or off and wherever the reads end.
func TestCtrlCInAPasteIsContent(t *testing.T) {
	const start, end = "\x1b[200~", "\x1b[201~"
	feed := func(spaces bool, reads ...string) string {
		in := &input{fd: -1, ed: &editor{spaces: spaces}, wake: -1}
		var got []byte
		for _, r := range reads {
			got = append(got, in.rewrite([]byte(r))...)
		}
		return string(got)
	}
	for _, spaces := range []bool{true, false} {
		got := feed(spaces, start+"echo a\x03b", "\rrm x\r"+end)
		if want := start + "echo ab rm x " + end; got != want {
			t.Errorf("spaces %v: %q, want %q", spaces, got, want)
		}
		whole := start + "echo a\x03b\rrm x\r" + end
		for k := 1; k < len(whole); k++ {
			got := feed(spaces, whole[:k], whole[k:])
			if strings.ContainsAny(got, "\r\n") || strings.ContainsRune(got, markInterrupt) {
				t.Errorf("spaces %v split at %d: %q", spaces, k, got)
			}
		}
	}
}

// When the editor asks a question or pages, key answers 'q' and consumes
// nothing if what the editor has not read holds a paste start or end mark,
// so a pager never eats the end mark of a pasted line; else it takes the
// next byte.
func TestKeyLeavesPasteMarks(t *testing.T) {
	const start, end = "\x1b[200~", "\x1b[201~"
	for _, pending := range []string{start + "bbb" + end, "bbb" + end, "x" + start + "bbb", end} {
		in := &input{fd: -1, ed: &editor{}, wake: -1, pending: []byte(pending)}
		for range 3 {
			if k, err := in.key(); err != nil || k != 'q' || string(in.pending) != pending {
				t.Fatalf("%q: key %q, %v, pending %q", pending, k, err, in.pending)
			}
		}
	}
	in := &input{fd: -1, ed: &editor{}, wake: -1, pending: []byte("ny")}
	if k, err := in.key(); err != nil || k != 'n' || string(in.pending) != "y" {
		t.Errorf("plain pending: key %q, %v, pending %q", k, err, in.pending)
	}
}

// A typed blank asks completeFixed (which does not look up live names),
// Tab and '?' ask complete.
func TestSpaceAsksTheFixedCompleter(t *testing.T) {
	e, _ := newSpaceEditor(t)
	var full, fixed int
	e.complete = func(words []string, partial string) []Candidate { full++; return spaceCompleter(words, partial) }
	e.completeFixed = func(words []string, partial string) []Candidate { fixed++; return spaceCompleter(words, partial) }
	if got, _, ok := e.key("gr", 2, ' '); !ok || got != "group " {
		t.Errorf("space: %q, %v", got, ok)
	}
	if full != 0 || fixed != 1 {
		t.Errorf("space asked complete %d, completeFixed %d times", full, fixed)
	}
	e.key("gr", 2, '\t')
	e.key("user ", 5, '?')
	if full != 2 || fixed != 1 {
		t.Errorf("Tab and ? asked complete %d, completeFixed %d times", full, fixed)
	}
}
