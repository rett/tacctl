package shell

import (
	"bytes"
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
			{Word: "user", Desc: "User management"}, {Word: "group", Desc: "Group management"},
			{Word: "scope", Desc: "Scope management"}, {Word: "store", Desc: "The canonical store"},
		}
	case "user":
		return []Candidate{{Word: "list", Desc: "List all users"}, {Word: "show", Desc: "Show a user"}}
	case "user show":
		return []Candidate{{Word: "alice"}, {Word: "albert"}, {Word: "bob"}, {Word: "o'neil"}}
	case "user add bob":
		return []Candidate{{Word: "lab,", NoSpace: true}}
	}
	return nil
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
	if strings.Contains(sc.String(), "List all users") {
		t.Fatal("the first Tab listed")
	}
	got, _, _ := e.key("user ", 5, '\t')
	if got != "user " {
		t.Errorf("line changed: %q", got)
	}
	out := sc.String()
	for _, want := range []string{"  list  List all users", "  show  Show a user"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing %q lacks %q", out, want)
		}
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

// A list is in the order the completer gave (Order) then alphabetical, a
// Label standing for the word; the shell's own words are not listed with
// others, and are when alone.
func TestListingOrderLabels(t *testing.T) {
	e, _ := newTestEditor()
	e.complete = func([]string, string) []Candidate {
		return []Candidate{
			{Word: "zed", Label: "zed [-x]", Desc: "Last", Order: 2},
			{Word: "amy", Desc: "First", Order: 1},
			{Word: "bob", Desc: "Unordered"},
		}
	}
	lines := strings.Split(listing(e.candidates(nil, "")), "\n")
	for i, p := range []string{"  amy ", "  zed [-x] ", "  bob "} {
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
