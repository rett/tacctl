package shell

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/ui"
)

// stripped is s with its SGR sequences removed.
func stripped(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := ui.StripSGR(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

// The styled list is the plain one with the words in the palette: the same
// bytes once the escapes are gone, the padding counted on the plain label. A
// command name is bright white, a sub-command, a fixed word and an option
// teal, a live name bold; the description is plain.
func TestListingStyled(t *testing.T) {
	cands := []Candidate{
		{Word: "device", Label: "device [<name>]", Desc: "x", Command: true, Fixed: true},
		{Word: "bbb", Label: "bbb [--long]", Desc: "y", Fixed: true},
		{Word: "--all", Desc: "z", Fixed: true},
		{Word: "alice", Desc: "operator", Live: true},
		{Word: "ünï", Live: true},
	}
	plain := listing(cands)
	got := listingStyled(cands, true)
	if got == plain {
		t.Fatal("styled list is plain")
	}
	if want := listingStyled(cands, false); plain != want {
		t.Errorf("listing %q != unstyled %q", plain, want)
	}
	if s := stripped(t, got); s != plain {
		t.Errorf("plain text of the styled list %q, want %q", s, plain)
	}
	for _, want := range []string{
		"  " + ui.BrightWhite + "device" + ui.NC + " [<name>]",
		"  " + ui.Teal + "bbb" + ui.NC + " " + ui.Teal + "[--long]" + ui.NC,
		"  " + ui.Teal + "--all" + ui.NC,
		"  " + ui.Bold + "alice" + ui.NC,
		"  " + ui.Bold + "ünï" + ui.NC + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %q", want, got)
		}
	}
	// A description is plain text.
	for _, d := range []string{"x\n", "y\n", "z\n", "operator\n"} {
		if !strings.Contains(got, "  "+d) {
			t.Errorf("the description %q is not plain in %q", d, got)
		}
	}
}

// The Tab columns carry the same palette; the columns are those of the plain
// words, whatever the colour.
func TestColumnsStyled(t *testing.T) {
	cands := []Candidate{
		{Word: "device", Command: true, Fixed: true}, {Word: "alice", Live: true}, {Word: "list", Fixed: true},
		{Word: "bob", Live: true}, {Word: "--all", Fixed: true}, {Word: "quit", Unlisted: true, Fixed: true},
	}
	for _, w := range []int{20, 40, 60, 120} {
		plain, styled := columns(cands, w), columnsStyled(cands, w, true)
		if stripped(t, styled) != plain {
			t.Errorf("width %d: %q is not the plain %q", w, styled, plain)
		}
		for _, row := range strings.Split(strings.TrimSuffix(plain, "\n"), "\n") {
			if len([]rune(row)) > w {
				t.Errorf("width %d: a row of %d", w, len([]rune(row)))
			}
		}
	}
	got := columnsStyled(cands, 80, true)
	for _, want := range []string{ui.BrightWhite + "device" + ui.NC, ui.Bold + "alice" + ui.NC, ui.Teal + "list" + ui.NC, ui.Bold + "bob" + ui.NC} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %q", want, got)
		}
	}
	if columnsStyled(cands, 80, false) != columns(cands, 80) {
		t.Error("unstyled columns differ")
	}
}

// Colour in a label and in a description takes no column: at 40, 60 and 120
// columns the lines break, cut and pad exactly as they do without it, a style
// open at a break is closed there and opened on the next line, and nothing is
// cut inside a sequence.
func TestListingWidthsIgnoreSGR(t *testing.T) {
	longDesc := "Show the " + ui.Bold + "live names with their vendor, address and scope" + ui.NC + " and wrap this text past the width of the column so that it goes on under it"
	plainDesc := stripSGR(longDesc)
	longLabel := ui.Teal + "devices" + ui.NC + " [show|max-concurrency|transport|timeout] [<value>]"
	for _, w := range []int{40, 60, 120} {
		for _, shortLabel := range []bool{true, false} {
			label, plainLabel := ui.Teal+"x"+ui.NC+" <"+ui.Bold+"n"+ui.NC+">", "x <n>"
			if !shortLabel {
				label, plainLabel = longLabel, stripSGR(longLabel)
			}
			colour := []Candidate{{Word: "x", Label: label, Desc: longDesc}, {Word: "ab", Label: ui.Teal + "ab" + ui.NC, Desc: ui.Teal + "short" + ui.NC}}
			bare := []Candidate{{Word: "x", Label: plainLabel, Desc: plainDesc}, {Word: "ab", Label: "ab", Desc: "short"}}
			for _, styled := range []bool{false, true} {
				got := listingWidth(colour, styled, w)
				want := listingWidth(bare, false, w)
				if !styled {
					if got != want {
						t.Errorf("w=%d short=%v: unstyled\n%q\nwant\n%q", w, shortLabel, got, want)
					}
					continue
				}
				// The same rows once the colour is gone: the same breaks, the
				// same padding.
				if s := stripped(t, got); s != want {
					t.Errorf("w=%d short=%v: the plain text of the coloured list\n%q\nwant\n%q", w, shortLabel, s, want)
				}
				for i, row := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
					if open := openStyle(row); open != "" {
						t.Errorf("w=%d short=%v row %d is left with %q open: %q", w, shortLabel, i, open, row)
					}
				}
			}
		}
	}
	// The wrapped description keeps its bold across the break.
	rows := strings.Split(strings.TrimSuffix(listingWidth([]Candidate{{Word: "x", Label: "x", Desc: longDesc}}, true, 40), "\n"), "\n")
	if len(rows) < 3 {
		t.Fatalf("not wrapped at 40: %q", rows)
	}
	opened := 0
	for _, r := range rows[:2] {
		if strings.Contains(r, ui.Bold) {
			opened++
		}
	}
	if opened < 2 {
		t.Errorf("the bold run did not carry over the break: %q", rows)
	}
}

// openStyle is the style left open at the end of s ("": none).
func openStyle(s string) string {
	open := ""
	for i := 0; i < len(s); {
		if k := sgrAt(s, i); k > 0 {
			open = track(open, s[i:i+k])
			i += k
			continue
		}
		i++
	}
	return open
}

// capLabel counts columns, not bytes: a label with colour is cut at the same
// place as the plain one, never inside a sequence, with its style closed.
func TestCapLabelSGR(t *testing.T) {
	plain := "devices [show|max-concurrency|transport|timeout] [<value>]"
	colour := ui.Teal + "devices" + ui.NC + " [" + ui.Bold + "show|max-concurrency|transport|timeout" + ui.NC + "] [<value>]"
	for _, max := range []int{10, 20, 40, 60} {
		want := capLabel(plain, max)
		got := capLabel(colour, max)
		if s := stripSGR(got); s != want {
			t.Errorf("max %d: %q cut to %q, want %q", max, got, s, want)
		}
		if open := openStyle(strings.TrimSuffix(got, "...")); open != "" {
			t.Errorf("max %d: style %q open before the dots in %q", max, open, got)
		}
		if visLen(got) > max {
			t.Errorf("max %d: %d columns", max, visLen(got))
		}
	}
	if got := capLabel(colour, 80); got != colour {
		t.Errorf("a label that fits is cut: %q", got)
	}
}

// wrapWords counts columns and carries a style over the break.
func TestWrapWordsSGR(t *testing.T) {
	in := "one " + ui.Bold + "two three" + ui.NC + " four"
	got := wrapWords(in, 10)
	want := []string{"one " + ui.Bold + "two" + ui.NC, ui.Bold + "three" + ui.NC + " four"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("wrapWords = %q, want %q", got, want)
	}
	for _, w := range []int{9, 14, 40} {
		var plain []string
		for _, l := range wrapWords(in, w) {
			plain = append(plain, stripSGR(l))
		}
		if want := wrapWords(stripSGR(in), w); strings.Join(plain, "|") != strings.Join(want, "|") {
			t.Errorf("w=%d: %q, want %q", w, plain, want)
		}
	}
}

// A styled row is cut by its visible runes, never inside a sequence, and
// each row closes and reopens a style the cut left open.
func TestWrapRowsStyled(t *testing.T) {
	rows := wrapRows("  "+ui.Bold+"abcdef"+ui.NC+"  tail\nplain\n", 5)
	want := []string{
		"  " + ui.Bold + "abc" + ui.NC,
		ui.Bold + "def" + ui.NC + "  ",
		"tail",
		"plain",
	}
	if strings.Join(rows, "|") != strings.Join(want, "|") {
		t.Errorf("rows %q, want %q", rows, want)
	}
	for _, r := range rows {
		if n := len([]rune(stripped(t, r))); n > 5 {
			t.Errorf("row %q is %d wide", r, n)
		}
	}
	// A cut inside a bold label: each row stands alone.
	cut := wrapRows(ui.Bold+"abcd"+ui.NC+"\n", 2)
	if want := []string{ui.Bold + "ab" + ui.NC, ui.Bold + "cd" + ui.NC}; strings.Join(cut, "|") != strings.Join(want, "|") {
		t.Errorf("cut label rows %q, want %q", cut, want)
	}
	// A line that fits is one row, escapes and all.
	one := ui.Bold + "ab" + ui.NC + "cd"
	if got := wrapRows(one+"\n", 4); len(got) != 1 || got[0] != one {
		t.Errorf("fitting line %q", got)
	}
}

// A label wider than LabelMax is shown as its first words and "...".
func TestCapLabel(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"version [--long]", "version [--long]"},
		{strings.Repeat("x", LabelMax), strings.Repeat("x", LabelMax)},
		{"cisco source-interface [<scope> [<interface>|none]]", "cisco source-interface [<scope>..."},
		{"devices [show|max-concurrency|transport|timeout] [<value>]", "devices [show|max-concurrency|transpo..."},
		{strings.Repeat("x", 60), strings.Repeat("x", LabelMax-3) + "..."},
	} {
		got := capLabel(c.in, LabelMax)
		if got != c.want || len([]rune(got)) > LabelMax {
			t.Errorf("capLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The descriptions start in one column, after the capped labels; one that
// does not fit goes on under that column, word by word, and no row is
// wider than the terminal.
func TestListingWidthWrapsDescriptions(t *testing.T) {
	long := "How the pull reads the devices, the confirm timeout of the plan and how the apply runs, with its pause and its transport"
	cands := []Candidate{
		{Word: "a", Label: "a <x>", Desc: "Short"},
		{Word: "devices", Label: "devices [show|max-concurrency|transport|timeout] [<value>]", Desc: long},
	}
	const w = 80
	got := listingWidth(cands, false, w)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("the long description is not wrapped:\n%s", got)
	}
	col := 2 + LabelMax + 2
	if !strings.HasPrefix(lines[0], "  a <x>"+strings.Repeat(" ", LabelMax-len("a <x>"))+"  Short") {
		t.Errorf("first row %q", lines[0])
	}
	for i, l := range lines {
		if len([]rune(l)) > w {
			t.Errorf("row %d is %d wide: %q", i, len([]rune(l)), l)
		}
		if i >= 2 && !strings.HasPrefix(l, strings.Repeat(" ", col)) {
			t.Errorf("row %d does not go on at column %d: %q", i, col, l)
		}
	}
	if joined := strings.Join(strings.Fields(strings.Join(lines[1:], " ")), " "); !strings.HasSuffix(joined, long) {
		t.Errorf("the wrapped text lost words:\n%s", got)
	}
	// Width unknown: no wrapping, as before.
	if one := listingWidth(cands, false, 0); strings.Count(one, "\n") != 2 {
		t.Errorf("wrapped without a width:\n%s", one)
	}
	// A terminal too narrow for a sensible column is left to the terminal.
	if one := listingWidth(cands, false, 50); strings.Count(one, "\n") != 2 {
		t.Errorf("wrapped at 50 columns:\n%s", one)
	}
}

// A candidate with no label and a long word is capped like a label: the
// column never grows past LabelMax, and a row stays within the terminal.
func TestListingCapsALongWord(t *testing.T) {
	long := strings.Repeat("core-router-", 6) + "1"
	cands := []Candidate{
		{Word: "a", Desc: "Short"},
		{Word: long, Desc: "cisco 192.0.2.1 site-a"},
	}
	got := listingWidth(cands, false, 120)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows:\n%s", got)
	}
	short := capLabel(long, LabelMax)
	if !strings.HasSuffix(short, "...") || len([]rune(short)) != LabelMax {
		t.Fatalf("capped word %q", short)
	}
	if want := "  " + short + "  cisco 192.0.2.1 site-a"; lines[1] != want {
		t.Errorf("row %q, want %q", lines[1], want)
	}
	if want := "  a" + strings.Repeat(" ", LabelMax-1) + "  Short"; lines[0] != want {
		t.Errorf("row %q, want %q", lines[0], want)
	}
	// Without a description the word is capped as well.
	if one := listingWidth([]Candidate{{Word: long}}, false, 120); one != "  "+short+"\n" {
		t.Errorf("bare word row %q", one)
	}
}

// A description whose words are aligned in columns by blanks (the live
// names of a device: vendor, address, scope) keeps them when it goes on
// under its column; only the run at the cut is dropped.
func TestWrapWordsKeepsTheBlanks(t *testing.T) {
	for _, c := range []struct {
		in   string
		w    int
		want []string
	}{
		{"cisco   192.0.2.1    site-a", 40, []string{"cisco   192.0.2.1    site-a"}},
		{"cisco   192.0.2.1    site-a", 20, []string{"cisco   192.0.2.1", "site-a"}},
		{"cisco   192.0.2.1    site-a", 22, []string{"cisco   192.0.2.1", "site-a"}},
		{"cisco   192.0.2.1    site-a", 26, []string{"cisco   192.0.2.1", "site-a"}},
		{"cisco   192.0.2.1    site-a", 27, []string{"cisco   192.0.2.1    site-a"}},
		{"a  b  c", 4, []string{"a  b", "c"}},
		{"one two three four", 9, []string{"one two", "three", "four"}},
		{"  lead", 10, []string{"lead"}},
		{"", 10, []string{""}},
		{strings.Repeat("x", 12), 5, []string{strings.Repeat("x", 12)}},
	} {
		if got := wrapWords(c.in, c.w); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrapWords(%q, %d) = %q, want %q", c.in, c.w, got, c.want)
		}
	}
}
