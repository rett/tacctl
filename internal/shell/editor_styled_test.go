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

// The styled list is the plain one with the labels in bold: the same bytes
// once the escapes are gone, the padding counted on the plain label.
func TestListingStyled(t *testing.T) {
	cands := []Candidate{
		{Word: "a", Desc: "x"},
		{Word: "bbb", Label: "bbb [--long]", Desc: "y"},
		{Word: "ünï"},
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
	for _, label := range []string{"a", "bbb [--long]", "ünï"} {
		if !strings.Contains(got, ui.Bold+label+ui.NC) {
			t.Errorf("label %q not bold in %q", label, got)
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
