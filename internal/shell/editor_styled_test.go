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
