package ui

import (
	"strings"
	"testing"
)

func TestTableGeometry(t *testing.T) {
	tb := NewTable("Users", Left("USERNAME"), Left("UID"), Left("GROUP"), Left("STATUS"), Left("PW CHANGED"), Left("SCOPES"))
	tb.Add("alice", "20001", "superuser", Styled(Green, "active"), "2026-10-01", "lab,dmz,fw")
	tb.Add("operator", "20003", "operator", Styled(Red, "disabled"), "2026-10-04", "lab")
	tb.Add("guest", "-", "readonly", Styled(Red, "disabled"), "unknown", "lab")
	got := tb.String()
	for _, c := range []string{Bold, Green, Red, NC} {
		got = strings.ReplaceAll(got, c, "")
	}
	want := `Users
` + strings.Repeat("-", 62) + `
  USERNAME  UID    GROUP      STATUS    PW CHANGED  SCOPES
  ` + strings.Repeat("-", 60) + `
  alice     20001  superuser  active    2026-10-01  lab,dmz,fw
  operator  20003  operator   disabled  2026-10-04  lab
  guest     -      readonly   disabled  unknown     lab
`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestTableColourDoesNotCountAndNoTrailingSpace(t *testing.T) {
	tb := NewTable("T", Left("A"), Left("B"))
	tb.Add(Styled(Green, "x"), "1")
	tb.Add(Styled(Green, "longer"), "")
	tb.Add("y", Styled(Cyan, "z"))
	for _, l := range strings.Split(strings.TrimSuffix(tb.String(), "\n"), "\n") {
		if strings.HasSuffix(l, " ") {
			t.Errorf("trailing space in %q", l)
		}
	}
	if !strings.Contains(tb.String(), "  "+Green+"x"+NC+"       1\n") {
		t.Errorf("column not aligned on visible width: %q", tb.String())
	}
}

func TestTableEmptyAndRight(t *testing.T) {
	tb := NewTable("Things", Right("#"), Left("NAME"))
	lines := strings.Split(tb.String(), "\n")
	if len(lines) != 5 || lines[1] != strings.Repeat("-", 2+1+2+4) || lines[3] != "  "+strings.Repeat("-", 7) {
		t.Errorf("empty table: %q", lines)
	}
	tb.Add("10", "a")
	tb.Add("2", "b")
	if !strings.Contains(tb.String(), "\n   2  b\n") {
		t.Errorf("right alignment: %q", tb.String())
	}
}

func TestWidthCountsCharactersNotEscapes(t *testing.T) {
	if got := Width(Green + "a,b (…+2)" + NC); got != 9 {
		t.Errorf("Width = %d, want 9", got)
	}
}

func TestRule(t *testing.T) {
	if len(Rule("short")) != DetailRuleWidth || len(Rule(strings.Repeat("x", 60))) != 60 {
		t.Error("Rule width")
	}
}
