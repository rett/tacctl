package ui

import (
	"bytes"
	"context"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// bashPrintf runs script with the colour variables of lib/core.sh defined
// and returns stdout.
func bashPrintf(t *testing.T, script string) string {
	t.Helper()
	pre := "BOLD='\\033[1m'; NC='\\033[0m'; RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'\n"
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{
		Name:  "bash",
		Args:  []string{"-c", pre + script},
		Env:   []string{"LC_ALL=C", "PATH=/usr/bin:/bin"},
		Stdin: bytes.NewReader(nil),
	})
	if err != nil || res.Code != 0 {
		t.Fatalf("bash: %v (exit %d): %s", err, res.Code, res.Stderr)
	}
	return string(res.Stdout)
}

// The tables below are the printf lines of the 0.1.16 lib/*.sh listings; the
// expected text is what bash itself prints for them.
func TestTableMatchesBashPrintf(t *testing.T) {
	// lib/users.sh:235,261 (user list; colour wraps the padded status cell)
	users := NewTable(L(20), L(15), L(10), L(12), L(30))
	got := users.Header("USERNAME", "GROUP", "STATUS", "PW CHANGED", "SCOPES") +
		users.Row("alice", "superuser", Styled(Green, "active"), "2026-10-01", "lab,prod") +
		users.Row("bob", "readonly", Styled(Red, "disabled"), "unknown", "")
	want := bashPrintf(t, `
printf "  ${BOLD}%-20s %-15s %-10s %-12s %-30s${NC}\n" "USERNAME" "GROUP" "STATUS" "PW CHANGED" "SCOPES"
printf "  %-20s %-15s ${GREEN}%-10s${NC} %-12s %-30s\n" "alice" "superuser" "active" "2026-10-01" "lab,prod"
printf "  %-20s %-15s ${RED}%-10s${NC} %-12s %-30s\n" "bob" "readonly" "disabled" "unknown" ""
`)
	if got != want {
		t.Errorf("user list:\n got %q\nwant %q", got, want)
	}

	// lib/scopes.sh:386-404 (scope list: right-aligned count, two-space gaps,
	// the name cell bold, an empty first cell for continuation lines)
	scopes := NewTable(L(18), L(20), R(5), L(7).WithGap(2), L(0).WithGap(2))
	got = scopes.Header("NAME", "PREFIXES", "USERS", "DEFAULT", "VENDOR ATTRIBUTES (RADIUS)") +
		scopes.Row(Styled(Bold, "lab"), "10.0.0.0/8", "3", "default", "cisco,juniper") +
		scopes.Row("", "172.16.0.0/12") +
		scopes.Row(Styled(Bold, "a-long-scope-name-over-18"), "192.168.0.0/16", "12345678", "", "not sent")
	want = bashPrintf(t, `
printf "  ${BOLD}%-18s %-20s %5s  %-7s  %s${NC}\n" "NAME" "PREFIXES" "USERS" "DEFAULT" "VENDOR ATTRIBUTES (RADIUS)"
printf "  ${BOLD}%-18s${NC} %-20s %5s  %-7s  %s\n" "lab" "10.0.0.0/8" "3" "default" "cisco,juniper"
printf "  %-18s %-20s\n" "" "172.16.0.0/12"
printf "  ${BOLD}%-18s${NC} %-20s %5s  %-7s  %s\n" "a-long-scope-name-over-18" "192.168.0.0/16" "12345678" "" "not sent"
`)
	if got != want {
		t.Errorf("scope list:\n got %q\nwant %q", got, want)
	}

	// lib/scopes.sh:430,438 (numbered prefix list, %3s first column)
	nums := NewTable(R(3), L(18).WithGap(2), L(20), R(5), L(0).WithGap(2))
	got = nums.Header("#", "NAME", "PREFIX", "USERS", "DEFAULT") +
		nums.Row("1", Styled(Bold, "lab"), "10.0.0.0/8", "3", Styled(Green, "yes"))
	want = bashPrintf(t, `
printf "  ${BOLD}%3s  %-18s %-20s %5s  %s${NC}\n" "#" "NAME" "PREFIX" "USERS" "DEFAULT"
printf "  %3d  ${BOLD}%-18s${NC} %-20s %5s  %b\n" "1" "lab" "10.0.0.0/8" "3" "${GREEN}yes${NC}"
`)
	if got != want {
		t.Errorf("numbered list:\n got %q\nwant %q", got, want)
	}

	// lib/groups.sh:364-375 (rules: colour in the middle, "(catchall)")
	rules := NewTable(L(20), L(8), L(0))
	got = rules.Header("NAME", "ACTION", "MATCH") +
		rules.Row("show (catchall)", Styled(Green, "permit"), "") +
		rules.Row("configure", Styled(Red, "deny"), "terminal.*")
	want = bashPrintf(t, `
printf "  ${BOLD}%-20s %-8s %s${NC}\n" "NAME" "ACTION" "MATCH"
printf "  %-20s ${GREEN}%-8s${NC} %s\n" "show (catchall)" "permit" ""
printf "  %-20s ${RED}%-8s${NC} %s\n" "configure" "deny" "terminal.*"
`)
	if got != want {
		t.Errorf("rules:\n got %q\nwant %q", got, want)
	}
}

// printf pads by bytes, not characters.
func TestPadCountsBytes(t *testing.T) {
	got := Pad("é€", 6) + "|" + PadLeft("é€", 6) + "|"
	want := bashPrintf(t, `printf '%-6s|%6s|' 'é€' 'é€'`)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if Pad("toolong", 3) != "toolong" || PadLeft("toolong", 3) != "toolong" {
		t.Error("padding must not truncate")
	}
}

func TestTableRowShorterAndLonger(t *testing.T) {
	tb := NewTable(L(4), L(4))
	if got := tb.Row("a"); got != "  a   \n" {
		t.Errorf("short row = %q", got)
	}
	if got := tb.Row("a", "b", "ignored"); got != "  a    b   \n" {
		t.Errorf("long row = %q", got)
	}
	tb.Indent = ""
	if got := tb.Row("a", "b"); got != "a    b   \n" {
		t.Errorf("no indent = %q", got)
	}
}
