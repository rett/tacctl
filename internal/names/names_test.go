package names

import (
	"errors"
	"strings"
	"testing"
)

func msg(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want *Error", err)
	}
	return err.Error()
}

// --- validate_username ---

func TestValidateUsernameAccepts(t *testing.T) {
	for _, s := range []string{"jsmith", "j_smith-2", "A1"} {
		if err := ValidateUsername(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestValidateUsernameRejects(t *testing.T) {
	const want = "Username must contain only letters, numbers, underscores, and hyphens."
	for _, s := range []string{"j smith", "", "foo;rm", "foo$bar", "foo/bar", "foo.bar", "abc\n", "é"} {
		if got := msg(t, ValidateUsername(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// --- validate_class_name ---

func TestValidateClassName(t *testing.T) {
	for _, s := range []string{"readonly", "my-group_1"} {
		if err := ValidateClassName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"bad group", ""} {
		want := "Invalid name '" + s + "'. Only letters, numbers, underscores, and hyphens are allowed."
		if got := msg(t, ValidateClassName(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// --- reject_reserved_username ---

func TestRejectReservedUsername(t *testing.T) {
	wantRoot := []string{
		"Username 'root' is reserved as an accounting-only sink for Junos internal daemons (non-tty CLI as root).",
		"The hash stays disabled permanently — root must only be used for local/console login, never TACACS+ or RADIUS.",
		"Create an operator-specific account instead (e.g. tacctl user add jsmith <group>).",
	}
	var e *Error
	if !errors.As(RejectReservedUsername("root"), &e) || strings.Join(e.Lines(), "|") != strings.Join(wantRoot, "|") {
		t.Errorf("root: %v", e)
	}
	if !errors.As(RejectReservedUsername("tacquito"), &e) ||
		len(e.Lines()) != 1 || e.Lines()[0] != "Username 'tacquito' is reserved (matches the service user). Pick a different name." {
		t.Errorf("tacquito: %v", e)
	}
	for _, s := range []string{"jsmith", "Root", "tacquito2", ""} {
		if err := RejectReservedUsername(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// --- group and scope names ---

func TestValidateGroupName(t *testing.T) {
	for _, s := range []string{"a", "helpdesk", "net-ops_2"} {
		if err := ValidateGroupName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "Helpdesk", "1abc", "-a", "a b", "a.b"} {
		if got := msg(t, ValidateGroupName(s)); got != "Group name must be lowercase, starting with a letter." {
			t.Errorf("%q: %q", s, got)
		}
	}
}

func TestValidateScopeName(t *testing.T) {
	for _, s := range []string{"a", "lab", "Prod-1", "x_y", strings.Repeat("a", 32)} {
		if err := ValidateScopeName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "1lab", "-lab", "la b", strings.Repeat("a", 33), "lab.1"} {
		want := "Invalid scope name '" + s + "'. Use letters/digits/_-, starting with a letter."
		if got := msg(t, ValidateScopeName(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

func TestMatchers(t *testing.T) {
	if !MatchUser("a-b_1") || MatchUser("") || MatchUser("a b") {
		t.Error("MatchUser")
	}
	if !MatchGroup("a1") || MatchGroup("A1") {
		t.Error("MatchGroup")
	}
	if !MatchScope("A1") || MatchScope("1A") {
		t.Error("MatchScope")
	}
	if !MatchClass("READ-ONLY_1") || MatchClass("a b") {
		t.Error("MatchClass")
	}
}

// --- validate_priv_command_string ---

func TestPrivCommandAccepts(t *testing.T) {
	for _, s := range []string{"show running-config", "terminal monitor", "ab", strings.Repeat("a", 64)} {
		if err := ValidatePrivCommandString(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestPrivCommandRejectsEmpty(t *testing.T) {
	if got := msg(t, ValidatePrivCommandString("")); got != "Privilege command must not be empty." {
		t.Error(got)
	}
}

func TestPrivCommandRejectsEdgeWhitespace(t *testing.T) {
	for _, s := range []string{" show", "show ", "\tshow", "show\n"} {
		want := "Privilege command has leading/trailing whitespace: '" + s + "'"
		if got := msg(t, ValidatePrivCommandString(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

func TestPrivCommandRejectsMetacharacters(t *testing.T) {
	for _, s := range []string{"show; rm", "show$(pwd)", "a", "1show", "-show", "show\tall"} {
		want := "Invalid privilege command '" + s + "'.\nUse letters, digits, spaces, '-', '_' (e.g. 'show running-config', 'terminal monitor')."
		if got := msg(t, ValidatePrivCommandString(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

func TestPrivCommandRejectsOver64(t *testing.T) {
	if got := msg(t, ValidatePrivCommandString(strings.Repeat("a", 65))); got != "Privilege command too long (65 chars; max 64)." {
		t.Error(got)
	}
}

// --- validate_command_name ---

func TestCommandName(t *testing.T) {
	for _, s := range []string{"*", "show", "configure", "ping", "a", "show-all_1", "a" + strings.Repeat("b", 31)} {
		if err := ValidateCommandName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"1show", "show all", "show*", "", "**", "a" + strings.Repeat("b", 32)} {
		want := "Invalid command name '" + s + "'.\nUse a literal cmd token (e.g. 'show', 'configure') or '*' for the catchall."
		if got := msg(t, ValidateCommandName(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// --- validate_acl_name ---

func TestACLName(t *testing.T) {
	for _, s := range []string{"VTY-ACL", "mgmt_ssh_v2", strings.Repeat("A", 63)} {
		if err := ValidateACLName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	if got := msg(t, ValidateACLName("")); got != "ACL name must not be empty." {
		t.Error(got)
	}
	if got := msg(t, ValidateACLName(strings.Repeat("A", 64))); got != "ACL name too long (64 chars; max 63)." {
		t.Error(got)
	}
	// Too long wins over bad shape, as in the bash.
	if got := msg(t, ValidateACLName("1"+strings.Repeat("A", 70))); got != "ACL name too long (71 chars; max 63)." {
		t.Error(got)
	}
	for _, s := range []string{"1-ACL", "-ACL", "A B", "A.B"} {
		want := "Invalid ACL name '" + s + "'. Must start with a letter and contain only letters, digits, '_', '-'."
		if got := msg(t, ValidateACLName(s)); got != want {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// --- validate_regex ---

func TestValidateRegex(t *testing.T) {
	for _, s := range []string{`^show .*$`, `config(ure)?`, ``, `.*`} {
		if err := ValidateRegex(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{`(`, `[a-`, `a**`, `(?=x)`} {
		if got := msg(t, ValidateRegex(s)); got != "Invalid regex: '"+s+"'" {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// --- command_match_is_dead ---

func TestCommandMatchIsDeadFlagsRepeatedCommandWord(t *testing.T) {
	for _, c := range [][2]string{
		{"show", `^show .*$`}, {"ping", `^ping( .*)?$`}, {"show", `^show$`}, {"show", `show\s+running.*`},
		{"show", `show (a|b)`}, {"show", `^show(\s.*)?$`}, {"show", `^show(?: .*)?$`}, {"show", "show\tx"},
		{"show", `(show .*)`[1:]}, {"show", `show(\s+x)?`},
	} {
		if !CommandMatchIsDead(c[0], c[1]) {
			t.Errorf("%v not flagged", c)
		}
	}
}

func TestCommandMatchIsDeadAcceptsArgumentRegexes(t *testing.T) {
	for _, c := range [][2]string{
		{"show", `running-config`}, {"show", `^run.*$`}, {"show", `.*`}, {"clear", `(counters|line) .*`},
		{"show", `ping .*`}, {"show", `showing`}, {"show", `^^show$`}, {"show", `(show .*)`}, {"show", `show`},
		{"show", `shows`}, {"show", `show(x)`}, {"show", `show(?!x)`}, {"show", ``},
	} {
		if CommandMatchIsDead(c[0], c[1]) {
			t.Errorf("%v flagged", c)
		}
	}
}

func TestCommandMatchIsDeadCatchallAndEmpty(t *testing.T) {
	if CommandMatchIsDead("*", `^\* .*$`) {
		t.Error("catchall flagged")
	}
	if CommandMatchIsDead("show", "") {
		t.Error("empty flagged")
	}
}

// bash's [[:space:]] does not count the no-break spaces.
func TestPrivCommandWhitespaceClass(t *testing.T) {
	for _, s := range []string{" show", "show　"} {
		if got := msg(t, ValidatePrivCommandString(s)); !strings.HasPrefix(got, "Privilege command has leading/trailing whitespace") {
			t.Errorf("%q: %q", s, got)
		}
	}
	for _, s := range []string{" show", "show ", "\u0085show"} {
		if got := msg(t, ValidatePrivCommandString(s)); !strings.HasPrefix(got, "Invalid privilege command") {
			t.Errorf("%q: %q", s, got)
		}
	}
}
