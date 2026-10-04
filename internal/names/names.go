// Package names holds tacctl's validators for names and short strings: the
// shape rules of lib/core.sh (validate_class_name, validate_username,
// reject_reserved_username), lib/groups.sh and lib/scopes.sh (group and
// scope names), lib/render_devices.sh (validate_acl_name) and lib/policy.sh
// (validate_priv_command_string, validate_command_name, validate_regex,
// command_match_is_dead), plus the name lists of lib/store.sh.
//
// A validator returns nil, or an *Error carrying the lines the bash printed
// with error() before it exited 1; the caller prints each through
// ui.Output.Error (ui.Output.ErrorLines does it). The messages are
// byte-identical to the bash ones.
package names

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error is a validation failure: one or more error lines, without the
// "[ERROR] " tag.
type Error struct{ Msgs []string }

// Error joins the lines with newlines.
func (e *Error) Error() string { return strings.Join(e.Msgs, "\n") }

// Lines are the messages, one per error() call of the bash.
func (e *Error) Lines() []string { return e.Msgs }

func fail(lines ...string) error { return &Error{Msgs: lines} }

// The name lists of lib/store.sh.
var (
	// KnownProtocols are the protocols a scope's filter may name.
	KnownProtocols = []string{"tacacs", "radius"}
	// KnownVendors are the vendors with a RADIUS privilege attribute, in the
	// order a scope's list is stored.
	KnownVendors = []string{"cisco", "juniper", "wti"}
	// ReservedUsers collide with the service user and cannot be managed.
	ReservedUsers = []string{"tacquito"}
	// SinkUsers exist only as accounting sinks.
	SinkUsers = []string{"root"}
)

var (
	reUser  = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	reGroup = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	reScope = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)
	reClass = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reACL   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	reCmd   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	rePriv  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9 _-]+$`)
)

// The patterns are ASCII-only, as the store's Python validators are. Bash's
// [a-z] ranges follow the locale's collation, so under en_US.UTF-8 'jos\u00e9'
// passed the shell check and was then refused by the store; here it is refused
// at once.

// MatchUser reports whether s has the shape of a username: letters, digits,
// '_' and '-'. This is the store's RE_USER; reserved names are separate.
func MatchUser(s string) bool { return reUser.MatchString(s) }

// MatchGroup reports whether s is a group name: lower case, starting with a
// letter (the store's RE_GROUP).
func MatchGroup(s string) bool { return reGroup.MatchString(s) }

// MatchScope reports whether s is a scope name: a letter, then up to 31
// letters, digits, '_' or '-' (RE_SCOPE).
func MatchScope(s string) bool { return reScope.MatchString(s) }

// MatchClass reports whether s is a Juniper class name (RE_CLASS, the same
// shape as a username).
func MatchClass(s string) bool { return reClass.MatchString(s) }

// ValidateClassName is validate_class_name.
func ValidateClassName(value string) error {
	if !reClass.MatchString(value) {
		return fail(fmt.Sprintf("Invalid name '%s'. Only letters, numbers, underscores, and hyphens are allowed.", value))
	}
	return nil
}

// ValidateUsername is validate_username: shape only. See
// RejectReservedUsername for the creation-path check.
func ValidateUsername(value string) error {
	if !reUser.MatchString(value) {
		return fail("Username must contain only letters, numbers, underscores, and hyphens.")
	}
	return nil
}

// RejectReservedUsername is reject_reserved_username: 'root' is the
// accounting-only sink for Junos internal daemons and 'tacquito' the service
// user. It lives on the creation path only, so 'user remove root' can still
// reach a legacy entry.
func RejectReservedUsername(value string) error {
	switch value {
	case "root":
		return fail(
			"Username 'root' is reserved as an accounting-only sink for Junos internal daemons (non-tty CLI as root).",
			"The hash stays disabled permanently — root must only be used for local/console login, never TACACS+ or RADIUS.",
			"Create an operator-specific account instead (e.g. tacctl user add jsmith <group>).",
		)
	case "tacquito":
		return fail("Username 'tacquito' is reserved (matches the service user). Pick a different name.")
	}
	return nil
}

// ValidateGroupName is the group-name check of 'group add'.
func ValidateGroupName(value string) error {
	if !reGroup.MatchString(value) {
		return fail("Group name must be lowercase, starting with a letter.")
	}
	return nil
}

// ValidateScopeName is the scope-name check of 'scope add'.
func ValidateScopeName(value string) error {
	if !reScope.MatchString(value) {
		return fail(fmt.Sprintf("Invalid scope name '%s'. Use letters/digits/_-, starting with a letter.", value))
	}
	return nil
}

// ValidateACLName is validate_acl_name: letters, digits, '_' and '-',
// starting with a letter, at most 63 characters (IOS and Junos limits).
func ValidateACLName(name string) error {
	if name == "" {
		return fail("ACL name must not be empty.")
	}
	if n := utf8.RuneCountInString(name); n > 63 {
		return fail(fmt.Sprintf("ACL name too long (%d chars; max 63).", n))
	}
	if !reACL.MatchString(name) {
		return fail(fmt.Sprintf("Invalid ACL name '%s'. Must start with a letter and contain only letters, digits, '_', '-'.", name))
	}
	return nil
}

// ValidateCommandName is validate_command_name: '*' (the catchall) or a
// literal TACACS+ cmd token.
func ValidateCommandName(name string) error {
	if name == "*" || reCmd.MatchString(name) {
		return nil
	}
	return fail(
		fmt.Sprintf("Invalid command name '%s'.", name),
		"Use a literal cmd token (e.g. 'show', 'configure') or '*' for the catchall.",
	)
}

// ValidatePrivCommandString is validate_priv_command_string: a Cisco
// privilege-exec command path ("show running-config"): letters, digits,
// spaces, '-' and '_', starting with a letter, no leading or trailing
// whitespace, at most 64 characters.
func ValidatePrivCommandString(cmd string) error {
	if cmd == "" {
		return fail("Privilege command must not be empty.")
	}
	first, _ := utf8.DecodeRuneInString(cmd)
	last, _ := utf8.DecodeLastRuneInString(cmd)
	if isShellSpace(first) || isShellSpace(last) {
		return fail(fmt.Sprintf("Privilege command has leading/trailing whitespace: '%s'", cmd))
	}
	if !rePriv.MatchString(cmd) {
		return fail(
			fmt.Sprintf("Invalid privilege command '%s'.", cmd),
			"Use letters, digits, spaces, '-', '_' (e.g. 'show running-config', 'terminal monitor').",
		)
	}
	if n := utf8.RuneCountInString(cmd); n > 64 {
		return fail(fmt.Sprintf("Privilege command too long (%d chars; max 64).", n))
	}
	return nil
}

// ValidateRegex is validate_regex, gating a --match value. tacquito
// compiles the pattern with Go's regexp (RE2), so that is what is checked;
// bash asked Python's re.compile, which also accepts lookarounds and
// backreferences that tacquito cannot load.
func ValidateRegex(pattern string) error {
	if _, err := regexp.Compile(pattern); err != nil {
		return fail(fmt.Sprintf("Invalid regex: '%s'", pattern))
	}
	return nil
}

// isShellSpace is [[:space:]] in a UTF-8 locale (glibc's iswspace): the
// Unicode spaces except the no-break ones (U+0085, U+00A0, U+2007, U+202F).
func isShellSpace(r rune) bool {
	switch r {
	case 0x85, 0xa0, 0x2007, 0x202f:
		return false
	}
	return unicode.IsSpace(r)
}

// isPySpace is what Python's \s matches in a str pattern: str.isspace().
func isPySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// CommandMatchIsDead is command_match_is_dead: true when a command rule's
// match regex can never match. tacquito tests 'match' against the command's
// arguments only, so a regex that begins with the command word itself
// ('^show .*$', '^ping( .*)?$', '^show$') never matches and the rule is dead.
// The catchall '*' is never dead.
func CommandMatchIsDead(name, rx string) bool {
	if name == "*" {
		return false
	}
	body := strings.TrimPrefix(rx, "^")
	if !strings.HasPrefix(body, name) {
		return false
	}
	t := body[len(name):]
	// re.escape(name) + (?:\s|\\s|\$|\((?:\?:)?(?:\s|\\s))
	startsSpace := func(s string) bool {
		r, _ := utf8.DecodeRuneInString(s)
		return s != "" && (isPySpace(r) || strings.HasPrefix(s, `\s`))
	}
	switch {
	case startsSpace(t), strings.HasPrefix(t, "$"):
		return true
	case strings.HasPrefix(t, "("):
		u := t[1:]
		return startsSpace(u) || (strings.HasPrefix(u, "?:") && startsSpace(u[2:]))
	}
	return false
}
