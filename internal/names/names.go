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
	// reUser: letters, digits, '_' and '-': the name of a new user, which
	// is also its Linux account name on the tacctl server.
	reUser = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	// reExistingUser is reUser with single periods between its runs, the
	// shape 0.2.20 and 0.2.21 accepted. A store written by them can still
	// hold such a name; it is read, shown, renamed from and removed.
	reExistingUser = regexp.MustCompile(`^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$`)
	reGroup        = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	reScope        = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)
	reClass        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reACL          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	reCmd          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	rePriv         = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9 _-]+$`)
)

// The patterns are ASCII-only, as the store's Python validators are. Bash's
// [a-z] ranges follow the locale's collation, so under en_US.UTF-8 'jos\u00e9'
// passed the shell check and was then refused by the store; here it is refused
// at once.

// HasUpper reports whether s has an upper-case letter (ASCII; the name
// patterns admit no other letters).
func HasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// LowerLine is the refusal of a name with upper case: new device, host, user
// and scope names are lower case (0.2.14).
func LowerLine(name string) string {
	return "Names are lower case: use '" + strings.ToLower(name) + "'."
}

// RequireLower is the check every path that creates or renames a device,
// host, user or scope adds to the shape check of its name: nil for a name
// with no upper case, else the refusal, "Names are lower case: use
// '<lowercased>'. Nothing was changed.". The Match functions below do not
// call it: a name that exists with upper case keeps loading and matching.
func RequireLower(name string) error {
	if HasUpper(name) {
		return fail(LowerLine(name) + " Nothing was changed.")
	}
	return nil
}

// MatchUser reports whether s has the shape of a new username: letters,
// digits, '_' and '-'. Reserved names are separate.
func MatchUser(s string) bool { return reUser.MatchString(s) }

// MatchExistingUser reports whether s has the shape of a username that may
// already stand in a store: MatchUser, or the same with single periods
// between the parts (0.2.20 and 0.2.21 allowed them). It is what the store
// and console.yaml accept when they read; a new name is MatchUser.
func MatchExistingUser(s string) bool { return reExistingUser.MatchString(s) }

// MatchGroup reports whether s is a group name: lower case, starting with a
// letter (the store's RE_GROUP).
func MatchGroup(s string) bool { return reGroup.MatchString(s) }

// MatchScope reports whether s is a scope name: a letter, then up to 31
// letters, digits, '_' or '-' (RE_SCOPE).
func MatchScope(s string) bool { return reScope.MatchString(s) }

// MatchClass reports whether s is a Juniper class name (RE_CLASS). It had
// the shape of a username; a class name never held a period.
func MatchClass(s string) bool { return reClass.MatchString(s) }

// ValidateClassName is validate_class_name.
func ValidateClassName(value string) error {
	if !reClass.MatchString(value) {
		return fail(fmt.Sprintf("Invalid name '%s'. Only letters, numbers, underscores, and hyphens are allowed.", value))
	}
	return nil
}

// usernameShape is the refusal of a name that is not letters, digits, '_' and
// '-': it says why a period is not among them.
const usernameShape = "Username must contain only letters, numbers, underscores and hyphens (a period cannot be part of a Linux account name)."

// ValidateUsername is validate_username: the shape of a new name, letters,
// digits, '_' and '-'. See RejectReservedUsername for the creation-path
// check. A command that reads a user that exists uses
// ValidateExistingUsername.
func ValidateUsername(value string) error {
	if !reUser.MatchString(value) {
		return fail(usernameShape)
	}
	return nil
}

// ValidateExistingUsername is the shape check of a command that names a
// user that is already there (show, remove, rename from): a name with
// periods that 0.2.20 or 0.2.21 stored passes, so that it can be shown,
// removed or renamed. Any other bad shape is refused with the same text.
func ValidateExistingUsername(value string) error {
	if !reExistingUser.MatchString(value) {
		return fail(usernameShape)
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

// reServerName: a DNS label that starts with a letter, in lower case: 1 to
// 63 characters, letters, digits and hyphens, not ending in a hyphen.
var reServerName = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ServerNameReserved is the word 'server name' takes to remove the name; it
// cannot be one.
const ServerNameReserved = "unset"

// ServerNameProblem is "" when s can be the name of this server (server.name:
// the name the console prompt and its notices show in place of the host
// name), else why not.
func ServerNameProblem(s string) string {
	switch {
	case s == ServerNameReserved:
		return "is the word that removes the name"
	case HasUpper(s):
		return "has upper case: a server name is lower case"
	case len(s) > 63:
		return "is longer than 63 characters"
	case !reServerName.MatchString(s):
		return "is not a name of letters, digits and hyphens that starts with a letter and does not end in a hyphen"
	}
	return ""
}
