package names

import (
	"strings"
	"unicode"
)

// EmailMax is the longest address a user may hold (the SMTP path limit).
const EmailMax = 254

// EmailClear is the word of 'user email <name> clear'. It has no '@', so it
// is never an address.
const EmailClear = "clear"

// EmailRefusal is the refusal of a value that is not a plain address. It
// does not repeat the value: an address is never written to a log, an audit
// line or an error message.
const EmailRefusal = "Not a plain email address: write local@domain (for example alice@example.net), at most 254 characters, with no spaces, angle brackets or quotes."

// MatchEmail reports whether s is a plain address (users.<name>.email): one
// '@', a non-empty local part, and a domain of at least two dot-separated
// labels none of which is empty; at most EmailMax bytes, with no white
// space, control or other non-printable character (a zero-width space and a
// right-to-left override included, which would make two addresses look the
// same), angle bracket or quote, and a local part that does not start with
// '-' (a word of that shape is an option). The address is kept as typed: the
// check does not change its case.
func MatchEmail(s string) bool {
	if s == "" || len(s) > EmailMax || s[0] == '-' || strings.Count(s, "@") != 1 {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) || strings.ContainsRune("<>\"'", r) {
			return false
		}
	}
	local, domain, _ := strings.Cut(s, "@")
	if local == "" || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return false
		}
	}
	return true
}

// ValidateEmail is the check of an address a verb takes: nil, or the
// refusal EmailRefusal.
func ValidateEmail(value string) error {
	if !MatchEmail(value) {
		return fail(EmailRefusal)
	}
	return nil
}

// EmailKey is the form in which two addresses are compared: an address
// belongs to one user, with no regard to case.
func EmailKey(s string) string { return strings.ToLower(s) }

// SameEmail reports whether two addresses are the same address.
func SameEmail(a, b string) bool { return EmailKey(a) == EmailKey(b) }
