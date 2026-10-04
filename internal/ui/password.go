package ui

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/hash"
)

// weakExact and weakPrefix are the case patterns of validate_password_strength
// (lib/users.sh), matched against the lower-cased password: the words
// that dominate breach corpora, not a dictionary check.
var (
	weakExact = []string{
		"admin", "administrator", "root", "password", "password1", "passw0rd",
		"tacacs", "tacacs+", "tacplus", "tacquito",
		"cisco", "cisco123", "juniper", "juniper1",
		"changeme", "welcome", "welcome1", "letmein",
	}
	// A password that starts with one of these ('qwerty*' ...) is weak.
	weakPrefix = []string{"qwerty", "abc123", "12345", "00000", "aaaaaa"}
)

// PasswordStrength is validate_password_strength: nil, or an error whose
// text is the message the bash printed. The checks run in the bash's order:
// length in characters against minLength (the 'password.min_length'
// setting), the common-weak list (case-insensitive), equality with username
// (case-insensitive; skipped when username is empty); then the 72-byte limit
// of bcrypt (hash.ErrPasswordTooLong), which is new in 0.2.0. Auto-generated
// passwords bypass all of this.
func PasswordStrength(password, username string, minLength int) error {
	if n := utf8.RuneCountInString(password); n < minLength {
		return weakError(fmt.Sprintf("Password is %d characters; minimum is %d.", n, minLength))
	}
	lower := strings.Map(unicode.ToLower, password)
	weak := false
	for _, w := range weakExact {
		weak = weak || lower == w
	}
	for _, p := range weakPrefix {
		weak = weak || strings.HasPrefix(lower, p)
	}
	if weak {
		return weakError("Password is on the common-weak list. Choose another.")
	}
	if username != "" && lower == strings.Map(unicode.ToLower, username) {
		return weakError("Password must not equal the username.")
	}
	if len(password) > hash.MaxPasswordBytes {
		return hash.ErrPasswordTooLong
	}
	return nil
}

// weakError carries a message that starts with a capital, as the bash's do
// (staticcheck's capitalised-error rule does not apply to text printed after
// "[ERROR] ").
type weakError string

func (e weakError) Error() string { return string(e) }

// RandomBase64 is 'openssl rand -base64 <n>' without the line wrapping: n
// random bytes from r (crypto/rand.Reader in production; tests inject a
// reader), standard base64 with padding.
func RandomBase64(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GeneratePassword is the auto-generated password of prompt_password:
// 'openssl rand -base64 18', 24 characters. A nil reader means crypto/rand.
func GeneratePassword(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	return RandomBase64(r, 18)
}
