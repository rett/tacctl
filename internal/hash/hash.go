// Package hash is tacctl's password-hash handling: the bcrypt generate,
// verify and normalise operations of lib/users.sh (generate_hash,
// verify_hash, normalize_bcrypt_hash, is_disabled_hash, DISABLED_MARKER_HEX)
// and the 'Hash type' display of lib/model.sh.
//
// Hashes are stored and passed around hex-encoded (the form tacquito reads);
// "raw" means the '$2b$12$...' text. Generation uses golang.org/x/crypto/
// bcrypt and rewrites its '$2a$' prefix to '$2b$', the prefix python-bcrypt
// (and so tacctl 0.1.x) produced; '$2a$', '$2b$' and '$2y$' denote the same
// algorithm for the passwords tacctl accepts (docs/plans/go-rewrite.md 3.4).
package hash

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the longest password bcrypt reads. python-bcrypt
// truncated a longer one silently; tacctl 0.2.0 refuses it (docs/plans/
// go-rewrite.md 3.9 item 10).
const MaxPasswordBytes = 72

// ErrPasswordTooLong is the refusal for a password over MaxPasswordBytes.
var ErrPasswordTooLong error = tooLongError{}

type tooLongError struct{}

// Error is a sentence, capitalised like the other messages tacctl prints
// after "[ERROR] ".
func (tooLongError) Error() string {
	return "Password is longer than 72 bytes; bcrypt would ignore the rest. Choose a shorter one."
}

// Cost limits the bcrypt library accepts (the tacctl range 10..14 is the
// configuration's business, bcrypt.cost in tacctl.yaml).
const (
	MinCost = bcrypt.MinCost
	MaxCost = bcrypt.MaxCost
)

// The disabled-user marker: a well-formed but unverifiable bcrypt hash,
// '$2b$12$' followed by 53 '.' (all-zero salt and digest). Stored
// hex-encoded.
const (
	DisabledMarkerRaw = "$2b$12$" + "....................................................."
	DisabledMarkerHex = "24326224313224" +
		"2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e" +
		"2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
)

// IsDisabled is is_disabled_hash: true only for the marker itself, in the
// exact (lower-case hex) form.
func IsDisabled(hexHash string) bool { return hexHash == DisabledMarkerHex }

// Generate is generate_hash: the hex-encoded bcrypt hash of password at the
// given cost, with the '$2b$' prefix. A password over MaxPasswordBytes is
// ErrPasswordTooLong; a cost outside MinCost..MaxCost is an error (the
// library would silently substitute its default for a low one).
func Generate(password string, cost int) (string, error) {
	raw, err := GenerateRaw(password, cost)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString([]byte(raw)), nil
}

// GenerateRaw is Generate without the hex encoding ('$2b$12$...').
func GenerateRaw(password string, cost int) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if cost < MinCost || cost > MaxCost {
		return "", fmt.Errorf("bcrypt cost %d is outside %d..%d", cost, MinCost, MaxCost)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	s := string(h)
	if !strings.HasPrefix(s, "$2a$") {
		return "", fmt.Errorf("bcrypt produced an unexpected hash prefix %q", s[:4])
	}
	return "$2b$" + s[4:], nil
}

// Result is what verify_hash prints.
type Result string

// The three answers of verify_hash.
const (
	Match       Result = "MATCH"
	NoMatch     Result = "NO_MATCH"
	InvalidHash Result = "INVALID_HASH"
)

// Verify is verify_hash, classified as python-bcrypt 3.2.2's checkpw
// does, with the hashing itself done by golang.org/x/crypto/bcrypt:
//
//   - INVALID_HASH (checkpw raises ValueError) when hexHash is not hex, or
//     its text does not start with a salt bcrypt_hashpass accepts ('$2a$',
//     '$2b$' or '$2y$', a cost of 04 to 31, then 22 characters of bcrypt's
//     alphabet);
//   - NO_MATCH when it does, but hashpw(password, h) cannot equal h: the text
//     is not exactly 60 characters (truncated, or with a tail), or its salt
//     is not in the canonical form hashpw writes back;
//   - otherwise MATCH or NO_MATCH as bcrypt.CompareHashAndPassword says.
//
// Only the first 72 bytes of password count, as in python-bcrypt, so a hash
// made from a longer password by tacctl 0.1.x still verifies.
func Verify(password, hexHash string) Result {
	h, err := hex.DecodeString(hexHash)
	if err != nil {
		return InvalidHash
	}
	salt, ok := parseSalt(h)
	if !ok {
		return InvalidHash
	}
	if len(h) != rawHashLen || bcryptB64.EncodeToString(salt) != string(h[7:7+saltChars]) {
		return NoMatch
	}
	pw := []byte(password)
	if len(pw) > MaxPasswordBytes {
		pw = pw[:MaxPasswordBytes]
	}
	switch err := bcrypt.CompareHashAndPassword(h, pw); {
	case err == nil:
		return Match
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return NoMatch
	}
	return InvalidHash
}

const (
	rawHashLen = 60 // '$2b$12$' + 22 salt + 31 hash characters
	saltChars  = 22
	saltBytes  = 16
	// bcryptAlphabet is bcrypt's base64 alphabet.
	bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// bcryptB64 is bcrypt's base64: its own alphabet, no padding.
var bcryptB64 = base64.NewEncoding(bcryptAlphabet).WithPadding(base64.NoPadding)

// parseSalt is the salt check of bcrypt_hashpass (the OpenBSD code inside
// python-bcrypt): '$2' and a minor version a, b or y, '$', two digits of a
// cost from 4 to 31, '$', then 22 characters of bcrypt's alphabet, which
// decode to the 16 salt bytes.
func parseSalt(h []byte) (salt []byte, ok bool) {
	if len(h) < 7 || h[0] != '$' || h[1] != '2' || (h[2] != 'a' && h[2] != 'b' && h[2] != 'y') || h[3] != '$' {
		return nil, false
	}
	if h[4] < '0' || h[4] > '9' || h[5] < '0' || h[5] > '9' || h[6] != '$' {
		return nil, false
	}
	if cost := int(h[4]-'0')*10 + int(h[5]-'0'); cost < MinCost || cost > 31 {
		return nil, false
	}
	rest := h[7:]
	if len(rest) < saltChars {
		return nil, false
	}
	for _, c := range rest[:saltChars] {
		if !strings.ContainsRune(bcryptAlphabet, rune(c)) { // the decoder would skip \r and \n
			return nil, false
		}
	}
	salt, err := bcryptB64.DecodeString(string(rest[:saltChars]))
	if err != nil || len(salt) != saltBytes {
		return nil, false
	}
	return salt, true
}

// hasRawPrefix is re.match(r'^\$2[aby]\$', s).
func hasRawPrefix(s string) bool {
	return len(s) >= 4 && s[0] == '$' && s[1] == '2' && (s[2] == 'a' || s[2] == 'b' || s[2] == 'y') && s[3] == '$'
}

// Normalize is normalize_bcrypt_hash: a raw hash ('$2a$', '$2b$', '$2y$'
// prefix, nothing else is checked) becomes its lower-case hex; a hex string
// that decodes to ASCII beginning with one of those prefixes comes back
// lower-cased; anything else is rejected (ok false). The input is not
// trimmed.
func Normalize(input string) (hexHash string, ok bool) {
	if hasRawPrefix(input) {
		return hex.EncodeToString([]byte(input)), true
	}
	dec, err := hex.DecodeString(input)
	if err != nil {
		return "", false
	}
	for _, b := range dec {
		if b >= 0x80 {
			return "", false
		}
	}
	if !hasRawPrefix(string(dec)) {
		return "", false
	}
	return strings.ToLower(input), true
}

// TypePrefix is the 'Hash type' shown by 'user show': the first seven
// characters of the decoded hash ('$2b$12$'), or "" when they do not decode
// to ASCII (lib/model.sh user-info). Callers pass "" for a disabled user.
func TypePrefix(hexHash string) string {
	if len(hexHash) > 14 {
		hexHash = hexHash[:14]
	}
	b, err := hex.DecodeString(hexHash)
	if err != nil {
		return ""
	}
	for _, c := range b {
		if c >= 0x80 {
			return ""
		}
	}
	return string(b)
}
