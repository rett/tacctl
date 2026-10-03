package radius

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// reBcryptRaw is the alphabet of a bcrypt hash; nothing in it needs quoting.
// A hash of the wrong length is still written: crypt(3) matches no password
// against it.
var reBcryptRaw = regexp.MustCompile(`^\$2[aby]\$[./A-Za-z0-9$]*$`)

// HashRaw is hash_raw: the stored hex form of a bcrypt hash as the '$2b$..'
// string crypt(3) takes. A value that is not hex, not ASCII, or does not
// have the alphabet of a bcrypt hash is an *Error.
func HashRaw(hexHash string) (string, error) {
	b, err := hex.DecodeString(hexHash)
	if err != nil {
		return "", errorf("a password hash is not hex-encoded bcrypt")
	}
	for _, c := range b {
		if c >= 0x80 {
			return "", errorf("a password hash is not hex-encoded bcrypt")
		}
	}
	raw := string(b)
	if !reBcryptRaw.MatchString(raw) {
		return "", errorf("a password hash holds characters no bcrypt hash has")
	}
	return raw, nil
}

// frDQ is fr_dq: a FreeRADIUS double-quoted string for a value that has no
// '$' to be expanded (backslash and the quote are escaped, nothing else).
func frDQ(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// FRSecret is fr_secret: a shared secret as a FreeRADIUS config string that
// reads back as exactly the secret on 3.0.x and 3.2.x (docs/radius-notes.md).
// Single quotes take everything but a backslash literally (only ' is
// escaped); double quotes take backslash escapes but expand '${...}' and
// '$ENV{...}'. ok is false when neither form is safe: an empty secret, a
// control character or DEL, or a backslash together with a dollar sign.
// Non-ASCII characters are written as they are (UTF-8).
func FRSecret(secret string) (quoted string, ok bool) {
	if secret == "" {
		return "", false
	}
	for _, r := range secret {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	if !strings.Contains(secret, `\`) {
		return "'" + strings.ReplaceAll(secret, "'", `\'`) + "'", true
	}
	if !strings.Contains(secret, "$") {
		return frDQ(secret), true
	}
	return "", false
}
