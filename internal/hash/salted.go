package hash

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateWith is Generate with the salt drawn from rng, for the
// differential runner: with TACCTL_TEST_RANDOM set, python-bcrypt's
// os.urandom on the bash side answers the same 16 bytes, and the two
// implementations produce the very same hash.
//
// Only a binary built with -tags testknobs honours a test reader (the hash
// is then computed by salted_testknobs.go, which contains the one hand-made
// bcrypt of this tree). A production build ignores rng and always salts
// from crypto/rand through golang.org/x/crypto/bcrypt (salted_off.go): a
// production binary has no test knobs, so its reader is crypto/rand anyway.
// A nil rng, or crypto/rand.Reader itself, is Generate in either build.
func GenerateWith(password string, cost int, rng io.Reader) (string, error) {
	raw, err := GenerateRawWith(password, cost, rng)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString([]byte(raw)), nil
}

// GenerateRawWith is GenerateWith without the hex encoding.
func GenerateRawWith(password string, cost int, rng io.Reader) (string, error) {
	if rng == nil || rng == rand.Reader || !SaltFromReader {
		return GenerateRaw(password, cost)
	}
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if cost < MinCost || cost > MaxCost {
		return "", fmt.Errorf("bcrypt cost %d is outside %d..%d", cost, MinCost, MaxCost)
	}
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rng, salt); err != nil {
		return "", err
	}
	return saltedRaw([]byte(password), cost, salt)
}
