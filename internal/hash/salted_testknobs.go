//go:build testknobs

package hash

import (
	"fmt"

	// bcrypt is EksBlowfish: x/crypto/bcrypt itself is built on this
	// package (deprecated for new ciphers, not for bcrypt).
	"golang.org/x/crypto/blowfish" //nolint:staticcheck // SA1019: see above
)

// SaltFromReader reports whether GenerateWith takes its salt from the
// reader it is given: in this -tags testknobs build it does.
const SaltFromReader = true

// cryptedBytes: only 23 of the 24 encrypted bytes are encoded (C bcrypt).
const cryptedBytes = 23

// orpheus is "OrpheanBeholderScryDoubt", the text bcrypt encrypts.
var orpheus = []byte("OrpheanBeholderScryDoubt")

// saltedRaw is the bcrypt algorithm (EksBlowfishSetup, then 64
// encryptions of the magic text) with a given 16-byte salt, as
// golang.org/x/crypto/bcrypt computes it internally; the result is
// '$2b$<cost>$<22 salt chars><31 hash chars>'. Test builds only: it exists
// so that the differential runner can fix the salt.
func saltedRaw(password []byte, cost int, salt []byte) (string, error) {
	// The C implementations hash the key with its terminating NUL.
	key := append(append([]byte(nil), password...), 0)
	c, err := blowfish.NewSaltedCipher(key, salt)
	if err != nil {
		return "", err
	}
	for i := uint64(0); i < 1<<uint(cost); i++ {
		blowfish.ExpandKey(key, c)
		blowfish.ExpandKey(salt, c)
	}
	data := append([]byte(nil), orpheus...)
	for i := 0; i < len(data); i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(data[i:i+8], data[i:i+8])
		}
	}
	return fmt.Sprintf("$2b$%02d$%s%s", cost, bcryptB64.EncodeToString(salt), bcryptB64.EncodeToString(data[:cryptedBytes])), nil
}
