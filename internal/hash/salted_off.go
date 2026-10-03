//go:build !testknobs

package hash

import "errors"

// SaltFromReader reports whether GenerateWith takes its salt from the
// reader it is given: only in a -tags testknobs build.
const SaltFromReader = false

// saltedRaw is never reached in a production build (GenerateRawWith calls
// it only when SaltFromReader is true): there is no hand-made bcrypt here.
func saltedRaw([]byte, int, []byte) (string, error) {
	return "", errors.New("hash: a caller-supplied salt needs a -tags testknobs build")
}
