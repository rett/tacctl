//go:build !testknobs

package hash

import "testing"

// A production build has no hand-made bcrypt: the salted path refuses.
func TestNoSaltedBcryptInProduction(t *testing.T) {
	if SaltFromReader {
		t.Fatal("SaltFromReader in a production build")
	}
	if _, err := saltedRaw([]byte("pw"), 4, make([]byte, 16)); err == nil {
		t.Error("saltedRaw works in a production build")
	}
}
