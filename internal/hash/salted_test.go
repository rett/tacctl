package hash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// seeded is the differential runner's TACCTL_TEST_RANDOM.
func seeded() *bytes.Reader {
	b, _ := hex.DecodeString("a1b2c3d4e5f60718293a4b5c6d7e8f90")
	return bytes.NewReader(b)
}

// pythonVectors are python-bcrypt 3.2.2 with os.urandom answering the seed
// bytes: bcrypt.hashpw(pw, bcrypt.gensalt(rounds=cost)).
var pythonVectors = []struct {
	pw   string
	cost int
	want string
}{
	{"CorrectHorse99", 10, "$2b$10$mZJBzMV0/venMiraZV4Ni.v/jcP7fWpKo.C.wWq.v4.8vOtwwQYBK"},
	{strings.Repeat("x", 72), 4, "$2b$04$mZJBzMV0/venMiraZV4Ni.0.qwv0ZeEo6Wz093W1r4.yC3bsOws7C"},
	{"", 4, "$2b$04$mZJBzMV0/venMiraZV4Ni.EGBIs1it8ix1VCZMgfaUvPJiZlYkGWi"},
	{"pässwörd€", 5, "$2b$05$mZJBzMV0/venMiraZV4Ni.NEJPNsSUpYiOuY44IC3LuOEMw8Wj5li"},
}

// A -tags testknobs build salts from the reader and reproduces the python
// hashes; a production build ignores the reader (crypto/rand salt).
func TestGenerateWithMatchesPythonBcrypt(t *testing.T) {
	for _, c := range pythonVectors {
		got, err := GenerateRawWith(c.pw, c.cost, seeded())
		if err != nil {
			t.Fatalf("%q: %v", c.pw, err)
		}
		if SaltFromReader != (got == c.want) {
			t.Errorf("%q cost %d (salt from reader: %v): %q, python %q", c.pw, c.cost, SaltFromReader, got, c.want)
		}
		if Verify(c.pw, hex.EncodeToString([]byte(got))) != Match {
			t.Errorf("%q: own hash does not verify", c.pw)
		}
		h, err := GenerateWith(c.pw, c.cost, seeded())
		if err != nil || (SaltFromReader && h != hex.EncodeToString([]byte(c.want))) {
			t.Errorf("%q hex: %q %v", c.pw, h, err)
		}
	}
}

// Verify (x/crypto underneath, in every build) accepts the python hashes,
// under each prefix python accepts, and classifies a non-canonical salt as
// python does (hashpw writes the salt back canonically: no match).
func TestVerifyPythonVectors(t *testing.T) {
	for _, c := range pythonVectors {
		for _, prefix := range []string{"$2b$", "$2a$", "$2y$"} {
			h := hex.EncodeToString([]byte(prefix + c.want[4:]))
			if got := Verify(c.pw, h); got != Match {
				t.Errorf("%q %s: %s", c.pw, prefix, got)
			}
			if got := Verify(c.pw+"x", h); c.pw != strings.Repeat("x", 72) && got != NoMatch {
				t.Errorf("%q %s wrong password: %s", c.pw, prefix, got)
			}
		}
	}
	h := pythonVectors[0].want
	for _, salt22 := range []string{"/", "O"} {
		if got := Verify("CorrectHorse99", hex.EncodeToString([]byte(h[:28]+salt22+h[29:]))); got != NoMatch {
			t.Errorf("salt end %q: %s, python says NO_MATCH", salt22, got)
		}
	}
}

// The library verifies what the salted path computes, for every cost a
// test can afford.
func TestGenerateWithVerifiesWithTheLibrary(t *testing.T) {
	for cost := MinCost; cost <= 8; cost++ {
		raw, err := GenerateRawWith("some password", cost, seeded())
		if err != nil {
			t.Fatal(err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(raw), []byte("some password")); err != nil {
			t.Errorf("cost %d: %v", cost, err)
		}
	}
}

func TestGenerateWithRefusals(t *testing.T) {
	if _, err := GenerateWith(strings.Repeat("x", 73), 10, seeded()); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("73 bytes: %v", err)
	}
	if _, err := GenerateWith("pw", 3, seeded()); err == nil {
		t.Error("cost 3 accepted")
	}
	if _, err := GenerateWith("pw", 4, bytes.NewReader([]byte{1, 2})); SaltFromReader && err == nil {
		t.Error("short random source accepted")
	}
}

// Without a test source the library draws the salt: two hashes differ.
func TestGenerateWithRealRandom(t *testing.T) {
	for _, rng := range []io.Reader{nil, rand.Reader} {
		a, err1 := GenerateRawWith("CorrectHorse99", 4, rng)
		b, err2 := GenerateRawWith("CorrectHorse99", 4, rng)
		if err1 != nil || err2 != nil || a == b || !strings.HasPrefix(a, "$2b$04$") {
			t.Errorf("%v: %q %q %v %v", rng, a, b, err1, err2)
		}
	}
}
