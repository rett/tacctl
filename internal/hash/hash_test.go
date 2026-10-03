package hash

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Cost 4 keeps the race-enabled run short; cost 10 and 12 each appear once.
const (
	// Made-up passwords with hashes python-bcrypt 3.2.2 generated (the hash
	// the bash implementation stores); Verify must accept them.
	interopPW    = "Interop-Test-Passphrase-7"
	interopRaw10 = "$2b$10$pFQ6Ny7gWDP7oth6qL0M6.q58AgpTA0FUvQes4NY9xnwiTJbTFngW"
	interopRaw12 = "$2b$12$ANFhWe21W4oEc.oo3OBCNeFvHwvmjoZ9reHfwmmQS.iKG.i9V6IqS"
	interopRaw04 = "$2b$04$wmsYM.dSO/NstqLH6NuaR.fNFIG3v6tFrmsgMLFimZHn1/4VSM1sa"
	interopRaw2a = "$2a$04$wmsYM.dSO/NstqLH6NuaR.fNFIG3v6tFrmsgMLFimZHn1/4VSM1sa" // the same hash under the other prefixes
	interopRaw2y = "$2y$04$wmsYM.dSO/NstqLH6NuaR.fNFIG3v6tFrmsgMLFimZHn1/4VSM1sa"
	longRaw      = "$2b$04$w2N6V0k.ahObtwJKIWqJg.u4Fu7OqOvbWlHHdjU9zBU4lwuSASCjy" // python hash of 80 x's
	emptyPWRaw   = "$2b$04$IcW57BIm26k6IHZPQvOivuYD5sijidYiIJHroMJRIdZ9a.E4u3LT."

	goodPassword   = "Correct-Horse-Battery-Staple-42"
	lowestTestCost = 10
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

// --- generate_hash ---

func TestGenerateIsHexBcryptAt2bAndCost(t *testing.T) {
	h, err := Generate(goodPassword, lowestTestCost)
	if err != nil {
		t.Fatal(err)
	}
	if h == "" || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("not lower-case hex: %q", h)
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "$2b$10$") || len(raw) != 60 {
		t.Errorf("decoded = %q", raw)
	}
}

func TestGeneratedHashVerifies(t *testing.T) {
	h, err := Generate(goodPassword, 4)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(goodPassword, h) != Match || Verify(goodPassword+"x", h) != NoMatch {
		t.Error("a generated hash must verify its password and nothing else")
	}
	raw, _ := GenerateRaw("", 4)
	if Verify("", hx(raw)) != Match || Verify("not-empty", hx(raw)) != NoMatch {
		t.Error("the empty password must work and must not match others")
	}
}

func TestGenerateRawPrefixPerCost(t *testing.T) {
	for cost, want := range map[int]string{4: "$2b$04$", 5: "$2b$05$", 6: "$2b$06$"} {
		raw, err := GenerateRaw("pw", cost)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(raw, want) || len(raw) != 60 {
			t.Errorf("cost %d: %q does not start with %q", cost, raw, want)
		}
	}
}

func TestGenerateSaltsDiffer(t *testing.T) {
	a, _ := Generate("same", 4)
	b, _ := Generate("same", 4)
	if a == b {
		t.Error("two hashes of one password are identical")
	}
}

func TestGenerateRefusesBadCost(t *testing.T) {
	for _, c := range []int{-1, 0, 3, 32} {
		if _, err := Generate("pw", c); err == nil {
			t.Errorf("cost %d accepted", c)
		}
	}
}

// §3.9 item 10: a password over 72 bytes is refused, 72 is the limit.
func TestGenerateRefusesOver72Bytes(t *testing.T) {
	if _, err := Generate(strings.Repeat("x", 73), 4); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("73 bytes: err = %v", err)
	}
	if _, err := Generate(strings.Repeat("x", 72), 4); err != nil {
		t.Errorf("72 bytes: %v", err)
	}
	// Bytes, not characters: 37 two-byte characters are 74 bytes.
	if _, err := Generate(strings.Repeat("é", 37), 4); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("37 x é: err = %v", err)
	}
	want := "Password is longer than 72 bytes; bcrypt would ignore the rest. Choose a shorter one."
	if ErrPasswordTooLong.Error() != want {
		t.Errorf("message = %q", ErrPasswordTooLong)
	}
}

// --- verify_hash, interop with python-bcrypt ---

func TestVerifyPythonGeneratedHashes(t *testing.T) {
	if got := Verify(interopPW, hx(interopRaw10)); got != Match {
		t.Errorf("cost 10: Verify = %s", got)
	}
	if got := Verify(interopPW, hx(interopRaw12)); got != Match {
		t.Errorf("cost 12: Verify = %s", got)
	}
	for name, raw := range map[string]string{"2b": interopRaw04, "2a": interopRaw2a, "2y": interopRaw2y} {
		if got := Verify(interopPW, hx(raw)); got != Match {
			t.Errorf("%s: Verify = %s", name, got)
		}
		if got := Verify(interopPW+"x", hx(raw)); got != NoMatch {
			t.Errorf("%s wrong password: Verify = %s", name, got)
		}
	}
	// Upper-case hex is accepted, as binascii.unhexlify accepts it.
	if got := Verify(interopPW, strings.ToUpper(hx(interopRaw04))); got != Match {
		t.Errorf("upper-case hex: %s", got)
	}
}

func TestVerifyDoesNotTreatEveryInputAsEmpty(t *testing.T) {
	if got := Verify("not-empty", hx(emptyPWRaw)); got != NoMatch {
		t.Errorf("= %s", got)
	}
	if got := Verify("", hx(emptyPWRaw)); got != Match {
		t.Errorf("empty password = %s", got)
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	tooShort := interopRaw04[:28] // 21 salt characters
	for name, in := range map[string]string{
		"not hex":         "not-hex",
		"empty":           "",
		"odd length":      hx(interopRaw04) + "0",
		"newline":         hx(interopRaw04) + "\n",
		"raw not hex":     interopRaw04,
		"prefix 2x":       hx("$2x$" + interopRaw04[4:]),
		"cost 03":         hx("$2b$03$" + interopRaw04[7:]),
		"cost 32":         hx("$2b$32$" + interopRaw04[7:]),
		"too short":       hx(tooShort),
		"just a prefix":   hx("$2b$"),
		"three bytes":     hx("$2b"),
		"bad salt char":   hx("$2b$04$!" + interopRaw04[8:]),
		"newline in salt": hx("$2b$04$\n" + interopRaw04[8:]),
		"not bcrypt":      hx("hello world, this is not a hash at all, not even close!!"),
	} {
		if got := Verify(interopPW, in); got != InvalidHash {
			t.Errorf("%s: Verify = %s, want INVALID_HASH", name, got)
		}
	}
}

// python-bcrypt answers NO_MATCH, not an error, for a hash with a bad tail
// or extra characters.
func TestVerifyMalformedTailsAreNoMatch(t *testing.T) {
	for name, raw := range map[string]string{
		"trailing garbage": interopRaw04 + "X",
		"bad last char":    interopRaw04[:59] + "!",
		"59 characters":    interopRaw04[:59],
		// checkpw compares the whole text: a short one is no match.
		"58 characters":   interopRaw04[:58],
		"salt only":       interopRaw04[:29],
		"the corpus hash": "$2b$10$" + strings.Repeat("a", 48),
	} {
		if got := Verify(interopPW, hx(raw)); got != NoMatch {
			t.Errorf("%s: Verify = %s, want NO_MATCH", name, got)
		}
	}
}

// python-bcrypt truncates at 72 bytes, so a hash made from a longer password
// by 0.1.x verifies against the first 72 bytes.
func TestVerifyTruncatesAt72LikePython(t *testing.T) {
	long := strings.Repeat("x", 80)
	if got := Verify(long, hx(longRaw)); got != Match {
		t.Errorf("80 x's: %s", got)
	}
	if got := Verify(strings.Repeat("x", 72), hx(longRaw)); got != Match {
		t.Errorf("72 x's: %s", got)
	}
	if got := Verify(strings.Repeat("x", 71), hx(longRaw)); got != NoMatch {
		t.Errorf("71 x's: %s", got)
	}
}

func TestVerifyDisabledMarkerNeverMatches(t *testing.T) {
	for _, pw := range []string{"........"} {
		if got := Verify(pw, DisabledMarkerHex); got != NoMatch {
			t.Errorf("Verify(%q, marker) = %s", pw, got)
		}
	}
}

// --- normalize_bcrypt_hash ---

func TestNormalizeRawToHex(t *testing.T) {
	raw := "$2b$10$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got, ok := Normalize(raw)
	if !ok || got != hx(raw) {
		t.Errorf("= %q, %v", got, ok)
	}
	for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
		if _, ok := Normalize(p + "whatever"); !ok {
			t.Errorf("%s prefix rejected", p)
		}
	}
	// Only the prefix is checked, as the bash does.
	if got, ok := Normalize("$2b$"); !ok || got != hx("$2b$") {
		t.Errorf("bare prefix: %q %v", got, ok)
	}
}

func TestNormalizeHexStaysHexLowercased(t *testing.T) {
	h := hx("$2b$10$" + strings.Repeat(".", 53))
	if got, ok := Normalize(h); !ok || got != h {
		t.Errorf("lower: %q %v", got, ok)
	}
	if got, ok := Normalize(strings.ToUpper(h)); !ok || got != h {
		t.Errorf("upper: %q %v", got, ok)
	}
}

func TestNormalizeRejects(t *testing.T) {
	for _, in := range []string{
		"not-a-hash", "", "$2c$10$xxxx", "$2$10$xxxx", "$3b$10$x",
		hx("hello"),       // hex of something else
		hx("$2x$10$xxxx"), // wrong prefix after decoding
		"24326224313024z", // not hex
		"2432622",         // odd length
		hx("$2b$\xe9"),    // decodes to non-ASCII
		" $2b$10$x",       // not trimmed
		" " + hx("$2b$10$x"),
	} {
		if got, ok := Normalize(in); ok || got != "" {
			t.Errorf("Normalize(%q) = %q, %v", in, got, ok)
		}
	}
}

// --- is_disabled_hash and the marker ---

func TestDisabledMarker(t *testing.T) {
	if len(DisabledMarkerRaw) != 60 || !strings.HasPrefix(DisabledMarkerRaw, "$2b$12$") ||
		strings.Trim(DisabledMarkerRaw[7:], ".") != "" {
		t.Errorf("raw marker = %q", DisabledMarkerRaw)
	}
	if DisabledMarkerHex != hx(DisabledMarkerRaw) {
		t.Errorf("hex marker %q != hex of the raw one", DisabledMarkerHex)
	}
	// The hex form python's store.py pins: '24326224313224' + '2e' * 53.
	if DisabledMarkerHex != "24326224313224"+strings.Repeat("2e", 53) {
		t.Error("marker differs from lib/store.sh's DISABLED_MARKER_HEX")
	}
	if got, ok := Normalize(DisabledMarkerHex); !ok || got != DisabledMarkerHex {
		t.Error("the marker must normalise to itself")
	}
}

func TestIsDisabled(t *testing.T) {
	if !IsDisabled(DisabledMarkerHex) {
		t.Error("marker not recognised")
	}
	for _, s := range []string{"", "$2b$12$somehashvalue", "DISABLED", strings.ToUpper(DisabledMarkerHex), DisabledMarkerRaw} {
		if IsDisabled(s) {
			t.Errorf("IsDisabled(%q)", s)
		}
	}
}

// --- hash_type ---

func TestTypePrefix(t *testing.T) {
	for in, want := range map[string]string{
		hx(interopRaw12):  "$2b$12$",
		hx(interopRaw2a):  "$2a$04$",
		DisabledMarkerHex: "$2b$12$",
		"":                "",
		"zz":              "",
		"24326224":        "$2b$",
		"2432622":         "",        // odd length
		"ff326224313224":  "",        // not ASCII
		"243262243132243": "$2b$12$", // only the first 14 characters count
	} {
		if got := TypePrefix(in); got != want {
			t.Errorf("TypePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
