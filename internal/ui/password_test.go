package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// --- tests/unit/hash.bats: validate_password_strength ---

func TestStrengthAcceptsMixedPassword(t *testing.T) {
	if err := PasswordStrength("Correct-Horse-Battery-Staple-42", "", 12); err != nil {
		t.Error(err)
	}
}

func TestStrengthRejectsShort(t *testing.T) {
	err := PasswordStrength("short", "", 12)
	if err == nil || err.Error() != "Password is 5 characters; minimum is 12." {
		t.Errorf("err = %v", err)
	}
	// Characters, not bytes: six two-byte characters.
	err = PasswordStrength("ééééé", "", 6)
	if err == nil || err.Error() != "Password is 5 characters; minimum is 6." {
		t.Errorf("err = %v", err)
	}
	if err := PasswordStrength("éééééé", "", 6); err != nil {
		t.Errorf("6 characters: %v", err)
	}
}

func TestStrengthRejectsCommonWeak(t *testing.T) {
	const want = "Password is on the common-weak list. Choose another."
	for _, pw := range []string{
		"Administrator", "ADMIN", "Password1", "passw0rd", "TACACS+", "tacquito", "Cisco123", "Juniper1", "ChangeMe", "LetMeIn",
		"Qwerty123456", "qwerty", "ABC123xyz", "123456789012", "12345", "0000000000000", "aaaaaaaaaaaa", "AAAAAAA",
	} {
		// min length 1 so that only the weak list can reject
		err := PasswordStrength(pw, "", 1)
		if err == nil || err.Error() != want {
			t.Errorf("%q: err = %v", pw, err)
		}
	}
	// Exact words only: a longer word is not weak, nor is a near miss.
	for _, pw := range []string{"administrators", "password12", "tacacs++", "xqwerty", "1234", "0000", "aaaaa", "welcome12", "cisco1234"} {
		if err := PasswordStrength(pw, "", 1); err != nil {
			t.Errorf("%q wrongly rejected: %v", pw, err)
		}
	}
}

func TestStrengthRejectsUsername(t *testing.T) {
	err := PasswordStrength("ThisIsJSmithAlready", "ThisIsJSmithAlready", 12)
	if err == nil || err.Error() != "Password must not equal the username." {
		t.Errorf("err = %v", err)
	}
	if err := PasswordStrength("thisisjsmithalready", "ThisIsJSmithAlready", 12); err == nil {
		t.Error("the comparison is case-insensitive")
	}
	if err := PasswordStrength("Correct-Horse-42", "jsmith", 12); err != nil {
		t.Error(err)
	}
	if err := PasswordStrength("Correct-Horse-42", "", 12); err != nil {
		t.Error(err)
	}
}

// The check order of the bash: length, weak list, username.
func TestStrengthOrder(t *testing.T) {
	err := PasswordStrength("admin", "admin", 12)
	if err == nil || !strings.Contains(err.Error(), "minimum is 12") {
		t.Errorf("length must win: %v", err)
	}
	err = PasswordStrength("administrator", "administrator", 1)
	if err == nil || !strings.Contains(err.Error(), "common-weak") {
		t.Errorf("weak list must win over username: %v", err)
	}
}

// §3.9 item 10.
func TestStrengthRefusesOver72Bytes(t *testing.T) {
	if err := PasswordStrength(strings.Repeat("x7Q", 24), "", 12); err != nil {
		t.Errorf("72 bytes: %v", err)
	}
	if err := PasswordStrength(strings.Repeat("x7Q", 24)+"z", "", 12); !errors.Is(err, hash.ErrPasswordTooLong) {
		t.Errorf("73 bytes: %v", err)
	}
}

// --- generated passwords ---

type fixedReader struct{ b byte }

func (f fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.b
	}
	return len(p), nil
}

func TestGeneratePassword(t *testing.T) {
	// 18 zero bytes: 'openssl rand -base64 18' of those bytes is 24 'A'.
	got, err := GeneratePassword(fixedReader{0})
	if err != nil || got != strings.Repeat("A", 24) {
		t.Errorf("got %q, %v", got, err)
	}
	a, _ := GeneratePassword(nil)
	b, _ := GeneratePassword(nil)
	if len(a) != 24 || a == b || strings.ContainsAny(a, "=\n") {
		t.Errorf("crypto/rand passwords: %q %q", a, b)
	}
	if _, err := GeneratePassword(strings.NewReader("short")); err == nil {
		t.Error("a short read must fail")
	}
}

func TestRandomBase64(t *testing.T) {
	// A scope secret: 24 bytes, 32 characters ('openssl rand -base64 24').
	got, err := RandomBase64(fixedReader{0xfb}, 24)
	if err != nil || got != strings.Repeat("+/v7", 8) {
		t.Errorf("got %q, %v", got, err)
	}
}
