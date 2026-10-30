package names

import (
	"strings"
	"testing"
)

func TestMatchEmail(t *testing.T) {
	long := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57) + ".net"
	if len(long) != EmailMax {
		t.Fatalf("fixture is %d bytes, want %d", len(long), EmailMax)
	}
	for _, s := range []string{
		"alice@example.net", "Alice.Smith+ops@Example.NET", "bob@mail.example.net", "a_b-c@sub.example.org",
		"alice@example.net.", "carol@lab.example.net", long,
	} {
		want := s != "alice@example.net." // an empty last label
		if got := MatchEmail(s); got != want {
			t.Errorf("MatchEmail(%q) = %v, want %v", s, got, want)
		}
	}
	for _, s := range []string{
		"", "alice", "alice@", "@example.net", "alice@example", "alice@@example.net",
		"alice@example@example.net", "alice@.example.net", "alice@example..net",
		"alice smith@example.net", "alice@example.net ", " alice@example.net", "alice@exa mple.net",
		"Alice <alice@example.net>", "<alice@example.net>", "\"alice\"@example.net",
		"o'brien@example.net", "alice@example.net\n", "alice\t@example.net", "alice\x00@example.net",
		"alice @example.net", long + "x",
	} {
		if MatchEmail(s) {
			t.Errorf("MatchEmail(%q) = true", s)
		}
	}
}

func TestValidateEmailDoesNotEchoTheAddress(t *testing.T) {
	err := ValidateEmail("alice example.net")
	if err == nil {
		t.Fatal("not refused")
	}
	if strings.Contains(err.Error(), "alice example") {
		t.Errorf("refusal echoes the value: %q", err)
	}
	if err := ValidateEmail("alice@example.net"); err != nil {
		t.Errorf("valid address refused: %v", err)
	}
}

func TestSameEmail(t *testing.T) {
	if !SameEmail("Alice@Example.NET", "alice@example.net") || SameEmail("alice@example.net", "bob@example.net") {
		t.Error("SameEmail")
	}
}
