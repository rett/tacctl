package conf

import (
	"strings"
	"testing"
)

func TestJunosLimitsAndValue(t *testing.T) {
	if JunosLimit(JunosDenyCommands) != 241 || JunosLimit(JunosDenyConfiguration) != 236 {
		t.Fatalf("limits %d %d", JunosLimit(JunosDenyCommands), JunosLimit(JunosDenyConfiguration))
	}
	if JunosArg(JunosDenyConfiguration) != "deny-configuration" {
		t.Fatal(JunosArg(JunosDenyConfiguration))
	}
	if v := JunosValue([]string{"^a", "b$"}); v != "(^a)|(b$)" {
		t.Fatalf("value %q", v)
	}
	if JunosValue(nil) != "" {
		t.Fatal("empty")
	}
}

func TestJunosSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	ok := []any{"^show (system login)( .*)?$", "^file delete .*"}
	if msg := s.Validate("junos.operator.deny_commands", ok, true); msg != "" {
		t.Fatalf("valid set refused: %s", msg)
	}
	if msg := s.Validate("junos.engineer.deny_configuration", []any{}, true); msg != "" {
		t.Fatalf("empty set refused: %s", msg)
	}
	for path, want := range map[string]string{
		"junos.operator.allow_commands": "allow_commands is not supported in this release",
		"junos.operator.deny_other":     "must be deny_commands or deny_configuration",
	} {
		if msg := s.Validate(path, ok, true); !strings.Contains(msg, want) {
			t.Errorf("%s: %q, want %q", path, msg, want)
		}
	}
	for _, c := range []struct {
		items []any
		want  string
	}{
		{[]any{""}, "element 0: '' is empty"},
		{[]any{"^(?i)show"}, "not POSIX ERE"},
		{[]any{"^(show"}, "not a valid regular expression"},
		{[]any{"^a", "^a"}, "element 1: '^a' is listed twice"},
		{[]any{3}, "element 0: must be a string"},
		{[]any{strings.Repeat("x", 240)}, "deny-commands would be 242 bytes; the limit is 241"},
	} {
		if msg := s.Validate("junos.g.deny_commands", c.items, true); !strings.Contains(msg, c.want) {
			t.Errorf("%v: %q, want %q", c.items, msg, c.want)
		}
	}
	// Exactly at the limit: 239 bytes in parentheses is 241.
	if msg := s.Validate("junos.g.deny_commands", []any{strings.Repeat("x", 239)}, true); msg != "" {
		t.Errorf("241 bytes refused: %s", msg)
	}
	if msg := s.Validate("junos.g.deny_commands", "^a", false); !strings.Contains(msg, "requires list input") {
		t.Errorf("scalar: %q", msg)
	}
	// The other two keys are enums without a default.
	if msg := s.Validate("wti_level.engineer", "superuser", false); msg != "" {
		t.Error(msg)
	}
	if msg := s.Validate("wti_level.engineer", "admin", false); !strings.Contains(msg, "must be one of: viewonly, user, superuser, administrator") {
		t.Error(msg)
	}
	if msg := s.Validate("tier.engineer", "engineer", false); msg != "" {
		t.Error(msg)
	}
	if msg := s.Validate("tier.engineer", "root", false); !strings.Contains(msg, "must be one of: readonly, operator, engineer, superuser") {
		t.Error(msg)
	}
	if _, ok := s.ImplicitDefault("tier.engineer"); ok {
		t.Error("tier has a default")
	}
}
