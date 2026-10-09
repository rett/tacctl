package conf

import (
	"strconv"
	"strings"
	"testing"
)

// snmp_scope.<scope>.<setting>: the scope is a name without dots, the
// setting one of the listed.
func TestSNMPScopeKeysInTheSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for path, typ := range map[string]string{
		"snmp_scope.lab.version": TypeEnum, "snmp_scope.lab.port": TypeInt, "snmp_scope.lab.timeout": TypeInt,
		"snmp_scope.lab.v3.auth": TypeEnum, "snmp_scope.lab.v3.priv": TypeEnum,
		"snmp_scope.lab.contact": TypeSNMPText, "snmp_scope.lab.clients": TypeSNMPClients,
		"snmp_scope.my-scope_2.version": TypeEnum,
	} {
		r, ok := s.RuleFor(path)
		if !ok || r.Type != typ {
			t.Errorf("%s: %+v %v", path, r, ok)
		}
	}
	for _, path := range []string{"snmp_scope", "snmp_scope.", "snmp_scope.lab", "snmp_scope..version", "snmp_scope.lab.nosuch",
		"snmp_scope.lab.v3", "snmp_scope.a.b.version", "snmp_scope.version", "snmp_scope.lab.v3.nosuch", "snmp_scope.lab.clients.x"} {
		if r, ok := s.RuleFor(path); ok {
			t.Errorf("%s has a rule: %+v", path, r)
		}
	}
	// The default's keys are untouched.
	if _, ok := s.RuleFor("snmp.version"); !ok {
		t.Error("snmp.version")
	}
	if d, ok := s.ImplicitDefault("snmp_scope.lab.clients"); !ok || d == nil {
		t.Errorf("clients default: %v %v", d, ok)
	}
	if _, ok := s.ImplicitDefault("snmp_scope.lab.version"); ok {
		t.Error("version has a default")
	}
}

func TestSNMPScopeValidation(t *testing.T) {
	s := NewSchema(DefaultBackends)
	var many []any
	for i := 0; i < 33; i++ {
		many = append(many, "10.0."+strconv.Itoa(i)+".0/24")
	}
	for _, c := range []struct {
		path   string
		value  any
		isList bool
		want   string // a fragment of the reason; "" is accepted
	}{
		{"snmp_scope.lab.version", "v2c", false, ""},
		{"snmp_scope.lab.version", "v1", false, "must be one of: v2c, v3"},
		{"snmp_scope.lab.port", 1161, false, ""},
		{"snmp_scope.lab.port", 0, false, "must be >= 1"},
		{"snmp_scope.lab.timeout", 11, false, "must be <= 10"},
		{"snmp_scope.lab.v3.auth", "sha256", false, ""},
		{"snmp_scope.lab.v3.auth", "md5", false, "must be one of: sha, sha256"},
		{"snmp_scope.lab.v3.priv", "des", false, "must be one of: aes128"},
		{"snmp_scope.lab.contact", "NOC <noc@example.net>", false, ""},
		{"snmp_scope.lab.contact", "", false, "must not be empty"},
		{"snmp_scope.lab.contact", "line\nbreak", false, "control characters"},
		{"snmp_scope.lab.contact", "help?", false, "'?'"},
		{"snmp_scope.lab.contact", strings.Repeat("x", 121), false, "limited to 120"},
		{"snmp_scope.lab.contact", 5, false, "must be a string"},
		{"snmp_scope.lab.clients", []any{"192.0.2.0/24", "10.0.0.0/8"}, true, ""},
		{"snmp_scope.lab.clients", []any{}, true, ""},
		{"snmp_scope.lab.clients", []any{"0.0.0.0/0"}, true, "would allow every address"},
		{"snmp_scope.lab.clients", []any{"::/0"}, true, "IPv6"},
		{"snmp_scope.lab.clients", []any{"2001:db8::/32"}, true, "IPv4 only"},
		{"snmp_scope.lab.clients", []any{"192.0.2.1"}, true, "canonical"},
		{"snmp_scope.lab.clients", []any{"junk"}, true, "not a valid CIDR"},
		{"snmp_scope.lab.clients", []any{"192.0.2.0/24", "192.0.2.0/24"}, true, "listed twice"},
		{"snmp_scope.lab.clients", []any{5}, true, "must be a string"},
		{"snmp_scope.lab.clients", many, true, "at most 32"},
		{"snmp_scope.lab.clients", many[:32], true, ""},
		{"snmp_scope.lab.clients", "192.0.2.0/24", false, "requires list input"},
		{"snmp_scope.lab.version", []any{"v2c"}, true, "does not accept list input"},
	} {
		got := s.Validate(c.path, c.value, c.isList)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s = %v: %q, want %q", c.path, c.value, got, c.want)
		}
	}
}

// Overlapping ranges are no error.
func TestSNMPClientsOverlapIsAccepted(t *testing.T) {
	if why := SNMPClientsProblem([]string{"10.0.0.0/8", "10.1.0.0/16"}); why != "" {
		t.Errorf("overlap refused: %q", why)
	}
}
