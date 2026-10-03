package store

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/rett/tacctl/internal/yamlpy"
)

func TestPyRepr(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{"abc", "'abc'"},
		{"it's", `"it's"`},
		{`it's "x"`, `'it\'s "x"'`},
		{"a\\b", `'a\\b'`},
		{"tab\there\nnl\r\x01\x7f", `'tab\there\nnl\r\x01\x7f'`},
		{"\u00fc\u00a0\u2028\U0001F600", "'\u00fc\\xa0\\u2028\U0001F600'"},
		{nil, "None"}, {true, "True"}, {false, "False"}, {7, "7"}, {int64(-3), "-3"},
		{1.5, "1.5"}, {1e16, "1e+16"}, {2.0, "2.0"}, {1e-5, "1e-05"},
		{math.NaN(), "nan"}, {math.Inf(1), "inf"}, {math.Inf(-1), "-inf"},
		{[]any{"a", 1, nil}, "['a', 1, None]"},
		{[]string{"a", "b"}, "['a', 'b']"},
		{yamlpy.NewMap("k", "v", "n", 2), "{'k': 'v', 'n': 2}"},
		{yamlpy.Date{Year: 2026, Month: 10, Day: 1}, "datetime.date(2026, 10, 1)"},
		{struct{}{}, "{}"},
	} {
		if got := PyRepr(c.in); got != c.want {
			t.Errorf("PyRepr(%#v) = %s, want %s", c.in, got, c.want)
		}
	}
	if PyStr("x") != "x" || PyStr(3) != "3" || PyStr(nil) != "None" {
		t.Error("PyStr")
	}
	if got := reprString("\xff"); got != `'\xff'` {
		t.Errorf("invalid UTF-8: %s", got)
	}
}

func TestPyFloat(t *testing.T) {
	for f, want := range map[float64]string{0: "0.0", 100: "100.0", 0.0001: "0.0001", 1e22: "1e+22", -2.5e-7: "-2.5e-07"} {
		if got := PyFloat(f); got != want {
			t.Errorf("PyFloat(%v) = %s, want %s", f, got, want)
		}
	}
}

func TestStrerror(t *testing.T) {
	if got := strerror(syscall.EACCES); got != "Permission denied" {
		t.Error(got)
	}
	if got := strerror(errors.New("x")); got != "x" {
		t.Error(got)
	}
	pe := &fs.PathError{Op: "open", Path: "/x", Err: syscall.ENOENT}
	if got := osErrorText(pe); got != "/x: No such file or directory" {
		t.Error(got)
	}
	le := &os.LinkError{Op: "rename", Old: "/a", New: "/b", Err: syscall.EXDEV}
	if got := osErrorText(le); got != "/a: Invalid cross-device link" {
		t.Error(got)
	}
	if got := osErrorText(syscall.EIO); got != "I/O: Input/output error" {
		t.Error(got)
	}
	if got := Report(&osError{pe}); got != "tacctl store: /x: No such file or directory" {
		t.Error(got)
	}
	if got := Report(errors.New("plain")); got != "plain" {
		t.Error(got)
	}
	if (&osError{pe}).Error() != "/x: No such file or directory" {
		t.Error("osError.Error")
	}
}

func TestPyStrip(t *testing.T) {
	if got := pyStrip(" \t\x1c10.0.0.0/8\x1f\u00a0\n"); got != "10.0.0.0/8" {
		t.Errorf("%q", got)
	}
}

func TestCIDRHelpers(t *testing.T) {
	if c, ok := CanonicalCIDR(" 10.1.5.5/24 "); !ok || c != "10.1.5.0/24" {
		t.Error(c)
	}
	if _, ok := CanonicalCIDR(7); ok {
		t.Error("int accepted")
	}
	if _, ok := CanonicalCIDR("banana"); ok {
		t.Error("banana accepted")
	}
	a, _ := ParseNet("10.0.0.0/8")
	b, _ := ParseNet("10.1.0.0/16")
	h, _ := ParseNet("10.1.2.3")
	v6, _ := ParseNet("fd00::/8")
	if !b.SubnetOf(a) || a.SubnetOf(b) || !a.Contains(h) || !h.IsHost() || a.IsHost() {
		t.Error("containment")
	}
	if v6.SubnetOf(a) || v6.Version() != 6 || v6.MaxPrefixLen() != 128 || a.MaxPrefixLen() != 32 {
		t.Error("versions")
	}
	a2, _ := ParseNet("10.0.0.5/8")
	if !a.Equal(a2) || a.Equal(b) || a.String() != "10.0.0.0/8" {
		t.Error("equality")
	}
	if !b.Key().Less(a.Key()) || a.Key().Less(b.Key()) {
		t.Error("cidr_key order: the narrower range first")
	}
	if _, ok := ParseNet(" 10.0.0.0/8"); ok {
		t.Error("ParseNet strips")
	}
	got := SortDisplay([]string{"10.0.0.0/8", "junk", "fd00::/64", "10.1.0.0/16", "10.0.0.5/8", "192.168.1.0/24"})
	if strings.Join(got, " ") != "fd00::/64 192.168.1.0/24 10.1.0.0/16 10.0.0.0/8 10.0.0.5/8 junk" {
		t.Error(got)
	}
	if DisplayKeyOf("junk").Less(DisplayKeyOf("junk2")) {
		t.Error("bad keys are equal")
	}
	if got := canonicalCIDRList([]any{"10.9.0.0/16", " 10.0.0.1/8", "10.0.0.0/8", "::/0"}); PyRepr(got) != "['10.9.0.0/16', '10.0.0.0/8', '::/0']" {
		t.Error(PyRepr(got))
	}
	if got := canonicalCIDRList([]any{"10.0.0.0/8", "x"}); PyRepr(got) != "['10.0.0.0/8', 'x']" {
		t.Error("untouched")
	}
	if got := canonicalCIDRList("x"); got != "x" {
		t.Error("non-list")
	}
}

func TestDeviceProblemsTieGoesToFirst(t *testing.T) {
	// max() keeps the first of equal prefix lengths: with the same prefix
	// in two scopes, the first scope in order owns the tagged address.
	scopes := []DeviceScope{
		{Name: "a", Prefixes: []any{"10.0.0.0/8"}},
		{Name: "b", Prefixes: []any{"10.0.0.0/8", 7}, Devices: []string{"10.1.1.1/32", "junk"}},
	}
	got := DeviceProblems(scopes)
	if len(got) != 1 || got[0].Msg != "scope 'b': devices: 10.1.1.1/32 belongs to scope 'a' (its prefix 10.0.0.0/8 is the most specific one that contains it)" {
		t.Errorf("%+v", got)
	}
}

func TestBcryptHelpers(t *testing.T) {
	raw := "$2b$12$" + strings.Repeat("A", 53)
	h, ok := NormalizeHash("  " + raw + "\n")
	if !ok || !BcryptHexOK(h) {
		t.Error("raw")
	}
	if up, ok := NormalizeHash(strings.ToUpper(h)); !ok || up != h {
		t.Error("upper hex")
	}
	for _, bad := range []any{nil, 3, "abc", "zz", h[:len(h)-2] + "2E", "2432", "ff" + h[2:]} {
		if BcryptHexOK(bad) {
			t.Errorf("BcryptHexOK(%v)", bad)
		}
	}
}

func TestFieldsAndBuiltins(t *testing.T) {
	f, label := Fields("users")
	if label != "user" || strings.Join(f, ",") != "group,scopes,hash,disabled,password_changed,accounting_sink" {
		t.Error(f, label)
	}
	if f, _ := Fields("nope"); f != nil {
		t.Error(f)
	}
	if !IsBuiltinGroup("operator") || IsBuiltinGroup("netops") {
		t.Error("IsBuiltinGroup")
	}
}

func TestNormalizeShapeErrors(t *testing.T) {
	for _, c := range []struct {
		raw  any
		want string
	}{
		{[]any{1}, "store is not a YAML mapping"},
		{yamlpy.NewMap("groups", []any{}), "'groups' must be a mapping keyed by name"},
		{yamlpy.NewMap("users", yamlpy.NewMap("bob", 3)), "user 'bob': must be a mapping"},
		{yamlpy.NewMap("filters", 3), "'filters' must be a mapping with allow and deny"},
	} {
		_, err := Normalize(c.raw)
		var se *Error
		if !errors.As(err, &se) || se.Msg != c.want {
			t.Errorf("Normalize(%s): %v", PyRepr(c.raw), err)
		}
	}
	s, err := Normalize(nil)
	if err != nil || s.Doc().Len() != 5 {
		t.Error("empty document")
	}
	if got := Validate(3); len(got) != 1 || got[0] != "store is not a YAML mapping" {
		t.Error(got)
	}
}

func TestNormalizeKeepsUnknownAndDefaults(t *testing.T) {
	raw := yamlpy.NewMap("extra", 1, "users", yamlpy.NewMap("bob", yamlpy.NewMap("group", "g",
		"password_changed", yamlpy.Date{Year: 2026, Month: 1, Day: 2})))
	s, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := PyRepr(s.Doc()); got != "{'version': 1, 'groups': {}, 'users': {'bob': {'group': 'g', "+
		"'password_changed': '2026-01-02', 'accounting_sink': False}}, 'scopes': {}, "+
		"'filters': {'allow': [], 'deny': []}, 'extra': 1}" {
		t.Error(got)
	}
	// The raw value is untouched.
	u, _ := raw.Get("users")
	b, _ := u.(*yamlpy.Map).Get("bob")
	if pc, _ := b.(*yamlpy.Map).Get("password_changed"); pc != (yamlpy.Date{Year: 2026, Month: 1, Day: 2}) {
		t.Error("raw changed")
	}
}

func TestCanonicalize(t *testing.T) {
	raw := yamlpy.NewMap(
		"groups", yamlpy.NewMap("readonly", yamlpy.NewMap("builtin", false), "x", yamlpy.NewMap("builtin", true)),
		"users", yamlpy.NewMap("bob", yamlpy.NewMap("hash", "ABCDEF", "scopes", []any{"a", "b", "a"})),
		"scopes", yamlpy.NewMap(
			"a", yamlpy.NewMap("vendor_attrs", []any{"wti", "cisco", "wti"},
				"devices", yamlpy.NewMap("10.10.0.0/16", "cisco", "10.9.0.1", "wti", "10.9.0.1/32", "juniper")),
			"b", yamlpy.NewMap("prefixes", []any{"10.0.0.0/8"}, "vendor_attrs", []any{}, "devices", nil),
			"c", yamlpy.NewMap("vendor_attrs", []any{"arista"}, "devices", yamlpy.NewMap("junk", "x")),
		),
		"filters", yamlpy.NewMap("allow", []any{"10.0.0.1/8"}, "deny", nil),
	)
	s, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Canonicalize()
	if got := PyRepr(s.Doc()); got != "{'version': 1, "+
		"'groups': {'readonly': {'builtin': True}, 'x': {'builtin': False}}, "+
		"'users': {'bob': {'hash': 'abcdef', 'scopes': ['a', 'b'], 'password_changed': None, 'accounting_sink': False}}, "+
		"'scopes': {'a': {'vendor_attrs': ['cisco', 'wti'], 'devices': {'10.9.0.1/32': 'wti', '10.10.0.0/16': 'cisco'}, "+
		"'protocols': None, 'prefixes': None}, "+
		"'b': {'prefixes': ['10.0.0.0/8'], 'protocols': None}, "+
		"'c': {'vendor_attrs': ['arista'], 'devices': {'junk': 'x'}, 'protocols': None, 'prefixes': None}}, "+
		"'filters': {'allow': ['10.0.0.0/8'], 'deny': []}}" {
		t.Error(got)
	}
}

func TestEmptyAndText(t *testing.T) {
	s := Empty()
	text, err := s.Text()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(text), Header+"version: 1\ngroups:\n  operator:") {
		t.Error(string(text))
	}
	if errs := Validate(s.Doc()); len(errs) != 0 {
		t.Error(errs)
	}
	if s.now().IsZero() {
		t.Error("clock")
	}
}
