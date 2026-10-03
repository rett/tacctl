package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/yamlpy"
)

func writeTemp(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tacquito.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReadLegacyYAMLAgreesWithDecode: on YAML without anchors,
// ReadLegacyYAML is yamlpy.Decode (safe_load), scalar for scalar, in block
// and in flow context; where Decode refuses a scalar, so does it (bar
// integers beyond int64, which it keeps).
func TestReadLegacyYAMLAgreesWithDecode(t *testing.T) {
	scalars := []string{
		"plain", "yes", "No", "ON", "off", "true", "False", "y", "n", "~", "null", "Null", "", "''", `""`,
		"0", "7", "-7", "+7", "0123", "0o17", "0x1f", "0b101", "1_000", "1:30", "-1:30", "190:20:30",
		"1.5", "1.", ".5", "1e3", "1.0e3", "1.0e+3", "6.8523015e+5", ".inf", "-.Inf", ".NaN", "+.INF",
		"2026-10-01", "2026-1-1", "2026-02-30", "2001-12-14t21:59:43.10-05:00", "2001-12-14 21:59:43.10",
		"=", "<<", "'yes'", `"0123"`, "!!str 0123", "!!int '7'", "!!bool yes", "!!float 1", "!!null ''",
		"!!str", "it's", "'it''s'", "a b c", "a:b", "::1", "10.0.0.0/8", "'fd00::/8'", "$2b$12$abc",
		`"tab\there"`, `"ü"`, "x # comment", "9223372036854775807", "-9223372036854775808",
		"!custom x", "!!timestamp 2026-10-01", "!!binary aGk=",
	}
	for _, s := range scalars {
		for _, doc := range []string{"v: " + s + "\n", "v: [" + s + "]\n", "- " + s + "\n"} {
			want, werr := yamlpy.Decode([]byte(doc))
			got, gerr := ReadLegacyYAML(writeTemp(t, doc))
			if (werr != nil) != (gerr != nil) {
				t.Errorf("%q: Decode error %v, ReadLegacyYAML error %v", doc, werr, gerr)
				continue
			}
			if werr == nil && !yamlpy.Equal(got, want) {
				t.Errorf("%q: got %#v, want %#v", doc, got, want)
			}
		}
	}
}

// TestReadLegacyYAMLCorpus: the same on every file of yamlpy's decode and
// emitter corpus and on the store fixtures.
func TestReadLegacyYAMLCorpus(t *testing.T) {
	var files []string
	for _, g := range []string{"../yamlpy/testdata/decode/*.yaml", "../yamlpy/testdata/corpus/*.yaml", "../../tests/fixtures/store.*.yaml"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	if len(files) < 100 {
		t.Fatalf("only %d corpus files", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want, werr := yamlpy.Decode(data)
		got, gerr := ReadLegacyYAML(f)
		if (werr != nil) != (gerr != nil) {
			t.Errorf("%s: Decode error %v, ReadLegacyYAML error %v", f, werr, gerr)
			continue
		}
		if werr == nil && !yamlpy.Equal(got, want) {
			t.Errorf("%s: values differ", f)
		}
	}
}

func TestReadLegacyYAMLAliases(t *testing.T) {
	// An alias is its anchor's very value (what the loader's identity
	// tests rely on), whatever it is.
	p := writeTemp(t, `num: &n 0x10
grp: &g {name: ops, services: [&svc {name: shell}]}
list: &l [a, b]
users:
  - {groups: [*g], n: *n, l: *l, s: *svc}
  - {groups: [*g]}
copy: {name: ops, services: [{name: shell}]}
*n : aliased-key-is-not-a-string
`)
	if _, err := ReadLegacyYAML(p); err == nil || !strings.Contains(err.Error(), "a key that is not a string") {
		t.Errorf("an alias key to an int: %v", err)
	}
	p = writeTemp(t, `num: &n 0x10
grp: &g {name: ops, services: [&svc {name: shell}]}
list: &l [a, b]
key: &k name
users:
  - {groups: [*g], n: *n, l: *l, s: *svc}
  - {groups: [*g], *k : bob}
copy: {name: ops, services: [{name: shell}]}
`)
	v, err := ReadLegacyYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(*yamlpy.Map)
	g := get(doc, "grp").(*yamlpy.Map)
	users := get(doc, "users").([]any)
	u0, u1 := users[0].(*yamlpy.Map), users[1].(*yamlpy.Map)
	if get(u0, "groups").([]any)[0] != g || get(u1, "groups").([]any)[0] != g {
		t.Error("the group alias is not the anchor's mapping")
	}
	if get(u0, "s") != get(g, "services").([]any)[0] {
		t.Error("the service alias is not the anchor's mapping")
	}
	if get(u0, "n") != 16 || get(u1, "name") != "bob" {
		t.Errorf("scalars: %#v %#v", get(u0, "n"), get(u1, "name"))
	}
	if c := get(doc, "copy").(*yamlpy.Map); c == g || !pyEqual(c, g) {
		t.Error("an equal copy must be equal and not identical")
	}
}

func TestReadLegacyYAMLRefusals(t *testing.T) {
	for doc, want := range map[string]string{
		"a: &x [1, *x]\n":                "an alias inside its own anchor",
		"base: &b {x: 1}\nm: {<<: *b}\n": "a merge key '<<'",
		"a: 2001-12-14 21:59:43.10\n":    "a timestamp with a time of day",
		"a: !custom x\n":                 "tag !custom",
		"a: !!set {x: null}\n":           "tag !!set",
		"? [a, b]\n: c\n":                "a key that is not a scalar",
		"1: x\n":                         "a key that is not a string",
		"a: =\n":                         "the indicator '=' as a value",
		"a: 1\n---\nb: 2\n":              "expected a single document in the stream",
		"a: [1\n":                        "(line ",
		"a: \"leaky-secret-0123456789\n": "(line ",
		strings.Repeat("[", 70) + strings.Repeat("]", 70): "nested deeper than 64",
	} {
		p := writeTemp(t, doc)
		_, err := ReadLegacyYAML(p)
		if err == nil {
			t.Errorf("%q: no error", doc)
			continue
		}
		msg := Report(err)
		if !strings.HasPrefix(msg, "tacctl store: "+p+": ") || !strings.Contains(msg, want) || strings.Contains(msg, "leaky") {
			t.Errorf("%q: %s (want %q)", doc, msg, want)
		}
	}
	// '=' is a string as a key, as in flatten_mapping.
	v, err := ReadLegacyYAML(writeTemp(t, "=: x\n"))
	if err != nil || get(v.(*yamlpy.Map), "=") != "x" {
		t.Errorf("'=' key: %v %v", v, err)
	}
	// An empty file is None; a missing one is the OS error.
	if v, err := ReadLegacyYAML(writeTemp(t, "# nothing\n")); v != nil || err != nil {
		t.Errorf("empty: %v %v", v, err)
	}
	if _, err := ReadLegacyYAML("/nonexistent/tacquito.yaml"); Report(err) != "tacctl store: /nonexistent/tacquito.yaml: No such file or directory" {
		t.Errorf("missing: %v", Report(err))
	}
}

func TestReadLegacyYAMLBigInts(t *testing.T) {
	// safe_load reads integers of any size; they come back as their
	// decimal text (what str(int) prints).
	for text, want := range map[string]bigInt{
		"243262243132244141414141414141414141414141414141": "243262243132244141414141414141414141414141414141",
		"-9223372036854775809":                             "-9223372036854775809",
		"+9_223_372_036_854_775_808":                       "9223372036854775808",
		"0x10000000000000000":                              "18446744073709551616",
		"0b1" + strings.Repeat("0", 64):                    "18446744073709551616",
		"02" + strings.Repeat("0", 22):                     "147573952589676412928",
		"1" + strings.Repeat(":00", 11):                    "36279705600000000000",
	} {
		v, err := ReadLegacyYAML(writeTemp(t, "v: "+text+"\n"))
		if err != nil {
			t.Errorf("%s: %v", text, err)
			continue
		}
		if got := get(v.(*yamlpy.Map), "v"); got != want {
			t.Errorf("%s: %#v, want %s", text, got, want)
		}
	}
	// Quoted, it is a string.
	v, _ := ReadLegacyYAML(writeTemp(t, "v: '243262243132244141414141414141414141414141414141'\n"))
	if _, ok := get(v.(*yamlpy.Map), "v").(string); !ok {
		t.Error("a quoted number is not a string")
	}
}

func TestReadBaseYAML(t *testing.T) {
	// BaseLoader: every scalar is its text, whatever its tag or style; a
	// merge key is a key; aliases resolve.
	v, err := ReadBaseYAML(writeTemp(t, `a: 015
b: "015"
c: !!int 7
d: yes
e:
f: ~
base: &b {x: 1}
m: {<<: *b}
l: *b
2026-01-01: date-key
`))
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(*yamlpy.Map)
	for k, want := range map[string]string{"a": "015", "b": "015", "c": "7", "d": "yes", "e": "", "f": "~", "2026-01-01": "date-key"} {
		if got := get(doc, k); got != want {
			t.Errorf("%s: %#v, want %q", k, got, want)
		}
	}
	if m := get(get(doc, "m").(*yamlpy.Map), "<<"); m != get(doc, "base") {
		t.Errorf("merge key: %#v", m)
	}
	if _, err := ReadBaseYAML(writeTemp(t, "? [a]\n: b\n")); err == nil || !strings.Contains(err.Error(), "found unhashable key") {
		t.Errorf("non-scalar key: %v", err)
	}
	if v, err := ReadBaseYAML(writeTemp(t, "")); v != nil || err != nil {
		t.Errorf("empty: %v %v", v, err)
	}
}

func TestPyHelpers(t *testing.T) {
	for _, c := range []struct {
		v    any
		n    int
		want bool
	}{{1, 1, true}, {true, 1, true}, {false, 0, true}, {1.0, 1, true}, {"1", 1, false}, {bigInt("1"), 1, false}, {nil, 1, false}, {2, 1, false}} {
		if pyEqInt(c.v, c.n) != c.want {
			t.Errorf("pyEqInt(%#v, %d)", c.v, c.n)
		}
	}
	if pyStr(nil) != "None" || pyStr(true) != "True" || pyStr(bigInt("12")) != "12" ||
		pyStr(yamlpy.Date{Year: 2026, Month: 1, Day: 2}) != "2026-01-02" || pyStr(1.5) != "1.5" || pyStr([]any{"a", 1}) != "['a', 1]" {
		t.Error("pyStr")
	}
	a := yamlpy.NewMap("x", 1, "y", []any{true, "s"})
	b := yamlpy.NewMap("y", []any{1, "s"}, "x", 1.0)
	if !pyEqual(a, b) || pyEqual(a, yamlpy.NewMap("x", 1)) || pyEqual([]any{1}, []any{"1"}) || !pyEqual(nil, nil) {
		t.Error("pyEqual")
	}
	if !pyEqual(bigInt("5"), bigInt("5")) || pyEqual(bigInt("5"), 5) {
		t.Error("pyEqual bigInt")
	}
	for in, want := range map[string]int{"7": 7, " 12 ": 12, "0099": 99} {
		if got, ok := privLevel(in); !ok || got != want {
			t.Errorf("privLevel(%q) = %d %v", in, got, ok)
		}
	}
	for _, in := range []any{"x", "-1", "1.5", true, 1.5, nil} {
		if _, ok := privLevel(in); ok {
			t.Errorf("privLevel(%#v) accepted", in)
		}
	}
	if pyList("ab").([]any)[1] != "b" || len(pyList(yamlpy.NewMap("k", 1)).([]any)) != 1 || pyList(3) != 3 {
		t.Error("pyList")
	}
}

func TestSidecarUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "alice.date")
	if err := os.WriteFile(p, []byte("2026-01-01\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	rep := &LegacyReport{}
	if _, ok := sidecar(dir, "alice.date", rep); ok {
		t.Error("read an unreadable file")
	}
	if len(rep.Notes) != 1 || rep.Notes[0] != "alice.date: sidecar file not readable (Permission denied); ignored" {
		t.Errorf("notes: %q", rep.Notes)
	}
	// A file where the directory should be: no sidecar, no note.
	if _, ok := sidecar(p, "x.date", rep); ok || len(rep.Notes) != 1 {
		t.Error("ENOTDIR")
	}
}
