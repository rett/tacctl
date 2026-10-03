package yamlpy

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

// The corpus (corpus_test.go) is the parity proof; these tests pin the API
// around it: the refusals, Map, Options and Equal.

func TestEmitRefusesScalarsOutsideTheDomain(t *testing.T) {
	bad := []string{
		"caf\u00e9", // non-ASCII (PyYAML would write "caf\xE9")
		"\u2028",    // unicode line separator
		"a\rb",      // control characters other than tab and newline
		"a\x00b", "a\x1bb", "a\x7fb",
		"\nleading", "trailing\n", "\n",
		string([]byte{0xff}), // not UTF-8
	}
	for _, s := range bad {
		for _, v := range []any{s, []any{s}, NewMap("k", s), NewMap(s, "v")} {
			_, err := Emit(v, StoreOptions)
			if !errors.Is(err, ErrUnsupportedScalar) {
				t.Errorf("Emit(%#v): err = %v, want ErrUnsupportedScalar", v, err)
				continue
			}
			if strings.Contains(err.Error(), s) {
				t.Errorf("Emit(%q): the error quotes the value: %v", s, err)
			}
		}
	}
	// The error names where the value is.
	_, err := Emit(NewMap("scopes", NewMap("lab", NewMap("secret", "s\u00e9cret"))), StoreOptions)
	if err == nil || !strings.Contains(err.Error(), "scopes.lab.secret") {
		t.Errorf("error without the path: %v", err)
	}
	_, err = Emit(NewMap("l", []string{"ok", "b\u00e4d"}), StoreOptions)
	if err == nil || !strings.Contains(err.Error(), "l[1]") {
		t.Errorf("error without the path: %v", err)
	}
	// Inside the domain: tab, inner newline, every printable ASCII byte.
	var all []byte
	for c := byte(0x20); c <= 0x7e; c++ {
		all = append(all, c)
	}
	for _, s := range []string{"a\tb", "\t", "a\nb", string(all)} {
		if _, err := EmitChecked(NewMap(s, s), StoreOptions, ""); err != nil {
			t.Errorf("EmitChecked(%q): %v", s, err)
		}
	}
}

func TestEmitRefusesUnsupportedValues(t *testing.T) {
	shared := NewMap("a", 1)
	cyclic := NewMap()
	cyclic.Set("self", cyclic)
	deep := any("leaf")
	for range MaxDepth + 1 {
		deep = []any{deep}
	}
	var nilMap *Map
	bad := []any{
		float32(1.5),
		map[string]any{"a": 1},
		struct{}{},
		[]int{1},
		time.Now(),
		nilMap,
		NewMap("x", shared, "y", shared),
		cyclic,
		deep,
		Date{2026, 2, 30},
		Date{0, 1, 1},
	}
	for _, v := range bad {
		if _, err := Emit(v, StoreOptions); !errors.Is(err, ErrUnsupportedValue) {
			t.Errorf("Emit(%T): err = %v, want ErrUnsupportedValue", v, err)
		}
	}
}

func TestEmitScalarTypes(t *testing.T) {
	v := NewMap(
		"i", int8(-8), "u", uint64(math.MaxUint64), "i64", int64(math.MinInt64),
		"u8", uint8(255), "i16", int16(1), "i32", int32(2), "u16", uint16(3), "u32", uint32(4), "ui", uint(5),
		"f", 0.5, "d", Date{2026, time.October, 1}, "s", []string{"a"}, "m", []*Map{NewMap("k", "v")},
	)
	got, err := Emit(v, StoreOptions)
	if err != nil {
		t.Fatal(err)
	}
	want := "i: -8\nu: 18446744073709551615\ni64: -9223372036854775808\nu8: 255\ni16: 1\ni32: 2\nu16: 3\nu32: 4\nui: 5\n" +
		"f: 0.5\nd: 2026-10-01\ns: [a]\nm:\n- {k: v}\n"
	if string(got) != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestOptions(t *testing.T) {
	long := strings.Repeat("word ", 30)
	long = long[:len(long)-1]
	v := NewMap("k", long, "l", []string{"a", "b"})
	conf, _ := Emit(v, ConfOptions)
	if !strings.Contains(string(conf), "\n  word") || !strings.Contains(string(conf), "l:\n- a\n- b\n") {
		t.Errorf("ConfOptions: want folding at 80 and block sequences:\n%s", conf)
	}
	tiny, _ := Emit(v, Options{Width: 4}) // too small: PyYAML falls back to 80
	if string(tiny) != string(conf) {
		t.Errorf("Width 4 should mean 80")
	}
	store, _ := Emit(v, StoreOptions)
	if string(store) != "k: "+long+"\nl: [a, b]\n" {
		t.Errorf("StoreOptions:\n%s", store)
	}
}

func TestPyFloat(t *testing.T) {
	cases := map[float64]string{
		0: "0.0", math.Copysign(0, -1): "-0.0", 1: "1.0", 0.1: "0.1", 1e16: "1.0e+16",
		1.5e16: "1.5e+16", 9999999999999998: "9999999999999998.0", 1e-4: "0.0001", 1e-5: "1.0e-05",
		123456789.125: "123456789.125", 1e300: "1.0e+300", 2.5e-300: "2.5e-300",
		math.Inf(1): ".inf", math.Inf(-1): "-.inf",
	}
	for f, want := range cases {
		if got := pyFloat(f); got != want {
			t.Errorf("pyFloat(%v) = %q, want %q", f, got, want)
		}
	}
	if got := pyFloat(math.NaN()); got != ".nan" {
		t.Errorf("pyFloat(NaN) = %q", got)
	}
}

func TestResolvePlain(t *testing.T) {
	cases := map[string]string{
		"": tagNull, "~": tagNull, "null": tagNull, "nil": tagStr,
		"yes": tagBool, "Off": tagBool, "y": tagStr, "yEs": tagStr,
		"0123": tagInt, "08": tagStr, "0x1f": tagInt, "1_000": tagInt, "1:30": tagInt, "0:30": tagStr,
		"1.0": tagFloat, "1e3": tagStr, "1.0e+3": tagFloat, ".nan": tagFloat, "-.5": tagStr,
		"2026-10-01": tagTimestamp, "2026-1-1": tagStr, "2026-10-01 1:02:03": tagTimestamp,
		"<<": tagMerge, "=": tagValue, "*": tagYAML, "*a": tagStr, "::1": tagStr,
		"yes\n": tagBool, // Python's '$' matches before a final newline
	}
	for in, want := range cases {
		if got := resolvePlain(in); got != want {
			t.Errorf("resolvePlain(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMap(t *testing.T) {
	m := NewMap("b", 1, "a", 2)
	m.Set("c", 3)
	m.Set("b", 4) // in place
	if got := m.Keys(); !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Errorf("Keys = %v", got)
	}
	if v, ok := m.Get("b"); !ok || v != 4 {
		t.Errorf("Get(b) = %v, %v", v, ok)
	}
	if !m.Delete("a") || m.Delete("a") || m.Has("a") || m.Len() != 2 {
		t.Errorf("Delete")
	}
	m.Set("a", 5) // re-added at the end, as in a Python dict
	var keys []string
	for k := range m.All() {
		keys = append(keys, k)
		if k == "a" {
			break
		}
	}
	if !slices.Equal(keys, []string{"b", "c", "a"}) {
		t.Errorf("All = %v", keys)
	}
	var zero Map
	zero.Set("x", nil)
	if zero.Len() != 1 {
		t.Errorf("zero Map not usable")
	}
	var nilMap *Map
	if nilMap.Len() != 0 || nilMap.Keys() != nil || nilMap.Has("x") || nilMap.Delete("x") {
		t.Errorf("nil Map")
	}
	for range nilMap.All() {
		t.Errorf("nil Map yields")
	}
	for _, args := range [][]any{{"odd"}, {1, "v"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewMap(%v) did not panic", args)
				}
			}()
			NewMap(args...)
		}()
	}
}

func TestEqual(t *testing.T) {
	yes := [][2]any{
		{7, int64(7)}, {uint8(7), 7}, {math.NaN(), math.NaN()}, {nil, nil}, {"a", "a"},
		{[]string{"a"}, []any{"a"}}, {[]*Map{NewMap()}, []any{NewMap()}},
		{NewMap("a", []any{1}), NewMap("a", []any{int64(1)})}, {Date{2026, 1, 2}, Date{2026, 1, 2}},
	}
	no := [][2]any{
		{7, "7"}, {"7", 7}, {7, 7.0}, {true, "true"}, {nil, ""}, {NewMap("a", 1, "b", 2), NewMap("b", 2, "a", 1)},
		{[]any{1}, []any{1, 2}}, {NewMap(), []any{}}, {0.0, math.Copysign(0, -1)}, {"x", []any{"x"}},
		{Date{2026, 1, 2}, "2026-01-02"}, {Date{2026, 2, 30}, Date{2026, 2, 30}}, {struct{}{}, struct{}{}},
	}
	for _, c := range yes {
		if !Equal(c[0], c[1]) {
			t.Errorf("Equal(%#v, %#v) = false", c[0], c[1])
		}
	}
	for _, c := range no {
		if Equal(c[0], c[1]) {
			t.Errorf("Equal(%#v, %#v) = true", c[0], c[1])
		}
	}
}

func TestEmitCheckedHeader(t *testing.T) {
	got, err := EmitChecked(NewMap("a", 1), ConfOptions, "# h\n\n")
	if err != nil || string(got) != "# h\n\na: 1\n" {
		t.Errorf("EmitChecked = %q, %v", got, err)
	}
	// A header that is not YAML comments breaks the read-back.
	if _, err := EmitChecked(NewMap("a", 1), ConfOptions, "b: 2\n"); !errors.Is(err, ErrSelfCheck) {
		t.Errorf("err = %v, want ErrSelfCheck", err)
	}
	if _, err := EmitChecked(NewMap("a", 1), ConfOptions, "[\n"); !errors.Is(err, ErrSelfCheck) {
		t.Errorf("err = %v, want ErrSelfCheck", err)
	}
	if _, err := EmitChecked(float32(1), ConfOptions, ""); !errors.Is(err, ErrUnsupportedValue) {
		t.Errorf("err = %v, want ErrUnsupportedValue", err)
	}
}

func TestDateTime(t *testing.T) {
	d := Date{2026, time.October, 1}
	if !d.Time().Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || d.String() != "2026-10-01" {
		t.Errorf("Date: %v %v", d.Time(), d)
	}
}
