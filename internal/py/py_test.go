package py

import (
	"bufio"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/yamlpy"
)

// corpusValue turns a ../conf/testdata/py.jsonl value into the Go value:
// {"$float": ...}, {"$date": ...}, {"$bigint": ...}.
func corpusValue(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	v, err := Loads(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	var conv func(any) any
	conv = func(v any) any {
		switch x := v.(type) {
		case *yamlpy.Map:
			if x.Len() == 1 {
				if f, ok := x.Get("$float"); ok {
					switch f {
					case "nan":
						return math.NaN()
					case "inf":
						return math.Inf(1)
					}
					return math.Inf(-1)
				}
				if d, ok := x.Get("$date"); ok {
					tm, _ := time.Parse("2006-01-02", d.(string))
					return yamlpy.Date{Year: tm.Year(), Month: tm.Month(), Day: tm.Day()}
				}
				if b, ok := x.Get("$bigint"); ok {
					n, _ := new(big.Int).SetString(b.(string), 10)
					return n
				}
			}
			out := yamlpy.NewMap()
			for k, val := range x.All() {
				out.Set(k, conv(val))
			}
			return out
		case []any:
			for i := range x {
				x[i] = conv(x[i])
			}
		}
		return v
	}
	return conv(v)
}

// TestCorpus: repr(), str() and json.dumps() of values as Python 3.12
// gives them (internal/conf/testdata/gen.py).
func TestCorpus(t *testing.T) {
	f, err := os.Open("../conf/testdata/py.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		var rec struct {
			Value json.RawMessage `json:"value"`
			Repr  string          `json:"repr"`
			Str   string          `json:"str"`
			JSON  *string         `json:"json"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		v := corpusValue(t, rec.Value)
		if got := Repr(v); got != rec.Repr {
			t.Errorf("line %d: repr(%s) = %q, want %q", n, rec.Value, got, rec.Repr)
		}
		if got := Str(v); got != rec.Str {
			t.Errorf("line %d: str(%s) = %q, want %q", n, rec.Value, got, rec.Str)
		}
		got, err := Dumps(v)
		switch {
		case rec.JSON == nil && !errors.Is(err, ErrNotSerializable):
			t.Errorf("line %d: json.dumps(%s) should fail, got %q %v", n, rec.Value, got, err)
		case rec.JSON != nil && (err != nil || got != *rec.JSON):
			t.Errorf("line %d: json.dumps(%s) = %q %v, want %q", n, rec.Value, got, err, *rec.JSON)
		}
	}
	if n < 500 {
		t.Fatalf("only %d cases", n)
	}
}

func TestLoadsKeepsOrderAndTypes(t *testing.T) {
	v, err := Loads(` {"b": 1, "a": [2.5, 1e400, NaN, -Infinity, null, true, "xé😀"], "b": 3, "big": 123456789012345678901} `)
	if err != nil {
		t.Fatal(err)
	}
	if got := Repr(v); got != "{'b': 3, 'a': [2.5, inf, nan, -inf, None, True, 'xé😀'], 'big': 123456789012345678901}" {
		t.Fatalf("got %s", got)
	}
}

// The messages are CPython 3.12's json scanner's.
func TestLoadsErrors(t *testing.T) {
	for in, want := range map[string]string{
		"":                "Expecting value: line 1 column 1 (char 0)",
		"{bad json":       "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
		`{"a" 1}`:         "Expecting ':' delimiter: line 1 column 6 (char 5)",
		`{"a": 1 "b": 2}`: "Expecting ',' delimiter: line 1 column 9 (char 8)",
		`[1, 2`:           "Expecting ',' delimiter: line 1 column 6 (char 5)",
		`[1,]`:            "Expecting value: line 1 column 4 (char 3)",
		`{"a": 1,}`:       "Expecting property name enclosed in double quotes: line 1 column 9 (char 8)",
		`"abc`:            "Unterminated string starting at: line 1 column 1 (char 0)",
		"\"a\nb\"":        "Invalid control character at: line 1 column 3 (char 2)",
		`"\q"`:            "Invalid \\escape: line 1 column 2 (char 1)",
		`"\u12"`:          "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
		"1 2":             "Extra data: line 1 column 3 (char 2)",
		"[\n  1,\n  x]":   "Expecting value: line 3 column 3 (char 9)",
		"-":               "Expecting value: line 1 column 1 (char 0)",
		"01":              "Extra data: line 1 column 2 (char 1)",
	} {
		_, err := Loads(in)
		var je *JSONError
		if !errors.As(err, &je) || je.Error() != want {
			t.Errorf("Loads(%q) = %v, want %q", in, err, want)
		}
	}
}

func TestEqualIsPythonEquality(t *testing.T) {
	for _, tc := range []struct {
		a, b any
		eq   bool
	}{
		{1, true, true}, {0, false, true}, {1, 1.0, true}, {big.NewInt(5), 5, true}, {1.5, 1, false},
		{math.NaN(), math.NaN(), false}, {"a", "a", true}, {"1", 1, false}, {nil, nil, true}, {nil, 0, false},
		{[]any{"a"}, []string{"a"}, true}, {[]any{1, 2}, []any{2, 1}, false},
		{yamlpy.NewMap("a", 1, "b", 2), yamlpy.NewMap("b", 2, "a", 1), true},
		{yamlpy.NewMap("a", 1), yamlpy.NewMap("a", 1, "b", 2), false},
		{yamlpy.Date{Year: 2026, Month: 10, Day: 1}, yamlpy.Date{Year: 2026, Month: 10, Day: 1}, true},
		{math.Inf(1), big.NewInt(1), false},
	} {
		if got := Equal(tc.a, tc.b); got != tc.eq {
			t.Errorf("Equal(%s, %s) = %v", Repr(tc.a), Repr(tc.b), got)
		}
	}
}

// int() and float() of a str, as coerce_scalar applies them (the full
// table is internal/conf/testdata/coerce.jsonl).
func TestIntAndFloat(t *testing.T) {
	for in, want := range map[string]string{" 14 ": "14", "+1_4": "14", "-0": "0", "١٤": "14", "𝟏𝟐": "12",
		"1__4": "", "_1": "", "1_": "", "0x10": "", "": "", "1.5": ""} {
		n, ok := Int(in)
		got := ""
		if ok {
			got = n.String()
		}
		if got != want {
			t.Errorf("Int(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]float64{"1.5": 1.5, " .5 ": 0.5, "1_0.5": 10.5, "1e5": 1e5, "1.e1": 10, "١.٥": 1.5} {
		if f, ok := Float(in); !ok || f != want {
			t.Errorf("Float(%q) = %v %v", in, f, ok)
		}
	}
	for _, in := range []string{"1._5", "nan.", "1.2.3", "10.0.0.1", ".", "0x1.5", "1.5e", "1.5e_10", "inf."} {
		if _, ok := Float(in); ok {
			t.Errorf("Float(%q) accepted", in)
		}
	}
	if f, ok := Float("Infinity"); !ok || !math.IsInf(f, 1) {
		t.Error("Infinity")
	}
}

func TestStringHelpers(t *testing.T) {
	if got := Split(" a b\x1cc\n"); len(got) != 3 {
		t.Errorf("Split %q", got)
	}
	if Strip("  x \t") != "x" || CollapseSpace("a \n\t b") != "a b" {
		t.Error("Strip/CollapseSpace")
	}
	if !IsSpace('\x1f') || IsSpace('x') {
		t.Error("IsSpace")
	}
	if ReprString("a\xffb") != `'a\xffb'` {
		t.Errorf("invalid UTF-8: %s", ReprString("a\xffb"))
	}
	if TypeName(yamlpy.Date{}) != "date" || TypeName([]string{}) != "list" || TypeName(nil) != "NoneType" {
		t.Error("TypeName")
	}
	if !IsInt(big.NewInt(1)) || IsInt(true) || BigInt(1.5) != nil {
		t.Error("IsInt/BigInt")
	}
	if l, ok := List([]string{"a"}); !ok || len(l) != 1 {
		t.Error("List")
	}
	if FloatRepr(1e16) != "1e+16" || FloatRepr(123.0) != "123.0" || FloatRepr(-1.5e-7) != "-1.5e-07" {
		t.Error("FloatRepr")
	}
}
