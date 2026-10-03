package yamlpy

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecodeCorpus compares Decode with what PyYAML's safe_load made of
// every testdata/decode/<case>.yaml (tests/tools/pyyaml-corpus.py).
func TestDecodeCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/decode/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no decode cases: %v", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			want := loadJSONCase(t, strings.TrimSuffix(f, ".yaml")+".json")
			got, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !Equal(got, want) {
				g, _ := Emit(got, ConfOptions)
				w, _ := Emit(want, ConfOptions)
				t.Errorf("Decode differs from safe_load:\n%s", firstDiff(w, g))
			}
		})
	}
}

// TestCorpusReadsBack is the write-time self-check over the whole emitter
// corpus: PyYAML's bytes, read with Decode, give the value back.
func TestCorpusReadsBack(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(*corpusDir, "*.json"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		data := loadJSONCase(t, f)
		for _, m := range corpusModes {
			raw, err := os.ReadFile(filepath.Join(*corpusDir, name+"."+m.name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(raw)
			if err != nil {
				t.Errorf("%s/%s: Decode: %v", name, m.name, err)
				continue
			}
			if !Equal(got, data) {
				t.Errorf("%s/%s: does not read back as the case's data", name, m.name)
			}
			if _, err := EmitChecked(data, m.opts, "# header\n\n"); err != nil {
				t.Errorf("%s/%s: EmitChecked: %v", name, m.name, err)
			}
		}
	}
}

func TestDecodeValues(t *testing.T) {
	cases := []struct {
		in   string
		want any
	}{
		{"", nil},
		{"# only\n# comments\n", nil},
		{"---\n", nil},
		{"yes", true},
		{"Off", false},
		{"0123", 83},
		{"08", "08"},
		{"1_000", 1000},
		{"0x1f", 31},
		{"-0b11", -3},
		{"1:30", 90},
		{"-9223372036854775808", math.MinInt64},
		{"1e3", "1e3"},
		{"1.5", 1.5},
		{"-.inf", math.Inf(-1)},
		{"2026-10-01", Date{2026, 10, 1}},
		{"'2026-10-01'", "2026-10-01"},
		{"!!timestamp 2026-1-5", Date{2026, 1, 5}},
		{"~", nil},
		{"=: x", NewMap("=", "x")},
		{"a: 1\nb: 2\na: 3\n", NewMap("a", 3, "b", 2)},
		{"[a, {b: c}]", []any{"a", NewMap("b", "c")}},
	}
	for _, c := range cases {
		got, err := Decode([]byte(c.in))
		if err != nil {
			t.Errorf("Decode(%q): %v", c.in, err)
			continue
		}
		if !Equal(got, c.want) {
			t.Errorf("Decode(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestDecodeRefuses(t *testing.T) {
	unsupported := []string{
		"a: &x [1]\nb: *x\n",            // alias
		"a: {x: 1}\nb:\n  <<: {y: 2}\n", // merge key
		"1: one\n",                      // int key
		"yes: true\n",                   // bool key
		"~: x\n",                        // null key
		"? [a]\n: b\n",                  // collection key
		"a: =\n",                        // value indicator as a value
		"a: 2026-10-01 12:00:00\n",      // timestamp with a time
		"a: 2026-02-30\n",               // invalid date (datetime.date raises)
		"a: 99999999999999999999\n",
		"a: !!binary aGVsbG8=\n",
		"a: !custom x\n",
		"!!set {a, b}\n",
	}
	for _, in := range unsupported {
		if _, err := Decode([]byte(in)); !errors.Is(err, ErrUnsupportedValue) {
			t.Errorf("Decode(%q): err = %v, want ErrUnsupportedValue", in, err)
		}
	}
	for _, in := range []string{"a: [1\n", "a: 1\n---\nb: 2\n", "\ta: 1\n"} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%q): no error", in)
		}
	}
}
