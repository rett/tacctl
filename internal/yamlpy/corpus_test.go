package yamlpy

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The modes of tests/tools/pyyaml-corpus.py.
var corpusModes = []struct {
	name string
	opts Options
}{
	{"store", StoreOptions},
	{"conf", ConfOptions},
	{"flow80", Options{FlowLeaves: true}},
}

// corpusDir is the corpus TestCorpus reads; another one (made with
// tests/tools/pyyaml-corpus.py <dir>) can be checked with
// go test ./internal/yamlpy -run TestCorpus -args -corpus=<dir>.
var corpusDir = flag.String("corpus", "testdata/corpus", "directory of <case>.json and <case>.<mode>.yaml")

// TestCorpus emits every testdata/corpus/<case>.json in every mode and
// compares with what PyYAML 6.0.1 wrote (tests/tools/pyyaml-corpus.py).
func TestCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(*corpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus in %s: %v", *corpusDir, err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		data := loadJSONCase(t, f)
		for _, m := range corpusModes {
			t.Run(name+"/"+m.name, func(t *testing.T) {
				want, err := os.ReadFile(filepath.Join(*corpusDir, name+"."+m.name+".yaml"))
				if err != nil {
					t.Fatal(err)
				}
				got, err := Emit(data, m.opts)
				if err != nil {
					t.Fatalf("Emit: %v", err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("differs from PyYAML:\n%s", firstDiff(want, got))
				}
			})
		}
	}
}

// firstDiff describes the first differing line with a little context.
func firstDiff(want, got []byte) string {
	wl := strings.SplitAfter(string(want), "\n")
	gl := strings.SplitAfter(string(got), "\n")
	i := 0
	for i < len(wl) && i < len(gl) && wl[i] == gl[i] {
		i++
	}
	var b strings.Builder
	for j := max(0, i-3); j < i; j++ {
		fmt.Fprintf(&b, "  %4d   %q\n", j+1, wl[j])
	}
	for j := i; j < min(i+3, len(wl)); j++ {
		fmt.Fprintf(&b, "  %4d - %q\n", j+1, wl[j])
	}
	for j := i; j < min(i+3, len(gl)); j++ {
		fmt.Fprintf(&b, "  %4d + %q\n", j+1, gl[j])
	}
	return b.String()
}

// loadJSONCase reads a corpus case keeping object key order, with the
// conventions of pyyaml-corpus.py ($date, $float; a number with a
// fraction or exponent is a float).
func loadJSONCase(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := jsonValue(dec)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: trailing data", path)
	}
	return v
}

func jsonValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch x := tok.(type) {
	case json.Delim:
		switch x {
		case '[':
			out := []any{}
			for dec.More() {
				v, err := jsonValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			_, err := dec.Token()
			return out, err
		case '{':
			m := NewMap()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := jsonValue(dec)
				if err != nil {
					return nil, err
				}
				m.Set(kt.(string), v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return special(m)
		}
		return nil, fmt.Errorf("unexpected %v", x)
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return strconv.ParseFloat(s, 64)
		}
		return strconv.ParseInt(s, 10, 64)
	case string, bool, nil:
		return x, nil
	}
	return nil, fmt.Errorf("unexpected token %T", tok)
}

func special(m *Map) (any, error) {
	if m.Len() != 1 {
		return m, nil
	}
	if v, ok := m.Get("$date"); ok {
		t, err := time.Parse("2006-01-02", v.(string))
		if err != nil {
			return nil, err
		}
		return Date{t.Year(), t.Month(), t.Day()}, nil
	}
	if v, ok := m.Get("$float"); ok {
		switch v {
		case "nan":
			return math.NaN(), nil
		case "inf":
			return math.Inf(1), nil
		case "-inf":
			return math.Inf(-1), nil
		}
		return nil, fmt.Errorf("bad $float %v", v)
	}
	return m, nil
}
