package conf

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// forEachRecord decodes every line of testdata/<name> (written by
// testdata/gen.py from tacctl 0.1.16) into a fresh T and calls fn.
func forEachRecord[T any](t *testing.T, name string, fn func(line int, rec T)) int {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	n := 0
	for sc.Scan() {
		n++
		var rec T
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("%s:%d: %v", name, n, err)
		}
		fn(n, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

// fromJSON reads a corpus value: json.loads semantics (order kept, big
// integers), then the conventions {"$date": ...} and {"$float": ...}.
func fromJSON(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	if raw == nil {
		return nil
	}
	v, err := py.Loads(string(raw))
	if err != nil {
		t.Fatalf("corpus value %s: %v", raw, err)
	}
	return special(t, v)
}

func special(t *testing.T, v any) any {
	switch x := v.(type) {
	case *yamlpy.Map:
		if x.Len() == 1 {
			if d, ok := x.Get("$date"); ok {
				tm, err := time.Parse("2006-01-02", d.(string))
				if err != nil {
					t.Fatal(err)
				}
				return yamlpy.Date{Year: tm.Year(), Month: tm.Month(), Day: tm.Day()}
			}
			if f, ok := x.Get("$float"); ok {
				switch f {
				case "nan":
					return math.NaN()
				case "inf":
					return math.Inf(1)
				case "-inf":
					return math.Inf(-1)
				}
			}
		}
		out := yamlpy.NewMap()
		for k, val := range x.All() {
			out.Set(k, special(t, val))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = special(t, val)
		}
		return out
	}
	return v
}

// tempConf is a Config on a file in a fresh directory (no chown).
func tempConf(t *testing.T) *Config {
	t.Helper()
	c := Load(filepath.Join(t.TempDir(), "tacctl.yaml"), DefaultBackends)
	c.Owner = nil
	return c
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
