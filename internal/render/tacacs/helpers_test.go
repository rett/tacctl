package tacacs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The repository's fixtures.
var (
	fixDir    = filepath.Join("..", "..", "..", "tests", "fixtures")
	goldenDir = filepath.Join(fixDir, "golden")
	unitsDir  = filepath.Join("..", "..", "..", "config", "backends", "tacacs")
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadStore(t *testing.T, name string) *store.Store {
	t.Helper()
	st, err := store.Load(filepath.Join(fixDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// section returns a section of the store document, for edits.
func section(st *store.Store, name string) *yamlpy.Map {
	v, _ := st.Doc().Get(name)
	return v.(*yamlpy.Map)
}

func entry(st *store.Store, sec, name string) *yamlpy.Map {
	v, _ := section(st, sec).Get(name)
	return v.(*yamlpy.Map)
}

// viewOf is the merged tacctl.yaml view of text ("" for no file).
func viewOf(t *testing.T, text string) *conf.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if text != "" {
		writeFile(t, p, text)
	}
	return conf.Load(p, conf.DefaultBackends)
}

func defaultView(t *testing.T) *yamlpy.Map { return viewOf(t, "").Merged() }

// render is Render that must succeed.
func render(t *testing.T, st *store.Store, view *yamlpy.Map) []byte {
	t.Helper()
	out, err := Render(st, view)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// renderFile is RenderToFile into a temp dir with the test loader.
func renderFile(t *testing.T, st *store.Store, view *yamlpy.Map) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "rendered.yaml")
	_, err := RenderToFile(st, view, out, DefaultLoader, func(string) {})
	return out, err
}

// decoded is the rendered text as yaml.v3 decodes it.
func decoded(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var d map[string]any
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func usersOf(d map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	l, _ := d["users"].([]any)
	for _, u := range l {
		m := u.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

func diffText(t *testing.T, got, want []byte, what string) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	gl, wl := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("%s differs at line %d:\n got: %q\nwant: %q", what, i+1, g, w)
		}
	}
	t.Fatalf("%s differs", what)
}
