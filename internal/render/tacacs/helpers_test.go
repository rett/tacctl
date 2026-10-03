package tacacs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/model"
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

// A test stand-in for the importer (model.LegacyLoad, WP1.4b): it reads
// the layout Render writes with yaml.v3 (tacquito's library), taking every
// scalar as its text, and reports nothing. That is enough to tell a file
// that says what the model says from one that does not.

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return resolve(n.Content[0])
	}
	return n
}

func field(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return resolve(n.Content[i+1])
		}
	}
	return nil
}

func items(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, len(n.Content))
	for i, c := range n.Content {
		out[i] = resolve(c)
	}
	return out
}

func text(n *yaml.Node) string {
	if n = resolve(n); n == nil {
		return ""
	}
	return n.Value
}

func strs(n *yaml.Node) []any {
	out := []any{}
	for _, c := range items(n) {
		out = append(out, c.Value)
	}
	return out
}

func testLoad(path string) (*LegacyResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	top := resolve(&doc)
	groups, users, scopes := yamlpy.NewMap(), yamlpy.NewMap(), yamlpy.NewMap()
	for i := 0; i+1 < len(top.Content); i += 2 {
		v := resolve(top.Content[i+1])
		if v.Kind != yaml.MappingNode || field(v, "services") == nil {
			continue
		}
		g := yamlpy.NewMap()
		for _, svc := range items(field(v, "services")) {
			vals := items(field(items(field(svc, "set_values"))[0], "values"))
			switch text(field(svc, "name")) {
			case "shell":
				g.Set("priv_lvl", mustAtoi(vals[0].Value))
			case "junos-exec":
				g.Set("juniper_class", vals[0].Value)
			}
		}
		groups.Set(text(field(v, "name")), g)
	}
	for _, u := range items(field(top, "users")) {
		h := text(field(field(field(u, "authenticator"), "options"), "hash"))
		disabled := h == hash.DisabledMarkerHex
		var hv any = h
		if disabled {
			hv = nil
		}
		users.Set(text(field(u, "name")), yamlpy.NewMap(
			"group", text(field(items(field(u, "groups"))[0], "name")),
			"scopes", strs(field(u, "scopes")),
			"hash", hv, "disabled", disabled))
	}
	for _, s := range items(field(top, "secrets")) {
		name := text(field(s, "name"))
		var prefixes []string
		if err := json.Unmarshal([]byte(text(field(field(s, "options"), "prefixes"))), &prefixes); err != nil {
			return nil, err
		}
		cur, ok := scopes.Get(name)
		if !ok {
			cur = yamlpy.NewMap("prefixes", []any{}, "secret", text(field(field(s, "secret"), "key")))
			scopes.Set(name, cur)
		}
		m := cur.(*yamlpy.Map)
		pl, _ := m.Get("prefixes")
		for _, p := range prefixes {
			pl = append(pl.([]any), p)
		}
		m.Set("prefixes", pl)
	}
	doc2 := yamlpy.NewMap("version", 1, "groups", groups, "users", users, "scopes", scopes,
		"filters", yamlpy.NewMap("allow", strs(field(top, "prefix_allow")), "deny", strs(field(top, "prefix_deny"))))
	st, err := store.Normalize(doc2)
	if err != nil {
		return nil, err
	}
	return &LegacyResult{Model: model.FromStore(st)}, nil
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

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
	_, err := RenderToFile(st, view, out, testLoad, func(string) {})
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
