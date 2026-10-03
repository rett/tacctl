package model_test

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

func TestJSONLikePython(t *testing.T) {
	// Expected strings are json.dumps(v, sort_keys=True) of python3.12.
	v := yamlpy.NewMap(
		"b", []any{1, 2.5, nil, true, false, "x"},
		"a", "q\"\\/\n\r\t\b\f\x01\x7f\u00fc\u2028\U0001F600",
		"c", yamlpy.NewMap(),
		"d", []any{},
		"e", []string{"s"},
		"f", []any{math.NaN(), math.Inf(1), math.Inf(-1), 1e16, 3.0},
	)
	got, err := model.JSON(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a": "q\"\\/\n\r\t\b\f\u0001\u007f\u00fc\u2028\ud83d\ude00", "b": [1, 2.5, null, true, false, "x"], ` +
		`"c": {}, "d": [], "e": ["s"], "f": [NaN, Infinity, -Infinity, 1e+16, 3.0]}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got, err = model.JSONIndent(yamlpy.NewMap("z", []any{1, yamlpy.NewMap("k", []any{})}, "a", yamlpy.NewMap()), 4)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n    \"a\": {},\n    \"z\": [\n        1,\n        {\n            \"k\": []\n        }\n    ]\n}"; got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if _, err := model.JSON(yamlpy.Date{Year: 2026, Month: 1, Day: 1}); !errors.Is(err, model.ErrNotJSON) {
		t.Errorf("date: %v", err)
	}
}

func TestStoreJSONAndShowRefuseDates(t *testing.T) {
	// A YAML date outside password_changed: 0.1.16's json.dumps raised.
	p := filepath.Join(t.TempDir(), "store.yaml")
	if err := os.WriteFile(p, []byte("version: 1\nscopes: {lab: {prefixes: [10.0.0.0/8], secret: 2026-01-01}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.StoreJSON(s); !errors.Is(err, model.ErrNotJSON) {
		t.Error(err)
	}
	if _, err := model.ShowJSON(s); err == nil {
		t.Error("ShowJSON")
	}
	if _, err := model.ShowYAML(s); err == nil {
		t.Error("ShowYAML")
	}
	if _, _, err := model.Get(s, "scopes", "lab"); err == nil {
		t.Error("Get entry")
	}
	s2, _ := store.Load(fixtures + "store.minimal.yaml")
	j, err := model.StoreJSON(s2)
	if err != nil || !strings.HasPrefix(j, `{"filters": {"allow": [], "deny": []}, "groups": {"operator": {"builtin": true,`) {
		t.Error(j, err)
	}
}

func TestViewArgumentErrors(t *testing.T) {
	_, m := load(t, fixtures+"store.minimal.yaml")
	for _, v := range []string{"has", "user-info", "user-privlvl", "group-users", "scope-prefixes", "scope-users",
		"prefix-owner", "scope-devices", "device-problems", "scope-lookup", "linux-users", "status"} {
		if _, code, err := m.View(v); err == nil || code != 1 {
			t.Errorf("%s without arguments: %v", v, err)
		}
	}
	if _, _, err := m.View("status", "x"); err == nil {
		t.Error("status x")
	}
	if _, _, err := m.View("vendor-gaps", "lab=x"); err == nil {
		t.Error("vendor-gaps lab=x")
	}
	if _, _, err := model.Get(&store.Store{}, "nope"); err == nil {
		t.Error("unknown kind")
	}
}

func TestLoadStoreError(t *testing.T) {
	if _, _, err := model.LoadStore(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("loaded a missing store")
	}
}
