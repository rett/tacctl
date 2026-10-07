package snmpcred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTripModeAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snmp.yaml")
	if c, err := Load(path); err != nil || !c.Empty() {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	want := Creds{Community: "c0mm: un'ity #x", User: "alice", AuthPass: "auth pass\"1", PrivPass: "yes"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	got, err := Load(path)
	if err != nil || got != want {
		t.Errorf("round trip: %+v %v", got, err)
	}
	if !got.HasV3() {
		t.Error("HasV3")
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), Header) || !strings.Contains(string(data), "version: 1\n") {
		t.Errorf("text:\n%s", data)
	}
	// No temporary file is left beside it.
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Errorf("%d files in the directory", len(ents))
	}
	if err := Save(path, Creds{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("empty credentials left the file: %v", err)
	}
	if err := Save(path, Creds{}); err != nil {
		t.Errorf("removing a missing file: %v", err)
	}
}

func TestLoadRefusesWhatItDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	for text, want := range map[string]string{
		"version: 2\n":                      "unsupported version",
		"version: 1\nfrob: x\n":             "unknown key 'frob'",
		"version: 1\ncommunity: [a]\n":      "community must be text",
		"version: 1\nv3: x\n":               "v3 must be a mapping",
		"version: 1\nv3: {user: a, x: b}\n": "unknown key 'v3.x'",
		"- a\n":                             "expected a mapping",
		"version: [\n":                      "not valid YAML",
	} {
		path := filepath.Join(dir, "snmp.yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
}
