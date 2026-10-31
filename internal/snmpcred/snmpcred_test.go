package snmpcred

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTripModeAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snmp.yaml")
	if c, err := Load(path); err != nil || !c.Empty() {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	want := Creds{Community: "c0mm: un'ity #x", Users: []User{{"alice", "auth pass\"1", "yes"}, {"bob: #1", "auth-pass-2", "priv-pass-2"}}, Default: "bob: #1"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	got, err := Load(path)
	if err != nil || !same(got, want) {
		t.Errorf("round trip: %+v %v", got, err)
	}
	if got.Format != Version {
		t.Errorf("format %d", got.Format)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), Header) || !strings.Contains(string(data), "version: 2\n") {
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
		"version: 3\n":                                "unsupported version",
		"version: 1\nfrob: x\n":                       "unknown key 'frob'",
		"version: 1\ncommunity: [a]\n":                "community must be text",
		"version: 1\nv3: x\n":                         "v3 must be a mapping",
		"version: 1\nv3: {user: a, x: b}\n":           "unknown key 'v3.x'",
		"version: 1\nusers: []\n":                     "unknown key 'users'",
		"version: 1\ndefault: a\n":                    "unknown key 'default'",
		"version: 2\nv3: {user: a}\n":                 "unknown key 'v3'",
		"version: 2\nusers: x\n":                      "users must be a list",
		"version: 2\nusers: [x]\n":                    "users[0] must be a mapping",
		"version: 2\nusers: [{name: a, x: b}]\n":      "unknown key 'users[0].x'",
		"version: 2\nusers: [{auth_passphrase: b}]\n": "users[0] has no name",
		"version: 2\nusers: [{name: a}, {name: a}]\n": "the user 'a' is listed twice",
		"version: 2\ndefault: [a]\n":                  "default must be text",
		"- a\n":                                       "expected a mapping",
		"version: [\n":                                "not valid YAML",
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

// same compares credentials by content: the format a file was read in is not
// part of it.
func same(a, b Creds) bool {
	a.Format, b.Format = 0, 0
	return reflect.DeepEqual(a, b)
}

// The rollback writes version 1 again: the community and the default user as
// the one v3 user; the file reads back as a pool of one, the same bytes a
// 0.2.22 reads.
func TestLegacyText(t *testing.T) {
	c := Creds{Community: "comm", Users: []User{{"alice", "a-pass-1", "p-pass-1"}, {"bob", "a-pass-2", "p-pass-2"}}, Default: "bob"}
	text, err := c.LegacyText(DeviceHeader)
	if err != nil {
		t.Fatal(err)
	}
	want := DeviceHeader + "version: 1\ncommunity: comm\nv3: {user: bob, auth_passphrase: a-pass-2, priv_passphrase: p-pass-2}\n"
	if string(text) != want {
		t.Errorf("text:\n%s\nwant:\n%s", text, want)
	}
	path := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Format != LegacyVersion || !same(got, Creds{Community: "comm", Users: []User{{"bob", "a-pass-2", "p-pass-2"}}, Default: "bob"}) {
		t.Errorf("read back: %+v %v", got, err)
	}
	// No default user: no v3 key.
	text, _ = Creds{Community: "comm", Users: c.Users}.LegacyText(Header)
	if strings.Contains(string(text), "v3:") || !strings.Contains(string(text), "version: 1") {
		t.Errorf("no default:\n%s", text)
	}
}

func TestPoolEditing(t *testing.T) {
	var c Creds
	c.Put(User{"a", "x", "y"})
	c.Put(User{"b", "x", "y"})
	c.Put(User{"a", "x2", "y2"})
	if len(c.Users) != 2 || c.Users[0].AuthPass != "x2" || strings.Join(c.Names(), ",") != "a,b" {
		t.Errorf("put: %+v", c)
	}
	c.Default = "a"
	if !c.Drop("a") || c.Default != "" || len(c.Users) != 1 {
		t.Errorf("drop: %+v", c)
	}
	if c.Drop("a") {
		t.Error("dropped twice")
	}
	if u, ok := c.Find("b"); !ok || !u.Complete() {
		t.Errorf("find: %+v %v", u, ok)
	}
	if (User{Name: "z", AuthPass: "x"}).Complete() {
		t.Error("half a user is complete")
	}
	// A default alone is something (a device's choice of its scope's user).
	if (Creds{Default: "a"}).Empty() {
		t.Error("a default is not empty")
	}
}
