package snmpcred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func poolStore(t *testing.T) Store {
	t.Helper()
	root := t.TempDir()
	s := Store{File: filepath.Join(root, "snmp.yaml"), Dir: filepath.Join(root, "snmp")}
	u := func(n string) Creds { return Creds{Users: []User{{n, n + "-auth-1", n + "-priv-1"}}, Default: n} }
	if err := Save(s.File, u("alice")); err != nil {
		t.Fatal(err)
	}
	for scope, user := range map[string]string{"lab": "carol", "prod": "bob"} {
		if err := SaveScope(s.Dir, scope, u(user)); err != nil {
			t.Fatal(err)
		}
	}
	for dev, user := range map[string]string{"sw1": "dave", "sw2": "monitor"} {
		if err := SaveDevice(s.Dir, dev, u(user), true); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestPeers(t *testing.T) {
	s := poolStore(t)
	holds := func(name string, at Level, scope string, devs []string) string {
		t.Helper()
		peers, err := s.Peers(at, scope, devs)
		if err != nil {
			t.Fatal(err)
		}
		if l, ok := Holder(name, peers); ok {
			return l.Label()
		}
		return ""
	}
	// A user of the config cannot be added to a scope or a device; a name is
	// free where no device or scope below or above can see it.
	for _, tc := range []struct {
		name  string
		at    Level
		scope string
		devs  []string
		want  string
	}{
		{"alice", Level{Kind: LevelScope, Name: "lab"}, "", nil, "the config"},
		{"alice", Level{Kind: LevelDevice, Name: "sw9"}, "lab", nil, "the config"},
		{"carol", Level{Kind: LevelDevice, Name: "sw9"}, "lab", nil, "scope lab"},
		{"carol", Level{Kind: LevelDevice, Name: "sw9"}, "prod", nil, ""},
		{"carol", Level{Kind: LevelDevice, Name: "sw9"}, "", nil, ""},
		{"dave", Level{Kind: LevelScope, Name: "lab"}, "", []string{"sw1"}, "device sw1"},
		{"dave", Level{Kind: LevelScope, Name: "prod"}, "", []string{"sw3"}, ""},
		{"carol", Level{Kind: LevelDefault}, "", nil, "scope lab"},
		{"monitor", Level{Kind: LevelDefault}, "", nil, "device sw2"},
		{"fresh", Level{Kind: LevelDefault}, "", nil, ""},
		// The level itself is not a peer: the same name is a replacement.
		{"alice", Level{Kind: LevelDefault}, "", nil, ""},
		{"carol", Level{Kind: LevelScope, Name: "lab"}, "", nil, ""},
	} {
		if got := holds(tc.name, tc.at, tc.scope, tc.devs); got != tc.want {
			t.Errorf("%s at %v (scope %q, devices %v): held by %q, want %q", tc.name, tc.at, tc.scope, tc.devs, got, tc.want)
		}
	}
	// A pool that cannot be read is an error, not a free name.
	if err := writeRaw(s.Dir, "lab.yaml", "version: 9\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peers(Level{Kind: LevelDefault}, "", nil); err == nil || !strings.Contains(err.Error(), "lab.yaml") {
		t.Errorf("unreadable pool: %v", err)
	}
}

func TestReferrers(t *testing.T) {
	s := poolStore(t)
	// sw1 chooses the config's user and sw2 its scope's; sw3 has its own.
	if err := SaveDevice(s.Dir, "sw1", Creds{Default: "alice"}, true); err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(s.Dir, "sw2", Creds{Default: "carol"}, true); err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(s.Dir, "sw3", Creds{Users: []User{{"monitor", "a", "b"}}, Default: "monitor"}, true); err != nil {
		t.Fatal(err)
	}
	labels := func(name string, at Level, devs []string) string {
		t.Helper()
		ls, err := s.Referrers(name, at, devs)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, l := range ls {
			out = append(out, l.Label())
		}
		return strings.Join(out, ",")
	}
	if got := labels("alice", Level{Kind: LevelDefault}, nil); got != "device sw1" {
		t.Errorf("config user: %q", got)
	}
	if got := labels("carol", Level{Kind: LevelScope, Name: "lab"}, []string{"sw1", "sw2"}); got != "device sw2" {
		t.Errorf("scope user: %q", got)
	}
	if got := labels("monitor", Level{Kind: LevelDevice, Name: "sw3"}, nil); got != "" {
		t.Errorf("device user: %q", got)
	}
	if got := labels("carol", Level{Kind: LevelScope, Name: "lab"}, []string{"sw1"}); got != "" {
		t.Errorf("a device outside the list: %q", got)
	}
}

func TestLevelLabelsAndPaths(t *testing.T) {
	s := poolStore(t)
	for l, want := range map[Level]string{
		{Kind: LevelDefault}:             "the config",
		{Kind: LevelScope, Name: "lab"}:  "scope lab",
		{Kind: LevelDevice, Name: "sw1"}: "device sw1",
	} {
		if l.Label() != want {
			t.Errorf("%v: %q", l, l.Label())
		}
		if _, err := s.Path(l); err != nil {
			t.Error(err)
		}
		c, err := s.Load(l)
		if err != nil || len(c.Users) != 1 {
			t.Errorf("%v: %+v %v", l, c, err)
		}
	}
}

func writeRaw(dir, name, text string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600)
}
