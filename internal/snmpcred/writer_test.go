package snmpcred

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// parse0222 is the reader of 0.2.22 and before, as they have it: strict, one
// v3 user, version 1 only. A file the writer says an older release can read is
// read with it (the real binaries do the same in the tests of internal/cli).
func parse0222(data []byte) (Creds, error) {
	var c Creds
	v, err := pyyaml.LoadBytes(data)
	if err != nil {
		return c, err
	}
	if v == nil {
		return c, nil
	}
	root, ok := v.(*yamlpy.Map)
	if !ok {
		return c, errors.New("expected a mapping at the top level")
	}
	str := func(key string, val any) (string, error) {
		s, ok := val.(string)
		if !ok && val != nil {
			return "", errors.New(key + " must be text")
		}
		return s, nil
	}
	var u User
	for k, val := range root.All() {
		switch k {
		case "version":
			if n, ok := val.(int); !ok || n != 1 {
				return c, errors.New("unsupported version (this tacctl reads version 1)")
			}
		case "community":
			if c.Community, err = str(k, val); err != nil {
				return c, err
			}
		case "v3":
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return c, errors.New("v3 must be a mapping (user, auth_passphrase, priv_passphrase)")
			}
			for k3, v3 := range m.All() {
				var dst *string
				switch k3 {
				case "user":
					dst = &u.Name
				case "auth_passphrase":
					dst = &u.AuthPass
				case "priv_passphrase":
					dst = &u.PrivPass
				default:
					return c, errors.New("unknown key 'v3." + k3 + "'")
				}
				if *dst, err = str("v3."+k3, v3); err != nil {
					return c, err
				}
			}
		default:
			return c, errors.New("unknown key '" + k + "'")
		}
	}
	if u.Name != "" {
		c.Users, c.Default = []User{u}, u.Name
	}
	return c, nil
}

// The one writer chooses the format: version 1 whenever the older releases can
// hold the content (the community and at most one v3 user, that user the
// default), version 2 for what they cannot (a second or a non-default user, a
// default that names another level's user) and for a device's file that
// counts without an snmp: entry. Every file it calls version 1 is read by the
// strict reader of 0.2.22; every other is refused by it.
func TestWriterChoosesVersionOneWhenItFits(t *testing.T) {
	alice := User{"alice", "alice-auth-1", "alice-priv-1"}
	bob := User{"bob", "bob-auth-1", "bob-priv-1"}
	for _, tc := range []struct {
		name   string
		c      Creds
		mapped bool // a device that has an snmp: entry
		device bool
		v1     bool
	}{
		{"community only", Creds{Community: "comm"}, true, false, true},
		{"one default user", Creds{Users: []User{alice}, Default: "alice"}, true, false, true},
		{"community and one default user", Creds{Community: "comm", Users: []User{alice}, Default: "alice"}, true, false, true},
		{"one user that is not the default", Creds{Users: []User{alice}}, true, false, false},
		{"two users, one the default", Creds{Users: []User{alice, bob}, Default: "alice"}, true, false, false},
		{"two users, no default", Creds{Users: []User{alice, bob}}, true, false, false},
		{"a default naming another level's user", Creds{Default: "carol"}, true, false, false},
		{"a default naming another level's user, with a community", Creds{Community: "comm", Default: "carol"}, true, false, false},
		{"a device with an entry: community only", Creds{Community: "comm"}, true, true, true},
		{"a device with an entry: one default user", Creds{Users: []User{alice}, Default: "alice"}, true, true, true},
		{"a device with an entry: two users", Creds{Users: []User{alice, bob}, Default: "alice"}, true, true, false},
		{"a device without an entry: community only", Creds{Community: "comm"}, false, true, false},
		{"a device without an entry: one default user", Creds{Users: []User{alice}, Default: "alice"}, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "x.yaml")
			var err error
			if tc.device {
				err = SaveDevice(dir, "sw1", tc.c, tc.mapped)
				path = filepath.Join(dir, DevicesDir, "sw1.yaml")
			} else {
				err = Save(path, tc.c)
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			want := LegacyVersion
			if !tc.v1 {
				want = Version
			}
			if got.Format != want || !strings.Contains(string(data), "version: "+strconv.Itoa(want)) {
				t.Fatalf("format %d, want %d:\n%s", got.Format, want, data)
			}
			if !same(got, tc.c) {
				t.Errorf("read back %+v, wrote %+v", got, tc.c)
			}
			old, oerr := parse0222(data)
			switch {
			case tc.v1 && (oerr != nil || old.Community != tc.c.Community || len(old.Users) != len(tc.c.Users)):
				t.Errorf("0.2.22 cannot read a version 1 file: %+v %v\n%s", old, oerr, data)
			case !tc.v1 && (oerr == nil || !strings.Contains(oerr.Error(), "unsupported version")):
				t.Errorf("0.2.22 reads a version 2 file: %+v %v\n%s", old, oerr, data)
			}
		})
	}
}

// Text is the same choice, FitsLegacy its condition, and the Store takes a
// device's entry from its Mapped (not known: none, so version 2).
func TestWriterTextAndStore(t *testing.T) {
	if !(Creds{}).FitsLegacy() || !(Creds{Community: "c"}).FitsLegacy() || (Creds{Default: "a"}).FitsLegacy() {
		t.Error("FitsLegacy of the empty, the community and a lone default")
	}
	one, _ := Creds{Users: []User{{"alice", "a-pass-1", "p-pass-1"}}, Default: "alice"}.Text()
	two, _ := Creds{Users: []User{{"alice", "a", "p"}, {"bob", "a", "p"}}, Default: "alice"}.Text()
	if !strings.Contains(string(one), "version: 1") || !strings.Contains(string(two), "version: 2") {
		t.Errorf("Text:\n%s\n%s", one, two)
	}
	root := t.TempDir()
	creds := Creds{Community: "comm"}
	for _, tc := range []struct {
		mapped func(string) bool
		want   int
	}{{nil, Version}, {func(string) bool { return false }, Version}, {func(n string) bool { return n == "sw1" }, LegacyVersion}} {
		st := Store{File: filepath.Join(root, "snmp.yaml"), Dir: filepath.Join(root, "snmp"), Mapped: tc.mapped}
		if err := st.Save(Level{Kind: LevelDevice, Name: "sw1"}, creds); err != nil {
			t.Fatal(err)
		}
		got, err := st.Load(Level{Kind: LevelDevice, Name: "sw1"})
		if err != nil || got.Format != tc.want {
			t.Errorf("format %d, want %d (%v)", got.Format, tc.want, err)
		}
	}
	// The config's and a scope's file need no entry.
	st := Store{File: filepath.Join(root, "snmp.yaml"), Dir: filepath.Join(root, "snmp")}
	for _, l := range []Level{{Kind: LevelDefault}, {Kind: LevelScope, Name: "lab"}} {
		if err := st.Save(l, creds); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.Load(l); got.Format != LegacyVersion {
			t.Errorf("%v: format %d", l, got.Format)
		}
	}
}
