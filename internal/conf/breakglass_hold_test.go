package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHoldSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	ok := map[string]any{
		"breakglass_hold.sw-lab-1.address": "192.0.2.21",
		"breakglass_hold.r1.address":       "2001:db8::5",
		"breakglass_hold.sw-lab-1.since":   "2026-10-10T14:02:00Z",
		"breakglass_hold.sw-lab-1.by":      "alice",
		"breakglass_hold.sw-lab-1.reason":  "console recovery after a failed paste",
	}
	for p, v := range ok {
		if msg := s.Validate(p, v, false); msg != "" {
			t.Errorf("%s=%v refused: %s", p, v, msg)
		}
	}
	for _, c := range []struct {
		path string
		v    any
		want string
	}{
		{"breakglass_hold.sw.address", "192.0.2.0/24", "without a prefix length"},
		{"breakglass_hold.sw.address", "2001:DB8:0::5", "not in its canonical form"},
		{"breakglass_hold.sw.address", "nope", "not a valid IPv4 or IPv6 address"},
		{"breakglass_hold.sw.address", 3, "must be a string"},
		{"breakglass_hold.sw.since", "yesterday", "RFC 3339"},
		{"breakglass_hold.sw.reason", "", "must not be empty"},
		{"breakglass_hold.sw.reason", "a\nb", "control characters"},
		{"breakglass_hold.sw.reason", strings.Repeat("x", 257), "limited to 256"},
		{"breakglass_hold.sw.by", "two words", "blanks"},
		{"breakglass_hold.sw.other", "x", "unknown config key"},
		{"breakglass_hold.sw", "x", "unknown config key"},
		{"breakglass_hold.a.b.address", "192.0.2.1", "unknown config key"},
	} {
		if msg := s.Validate(c.path, c.v, false); !strings.Contains(msg, c.want) {
			t.Errorf("%s=%v: %q, want %q", c.path, c.v, msg, c.want)
		}
	}
	if msg := s.Validate("breakglass_hold.sw.reason", "x", true); !strings.Contains(msg, "does not accept list input") {
		t.Errorf("list: %q", msg)
	}
	if len(strings.Repeat("é", 256)) <= 256 || s.Validate("breakglass_hold.sw.reason", strings.Repeat("é", 256), false) != "" {
		t.Error("256 characters of two bytes each are within the limit")
	}
}

func TestHoldKeyDots(t *testing.T) {
	if HoldKey("sw-1.lab.example") != "sw-1~lab~example" || HoldDevice("sw-1~lab~example") != "sw-1.lab.example" {
		t.Error("the key encoding")
	}
	if HoldPath("a.b", HoldKeyAddress) != "breakglass_hold.a~b.address" {
		t.Error(HoldPath("a.b", HoldKeyAddress))
	}
}

func TestHoldWriteReadAndRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := Load(p, DefaultBackends)
	if err := c.Set("exec_timeout.lab", "30"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	h := Hold{Device: "sw.lab", Address: "192.0.2.21", Since: "2026-10-10T14:02:00+00:00", By: "alice", Reason: "console recovery"}
	if err := c.SetHold(h); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(p)
	if !strings.Contains(string(text), "breakglass_hold:\n  sw~lab:\n    address: 192.0.2.21\n    since: '2026-10-10T14:02:00+00:00'\n") {
		t.Errorf("written as:\n%s", text)
	}
	got := Load(p, DefaultBackends).Holds()
	if len(got) != 1 || got[0] != h {
		t.Errorf("read back %+v", got)
	}
	if got[0].SinceTime().IsZero() {
		t.Error("since does not parse")
	}
	if a := HeldAddresses(Load(p, DefaultBackends).Merged()); len(a) != 1 || a[0] != "192.0.2.21" {
		t.Errorf("addresses %v", a)
	}
	if keys := Load(p, DefaultBackends).HoldKeysOf(); len(keys) != 4 {
		t.Errorf("keys %v", keys)
	}
	// One of the four refused: nothing is written.
	bad := h
	bad.Reason = ""
	if err := c.SetHold(bad); err == nil {
		t.Error("an empty reason was accepted")
	}
	if again, _ := os.ReadFile(p); string(again) != string(text) {
		t.Error("a refused hold changed the file")
	}
	if err := c.UnsetHold("sw.lab"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(before) {
		t.Errorf("not byte-identical after the release:\n%s\nwas:\n%s", after, before)
	}
	if len(Load(p, DefaultBackends).Holds()) != 0 {
		t.Error("a hold is left")
	}
}

func TestHoldFamilyIsAdded025(t *testing.T) {
	for _, k := range []string{"breakglass_hold.sw.address", "breakglass_hold.sw~lab.reason", "breakglass_hold"} {
		if !Added025Key(k) {
			t.Errorf("%s is not a 0.2.5 key", k)
		}
	}
	if Added025Key("breakglass_scope.lab.users") {
		t.Error("breakglass_scope is 0.2.3's")
	}
	if !Unknown023("breakglass_hold.sw.address") {
		t.Error("0.2.3 does not know the hold")
	}
}
