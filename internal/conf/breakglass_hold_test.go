package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const handHolds = `breakglass_hold:
  sw.lab:
    address: 192.0.2.21
    since: '2026-10-10T14:02:00+00:00'
    by: alice
    reason: hand written
  bare:
    reason: no address
  wrong:
    address: 10.0.0.0/8
    reason: a prefix is not an address
  word:
    address: nope
  text: x
`

// An entry the file holds is a usable hold or is named: a hand-written key
// with a dot is carved and listed (and named), an entry with no address, a
// prefix, or something that is not an address carves nothing.
func TestHoldRecordsAndDefects(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if err := os.WriteFile(p, []byte(handHolds), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Load(p, DefaultBackends)
	hs := c.Holds()
	if len(hs) != 1 || hs[0].Device != "sw.lab" || hs[0].Address != "192.0.2.21" {
		t.Fatalf("usable holds %+v", hs)
	}
	if a := HeldAddresses(c.Merged()); len(a) != 1 || a[0] != "192.0.2.21" {
		t.Errorf("a prefix or a word was carved: %v", a)
	}
	got := map[string]HoldRecord{}
	for _, d := range c.HoldDefects() {
		got[d.Key] = d
	}
	if len(got) != 5 {
		t.Fatalf("defects %+v", got)
	}
	for key, want := range map[string]string{
		"sw.lab": "holds a dot", "bare": "has no address", "wrong": "not one IPv4 or IPv6 address",
		"word": "not one IPv4 or IPv6 address", "text": "is not a record",
	} {
		if d := got[key]; !strings.Contains(d.Defect, want) {
			t.Errorf("%s: %q, want %q", key, d.Defect, want)
		}
	}
	if !got["sw.lab"].Usable || got["bare"].Usable || got["wrong"].Usable {
		t.Errorf("usable: %+v", got)
	}
	if n := len(c.HoldRecordsNamed("bare")); n != 1 {
		t.Errorf("named: %d", n)
	}
}

// A release removes the entry under the key it is stored under, whichever
// spelling, and the mapping goes with the last one.
func TestUnsetHoldRemovesAHandWrittenKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if err := os.WriteFile(p, []byte(handHolds), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Load(p, DefaultBackends)
	// The tacctl spelling of the same device, beside the dotted one.
	if err := c.SetHold(Hold{Device: "sw.lab", Address: "192.0.2.21", Since: "2026-10-10T14:02:00Z", By: "bob", Reason: "again"}); err != nil {
		t.Fatal(err)
	}
	if err := c.UnsetHold("sw.lab"); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(p)
	if strings.Contains(string(text), "sw.lab") || strings.Contains(string(text), "sw~lab") || !strings.Contains(string(text), "bare:") {
		t.Errorf("after the release:\n%s", text)
	}
	if len(Load(p, DefaultBackends).Holds()) != 0 {
		t.Error("a hold is left")
	}
	// The unusable ones go by name too, and the last one takes the mapping
	// and the file.
	for _, n := range []string{"bare", "wrong", "word", "text"} {
		if err := c.UnsetHold(n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(p); err == nil {
		again, _ := os.ReadFile(p)
		t.Errorf("the file is left:\n%s", again)
	}
	// Nothing to remove writes nothing.
	if err := c.UnsetHold("nosuch"); err != nil {
		t.Fatal(err)
	}
}

// The check of a hold runs under the file's lock, on the file as it is: a
// writer whose own view is stale is still refused, and nothing is written.
func TestSetHoldIfChecksTheFileUnderTheLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	stale := Load(p, DefaultBackends)
	first := Load(p, DefaultBackends)
	h := Hold{Device: "sw-1", Address: "192.0.2.21", Since: "2026-10-10T14:02:00Z", By: "alice", Reason: "first"}
	refuse := func(existing []Hold) error {
		for _, x := range existing {
			if x.Device == h.Device {
				return errors.New("held already")
			}
		}
		return nil
	}
	if err := first.SetHoldIf(h, refuse); err != nil {
		t.Fatal(err)
	}
	if len(stale.Holds()) != 0 {
		t.Fatal("the stale view saw the write")
	}
	second := h
	second.By, second.Reason = "bob", "second"
	if err := stale.SetHoldIf(second, refuse); err == nil || err.Error() != "held already" {
		t.Fatalf("the second hold: %v", err)
	}
	got := Load(p, DefaultBackends).Holds()
	if len(got) != 1 || got[0].By != "alice" || got[0].Reason != "first" {
		t.Errorf("the first hold was overwritten: %+v", got)
	}
}

// Several writers at once: exactly one hold of a device is made.
func TestSetHoldIfOnlyOneWriterWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	const n = 8
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := Load(p, DefaultBackends)
			h := Hold{Device: "sw-1", Address: "192.0.2.21", Since: "2026-10-10T14:02:00Z", By: "user" + strconv.Itoa(i), Reason: "r"}
			err := c.SetHoldIf(h, func(existing []Hold) error {
				if len(existing) > 0 {
					return errors.New("held already")
				}
				return nil
			})
			if err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Errorf("%d holds were made", won.Load())
	}
	if got := Load(p, DefaultBackends).Holds(); len(got) != 1 {
		t.Errorf("records %+v", got)
	}
}

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

// Several holds in one write: each is checked under the lock against the file
// and against those accepted before it; the refused are returned, the rest
// written together, and UnsetHolds takes several away in one write, leaving
// the file as it was.
func TestSetHoldsIfWritesTheAcceptedAndUnsetHoldsReleasesThem(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := Load(p, DefaultBackends)
	if err := c.Set("exec_timeout.lab", "30"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	mk := func(dev, addr, reason string) Hold {
		return Hold{Device: dev, Address: addr, Since: "2026-10-10T14:02:00Z", By: "alice", Reason: reason}
	}
	// A record made meanwhile by another writer: the stale view does not see it.
	stale := Load(p, DefaultBackends)
	if err := c.SetHold(mk("sw-3", "192.0.2.23", "earlier")); err != nil {
		t.Fatal(err)
	}
	if len(stale.Holds()) != 0 {
		t.Fatal("the stale view saw the write")
	}
	check := func(existing []Hold, h Hold) error {
		for _, x := range existing {
			if x.Device == h.Device || x.Address == h.Address {
				return errors.New("held already: " + x.Device)
			}
		}
		return nil
	}
	got, skipped, err := stale.SetHoldsIf([]Hold{
		mk("sw-1", "192.0.2.21", "first"),
		mk("sw-3", "192.0.2.23", "raced"),
		mk("sw-2", "192.0.2.22", "second"),
		mk("sw-4", "192.0.2.21", "same address as the first"),
	}, check)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Device != "sw-1" || got[1].Device != "sw-2" {
		t.Errorf("written %+v", got)
	}
	if len(skipped) != 2 || skipped[0].Hold.Device != "sw-3" || skipped[1].Hold.Device != "sw-4" ||
		skipped[0].Err.Error() != "held already: sw-3" || skipped[1].Err.Error() != "held already: sw-1" {
		t.Errorf("skipped %+v", skipped)
	}
	holds := Load(p, DefaultBackends).Holds()
	if len(holds) != 3 || holds[0].Reason != "first" || holds[1].Reason != "second" || holds[2].Reason != "earlier" {
		t.Errorf("records %+v", holds)
	}
	// Nothing accepted: nothing is written.
	text, _ := os.ReadFile(p)
	got, skipped, err = c.SetHoldsIf([]Hold{mk("sw-1", "192.0.2.21", "again")}, check)
	if err != nil || len(got) != 0 || len(skipped) != 1 {
		t.Errorf("nothing accepted: %+v %+v %v", got, skipped, err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(text) {
		t.Error("a call that accepted nothing changed the file")
	}
	// One that fails the schema fails the call whole.
	bad := mk("sw-9", "192.0.2.29", "")
	if got, skipped, err = c.SetHoldsIf([]Hold{mk("sw-8", "192.0.2.28", "ok"), bad}, nil); err == nil || got != nil || skipped != nil {
		t.Errorf("an empty reason: %+v %+v %v", got, skipped, err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(text) {
		t.Error("a refused call changed the file")
	}
	// Released together; an unknown name is ignored.
	if err := c.UnsetHolds([]string{"sw-1", "sw-2", "sw-3", "nosuch"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Errorf("not byte-identical after the release:\n%s\nwas:\n%s", after, before)
	}
	if err := c.UnsetHolds([]string{"sw-1"}); err != nil {
		t.Errorf("releasing none: %v", err)
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
