package devreg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The per-device NETCONF service setting of D145 (docs/plans/0.2.10-
// plan.md): the optional 'netconf:' map of a Junos device in devices.yaml.

const sampleNetconf = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco}
  lab-rtr1:
    address: 192.0.2.7
    vendor: juniper
    netconf:
      state: enable
      connection_limit: 5
      rate_limit: 10
  lab-rtr2:
    address: 192.0.2.8
    vendor: juniper
    netconf: {state: leave}
  lab-rtr3:
    address: 192.0.2.9
    vendor: juniper
    netconf: {state: disable}
  lab-rtr4: {address: 192.0.2.10, vendor: juniper}
`

func TestNetconfMapRoundTrip(t *testing.T) {
	f, p := loadText(t, sampleNetconf)
	want := map[string]Netconf{
		"core-sw1": {},
		"lab-rtr1": {State: NetconfEnable, ConnectionLimit: 5, RateLimit: 10},
		"lab-rtr2": {State: NetconfLeave},
		"lab-rtr3": {State: NetconfDisable},
		"lab-rtr4": {},
	}
	for name, w := range want {
		if d := f.Find(name); d == nil || d.Netconf != w {
			t.Errorf("%s: %+v, want %+v", name, d, w)
		}
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	// written only when set, in the order the file has
	if strings.Contains(strings.SplitAfter(string(text), "core-sw1")[1][:80], "netconf") {
		t.Errorf("a device without a setting has the map:\n%s", text)
	}
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v\n%s", err, text)
	}
	for name, w := range want {
		if d := again.Find(name); d == nil || d.Netconf != w {
			t.Errorf("after a round trip %s: %+v, want %+v", name, d, w)
		}
	}
}

func TestNetconfMapIsValidated(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"a state of its own":       {"vendor: juniper\n    netconf: {state: maybe}", "Invalid netconf state 'maybe'"},
		"a limit too high":         {"vendor: juniper\n    netconf: {state: enable, connection_limit: 251}", "Invalid netconf connection_limit 251"},
		"a limit too low":          {"vendor: juniper\n    netconf: {state: enable, rate_limit: -1}", "Invalid netconf rate_limit -1"},
		"a limit alone":            {"vendor: juniper\n    netconf: {rate_limit: 5}", "needs a state"},
		"another vendor":           {"vendor: cisco\n    netconf: {state: enable}", "netconf is a Junos setting; the vendor is 'cisco'"},
		"an unknown key":           {"vendor: juniper\n    netconf: {state: enable, port: 830}", "unknown key 'port'"},
		"not a mapping":            {"vendor: juniper\n    netconf: enable", "netconf must be a mapping"},
		"a state that is a number": {"vendor: juniper\n    netconf: {state: 3}", "invalid 'state'"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "devices.yaml")
			text := Header + "version: 1\nsettings: {stale_days: 30}\ndevices:\n  x1:\n    address: 192.0.2.7\n    " + tc.body + "\n"
			if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if err == nil || !strings.Contains(strings.Join(msgs(err), " "), tc.want) {
				t.Errorf("Load: %v, want %q", err, tc.want)
			}
		})
	}
}

// The bounds of the setting are the scope's (internal/conf): a copy that
// drifts would let a device hold what its scope refuses.
func TestNetconfBoundsAreTheScopes(t *testing.T) {
	if NetconfMinLimit != 1 || NetconfMaxLimit != 250 {
		t.Errorf("the bounds are %d-%d; internal/conf has 1-250", NetconfMinLimit, NetconfMaxLimit)
	}
}

func TestNetconfJSONAndImport(t *testing.T) {
	f, _ := loadText(t, sampleNetconf)
	d := f.Find("lab-rtr1")
	j, err := JSON([]Device{*d, *f.Find("core-sw1")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"netconf": {`) || !strings.Contains(string(j), `"connection_limit": 5`) ||
		strings.Count(string(j), `"netconf"`) != 1 {
		t.Errorf("the JSON of a device with and one without:\n%s", j)
	}
	// An import of a file that says nothing of the setting keeps it (a CSV
	// has no column for it), and moves nothing to a vendor that has none.
	rows, err := ParseImport([]byte("lab-rtr1,192.0.2.7,juniper\ncore-sw1,10.99.0.1,cisco\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("lab-rtr1").Netconf; got != (Netconf{State: NetconfEnable, ConnectionLimit: 5, RateLimit: 10}) {
		t.Errorf("the import dropped the setting: %+v", got)
	}
}

func TestRollbackNetconf(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(p, []byte(sampleNetconf), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := NetconfSet(p)
	if err != nil || !reflect.DeepEqual(names, []string{"lab-rtr1", "lab-rtr2", "lab-rtr3"}) {
		t.Fatalf("NetconfSet: %q %v", names, err)
	}
	ran := 0
	cleared, err := RollbackNetconf(p, func() error { ran++; return nil })
	if err != nil || ran != 1 || !reflect.DeepEqual(cleared, names) {
		t.Fatalf("RollbackNetconf: %q %v (snapshots %d)", cleared, err, ran)
	}
	got, _ := os.ReadFile(p)
	if strings.Contains(string(got), "netconf") {
		t.Errorf("the key is still there:\n%s", got)
	}
	f, err := Load(p)
	if err != nil || f.Find("lab-rtr1") == nil || f.Find("lab-rtr1").Address != "192.0.2.7" {
		t.Errorf("the rest of the device is not kept: %v", err)
	}
	// idempotent, and a missing registry is not created
	ran = 0
	if cleared, err = RollbackNetconf(p, func() error { ran++; return nil }); err != nil || len(cleared) != 0 || ran != 0 {
		t.Errorf("second run: %q %v (snapshots %d)", cleared, err, ran)
	}
	missing := filepath.Join(dir, "sub", "devices.yaml")
	if cleared, err := RollbackNetconf(missing, nil); err != nil || len(cleared) != 0 {
		t.Errorf("missing: %q %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing registry was created: %v", err)
	}
}
