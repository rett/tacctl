package devreg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devssh"
)

// The per-device timing scale of 0.2.22: the optional 'timeout_scale:' key of
// a device in devices.yaml, a whole number from 1 to 10.

const sampleTimeoutScale = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco}
  sat-rtr1:
    address: 192.0.2.7
    vendor: juniper
    timeout_scale: 3
  sat-sw2:
    address: 192.0.2.8
    vendor: cisco
    timeout_scale: 10
`

func TestTimeoutScaleRoundTrip(t *testing.T) {
	f, p := loadText(t, sampleTimeoutScale)
	want := map[string]int{"core-sw1": 0, "sat-rtr1": 3, "sat-sw2": 10}
	for name, w := range want {
		if d := f.Find(name); d == nil || d.TimeoutScale != w {
			t.Errorf("%s: %+v, want %d", name, d, w)
		}
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	// written only when set
	if strings.Count(string(text), "timeout_scale") != 2 {
		t.Errorf("the key is written for a device without one, or not for the others:\n%s", text)
	}
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v\n%s", err, text)
	}
	for name, w := range want {
		if d := again.Find(name); d == nil || d.TimeoutScale != w {
			t.Errorf("after a round trip %s: %+v, want %d", name, d, w)
		}
	}
}

func TestTimeoutScaleIsValidated(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"too high":      {"timeout_scale: 11", "Invalid timeout_scale 11: expected 1-10."},
		"negative":      {"timeout_scale: -2", "Invalid timeout_scale -2: expected 1-10."},
		"zero":          {"timeout_scale: 0", "invalid 'timeout_scale'"},
		"not a number":  {"timeout_scale: fast", "invalid 'timeout_scale'"},
		"a fraction":    {"timeout_scale: 2.5", "invalid 'timeout_scale'"},
		"a string":      {"timeout_scale: '3'", "invalid 'timeout_scale'"},
		"another key":   {"timeout: 3", "unknown key 'timeout'"},
		"a null":        {"timeout_scale:", "invalid 'timeout_scale'"},
		"a mapping":     {"timeout_scale: {n: 3}", "invalid 'timeout_scale'"},
		"a list":        {"timeout_scale: [3]", "invalid 'timeout_scale'"},
		"a boolean":     {"timeout_scale: true", "invalid 'timeout_scale'"},
		"the top bound": {"timeout_scale: 10", ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "devices.yaml")
			text := Header + "version: 1\nsettings: {stale_days: 30}\ndevices:\n  x1:\n    address: 192.0.2.7\n    " + tc.body + "\n"
			if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if tc.want == "" {
				if err != nil {
					t.Errorf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(strings.Join(msgs(err), " "), tc.want) {
				t.Errorf("Load: %v, want %q", err, tc.want)
			}
		})
	}
}

// A device is validated when it is set through the registry too (a setter
// that passes a number outside the bounds is refused before anything is
// written).
func TestTimeoutScaleOfADeviceIsCheckedOnWrite(t *testing.T) {
	f, _ := loadText(t, sampleTimeoutScale)
	f.Find("core-sw1").TimeoutScale = 11
	if _, err := f.Text(); err == nil || !strings.Contains(strings.Join(msgs(err), " "), "Invalid timeout_scale 11") {
		t.Errorf("Text: %v", err)
	}
}

// The bounds are the scale's (internal/devssh, internal/conf): a copy that
// drifts would let a device hold what its scope refuses.
func TestTimeoutScaleBoundsAreTheScales(t *testing.T) {
	if devssh.MinTimeoutScale != 1 || devssh.MaxTimeoutScale != 10 {
		t.Errorf("devssh has %d-%d; the documented bounds are 1-10", devssh.MinTimeoutScale, devssh.MaxTimeoutScale)
	}
}

func TestTimeoutScaleJSONAndImport(t *testing.T) {
	f, _ := loadText(t, sampleTimeoutScale)
	j, err := JSON([]Device{*f.Find("sat-rtr1"), *f.Find("core-sw1")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"timeout_scale": 3`) || strings.Count(string(j), `"timeout_scale"`) != 1 {
		t.Errorf("the JSON of a device with and one without:\n%s", j)
	}
	// An import of a file that says nothing of the scale keeps it (a CSV has
	// no column for it); one that states it replaces it.
	rows, err := ParseImport([]byte("sat-rtr1,192.0.2.7,juniper\ncore-sw1,10.99.0.1,cisco\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("sat-rtr1").TimeoutScale; got != 3 {
		t.Errorf("the import dropped the scale: %d", got)
	}
	yamlRows, err := ParseImport([]byte(Header + "version: 1\nsettings: {stale_days: 30}\ndevices:\n  sat-rtr1: {address: 192.0.2.7, vendor: juniper, timeout_scale: 5}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(yamlRows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("sat-rtr1").TimeoutScale; got != 5 {
		t.Errorf("the import of the registry's YAML did not state the scale: %d", got)
	}
}

func TestRollbackTimeoutScale(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(p, []byte(sampleTimeoutScale), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := TimeoutScaleSet(p)
	var names []string
	for _, d := range set {
		names = append(names, d.Name)
	}
	if err != nil || !reflect.DeepEqual(names, []string{"sat-rtr1", "sat-sw2"}) {
		t.Fatalf("TimeoutScaleSet: %q %v", names, err)
	}
	ran := 0
	cleared, err := RollbackTimeoutScale(p, func() error { ran++; return nil })
	if err != nil || ran != 1 || !reflect.DeepEqual(cleared, names) {
		t.Fatalf("RollbackTimeoutScale: %q %v (snapshots %d)", cleared, err, ran)
	}
	got, _ := os.ReadFile(p)
	if strings.Contains(string(got), "timeout_scale") {
		t.Errorf("the key is still there:\n%s", got)
	}
	f, err := Load(p)
	if err != nil || f.Find("sat-rtr1") == nil || f.Find("sat-rtr1").Address != "192.0.2.7" || f.Find("sat-rtr1").Vendor != "juniper" {
		t.Errorf("the rest of the device is not kept: %v", err)
	}
	// idempotent, and a missing registry is not created
	ran = 0
	if cleared, err = RollbackTimeoutScale(p, func() error { ran++; return nil }); err != nil || len(cleared) != 0 || ran != 0 {
		t.Errorf("second run: %q %v (snapshots %d)", cleared, err, ran)
	}
	missing := filepath.Join(dir, "sub", "devices.yaml")
	if cleared, err := RollbackTimeoutScale(missing, nil); err != nil || len(cleared) != 0 {
		t.Errorf("missing: %q %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing registry was created: %v", err)
	}
}
