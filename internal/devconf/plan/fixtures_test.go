package plan

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// update rewrites the goldens of tests/fixtures/golden/plan.* (the
// convention of internal/devices: go test -update).
var update = flag.Bool("update", false, "rewrite the golden files of tests/fixtures/golden/plan.*")

const (
	fixtureDir = "../../../tests/fixtures/devconf"
	goldenDir  = "../../../tests/fixtures/golden"
)

// capture reads a fixture and returns the text after its '# ---' header.
func capture(t testing.TB, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "# ") {
		return text
	}
	_, body, ok := strings.Cut(text, "\n# ---\n")
	if !ok {
		t.Fatalf("%s: no '# ---' line after the header", rel)
	}
	return body
}

// expectedSections reads an expected.txt ('[section]', '| statement', '*
// secret statement'; '&' and '+' for a statement of a configuration block, with
// and without a secret).
func expectedSections(t testing.TB, rel string) []devices.Section {
	t.Helper()
	var out []devices.Section
	var cur *devices.Section
	for _, l := range strings.Split(capture(t, rel), "\n") {
		switch {
		case strings.HasPrefix(l, "["):
			name, rest, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
			if strings.TrimSpace(rest) == "not rendered" {
				cur = nil
				continue
			}
			out = append(out, devices.Section{Name: name})
			cur = &out[len(out)-1]
		case (strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "* ") || strings.HasPrefix(l, "& ") || strings.HasPrefix(l, "+ ")) && cur != nil:
			cur.Lines = append(cur.Lines, l[2:])
			cur.Secret = append(cur.Secret, l[0] == '*' || l[0] == '&')
			// '&' and '+' are statements of a configuration block (the
			// first one that carries a secret)
			fromBlock := l[0] == '&' || l[0] == '+'
			if fromBlock && cur.Block == nil {
				cur.Block = make([]bool, len(cur.Lines)-1)
			}
			if cur.Block != nil {
				cur.Block = append(cur.Block, fromBlock)
			}
		}
	}
	return out
}

// golden compares got with tests/fixtures/golden/plan.<name> (-update
// rewrites it).
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join(goldenDir, "plan."+name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test -run %s -update writes it)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("plan.%s differs from the golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// the fixed times of the goldens.
var (
	tPull = time.Date(2026, 10, 10, 14, 2, 0, 0, time.UTC)
	tNow  = time.Date(2026, 10, 10, 14, 20, 0, 0, time.UTC)
)

// fixture is one pulled device of the fixtures and the rendering it is
// planned against.
type fixture struct {
	name     string
	vendor   string // juniper or cisco
	raw      string // rel path of the pulled text
	expected string // rel path of expected.txt
	class    *Class
	legacy   bool
	// plain is a rel path of the plain view (default: the pulled text).
	plain    string
	protocol string
}

func enClass(t testing.TB, exp []devices.Section) *Class {
	for _, s := range exp {
		for _, l := range s.Lines {
			if strings.HasPrefix(l, "set system login class EN-CLASS permissions [ ") {
				f := strings.Fields(l)
				var perms []string
				for _, w := range f[6:] {
					if w != "]" {
						perms = append(perms, w)
					}
				}
				return &Class{Name: "EN-CLASS", Permissions: perms}
			}
		}
	}
	t.Fatal("no EN-CLASS in the rendering")
	return nil
}

const synthExpected = "juniper/synthetic-lab/expected.txt"

func fixtures(t testing.TB) []fixture {
	exp := expectedSections(t, synthExpected)
	en := enClass(t, exp)
	return []fixture{
		{name: "juniper.synthetic-lab", vendor: "juniper", raw: "juniper/synthetic-lab/display-set.txt", expected: synthExpected},
		{name: "juniper.synthetic-lab-engineer", vendor: "juniper", raw: "juniper/synthetic-lab/display-set-engineer.txt", expected: synthExpected, class: en},
		{name: "juniper.synthetic-lab-nolo0", vendor: "juniper", raw: "juniper/synthetic-lab/display-set-nolo0.txt", expected: synthExpected},
		{name: "juniper.synthetic-inherit", vendor: "juniper", raw: "juniper/synthetic-inherit/display-set.txt", expected: synthExpected},
		{name: "juniper.lab-superuser", vendor: "juniper", raw: "juniper/lab-superuser/display-set.txt", expected: synthExpected},
		{name: "juniper.lab-engineer", vendor: "juniper", raw: "juniper/lab-engineer/display-set.txt", expected: synthExpected, class: en},
		{name: "cisco.reference-lab", vendor: "cisco", raw: "ios/reference-lab/running-config.txt", expected: "ios/reference-lab/expected.txt"},
		{name: "cisco.reference-12x", vendor: "cisco", raw: "ios/reference-12x/running-config.txt", expected: "ios/reference-12x/expected.txt", legacy: true},
		{name: "cisco.real-12.4-7200", vendor: "cisco", raw: "ios/real-12.4-7200/running-config.txt", expected: "ios/real-12.4-7200/expected.txt", legacy: true},
		{name: "cisco.reference-bare", vendor: "cisco", raw: "ios/reference-bare/running-config.txt", expected: "ios/reference-lab/expected.txt"},
		{name: "cisco.xe-reference-16", vendor: "cisco", raw: "ios-xe/reference-16/running-config.txt", expected: "ios-xe/reference-16/expected.txt", protocol: "RADIUS"},
		// D117 (amended): the shape of a real 15.6 device, a named block of
		// another name at the standard's address, with the command lists on
		// the device and without (appended last: the fuzz seeds follow the
		// order of the fixtures)
		{name: "cisco.same-address-block", vendor: "cisco", raw: "ios/same-address-block/running-config.txt", expected: "ios/same-address-block/expected.txt"},
		{name: "cisco.same-address-block-nocmd", vendor: "cisco", raw: "ios/same-address-block-nocmd/running-config.txt", expected: "ios/same-address-block-nocmd/expected.txt"},
		// 0.2.7: tacctl's community beside one of the device's own with its
		// own clients, a trap group, trap options and a name
		{name: "juniper.synthetic-communities", vendor: "juniper", raw: "juniper/synthetic-communities/display-set.txt", expected: synthExpected},
		// 0.2.7: the synthetic lab after the scope's system block was pasted
		{name: "juniper.synthetic-system", vendor: "juniper", raw: "juniper/synthetic-system/display-set.txt", expected: "juniper/synthetic-system/expected.txt"},
		// the same rendering against a device that holds none of it
		{name: "juniper.synthetic-system-new", vendor: "juniper", raw: "juniper/synthetic-lab/display-set.txt", expected: "juniper/synthetic-system/expected.txt"},
	}
}

// load extracts a fixture against its rendering.
func (f fixture) load(t testing.TB) (exp []devices.Section, cur, plain devconf.Extracted) {
	t.Helper()
	exp = expectedSections(t, f.expected)
	var err error
	cur, err = devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatalf("%s: %v", f.name, err)
	}
	plain = cur
	if f.plain != "" {
		plain, err = devconf.Extract(f.vendor, capture(t, f.plain), exp...)
		if err != nil {
			t.Fatal(err)
		}
	}
	return exp, cur, plain
}

func (f fixture) header() Header {
	proto := f.protocol
	if proto == "" {
		proto = "TACACS+"
	}
	return Header{Device: "dev-" + strings.ReplaceAll(f.name, ".", "-"), Address: "192.0.2.21", Scope: "lab", Vendor: f.vendor, Protocol: proto,
		Pulled: tPull, PulledBy: "alice", Transport: map[string]string{"juniper": "netconf", "cisco": "ssh"}[f.vendor],
		SecretsVisible: !strings.Contains(f.name, "engineer"), Now: tNow, Version: "0.2.5", User: "alice", StaleDays: 7}
}

// syntax is the configuration syntax the fixture's device is planned with
// (empty for Junos).
func (f fixture) syntax() string {
	switch {
	case f.vendor != "cisco":
		return ""
	case f.legacy:
		return SyntaxIOS12
	}
	return SyntaxModern
}

func (f fixture) options() Options {
	return Options{Scope: "lab", Class: f.class, Syntax: f.syntax()}
}
