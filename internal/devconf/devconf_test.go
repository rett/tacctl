package devconf

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

var update = flag.Bool("update", false, "rewrite the golden files of tests/fixtures/devconf")

const fixtureDir = "../../tests/fixtures/devconf"

// capture reads a fixture of tests/fixtures/devconf and returns the text
// after its '# ---' header (plan 7.3).
func capture(t *testing.T, rel string) string {
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

// header returns the value of a '# key: value' line of a fixture's header.
func header(t *testing.T, rel, key string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(data), "\n") {
		if l == "# ---" {
			break
		}
		if v, ok := strings.CutPrefix(l, "# "+key+": "); ok {
			return v
		}
	}
	return ""
}

// expectedSections reads an expected.txt: devices.Managed's golden form
// ('[section]', then '| statement' or '* secret statement').
func expectedSections(t *testing.T, rel string) []devices.Section {
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
		case (strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "* ")) && cur != nil:
			cur.Lines = append(cur.Lines, l[2:])
			cur.Secret = append(cur.Secret, l[0] == '*')
		}
	}
	return out
}

// resultText renders a comparison as the golden files hold it.
func resultText(ex Extracted, results []SectionResult) string {
	var b strings.Builder
	b.WriteString("# secrets visible: ")
	if ex.SecretsVisible {
		b.WriteString("true\n")
	} else {
		b.WriteString("false\n")
	}
	for _, r := range results {
		b.WriteString("[" + r.Name + "] " + string(r.State) + "\n")
		for _, l := range r.Lines {
			b.WriteString(string(l.Op) + " " + l.Text + "\n")
		}
	}
	return b.String()
}

// golden compares got with a file next to the fixture (-update rewrites it).
func golden(t *testing.T, rel, got string) {
	t.Helper()
	p := filepath.Join(fixtureDir, rel)
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
		t.Errorf("%s differs from the golden:\n--- got\n%s\n--- want\n%s", rel, got, want)
	}
}

// allText joins every line of a comparison, for the leak checks.
func allText(results []SectionResult) string {
	var b strings.Builder
	for _, r := range results {
		b.WriteString(string(r.State) + "\n")
		for _, l := range r.Lines {
			b.WriteString(l.Text + "\n")
		}
	}
	return b.String()
}
