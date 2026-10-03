package assets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The embedded templates are the files of config/templates, byte for byte,
// and every one of them is there.
func TestTemplatesAreTheTreesFiles(t *testing.T) {
	files, err := filepath.Glob("../../config/templates/*.template")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates in the tree: %v", err)
	}
	var want []string
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".template")
		want = append(want, name)
		disk, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := Template(name)
		if !ok || got != string(disk) {
			t.Errorf("%s: embedded copy differs from the tree (ok=%v)", name, ok)
		}
	}
	sort.Strings(want)
	if got := strings.Join(TemplateNames(), " "); got != strings.Join(want, " ") {
		t.Errorf("TemplateNames() = %q, want %q", got, strings.Join(want, " "))
	}
	for _, n := range []string{"cisco", "cisco-legacy", "cisco-radius", "juniper", "juniper-radius", "wti", "wti-radius"} {
		if _, ok := Template(n); !ok {
			t.Errorf("%s.template is not shipped", n)
		}
	}
}

func TestTemplateUnknown(t *testing.T) {
	for _, n := range []string{"", "nosuch", "../templates/cisco", "x/cisco"} {
		if _, ok := Template(n); ok {
			t.Errorf("Template(%q) found something", n)
		}
	}
}
