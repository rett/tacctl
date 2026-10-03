// Package assets is the files tacctl ships inside its binary
// (docs/plans/go-rewrite.md 3.7): so far the device templates of
// config/templates. The embedding itself is the module root's (package
// tacctl, assets.go), because go:embed reads only below the embedding
// package's directory.
package assets

import (
	"io/fs"
	"sort"
	"strings"

	tacctl "github.com/rett/tacctl"
)

// templateDir is where the templates sit in the tree and in the embedded
// file system.
const templateDir = "config/templates"

// Template is the shipped <name>.template (name without the suffix, e.g.
// "cisco-radius"); ok is false when tacctl ships no such template.
func Template(name string) (text string, ok bool) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return "", false
	}
	b, err := fs.ReadFile(tacctl.Templates, templateDir+"/"+name+".template")
	if err != nil {
		return "", false
	}
	return string(b), true
}

// TemplateNames are the names of the shipped templates, sorted.
func TemplateNames() []string {
	entries, err := fs.ReadDir(tacctl.Templates, templateDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".template"); ok && !e.IsDir() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
