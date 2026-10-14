// Package doctext reads the user documentation as one text: README.md and
// every page under docs/ except the plans and the release notes. Tests that
// assert what the documentation says read it through here, so a page can
// move without the assertion noticing.
package doctext

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Read returns the text of README.md followed by every shipped page of
// docs/ under root, in path order.
func Read(root string) (string, error) {
	var b strings.Builder
	data, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		return "", err
	}
	b.Write(data)
	var pages []string
	docs := filepath.Join(root, "docs")
	err = filepath.WalkDir(docs, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(docs, p)
		if e.IsDir() {
			if rel == "plans" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".md") && !strings.HasPrefix(rel, "release-notes-") {
			pages = append(pages, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(pages)
	for _, p := range pages {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		b.WriteString("\n")
		b.Write(data)
	}
	return b.String(), nil
}
