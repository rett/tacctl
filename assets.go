// Package tacctl holds the files of this tree that the Go binary carries
// inside it (docs/plans/go-rewrite.md 3.7). go:embed cannot reach outside
// the directory of the package that embeds, and these files stay at their
// paths in the tree, so the embedding lives at the module root;
// internal/assets is the API the rest of the program uses.
package tacctl

import "embed"

// Templates are the shipped device templates, config/templates/*.template.
//
//go:embed config/templates/*.template
var Templates embed.FS
