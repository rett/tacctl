//go:build tools

// Package deps pins the third-party modules the rewrite's later packages
// import (docs/plans/go-rewrite.md 9.2, WP0.1), so that 'go mod tidy' keeps
// them in go.mod and 'go mod vendor' keeps them in vendor/ before any code
// uses them: go.mod and vendor/ change only in main-tree packages. The tools
// tag keeps this file out of every build. Drop a line once a package imports
// the module for real.
package deps

import (
	_ "golang.org/x/crypto/bcrypt"
	_ "golang.org/x/sys/unix"
	_ "golang.org/x/term"
	_ "gopkg.in/yaml.v3"
)
