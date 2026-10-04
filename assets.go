// Package tacctl holds the files of this tree that the Go binary carries
// inside it (docs/plans/go-rewrite.md 3.7). go:embed cannot reach outside
// the directory of the package that embeds, and these files stay at their
// paths in the tree, so the embedding lives at the module root;
// internal/assets is the API the rest of the program uses.
//
// What is embedded: the device templates (rendered by 'config cisco|
// juniper|wti' when the operator has no override, and the shipped set
// install and upgrade keep in the state directory) and the two Linux client
// scripts (the body of the installer 'host enroll|sync' sends, and the
// remover). What the lifecycle phases install from a tree (systemd units,
// logrotate, the tacquito patches, README.md, the man page, the
// completion) is read from the deploy clone, as 0.1.16 does: the clone is
// always there (the binary is built from it), and the bash release a
// rollback hands over to reads the same files.
package tacctl

import "embed"

// Templates are the shipped device templates, config/templates/*.template.
//
//go:embed config/templates/*.template
var Templates embed.FS

// LinuxScripts are the Linux client scripts, config/linux/client-install.sh
// and client-remove.sh, shipped verbatim.
//
//go:embed config/linux/client-install.sh config/linux/client-remove.sh
var LinuxScripts embed.FS
