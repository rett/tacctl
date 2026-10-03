// Package linux carries the two Linux client scripts into the tacctl binary
// (docs/plans/go-rewrite.md 1.5, 3.7). The scripts run on the enrolled
// hosts under their own bash, so they stay shell and are shipped verbatim:
// client-install.sh is the body of the installer that internal/hosts
// assembles ('config linux script', 'host enroll|sync'), client-remove.sh
// is written by 'config linux remove-script' and pushed by 'host unenroll'.
//
// The embed lives next to the scripts because go:embed cannot reach up out
// of a package's directory. WP3.3d may fold it into internal/assets.
package linux

import _ "embed" // the scripts below

// InstallScript is config/linux/client-install.sh.
//
//go:embed client-install.sh
var InstallScript []byte

// RemoveScript is config/linux/client-remove.sh.
//
//go:embed client-remove.sh
var RemoveScript []byte
