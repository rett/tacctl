// Command tacctl manages network-device AAA servers: users, groups, scopes
// and filters kept once in /etc/tacctl/store.yaml and served over TACACS+
// (tacquito) and RADIUS (FreeRADIUS). See README.md and man tacctl.
package main

import (
	"os"
	"syscall"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/cli"
)

// Set by the build (bin/tacctl.sh --build: -ldflags -X main.version=...).
var (
	version string
	commit  string
	date    string
)

func main() {
	// Everything tacctl creates is private unless a command sets a mode
	// (bin/tacctl.sh: umask 077 before anything else).
	syscall.Umask(0o077)
	os.Exit(cli.Main(os.Args, os.Environ(),
		app.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
		cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
