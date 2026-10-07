package cli

// 'device ssh-config' (docs/plans/operator-console.md 5.4): the ssh_config
// fragment of the devices and hosts the caller may see, on stdout, with
// the install hint on stderr. Print-only: the user saves it in their own
// home and Includes it, so a plain 'ssh <name>' gets the profile and the pin
// that 'tacctl ssh <name>' gives (internal/devreg/sshconfig.go).

import (
	"io"
	"os"
	"slices"

	"github.com/rett/tacctl/internal/devreg"
)

// sshConfigServer names this machine in the fragment's header line.
var sshConfigServer = func() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "this server"
}

func (inv *invocation) deviceSSHConfig(args []string) error {
	if _, err := inv.deviceParse("ssh-config", args); err != nil {
		return err
	}
	a := inv.app
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	entries := res.Visible(inv.deviceFilter())
	// The Host blocks of pinned entries name the generated known_hosts:
	// bring it up to date with the registry first.
	if slices.ContainsFunc(entries, devreg.Pinned) {
		if err := devreg.SyncKnownHosts(a.Paths.DevicesFile, a.Paths.KnownHosts); err != nil {
			return err
		}
	}
	inv.write(string(devreg.SSHConfig(entries, a.Paths.KnownHosts, sshConfigServer(), a.Knobs.Now())))
	_, _ = io.WriteString(a.Out.Stderr, devreg.SSHConfigHint)
	return nil
}
