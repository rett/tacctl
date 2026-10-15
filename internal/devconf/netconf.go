package devconf

// The NETCONF service section of a Junos device (D145, D146 of
// docs/plans/0.2.10-plan.md): the bare 'ssh' of an enabled service is
// implied by any child, and what the device holds beside the rendered
// statements is its own (the shapes in unmanaged.go).

import (
	"slices"
	"strings"
)

// netconfSSH is the bare statement of an enabled service.
const netconfSSH = "set system services netconf ssh"

// withImpliedNetconfSSH adds the bare 'ssh' statement to the device's when
// the rendering states it and the device holds a statement under it: Junos
// prints no bare 'ssh' beside a child ('show configuration | display set'
// has only 'ssh connection-limit 5'), though the service is on, so the bare
// statement is satisfied by any child.
func withImpliedNetconfSSH(exp, dev []stmt) []stmt {
	bare := slices.IndexFunc(exp, func(x stmt) bool { return x.stem == netconfSSH })
	if bare < 0 || slices.ContainsFunc(dev, func(x stmt) bool { return x.stem == netconfSSH }) {
		return dev
	}
	if !slices.ContainsFunc(dev, func(x stmt) bool {
		return strings.HasPrefix(x.stem, netconfSSH+" ") && !strings.HasPrefix(x.stem, "deactivate ")
	}) {
		return dev
	}
	return append(slices.Clone(dev), exp[bare])
}
