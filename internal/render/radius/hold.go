package radius

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

// holdComment is the comment block of clients.conf naming each held address,
// its device or host (a name in hostNames is a host) and the prefixes and tagged addresses it was carved out of
// (the stored ones of the scopes RADIUS serves), "" when no hold carves
// anything out of this file. Never the reason: free text does not go into a
// backend file (docs/plans/0.2.5-plan.md D123).
func holdComment(m *model.Model, holds []conf.Hold, hostNames map[string]bool) string {
	var b strings.Builder
	for _, h := range holds {
		from := m.CarvedFrom(h.Address, "radius", true)
		if len(from) == 0 {
			continue
		}
		parts := make([]string, len(from))
		for i, c := range from {
			parts[i] = c.CIDR + " (" + c.Scope + ")"
		}
		fmt.Fprintf(&b, "\t# break-glass held: %s (%s %s) is answered by no client; carved out of %s\n",
			h.Address, conf.HoldKind(h.Device, hostNames), h.Device, strings.Join(parts, ", "))
	}
	if b.Len() == 0 {
		return ""
	}
	return "\t# Break-glass holds ('tacctl breakglass list'): the addresses below are taken out of the\n" +
		"\t# clients that cover them, so this server does not answer them.\n" + b.String()
}
