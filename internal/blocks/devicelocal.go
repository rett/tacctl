package blocks

// The rule for what a scope's block may state (0.2.19): only settings that
// are the same for every device of the scope. A value that names the device
// itself, an address it holds or an interface it has, is its own: a scope's
// block (and the default) refuses it, the device's own block states it. The
// convention names every device of a design shares (Junos lo0, IOS
// Loopback0) are the one exception, with a note: a device without such an
// interface cannot take the statement.

import (
	"regexp"
	"strings"
)

// reLoopbackName is a loopback interface as IOS names it (Loopback0, Lo0).
var reLoopbackName = regexp.MustCompile(`(?i)^lo(?:opback)?[0-9]+$`)

// isLoopbackName reports an IOS loopback interface name.
func isLoopbackName(s string) bool { return reLoopbackName.MatchString(strings.TrimSpace(s)) }

// deviceLocalProblem is why a layer may not state a device-local value ("" when it
// may): a scope or default layer states none, unless convention says it is
// the loopback.
func deviceLocalProblem(layer Layer, statement string, isConvention bool) string {
	if layer == LayerDevice || isConvention {
		return ""
	}
	return statement + " names an address or an interface of one device: state it in the device's own block (only the loopback by its convention name, lo0 or Loopback0, is the same for every device of a scope)"
}
