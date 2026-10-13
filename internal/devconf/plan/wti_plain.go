package plan

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// A plain entry of the management permit list (0.2.7) is every protocol and
// port from its source, and it renders as 'iptables -A INPUT -s <net> -j
// ACCEPT': the unit's telnet and web pages are reachable from there as well
// as ssh. The plan and its back-out name such entries in the first lines of
// the report, where the box and the pull's age are, not among the notes at the
// bottom.

// wtiPlainWarning is the headline of a plan that pastes a list with plain
// permits ("" when the plan pastes no list, or the list has none).
func wtiPlainWarning(d Delta) string {
	if d.WTI == nil || d.WTI.Block == nil || d.Empty() {
		return ""
	}
	return wtiPlainWords(devices.WTIPlainPermits(d.WTI.Block.Commands), "of the rendered list")
}

// wtiPlainBackoutWarning is the headline of a back-out that puts a list with
// plain permits back (the unit's list of the pull).
func wtiPlainBackoutWarning(d Delta) string {
	if d.WTI == nil || d.WTI.Block == nil {
		return ""
	}
	return wtiPlainWords(devices.WTIPlainPermits(d.WTI.Block.Old), "of the list this back-out puts back")
}

// wtiPlainWords is the sentence for the plain sources (none: "").
func wtiPlainWords(plain []string, of string) string {
	if len(plain) == 0 {
		return ""
	}
	verb := "allows"
	if len(plain) > 1 {
		verb = "allow"
	}
	return fmt.Sprintf("%s %s %s every protocol and port from the source (%s), the unit's telnet and web pages included: <cidr>:tcp/22 in the management permit list restricts a permit to ssh",
		plural(len(plain), "plain permit", "plain permits"), of, verb, strings.Join(plain, ", "))
}

// headlineWarnings are the warnings of the JSON form: the one the report
// names in its header first, then the plan's own.
func headlineWarnings(d Delta) []string {
	if w := wtiPlainWarning(d); w != "" {
		return append([]string{w}, d.Warnings...)
	}
	return nonNil(d.Warnings)
}
