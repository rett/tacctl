package plan

// The NETCONF service section of a Junos plan (D145-D148 of
// docs/plans/0.2.10-plan.md). Until 0.2.10 'system services netconf' was on
// the never list and the section was never planned; a scope that enables or
// disables the service has a netconf section in the rendering (enable: the
// statements, disable: Absent), and only then is it planned. A scope that
// leaves it has none, and the section stays 'never' as before.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// netconfPrefix is the hierarchy the section owns.
const netconfPrefix = "system services netconf"

// netconfRendered reports whether the rendering has a netconf section: an
// enabled service's statements or the absence of a disabled one.
func netconfRendered(expected []devices.Section) bool {
	for _, s := range expected {
		if s.Name == devconf.SectionNetconf {
			return len(s.Lines) > 0 || s.Absent
		}
	}
	return false
}

// neverFor are the sections that are never planned for this rendering:
// break-glass always, netconf unless the setting enables or disables it.
func neverFor(expected []devices.Section) []string {
	if netconfRendered(expected) {
		return []string{devconf.SectionBreakGlass}
	}
	return []string{devconf.SectionNetconf, devconf.SectionBreakGlass}
}

// order is PlanOrder of the delta's vendor with the netconf section left
// out of a plan that has none (it is 'never' there).
func (d Delta) order() []string {
	o := PlanOrder(d.Vendor)
	if st := d.Of(devconf.SectionNetconf).State; st == "" || st == StateNever {
		o = slices.DeleteFunc(slices.Clone(o), func(n string) bool { return n == devconf.SectionNetconf })
	}
	return o
}

// netconfStatement reports whether the statement's path (the words after
// the verb) lies under 'system services netconf'.
func netconfStatement(path []string) bool {
	pre := strings.Fields(netconfPrefix)
	return len(path) >= len(pre) && slices.Equal(path[:len(pre)], pre)
}

// NetconfStatementAllowed reports whether a statement (with its verb) is one
// of the exact forms a plan may write under 'system services netconf'
// (D147): 'set ... netconf ssh', 'set ... netconf ssh connection-limit <n>',
// 'set ... netconf ssh rate-limit <n>' with n in range, and 'delete
// system services netconf'. Nothing else under the hierarchy is ever
// written, a limit's delete included (a limit the setting does not set is
// the device's own).
func NetconfStatementAllowed(line string) bool {
	t := splitTokens(strings.TrimSpace(line))
	if len(t) < 2 || !netconfStatement(t[1:]) {
		return false
	}
	path := t[1:]
	switch t[0] {
	case "delete":
		return len(path) == len(strings.Fields(netconfPrefix))
	case "set":
		ssh := len(strings.Fields(netconfPrefix)) + 1
		switch {
		case len(path) == ssh && path[ssh-1] == "ssh":
			return true
		case len(path) == ssh+2 && path[ssh-1] == "ssh" && (path[ssh] == "connection-limit" || path[ssh] == "rate-limit"):
			n, err := strconv.Atoi(path[ssh+1])
			return err == nil && n >= conf.NetconfMinLimit && n <= conf.NetconfMaxLimit && strconv.Itoa(n) == path[ssh+1]
		}
	}
	return false
}

// TouchesNetconf reports whether a delta writes under 'system services
// netconf': the apply of such a delta runs over the command line whatever
// the transport setting says (D148), since the verification of a change to
// the service depends on the service.
func TouchesNetconf(d Delta) bool {
	for _, l := range slices.Concat(d.Lines, d.Cleanup.Lines) {
		t := splitTokens(strings.TrimSpace(l.Text))
		if len(t) >= 2 && netconfStatement(t[1:]) {
			return true
		}
	}
	return false
}

// junosAbsent plans a section the rendering expects to be absent (D146): one
// statement deletes the hierarchy when the device holds anything under it.
// What a login's class cannot see is withheld, and a statement that comes
// from a group refuses the section, as in every other section.
func (p *planner) junosAbsent(name string, r devconf.SectionResult) secOut {
	var o secOut
	var stems, refs []string
	for _, x := range parseJunosLines(r) {
		if x.op != devconf.OpExtra {
			continue
		}
		if ok, _ := p.opt.Class.canSee(x.path); !ok {
			o.withheld = append(o.withheld, displayStem(x))
			continue
		}
		stems = append(stems, x.stem)
		if !p.inPlain(name, x.stem) {
			refs = append(refs, x.stem)
		}
	}
	switch {
	case len(refs) > 0:
		o.inherited = refs
		o.refused = "inherited from a group: change the group by hand (" + strings.Join(dedupe(refs), "; ") + ")"
	case len(stems) == 0 && len(o.withheld) > 0:
		o.refused, o.refusedKind = "not visible to class "+p.opt.Class.Name, KindClassSkip
	case len(stems) > 0:
		o.lines = []Line{{Op: OpDelete, Text: devices.NetconfDeleteStatement, For: stems}}
		o.why = []string{"the NETCONF service, which the scope's setting disables (its whole hierarchy goes in one statement)"}
		o.warnings = []string{"disabling NETCONF ends the service for every NETCONF client of the device; " +
			"tacctl reads and applies over the command line afterwards"}
	}
	return o
}

// netconfAllowed reports whether a statement under 'system services
// netconf' is one of the exact forms (NetconfStatementAllowed) and the
// rendering states it: a 'set' the netconf section's own lines hold, or the
// 'delete' of a section the rendering expects to be absent. With no
// rendering, or a netconf section that is not planned, nothing is allowed.
func (a Allow) netconfAllowed(line string) bool {
	if !NetconfStatementAllowed(line) {
		return false
	}
	if a.Sections != nil && !slices.Contains(a.Sections, devconf.SectionNetconf) {
		return false
	}
	var exp *devices.Section
	for i := range a.Expected {
		if a.Expected[i].Name == devconf.SectionNetconf {
			exp = &a.Expected[i]
		}
	}
	if exp == nil {
		return false
	}
	if splitTokens(strings.TrimSpace(line))[0] == "delete" {
		return exp.Absent
	}
	return !exp.Absent && a.rendered(line)
}
