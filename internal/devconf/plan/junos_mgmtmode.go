package plan

// The management filter modes of a Junos scope (0.2.20, devices/mgmtfilter.go):
// what the planner says when a plan moves the filter between ssh-only and
// strict, and the lock-out check of a strict filter. The statements
// themselves need nothing here: the filter row is owned whole (owned.go), so
// the terms, their leaves and their order that the rendering of the mode has
// replace the device's, in either direction.

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// strictMgmt reports a plan for a scope whose filter mode is strict.
func (p *planner) strictMgmt() bool { return p.opt.MgmtMode == devices.MgmtModeStrict }

// lo0Applied reports whether the device applies a filter the rendering names
// to lo0 (the statements of its stored mgmt-acl section).
func (p *planner) lo0Applied(row *jrow) bool {
	for _, s := range p.cur.Sections["mgmt-acl"].Lines {
		t := splitTokens(strings.TrimPrefix(s, "set "))
		if len(t) >= 7 && t[0] == "interfaces" && t[1] == "lo0" {
			if i := slices.Index(t, "filter"); i >= 0 {
				for _, n := range t[i+1:] {
					if row.names[n] {
						return true
					}
				}
			}
		}
	}
	return false
}

// filterTerm is one term of a filter as the rendering states it.
type filterTerm struct {
	sources []string
	protos  []string
	ports   []string
	accept  bool
}

// renderedTerms are the terms of the filters the rendering names, by term
// name, from the statements of the rendering.
func renderedTerms(exp devices.Section, row *jrow) map[string]*filterTerm {
	out := map[string]*filterTerm{}
	for _, raw := range exp.Lines {
		t := splitTokens(raw)
		if len(t) < 9 || t[0] != "set" || t[1] != "firewall" || t[4] != "filter" || !row.names[t[5]] || t[6] != "term" {
			continue
		}
		ft := out[t[7]]
		if ft == nil {
			ft = &filterTerm{}
			out[t[7]] = ft
		}
		var vals []string
		for _, v := range t[10:] {
			if v != "[" && v != "]" {
				vals = append(vals, v)
			}
		}
		switch {
		case t[8] == "then" && t[9] == "accept":
			ft.accept = true
		case t[8] == "from" && t[9] == "source-address":
			ft.sources = append(ft.sources, vals...)
		case t[8] == "from" && t[9] == "protocol":
			ft.protos = append(ft.protos, vals...)
		case t[8] == "from" && t[9] == "destination-port":
			ft.ports = append(ft.ports, vals...)
		}
	}
	return out
}

// admitsSSH reports whether the term accepts tcp port 22: no protocol or tcp,
// and no port or one that is ssh, 22 or a range that holds it.
func (ft *filterTerm) admitsSSH() bool {
	if !ft.accept || len(ft.protos) > 0 && !slices.Contains(ft.protos, "tcp") {
		return false
	}
	if len(ft.ports) == 0 {
		return true
	}
	for _, q := range ft.ports {
		if q == "ssh" || q == "22" {
			return true
		}
		if lo, hi, ok := strings.Cut(q, "-"); ok {
			l, e1 := strconv.Atoi(lo)
			h, e2 := strconv.Atoi(hi)
			if e1 == nil && e2 == nil && l <= 22 && 22 <= h {
				return true
			}
		}
	}
	return false
}

// strictPermitsFrom reports whether a source of the strict filter that is
// accepted for ssh holds the address (the filter's statements are the
// rendering's).
func strictPermitsFrom(exp devices.Section, row *jrow, from netip.Addr) bool {
	for _, ft := range renderedTerms(exp, row) {
		if !ft.admitsSSH() {
			continue
		}
		for _, c := range ft.sources {
			if pf, err := netip.ParsePrefix(c); err == nil && pf.Contains(from) {
				return true
			}
			if a, err := netip.ParseAddr(c); err == nil && a == from {
				return true
			}
		}
	}
	return false
}

// deviceFilterShape says what the device holds of the filters the rendering
// names: whether it has any term of them, and whether one is a
// default-accept term (the ssh-only filter's last).
func (p *planner) deviceFilterShape(row *jrow) (has, defaultAccept bool) {
	for _, s := range p.cur.Sections["mgmt-acl"].Lines {
		t := splitTokens(strings.TrimPrefix(s, "set "))
		if len(t) >= 7 && t[0] == "firewall" && t[1] == "family" && t[3] == "filter" && row.names[t[4]] && t[5] == "term" {
			has = true
			if t[6] == "default-accept" {
				defaultAccept = true
			}
		}
	}
	return has, defaultAccept
}

// strictSources are the sources the rendered strict filter accepts, in the
// order the terms name them (the SNMP terms' are the clients', not the
// permit list's).
func strictSources(exp devices.Section, row *jrow) []string {
	var out []string
	for _, raw := range exp.Lines {
		t := splitTokens(raw)
		if len(t) < 11 || t[0] != "set" || t[1] != "firewall" || t[4] != "filter" || !row.names[t[5]] || t[6] != "term" ||
			t[8] != "from" || t[9] != "source-address" || strings.HasSuffix(t[7], "-snmp") {
			continue
		}
		for _, c := range t[10:] {
			if c != "[" && c != "]" && !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// mgmtModeWarnings are the findings of a plan that changes the management
// filter: what a strict filter stops (the device's filter accepts by default,
// or it has none yet), and what a move to the ssh-only filter accepts again
// (the device's filter has terms and no default-accept term, so it drops by
// default: a strict filter of tacctl's, or the site's own). Nothing for a
// device whose filter already is what the mode renders in that respect.
func (p *planner) mgmtModeWarnings(exp devices.Section, row *jrow) []string {
	has, defaultAccept := p.deviceFilterShape(row)
	applied := p.lo0Applied(row)
	when := "Once it is applied to lo0 (the line that does is a comment of the walkthrough and never part of a plan)"
	if applied {
		when = "The device applies it to lo0 already, so from the commit"
	}
	scope := "<scope>"
	if p.opt.Scope != "" {
		scope = p.opt.Scope
	}
	switch {
	case p.strictMgmt() && (!has || defaultAccept):
		srcs := strictSources(exp, row)
		var list string
		if len(srcs) > 0 {
			shown := srcs
			if len(shown) > 6 {
				shown = shown[:6]
			}
			list = " (" + strings.Join(shown, ", ")
			if len(srcs) > len(shown) {
				list += " and " + strconv.Itoa(len(srcs)-len(shown)) + " more"
			}
			list += ")"
		}
		return []string{"the management filter of " + p.blockScope() + " is strict: it has no default-accept term. " + when +
			" the device accepts traffic to its routing engine only from the sources of the permit list" + list + " and the SNMP clients, and these stop: " +
			"routing protocols from neighbours that are not in the list (BGP, OSPF, IS-IS, VRRP, LDP, BFD); TACACS+ and RADIUS replies from servers that are not in the list (the server the walkthrough names is); NTP, syslog and DHCP from hosts that are not in the list; " +
			"SNMP from sources outside the list (the SNMP clients still poll); every other protocol from sources outside it. Keep a console session open while you paste, and add every neighbour and server the device needs to the permit list the scope renders from first (the first entry of the scope's own list replaces the global list for the scope)"}
	case !p.strictMgmt() && has && !defaultAccept:
		return []string{"the device's management filter has no default-accept term, so it drops by default (a strict filter, or the site's own), and the mode of " + p.blockScope() +
			" is ssh-only: the plan adds the default-accept term. " + when +
			" the device accepts every protocol from every source again, except ssh, NETCONF and SNMP from sources outside the permit list; " +
			"for a filter that drops by default, set the scope's mode to strict (tacctl scope mgmt-acl " + scope + " mode strict)"}
	}
	return nil
}
