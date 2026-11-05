package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// States of a Check.
const (
	// InSync: the live table is what the holds and the setting ask for.
	InSync = "in sync"
	// Differs: the live table is not.
	Differs = "differs"
	// Unreadable: nft could not be asked (not installed, or not allowed to
	// read the ruleset); nothing is known, nothing is wrong.
	Unreadable = "unreadable"
)

// Check is the comparison of the live table with the holds and the setting.
type Check struct {
	// State is InSync, Differs or Unreadable.
	State string
	// Mode is the setting the table was compared with.
	Mode string
	// Why is what nft said when State is Unreadable.
	Why string
	// Differences name each difference in a sentence.
	Differences []string
	// Fix is the command that puts the table right: the setting command with
	// the current setting, which loads the table again whatever it holds.
	Fix string
}

// FixCommand is the command that loads the table again for the setting mode,
// even when the setting is not changed.
func FixCommand(mode string) string { return "tacctl config breakglass-firewall " + mode }

// observed is what 'nft -j list table inet tacctl' says.
type observed struct {
	exists bool
	// sets are the elements of each set, by name.
	sets map[string][]string
	// rules are the rules of the input chain.
	rules []obsRule
}

type obsRule struct {
	set     string
	ports   []int
	verdict string
}

// Check asks nft for the table ('nft -j list table inet tacctl') and compares
// it with the holds and the setting. It reads nothing else of the ruleset and
// changes nothing. A table that is not there is a difference only when there
// is something to enforce (an address is held and the setting is not off),
// and a table that is there with the setting off is one.
func (e *Engine) Check(ctx context.Context) Check {
	spec := SpecOf(e.Conf)
	c := Check{State: InSync, Mode: spec.Mode, Fix: FixCommand(spec.Mode)}
	if _, err := e.Runner.LookPath(Tool); err != nil {
		c.State, c.Why = Unreadable, "nft is not installed"
		if spec.Enforces() {
			c.State = Differs
			c.Differences = []string{"nft is not installed, so the server still completes the TCP handshake of " + strings.Join(spec.Strings(), ", ") + " on " + PortList(spec.Ports) + " (" + InstallCommand + ")"}
			c.Why = ""
		}
		return c
	}
	r, err := e.Runner.Run(ctx, execx.Cmd{Name: Tool, Args: []string{"-j", "list", "table", Family, Table}})
	obs := observed{}
	switch {
	case err != nil && r.Code == 0:
		c.State, c.Why = Unreadable, "nft could not be run: "+errText(err)
		return c
	case r.Code != 0:
		msg := firstLine(string(r.Stderr))
		if strings.Contains(msg, "No such file or directory") {
			// the table is not in the kernel
			break
		}
		c.State = Unreadable
		c.Why = "nft says: " + msg
		if msg == "" {
			c.Why = "nft exited " + strconv.Itoa(r.Code)
		}
		return c
	default:
		var perr error
		if obs, perr = parseTable(r.Stdout); perr != nil {
			c.State, c.Why = Unreadable, "the output of nft could not be read: "+perr.Error()
			return c
		}
	}
	c.Differences = compare(spec, obs)
	if len(c.Differences) > 0 {
		c.State = Differs
	}
	return c
}

// compare names each difference between the table asked for and the live one.
func compare(spec Spec, obs observed) []string {
	var out []string
	if spec.Mode == Off {
		if obs.exists {
			out = append(out, "the table inet tacctl exists although breakglass.firewall is off")
		}
		return out
	}
	if !obs.exists {
		if spec.Enforces() {
			out = append(out, "the table inet tacctl is missing, so the server still completes the TCP handshake of "+
				strings.Join(spec.Strings(), ", ")+" on "+PortList(spec.Ports))
		}
		return out
	}
	var want4, want6 []string
	for _, a := range spec.Addrs() {
		if a.Is4() {
			want4 = append(want4, a.String())
		} else {
			want6 = append(want6, a.String())
		}
	}
	for _, s := range []struct {
		name string
		want []string
	}{{Set4, want4}, {Set6, want6}} {
		have, present := obs.sets[s.name]
		if !present {
			out = append(out, "the set "+s.name+" is missing")
			continue
		}
		have = canonical(have)
		for _, a := range s.want {
			if !slices.Contains(have, a) {
				out = append(out, a+" is held but missing from the set "+s.name)
			}
		}
		for _, a := range have {
			if !slices.Contains(s.want, a) {
				out = append(out, a+" is in the set "+s.name+" but not held")
			}
		}
	}
	verdict := "reject"
	if spec.Mode == Drop {
		verdict = "drop"
	}
	for _, set := range []string{Set4, Set6} {
		var got []obsRule
		for _, r := range obs.rules {
			if r.set == set {
				got = append(got, r)
			}
		}
		switch {
		case len(spec.Ports) == 0 && len(got) == 0:
		case len(got) == 0:
			out = append(out, "the rule of the set "+set+" is missing")
		case len(got) > 1:
			out = append(out, "the set "+set+" has "+strconv.Itoa(len(got))+" rules, not one")
		default:
			r := got[0]
			if r.verdict != verdict {
				out = append(out, "the verdict for the set "+set+" is "+r.verdict+", not "+verdict+" (breakglass.firewall is "+spec.Mode+")")
			}
			slices.Sort(r.ports)
			if !slices.Equal(r.ports, spec.Ports) {
				out = append(out, "the rule of the set "+set+" matches "+PortList(r.ports)+", not "+PortList(spec.Ports)+" (the ports tacquito listens on)")
			}
		}
	}
	return out
}

// canonical is the addresses written as netip prints them, so that 192.0.2.1
// and an IPv6 address compare as text.
func canonical(l []string) []string {
	out := make([]string, 0, len(l))
	for _, s := range l {
		if a, err := netip.ParseAddr(s); err == nil {
			s = a.String()
		}
		out = append(out, s)
	}
	return out
}

// parseTable reads the JSON of 'nft -j list table'.
func parseTable(data []byte) (observed, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return observed{}, err
	}
	obs := observed{sets: map[string][]string{}}
	for _, item := range doc.Nftables {
		for kind, raw := range item {
			switch kind {
			case "table":
				var t struct{ Family, Name string }
				if json.Unmarshal(raw, &t) == nil && t.Family == Family && t.Name == Table {
					obs.exists = true
				}
			case "set":
				var s struct {
					Name string
					Elem []json.RawMessage
				}
				if err := json.Unmarshal(raw, &s); err != nil {
					return observed{}, err
				}
				elems := []string{}
				for _, el := range s.Elem {
					var text string
					if err := json.Unmarshal(el, &text); err != nil {
						// an element with a timeout or a counter is not ours
						text = strings.TrimSpace(string(el))
					}
					elems = append(elems, text)
				}
				obs.sets[s.Name] = elems
			case "rule":
				var r struct {
					Chain string
					Expr  []map[string]json.RawMessage
				}
				if err := json.Unmarshal(raw, &r); err != nil {
					return observed{}, err
				}
				if r.Chain == Chain {
					obs.rules = append(obs.rules, ruleOf(r.Expr))
				}
			}
		}
	}
	return obs, nil
}

// ruleOf reads the expressions of one rule: the set its saddr is matched
// against, the ports of its dport, and its verdict ("reject" for a reset,
// "reject <type>" for any other, "drop", or what else is there).
func ruleOf(exprs []map[string]json.RawMessage) obsRule {
	var r obsRule
	for _, ex := range exprs {
		for kind, raw := range ex {
			switch kind {
			case "match":
				var m struct {
					Left struct {
						Payload struct{ Protocol, Field string }
					}
					Right json.RawMessage
				}
				if json.Unmarshal(raw, &m) != nil {
					continue
				}
				switch p := m.Left.Payload; {
				case p.Field == "saddr":
					var set string
					if json.Unmarshal(m.Right, &set) == nil {
						r.set = strings.TrimPrefix(set, "@")
					}
				case p.Protocol == "tcp" && p.Field == "dport":
					r.ports = portsOf(m.Right)
				}
			case "drop":
				r.verdict = "drop"
			case "reject":
				var rj struct{ Type string }
				_ = json.Unmarshal(raw, &rj)
				switch rj.Type {
				case "tcp reset":
					r.verdict = "reject"
				case "":
					r.verdict = "reject (icmp)"
				default:
					r.verdict = "reject (" + rj.Type + ")"
				}
			case "accept":
				r.verdict = "accept"
			}
		}
	}
	return r
}

// portsOf is a dport right-hand side: one number or a set of them.
func portsOf(raw json.RawMessage) []int {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return []int{n}
	}
	var set struct{ Set []json.RawMessage }
	if json.Unmarshal(raw, &set) != nil {
		return nil
	}
	var out []int
	for _, el := range set.Set {
		var v int
		if json.Unmarshal(el, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// String is the check as one line, for the logs of a test.
func (c Check) String() string {
	return fmt.Sprintf("%s (%s) %s", c.State, c.Mode, strings.Join(c.Differences, "; "))
}
