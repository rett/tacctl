package devconf

// The SNMP community labels (0.2.7). A community's name is its secret, so the
// compared form never holds it; but a name elided to one mark for every
// community makes all communities one, and the leaves of another community
// read as tacctl's own. A name is therefore elided to a label that says
// whose it is and nothing else: '<secret:N>' for the N-th community string
// of the rendering (in the order of the rendering), '<other:N>' for the N-th
// other string of the device (by first appearance in the text). Equal
// strings have equal labels within one extraction, a Junos trap group's name
// (the community its traps are sent with) and the community word of an IOS
// 'snmp-server host' included.
//
// The labels are relative to the rendering at pull time: a scope's changed
// community needs a new pull. A record of an older tacctl holds the bare
// '<secret>' for every name: Compare then compares the communities by
// presence, as that tacctl did, and says so.

import (
	"regexp"
	"strconv"
	"strings"
)

// reLabel is a community label.
var reLabel = regexp.MustCompile(`^<(secret|other):[1-9][0-9]*>$`)

// IsLabel reports a community label ('<secret:1>', '<other:2>').
func IsLabel(w string) bool { return reLabel.MatchString(w) }

// IsOtherLabel reports the label of a community the rendering does not
// have ('<other:N>').
func IsOtherLabel(w string) bool { return IsLabel(w) && strings.HasPrefix(w, "<other:") }

// isElided reports a word that already stands for a community's name: a
// label or the bare mark of an older record.
func isElided(w string) bool { return w == secretMark || IsLabel(w) }

// labels maps the community strings of one comparison to their labels.
type labels struct {
	rendered map[string]string
	other    map[string]string
	// fresh is set for a device's text as it was read: every name is a
	// string to label, none a label already (a community may be called
	// anything).
	fresh bool
}

// newLabels labels the community strings of the rendered lines, in order.
func newLabels(fam string, lines []string) *labels {
	l := &labels{rendered: map[string]string{}, other: map[string]string{}}
	for _, n := range communityNames(fam, lines) {
		if _, ok := l.rendered[n]; !ok {
			l.rendered[n] = "<secret:" + strconv.Itoa(len(l.rendered)+1) + ">"
		}
	}
	return l
}

// of is the word a community's name is elided to. A nil labels elides every
// name to the bare mark, as tacctl did before the labels; a name that is
// elided already stays as it is.
func (l *labels) of(name string) string {
	switch {
	case l == nil:
		if IsLabel(name) {
			return name
		}
		return secretMark
	case !l.fresh && isElided(name):
		return name
	}
	if m, ok := l.rendered[name]; ok {
		return m
	}
	if m, ok := l.other[name]; ok {
		return m
	}
	m := "<other:" + strconv.Itoa(len(l.other)+1) + ">"
	l.other[name] = m
	return m
}

// communityNames are the community strings of the lines, in order: the
// name of a Junos 'snmp community' and 'snmp trap-group', the string of an
// IOS 'snmp-server community' and the community word of an 'snmp-server
// host'. A word that is elided already is no string.
func communityNames(fam string, lines []string) []string {
	var out []string
	for _, line := range lines {
		if fam == FamilyJunos {
			head, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
			if head != "set" {
				continue
			}
			for _, ts := range expand(tokenize(rest)) {
				if len(ts) >= 3 && ts[0].s == "snmp" && (ts[1].s == "community" || ts[1].s == "trap-group") && !isElided(ts[2].s) {
					out = append(out, ts[2].s)
				}
			}
			continue
		}
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
			if !isElided(f[2]) {
				out = append(out, f[2])
			}
		case len(f) >= 4 && f[0] == "snmp-server" && f[1] == "host":
			if i := snmpHostSecret(f); i > 0 && !isElided(f[i]) {
				out = append(out, f[i])
			}
		}
	}
	return out
}

// CommunityLabels maps the labels of a rendering's communities to their
// strings ('<secret:1>' to the scope's community): what the planner types
// for a statement the comparison shows under a label. The rendering's lines
// are devices.Managed's (Section.Lines).
func CommunityLabels(vendor string, lines []string) (map[string]string, error) {
	fam, err := Family(vendor)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, m := range newLabels(fam, lines).rendered {
		out[m] = name
	}
	return out, nil
}

// legacyCommunity reports a statement of a record made before the labels:
// a community's name elided to the bare mark.
func legacyCommunity(fam string, x stmt) bool {
	p := x.path
	if fam == FamilyJunos {
		return len(p) >= 3 && p[0] == "snmp" && (p[1] == "community" || p[1] == "trap-group") && p[2] == secretMark
	}
	f := strings.Fields(p[len(p)-1])
	switch {
	case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
		return f[2] == secretMark
	case len(f) >= 4 && f[0] == "snmp-server" && f[1] == "host":
		i := snmpHostSecret(f)
		return i > 0 && f[i] == secretMark
	}
	return false
}
