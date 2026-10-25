package blocks

// The drafts of 'block adopt' (0.2.7, docs/plans/0.2.7-blocks-plan.md B6): a
// device's own statements, read live as 'show configuration <hierarchy> |
// display set', turned into the text of a block to prune. Pure functions of
// text: the read, the editor and every question are the CLI's.
//
// What a draft holds is only what the grammar of the block takes and what the
// block does not state already:
//
//   - the device identity statements (snmp name, engine-id) are never part of
//     a block, and what tacctl renders itself (the scope's own community and
//     its client list, the v3 objects, the location and contact it renders) is
//     the structured settings' and refused by a block;
//   - an object (a community by its string, a trap group by its name, a
//     trap-options leaf; in the system block a single value or a list entry)
//     that the block in force at the same level states with the same
//     statements, or that the layer beneath states (the scope's, for a device
//     level) with the same statements, is not repeated; one that is in the
//     same file with other statements is left as it is (the person edits it
//     in place), and one that differs from the scope's is the device's
//     exception, whole (a device's object replaces the scope's of the same
//     key);
//   - a secret that cannot be read is never guessed: a community string or
//     trap group name the login sees masked or as the device's ciphertext, and
//     an NTP authentication key (always the device's ciphertext), are left out
//     with a line that says so, per statement, and never a value.
//
// Nothing here echoes a community string, a trap group name, a key or the
// login message: the notes are counts and the shapes of what was left out.

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
)

// AdoptOwn is what tacctl renders itself for the device the draft is read
// from: the structured community string ("" when it renders none) and the
// statements of its structured settings, as rendered ('set snmp ...').
type AdoptOwn struct {
	Community string
	Lines     map[string]bool
}

// AdoptResult is a draft: its statements, the report and the lines for what
// was left out.
type AdoptResult struct {
	// Text is the statements, canonical, one per line (the login message as
	// its heredoc); "" when there is nothing to adopt.
	Text string
	// Statements and Objects count what Text holds: the 'set' statements
	// (the login message is one) and the objects they belong to.
	Statements, Objects int
	// Notes are the lines of the report: counts, never a value.
	Notes []string
	// Left are the statements that could not be adopted, as a line each
	// (never a value).
	Left []string
}

// --- the device's text ----------------------------------------------------------

// dword is one word of a device's 'display set' line.
type dword struct {
	s       string
	quoted  bool
	comment bool
}

// deviceWords splits a line the way a device prints it: blanks separate, a
// double quoted word may hold blanks and escapes (\" and \\), and '/* ... */'
// is one word (the mark of a secret the login cannot read).
func deviceWords(line string) ([]dword, bool) {
	var out []dword
	for i := 0; i < len(line); {
		switch c := line[i]; {
		case c == ' ' || c == '\t':
			i++
		case strings.HasPrefix(line[i:], "/*"):
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				return nil, false
			}
			out = append(out, dword{s: line[i : i+2+end+2], comment: true})
			i += 2 + end + 2
		case c == '"':
			var b strings.Builder
			j, closed := i+1, false
			for j < len(line) && !closed {
				switch ch := line[j]; {
				case ch == '\\' && j+1 < len(line):
					b.WriteByte(line[j+1])
					j += 2
				case ch == '"':
					closed = true
					j++
				default:
					b.WriteByte(ch)
					j++
				}
			}
			if !closed {
				return nil, false
			}
			out = append(out, dword{s: b.String(), quoted: true})
			i = j
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' {
				j++
			}
			out = append(out, dword{s: line[i:j]})
			i = j
		}
	}
	return out, true
}

// reCipher is a value as the device stores a secret ('$9$...', '$1$...').
var reCipher = regexp.MustCompile(`^\$[0-9]{1,2}\$\S{4,}$`)

// masked reports a word that stands for a value the login cannot read: the
// comment Junos prints for a secret ('/* SECRET-DATA */'), a '<masked>' mark,
// or asterisks.
func (w dword) masked() bool {
	switch {
	case w.comment:
		return true
	case strings.Contains(w.s, "SECRET-DATA"):
		return true
	case strings.HasPrefix(w.s, "<") && strings.HasSuffix(w.s, ">"):
		return true
	}
	return w.s != "" && strings.Trim(w.s, "*") == ""
}

// cipher reports a word that is the device's ciphertext of a secret.
func (w dword) cipher() bool { return !w.quoted && reCipher.MatchString(w.s) }

// statement is 'set <words>' with a name quoted when it holds a blank.
func statement(w []dword) string {
	parts := make([]string, len(w))
	for i, x := range w {
		parts[i] = word(x.s)
	}
	return "set " + strings.Join(parts, " ")
}

// sameSet reports whether two statement lists hold the same statements
// whatever their order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

// --- the snmp block -----------------------------------------------------------------

// snmpLeaves are the leaves of a community or trap group a draft reports by
// shape when its string is masked.
var snmpLeaves = []string{"authorization", "clients", "client-list-name", "version", "categories", "targets"}

// AdoptSNMP is the draft of an snmp block from raw, the text of 'show
// configuration snmp | display set'. same is the block in force at the level
// the draft is for and up the block of the layer beneath it (a device's
// draft: the scope's); either may be nil. layer is the level of the draft: a
// scope's draft leaves out what names the device itself.
func AdoptSNMP(raw string, own AdoptOwn, same, up *SNMPBlock, layer Layer) AdoptResult {
	var res AdoptResult
	var accepted []string
	var identity, ours, outside int
	cipherOrd := map[string]int{}
	var maskedTails, cipherTails []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "set ")
		if !ok {
			if strings.HasPrefix(line, "deactivate ") {
				outside++
			}
			continue
		}
		w, ok := deviceWords(rest)
		if !ok || len(w) < 2 || w[0].s != "snmp" || w[0].quoted {
			outside++
			continue
		}
		h := w[1:]
		switch {
		case h[0].s == "name" || h[0].s == "engine-id":
			identity++
		case (h[0].s == "community" || h[0].s == "trap-group") && len(h) >= 3 && !h[0].quoted:
			stmt := statement(w)
			isOwn := own.Lines[stmt] || (h[0].s == "community" && own.Community != "" && h[1].s == own.Community)
			for _, x := range h {
				if names.IsTacctlSNMPName(x.s) {
					isOwn = true
				}
			}
			leaf := h[2].s
			known := !h[2].quoted && slices.Contains(snmpLeaves, leaf)
			tail := strings.Join(wordsOf(h[2:]), " ")
			switch {
			case isOwn:
				ours++
			case h[1].masked():
				if !known {
					outside++
					break
				}
				maskedTails = append(maskedTails, h[0].s+" "+tail)
			case h[1].cipher():
				if !known {
					outside++
					break
				}
				key := h[0].s + " " + h[1].s
				if _, seen := cipherOrd[key]; !seen {
					cipherOrd[key] = len(cipherOrd) + 1
				}
				cipherTails = append(cipherTails, fmt.Sprintf("%s %d: %s", h[0].s, cipherOrd[key], tail))
			default:
				if _, fs := Parse(stmt + "\n"); HasErrors(fs) {
					outside++
					break
				}
				accepted = append(accepted, stmt)
			}
		case h[0].s == "trap-options":
			stmt := statement(w)
			if _, fs := Parse(stmt + "\n"); HasErrors(fs) || own.Lines[stmt] {
				if own.Lines[stmt] {
					ours++
				} else {
					outside++
				}
				break
			}
			accepted = append(accepted, stmt)
		default:
			isOwn := own.Lines[statement(w)]
			for _, x := range h {
				if names.IsTacctlSNMPName(x.s) {
					isOwn = true
				}
			}
			if isOwn {
				ours++
			} else {
				outside++
			}
		}
	}

	dev, _ := Parse(strings.Join(accepted, "\n") + "\n")
	incl := &SNMPBlock{}
	var already, conflict int
	for _, c := range dev.Communities {
		st := Statements(&SNMPBlock{Communities: []*Community{c}})
		switch {
		case same.community(c.String) != nil:
			if sameSet(st, Statements(&SNMPBlock{Communities: []*Community{same.community(c.String)}})) {
				already++
			} else {
				conflict++
			}
		case up.community(c.String) != nil && sameSet(st, Statements(&SNMPBlock{Communities: []*Community{up.community(c.String)}})):
			already++
		default:
			incl.Communities = append(incl.Communities, c)
		}
	}
	for _, g := range dev.TrapGroups {
		st := Statements(&SNMPBlock{TrapGroups: []*TrapGroup{g}})
		switch {
		case same.trapGroup(g.Name) != nil:
			if sameSet(st, Statements(&SNMPBlock{TrapGroups: []*TrapGroup{same.trapGroup(g.Name)}})) {
				already++
			} else {
				conflict++
			}
		case up.trapGroup(g.Name) != nil && sameSet(st, Statements(&SNMPBlock{TrapGroups: []*TrapGroup{up.trapGroup(g.Name)}})):
			already++
		default:
			incl.TrapGroups = append(incl.TrapGroups, g)
		}
	}
	for _, o := range dev.TrapOptions {
		st := Statements(&SNMPBlock{TrapOptions: []*TrapOption{o}})
		pick := func(b *SNMPBlock) *TrapOption {
			if b == nil {
				return nil
			}
			for _, x := range b.TrapOptions {
				if x.Leaf == o.Leaf {
					return x
				}
			}
			return nil
		}
		switch {
		case pick(same) != nil:
			if sameSet(st, Statements(&SNMPBlock{TrapOptions: []*TrapOption{pick(same)}})) {
				already++
			} else {
				conflict++
			}
		case pick(up) != nil && sameSet(st, Statements(&SNMPBlock{TrapOptions: []*TrapOption{pick(up)}})):
			already++
		case o.Leaf == trapSourceLeaf && layer != LayerDevice && len(o.Args) == 1 && o.Args[0] != "lo0":
			res.Left = append(res.Left, "trap-options source-address names an address of this device, which a scope's block does not state: it is left out (state it in the device's own block)")
		default:
			incl.TrapOptions = append(incl.TrapOptions, o)
		}
	}
	res.Text = incl.String(false)
	res.Statements = len(Statements(incl))
	res.Objects = len(incl.Communities) + len(incl.TrapGroups) + len(incl.TrapOptions)

	note := func(n int, label, noun, nouns, tail string) {
		if n > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %d %s, %s", label, n, count(n, noun, nouns), tail))
		}
	}
	note(ours, "tacctl's own, rendered from its settings (the scope's community and its client list, v3, location, contact)", "statement", "statements", "not adopted")
	note(identity, "identity (snmp name, engine-id), never part of a block", "statement", "statements", "not adopted")
	note(outside, "outside what an snmp block takes (v3 users and views, rmon, and the like)", "statement", "statements", "not adopted")
	note(already, "stated already, with the same statements, by this block or the scope's", "object", "objects", "not repeated")
	note(conflict, "in this block already with other statements", "object", "objects", "left as they are (edit them in place)")
	for _, t := range maskedTails {
		res.Left = append(res.Left, "the string of this "+strings.SplitN(t, " ", 2)[0]+" is masked (the login lacks the secret permission), so it cannot be adopted: "+strings.SplitN(t, " ", 2)[1])
	}
	for _, t := range cipherTails {
		res.Left = append(res.Left, "this "+strings.SplitN(t, ":", 2)[0]+" is shown only as the device's ciphertext, so its string cannot be adopted:"+strings.SplitN(t, ":", 2)[1])
	}
	return res
}

// wordsOf are the words as a statement writes them.
func wordsOf(w []dword) []string {
	out := make([]string, len(w))
	for i, x := range w {
		out[i] = word(x.s)
	}
	return out
}

// --- the system block ---------------------------------------------------------------

// AdoptSystem is the draft of a system block from raw, the text of 'show
// configuration system | display set', with the same meaning of same and up
// as AdoptSNMP.
func AdoptSystem(raw string, same, up *SystemBlock, layer Layer) AdoptResult {
	var res AdoptResult
	var accepted []string
	var msg *LoginMessage
	var outside int
	keys := map[int]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "set system ")
		if !ok {
			if strings.HasPrefix(line, "set ") || strings.HasPrefix(line, "deactivate ") {
				outside++
			}
			continue
		}
		if v, ok := strings.CutPrefix(rest, "login message "); ok {
			body, err := FromDeviceMessage(strings.TrimSpace(v))
			if err != nil {
				res.Left = append(res.Left, "the login message could not be read ("+err.Error()+"): it is not adopted")
				continue
			}
			msg = &LoginMessage{Body: body}
			continue
		}
		w, ok := deviceWords(rest)
		if !ok || len(w) < 2 {
			outside++
			continue
		}
		plain := true
		parts := make([]string, len(w))
		for i, x := range w {
			if x.quoted || x.comment || strings.ContainsAny(x.s, " \"") {
				plain = false
			}
			parts[i] = x.s
		}
		switch {
		case w[0].s == "ntp" && w[1].s == "authentication-key":
			// The device holds ciphertext: the value is never adopted.
			n := 0
			if len(w) > 2 {
				n, _ = strconv.Atoi(w[2].s)
			}
			if !keys[n] {
				keys[n] = true
				if n > 0 {
					res.Left = append(res.Left, fmt.Sprintf("ntp authentication-key %d holds the device's ciphertext, so its value cannot be adopted: type it in the block where the device lacks it", n))
				} else {
					res.Left = append(res.Left, "an ntp authentication-key holds the device's ciphertext, so its value cannot be adopted")
				}
			}
		case !plain:
			outside++
		default:
			stmt := "set system " + strings.Join(parts, " ")
			if _, fs := ParseSystem(stmt + "\n"); HasErrors(fs) {
				outside++
				break
			}
			accepted = append(accepted, stmt)
		}
	}
	dev, _ := ParseSystem(strings.Join(accepted, "\n") + "\n")
	dev.Message = msg
	incl := &SystemBlock{}
	var already, conflict int
	// pick says whether a single value is new: not stated by this block (the
	// same value is a repeat, another is a conflict), and not stated by the
	// layer beneath with the same value.
	single := func(dv *Value, sv, uv *Value, set func(*Value)) {
		if dv == nil {
			return
		}
		switch {
		case sv != nil:
			if sv.Text == dv.Text {
				already++
			} else {
				conflict++
			}
		case uv != nil && uv.Text == dv.Text:
			already++
		default:
			set(dv)
		}
	}
	valueOf := func(b *SystemBlock, f func(*SystemBlock) *Value) *Value {
		if b == nil {
			return nil
		}
		return f(b)
	}
	single(dev.DomainName, valueOf(same, func(b *SystemBlock) *Value { return b.DomainName }),
		valueOf(up, func(b *SystemBlock) *Value { return b.DomainName }), func(v *Value) { incl.DomainName = v })
	single(dev.TimeZone, valueOf(same, func(b *SystemBlock) *Value { return b.TimeZone }),
		valueOf(up, func(b *SystemBlock) *Value { return b.TimeZone }), func(v *Value) { incl.TimeZone = v })
	single(dev.NTPBootServer, valueOf(same, func(b *SystemBlock) *Value { return b.NTPBootServer }),
		valueOf(up, func(b *SystemBlock) *Value { return b.NTPBootServer }), func(v *Value) { incl.NTPBootServer = v })
	single(dev.NTPSourceAddress, valueOf(same, func(b *SystemBlock) *Value { return b.NTPSourceAddress }),
		valueOf(up, func(b *SystemBlock) *Value { return b.NTPSourceAddress }), func(v *Value) {
			if layer != LayerDevice {
				res.Left = append(res.Left, "ntp source-address names an address of this device, which a scope's block does not state: it is left out (state it in the device's own block)")
				return
			}
			incl.NTPSourceAddress = v
		})
	if dev.Message != nil {
		var sm, um *Value
		if same != nil && same.Message != nil {
			sm = &Value{Text: same.Message.Body}
		}
		if up != nil && up.Message != nil {
			um = &Value{Text: up.Message.Body}
		}
		single(&Value{Text: dev.Message.Body}, sm, um, func(*Value) { incl.Message = dev.Message })
	}
	list := func(dst *[]Value, dv []Value, sv, uv []Value, eq func(a, b string) bool) {
		for _, v := range dv {
			has := func(l []Value) bool {
				return slices.ContainsFunc(l, func(o Value) bool { return eq(o.Text, v.Text) })
			}
			if has(sv) || has(uv) {
				already++
				continue
			}
			*dst = append(*dst, v)
		}
	}
	listOf := func(b *SystemBlock, f func(*SystemBlock) []Value) []Value {
		if b == nil {
			return nil
		}
		return f(b)
	}
	list(&incl.DomainSearch, dev.DomainSearch, listOf(same, func(b *SystemBlock) []Value { return b.DomainSearch }),
		listOf(up, func(b *SystemBlock) []Value { return b.DomainSearch }), strings.EqualFold)
	list(&incl.NameServers, dev.NameServers, listOf(same, func(b *SystemBlock) []Value { return b.NameServers }),
		listOf(up, func(b *SystemBlock) []Value { return b.NameServers }), func(a, b string) bool { return a == b })
	for _, s := range dev.NTPServers {
		find := func(b *SystemBlock) *NTPServer {
			if b == nil {
				return nil
			}
			for i := range b.NTPServers {
				if strings.EqualFold(b.NTPServers[i].Host, s.Host) {
					return &b.NTPServers[i]
				}
			}
			return nil
		}
		eq := func(o *NTPServer) bool {
			return o.Prefer == s.Prefer && o.Version == s.Version && o.Key == s.Key && o.RoutingInstance == s.RoutingInstance
		}
		switch o := find(same); {
		case o != nil && eq(o):
			already++
		case o != nil:
			conflict++
		default:
			if u := find(up); u != nil && eq(u) {
				already++
			} else {
				incl.NTPServers = append(incl.NTPServers, s)
			}
		}
	}
	for _, k := range dev.NTPTrustedKeys {
		has := func(b *SystemBlock) bool {
			return b != nil && slices.ContainsFunc(b.NTPTrustedKeys, func(o KeyRef) bool { return o.Number == k.Number })
		}
		if has(same) || has(up) {
			already++
			continue
		}
		incl.NTPTrustedKeys = append(incl.NTPTrustedKeys, k)
	}
	res.Text = incl.String(false)
	res.Statements = len(SystemStatements(incl))
	res.Objects = res.Statements

	note := func(n int, label, tail string) {
		if n > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %d %s, %s", label, n, count(n, "statement", "statements"), tail))
		}
	}
	note(outside, "outside what a system block takes (host name, login users and classes, services, syslog, and the like)", "not adopted")
	note(already, "stated already, with the same value, by this block or the scope's", "not repeated")
	note(conflict, "differing from what this block states (a single value, or a server with other options)", "left as they are (edit them in place)")
	return res
}

// count is the noun for n.
func count(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
