package blocks

// The IOS system block's closed table (system_rules.go): logging, the login
// and password policy, the ssh settings and summer time.

import "strings"

// rule reads a statement (its words) of the IOS table; it reports whether the
// table claimed it.
func (p *iosSysParser) rule(f []string) bool {
	r, c, claimed, why := iosRules.match(f, true)
	if !claimed {
		return false
	}
	if r == nil {
		p.errf("%s", why)
		return true
	}
	st := ruleStmtOf(r, c, p.line)
	if i := indexRule(p.b.Rules, st.Rule, st.Head); i >= 0 {
		p.errf("'%s' is stated twice (line %d)", strings.Join(c[:r.keyEnd], " "), p.b.Rules[i].Line)
		return true
	}
	p.b.Rules = append(p.b.Rules, st)
	return true
}

// ruleNo reads a 'no' line (the words after 'no') of the IOS table; it reports
// whether the table claimed it.
func (p *iosSysParser) ruleNo(t []string) bool {
	r, c, claimed, why := iosRules.match(t, false)
	if !claimed {
		r, c, claimed, why = iosAbsent.match(t, false)
	}
	if !claimed {
		return false
	}
	if r == nil {
		p.errf("a no line names the statement's identity: %s", why)
		return true
	}
	p.b.NotManaged = append(p.b.NotManaged, SystemNotManaged{Line: p.line, Kind: "rule:" + r.ID, Value: strings.Join(c, " ")})
	return true
}

// absent reads an 'absent <service>' line (the words after 'absent').
func (p *iosSysParser) absent(t []string) {
	r, c, claimed, why := iosAbsent.match(t, true)
	switch {
	case !claimed:
		p.errf("'absent' takes: %s", strings.Join(iosAbsent.patterns(), "; "))
		return
	case r == nil:
		p.errf("%s", why)
		return
	}
	st := ruleStmtOf(r, c, p.line)
	if i := indexRule(p.b.Rules, st.Rule, st.Head); i >= 0 {
		p.errf("'absent %s' is stated twice (line %d)", strings.Join(c, " "), p.b.Rules[i].Line)
		return
	}
	p.b.Rules = append(p.b.Rules, st)
}
