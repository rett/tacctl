package devconf

// Junos: the text of 'show configuration | display set' (verified identical
// over an exec channel, NETCONF <command> and <get-configuration
// format="set">), and the 'set' lines devices.Managed renders.
//
// Both sides are put in the form 'display set' prints: one leaf per line, a
// bracket list ('[ login change-log ]') and a brace block ('then { log;
// discard; }') expanded, a user's 'class' and 'authentication' split,
// tokens unquoted and re-quoted only where needed. A secret's value ('$9$…',
// '$6$…', or the '/* SECRET-DATA */' comment a class without the secret
// permission is shown) is elided from the compared form.
//
// 'deactivate <path>' lines are statements of the hierarchy of <path> (a
// deactivated managed statement is a finding); 'protect', 'unprotect',
// 'activate' and 'annotate' lines, comments and 'delete' commands are
// ignored, and so are the 'groups' and 'apply-groups' lines: the read asks
// for 'display inheritance', which shows a group-applied statement at its
// normal path, so the group definitions are informational only.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// token is one word of a Junos statement.
type token struct {
	s string
	// quoted is set for a word that was quoted: it is never punctuation.
	quoted bool
}

// punct reports an unquoted bracket, brace or semicolon.
func (t token) punct(p string) bool { return !t.quoted && t.s == p }

// comment is a '/* ... */' token (Junos shows a hidden secret as one).
func (t token) comment() bool {
	return strings.HasPrefix(t.s, "/*") && strings.HasSuffix(t.s, "*/")
}

// tokenize splits a statement into words: whitespace separates, double and
// single quotes group (a backslash escapes in double quotes), '/* ... */' is
// one word, ';' is a word of its own.
func tokenize(s string) []token {
	var out []token
	rs := []rune(s)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t':
			i++
		case r == ';':
			out = append(out, token{s: ";"})
			i++
		case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
			j := i + 2
			for j+1 < len(rs) && (rs[j] != '*' || rs[j+1] != '/') {
				j++
			}
			j = min(j+2, len(rs))
			out = append(out, token{s: string(rs[i:j])})
			i = j
		default:
			var b strings.Builder
			quoted := false
			for i < len(rs) && rs[i] != ' ' && rs[i] != '\t' && rs[i] != ';' {
				switch c := rs[i]; c {
				case '"':
					quoted = true
					i++
					for i < len(rs) && rs[i] != '"' {
						if rs[i] == '\\' && i+1 < len(rs) {
							i++
						}
						b.WriteRune(rs[i])
						i++
					}
					i++
				case '\'':
					quoted = true
					i++
					for i < len(rs) && rs[i] != '\'' {
						b.WriteRune(rs[i])
						i++
					}
					i++
				default:
					b.WriteRune(c)
					i++
				}
			}
			out = append(out, token{s: b.String(), quoted: quoted})
		}
	}
	return out
}

// render is the canonical text of a token: bare unless it holds a space,
// a quote or a character Junos reads as structure.
func (t token) render() string {
	if t.comment() || t.s == secretMark {
		return t.s
	}
	if t.s == "" || strings.ContainsAny(t.s, " \t\"'\\;[]{}") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(t.s) + `"`
	}
	return t.s
}

func renderTokens(ts []token) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.render()
	}
	return strings.Join(parts, " ")
}

// expand resolves the first bracket list or brace block of a statement,
// then the rest: 'a [ b c ] d' is 'a b d' and 'a c d'; 'a { b; c d; }' is
// 'a b' and 'a c d'.
func expand(ts []token) [][]token {
	for i, t := range ts {
		switch {
		case t.punct("["):
			end := slices.IndexFunc(ts[i+1:], func(x token) bool { return x.punct("]") })
			if end < 0 {
				return [][]token{ts}
			}
			end += i + 1
			var out [][]token
			for _, item := range ts[i+1 : end] {
				next := slices.Concat(ts[:i], []token{item}, ts[end+1:])
				out = append(out, expand(next)...)
			}
			return out
		case t.punct("{"):
			depth, end := 0, -1
			for j := i; j < len(ts); j++ {
				if ts[j].punct("{") {
					depth++
				} else if ts[j].punct("}") {
					if depth--; depth == 0 {
						end = j
						break
					}
				}
			}
			if end < 0 {
				return [][]token{ts}
			}
			var out [][]token
			var cur []token
			flush := func() {
				if len(cur) > 0 {
					out = append(out, expand(slices.Concat(ts[:i], cur, ts[end+1:]))...)
					cur = nil
				}
			}
			nest := 0
			for _, x := range ts[i+1 : end] {
				switch {
				case x.punct("{"):
					nest++
				case x.punct("}"):
					nest--
				}
				if x.punct(";") && nest == 0 {
					flush()
					continue
				}
				cur = append(cur, x)
			}
			flush()
			return out
		}
	}
	return [][]token{ts}
}

// junosSecretKeys are the keywords whose next word is a secret the device
// stores encrypted or hashed: the server secrets, the password and key
// leaves, and the broad list of the safety net (a statement the rules
// below do not know by name is elided all the same).
var junosSecretKeys = map[string]bool{
	"secret": true, "encrypted-password": true, "plain-text-password-value": true,
	"authentication-key": true, "privacy-key": true, "community-name": true,
	"pre-shared-key": true, "ascii-text": true, "hexadecimal": true,
}

// reHash is a password hash or an obfuscated secret as Junos prints it
// ('$9$…', '$6$…', '$1$…'): one word, no blanks.
var reHash = regexp.MustCompile(`^\$[0-9]{1,2}\$\S{4,}$`)

// hashed reports a word that is a password hash or an obfuscated secret.
func hashed(t token) bool { return reHash.MatchString(t.s) }

// elideKeys removes the value of every secret keyword of the statement
// (the word after it, unless that word is a keyword itself, as in
// 'pre-shared-key ascii-text <value>'). The value is kept as a mark only
// when words follow it.
func elideKeys(ts []token, ok func(i int, t token) bool) ([]token, bool) {
	var out []token
	found := false
	for i := 0; i < len(ts); i++ {
		out = append(out, ts[i])
		if !ok(i, ts[i]) {
			continue
		}
		found = true
		if i+1 >= len(ts) {
			continue
		}
		if ok(i+1, ts[i+1]) {
			continue // a keyword in turn: its own value is the next
		}
		i++
		if i+1 < len(ts) {
			out = append(out, token{s: secretMark})
		}
	}
	return out, found
}

// junosStem returns the statement without a secret's value, and whether it
// carries one. marked is the rendering side's mark; the device side is
// found by its keywords and by the look of the value.
func junosStem(ts []token, marked bool) ([]token, bool) {
	if slices.ContainsFunc(ts, func(t token) bool { return t.s == secretMark && !t.quoted }) {
		// Already elided: a stem read again.
		return ts, true
	}
	if len(ts) >= 3 && ts[0].s == "snmp" && (ts[1].s == "community" || ts[1].s == "trap-group") {
		// The community's name is the secret, and a trap group's name is
		// the community its traps are sent with.
		out := slices.Clone(ts)
		out[2] = token{s: secretMark}
		return out, true
	}
	isKey := func(i int, t token) bool {
		// A quoted word is text; 'permissions secret' is a login class's
		// permission bit, not a secret.
		return !t.quoted && junosSecretKeys[t.s] && (i == 0 || ts[i-1].s != "permissions")
	}
	if out, found := elideKeys(ts, isKey); found {
		return out, true
	}
	// A public key is no secret, but a login without the secret permission
	// is shown it masked: it is compared by presence like one.
	isSSHKey := func(i int, t token) bool {
		return i > 0 && ts[i-1].s == "authentication" && !t.quoted && (strings.HasPrefix(t.s, "ssh-") || strings.HasPrefix(t.s, "ecdsa-sha2-"))
	}
	if out, found := elideKeys(ts, isSSHKey); found {
		return out, true
	}
	// A hash or a masked value in a statement no rule knows: the word is
	// elided, the rest of the statement stays.
	var out []token
	for i, t := range ts {
		if (t.comment() && !t.quoted && strings.Contains(t.s, maskedSecret)) || hashed(t) {
			if out == nil {
				out = slices.Clone(ts)
			}
			out[i] = token{s: secretMark}
		}
	}
	if out != nil {
		return out, true
	}
	if marked && len(ts) > 0 {
		out := slices.Clone(ts)
		out[len(out)-1] = token{s: secretMark}
		return out, true
	}
	return ts, false
}

// junosCanon canonicalises 'set' (and 'deactivate') lines.
func junosCanon(lines []string, marks []bool) []stmt {
	var out []stmt
	for n, line := range lines {
		head, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		if head != "set" && head != "deactivate" {
			continue
		}
		ts := tokenize(rest)
		if len(ts) == 0 {
			continue
		}
		// A rendered line that stands for several statements is marked
		// secret as a whole, but only its secret leaf is one: the leaf is
		// found by its keyword.
		var parts [][]token
		for _, one := range expand(ts) {
			parts = append(parts, splitJunosUser(one)...)
		}
		marked := markAt(marks, n) && len(parts) == 1
		for _, s := range parts {
			for i := range s {
				switch s[i].s {
				case "authentication-password":
					s[i].s = "authentication-key"
				case "privacy-password":
					s[i].s = "privacy-key"
				}
			}
			stem, secret := junosStem(s, marked)
			x := stmt{text: head + " " + renderTokens(s), secret: secret}
			x.stem = x.text
			if secret {
				x.stem = head + " " + renderTokens(stem)
			}
			x.path = make([]string, len(s))
			for i, t := range s {
				x.path[i] = t.s
			}
			out = append(out, x)
		}
	}
	return out
}

// splitJunosUser splits 'system login user U class C authentication …' as
// 'display set' prints it: the class and each other leaf on its own line.
func splitJunosUser(ts []token) [][]token {
	if len(ts) <= 6 || ts[0].s != "system" || ts[1].s != "login" || ts[2].s != "user" || ts[4].s != "class" {
		return [][]token{ts}
	}
	return [][]token{ts[:6:6], slices.Concat(ts[:4:4], ts[6:])}
}

// junosCtx is what the classification of the device's statements needs
// from the whole text and from the rendering side.
type junosCtx struct {
	claim map[string]string // stem -> section, the rendered statements'
	// classes and filters the rendering names; nil when there is none (all
	// of the device's classes are kept, the filters applied on lo0).
	classes, filters map[string]bool
	// users: the rendering's users by section (roles or breakglass).
	users map[string]string
	// lo0 is set when the rendering applies a filter on lo0.
	lo0 bool
	// device side: a user's class, and the filters applied on lo0.
	userClass map[string]string
	lo0Filter map[string]bool
}

// lo0Apply returns the filter names an 'interfaces lo0 unit N family F
// filter <direction> <name>' statement applies.
func lo0Apply(p []string) (names []string, ok bool) {
	if len(p) < 7 || p[0] != "interfaces" || p[1] != "lo0" {
		return nil, false
	}
	i := slices.Index(p, "filter")
	if i < 0 {
		return nil, false
	}
	if i+2 < len(p) {
		names = p[i+2:]
	}
	return names, true
}

// defaultFilterNames are the names tacctl's own filters have by default;
// they are kept when nothing says otherwise.
var defaultFilterNames = []string{"MGMT-ACL"}

// section is the managed section a statement of the device belongs to, or
// "" when none: the rendered statements claim theirs, the rest go by
// hierarchy (plan D62).
func (c *junosCtx) section(x stmt) string {
	if s, ok := c.claim[x.stem]; ok {
		return s
	}
	p := x.path
	if len(p) < 2 {
		return ""
	}
	switch {
	case p[0] == "groups" || p[0] == "apply-groups" || p[0] == "apply-groups-except":
		// Group definitions: the read shows what they apply at the normal
		// path (display inheritance), so these are informational.
		return ""
	case p[0] == "system" && len(p) >= 2:
		switch p[1] {
		case "authentication-order", "tacplus-server", "radius-server", "tacplus-options", "radius-options", "accounting":
			return SectionAAA
		case "login":
			return c.login(p)
		case "services":
			if len(p) >= 3 && p[2] == "netconf" {
				return SectionNetconf
			}
		}
	case p[0] == "snmp":
		return SectionSNMP
	case p[0] == "firewall":
		// firewall family <inet|inet6> filter <name> ...
		if len(p) >= 5 && p[1] == "family" && p[3] == "filter" && c.filters[p[4]] {
			return SectionMgmtACL
		}
	case p[0] == "interfaces":
		if names, ok := lo0Apply(p); ok {
			if c.lo0 || slices.ContainsFunc(names, func(n string) bool { return c.filters[n] }) {
				return SectionMgmtACL
			}
		}
	}
	return ""
}

// login classifies a 'system login ...' statement.
func (c *junosCtx) login(p []string) string {
	if len(p) < 4 {
		return ""
	}
	switch p[2] {
	case "class":
		if c.classes == nil || c.classes[p[3]] {
			return SectionRoles
		}
	case "user":
		u := p[3]
		if len(p) >= 5 && p[4] == "uid" {
			// Junos assigns it; it is not something tacctl manages.
			return ""
		}
		if s, ok := c.users[u]; ok {
			return s
		}
		if c.userClass[u] == u {
			return SectionRoles
		}
		return SectionBreakGlass
	}
	return ""
}

// maskedSecret is the word of the placeholder ('/* SECRET-DATA */') a login
// without the secret permission is shown in place of a secret's value.
const maskedSecret = "SECRET-DATA"

// maskedText reports whether the text holds a masked secret: a
// '/* SECRET-DATA */' comment word of a statement (never free text inside
// quotes).
func maskedText(lines []string) bool {
	for _, l := range lines {
		for _, t := range tokenize(l) {
			if !t.quoted && t.comment() && strings.Contains(t.s, maskedSecret) {
				return true
			}
		}
	}
	return false
}

// junosExtract is Extract for Junos.
func junosExtract(raw string, expected []devices.Section, visible *bool) (Extracted, error) {
	text := cleanText(raw)
	lines := strings.Split(text, "\n")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "error:") || strings.HasPrefix(t, "syntax error") || strings.HasPrefix(t, "unknown command") {
			return Extracted{}, fmt.Errorf("%w: the device refused the command", ErrParse)
		}
	}
	got := junosCanon(lines, nil)
	if !slices.ContainsFunc(got, func(x stmt) bool { return strings.HasPrefix(x.text, "set ") }) {
		return Extracted{}, fmt.Errorf("%w: no 'set' statement in the text", ErrParse)
	}

	c := &junosCtx{claim: map[string]string{}, users: map[string]string{},
		userClass: map[string]string{}, lo0Filter: map[string]bool{}}
	haveExpected := false
	for _, sec := range expected {
		for _, x := range junosCanon(sec.Lines, sec.Secret) {
			haveExpected = true
			c.claim[x.stem] = sec.Name
			p := x.path
			switch {
			case len(p) >= 4 && p[0] == "system" && p[1] == "login" && p[2] == "class":
				if c.classes == nil {
					c.classes = map[string]bool{}
				}
				c.classes[p[3]] = true
			case len(p) >= 4 && p[0] == "system" && p[1] == "login" && p[2] == "user":
				if _, ok := c.users[p[3]]; !ok && (sec.Name == SectionRoles || sec.Name == SectionBreakGlass) {
					c.users[p[3]] = sec.Name
				}
			case len(p) >= 5 && p[0] == "firewall" && p[1] == "family" && p[3] == "filter":
				if c.filters == nil {
					c.filters = map[string]bool{}
				}
				c.filters[p[4]] = true
			}
			if names, ok := lo0Apply(p); ok {
				c.lo0 = true
				for _, n := range names {
					if c.filters == nil {
						c.filters = map[string]bool{}
					}
					c.filters[n] = true
				}
			}
		}
	}
	for _, x := range got {
		p := x.path
		if len(p) >= 6 && p[0] == "system" && p[1] == "login" && p[2] == "user" && p[4] == "class" {
			c.userClass[p[3]] = p[5]
		}
		if names, ok := lo0Apply(p); ok {
			for _, n := range names {
				c.lo0Filter[n] = true
			}
		}
	}
	if !haveExpected {
		// Nothing says which filters are tacctl's: the ones applied on lo0
		// and the shipped default's name.
		c.filters = map[string]bool{}
		for n := range c.lo0Filter {
			c.filters[n] = true
		}
		for _, n := range defaultFilterNames {
			c.filters[n] = true
		}
		c.lo0 = true
	}

	by := map[string][]stmt{}
	for _, x := range got {
		if s := c.section(x); s != "" {
			by[s] = append(by[s], x)
		}
	}
	out := make(map[string]devices.Section, len(SectionNames))
	for _, n := range SectionNames {
		out[n] = toSection(n, uniq(by[n]))
	}
	vis := !maskedText(lines)
	if visible != nil {
		vis = *visible
	}
	return Extracted{Vendor: FamilyJunos, Sections: out, SecretsVisible: vis}, nil
}
