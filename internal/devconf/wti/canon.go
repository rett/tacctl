package wti

import (
	"regexp"
	"sort"
	"strings"
)

var reLabel = regexp.MustCompile(`^<(?:secret|other)(?::[1-9][0-9]*)?>$`)

// IsLabel reports a word that already stands for a community's string: the
// bare mark or a label '<secret:N>' / '<other:N>'.
func IsLabel(w string) bool { return reLabel.MatchString(w) }

// The canonical statements (wti-design W7). A statement is one line: a key
// of two to four words and a value.
//
//	aaa       tacacs enable on          tacacs fallback-local on-transport-failure
//	          tacacs primary 192.0.2.10 tacacs secret <secret>
//	          tacacs default-services serial,telnet-ssh,web,restful-api
//	          radius ... (the same keys of page 29, and primary-secret,
//	          secondary-secret, retries, accounting-port, onetime-*)
//	snmp      snmp enable on            snmp ro-community <secret:1>
//	          snmp contact "Example NOC"  snmp trap manager 1 192.0.2.34
//	mgmt-acl  iptables -A INPUT -i lo -j ACCEPT   (one per entry, in order)
//	breakglass user localadmin level administrator
//	          user localadmin password <secret>
//
// A pick is a lower-case word, a number is bare, a text is as printed and
// quoted when it holds a blank (a menu's truncation '...' is kept), a
// secret is only its presence mark. A community string is never in a
// canonical statement: the comparison elides it to a label.

// Form is how a statement's value is written.
type Form int

const (
	// FormUnknown: a line no key of the table starts.
	FormUnknown Form = iota
	// FormWord: one word (a pick, a number, an address, a list joined by
	// commas).
	FormWord
	// FormText: free text, quoted when it holds a blank.
	FormText
	// FormSecret: a secret; the statement says it is set and nothing else.
	FormSecret
	// FormCommunity: an SNMP community string (a secret of the device that
	// the comparison can see in clear), elided to a label.
	FormCommunity
	// FormCommand: an IP tables entry; the statement is the unit's command.
	FormCommand
	// FormUser: a statement about a local user.
	FormUser
)

// SecretMark stands for a secret's value in a statement.
const SecretMark = "<secret>"

// The tail of the unit's IP tables list (the last step of the
// walkthrough): the final DROP, the unit's own traffic out and the three
// policies.
var (
	tailRules    = []string{"-A INPUT -j DROP", "-A OUTPUT -j ACCEPT"}
	tailPolicies = []string{"-P INPUT DROP", "-P OUTPUT DROP", "-P FORWARD DROP"}
)

// TailCommands are the five commands of the tail, in the walkthrough's
// order, as an iptables statement's value.
func TailCommands() []string {
	return append(append([]string{}, tailRules...), tailPolicies...)
}

// IsPolicy reports an iptables value that sets a chain's policy.
func IsPolicy(value string) bool { return contains(tailPolicies, value) }

// IsTailRule reports an iptables value that is the final DROP or the
// unit's own OUTPUT ACCEPT.
func IsTailRule(value string) bool { return contains(tailRules, value) }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// keyForms are the keys of the table (a user's are handled by name) and
// their forms; keyWords the same keys as words, longest first.
var (
	keyForms = map[string]Form{"iptables": FormCommand}
	keyWords [][]string
)

// userSecretKeys are the statements of a user that only say a credential
// is set.
var userSecretKeys = map[string]bool{"password": true, "keys": true, "api-token": true}

func init() {
	for _, p := range Pages {
		for _, it := range p.Items {
			if it.Key != "" && !strings.Contains(it.Key, "{user}") {
				keyForms[it.Key] = it.Form
			}
		}
	}
	for k := range keyForms {
		keyWords = append(keyWords, strings.Fields(k))
	}
	sort.Slice(keyWords, func(i, j int) bool {
		if len(keyWords[i]) != len(keyWords[j]) {
			return len(keyWords[i]) > len(keyWords[j])
		}
		return strings.Join(keyWords[i], " ") < strings.Join(keyWords[j], " ")
	})
}

// Canonical is a statement taken apart.
type Canonical struct {
	Form Form
	// Key is the statement's key ("tacacs primary", "snmp trap manager 1",
	// "iptables"; for a user "level", "password"). Name is the local user
	// of a FormUser statement.
	Key  string
	Name string
	// Value is the canonical value, unquoted: for a FormSecret the presence
	// mark, for a FormCommunity the community string as the caller handed it
	// (in clear, or already a label). It is "" for a statement with no
	// value, which is no statement.
	Value string
}

// Quote writes a text value: bare, or in double quotes when it holds a
// blank (or is empty).
func Quote(v string) string {
	if v == "" || strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

// words splits a line at blanks, a double-quoted run being one word (kept
// with its quotes).
func words(s string) []string {
	var out []string
	var b strings.Builder
	in := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			in = !in
			b.WriteRune(r)
		case (r == ' ' || r == '\t') && !in:
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// ParseLine takes a statement line apart. It never fails: a line of no
// known key is FormUnknown with its words as Value.
func ParseLine(line string) Canonical {
	ws := words(strings.TrimSpace(line))
	if len(ws) == 0 {
		return Canonical{}
	}
	if ws[0] == "user" && len(ws) >= 3 {
		c := Canonical{Form: FormUser, Name: unquote(ws[1]), Key: ws[2], Value: strings.Join(ws[3:], " ")}
		if userSecretKeys[c.Key] {
			c.Value = SecretMark
		}
		return c
	}
	for _, kw := range keyWords {
		if len(ws) < len(kw) || !equalWords(ws[:len(kw)], kw) {
			continue
		}
		key := strings.Join(kw, " ")
		rest := ws[len(kw):]
		c := Canonical{Form: keyForms[key], Key: key}
		switch c.Form {
		case FormCommand:
			// 'iptables N iptables -A ...', 'iptables N -A ...' and
			// 'iptables iptables -A ...' are all the command itself.
			if len(rest) > 0 && isDigits(rest[0]) {
				rest = rest[1:]
			}
			if len(rest) > 0 && rest[0] == "iptables" {
				rest = rest[1:]
			}
			c.Value = strings.Join(rest, " ")
		case FormText:
			c.Value = unquote(strings.Join(rest, " "))
		case FormSecret:
			c.Value = SecretMark
		default:
			c.Value = unquote(strings.Join(rest, " "))
		}
		return c
	}
	return Canonical{Form: FormUnknown, Value: strings.Join(ws, " ")}
}

func equalWords(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Words are the statement's parts as the comparison's path: the key and
// the value, for a user's the name, the key and the value, for an
// IP tables entry 'iptables' and the command.
func (c Canonical) Words() []string {
	switch c.Form {
	case FormUnknown:
		return strings.Fields(c.Value)
	case FormUser:
		return []string{"user", c.Name, c.Key, c.Value}
	}
	return []string{c.Key, c.Value}
}

// Raw is the statement's line: the community string of a FormCommunity in
// clear when it is. It is for the in-memory comparison only.
func (c Canonical) Raw() string {
	switch c.Form {
	case FormUnknown:
		return c.Value
	case FormUser:
		return "user " + Quote(c.Name) + " " + c.Key + " " + c.Value
	case FormText:
		return c.Key + " " + Quote(c.Value)
	case FormSecret:
		return c.Key + " " + SecretMark
	}
	return c.Key + " " + c.Value
}

// String is the statement's line with no secret in it: a community string
// is shown as the mark.
func (c Canonical) String() string {
	if c.Form == FormCommunity && !IsLabel(c.Value) {
		return c.Key + " " + SecretMark
	}
	return c.Raw()
}

// Statement is a statement of a section.
type Statement struct {
	Section string
	Canonical
}
