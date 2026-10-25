package devconf

// The Junos system section (0.2.7): the device's login message, domain name
// and search list, time zone, name servers and NTP, as 'display set' prints
// them and as the system block renders them, in one compared form.
//
//   - The login message is never in a compared statement, a stored section or
//     a report: it is a mark of its size and a short digest of its text
//     ('<message: 22 lines, 1300 characters, id 3fa9c2d1>'), so two messages
//     compare equal exactly when their bodies are (the device's \n-escaped
//     string and the block's heredoc are brought to one body first,
//     blocks.FromDeviceMessage). The pasted statement is the plan's own line.
//   - A host name (a domain, a search entry, an NTP server) is lower case, so
//     two spellings of a name are one statement.
//   - 'ntp server <h> prefer version 4' is the statements 'server <h>', 'server
//     <h> prefer' and 'server <h> version 4', which is how the device prints
//     it: each option is compared by itself, and a server is present when its
//     bare statement is.
//   - An 'ntp authentication-key <n>' is compared by its number: the
//     statement is 'authentication-key <n> value' with its value elided, and
//     the type is not compared (the device holds a ciphertext, so what can be
//     told is that a key of the number exists). The value is never stored.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
)

// reMessageMark matches the mark of a login message (as a statement's last
// word, with or without its quotes).
var reMessageMark = regexp.MustCompile(`^<message: [0-9]+ lines, [0-9]+ characters, id [0-9a-f]{8}>$`)

const messageStatement = "system login message "

// announcementStatement is the text shown before the login prompt (0.2.19),
// compared as the message is: by its mark.
const announcementStatement = "system login announcement "

// MessageMark is the compared form of a login message body: its size and a
// digest, never a word of the text.
func MessageMark(body string) string {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("<message: %d lines, %d characters, id %s>", strings.Count(body, "\n")+1, len(body), hex.EncodeToString(sum[:4]))
}

// isMessageMark reports a word that is the mark of a login message.
func isMessageMark(w string) bool { return reMessageMark.MatchString(w) }

// messageStmt reads a 'system login message <value>' statement from the text
// after its 'set' or 'deactivate': value is the device's quoted, \n-escaped
// string, a stored mark (a stem read again) or a bare word.
func messageStmt(head, rest string) (stmt, bool) {
	word := "message"
	value, ok := strings.CutPrefix(rest, messageStatement)
	if !ok {
		value, ok = strings.CutPrefix(rest, announcementStatement)
		word = "announcement"
	}
	if !ok {
		return stmt{}, false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return stmt{}, false
	}
	mark := strings.Trim(value, `"`)
	if !isMessageMark(mark) {
		body, err := blocks.FromDeviceMessage(value)
		if err != nil {
			// not a string this tacctl reads: it is compared as written, still
			// by digest
			body = value
		}
		mark = MessageMark(body)
	}
	ts := []token{{s: "system"}, {s: "login"}, {s: word}, {s: mark, quoted: true}}
	x := stmt{text: head + " " + renderTokens(ts)}
	x.stem = x.text
	x.path = []string{"system", "login", word, mark}
	return x, true
}

// sysPart is one statement of a system hierarchy line in its compared form.
type sysPart struct {
	ts     []token
	secret bool
}

// lowered is the token with its text in lower case.
func lowered(t token) token {
	t.s = strings.ToLower(t.s)
	return t
}

// systemParts puts a statement of the system section's hierarchies in its
// compared form: the statements it stands for (a server with its options
// several, a key's type none) and whether any was handled. Other statements
// of the 'system' hierarchy are not its.
func systemParts(s []token) ([]sysPart, bool) {
	if len(s) < 3 || s[0].s != "system" {
		return nil, false
	}
	one := func(ts []token) ([]sysPart, bool) { return []sysPart{{ts: ts}}, true }
	switch s[1].s {
	case "domain-name", "domain-search", "name-server":
		if len(s) != 3 {
			return nil, false
		}
		return one([]token{s[0], s[1], lowered(s[2])})
	case "time-zone":
		if len(s) != 3 {
			return nil, false
		}
		return one(s)
	case "syslog":
		// 'syslog host <h> <facility> <level>' and the options of a host: the
		// host is a name, so lower case; 'time-format' and 'source-address'
		// as they are. The rest of syslog (files, console, users) is the
		// device's own and goes the generic way.
		switch s[2].s {
		case "host":
			if len(s) < 5 {
				return nil, false
			}
			out := append([]token(nil), s...)
			out[3] = lowered(s[3])
			return one(out)
		case "time-format", "source-address":
			if len(s) != 4 {
				return nil, false
			}
			return one(s)
		}
		return nil, false
	case "login":
		// the retry options and the password policy: a leaf and its value
		if len(s) == 5 && (s[2].s == "retry-options" || s[2].s == "password") {
			return one(s)
		}
		return nil, false
	case "ntp":
	default:
		return nil, false
	}
	switch s[2].s {
	case "server":
		if len(s) < 4 {
			return nil, false
		}
		host := lowered(s[3])
		base := []token{s[0], s[1], s[2], host}
		out := []sysPart{{ts: base}}
		for i := 4; i < len(s); {
			w := s[i].s
			switch {
			case w == "prefer" && !s[i].quoted:
				out = append(out, sysPart{ts: append(append([]token(nil), base...), s[i])})
				i++
			case (w == "version" || w == "key" || w == "routing-instance") && !s[i].quoted && i+1 < len(s):
				out = append(out, sysPart{ts: append(append([]token(nil), base...), s[i], s[i+1])})
				i += 2
			default:
				// an option this tacctl does not know: kept as it is
				out = append(out, sysPart{ts: append(append([]token(nil), base...), s[i:]...)})
				i = len(s)
			}
		}
		return out, true
	case "boot-server", "source-address":
		if len(s) != 4 {
			return nil, false
		}
		return one([]token{s[0], s[1], s[2], lowered(s[3])})
	case "trusted-key":
		if len(s) != 4 {
			return nil, false
		}
		return one(s)
	case "authentication-key":
		// authentication-key <n> type <t> | value [<v>] | type <t> value <v>;
		// a stem read again has 'value' alone
		if len(s) < 5 {
			return nil, false
		}
		var out []sysPart
		key := []token{s[0], s[1], s[2], s[3]}
		for i := 4; i < len(s); {
			switch s[i].s {
			case "type":
				if i+1 >= len(s) {
					return nil, false
				}
				// the type is not compared: a key of the number is present
				i += 2
			case "value":
				out = append(out, sysPart{ts: append(append([]token(nil), key...), s[i]), secret: true})
				i += 2
			default:
				return nil, false
			}
		}
		return out, true
	}
	return nil, false
}
