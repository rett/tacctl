package devconf

// The IOS system section (0.2.7): the device's login banner, domain name and
// list, time zone, name servers and NTP, as 'show running-config' prints them
// and as the system block renders them, in one compared form. As on Junos,
// the section exists only for a scope that has a system block in force.
//
//   - A login banner is never in a compared statement, a stored section or a
//     report: it is 'banner login <message: 22 lines, 1300 characters, id
//     3fa9c2d1>', a mark of its size and a short digest of its text, so two
//     banners compare equal exactly when their bodies are. The device's text
//     is read by blocks.DeviceBanner ('^C' or one printable delimiter, the
//     first and the last line break belonging to the delimiters), the
//     rendering's by the same function, and both are brought to one body
//     first.
//   - 'ip domain-name' and 'ip domain-list' are the legacy spellings of 'ip
//     domain name' and 'ip domain list' and are compared as the latter; a
//     host name is lower case.
//   - 'clock timezone CET 1' (12.4) and 'clock timezone CET 1 0' (15.x) are
//     one statement, with its minutes.
//   - 'ip name-server A B C' is one statement per address.
//   - 'ntp server' keeps its address and the set of its options, in one order:
//     the keywords are reordered by the device when stored.
//   - An 'ntp authentication-key <n> md5 <string> [7]' is compared by its
//     number: the algorithm and the string (the device holds ciphertext) are
//     not, and the string is never stored.
//   - 'snmp-server trap-source Lo0' is stored by the device as 'Loopback0': the
//     interface is compared without case (the block requires the full name).
//
// Nothing here has been seen on a router: the shapes are the vendor
// references' (the plan's report says so).

import (
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
)

// reIOSBannerMark matches the stored form of a login banner.
var reIOSBannerMark = regexp.MustCompile(`^banner login <message: [0-9]+ lines, [0-9]+ characters, id [0-9a-f]{8}>$`)

// iosBannerStmt is the compared statement of a banner body.
func iosBannerStmt(body string) string { return "banner login " + MessageMark(body) }

// isIOSBannerMark reports a statement that is a stored banner mark.
func isIOSBannerMark(s string) bool { return reIOSBannerMark.MatchString(s) }

// isSystemStatement reports a top-level statement that belongs to the system
// section when the rendering has one: the banner, the domain name and list
// (either spelling, any vrf form), the time zone, the name servers and every
// 'ntp' statement.
func isSystemStatement(t string) bool {
	switch {
	case t == "banner login", strings.HasPrefix(t, "banner login "):
		return true
	case strings.HasPrefix(t, "ip domain name "), strings.HasPrefix(t, "ip domain-name "),
		strings.HasPrefix(t, "ip domain list "), strings.HasPrefix(t, "ip domain-list "),
		strings.HasPrefix(t, "ip name-server "), strings.HasPrefix(t, "clock timezone "):
		return true
	case t == "ntp", strings.HasPrefix(t, "ntp "):
		return true
	}
	return false
}

// expandNameServers splits a statement 'ip name-server [vrf <v>] A B C' into
// one statement per address (nil when it is not one or has one address).
func expandNameServers(f []string) [][]string {
	if len(f) < 3 || f[0] != "ip" || f[1] != "name-server" {
		return nil
	}
	head := f[:2]
	rest := f[2:]
	if rest[0] == "vrf" && len(rest) >= 2 {
		head, rest = f[:4], f[4:]
		if len(f) < 4 {
			return nil
		}
	}
	if len(rest) <= 1 {
		return nil
	}
	var out [][]string
	for _, a := range rest {
		out = append(out, append(append([]string(nil), head...), a))
	}
	return out
}

// ciscoSystemLine puts a top-level system statement (its fields) in its
// compared form; any other statement is returned as it is.
func ciscoSystemLine(f []string) []string {
	if len(f) < 2 {
		return f
	}
	switch {
	case f[0] == "ip" && (f[1] == "domain-name" || f[1] == "domain-list") && len(f) == 3:
		return []string{"ip", "domain", strings.TrimPrefix(f[1], "domain-"), strings.ToLower(f[2])}
	case f[0] == "ip" && f[1] == "domain" && len(f) == 4 && (f[2] == "name" || f[2] == "list") && f[3] != "vrf":
		return []string{"ip", "domain", f[2], strings.ToLower(f[3])}
	case f[0] == "ip" && f[1] == "name-server" && len(f) == 3:
		return []string{"ip", "name-server", strings.ToLower(f[2])}
	case f[0] == "clock" && f[1] == "timezone" && (len(f) == 4 || len(f) == 5):
		h := strings.TrimPrefix(f[3], "+")
		m := "0"
		if len(f) == 5 {
			m = f[4]
		}
		return []string{"clock", "timezone", f[2], h, m}
	case f[0] == "ntp" && f[1] == "server" && len(f) >= 3:
		return ciscoNTPServer(f)
	case f[0] == "snmp-server" && f[1] == "trap-source" && len(f) == 3:
		return []string{"snmp-server", "trap-source", strings.ToLower(f[2])}
	}
	return f
}

// ciscoNTPServer is 'ntp server <host> [key N] [prefer] [source IF] [version
// V]': the options in one order, the host and the interface without case. A
// statement with a word this does not know (a vrf, an option of another
// release) is returned as it is, which compares it as written.
func ciscoNTPServer(f []string) []string {
	host := f[2]
	if host == "vrf" || host == "ip" || host == "ipv6" {
		return f
	}
	var key, ver, src string
	prefer := false
	for i := 3; i < len(f); i++ {
		switch f[i] {
		case "prefer":
			if prefer {
				return f
			}
			prefer = true
		case "key", "version", "source":
			if i+1 >= len(f) {
				return f
			}
			i++
			dst := &key
			switch f[i-1] {
			case "version":
				dst = &ver
			case "source":
				dst = &src
			}
			if *dst != "" {
				return f
			}
			*dst = f[i]
		default:
			return f
		}
	}
	out := []string{"ntp", "server", strings.ToLower(host)}
	if key != "" {
		out = append(out, "key", key)
	}
	if prefer {
		out = append(out, "prefer")
	}
	if src != "" {
		out = append(out, "source", strings.ToLower(src))
	}
	if ver != "" {
		out = append(out, "version", ver)
	}
	return out
}

// DeviceBannerBody is blocks.DeviceBanner for the lines of a device's text.
func deviceBannerBody(lines []string) (string, int, bool) { return blocks.DeviceBanner(lines) }
