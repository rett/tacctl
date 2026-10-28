package store

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

// CarvedPrefix starts the comment the TACACS+ renderer writes into the users
// section of tacquito.yaml for users it cut out of scopes the store gives them
// (a required password change, an emergency lockdown):
//
//	# tacctl-carved reason=password-change protocol=tacacs users=bob,carol
//
// The file does not say what the scopes were or that a requirement stands, so
// an import of it would bring those users back with what the file shows;
// ImportLoad reads the comment and refuses (unless forced), naming them.
const CarvedPrefix = "# tacctl-carved "

// Reasons a user is cut out of scopes in the rendered file.
const (
	CarvedPasswordChange = "password-change"
	CarvedLockdown       = "lockdown"
)

// CarvedLine is the comment for users cut for reason in the file of protocol.
func CarvedLine(reason, protocol string, users []string) string {
	u := append([]string(nil), users...)
	sort.Strings(u)
	return CarvedPrefix + "reason=" + reason + " protocol=" + protocol + " users=" + strings.Join(u, ",")
}

var reCarved = regexp.MustCompile(`(?m)^# tacctl-carved reason=(\S+) protocol=(\S+) users=(\S*)$`)

// Carved is a user named by a carved comment of a file.
type Carved struct{ User, Reason, Protocol string }

// CarvedUsers reads the carved comments of the file at path (none when it has
// none or cannot be read).
func CarvedUsers(path string) []Carved {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Carved
	for _, m := range reCarved.FindAllStringSubmatch(string(data), -1) {
		for _, u := range strings.Split(m[3], ",") {
			if u != "" {
				out = append(out, Carved{User: u, Reason: m[1], Protocol: m[2]})
			}
		}
	}
	return out
}

// carvedDrops lists, as the import's cannot-be-represented items, the users of
// the file that were cut out of scopes when it was rendered and are in the
// imported store.
func carvedDrops(src string, s *Store, rep *LegacyReport) {
	users := s.section("users")
	for _, c := range CarvedUsers(src) {
		if _, ok := mapOf(get(users, c.User)); !ok {
			continue
		}
		switch c.Reason {
		case CarvedPasswordChange:
			rep.drop("user '%s': cut to this server's own scope in the file (%s) because it must change the password; the file holds neither the scopes it had nor the requirement, so the store would give it that scope only and no requirement (lift the requirement first, or re-add the scopes and the requirement after)", c.User, c.Protocol)
		case CarvedLockdown:
			rep.drop("user '%s': cut out of the scope an emergency lockdown locks (%s) in the file; the file does not hold the scopes it had, so the store would keep it out of them for good ('emergency lockdown <scope> disable' first)", c.User, c.Protocol)
		default:
			rep.drop("user '%s': cut out of scopes when the file was rendered (%s, %s); the file does not hold what it had", c.User, c.Reason, c.Protocol)
		}
	}
}
