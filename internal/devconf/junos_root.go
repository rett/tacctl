package devconf

// The Junos root account as a break-glass entry (0.2.20): the breakglass
// section checks it by two facts, root's password under 'system
// root-authentication' (by presence, as a local user's hash is) and 'system
// services ssh root-login allow', because Junos refuses root over ssh by
// default. Root's ssh keys are read as a presence mark and never kept; a
// hash or a key never reaches a record, a report or a log (junosStem keeps
// the leaf's name and nothing after it).
//
// Both statements are read into the section whether or not the scope records
// root, so a record does not depend on the scope's setting at the time of the
// pull; the comparison leaves them out when the rendering has no root.

import (
	"slices"
	"strings"
)

// The statements, as the stems the two sides compare: root's password is
// 'encrypted-password' alone (its value elided), the access the 'allow'.
const (
	rootAuthPrefix = "system root-authentication"
	rootPassword   = "system root-authentication encrypted-password"
	rootLoginPath  = "system services ssh root-login"
)

// isRootLogin reports a statement's path (the words after the verb) that is
// the 'root-login' leaf of 'system services ssh'.
func isRootLogin(p []string) bool {
	return len(p) >= 4 && p[0] == "system" && p[1] == "services" && p[2] == "ssh" && p[3] == "root-login"
}

// isRootAuth reports a path under 'system root-authentication' (the leaf
// itself, 'deactivate system root-authentication', included: section() puts
// it in the break-glass section as well).
func isRootAuth(p []string) bool {
	return len(p) >= 2 && p[0] == "system" && p[1] == "root-authentication"
}

// isSetStmt reports a 'set' statement (not a 'deactivate' one).
func isSetStmt(x stmt) bool { return strings.HasPrefix(x.stem, "set ") }

// isRootPassword reports the statement 'set system root-authentication
// encrypted-password': a deactivated password is not one.
func isRootPassword(x stmt) bool {
	return isSetStmt(x) && len(x.path) >= 3 && strings.Join(x.path[:3], " ") == rootPassword
}

// isRootKey reports a 'set system root-authentication ssh-<type> ...'
// statement: a public key (ssh-rsa, ssh-dsa, ssh-ecdsa, ssh-ed25519), and
// nothing else under the hierarchy.
func isRootKey(x stmt) bool {
	return isSetStmt(x) && isRootAuth(x.path) && len(x.path) >= 3 && strings.HasPrefix(x.path[2], "ssh-")
}

// isRootStmt reports one of the statements of the root break-glass access.
func isRootStmt(x stmt) bool { return isRootAuth(x.path) || isRootLogin(x.path) }

// rootBreakGlass puts the root statements of a device in the form the
// comparison reads and says what it shows about them. Without a root
// statement in the rendering they are dropped (the scope does not record
// root). With one, the device's ssh keys under root-authentication are not
// statements to compare: they are dropped, and a note says when they are all
// there is (a key is no local password); any other leaf there, and a
// deactivated one, stays a statement of the device. A root-login that is not
// 'allow' is left as the statement it is, a difference with its reason in a
// note.
func rootBreakGlass(exp, dev []stmt) ([]stmt, []string) {
	if !slices.ContainsFunc(exp, isRootStmt) {
		return slices.DeleteFunc(slices.Clone(dev), isRootStmt), nil
	}
	var notes []string
	havePassword, keys := false, false
	out := slices.DeleteFunc(slices.Clone(dev), func(x stmt) bool {
		if isRootPassword(x) {
			havePassword = true
		}
		if isRootKey(x) {
			keys = true
			return true
		}
		return false
	})
	if keys && !havePassword {
		notes = append(notes, "root-authentication holds ssh keys only (not compared) and no password: break-glass needs the local password")
	}
	login := ""
	for _, x := range out {
		if isSetStmt(x) && isRootLogin(x.path) && len(x.path) >= 5 {
			login = x.path[4]
		}
	}
	switch login {
	case "", "allow":
		if login == "" {
			notes = append(notes, "no root-login statement: Junos refuses root over ssh by default")
		}
	case "deny-password":
		notes = append(notes, "root-login is deny-password: root cannot log in over ssh with its password, which break-glass needs")
	case "deny":
		notes = append(notes, "root-login is deny: root cannot log in over ssh")
	default:
		notes = append(notes, "root-login is "+login+", not allow")
	}
	return out, notes
}
