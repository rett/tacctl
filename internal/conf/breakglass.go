package conf

// The per-scope break-glass local users of tacctl 0.2.3 in tacctl.yaml
// (decision D55): breakglass_scope.<scope>.users, a list of 'name:role'
// entries. Only the names and roles are recorded; no credential is stored,
// ever. Nothing here has a default: an absent key is "no break-glass user".

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/py"
)

// The roles of a break-glass user, as tacctl.yaml and the verb name them.
const (
	BreakGlassAdmin    = "admin"
	BreakGlassOperator = "operator"
	BreakGlassReadonly = "readonly"
)

// BreakGlassRoles are the roles in the order they are listed and shown.
var BreakGlassRoles = []string{BreakGlassAdmin, BreakGlassOperator, BreakGlassReadonly}

// BreakGlassUsersKey is the field the users are stored under, in
// breakglass_scope.<scope>.
const BreakGlassUsersKey = "users"

// MaxBreakGlassUsers is how many break-glass users one scope may record.
const MaxBreakGlassUsers = 16

// BreakGlassPath is the tacctl.yaml key of a scope's break-glass users.
func BreakGlassPath(scope string) string {
	return "breakglass_scope." + scope + "." + BreakGlassUsersKey
}

// BreakGlassEntry is the stored form of one user: 'name:role'.
func BreakGlassEntry(name, role string) string { return name + ":" + role }

// SplitBreakGlass splits a stored 'name:role' entry; ok is false when it
// is not one (no colon, a name that is not device-safe, an unknown role).
func SplitBreakGlass(entry string) (name, role string, ok bool) {
	name, role, found := strings.Cut(entry, ":")
	if !found || !names.MatchBreakGlass(name) || !ValidBreakGlassRole(role) {
		return "", "", false
	}
	return name, role, true
}

// ValidBreakGlassRole reports whether role is one of BreakGlassRoles.
func ValidBreakGlassRole(role string) bool {
	for _, r := range BreakGlassRoles {
		if r == role {
			return true
		}
	}
	return false
}

// breakGlassListProblem is the break-glass branch of Validate for
// breakglass_scope.<scope>.users.
func breakGlassListProblem(path string, value any) string {
	if field := path[strings.LastIndex(path, ".")+1:]; field != BreakGlassUsersKey {
		return "the only field of a scope's break-glass record is users"
	}
	items, isList := py.List(value)
	if !isList || len(items) == 0 {
		return "must be a non-empty list of 'name:role' entries"
	}
	if len(items) > MaxBreakGlassUsers {
		return fmt.Sprintf("at most %d break-glass users per scope; got %d", MaxBreakGlassUsers, len(items))
	}
	seen := map[string]bool{}
	for i, item := range items {
		s, isStr := item.(string)
		if !isStr {
			return fmt.Sprintf("element %d: must be a string", i)
		}
		name, _, found := strings.Cut(s, ":")
		if !found {
			return fmt.Sprintf("element %d: %s is not 'name:role' (role: %s)", i, py.ReprString(s), strings.Join(BreakGlassRoles, ", "))
		}
		if !names.MatchBreakGlass(name) {
			return fmt.Sprintf("element %d: %s is not a device-safe user name (a letter, then letters, digits, _ and -, 32 characters at most)", i, py.ReprString(name))
		}
		if _, _, ok := SplitBreakGlass(s); !ok {
			return fmt.Sprintf("element %d: the role of %s must be one of: %s", i, py.ReprString(name), strings.Join(BreakGlassRoles, ", "))
		}
		if seen[strings.ToLower(name)] {
			return fmt.Sprintf("element %d: %s is listed twice (names compare without regard to case)", i, py.ReprString(name))
		}
		seen[strings.ToLower(name)] = true
	}
	return ""
}
