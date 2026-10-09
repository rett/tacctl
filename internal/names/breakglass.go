package names

import "regexp"

// reBreakGlass is a break-glass local user's name: it must be accepted by
// every device the walkthroughs address (a WTI user name is at most 32
// characters; Cisco and Junos read nothing else as syntax in these).
var reBreakGlass = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// MatchBreakGlass reports whether s can be the name of a break-glass local
// user: a letter, then up to 31 letters, digits, '_' or '-'.
func MatchBreakGlass(s string) bool { return reBreakGlass.MatchString(s) }
