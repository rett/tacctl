package devconf

import (
	"fmt"
	"slices"
	"strings"
)

// loginUser returns the local user a statement of the break-glass section is
// about: the token after 'system login user' on Junos, after 'username' on IOS.
func loginUser(x stmt) (string, bool) {
	if len(x.path) >= 4 && x.path[0] == "system" && x.path[1] == "login" && x.path[2] == "user" {
		return x.path[3], true
	}
	if len(x.path) > 0 {
		if f := strings.Fields(x.path[len(x.path)-1]); len(f) >= 2 && f[0] == "username" {
			return f[1], true
		}
	}
	return "", false
}

// foldLoginNames makes a device's login user that differs from a rendered one
// only in case compare equal to it, and says so: the section reads ok with a
// note instead of a missing and an extra user. Login names are case-sensitive on
// the device, so the note keeps the difference in view (a login by the scope's
// spelling is refused there); it is not an error of the account's presence. A
// device that has the rendered spelling as well keeps its other spelling as an
// extra, and two rendered names that fold together are left alone.
func foldLoginNames(exp, dev []stmt) ([]stmt, []string) {
	expNames := map[string]bool{}
	for _, x := range exp {
		if n, ok := loginUser(x); ok {
			expNames[n] = true
		}
	}
	devNames := map[string]bool{}
	for _, x := range dev {
		if n, ok := loginUser(x); ok {
			devNames[n] = true
		}
	}
	fold := map[string]string{}
	ambiguous := map[string]bool{}
	for n := range expNames {
		l := strings.ToLower(n)
		if _, dup := fold[l]; dup {
			ambiguous[l] = true
		}
		fold[l] = n
	}
	var notes []string
	out := slices.Clone(dev)
	for i, x := range out {
		n, ok := loginUser(x)
		if !ok || expNames[n] {
			continue
		}
		l := strings.ToLower(n)
		m, found := fold[l]
		if !found || ambiguous[l] || devNames[m] || m == n {
			continue
		}
		y := x
		y.path = slices.Clone(x.path)
		if len(y.path) >= 4 && y.path[0] == "system" {
			y.path[3] = m
			y.text = strings.Replace(y.text, " user "+n+" ", " user "+m+" ", 1)
			y.stem = strings.Replace(y.stem, " user "+n+" ", " user "+m+" ", 1)
		} else {
			last := len(y.path) - 1
			y.path[last] = strings.Replace(y.path[last], "username "+n+" ", "username "+m+" ", 1)
			y.text = strings.Replace(y.text, "username "+n+" ", "username "+m+" ", 1)
			y.stem = strings.Replace(y.stem, "username "+n+" ", "username "+m+" ", 1)
		}
		out[i] = y
		note := fmt.Sprintf("login user '%s' on the device is '%s' in the scope: the names differ only in case, and they are "+
			"case-sensitive on the device, so a login by the scope's spelling is refused there", n, m)
		if !slices.Contains(notes, note) {
			notes = append(notes, note)
		}
	}
	return out, notes
}
