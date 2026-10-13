package devices

import (
	"regexp"
	"strconv"
)

// A gate is a statement that a release may not have yet: the first release
// that takes it, and the form the walkthrough renders before it. A row is
// added only when a real device refused the statement; there is no model or
// version matrix, because the device's own check refuses the rest.
//
// A device whose release is not known (no pull, or a release string no row
// can read) gets the current form. The IOS dialect facts do not ride on the
// release: they ride on Request.Legacy, the IOS 12.x syntax every Cisco
// compare resolves (devconf.SyntaxRows).
type gate struct {
	vendor    string
	statement string
	// first is the first release that takes the statement: major, minor.
	first [2]int
}

var gates = []gate{
	// Junos: 'set system login idle-timeout' exists from 16.1 (Juniper's
	// reference); a 11.4 switch refuses it at 'commit check'. Before it the
	// timeout is set per login class.
	{vendor: "juniper", statement: "system login idle-timeout", first: [2]int{16, 1}},
}

// junosRelease reads "<major>.<minor>" from a Junos release string
// ("25.4R1-S2.3", "11.4R7.5", "12.1X44-D35.5").
var junosRelease = regexp.MustCompile(`^(\d+)\.(\d+)`)

// lacks reports whether the device's recorded release is known to be older
// than the first release that takes the statement.
func (d Data) lacks(vendor, statement string) bool {
	if d.Release == "" {
		return false
	}
	for _, g := range gates {
		if g.vendor != vendor || g.statement != statement {
			continue
		}
		if vendor != "juniper" {
			return false
		}
		m := junosRelease.FindStringSubmatch(d.Release)
		if m == nil {
			return false
		}
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		return maj < g.first[0] || (maj == g.first[0] && min < g.first[1])
	}
	return false
}
