package devconf

// The statements a system block requires to be absent (0.2.19, 'absent system
// services telnet' on Junos, 'absent ip http server' on IOS): the rendering's
// system section names them (devices.Section.Forbid), the pull sorts the
// device's statements at or under one into that section, and the comparison
// takes each as a difference (the planner deletes it).

import (
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// forbidOf are the statements the rendering's system section requires to be
// absent.
func forbidOf(expected []devices.Section) []string {
	for _, sec := range expected {
		if sec.Name == SectionSystem {
			return sec.Forbid
		}
	}
	return nil
}

// forbiddenWords reports whether a statement's words are at or under one of
// the forbidden statements.
func forbiddenWords(forbid []string, words []string) bool {
	for _, f := range forbid {
		fw := strings.Fields(f)
		if len(words) < len(fw) {
			continue
		}
		ok := true
		for i := range fw {
			ok = ok && fw[i] == words[i]
		}
		if ok {
			return true
		}
	}
	return false
}

// Forbidden reports whether a statement of a device (its words: the Junos path
// without the verb, or the IOS line) is at or under a statement the section
// requires to be absent.
func Forbidden(sec devices.Section, words []string) bool {
	return forbiddenWords(sec.Forbid, words)
}
