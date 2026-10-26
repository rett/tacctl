package cli

import "testing"

// '?' after the words of 'scope block' and 'device block' lists a
// description beside every fixed word: the vendors, the verbs and the block
// names, including the block of 'adopt <device> <block>' (0.2.19).
func TestShellBlockWordsHaveDescriptions(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"scope", "block", "lab"}, []string{"cisco", "juniper"}},
		{[]string{"scope", "block", "lab", "juniper"}, []string{"list", "show", "check", "set", "remove", "edit", "adopt"}},
		{[]string{"scope", "block", "lab", "cisco", "show"}, []string{"snmp", "system"}},
		{[]string{"scope", "block", "lab", "juniper", "check"}, []string{"snmp", "system"}},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "jsw1"}, []string{"snmp", "system"}},
		{[]string{"device", "block", "jsw1"}, []string{"list", "show", "check", "set", "remove", "edit", "adopt"}},
		{[]string{"device", "block", "jsw1", "show"}, []string{"snmp", "system"}},
		{[]string{"device", "block", "jsw1", "adopt"}, []string{"snmp", "system"}},
	} {
		got := map[string]string{}
		for _, cand := range inv.shellCompleter(root)(c.words, "") {
			got[cand.Word] = cand.Desc
		}
		for _, w := range c.want {
			d, ok := got[w]
			switch {
			case !ok:
				t.Errorf("%q: %q is not offered (%v)", c.words, w, got)
			case d == "":
				t.Errorf("%q: %q has no description", c.words, w)
			default:
				if f := styleFault(d); f != "" {
					t.Errorf("%q: %q: %s", c.words, w, f)
				}
			}
		}
	}
}
