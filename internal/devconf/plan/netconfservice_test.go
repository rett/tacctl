package plan

import "testing"

// NetconfService says which proof a change to the service needs (D148).
func TestNetconfService(t *testing.T) {
	line := func(texts ...string) Delta {
		var d Delta
		for _, s := range texts {
			d.Lines = append(d.Lines, Line{Text: s})
		}
		return d
	}
	for _, c := range []struct {
		name string
		d    Delta
		want string
	}{
		{"nothing", Delta{}, ""},
		{"other sections", line("set system accounting events login"), ""},
		{"enable", line("set system services netconf ssh"), "enable"},
		{"enable with a limit", line("set system services netconf ssh connection-limit 5"), "enable"},
		{"disable", line("delete system services netconf"), "disable"},
		{"mixed", line("set system accounting events login", "set system services netconf ssh"), "enable"},
		{"disable among others", line("set system accounting events login", "delete system services netconf"), "disable"},
		{"ssh service is not netconf", line("set system services ssh root-login deny"), ""},
	} {
		if got := NetconfService(c.d); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
