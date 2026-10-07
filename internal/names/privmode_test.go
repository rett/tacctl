package names

import "testing"

func TestSplitPrivEntry(t *testing.T) {
	for _, c := range []struct {
		in, mode, cmd string
		ok            bool
	}{
		{"show version", "exec", "show version", true},
		{"exec: show version", "exec", "show version", true},
		{"exec all: show ip", "exec all", "show ip", true},
		{"exec  all:show ip", "exec all", "show ip", true},
		{"configure: router bgp", "configure", "router bgp", true},
		{"configure all:  interface ", "configure all", "interface", true},
		{"config: router bgp", "config", "router bgp", false},
		{"Exec: show", "Exec", "show", false},
	} {
		mode, cmd, ok := SplitPrivEntry(c.in)
		if mode != c.mode || cmd != c.cmd || ok != c.ok {
			t.Errorf("%q: got (%q, %q, %v)", c.in, mode, cmd, ok)
		}
	}
	if PrivEntry("exec", "show ip") != "show ip" || PrivEntry("configure all", "router bgp") != "configure all: router bgp" {
		t.Error("PrivEntry")
	}
}

func TestValidatePrivEntry(t *testing.T) {
	for in, want := range map[string]string{
		"show version":              "show version",
		"exec: show version":        "show version",
		"exec all:show ip":          "exec all: show ip",
		"configure:   router bgp":   "configure: router bgp",
		"configure all: interface":  "configure all: interface",
		"exec all:  show ip  route": "exec all: show ip  route",
	} {
		got, err := ValidatePrivEntry(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	_, err := ValidatePrivEntry("config: router bgp")
	if got := msg(t, err); got != "Unknown privilege mode 'config' in 'config: router bgp'.\nStart the entry with exec:, exec all:, configure: or configure all: (none means exec:)." {
		t.Error(got)
	}
	_, err = ValidatePrivEntry("configure: ")
	if got := msg(t, err); got != "Privilege command must not be empty." {
		t.Error(got)
	}
	_, err = ValidatePrivEntry("exec all: show; rm")
	if got := msg(t, err); got != "Invalid privilege command 'show; rm'.\nUse letters, digits, spaces, '-', '_' (e.g. 'show running-config', 'terminal monitor')." {
		t.Error(got)
	}
}
