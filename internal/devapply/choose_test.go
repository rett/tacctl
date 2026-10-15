package devapply

import "testing"

func TestChoose(t *testing.T) {
	cases := []struct {
		name string
		in   ChooseInput
		want Choice
		line string
	}{
		{"auto, hello ok", ChooseInput{Setting: SettingAuto, Probe: ProbeHelloOK}, Choice{Via: ViaNetconf}, "via netconf"},
		{"auto, port closed", ChooseInput{Setting: SettingAuto, Probe: ProbePortClosed}, Choice{Via: ViaCLI, Reason: ReasonPortClosed},
			"via cli: " + ReasonPortClosed},
		{"auto, no hello", ChooseInput{Setting: SettingAuto, Probe: ProbeNoHello}, Choice{Via: ViaCLI, Reason: ReasonNoHello},
			"via cli: " + ReasonNoHello},
		{"auto, never probed", ChooseInput{Setting: SettingAuto}, Choice{Via: ViaCLI, Reason: ReasonNotProbed}, "via cli: " + ReasonNotProbed},
		{"auto, not probed word", ChooseInput{Setting: SettingAuto, Probe: "not probed"}, Choice{Via: ViaCLI, Reason: ReasonNotProbed},
			"via cli: " + ReasonNotProbed},
		{"auto, service change beats the probe", ChooseInput{Setting: SettingAuto, Probe: ProbeHelloOK, ServiceChange: true},
			Choice{Via: ViaCLI, Reason: ReasonServiceChange}, "via cli: " + ReasonServiceChange},
		{"cli, hello ok", ChooseInput{Setting: SettingCLI, Probe: ProbeHelloOK}, Choice{Via: ViaCLI}, "via cli"},
		{"cli, service change", ChooseInput{Setting: SettingCLI, ServiceChange: true}, Choice{Via: ViaCLI}, "via cli"},
		{"netconf, hello ok", ChooseInput{Setting: SettingNetconf, Probe: ProbeHelloOK}, Choice{Via: ViaNetconf}, "via netconf"},
		{"netconf is tried on a stale probe", ChooseInput{Setting: SettingNetconf, Probe: ProbePortClosed}, Choice{Via: ViaNetconf}, "via netconf"},
		{"netconf never falls back to a probe it has not made", ChooseInput{Setting: SettingNetconf}, Choice{Via: ViaNetconf}, "via netconf"},
		{"cli-only verb, whatever the setting", ChooseInput{Setting: SettingNetconf, Probe: ProbeHelloOK, CLIOnly: true}, Choice{Via: ViaCLI}, "via cli"},
	}
	for _, c := range cases {
		got := Choose(c.in)
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
		if w := got.Words(); w != c.line {
			t.Errorf("%s: words %q, want %q", c.name, w, c.line)
		}
	}
}

// --transport netconf with a change to the service is a refusal that says
// what to run instead, never a quiet change of transport.
func TestChooseNetconfServiceChangeFails(t *testing.T) {
	got := Choose(ChooseInput{Setting: SettingNetconf, Probe: ProbeHelloOK, ServiceChange: true})
	if got.Fail == "" || got.Via != ViaCLI {
		t.Fatalf("%+v", got)
	}
	if got.Reason != "" {
		t.Errorf("a refusal carries no fallback reason: %+v", got)
	}
}

func TestSettingValid(t *testing.T) {
	for _, s := range []Setting{SettingAuto, SettingCLI, SettingNetconf} {
		if !s.Valid() {
			t.Errorf("%q is not valid", s)
		}
	}
	for _, s := range []Setting{"", "ssh", "AUTO", "netconf,cli"} {
		if s.Valid() {
			t.Errorf("%q is valid", s)
		}
	}
}
