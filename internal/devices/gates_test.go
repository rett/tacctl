package devices

import (
	"strings"
	"testing"
)

func TestLacksReadsTheReleaseOfAJunosDevice(t *testing.T) {
	for release, want := range map[string]bool{
		"":             false, // unknown: the current form
		"11.4R7.5":     true,
		"12.1X44-D35":  true,
		"15.1R7-S9":    true,
		"16.1R1":       false,
		"16.2R2-S11":   false,
		"25.4R1-S2.3":  false,
		"not a number": false,
	} {
		if got := (Data{Release: release}).lacks("juniper", "system login idle-timeout"); got != want {
			t.Errorf("release %q: lacks = %v, want %v", release, got, want)
		}
	}
	if (Data{Release: "11.4R7.5"}).lacks("cisco", "system login idle-timeout") {
		t.Error("another vendor is gated by a Junos row")
	}
	if (Data{Release: "11.4R7.5"}).lacks("juniper", "no such statement") {
		t.Error("a statement without a row is gated")
	}
}

// A release before 16.1 gets the idle timeout on each login class; an
// unknown release and a newer one get the global statement.
func TestJunosIdleTimeoutFollowsTheRecordedRelease(t *testing.T) {
	render := func(release string) string {
		d := mgmtData(t, "192.0.2.10", "", nil, SNMPInput{})
		d.Release = release
		return JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)["TACPLUS_CONFIG"]
	}
	for _, release := range []string{"", "16.1R1", "25.4R1-S2.3"} {
		out := render(release)
		if !strings.Contains(out, "set system login idle-timeout ") || strings.Contains(out, " idle-timeout 60\nset system login class") {
			t.Errorf("release %q: no global idle-timeout:\n%s", release, out)
		}
		if strings.Contains(out, "set system login class ") {
			t.Errorf("release %q: classes in the AAA block:\n%s", release, out)
		}
	}
	out := render("11.4R7.5")
	if strings.Contains(out, "set system login idle-timeout ") {
		t.Errorf("11.4 still gets the global statement:\n%s", out)
	}
	if n := strings.Count(out, "idle-timeout 60\n"); n < 1 || !strings.Contains(out, "set system login class ") {
		t.Errorf("11.4 gets no per-class timeouts (%d):\n%s", n, out)
	}
}
