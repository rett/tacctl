package devices

import (
	"strings"
	"testing"
)

// 'root' as a break-glass entry: the Junos walkthrough renders its two
// statements, commented out with the placeholder, and nothing under 'system
// login user'; Cisco and WTI render nothing for it and say so in one line.
const breakGlassWithRoot = "breakglass_scope:\n  lab:\n    users: [root:admin, lab-ops:operator]\n"
const breakGlassRootOnly = "breakglass_scope:\n  lab:\n    users: [root:admin]\n"

func TestBreakGlassRootJunosWalkthrough(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassWithRoot)
	d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "MGMT-ACL"}}
	out := renderLab(t, m, d, "juniper", "lab")
	for _, want := range []string{
		"# set system root-authentication encrypted-password '<HASH>'\n",
		"# set system services ssh root-login allow\n",
		"# set system login user lab-ops class OP-CLASS authentication encrypted-password '<HASH>'\n",
		"# Junos refuses root over ssh by default",
		"security\n# trade-off to decide: root can then log in over ssh, so keep the device behind its management filter\n",
		"Unfilled break-glass credentials (tacctl stores none; put in your own): root (admin), lab-ops (operator)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("juniper walkthrough lacks %q:\n%s", want, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "system login user root") {
			t.Errorf("a root user under system login user: %q", l)
		}
		if strings.HasPrefix(l, "set system root-authentication") || strings.HasPrefix(l, "set system services ssh root-login") {
			t.Errorf("a live root line: %q", l)
		}
	}
}

// The compared form: the two root statements are among the break-glass
// section's, the password marked secret.
func TestBreakGlassRootManagedSection(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassWithRoot)
	d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "MGMT-ACL"}}
	secs := mustManaged(t, Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)
	var bg *Section
	for i := range secs {
		if secs[i].Name == "breakglass" {
			bg = &secs[i]
		}
	}
	if bg == nil {
		t.Fatal("no breakglass section")
	}
	want := map[string]bool{
		"set system root-authentication encrypted-password '<HASH>'":                              true,
		"set system services ssh root-login allow":                                                false,
		"set system login user lab-ops class OP-CLASS authentication encrypted-password '<HASH>'": true,
	}
	for i, l := range bg.Lines {
		secret, ok := want[l]
		if !ok {
			t.Errorf("unexpected line %q", l)
			continue
		}
		if bg.Secret[i] != secret {
			t.Errorf("%q: secret = %v, want %v", l, bg.Secret[i], secret)
		}
		delete(want, l)
	}
	if len(want) != 0 {
		t.Errorf("lines missing: %v (got %q)", want, bg.Lines)
	}
}

func TestBreakGlassRootIsNothingOnCiscoAndWTI(t *testing.T) {
	for _, only := range []bool{false, true} {
		over := breakGlassWithRoot
		if only {
			over = breakGlassRootOnly
		}
		m, c := fixture(t, "store.multiscope.yaml", over)
		d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "X"}}
		for _, v := range []string{"cisco", "wti"} {
			out := renderLab(t, m, d, v, "lab")
			if n := strings.Count(out, "'root' is recorded for the scope: it is the Junos system account, so nothing is rendered for it here."); n != 1 {
				t.Errorf("%s (root only %v): the note appears %d times:\n%s", v, only, n, out)
			}
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "username root") || strings.Contains(l, "root  Access Level") || strings.Contains(l, "root-authentication") {
					t.Errorf("%s: a line for root: %q", v, l)
				}
			}
			if strings.Contains(out, "(admin), ") || strings.Contains(out, "root (admin)") {
				t.Errorf("%s: root on the Unfilled line:\n%s", v, out)
			}
			secs := mustManaged(t, Request{Vendor: v, Scope: "lab", Protocol: TACACS}, d)
			for _, s := range secs {
				if s.Name != "breakglass" {
					continue
				}
				for _, l := range s.Lines {
					if strings.Contains(l, "root") {
						t.Errorf("%s: the breakglass section expects %q", v, l)
					}
				}
				if only {
					t.Errorf("%s: a root-only scope has a breakglass section: %q", v, s.Lines)
				}
			}
			if only {
				// the scope has no account here: the notice, and no Unfilled line
				if !strings.Contains(out, "No break-glass local user is recorded for scope 'lab'") || strings.Contains(out, "Unfilled break-glass") {
					t.Errorf("%s: root-only scope:\n%s", v, out)
				}
			} else if !strings.Contains(out, "lab-ops") || !strings.Contains(out, "Unfilled break-glass credentials (tacctl stores none; put in your own): lab-ops (operator)\n") {
				t.Errorf("%s: the named user is not rendered:\n%s", v, out)
			}
		}
	}
}
