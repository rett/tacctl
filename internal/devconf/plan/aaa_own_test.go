package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// The device's own settings of the aaa section (a source address, a timeout,
// the client's options) are left alone by the plan and are no item: the
// plan of a device that holds them is the plan of one that does not, the
// statements are kept, and the number the plan keeps is the comparison's
// ('aaa +N unmanaged' of 'device config list').
func TestAAAOwnSettingsAreKeptAndNoItem(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fix   string
		mutJ  func(c *JunosConfig)
		mutI  func(c *IOSConfig)
		own   int
		kinds []string
		kept  []string
	}{
		{name: "junos tacplus", fix: "juniper.synthetic-lab", own: 3, kinds: []string{"TACACS+ server settings", "TACACS+ options"},
			kept: []string{"source-address", "timeout", "service-name"},
			mutJ: addMany("set system tacplus-server 192.0.2.10 source-address 192.0.2.250", "set system tacplus-server 192.0.2.10 timeout 10",
				"set system tacplus-options service-name junos-exec")},
		{name: "ios tacacs", fix: "cisco.reference-lab", own: 1, kinds: []string{"TACACS+ server settings"}, kept: []string{"send-nat-address"},
			mutI: func(c *IOSConfig) {
				_ = c.Apply([]Line{{Op: OpLine, Context: []string{"tacacs server TACACS"}, Text: "send-nat-address"}})
			}},
		{name: "ios tacacs group", fix: "cisco.reference-lab", own: 2, kinds: []string{"TACACS+ group settings"}, kept: []string{"ip vrf forwarding", "deadtime"},
			mutI: func(c *IOSConfig) {
				_ = c.Apply([]Line{{Op: OpLine, Context: []string{"aaa group server tacacs+ LAB-TACACS"}, Text: "ip vrf forwarding MGMT"},
					{Op: OpLine, Context: []string{"aaa group server tacacs+ LAB-TACACS"}, Text: "deadtime 5"}})
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureNamed(t, tc.fix)
			var base, d Delta
			if tc.mutJ != nil {
				base, d = planJ(t, f, nil, Options{}), planJ(t, f, tc.mutJ, Options{})
			} else {
				base, d = planI(t, f, nil, Options{}), planI(t, f, tc.mutI, Options{})
			}
			if len(d.Items) != len(base.Items) || !slices.Equal(lines(d, ""), lines(base, "")) {
				t.Errorf("the device's own settings change the plan:\nitems %d, was %d\n%v\nwas\n%v", len(d.Items), len(base.Items), lines(d, ""), lines(base, ""))
			}
			if o, was := ownOf(d, devconf.SectionAAA), ownOf(base, devconf.SectionAAA); o.Count != was.Count+tc.own || !slices.Equal(o.Kinds, tc.kinds) {
				t.Errorf("aaa keeps %+v (was %+v), want %d more of %v", o, was, tc.own, tc.kinds)
			}
			for _, k := range tc.kept {
				wantKept(t, d, devconf.SectionAAA, k)
			}
			marked := 0
			for _, e := range d.Extras {
				for _, k := range tc.kept {
					if e.Section == devconf.SectionAAA && strings.Contains(e.Text, k) {
						if !e.Own {
							t.Errorf("the extra %q is not marked as the device's own", e.Text)
						}
						marked++
					}
				}
			}
			if marked != len(tc.kept) {
				t.Errorf("%d extras of the device's own, want %d: %+v", marked, len(tc.kept), d.Extras)
			}
		})
	}
}
