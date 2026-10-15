package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
)

// The NETCONF service setting (D145 of docs/plans/0.2.10-plan.md): the
// layering, the two verbs and what they write.

func TestResolveNetconf(t *testing.T) {
	for name, tc := range map[string]struct {
		scope     policy.NetconfScope
		own       devreg.Netconf
		state     string
		conn, rat int
		from      string
		leave     bool
	}{
		"nothing is leave":                {state: "", from: netconfFromDefault, leave: true},
		"the scope enables":               {scope: policy.NetconfScope{State: "enable", ConnectionLimit: 5}, state: "enable", conn: 5, from: netconfFromScope},
		"the scope disables":              {scope: policy.NetconfScope{State: "disable"}, state: "disable", from: netconfFromScope},
		"the device leaves it alone":      {scope: policy.NetconfScope{State: "enable", ConnectionLimit: 5}, own: devreg.Netconf{State: "leave"}, state: "", from: netconfFromDevice, leave: true},
		"the device disables":             {scope: policy.NetconfScope{State: "enable", RateLimit: 3}, own: devreg.Netconf{State: "disable"}, state: "disable", from: netconfFromDevice},
		"the device enables a leaving":    {own: devreg.Netconf{State: "enable", RateLimit: 8}, state: "enable", rat: 8, from: netconfFromDevice},
		"a limit of its own wins":         {scope: policy.NetconfScope{State: "enable", ConnectionLimit: 5, RateLimit: 9}, own: devreg.Netconf{State: "enable", ConnectionLimit: 7}, state: "enable", conn: 7, rat: 9, from: netconfFromDevice},
		"a limit of the scope of a leave": {scope: policy.NetconfScope{State: "enable", ConnectionLimit: 5}, own: devreg.Netconf{State: "leave", RateLimit: 0}, state: "", from: netconfFromDevice, leave: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := resolveNetconf(tc.scope, tc.own)
			if e.State != tc.state || e.ConnectionLimit != tc.conn || e.RateLimit != tc.rat || e.StateFrom != tc.from || e.Leave != tc.leave {
				t.Errorf("%+v, want state %q limits %d/%d from %s leave %v", e, tc.state, tc.conn, tc.rat, tc.from, tc.leave)
			}
		})
	}
}

func TestParseNetconfLimit(t *testing.T) {
	for in, want := range map[string]int{"1": 1, "250": 250, "none": 0, "NONE": 0, "42": 42} {
		if n, err := parseNetconfLimit("--rate-limit", in); err != nil || n != want {
			t.Errorf("%q = %d, %v", in, n, err)
		}
	}
	for _, in := range []string{"0", "251", "-1", "x", "", "05", "1.5"} {
		if _, err := parseNetconfLimit("--rate-limit", in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestNetconfVerbs(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-c", "192.168.1.30", "cisco"})
	sb := b.sb

	// Reading changes nothing, and a scope that decided nothing leaves it.
	out := plain(sb.cfgRun("", []string{"scope", "netconf", "lab"}, nil))
	if sb.code != 0 || !strings.Contains(out, "NETCONF service of scope 'lab': leave") {
		t.Errorf("scope show: %d\n%s", sb.code, out)
	}
	if strings.Contains(sb.overrides(), "netconf_scope") {
		t.Errorf("a read wrote tacctl.yaml:\n%s", sb.overrides())
	}

	// The scope enables it with a limit and a rate limit.
	sb.cfgRun("", []string{"scope", "netconf", "lab", "enable", "--connection-limit", "5", "--rate-limit", "10"}, nil)
	sb.said(0, "Scope 'lab' NETCONF service: enable (connection limit 5, rate limit 10)")
	o := sb.overrides()
	for _, want := range []string{"netconf_scope:", "state: enable", "connection_limit: 5", "rate_limit: 10"} {
		if !strings.Contains(o, want) {
			t.Errorf("tacctl.yaml lacks %q:\n%s", want, o)
		}
	}
	// the same again changes nothing and says so
	sb.cfgRun("", []string{"scope", "netconf", "lab", "enable", "--connection-limit", "5"}, nil)
	sb.said(0, "nothing was changed")

	// the device follows it, and says where each value comes from
	out = plain(sb.dev("", "netconf", "lab-j"))
	for _, want := range []string{"NETCONF service of device 'lab-j': enable (connection limit 5, rate limit 10)", "scope 'lab'"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("device show lacks %q:\n%s", want, out)
		}
	}
	if show := plain(sb.dev("", "show", "lab-j")); !strings.Contains(show, "NETCONF:") || !strings.Contains(show, "scope 'lab'") {
		t.Errorf("device show:\n%s", show)
	}
	var j struct {
		Netconf *struct {
			State           string `json:"state"`
			StateFrom       string `json:"state_from"`
			ConnectionLimit int    `json:"connection_limit"`
			RateLimit       int    `json:"rate_limit"`
		} `json:"netconf"`
	}
	if err := json.Unmarshal([]byte(sb.dev("", "show", "lab-j", "--json")), &j); err != nil || j.Netconf == nil ||
		j.Netconf.State != "enable" || j.Netconf.StateFrom != "scope" || j.Netconf.ConnectionLimit != 5 || j.Netconf.RateLimit != 10 {
		t.Errorf("device show --json: %v %+v", err, j.Netconf)
	}

	// the device's own limit wins; the other is still the scope's
	sb.dev("", "netconf", "lab-j", "enable", "--connection-limit", "7")
	sb.said(0, "Device 'lab-j' NETCONF service: enable")
	if d := sb.devices(); !strings.Contains(d, "netconf:") || !strings.Contains(d, "connection_limit: 7") || !strings.Contains(d, "state: enable") {
		t.Errorf("devices.yaml:\n%s", d)
	}
	out = plain(sb.dev("", "netconf", "lab-j", "show"))
	if !strings.Contains(out, "enable (connection limit 7, rate limit 10)") || !strings.Contains(out, "the device's own") {
		t.Errorf("device netconf show:\n%s", out)
	}

	// limits go with enable; a limit out of range is refused
	sb.dev("", "netconf", "lab-j", "disable", "--connection-limit", "3")
	sb.said(1, "go with enable")
	sb.dev("", "netconf", "lab-j", "enable", "--rate-limit", "0")
	sb.said(1, "--rate-limit takes a number from 1 to 250, or none")
	sb.cfgRun("", []string{"scope", "netconf", "lab", "enable", "--connection-limit", "251"}, nil)
	sb.said(1, "--connection-limit takes a number from 1 to 250, or none")

	// the device leaves it alone whatever its scope says, then follows again
	sb.dev("", "netconf", "lab-j", "leave")
	sb.said(0, "Device 'lab-j' NETCONF service: leave")
	if out = plain(sb.dev("", "netconf", "lab-j")); !strings.Contains(out, "leave (tacctl plans and compares nothing of the service)") {
		t.Errorf("a device that leaves it alone:\n%s", out)
	}
	sb.dev("", "netconf", "lab-j", "clear")
	sb.said(0, "follows its scope's NETCONF service setting again")
	if strings.Contains(sb.devices(), "netconf:") {
		t.Errorf("the device's setting stayed:\n%s", sb.devices())
	}

	// the setting is a Junos one
	sb.dev("", "netconf", "lab-c", "enable")
	sb.said(1, "the NETCONF service setting is a Junos setting")
	sb.dev("", "netconf", "lab-c")
	sb.said(1, "the NETCONF service setting is a Junos setting")

	// the scope disables: its limits go with the enable
	sb.cfgRun("", []string{"scope", "netconf", "lab", "disable"}, nil)
	sb.said(0, "Scope 'lab' NETCONF service: disable")
	if o := sb.overrides(); !strings.Contains(o, "state: disable") || strings.Contains(o, "connection_limit") || strings.Contains(o, "rate_limit") {
		t.Errorf("tacctl.yaml after a disable:\n%s", o)
	}
	// and leaves the whole setting out of the file again
	sb.cfgRun("", []string{"scope", "netconf", "lab", "leave"}, nil)
	sb.said(0, "NETCONF service: leave")
	if strings.Contains(sb.overrides(), "netconf_scope") {
		t.Errorf("tacctl.yaml after leave:\n%s", sb.overrides())
	}

	// a device that stops being Junos loses its own setting, and says so
	sb.dev("", "netconf", "lab-j", "enable")
	sb.dev("", "vendor", "lab-j", "cisco")
	sb.said(0, "NETCONF service setting (enable) was removed: it is a Junos setting")
	if strings.Contains(sb.devices(), "netconf:") {
		t.Errorf("the setting stayed on a Cisco device:\n%s", sb.devices())
	}
}
