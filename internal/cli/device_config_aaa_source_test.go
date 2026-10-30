package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// The source of the AAA client must be on the device (D314). A device whose
// source address or source interface is on one of its interfaces reads like
// any device with settings of its own; one whose source names nothing it holds
// is a difference everywhere (config list, --differs, the CONFIG column of
// device list, diff, plan, their --json) and an access irregularity of the
// plan that the paste does not fix; a record that has no interface addresses
// is not checked and says so.

type aaaSourceCase struct {
	name   string
	vendor string
	radius bool
	// text puts the interfaces and the source, which names (or not) what the
	// interfaces hold, into the device's text
	text func(t *testing.T, text string, good bool) string
	// finding is the statement of the diff for the wrong source, and why its
	// reason
	finding, why string
}

func aaaSourceCases() []aaaSourceCase {
	return []aaaSourceCase{
		{name: "junos tacplus", vendor: "juniper",
			text: func(t *testing.T, text string, good bool) string {
				a := wordAfter(t, text, "set system tacplus-server ")
				src := "192.0.2.250"
				if !good {
					src = "192.0.2.99"
				}
				return appendStmts(text, "set interfaces lo0 unit 0 family inet address 192.0.2.250/32",
					"set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254",
					"set system tacplus-server "+a+" source-address "+src)
			},
			finding: "source-address 192.0.2.99", why: "is not an address of any interface this login can see"},
		{name: "junos radius", vendor: "juniper", radius: true,
			text: func(t *testing.T, text string, good bool) string {
				a := wordAfter(t, text, "set system radius-server ")
				src := "198.51.100.254"
				if !good {
					src = "2001:db8::99"
				}
				return appendStmts(text, "set interfaces lo0 unit 0 family inet address 192.0.2.250/32",
					"set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254",
					"set system radius-server "+a+" source-address "+src)
			},
			finding: "source-address 2001:db8::99", why: "is not an address of any interface this login can see"},
		{name: "ios tacacs global", vendor: "cisco",
			text: func(t *testing.T, text string, good bool) string {
				src := "Loopback0"
				if !good {
					src = "Loopback9"
				}
				return appendStmts(text, "interface Loopback0", " ip address 192.0.2.250 255.255.255.255", "!", "ip tacacs source-interface "+src)
			},
			finding: "ip tacacs source-interface Loopback9", why: "no such interface with an address that this login can see"},
		{name: "ios tacacs group", vendor: "cisco",
			text: func(t *testing.T, text string, good bool) string {
				src := "Loopback0"
				if !good {
					src = "Loopback7"
				}
				text = inBlock(t, text, "aaa group server tacacs+ ", "ip tacacs source-interface "+src)
				return appendStmts(text, "interface Loopback0", " ip address 192.0.2.250 255.255.255.255", "!")
			},
			finding: "ip tacacs source-interface Loopback7", why: "no such interface with an address that this login can see"},
		{name: "ios radius group", vendor: "cisco", radius: true,
			text: func(t *testing.T, text string, good bool) string {
				src := "Loopback0"
				if !good {
					src = "Loopback7"
				}
				text = inBlock(t, text, "aaa group server radius ", "ip radius source-interface "+src)
				return appendStmts(text, "interface Loopback0", " ip address 192.0.2.250 255.255.255.255", "!")
			},
			finding: "ip radius source-interface Loopback7", why: "no such interface with an address that this login can see"},
	}
}

func TestAAASourceOnAnInterfaceIsTheDevicesOwn(t *testing.T) {
	for _, c := range aaaSourceCases() {
		t.Run(c.name, func(t *testing.T) {
			b, name := aaaBox(t, c.vendor, c.radius, func(s string) string { return c.text(t, s, true) })
			if list := b.run("device", "config", "list"); b.sb.code != 0 || strings.Contains(list, "differs") {
				t.Fatalf("list: %d\n%s", b.sb.code, list)
			}
			if out := b.run("device", "config", "list", "--differs"); strings.Contains(out, name) {
				t.Errorf("config list --differs holds the device:\n%s", out)
			}
			if diff := b.run("device", "config", "diff", name, "--exit-code"); b.sb.code != 0 || strings.Contains(diff, c.why) || strings.Contains(diff, "not checked") {
				t.Errorf("diff: %d\n%s", b.sb.code, diff)
			}
			out := b.run("device", "config", "plan", name, "--exit-code")
			if b.sb.code != 0 || !strings.Contains(out, "CONSISTENT: nothing to paste.") || strings.Contains(out, "not checked") {
				t.Errorf("plan: exit %d\n%s", b.sb.code, out)
			}
		})
	}
}

func TestAAASourceOnNoInterfaceIsADifference(t *testing.T) {
	for _, c := range aaaSourceCases() {
		t.Run(c.name, func(t *testing.T) {
			b, name := aaaBox(t, c.vendor, c.radius, func(s string) string { return c.text(t, s, false) })
			list := b.run("device", "config", "list")
			if b.sb.code != 0 || !strings.Contains(list, "differs") || !strings.Contains(list, "aaa") {
				t.Fatalf("list: %d\n%s", b.sb.code, list)
			}
			if out := b.run("device", "config", "list", "--differs"); !strings.Contains(out, name) {
				t.Errorf("config list --differs lacks the device:\n%s", out)
			}
			if out := b.run("device", "list", "--differs"); !strings.Contains(out, name) {
				t.Errorf("device list --differs lacks the device:\n%s", out)
			}
			if out := b.run("device", "list"); !strings.Contains(out, "differs") {
				t.Errorf("the CONFIG column of device list:\n%s", out)
			}
			diff := b.run("device", "config", "diff", name, "--exit-code")
			if b.sb.code != 2 || !strings.Contains(diff, "+ ") || !strings.Contains(diff, c.finding) || !strings.Contains(diff, c.why) {
				t.Errorf("diff: %d\n%s", b.sb.code, diff)
			}
			js := b.run("device", "config", "diff", name, "--json")
			var dj []struct {
				Status   string
				Sections []struct {
					Name  string
					State string
					Lines []struct{ Op, Text, Why string }
				}
			}
			if err := json.Unmarshal([]byte(js), &dj); err != nil || len(dj) != 1 {
				t.Fatalf("diff json: %v\n%s", err, js)
			}
			found := false
			for _, s := range dj[0].Sections {
				for _, l := range s.Lines {
					if l.Why != "" && strings.Contains(l.Why, c.why) && s.Name == "aaa" && s.State == "differs" && l.Op == "+" {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("diff json has no source finding:\n%s", js)
			}

			out := b.run("device", "config", "plan", name, "--exit-code")
			flat := strings.Join(strings.Fields(unwrapPlan(out)), " ")
			for _, want := range []string{"What is irregular", "ACCESS", c.finding[strings.LastIndex(c.finding, " ")+1:], c.why,
				"Left alone: add the address to an interface, or change the source (not managed by tacctl)."} {
				if !strings.Contains(flat, strings.ReplaceAll(want, "\n", " ")) {
					t.Errorf("the plan lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "CONSISTENT") || strings.Contains(out, "PASTE FROM HERE") {
				t.Errorf("the plan pastes or reads consistent:\n%s", out)
			}
			pj := b.run("device", "config", "plan", name, "--json")
			var got []struct {
				Status         string
				Irregularities []struct{ Kind, Severity, Section, What, Action string }
			}
			if err := json.Unmarshal([]byte(pj), &got); err != nil || len(got) != 1 {
				t.Fatalf("plan json: %v\n%s", err, pj)
			}
			if got[0].Status != "left-alone" || len(got[0].Irregularities) != 1 || got[0].Irregularities[0].Severity != "ACCESS" ||
				!strings.Contains(got[0].Irregularities[0].What, c.why) || got[0].Irregularities[0].Section != "aaa" {
				t.Errorf("plan json: %+v\n%s", got, pj)
			}
		})
	}
}

// A record without interface addresses (pulled before they were recorded) or
// whose pull saw none is not checked, and the diff and the plan say so.
func TestAAASourceNotCheckedWithoutInterfaceAddresses(t *testing.T) {
	for _, c := range aaaSourceCases() {
		for _, tc := range []struct {
			name string
			set  func(*devconf.Record)
			note string
		}{
			{"not recorded", func(r *devconf.Record) { r.Interfaces = nil }, "their addresses are not recorded (pull the device again)"},
			{"not visible", func(r *devconf.Record) { r.Interfaces.Visible, r.Interfaces.Addresses = false, nil }, "this login cannot see the interfaces"},
		} {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				b, name := aaaBox(t, c.vendor, c.radius, func(s string) string { return c.text(t, s, false) })
				b.editRecord(name, func(r *devconf.Record) { tc.set(r) })
				if list := b.run("device", "config", "list"); b.sb.code != 0 {
					t.Fatalf("list: %d\n%s", b.sb.code, list)
				}
				out := b.run("device", "config", "list", "--differs")
				if strings.Contains(out, name) {
					t.Errorf("config list --differs holds the device:\n%s", out)
				}
				diff := b.run("device", "config", "diff", name, "--exit-code")
				plan := b.run("device", "config", "plan", name, "--exit-code")
				flat := strings.Join(strings.Fields(unwrapPlan(plan)), " ")
				if c.name == "ios tacacs global" && tc.name == "not recorded" {
					// the source interface of the device's own is in no section, only in
					// the facts: a record without them has nothing to say
					if b.sb.code != 0 || strings.Contains(diff, "not checked") {
						t.Errorf("diff: %s", diff)
					}
					return
				}
				if !strings.Contains(diff, tc.note) || !strings.Contains(flat, tc.note) {
					t.Errorf("no note %q\ndiff:\n%s\nplan:\n%s", tc.note, diff, plan)
				}
				if strings.Contains(flat, c.why) || strings.Contains(diff, c.why) {
					t.Errorf("a source is flagged without the interfaces:\n%s\n%s", diff, plan)
				}
			})
		}
	}
}
