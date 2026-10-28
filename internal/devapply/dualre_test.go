package devapply

import (
	"errors"
	"testing"

	"github.com/rett/tacctl/internal/devssh"
)

// A device with two routing engines (or a chassis cluster) prints the block
// of 'show version' once per engine under a header and a rule. Engines that
// agree on the hostname and the release are one device.
func TestParseVersionTwoRoutingEngines(t *testing.T) {
	for name, out := range map[string]string{
		"re": `re0:
--------------------------------------------------------------------------
Hostname: rtr1.example.net
Model: mx480
Junos: 21.4R3-S3.4
JUNOS Software Release [21.4R3-S3.4]

re1:
--------------------------------------------------------------------------
Hostname: rtr1.example.net
Model: mx480
Junos: 21.4R3-S3.4
JUNOS Software Release [21.4R3-S3.4]
`,
		"cluster": `node0:
--------------------------------------------------------------------------
Hostname: fw1.example.net
Model: srx345-dc
Junos: 21.4R3-S3.4

node1:
--------------------------------------------------------------------------
Hostname: fw1.example.net
Model: srx345-dc
Junos: 21.4R3-S3.4
`,
		"old": `re0:
--------------------------------------------------------------------------
Hostname: rtr1.example.net
Model: m10i
JUNOS Base OS boot [12.3R12-S15.1]

re1:
--------------------------------------------------------------------------
Hostname: rtr1.example.net
Model: m10i
JUNOS Base OS boot [12.3R12-S15.1]
`,
	} {
		id, err := parseVersion(out)
		if err != nil || id.Hostname == "" || id.Release == "" || id.Model == "" {
			t.Errorf("%s: %+v %v", name, id, err)
		}
	}
	// engines on two releases stay refused
	_, err := parseVersion("re0:\nHostname: rtr1.example.net\nModel: mx480\nJunos: 21.4R3-S3.4\nre1:\nHostname: rtr1.example.net\nModel: mx480\nJunos: 22.4R1.10\n")
	if !errors.Is(err, ErrUnrecognised) {
		t.Errorf("two releases: %v", err)
	}
}

// The line a Junos device prints before a prompt names the role of the
// routing engine, the virtual-chassis member or the cluster node; the apply
// takes the line of every role as no part of an answer.
func TestPromptAreaOfEveryRole(t *testing.T) {
	for _, role := range []string{"{master}", "{backup}", "{master:0}", "{backup:1}", "{linecard:2}", "{primary:node0}", "{secondary:node1}"} {
		if pending, _, err := parseBanner([]string{"", role}); err != nil || pending {
			t.Errorf("%s: %v %v", role, pending, err)
		}
		if _, ok := configAnswer("load complete\n" + role + "[edit]\n"); !ok {
			t.Errorf("%s[edit]: not a configuration prompt", role)
		}
		if !devssh.LocationLine(role + "[edit system]") {
			t.Errorf("%s[edit system]: not a location line", role)
		}
	}
}
