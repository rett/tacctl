package devapply

import (
	"context"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// The hello of a Junos device names its capabilities with the XML
// namespace's prefix; the transport must still see the candidate and the
// confirmed commit in it.
const nsHello = `<!-- user alice, class j-example-class -->
<hello>
  <capabilities>
    <capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:candidate:1.0</capability>
    <capability>
      urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0
    </capability>
  </capabilities>
  <session-id>1</session-id>
</hello>`

func TestProbeNetconfWhy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		knobs map[string]string
		state string
		why   []string
	}{
		{"hello", nil, ProbeHelloOK, nil},
		{"a device's own capability prefix", map[string]string{"netconf.hello": nsHello}, ProbeHelloOK, nil},
		{"port closed", map[string]string{"netconf.off": ""}, ProbePortClosed, nil},
		{"an error instead of a hello", map[string]string{"netconf.hello": "<rpc-error><error-message>no service</error-message></rpc-error>"},
			ProbeNoHello, []string{"the device's first message is <rpc-error>, not a hello", `the device sent "<rpc-error>`}},
		{"text", map[string]string{"netconf.hello": "Permission denied\r\n"},
			ProbeNoHello, []string{"not a hello", `the device sent "Permission denied"`}},
		{"no base:1.0", map[string]string{"netconf.hello": "<hello><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>"},
			ProbeNoHello, []string{"does not offer base:1.0 framing", `it offers "urn:ietf:params:netconf:base:1.1"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newDevice(t, c.knobs)
			tg := d.target(fakedev.DefaultUser, fakedev.DefaultPassword)
			state, why, err := ProbeNetconfWhy(context.Background(), tg)
			if err != nil || state != c.state {
				t.Fatalf("state %q, err %v; want %q", state, err, c.state)
			}
			for _, w := range c.why {
				if !strings.Contains(why, w) {
					t.Errorf("why %q lacks %q", why, w)
				}
			}
			if len(c.why) == 0 && why != "" {
				t.Errorf("why = %q", why)
			}
			if got, err := ProbeNetconf(context.Background(), tg); err != nil || got != c.state {
				t.Errorf("ProbeNetconf = %q, %v", got, err)
			}
		})
	}
}

// A transport whose device sends the XML namespace's prefix in its
// capabilities still confirms.
func TestNetconfConfirmsWithTheDevicesCapabilityPrefix(t *testing.T) {
	t.Parallel()
	d := netDevice(t, map[string]string{"netconf.hello": nsHello}, ModeAuto)
	j := d.dialNetconf(ModeAuto)
	defer func() { _ = j.Close() }()
	if _, err := j.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !j.Confirms() {
		t.Error("Confirms is false for a hello with the XML namespace's capability prefix")
	}
}
