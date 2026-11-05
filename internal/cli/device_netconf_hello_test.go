package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hello of a Junos device: its capabilities are named with the XML
// namespace's prefix, urn:ietf:params:xml:ns:netconf:..., in the lines the
// device prints around the hello.
const junosStyleHello = `<!-- user alice, class j-example-class -->
<hello>
  <capabilities>
    <capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0</capability>
  </capabilities>
  <session-id>1</session-id>
</hello>`

// A device that answers with something that is not a hello: the pull reads
// over ssh, records 'no hello', and its line says why and what the device
// sent; the record keeps the stored word only.
func TestPullNoHelloSaysWhy(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"jsw1", "192.0.2.20", "juniper"})
	b.serve("juniper", b.expected("jsw1"))
	if err := os.WriteFile(filepath.Join(b.dir, "netconf.hello"),
		[]byte("<rpc-error><error-message>no service</error-message></rpc-error>"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := b.run("device", "config", "pull", "jsw1")
	for _, want := range []string{
		"ok via ssh (netconf: no hello: the device's first message is <rpc-error>, not a hello;",
		`the device sent "<rpc-error><error-message>no service</error-message></rpc-error>")`,
	} {
		if b.sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("no %q (exit %d) in:\n%s", want, b.sb.code, out)
		}
	}
	rec, _ := b.records().Of("jsw1")
	if rec == nil || rec.Netconf != netconfNoHello || rec.Transport != "ssh" {
		t.Errorf("record %+v", rec)
	}
	// the JSON has the same text in its existing field
	b.run("device", "config", "pull", "jsw1", "--json")
	if got := b.sb.out.String(); !strings.Contains(got, `"fallback"`) || !strings.Contains(got, "netconf: no hello: the device's first message") {
		t.Errorf("json:\n%s", got)
	}
}

// The hello of a Junos device is a hello: a pull over NETCONF reads it.
func TestPullJunosStyleHelloIsOK(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"jsw1", "192.0.2.20", "juniper"})
	b.serve("juniper", b.expected("jsw1"))
	if err := os.WriteFile(filepath.Join(b.dir, "netconf.hello"), []byte(junosStyleHello), 0o644); err != nil {
		t.Fatal(err)
	}
	out := b.run("device", "config", "pull", "jsw1")
	if b.sb.code != 0 || !strings.Contains(out, "ok via netconf") {
		t.Errorf("exit %d:\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("jsw1"); rec == nil || rec.Netconf != netconfHelloOK || rec.Transport != transportNetconf {
		t.Errorf("record %+v", rec)
	}
}

// An enabling change whose hello is not one is rolled back, and the message
// says why; a Junos-style hello proves the service.
func TestApplyEnableNoHelloSaysWhy(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	b.knob("netconf.hello", "Permission denied")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 1 || !strings.Contains(out, `does not answer NETCONF after the change (no hello: the device's hello is not a hello; the device sent "Permission denied"; the record's NETCONF probe stays`) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before {
		t.Errorf("the device was left changed:\n%s", b.committed())
	}
}

func TestApplyEnableJunosStyleHelloProvesTheService(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	b.knob("netconf.hello", junosStyleHello)
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 0 || !strings.Contains(out, "[NETCONF verified: hello ok]") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
}
