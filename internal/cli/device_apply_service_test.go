package cli

import (
	"strings"
	"testing"
)

// The verification of a change to the NETCONF service itself (0.2.10, D148):
// the change is made over the command line and proved by a NETCONF probe on a
// fresh login before the confirming commit. The fake's subsystem follows the
// committed configuration with the 'netconf.follow' knob.

// serviceBox is a registered device whose NETCONF subsystem follows its
// configuration, and the name of the scope the setting is made on.
func serviceBox(t *testing.T) (*applyBox, string) {
	t.Helper()
	b := newApplyBox(t)
	b.register("example-sw1")
	b.knob("netconf.follow", "")
	code, out, errs := b.apply("example-sw1", "--check", "--json")
	rows := jsonRows(t, out)
	if code != 0 || len(rows) != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	scope, _ := rows[0]["scope"].(string)
	if scope == "" {
		t.Fatalf("no scope in %v", rows[0])
	}
	return b, scope
}

// setNetconf makes the scope's setting.
func (b *applyBox) setNetconf(scope, state string) {
	b.t.Helper()
	b.sb.cfgRun("", []string{"scope", "netconf", scope, state}, route, "SUDO_USER=alice")
	if b.sb.code != 0 {
		b.t.Fatalf("scope netconf %s %s: %d %s", scope, state, b.sb.code, b.sb.err.String())
	}
}

// probe is the device's NETCONF probe in its record.
func (b *applyBox) probe(name string) string {
	b.t.Helper()
	r, ok := b.records().Of(name)
	if !ok {
		return ""
	}
	return r.Netconf
}

// setProbe makes the record's probe what a pull would have kept.
func (b *applyBox) setProbe(name, probe string) {
	b.t.Helper()
	recs := b.records()
	r, ok := recs.Of(name)
	if !ok {
		b.t.Fatalf("no record of %s", name)
	}
	r.Netconf = probe
	recs.Put(name, *r)
	if err := b.invoke().configStore().Save(recs); err != nil {
		b.t.Fatal(err)
	}
}

const (
	serviceStatement = "set system services netconf ssh"
	mixedStatement   = "tacplus-server"
)

// enable: the statement is made together with the other sections over the
// command line, the hello proves it, and the record's probe becomes hello ok.
func TestApplyEnableProvesTheServiceWithAHello(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	b.setProbe("example-sw1", netconfPortClosed)
	if strings.Contains(b.committed(), serviceStatement) {
		t.Fatal("the device already runs the service")
	}
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 0 || !strings.Contains(out, "applied") || !strings.Contains(out, "[NETCONF verified: hello ok]") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	after := b.committed()
	if !strings.Contains(after, serviceStatement) || !strings.Contains(after, mixedStatement) {
		t.Errorf("the service and the other sections were not both applied:\n%s", after)
	}
	if p := b.probe("example-sw1"); p != netconfHelloOK {
		t.Errorf("the record's probe is %q", p)
	}
	a := b.applied("example-sw1")
	if a == nil || a.Via != "cli" || a.Result != "applied" {
		t.Errorf("record: %+v", a)
	}
	// the JSON says what was proved
	code, out, _ = b.apply("example-sw1", "--check", "--json")
	if code != 0 {
		t.Errorf("check after: exit %d\n%s", code, out)
	}
}

// disable: the delete is made, the hello is no longer answered, and the
// record's probe becomes port closed.
func TestApplyDisableProvesTheServiceIsGone(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	if code, out, errs := b.apply("example-sw1", "--confirmed", "--yes"); code != 0 {
		t.Fatalf("enable: exit %d\n%s\n%s", code, out, errs)
	}
	b.setNetconf(scope, "disable")
	b.seed("example-sw1")
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes", "--json")
	rows := jsonRows(t, out)
	if code != 0 || len(rows) == 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	var proof string
	for _, r := range rows {
		if p, _ := r["service_proof"].(string); p != "" {
			proof = p
		}
	}
	if proof != "NETCONF verified: not answering" {
		t.Errorf("service_proof %q in %v", proof, rows)
	}
	if strings.Contains(b.committed(), "set system services netconf") {
		t.Errorf("the service is still configured:\n%s", b.committed())
	}
	if p := b.probe("example-sw1"); p != netconfPortClosed {
		t.Errorf("the record's probe is %q", p)
	}
	// the next run sees a device with no NETCONF and says nothing more
	code, out, _ = b.apply("example-sw1", "--check")
	if code != 0 || !strings.Contains(out, "no change") {
		t.Errorf("after: exit %d\n%s", code, out)
	}
}

// disable that did not take effect: the hello still answers, the
// verification fails, the change is rolled back, and the record keeps what
// it had.
func TestApplyDisableStillAnsweringIsRolledBack(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	if code, out, errs := b.apply("example-sw1", "--confirmed", "--yes"); code != 0 {
		t.Fatalf("enable: exit %d\n%s\n%s", code, out, errs)
	}
	b.setNetconf(scope, "disable")
	b.seed("example-sw1")
	b.knob("netconf.disable.noeffect", "")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 1 || !strings.Contains(out, "still answers NETCONF after the change") ||
		!strings.Contains(out, "the record's NETCONF probe stays 'hello ok'") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before {
		t.Errorf("the device was left changed:\n%s", b.committed())
	}
	if p := b.probe("example-sw1"); p != netconfHelloOK {
		t.Errorf("the record's probe is %q", p)
	}
	if a := b.applied("example-sw1"); a == nil || a.Result == "applied" {
		t.Errorf("record: %+v", a)
	}
}

// enable whose fresh login is refused is rolled back by the verification
// that already existed; the probe is not reached.
func TestApplyEnableWithAFailedFreshLoginIsRolledBack(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	b.knob("verify.fail", "")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 1 || strings.Contains(out, "NETCONF verified") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before {
		t.Errorf("the device was left changed:\n%s", b.committed())
	}
	if p := b.probe("example-sw1"); p == netconfHelloOK {
		t.Errorf("a failed apply recorded a hello: %q", p)
	}
}

// enable that the device does not answer after the commit: the probe says
// port closed, the verification fails, and nothing is kept.
func TestApplyEnableNotAnsweringIsRolledBack(t *testing.T) {
	b, scope := serviceBox(t)
	b.setNetconf(scope, "enable")
	b.seed("example-sw1")
	// the device keeps refusing the subsystem whatever is committed
	b.knob("netconf.off", "")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 1 || !strings.Contains(out, "does not answer NETCONF after the change (port closed;") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before {
		t.Errorf("the device was left changed:\n%s", b.committed())
	}
}
