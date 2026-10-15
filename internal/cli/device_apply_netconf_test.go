package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// 'device config apply' over NETCONF (0.2.10, D150): the choice of the
// transport, the fallbacks and what the lines, the JSON and the record say.
// The transaction itself is pinned per transport by internal/devapply.

// jsonRows decodes the device objects of an apply's --json standard output.
func jsonRows(t *testing.T, out string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		if _, ok := m["name"]; ok {
			rows = append(rows, m)
		}
	}
	return rows
}

func TestApplyTransportFlagIsChecked(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	code, _, errs := b.apply("example-sw1", "--check", "--transport", "ssh")
	if code != 2 || !strings.Contains(errs, "--transport takes auto, cli or netconf: 'ssh'") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

// --transport cli is what 0.2.9 did: the line has no transport words and the
// record names the command line.
func TestApplyCheckOverTheCommandLine(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	code, out, errs := b.apply("example-sw1", "--check", "--transport", "cli")
	if code != 0 || strings.Contains(out, "[via") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if a := b.applied("example-sw1"); a == nil || a.Via != "cli" {
		t.Errorf("record: %+v", a)
	}
	code, out, _ = b.apply("example-sw1", "--check", "--transport", "cli", "--json")
	rows := jsonRows(t, out)
	if code != 0 || len(rows) != 1 || rows[0]["via"] != "cli" {
		t.Errorf("json: exit %d %v", code, rows)
	}
}

// --transport netconf checks over the subsystem, says so, records it, and the
// pull part of the record learns the hello.
func TestApplyCheckOverNetconf(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	code, out, errs := b.apply("example-sw1", "--check", "--transport", "netconf")
	if code != 0 || !strings.Contains(out, "[via netconf]") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	a := b.applied("example-sw1")
	if a == nil || a.Via != "netconf" {
		t.Errorf("record: %+v", a)
	}
	rec, ok := b.records().Of("example-sw1")
	if !ok || rec.Netconf != netconfHelloOK || rec.Transport != transportNetconf {
		t.Errorf("the read through NETCONF is a hello: %+v", rec)
	}
	// the read through NETCONF recorded the hello, so auto now takes it
	code, out, errs = b.apply("example-sw1", "--check")
	if code != 0 || !strings.Contains(out, "[via netconf]") {
		t.Errorf("auto after a hello: exit %d\n%s\n%s", code, out, errs)
	}
}

// auto and a device whose last probe was 'port closed' is the command line,
// with the reason; a device never probed says nothing in the line and
// everything in the JSON.
func TestApplyAutoFallsBackWithTheReason(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	code, out, errs := b.apply("example-sw1", "--check", "--json")
	rows := jsonRows(t, out)
	if code != 0 || len(rows) != 1 || rows[0]["via"] != "cli" || !strings.Contains(rows[0]["via_reason"].(string), "not probed") {
		t.Fatalf("never probed: exit %d %v\n%s", code, rows, errs)
	}
	code, out, _ = b.apply("example-sw1", "--check")
	if code != 0 || strings.Contains(out, "[via") {
		t.Errorf("a never probed device's line is 0.2.9's: %d\n%s", code, out)
	}
	rec, _ := b.records().Of("example-sw1")
	rec.Netconf = netconfPortClosed
	recs := b.records()
	recs.Put("example-sw1", *rec)
	if err := b.invoke().configStore().Save(recs); err != nil {
		t.Fatal(err)
	}
	code, out, errs = b.apply("example-sw1", "--check")
	if code != 0 || !strings.Contains(out, "[via cli: NETCONF port closed at the last read]") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
}

// netconf never falls back: a device whose subsystem is off is failed, and
// nothing was typed over the command line.
func TestApplyNetconfOnlyFailsWhenTheDeviceHasNone(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.knob("netconf.off", "")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--check", "--transport", "netconf")
	if code != 1 || !strings.Contains(out, "failed: NETCONF: ") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before {
		t.Error("the device was changed")
	}
	// auto, with the same device, uses the command line
	code, out, errs = b.apply("example-sw1", "--check", "--transport", "auto")
	if code != 0 {
		t.Errorf("auto: exit %d\n%s\n%s", code, out, errs)
	}
}

// A device that refuses a confirmed commit in a private session is run again,
// whole, in an exclusive one, and the line says so.
func TestApplyNetconfRetriesInAnExclusiveSession(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.knob("netconf.private.confirm", "refuse")
	b.seed("example-sw1")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes", "--transport", "netconf")
	if code != 0 || !strings.Contains(out, "via netconf, exclusive session") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() == before {
		t.Error("nothing was applied")
	}
	a := b.applied("example-sw1")
	if a == nil || a.Via != "netconf" || a.Result != "applied" {
		t.Errorf("record: %+v", a)
	}
	// a second apply has nothing to do
	code, out, errs = b.apply("example-sw1", "--confirmed", "--yes", "--transport", "netconf")
	if code != 0 {
		t.Errorf("second: exit %d\n%s\n%s", code, out, errs)
	}
}

// A change to the NETCONF service is made over the command line whatever the
// probe says (D148): auto takes the command line and says why, netconf is
// refused with what to run instead, and nothing was opened over NETCONF.
func TestApplyServiceChangeIsMadeOverTheCommandLine(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	// the device is known to answer NETCONF
	code, out, errs := b.apply("example-sw1", "--check", "--transport", "netconf", "--json")
	rows := jsonRows(t, out)
	if code != 0 || len(rows) != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	scope, _ := rows[0]["scope"].(string)
	b.sb.cfgRun("", []string{"scope", "netconf", scope, "enable"}, route, "SUDO_USER=alice")
	if b.sb.code != 0 {
		t.Fatalf("scope netconf: %d %s", b.sb.code, b.sb.err.String())
	}
	before := b.committed()

	code, out, errs = b.apply("example-sw1", "--check", "--json")
	rows = jsonRows(t, out)
	if code != 0 || len(rows) != 1 || rows[0]["via"] != "cli" || rows[0]["via_reason"] != "netconf service change" {
		t.Fatalf("auto: exit %d %v\n%s", code, rows, errs)
	}
	lines, _ := rows[0]["lines"].([]any)
	found := false
	for _, l := range lines {
		if s, _ := l.(string); strings.Contains(s, "set system services netconf ssh") {
			found = true
		}
	}
	if !found {
		t.Errorf("the check did not plan the service statement: %v", lines)
	}

	code, out, _ = b.apply("example-sw1", "--check", "--transport", "netconf")
	if code != 1 || !strings.Contains(out, "a change to the NETCONF service is made over the command line") {
		t.Errorf("netconf: exit %d\n%s", code, out)
	}
	if b.committed() != before {
		t.Error("a check changed the device")
	}
}

// An apply over NETCONF converges the device as over the command line, and
// the second is a no change.
func TestApplyOverNetconfConverges(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.seed("example-sw1")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes", "--transport", "netconf")
	if code != 0 || !strings.Contains(out, "applied") || !strings.Contains(out, "via netconf") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	after := b.committed()
	if after == before {
		t.Fatal("nothing was applied")
	}
	code, out, errs = b.apply("example-sw1", "--check", "--transport", "netconf")
	if code != 0 || !strings.Contains(out, "no change") {
		t.Errorf("second: exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != after {
		t.Error("the second run changed the device")
	}
}
