package cli

import (
	"strings"
	"testing"
)

// --discovered takes the unregistered addresses that authenticated, from the
// seen cache, and no others (a registered one, one only refused); with a
// terminal each one's key is accepted by its address typed back.
func TestCollectDiscovered(t *testing.T) {
	b := newCollectBox(t)
	b.devices([3]string{"sw-known", "192.168.1.40", "juniper"})
	seen := func(lastOK string) string {
		return `{"first":"2026-10-01T00:00:00Z","last":"2026-10-02T00:00:00Z","count":3,"last_user":"alice","last_outcome":"pass"` + lastOK + `}`
	}
	ok := `,"last_ok":"2026-10-02T00:00:00Z"`
	b.sb.write("var-lib/devices-seen.json", `{"version":1,"sources":{},"hostkeys":{},"addresses":{`+
		`"192.168.1.31":{"tacacs":`+seen(ok)+`},"192.168.1.40":{"tacacs":`+seen(ok)+`},"192.168.1.41":{"tacacs":`+seen("")+`}}}`, 0o600)
	// no terminal: refused (--host-key names one address's key only)
	b.collect("-", "--discovered")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "No terminal to answer the host-key question on") {
		t.Fatalf("no terminal: %d %q", b.sb.code, b.sb.stderr())
	}
	out := b.collect(onboardAddr+"\n", "--discovered")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if row := tableRow(out, onboardAddr); len(row) == 0 || row[len(row)-1] != "collected" {
		t.Errorf("row %q\n%s", row, out)
	}
	if tableRow(out, "192.168.1.40") != nil || tableRow(out, "192.168.1.41") != nil {
		t.Errorf("a registered or refused address was collected:\n%s", out)
	}
	if !strings.Contains(b.sb.stderr(), "Type the address ("+onboardAddr+") to accept it and send it the password of 'alice' (your tacctl password)") {
		t.Errorf("the question: %q", b.sb.stderr())
	}
}
