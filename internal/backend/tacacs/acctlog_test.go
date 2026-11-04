package tacacs

import (
	"bytes"
	"context"
	"testing"

	"github.com/rett/tacctl/internal/ui"
)

// The prefix tacquito's local accounter's logger writes before the JSON.
const acctPrefix = "2026/11/04 12:00:00 /opt/tacquito-src/cmds/server/config/accounters/local/local.go:105: "

// A record as patches/0006 writes it, and the same request as an older
// server wrote it (no "Device", "<", ">" and "&" as the escapes
// \u003c, \u003e and \u0026).
const (
	acctNew = `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"alice","Port":"ttyp0","RemAddr":"192.0.2.50",` +
		`"Args":["task_id=3","service=shell","session_pid = 29408","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\"<cr>"],"Device":"192.0.2.10"}`
	acctOld = `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"alice","Port":"ttyp0","RemAddr":"192.0.2.50",` +
		`"Args":["task_id=3","service=shell","session_pid = 29408","cmd=set: [interfaces ge-0/0/1 description] \u003cunconfigured\u003e -> \"a\u0026b\"\u003ccr\u003e"]}`
	acctShown = `"Args":["task_id=3","service=shell","session_pid = 29408","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\""]`
	acctHead  = `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"alice","Port":"ttyp0","RemAddr":"192.0.2.50",` + acctShown
)

func names(m map[string]string) func(string) string {
	return func(a string) string { return m[a] }
}

func TestAcctDisplayNamesTheDeviceOfANewRecord(t *testing.T) {
	got := AcctDisplay(acctPrefix+acctNew, names(map[string]string{"192.0.2.10": "sw1"}))
	if want := acctPrefix + acctHead + `,"Device":"sw1"}`; got != want {
		t.Fatalf("%s\nwant\n%s", got, want)
	}
}

func TestAcctDisplayKeepsTheAddressOfAnUnregisteredDevice(t *testing.T) {
	for _, n := range []func(string) string{nil, names(map[string]string{"192.0.2.99": "sw2"})} {
		got := AcctDisplay(acctPrefix+acctNew, n)
		mustContain(t, got, `,"Device":"192.0.2.10"}`)
		mustContain(t, got, acctShown)
	}
	// An IPv6 device is matched in canonical form, an IPv4-mapped one as IPv4.
	got := AcctDisplay(`{"Flags":4,"Device":"2001:DB8:0:0::1"}`, names(map[string]string{"2001:db8::1": "rtr1"}))
	if got != `{"Flags":4,"Device":"rtr1"}` {
		t.Fatal(got)
	}
	got = AcctDisplay(`{"Flags":4,"Device":"::ffff:192.0.2.10"}`, names(map[string]string{"192.0.2.10": "sw1"}))
	if got != `{"Flags":4,"Device":"sw1"}` {
		t.Fatal(got)
	}
	// What the server wrote when it knew no address.
	got = AcctDisplay(`{"Flags":4,"Device":"unknown"}`, names(map[string]string{"192.0.2.10": "sw1"}))
	if got != `{"Flags":4,"Device":"unknown"}` {
		t.Fatal(got)
	}
}

// A record written before the patch has no device, and is no error: its
// escapes are decoded as well.
func TestAcctDisplayOfARecordWithoutADevice(t *testing.T) {
	got := AcctDisplay(acctPrefix+acctOld, names(map[string]string{"192.0.2.10": "sw1"}))
	if want := acctPrefix + acctHead + "}"; got != want {
		t.Fatalf("%s\nwant\n%s", got, want)
	}
	mustNotContain(t, got, "Device")
	mustNotContain(t, got, `\u00`)
}

func TestAcctDisplayDropsOnlyTheTrailingCROfACommand(t *testing.T) {
	got := AcctDisplay(`{"Flags":4,"Args":["cmd=show version <cr>","cmd-arg=<cr>","cmd=a<cr>b","note=x<cr>","cmd=<cr>"]}`, nil)
	if want := `{"Flags":4,"Args":["cmd=show version","cmd-arg=<cr>","cmd=a<cr>b","note=x<cr>","cmd="]}`; got != want {
		t.Fatalf("%s\nwant\n%s", got, want)
	}
}

func TestAcctDisplayKeepsUnknownFieldsInOrder(t *testing.T) {
	in := `{"Flags":4,"Zed":1.50,"Extra":{"a":[1,"<x>"]},"Args":null,"Device":"192.0.2.10","Last":true}`
	if got := AcctDisplay(in, nil); got != in {
		t.Fatal(got)
	}
}

// A device chooses the bytes of a command: control characters stay
// escaped, so a record cannot move the cursor or start another line.
func TestAcctDisplayKeepsControlCharactersEscaped(t *testing.T) {
	in := `{"Flags":4,"Args":["cmd=a\u001b[2Jb\nc"]}`
	if got := AcctDisplay(in, nil); got != in {
		t.Fatal(got)
	}
}

func TestAcctDisplayLeavesOtherLinesAlone(t *testing.T) {
	for _, l := range []string{
		"",
		"2026-04-21T10:00:00Z START user=alice task_id=1",
		acctPrefix + `{"Flags":4,"User":"alice"`,           // cut short
		acctPrefix + `{"Flags":4,"User":"alice"} trailing`, // not only the object
		acctPrefix + `{"Flags":4,"User":}`,
		`{"Flags":4}{"Flags":4}`,
	} {
		if got := AcctDisplay(l, names(map[string]string{"192.0.2.10": "sw1"})); got != l {
			t.Errorf("%q became %q", l, got)
		}
	}
}

// 'log accounting' shows every record of every listener's log with its
// device, and the lines that are not records as they are.
func TestAccountingNamesTheDevices(t *testing.T) {
	e := newTenv(t)
	e.env.DeviceName = names(map[string]string{"192.0.2.10": "sw1"})
	writeFile(t, e.p.AcctLog, acctPrefix+acctOld+"\n"+acctPrefix+acctNew+"\n")
	mgmt := e.p.Log + "/accounting-mgmt.log"
	writeFile(t, mgmt, acctPrefix+acctNew+"\nnot a record")
	var w bytes.Buffer
	if err := e.b.Accounting(context.Background(), "tail", []string{"5"}, &w); err != nil {
		t.Fatal(err)
	}
	want := "\n" + ui.Bold + "Recent Accounting Entries" + ui.NC + "\n" + rule + "\n" +
		acctPrefix + acctHead + "}\n" +
		acctPrefix + acctHead + `,"Device":"sw1"}` + "\n" +
		"\n" + ui.Bold + mgmt + ui.NC + "\n" +
		acctPrefix + acctHead + `,"Device":"sw1"}` + "\n" + "not a record" + "\n"
	if w.String() != want {
		t.Fatalf("%q\nwant\n%q", w.String(), want)
	}
	// The log on disk is as it was.
	mustContain(t, readFile(t, e.p.AcctLog), `<cr>`)
}
