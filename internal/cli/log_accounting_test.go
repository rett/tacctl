package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
)

// 'log accounting' names the device that sent each record (patches/0006):
// the registered device's name, the address when none is registered at it,
// and no device for a record written before the patch.
func TestLogAccountingNamesTheDevices(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	if _, err := devreg.Mutate(sb.path("state", "devices.yaml"), "", nil, func(f *devreg.File) error {
		f.Devices = append(f.Devices,
			&devreg.Device{Name: "sw1", Address: "192.0.2.10", Vendor: "cisco"},
			&devreg.Device{Name: "rtr1", Address: "2001:db8::1", Vendor: "juniper"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const pre = "2026/11/04 12:00:00 /opt/tacquito-src/cmds/server/config/accounters/local/local.go:105: "
	const head = `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"alice","Port":"ttyp0","RemAddr":"192.0.2.50","Args":["task_id=3",`
	sb.write("log/accounting.log", strings.Join([]string{
		// Written before the patch: no device; the HTML escapes are decoded.
		pre + head + `"cmd=show version <cr>"]}`,
		pre + head + `"cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a\"<cr>"],"Device":"192.0.2.10"}`,
		pre + head + `"cmd=show version"],"Device":"2001:db8:0:0:0:0:0:1"}`,
		pre + head + `"cmd=show version"],"Device":"203.0.113.9"}`,
		pre + head + `"cmd=show version"],"Device":"unknown"}`,
		"",
	}, "\n"), 0o600)

	out := plain(sb.run("", []string{"log", "accounting", "--backend=tacacs", "10"}))
	sb.expect(0, "Recent Accounting Entries", "")
	for _, want := range []string{
		pre + head + `"cmd=show version"]}` + "\n",
		pre + head + `"cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a\""],"Device":"sw1"}` + "\n",
		pre + head + `"cmd=show version"],"Device":"rtr1"}` + "\n",
		pre + head + `"cmd=show version"],"Device":"203.0.113.9"}` + "\n",
		pre + head + `"cmd=show version"],"Device":"unknown"}` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `\u00`) {
		t.Errorf("an escape is shown:\n%s", out)
	}
}

// No registry file, no names: the address is the device.
func TestLogAccountingWithoutARegistry(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	sb.write("log/accounting.log", `{"Flags":4,"User":"alice","Device":"192.0.2.10"}`+"\n", 0o600)
	sb.run("", []string{"log", "accounting", "--backend=tacacs"})
	sb.expect(0, `{"Flags":4,"User":"alice","Device":"192.0.2.10"}`, "")
}
