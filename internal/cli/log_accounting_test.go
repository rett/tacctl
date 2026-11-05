package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
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
		pre + head + `"cmd=set: [interfaces ge-0/0/1 description] \u003cunconfigured\u003e -> \"a\u0026b\"\u003ccr\u003e"]}`,
		pre + head + `"cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a\"<cr>"],"Device":"192.0.2.10"}`,
		pre + head + `"cmd=show version"],"Device":"2001:db8:0:0:0:0:0:1"}`,
		pre + head + `"cmd=show version"],"Device":"203.0.113.9"}`,
		pre + head + `"cmd=show version"],"Device":"unknown"}`,
		"",
	}, "\n"), 0o600)

	out := plain(sb.run("", []string{"log", "accounting", "--backend=tacacs", "10"}))
	sb.expect(0, "Recent Accounting Entries", "")
	for _, want := range []string{
		pre + head + `"cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\""]}` + "\n",
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

// A caller whose tier is limited to scopes (an operator, an engineer, a
// read-only user) is told the names of the devices and hosts of those scopes
// only: another scope's device shows as its address, as it is not in their
// 'device list'.
func TestLogAccountingNamesOnlyTheDevicesTheCallerSees(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	// bob is an operator of the scope dmz (203.0.113.0/24) and not of prod.
	store := sb.read("state/store.yaml")
	if !strings.Contains(store, "    group: operator\n    scopes: [lab]\n") {
		t.Fatal("the fixture changed")
	}
	sb.write("state/store.yaml", strings.Replace(store, "    group: operator\n    scopes: [lab]\n", "    group: operator\n    scopes: [dmz]\n", 1), 0o600)
	sb.dev("", "add", "sw1", "203.0.113.10", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "rtr1", "10.0.0.1", "--vendor", "cisco", "--no-host-key")
	const pre = "2026/11/04 12:00:00 /opt/tacquito-src/cmds/server/config/accounters/local/local.go:105: "
	sb.write("log/accounting.log", pre+`{"Flags":4,"User":"alice","Device":"203.0.113.10"}`+"\n"+
		pre+`{"Flags":4,"User":"alice","Device":"10.0.0.1"}`+"\n", 0o600)

	as := func(user, group string) string {
		return plain(sb.cfgRun("", []string{"log", "accounting", "--backend=tacacs"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users " + group + "\n")})
		}, "SUDO_USER="+user))
	}
	out := as("bob", "tac-operator")
	if sb.code != 0 {
		t.Fatalf("%d %s", sb.code, sb.stderr())
	}
	for _, want := range []string{`"Device":"sw1"}`, `"Device":"10.0.0.1"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rtr1") {
		t.Errorf("a device of another scope is named:\n%s", out)
	}
	// A superuser (no SUDO_USER restriction) sees both names.
	out = plain(sb.run("", []string{"log", "accounting", "--backend=tacacs"}))
	for _, want := range []string{`"Device":"sw1"}`, `"Device":"rtr1"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("superuser: missing %q in:\n%s", want, out)
		}
	}
}

// A registry file that cannot be parsed leaves the enrolled hosts' names:
// a host at the single address of its scope is still named.
func TestLogAccountingKeepsHostNamesWithABrokenRegistry(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	store := sb.read("state/store.yaml")
	sb.write("state/store.yaml", strings.Replace(store, "filters:\n",
		"  site-a:\n    prefixes: [192.0.2.50/32]\n    secret: site-a-secret-0123456789abcdef\nfilters:\n", 1), 0o600)
	sb.write("state/linux-hosts", "web1|root@web1.example.net||site-a|tacacs.example.net|\n", 0o600)
	sb.write("state/devices.yaml", "devices: [unclosed\n", 0o600)
	sb.write("log/accounting.log", `{"Flags":4,"User":"alice","Device":"192.0.2.50"}`+"\n"+
		`{"Flags":4,"User":"alice","Device":"192.0.2.99"}`+"\n", 0o600)
	out := plain(sb.run("", []string{"log", "accounting", "--backend=tacacs"}))
	if sb.code != 0 {
		t.Fatalf("%d %s", sb.code, sb.stderr())
	}
	for _, want := range []string{`"Device":"web1"}`, `"Device":"192.0.2.99"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
