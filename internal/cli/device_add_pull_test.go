package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device add --pull': the registration as before, then the pull verb for
// that one device, in the same process and as the caller.

// addPull runs 'device add <args> --pull' as alice with ssh-keyscan
// offering the fake device's own key.
func (b *pullBox) addPull(addr string, args ...string) string {
	b.t.Helper()
	key, err := devreg.ParseHostKey(b.srv.HostKey())
	if err != nil {
		b.t.Fatal(err)
	}
	script := func(r *fake.Runner) {
		route(r)
		scan(addr, key)(r)
	}
	return plain(b.sb.cfgRun("", append([]string{"device", "add"}, args...), script, "SUDO_USER=alice"))
}

func TestDeviceAddPullRegistersThenPulls(t *testing.T) {
	b := newPullBox(t)
	b.serve("juniper", "set system host-name x\n")
	out := b.addPull("192.168.1.20", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-lookup", "--pull")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	reg, pull := strings.Index(out, "Device 'lab-j' registered: 192.168.1.20, juniper."), strings.Index(out, "via netconf")
	if reg < 0 || pull < 0 || reg > pull {
		t.Errorf("the add's report must come first, then the pull's:\n%s", out)
	}
	if !strings.Contains(out, "Scope: lab") || !strings.Contains(out, "1 differ") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(b.sb.devices(), "lab-j") {
		t.Errorf("not registered:\n%s", b.sb.devices())
	}
	rec, ok := b.records().Of("lab-j")
	if !ok || rec.By != "alice" || rec.Pulled.IsZero() {
		t.Errorf("record %+v", rec)
	}
	if b.pw.asked != 1 || b.pw.accepted != 1 || b.srv.Logins() != 1 {
		t.Errorf("asked %d accepted %d logins %d", b.pw.asked, b.pw.accepted, b.srv.Logins())
	}
}

// With --host-key, and with the name offered by no one: the add's options
// are the add's own.
func TestDeviceAddPullWithHostKey(t *testing.T) {
	b := newPullBox(t)
	b.serve("cisco", "hostname x\n")
	key, err := devreg.ParseHostKey(b.srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	out := b.addPull("192.168.1.30", "lab-c", "192.168.1.30", "--vendor", "cisco", "--no-lookup", "--host-key", key.Fingerprint(), "--pull")
	if b.sb.code != 0 || !strings.Contains(out, "Host key pinned (it matches --host-key)") || !strings.Contains(out, "via ssh") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	if rec, ok := b.records().Of("lab-c"); !ok || rec.Transport != "ssh" {
		t.Errorf("record %+v", rec)
	}
}

// Without --pull nothing is read and no password is asked.
func TestDeviceAddWithoutPullDoesNotPull(t *testing.T) {
	b := newPullBox(t)
	b.addPull("192.168.1.20", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-lookup")
	if b.sb.code != 0 || b.pw.asked != 0 || b.srv.Logins() != 0 {
		t.Errorf("exit %d asked %d logins %d", b.sb.code, b.pw.asked, b.srv.Logins())
	}
	if _, ok := b.records().Of("lab-j"); ok {
		t.Error("a record without --pull")
	}
}

// A device no scope covers is registered, one line says how to go on, and
// the exit status is 0.
func TestDeviceAddPullSkipsADeviceInNoScope(t *testing.T) {
	b := newPullBox(t)
	out := b.addPull("100.64.0.9", "stray-j", "100.64.0.9", "--vendor", "juniper", "--no-lookup", "--no-host-key", "--pull")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"Device 'stray-j' registered", "Scope: none yet",
		"Not pulled: no scope's prefixes cover 100.64.0.9.", "tacctl scope prefixes <scope> add <cidr>", "tacctl device config pull stray-j"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(b.sb.devices(), "stray-j") {
		t.Error("not registered")
	}
	if b.pw.asked != 0 || b.srv.Logins() != 0 {
		t.Errorf("a password was asked (%d) or a device dialled (%d)", b.pw.asked, b.srv.Logins())
	}
}

// A pull that fails leaves the device registered and is the exit status.
func TestDeviceAddPullFailureKeepsTheDevice(t *testing.T) {
	b := newPullBox(t)
	b.serve("juniper", "set system host-name x\n")
	b.pw.pw = "not-the-password"
	out := b.addPull("192.168.1.20", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-lookup", "--pull")
	if b.sb.code != 1 || !strings.Contains(out, "failed: authentication failed") {
		t.Errorf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(out, "Device 'lab-j' registered") || !strings.Contains(b.sb.devices(), "lab-j") {
		t.Errorf("the device is not registered:\n%s", out)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), "not-the-password", testPassword)
}

// A registration that is refused is not pulled.
func TestDeviceAddPullRefusedRegistrationDoesNotPull(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.addPull("192.168.1.20", "lab-k", "192.168.1.20", "--vendor", "juniper", "--no-lookup", "--pull")
	if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), "192.168.1.20") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.pw.asked != 0 || b.srv.Logins() != 0 || strings.Contains(b.sb.devices(), "lab-k") {
		t.Errorf("asked %d logins %d:\n%s", b.pw.asked, b.srv.Logins(), b.sb.devices())
	}
}

// The refusals that need no device come before anything is registered.
func TestDeviceAddPullRefusalsRegisterNothing(t *testing.T) {
	b := newPullBox(t)
	for _, c := range []struct {
		env  []string
		args []string
		err  string
	}{
		{[]string{"SUDO_USER=alice"}, []string{"device", "add", "lab-o", "192.168.1.9", "--no-host-key", "--no-lookup", "--pull"},
			"--pull reads the configuration, which needs --vendor cisco, juniper or wti."},
		{[]string{"SUDO_USER=alice"}, []string{"device", "add", "lab-o", "192.168.1.9", "--vendor", "other", "--no-host-key", "--pull"},
			"--pull reads the configuration, which needs --vendor cisco, juniper or wti."},
		{[]string{"SUDO_USER=root"}, []string{"device", "add", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--pull"},
			"logs in to the devices as the user who invoked it"},
		{nil, []string{"device", "add", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--pull"},
			"logs in to the devices as the user who invoked it"},
	} {
		b.sb.cfgRun("", c.args, route, c.env...)
		if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), c.err) {
			t.Errorf("%v %v: exit %d, stderr %q (want %q)", c.env, c.args, b.sb.code, b.sb.stderr(), c.err)
		}
		if d := b.sb.devices(); strings.Contains(d, "lab-o") || strings.Contains(d, "lab-j") {
			t.Errorf("%v: registered:\n%s", c.args, d)
		}
	}
	if b.pw.asked != 0 || b.srv.Logins() != 0 {
		t.Errorf("a refusal asked a password (%d) or dialled (%d)", b.pw.asked, b.srv.Logins())
	}
}
