package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// factsRunner is the host sandbox's runner whose session read of the facts
// prints out.
func (hs *hostSandbox) factsRunner(out string) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.FactsCommand },
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(out)}, nil })
	return r
}

// An enrolled host's address is the one the enrolment session reached; the
// registry refuses it to 'device add', finds the host by it and leaves it
// out of discover; a sync that finds another one records it and raises the
// address-changed notice, which the host may acknowledge.
func TestHostAddressRecordedAndChanged(t *testing.T) {
	hs := newHostSandbox(t)
	conn := func(addr string) string { return "ssh_connection=198.51.100.9 50022 " + addr + " 22\n" }
	r := hs.factsRunner(conn("192.0.2.50"))
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if !r.CalledRegexp(`^ssh .* -T admin@web1\.example\.net printf 'ssh_connection=%s\\n' "\$SSH_CONNECTION"; `) {
		t.Errorf("no facts read: %q", r.Argvs())
	}
	if !strings.Contains(hs.devices(), "hosts:\n  web1: {address: 192.0.2.50}\n") {
		t.Errorf("devices.yaml:\n%s", hs.devices())
	}
	if strings.Contains(hs.out.String()+hs.err.String(), "useradd") {
		t.Errorf("a login.defs warning without login.defs:\n%s%s", hs.out.String(), hs.err.String())
	}
	// The registry knows the address: refused to device add, found by it.
	hs.run(nil, "device", "add", "web1b", "192.0.2.50", "--no-host-key")
	hs.expect(1, "", "192.0.2.50 belongs to the enrolled host 'web1'.")
	out := plain(hs.run(nil, "device", "show", "192.0.2.50"))
	if hs.code != 0 || !strings.Contains(out, "Enrolled host web1") || !strings.Contains(out, "Address:      192.0.2.50") {
		t.Errorf("show by address: %d\n%s", hs.code, out)
	}
	// Same address on sync: nothing written.
	before := hs.devices()
	hs.run(hs.factsRunner(conn("192.0.2.50")), "host", "sync", "web1")
	hs.expect(0, "web1: synced (", "")
	if hs.devices() != before || strings.Contains(hs.out.String()+hs.err.String(), "address") {
		t.Errorf("same address: %s%s\n%s", hs.out.String(), hs.err.String(), hs.devices())
	}
	// Another address: recorded, logged, the notice raised.
	r = hs.factsRunner(conn("192.0.2.51"))
	hs.run(r, "host", "sync", "web1")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "web1: the enrolment session reached 192.0.2.51, but 'web1.example.net' resolves to 192.0.2.50; recorded 192.0.2.51 (the address the connection reached).") ||
		!strings.Contains(all, "web1: its address changed from 192.0.2.50 to 192.0.2.51; recorded 192.0.2.51 (notice address-changed: tacctl device show web1).") {
		t.Errorf("changed: %d\n%s", hs.code, all)
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.warning", "host address-changed name=web1 old=192.0.2.50 new=192.0.2.51 by=root") {
		t.Errorf("not logged: %q", r.Argvs())
	}
	if d := hs.devices(); !strings.Contains(d, "address: 192.0.2.51") || !strings.Contains(d, "previous_address: 192.0.2.50") || !strings.Contains(d, "address_changed:") {
		t.Errorf("devices.yaml:\n%s", d)
	}
	out = plain(hs.run(nil, "device", "notices"))
	if !strings.Contains(out, "web1  address-changed: the address of 'web1' changed from 192.0.2.50 to 192.0.2.51") ||
		!strings.Contains(out, "'tacctl device notice web1 ack address-changed'") {
		t.Errorf("notices:\n%s", out)
	}
	// The old address is free again; the new one is the host's.
	hs.run(nil, "device", "add", "web1c", "192.0.2.51", "--no-host-key")
	hs.expect(1, "", "192.0.2.51 belongs to the enrolled host 'web1'.")
	// Acknowledged by the host; other kinds are not.
	hs.run(nil, "device", "notice", "web1", "ack", "address-changed")
	hs.expect(0, "Notice 'address-changed' of 'web1' acknowledged.", "")
	if out := plain(hs.run(nil, "device", "notices")); strings.Contains(out, "address-changed") {
		t.Errorf("acknowledged notice still open:\n%s", out)
	}
	hs.run(nil, "device", "notice", "web1", "ack", "name-mismatch")
	hs.expect(1, "", "'web1' is an enrolled host; its 'name-mismatch' notice is cleared on the host, not acknowledged.")
	// A further change reopens it.
	hs.run(hs.factsRunner(conn("192.0.2.52")), "host", "sync", "web1")
	if out := plain(hs.run(nil, "device", "notices")); !strings.Contains(out, "changed from 192.0.2.51 to 192.0.2.52") {
		t.Errorf("not reopened:\n%s", out)
	}
	// Unenroll forgets the record.
	hs.run(nil, "host", "unenroll", "web1")
	if strings.Contains(hs.devices(), "web1") {
		t.Errorf("after unenroll:\n%s", hs.devices())
	}
}

// Without SSH_CONNECTION the resolution is recorded; a login.defs whose
// range overlaps tacctl's is warned about once per host; --local records
// 127.0.0.1 and reads this server's own login.defs.
func TestHostFactsFallbackAndLoginDefs(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(hs.factsRunner("ssh_connection=\nlogin_defs=present\nUID_MIN 1000\nUID_MAX 85000\n"),
		"host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "web1: the session did not report the address it reached (SSH_CONNECTION); recorded 192.0.2.50, which 'web1.example.net' resolves to.") ||
		strings.Count(all, "web1: local useradd there gives out UIDs 1000-85000 (/etc/login.defs UID_MIN/UID_MAX), which overlaps tacctl's 80000-89999:") != 1 ||
		!strings.Contains(all, "Keep UID_MAX below 80000 in /etc/login.defs on web1 (the default is 60000; tacctl does not change it).") {
		t.Errorf("enroll: %d\n%s", hs.code, all)
	}
	if !strings.Contains(hs.devices(), "web1: {address: 192.0.2.50}") {
		t.Errorf("devices.yaml:\n%s", hs.devices())
	}
	hs.run(hs.factsRunner("ssh_connection=1 2 192.0.2.50 22\nlogin_defs=present\nUID_MAX 60000\n"), "host", "sync", "web1")
	if all := hs.out.String() + hs.err.String(); hs.code != 0 || strings.Contains(all, "useradd") {
		t.Errorf("sync, UID_MAX 60000: %d\n%s", hs.code, all)
	}
	hs.run(nil, "host", "unenroll", "web1")

	if err := os.WriteFile(filepath.Join(hs.dir, "login.defs"), []byte("UID_MIN\t\t 1000\nUID_MAX\t\t99999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := hs.runner()
	r.On([]string{"bash"}, execx.Result{Stdout: []byte("[INFO] Accounts: 1 managed by tacctl here.\n")})
	hs.loopback()
	hs.run(r, "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Host 'authsrv' enrolled (1 user).") || !strings.Contains(all, "authsrv: local useradd there gives out UIDs 1000-99999") {
		t.Errorf("--local: %d\n%s", hs.code, all)
	}
	if !strings.Contains(hs.devices(), "authsrv: {address: 127.0.0.1}") {
		t.Errorf("devices.yaml:\n%s", hs.devices())
	}
}

// The suggested commands of 'device add' keep the flags the user gave.
func TestDeviceAddSuggestionsKeepFlags(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "switch", "198.51.100.8", "--vendor", "juniper", "--no-host-key", "--description", "rack 4")
	sb.expect(1, "", `To keep this name deliberately: tacctl device add switch 198.51.100.8 --vendor juniper --no-host-key --description rack\ 4 --allow-generic`)
	sb.devScan("", scan("198.51.100.9"), "add", "edge1", "198.51.100.9", "--vendor", "cisco", "--port", "2222")
	sb.expect(1, "", "register it without a pinned key: tacctl device add edge1 198.51.100.9 --vendor cisco --port 2222 --no-host-key")
}
