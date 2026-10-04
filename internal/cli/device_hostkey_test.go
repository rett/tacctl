package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// Host-key pinning end to end, in-process: ssh-keyscan is scripted with the
// public keys of internal/devreg/testdata/hostkeys (generated for the
// tests; no real host's keys).

func hkKey(t *testing.T, name string) devreg.HostKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "devreg", "testdata", "hostkeys", name+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(data))
	k, err := devreg.ParseHostKey(f[0] + " " + f[1])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// keyscanOut is what ssh-keyscan prints for addr offering keys.
func keyscanOut(addr string, keys ...devreg.HostKey) []byte {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(addr + " " + k.String() + "\n")
	}
	return []byte(b.String())
}

// scan scripts ssh-keyscan to offer keys (none: no answer).
func scan(addr string, keys ...devreg.HostKey) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: keyscanOut(addr, keys...), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")})
	}
}

// devScan runs 'tacctl device <args>' with ssh-keyscan scripted.
func (sb *sandbox) devScan(stdin string, script func(*fake.Runner), args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"device"}, args...), script))
}

func (sb *sandbox) knownHosts() string {
	data, err := os.ReadFile(sb.path("var-lib", "ssh", "known_hosts"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

func TestDeviceAddPinsHostKeys(t *testing.T) {
	sb := newSandbox(t, true)
	ed, rsa := hkKey(t, "ed25519"), hkKey(t, "rsa")
	out := sb.devScan("", scan("192.0.2.1", rsa, ed), "add", "x", "192.0.2.1", "--vendor", "cisco")
	if sb.code != 0 {
		t.Fatalf("add: %d %q %q", sb.code, out, sb.stderr())
	}
	if !sb.runner.Called("ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519,ecdsa,rsa", "192.0.2.1") {
		t.Errorf("keyscan argv %q", sb.runner.Argvs())
	}
	for _, want := range []string{
		"Device 'x' registered: 192.0.2.1, cisco.",
		"Host keys pinned (2); compare with the device console before first use:",
		"    ED25519  " + ed.Fingerprint(), "    RSA      " + rsa.Fingerprint(),
		"On the device: Cisco IOS/IOS-XE: 'show ip ssh'",
		"tacctl device hostkey x accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("add output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out+sb.stderr(), "hostkey-unpinned") {
		t.Errorf("a pinned device has the unpinned notice:\n%s", out)
	}
	if !strings.Contains(sb.devices(), "host_keys: [ssh-ed25519 "+ed.Blob+", ssh-rsa "+rsa.Blob+"]") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
	want := devreg.KnownHostsHeader + "x " + ed.String() + "\nx " + rsa.String() + "\n"
	if got := sb.knownHosts(); got != want {
		t.Errorf("known_hosts:\n%s\nwant:\n%s", got, want)
	}
	// The file 0644 in an 'ssh' directory 0755 under VarLib 0711: every
	// user's ssh reads it (/etc/tacctl is 0700).
	for path, mode := range map[string]os.FileMode{sb.path("var-lib", "ssh", "known_hosts"): 0o644,
		sb.path("var-lib", "ssh"): 0o755, sb.path("var-lib"): 0o711} {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s mode: %v %v, want %v", path, st, err, mode)
		}
	}
	// show lists the fingerprints.
	out = sb.dev("", "show", "x")
	if !strings.Contains(out, "Host keys:    ED25519  "+ed.Fingerprint()) || !strings.Contains(out, "RSA      "+rsa.Fingerprint()) {
		t.Errorf("show:\n%s", out)
	}
	// A legacy device on another port: ssh-rsa is asked for by name too.
	sb.devScan("", scan("[192.0.2.2]:830", rsa), "add", "old-ios", "192.0.2.2", "--vendor", "cisco", "--legacy-ssh", "--port", "830")
	if sb.code != 0 || !sb.runner.Called("ssh-keyscan", "-T", "5", "-p", "830", "-t", "ed25519,ecdsa,rsa,ssh-rsa", "192.0.2.2") {
		t.Errorf("legacy: %d %q %q", sb.code, sb.runner.Argvs(), sb.stderr())
	}
	if !strings.Contains(sb.knownHosts(), "\nold-ios "+rsa.String()+"\n") {
		t.Errorf("known_hosts:\n%s", sb.knownHosts())
	}
	// Removing a device drops its lines; renaming renames them.
	sb.dev("", "rename", "old-ios", "core-ios")
	if kh := sb.knownHosts(); strings.Contains(kh, "old-ios") || !strings.Contains(kh, "core-ios "+rsa.String()) {
		t.Errorf("after rename:\n%s", kh)
	}
	sb.dev("", "remove", "core-ios", "-y")
	if strings.Contains(sb.knownHosts(), "core-ios") {
		t.Errorf("after remove:\n%s", sb.knownHosts())
	}
	// A new address drops the pins, and their lines.
	sb.dev("", "address", "x", "192.0.2.9")
	if sb.knownHosts() != devreg.KnownHostsHeader || !strings.Contains(sb.stderr()+plain(sb.out.String()), "dropped") {
		t.Errorf("after address change:\n%s", sb.knownHosts())
	}
}

func TestDeviceAddHostKeyRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	ed, ec, rsa := hkKey(t, "ed25519"), hkKey(t, "ecdsa"), hkKey(t, "rsa")
	nothingWritten := func(what string) {
		t.Helper()
		if sb.devices() != "" || sb.knownHosts() != "" {
			t.Errorf("%s: something was written", what)
		}
		if snaps, _ := filepath.Glob(sb.path("state", "backups", "2*")); len(snaps) != 0 {
			t.Errorf("%s: a snapshot was taken", what)
		}
	}
	// --host-key that the device does not offer: refused, the offered listed.
	other := hkKey(t, "ecdsa521").Fingerprint()
	sb.devScan("", scan("192.0.2.1", ed, rsa), "add", "x", "192.0.2.1", "--host-key", other)
	sb.expect(1, "", "No host key 192.0.2.1 offers matches "+other+"; nothing was registered.")
	if e := sb.stderr(); !strings.Contains(e, "ED25519  "+ed.Fingerprint()) || !strings.Contains(e, "RSA      "+rsa.Fingerprint()) ||
		!strings.Contains(e, "Check the fingerprint on the device console") {
		t.Errorf("refusal:\n%s", e)
	}
	nothingWritten("--host-key mismatch")
	// No answer: refused with the way on.
	sb.devScan("", scan("192.0.2.1"), "add", "x", "192.0.2.1")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.1 port 22 (ssh-keyscan); nothing was changed.")
	if !strings.Contains(sb.stderr(), "or register it without a pinned key: tacctl device add x 192.0.2.1 --no-host-key") {
		t.Errorf("no answer:\n%s", sb.stderr())
	}
	nothingWritten("no answer")
	// ssh-keyscan missing.
	sb.devScan("", func(r *fake.Runner) { r.Missing("ssh-keyscan") }, "add", "x", "192.0.2.1")
	sb.expect(1, "", "openssh-client")
	nothingWritten("no ssh-keyscan")
	// --host-key that matches: only that key is pinned.
	out := sb.devScan("", scan("192.0.2.1", ed, ec, rsa), "add", "x", "192.0.2.1", "--host-key", ec.Fingerprint())
	if sb.code != 0 || !strings.Contains(out, "Host key pinned (it matches --host-key):\n    ECDSA    "+ec.Fingerprint()) ||
		!strings.Contains(out, "Also offered, not pinned (unverified)") || !strings.Contains(out, "ED25519  "+ed.Fingerprint()) {
		t.Errorf("--host-key match: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if kh := sb.knownHosts(); kh != devreg.KnownHostsHeader+"x "+ec.String()+"\n" {
		t.Errorf("known_hosts:\n%s", kh)
	}
	// A duplicate is refused before anything is scanned.
	sb.devScan("", scan("192.0.2.1", ed), "add", "X", "192.0.2.5")
	sb.expect(1, "", "already registered")
	if sb.runner.Called("ssh-keyscan") {
		t.Error("a duplicate was scanned")
	}
	// --no-host-key scans nothing and leaves the notice with the way to pin.
	out = sb.devScan("", scan("192.0.2.3", ed), "add", "y", "192.0.2.3", "--vendor", "juniper", "--no-host-key")
	if sb.code != 0 || sb.runner.Called("ssh-keyscan") {
		t.Errorf("--no-host-key: %d %q", sb.code, sb.runner.Argvs())
	}
	if all := out + sb.stderr(); !strings.Contains(all, "hostkey-unpinned: no host key is pinned for 'y'") ||
		!strings.Contains(all, "'show system ssh host-key'") || !strings.Contains(all, "then pin it: 'tacctl device hostkey y accept'") ||
		!strings.Contains(all, "or acknowledge it: 'tacctl device notice y ack hostkey-unpinned'") {
		t.Errorf("--no-host-key notice:\n%s", all)
	}
	if strings.Contains(sb.knownHosts(), "\ny ") {
		t.Error("an unpinned device is in known_hosts")
	}
}

func TestDeviceHostkeyVerb(t *testing.T) {
	sb := newSandbox(t, true)
	ed, ec, rsa := hkKey(t, "ed25519"), hkKey(t, "ecdsa"), hkKey(t, "rsa")
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	// show, unpinned.
	out := sb.dev("", "hostkey", "core-sw1")
	if sb.code != 0 || !strings.Contains(out, "No host key is pinned for 'core-sw1'.") || !strings.Contains(out, "tacctl device hostkey core-sw1 accept") {
		t.Errorf("show: %d\n%s", sb.code, out)
	}
	// accept asks; a closed stdin cancels.
	out = sb.devScan("", scan("10.99.0.1", ed, rsa), "hostkey", "core-sw1", "accept")
	if sb.code != 0 || !strings.Contains(out, "Pinned now: none") || !strings.Contains(out, "To pin (offered by 10.99.0.1 port 22):") ||
		!strings.Contains(out, "Aborted; the pin was not changed.") || strings.Contains(sb.devices(), "host_keys") {
		t.Errorf("accept, closed stdin: %d\n%s", sb.code, out)
	}
	out = sb.devScan("y\n", scan("10.99.0.1", ed, rsa), "hostkey", "core-sw1", "accept")
	if sb.code != 0 || !strings.Contains(out, "Pinned 2 host key(s) for 'core-sw1'.") {
		t.Errorf("accept, yes: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "device hostkey accept name=core-sw1 keys=2 by=root") {
		t.Errorf("no audit line: %q", sb.runner.Argvs())
	}
	if kh := sb.knownHosts(); !strings.Contains(kh, "core-sw1 "+ed.String()+"\ncore-sw1 "+rsa.String()+"\n") {
		t.Errorf("known_hosts:\n%s", kh)
	}
	if out = sb.dev("", "notices", "core-sw1"); strings.Contains(out, "hostkey-unpinned") {
		t.Errorf("pinned, still unpinned:\n%s", out)
	}
	// The same keys again: nothing to do.
	out = sb.devScan("", scan("10.99.0.1", rsa, ed), "hostkey", "core-sw1", "accept", "-y")
	if sb.code != 0 || !strings.Contains(out, "already these; nothing was changed") {
		t.Errorf("accept, unchanged: %d\n%s", sb.code, out)
	}
	// show, pinned.
	out = sb.dev("", "hostkey", "core-sw1", "show")
	if !strings.Contains(out, "Host keys pinned for 'core-sw1':\n    ED25519  "+ed.Fingerprint()+"\n    RSA      "+rsa.Fingerprint()) {
		t.Errorf("show pinned:\n%s", out)
	}
	// A changed device: accept -y shows both and re-pins.
	out = sb.devScan("", scan("10.99.0.1", ec), "hostkey", "core-sw1", "accept", "-y")
	if sb.code != 0 || !strings.Contains(out, "Pinned now:\n    ED25519") || !strings.Contains(out, "To pin (offered by 10.99.0.1 port 22):\n    ECDSA    "+ec.Fingerprint()) {
		t.Errorf("accept changed: %d\n%s", sb.code, out)
	}
	if kh := sb.knownHosts(); kh != devreg.KnownHostsHeader+"core-sw1 "+ec.String()+"\n" {
		t.Errorf("known_hosts:\n%s", kh)
	}
	// set pins the one key of that fingerprint.
	out = sb.devScan("", scan("10.99.0.1", ed, ec, rsa), "hostkey", "core-sw1", "set", rsa.Fingerprint())
	if sb.code != 0 || !strings.Contains(out, "Pinned 1 host key(s) for 'core-sw1'.") || sb.knownHosts() != devreg.KnownHostsHeader+"core-sw1 "+rsa.String()+"\n" {
		t.Errorf("set: %d\n%s\n%s", sb.code, out, sb.knownHosts())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "device hostkey set name=core-sw1 keys=1 by=root") {
		t.Errorf("no audit line: %q", sb.runner.Argvs())
	}
	before, khBefore := sb.devices(), sb.knownHosts()
	for _, c := range []struct {
		script func(*fake.Runner)
		args   []string
		err    string
	}{
		{scan("10.99.0.1", ed), []string{"set", ec.Fingerprint()}, "No host key 'core-sw1' (10.99.0.1) offers matches " + ec.Fingerprint() + "; the pin was not changed."},
		{scan("10.99.0.1"), []string{"accept", "-y"}, "No ssh host key could be read from 10.99.0.1 port 22 (ssh-keyscan); nothing was changed."},
		{nil, []string{"set"}, "'set' needs the fingerprint"},
		{nil, []string{"set", "SHA256:short"}, "Invalid fingerprint 'SHA256:short'"},
		{nil, []string{"forget"}, "Unknown action: 'forget'"},
		{nil, []string{"show", "extra"}, "Unknown argument: 'extra'"},
	} {
		sb.devScan("", c.script, append([]string{"hostkey", "core-sw1"}, c.args...)...)
		sb.expect(1, "", c.err)
		if sb.devices() != before || sb.knownHosts() != khBefore {
			t.Errorf("%v: the pin changed", c.args)
		}
	}
	sb.dev("", "hostkey", "nope", "show")
	sb.expect(1, "", "Device 'nope' not found")
	sb.dev("", "hostkey")
	sb.expect(1, "", "Usage: tacctl device hostkey")
	// Administrators only, show included.
	for _, args := range [][]string{{"hostkey", "core-sw1"}, {"hostkey", "core-sw1", "accept", "-y"}} {
		sb.cfgRun("", append([]string{"device"}, args...), func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-operator\n")})
		}, "SUDO_USER=carol")
		if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl device hostkey' is not permitted for the") {
			t.Errorf("carol %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// An import never changes a pin.
	sb.write("tmp/imp.yaml", "version: 1\ndevices:\n  core-sw1: {address: 10.99.0.1, vendor: cisco, host_keys: ['"+ed.String()+"']}\n", 0o600)
	sb.dev("", "import", sb.path("tmp", "imp.yaml"))
	if sb.code != 0 || sb.knownHosts() != khBefore {
		t.Errorf("import re-pinned: %d\n%s", sb.code, sb.knownHosts())
	}
}

// Enrolled hosts: pinned by host enroll and host sync from the keys read
// over the enrolment's own ssh session, cross-checked with ssh-keyscan
// (only keys both hold are pinned); re-pinned only by device hostkey,
// forgotten by host unenroll.
func TestHostEnrollSyncPinHostKeys(t *testing.T) {
	hs := newHostSandbox(t)
	ed, ec, rsa := hkKey(t, "ed25519"), hkKey(t, "ecdsa"), hkKey(t, "rsa")
	// hostKeys: the session's 'cat /etc/ssh/ssh_host_*_key.pub' prints own
	// (nothing and exit 1 when empty), ssh-keyscan offers offered.
	hostKeys := func(own []devreg.HostKey, offered ...devreg.HostKey) *fake.Runner {
		r := hs.runner()
		scan("web1.example.net", offered...)(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ReadKeysCommand },
			func(execx.Cmd) (execx.Result, error) {
				if len(own) == 0 {
					return execx.Result{Code: 1}, nil
				}
				var b strings.Builder
				for _, k := range own {
					b.WriteString(k.String() + " root@web1\n")
				}
				return execx.Result{Stdout: []byte(b.String())}, nil
			})
		return r
	}
	both := func(keys ...devreg.HostKey) []devreg.HostKey { return keys }
	r := hostKeys(both(ed, rsa), ed, rsa)
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--port", "2222", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if !r.CalledRegexp(`^ssh .* -p 2222 -T admin@web1\.example\.net cat /etc/ssh/ssh_host_\*_key\.pub$`) ||
		!r.Called("ssh-keyscan", "-T", "5", "-p", "2222", "-t", "ed25519,ecdsa,rsa", "web1.example.net") {
		t.Errorf("reads %q", r.Argvs())
	}
	// The session read comes before the connection is closed.
	argvs := r.Argvs()
	ri := slices.IndexFunc(argvs, func(s string) bool { return strings.HasSuffix(s, hosts.ReadKeysCommand) })
	ci := slices.IndexFunc(argvs, func(s string) bool { return strings.HasSuffix(s, "-O exit admin@web1.example.net") })
	if ri < 0 || ci < 0 || ri > ci {
		t.Errorf("order %q", argvs)
	}
	if e := plain(hs.out.String()); strings.Contains(e, "snapshot") || !strings.Contains(e, "web1: pinned 2 ssh host key(s) for 'tacctl ssh': ED25519 "+ed.Fingerprint()+", RSA "+rsa.Fingerprint()) {
		t.Errorf("enroll stderr:\n%s", e)
	}
	kh := hs.knownHosts()
	if kh != devreg.KnownHostsHeader+"web1 "+ed.String()+"\nweb1 "+rsa.String()+"\n" {
		t.Errorf("known_hosts:\n%s", kh)
	}
	if !strings.Contains(hs.devices(), "hosts:\n  web1:\n    host_keys: [ssh-ed25519 ") {
		t.Errorf("devices.yaml:\n%s", hs.devices())
	}
	if !strings.Contains(hs.registry(), "web1|admin@web1.example.net|2222|lab|") {
		t.Errorf("linux-hosts %q", hs.registry())
	}
	out := plain(hs.run(nil, "device", "show", "web1"))
	if !strings.Contains(out, "Host keys:    ED25519  "+ed.Fingerprint()) {
		t.Errorf("show web1:\n%s", out)
	}
	// sync with the same keys: silent about keys, nothing written; a pinned
	// host is checked against the session's keys, not re-scanned.
	devBefore := hs.devices()
	r = hostKeys(both(rsa, ed), ec)
	hs.run(r, "host", "sync", "web1")
	hs.expect(0, "web1: synced (3 users).", "")
	if strings.Contains(hs.out.String(), "pinned") || hs.devices() != devBefore || r.Called("ssh-keyscan") {
		t.Errorf("sync, same keys: %q %q", hs.out.String(), r.Argvs())
	}
	// a new key type: reported, not pinned.
	hs.run(hostKeys(both(ed, ec, rsa)), "host", "sync", "web1")
	if e := plain(hs.out.String()); hs.code != 0 || !strings.Contains(e, "web1: has host key types that are not pinned (ECDSA "+ec.Fingerprint()+")") ||
		!strings.Contains(e, "tacctl device hostkey web1 accept") || hs.devices() != devBefore {
		t.Errorf("sync, added: %d\n%s", hs.code, e)
	}
	// a changed key: reported, the pin stays, the sync still succeeds.
	hs.run(hostKeys(both(ec)), "host", "sync", "web1")
	if e := plain(hs.out.String()); hs.code != 0 || !strings.Contains(e, "web1: the ssh host key differs from the one pinned; the pin was not changed.") ||
		!strings.Contains(e, "Pinned: ED25519 "+ed.Fingerprint()) || !strings.Contains(e, "On the host: ECDSA "+ec.Fingerprint()) ||
		!strings.Contains(e, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub") || hs.devices() != devBefore || hs.knownHosts() != kh {
		t.Errorf("sync, changed: %d\n%s", hs.code, e)
	}
	// device hostkey accept re-pins a host.
	r = hostKeys(nil, ec)
	hs.run(r, "device", "hostkey", "web1", "accept", "-y")
	if hs.code != 0 || hs.knownHosts() != devreg.KnownHostsHeader+"web1 "+ec.String()+"\n" {
		t.Errorf("hostkey accept web1: %d %q\n%s", hs.code, hs.out.String(), hs.knownHosts())
	}
	if !r.Called("ssh-keyscan", "-T", "5", "-p", "2222", "-t", "ed25519,ecdsa,rsa", "web1.example.net") {
		t.Errorf("hostkey accept scanned %q", r.Argvs())
	}
	// unenroll forgets the pins.
	hs.run(nil, "host", "unenroll", "web1")
	hs.expect(0, "", "")
	if hs.knownHosts() != devreg.KnownHostsHeader || strings.Contains(hs.devices(), "web1") {
		t.Errorf("after unenroll:\n%s\n%s", hs.knownHosts(), hs.devices())
	}
	enroll := func(r *fake.Runner) string {
		hs.run(r, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
		if hs.code != 0 {
			t.Errorf("enroll: %d %q", hs.code, hs.stderr())
		}
		return plain(hs.out.String())
	}
	// Partial overlap: only the agreed key is pinned, the others reported.
	e := enroll(hostKeys(both(ed, ec), ed, rsa))
	if !strings.Contains(e, "web1: pinned 1 ssh host key(s) for 'tacctl ssh': ED25519 "+ed.Fingerprint()) ||
		!strings.Contains(e, "web1: not offered to ssh-keyscan, not pinned: ECDSA "+ec.Fingerprint()) ||
		!strings.Contains(e, "web1: offered but not among the host's key files, not pinned: RSA "+rsa.Fingerprint()) ||
		hs.knownHosts() != devreg.KnownHostsHeader+"web1 "+ed.String()+"\n" {
		t.Errorf("partial:\n%s\n%s", e, hs.knownHosts())
	}
	hs.run(nil, "host", "unenroll", "web1")
	// Mismatch: a type with different keys refuses the pin, both sets shown
	// and logged; the enrolment itself succeeds.
	r = hostKeys(both(ed, rsa), otherEd25519(t), rsa)
	e = enroll(r)
	if !strings.Contains(e, "web1: the keys the host holds and the keys offered at web1.example.net port 22 differ; nothing was pinned.") ||
		!strings.Contains(e, "Read over the enrolment session: ED25519 "+ed.Fingerprint()) ||
		!strings.Contains(e, "tacctl device hostkey web1 accept") || strings.Contains(hs.devices(), "host_keys") {
		t.Errorf("mismatch:\n%s\n%s", e, hs.devices())
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.warning", "host hostkey-mismatch name=web1 host=web1.example.net port=22") {
		t.Errorf("mismatch not logged: %q", r.Argvs())
	}
	hs.run(nil, "host", "unenroll", "web1")
	// Unreadable key files: nothing pinned, no scan to trust alone.
	r = hostKeys(nil, ed, rsa)
	e = enroll(r)
	if !strings.Contains(e, "web1: the host's ssh keys could not be read over the enrolment session") || r.Called("ssh-keyscan") ||
		strings.Contains(hs.devices(), "host_keys") {
		t.Errorf("unreadable:\n%s", e)
	}
	hs.run(nil, "host", "unenroll", "web1")
	// A host that does not answer the scan is enrolled, unpinned, with a warning.
	e = enroll(hostKeys(both(ed)))
	if !strings.Contains(e, "web1: no ssh host key could be read from web1.example.net port 22 (ssh-keyscan) to check the session's against; none pinned.") {
		t.Errorf("enroll, no answer:\n%s", e)
	}
	if strings.Contains(hs.devices(), "hosts:") {
		t.Errorf("devices.yaml:\n%s", hs.devices())
	}
	hs.run(nil, "host", "unenroll", "web1")
	// --local: no session, no scan, nothing pinned.
	r = hostKeys(both(ed), ed)
	hs.run(r, "host", "enroll", "--local", "--scope", "lab", "--build-on-host")
	if r.Called("ssh-keyscan") || r.CalledRegexp(`cat /etc/ssh`) || strings.Contains(hs.devices(), "host_keys") {
		t.Errorf("--local: %d %q", hs.code, r.Argvs())
	}
}

// otherEd25519 is a well-formed ed25519 key other than the test key.
func otherEd25519(t *testing.T) devreg.HostKey {
	t.Helper()
	var b []byte
	put := func(p []byte) { b = binary.BigEndian.AppendUint32(b, uint32(len(p))); b = append(b, p...) }
	put([]byte("ssh-ed25519"))
	put(bytes.Repeat([]byte{7}, 32))
	k, err := devreg.ParseHostKey("ssh-ed25519 " + base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
