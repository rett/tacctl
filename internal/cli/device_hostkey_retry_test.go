package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// A device that does not answer ssh-keyscan's combined scan (it limits the
// simultaneous connections ssh-keyscan opens per key type, or drops its long
// offer) but answers a scan of one type, as `ssh-keyscan -t ed25519 <address>`
// does by hand.

// scanOneAtATime scripts ssh-keyscan against such a device holding keys:
// a -t with several types prints a banner only, a -t with one type prints
// that type's key.
func scanOneAtATime(addr string, keys ...devreg.HostKey) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
			res := execx.Result{Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_7.5\n")}
			typ := c.Args[slices.Index(c.Args, "-t")+1]
			if strings.Contains(typ, ",") {
				return res, nil
			}
			prefix := map[string]string{"ed25519": "ssh-ed25519", "ecdsa": "ecdsa-", "rsa": "ssh-rsa", "ssh-rsa": "ssh-rsa"}[typ]
			for _, k := range keys {
				if strings.HasPrefix(k.Type, prefix) {
					res.Stdout = append(res.Stdout, keyscanOut(addr, k)...)
				}
			}
			return res, nil
		})
	}
}

func TestDeviceAddReadsAKeyOneTypeAtATime(t *testing.T) {
	sb := newSandbox(t, true)
	ed, rsa := hkKey(t, "ed25519"), hkKey(t, "rsa")
	out := sb.devScan("", scanOneAtATime("192.0.2.7", rsa, ed), "add", "x", "192.0.2.7", "--vendor", "juniper")
	if sb.code != 0 || !strings.Contains(out, "Host keys pinned (2)") ||
		!strings.Contains(out, "    ED25519  "+ed.Fingerprint()) || !strings.Contains(out, "    RSA      "+rsa.Fingerprint()) {
		t.Fatalf("add: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	argvs := sb.runner.Argvs()
	want := []string{
		"ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 192.0.2.7",
		"ssh-keyscan -T 3 -p 22 -t ed25519 192.0.2.7",
		"ssh-keyscan -T 3 -p 22 -t ecdsa 192.0.2.7",
		"ssh-keyscan -T 3 -p 22 -t rsa 192.0.2.7",
	}
	var got []string
	for _, a := range argvs {
		if strings.HasPrefix(a, "ssh-keyscan") {
			got = append(got, a)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("ssh-keyscan runs %q, want %q", got, want)
	}
	if !strings.Contains(sb.devices(), "host_keys: [ssh-ed25519 "+ed.Blob+", ssh-rsa "+rsa.Blob+"]") {
		t.Errorf("not pinned:\n%s", sb.devices())
	}

	// The re-pin verbs read it the same way, and --host-key names a key of
	// the one-type scan.
	out = sb.devScan("", scanOneAtATime("192.0.2.7", rsa, ed), "hostkey", "x", "set", rsa.Fingerprint())
	if sb.code != 0 || !strings.Contains(out, "Pinned 1 host key(s) for 'x'.") {
		t.Errorf("set: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	out = sb.devScan("", scanOneAtATime("192.0.2.8", ed), "add", "y", "192.0.2.8", "--host-key", ed.Fingerprint())
	if sb.code != 0 || !strings.Contains(out, "Host key pinned (it matches --host-key)") {
		t.Errorf("--host-key: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
}

// A device that accepted the connection and gave no key to any read: the
// refusal names the one-type retry and the built-in client, gives the command
// to read the key by hand and the ways to accept a key by its fingerprint.
// One that did not answer is refused as before.
func TestDeviceAddNoKeyAfterTheRetryNamesIt(t *testing.T) {
	sb := newSandbox(t, true)
	sb.devScan("", scanSilent("192.0.2.7"), "add", "x", "192.0.2.7", "--vendor", "juniper")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.7 port 22 (ssh-keyscan, then one key type at a time (ed25519, ecdsa, rsa), and tacctl's own ssh client); nothing was changed.")
	e := sb.stderr()
	for _, want := range []string{
		"The device accepted the connection but showed no key. See what it offers by hand: ssh-keyscan -t ed25519 192.0.2.7 (also -t ecdsa, -t rsa).",
		"Accept a key by its fingerprint with --host-key SHA256:<fp> (device add, enroll, collect, onboard) or, for a registered device, tacctl device hostkey <name> set SHA256:<fp>.",
		"or register it without a pinned key: tacctl device add x 192.0.2.7 --vendor juniper --no-host-key",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("stderr lacks %q:\n%s", want, e)
		}
	}
	if sb.devices() != "" {
		t.Errorf("registered:\n%s", sb.devices())
	}

	// A legacy-ssh device on another port.
	sb.devScan("", scanSilent("192.0.2.8"), "add", "y", "192.0.2.8", "--vendor", "cisco", "--legacy-ssh", "--port", "830")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.8 port 830 (ssh-keyscan, then one key type at a time (ed25519, ecdsa, rsa, ssh-rsa), and tacctl's own ssh client for legacy-ssh); nothing was changed.")
	if !strings.Contains(sb.stderr(), "ssh-keyscan -p 830 -t ed25519 192.0.2.8 (also -t ecdsa, -t rsa)") {
		t.Errorf("stderr:\n%s", sb.stderr())
	}

	// A device that did not answer: the same short text, no hand-reading
	// advice (the address and the port are what to check).
	sb.devScan("", scan("192.0.2.9"), "add", "z", "192.0.2.9")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.9 port 22 (ssh-keyscan); nothing was changed.")
	if strings.Contains(sb.stderr(), "by hand") || sb.runner.Count("ssh-keyscan") != 1 {
		t.Errorf("unreachable: %d runs\n%s", sb.runner.Count("ssh-keyscan"), sb.stderr())
	}
}
