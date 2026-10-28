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
