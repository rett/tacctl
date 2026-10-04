package devreg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// testdata/hostkeys holds public keys generated for these tests only (no
// host's real keys; the private halves were never kept) and the output of
// 'ssh-keygen -lf' for each, captured once.

// testKey is the public key of testdata/hostkeys/<name>.pub.
func testKey(t *testing.T, name string) HostKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "hostkeys", name+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(data))
	k, err := ParseHostKey(f[0] + " " + f[1])
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return k
}

func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "hostkeys", "fingerprints.txt"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// '<file> <bits> SHA256:<fp> <comment> (<TYPE>)'
		f := strings.Fields(line)
		name := strings.TrimSuffix(f[0], ".pub")
		k := testKey(t, name)
		if got := k.Fingerprint(); got != f[2] {
			t.Errorf("%s: fingerprint %s, ssh-keygen says %s", name, got, f[2])
		}
		if want := strings.Trim(f[len(f)-1], "()"); k.Label() != want {
			t.Errorf("%s: label %s, ssh-keygen says %s", name, k.Label(), want)
		}
		if !ValidFingerprint(k.Fingerprint()) {
			t.Errorf("%s: %s is not a valid fingerprint", name, k.Fingerprint())
		}
		n++
	}
	if n != 5 {
		t.Errorf("%d vectors", n)
	}
}

// sshString is the SSH wire encoding of a string.
func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// A key made here, at run time, with the standard library: the fingerprint
// is the unpadded base64 of the SHA-256 of the blob.
func TestFingerprintOfAGeneratedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
	b64 := base64.StdEncoding.EncodeToString(blob)
	keys := ParseKeyscan([]byte("192.0.2.1 ssh-ed25519 " + b64 + "\n"))
	if len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	sum := sha256.Sum256(blob)
	if want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]); keys[0].Fingerprint() != want {
		t.Errorf("fingerprint %s, want %s", keys[0].Fingerprint(), want)
	}
	if strings.HasSuffix(keys[0].Fingerprint(), "=") || len(keys[0].Fingerprint()) != 50 {
		t.Errorf("fingerprint %q is not 'SHA256:' + 43 characters", keys[0].Fingerprint())
	}
}

func TestParseHostKeyRefuses(t *testing.T) {
	ed := testKey(t, "ed25519")
	for name, s := range map[string]string{
		"one field":     "ssh-ed25519",
		"three fields":  ed.String() + " comment",
		"unknown type":  "ssh-dss " + ed.Blob,
		"wrong type":    "ssh-rsa " + ed.Blob,
		"bad base64":    "ssh-ed25519 !!!!",
		"short blob":    "ssh-ed25519 AAAA",
		"length beyond": "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 200, 's'}),
		"empty":         "",
		"security key":  "sk-ssh-ed25519@openssh.com " + ed.Blob,
	} {
		if _, err := ParseHostKey(s); err == nil {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
	if k, err := ParseHostKey(ed.String()); err != nil || k != ed {
		t.Errorf("round trip: %v %v", k, err)
	}
}

func TestParseKeyscan(t *testing.T) {
	ed, ec, ec384, rsa := testKey(t, "ed25519"), testKey(t, "ecdsa"), testKey(t, "ecdsa384"), testKey(t, "rsa")
	cases := []struct {
		name string
		out  string
		want []HostKey
	}{
		{"nothing (no answer)", "", nil},
		{"one key", "10.99.0.1 " + ed.String() + "\n", []HostKey{ed}},
		{"many keys, sorted by preference", "10.99.0.1 " + rsa.String() + "\n10.99.0.1 " + ec.String() + "\n10.99.0.1 " + ed.String() + "\n",
			[]HostKey{ed, ec, rsa}},
		{"another port", "[10.99.0.1]:2222 " + ed.String() + "\n[10.99.0.1]:2222 " + ec384.String() + "\n", []HostKey{ed, ec384}},
		{"legacy rsa only", "10.99.0.1 " + rsa.String() + "\n", []HostKey{rsa}},
		{"comments and banners", "# 10.99.0.1:22 SSH-2.0-OpenSSH_9.6\n\n10.99.0.1 " + ed.String() + "\n", []HostKey{ed}},
		{"duplicates", "10.99.0.1 " + ed.String() + "\n10.99.0.1 " + ed.String() + "\n", []HostKey{ed}},
		{"garbage lines", "garbage\nconnect: Connection refused\n10.99.0.1 ssh-ed25519 notbase64!!\n10.99.0.1 ssh-rsa " + ed.Blob +
			"\n10.99.0.1 ssh-dss " + ed.Blob + "\n10.99.0.1 " + ec.String() + "\n", []HostKey{ec}},
		{"CRLF", "10.99.0.1 " + ed.String() + "\r\n", []HostKey{ed}},
	}
	for _, c := range cases {
		if got := ParseKeyscan([]byte(c.out)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestKeyscanCmd(t *testing.T) {
	for _, c := range []struct {
		addr   string
		port   int
		legacy bool
		want   string
	}{
		{"10.99.0.1", 22, false, "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 10.99.0.1"},
		{"10.99.0.1", 0, false, "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 10.99.0.1"},
		{"2001:db8::7", 830, false, "ssh-keyscan -T 5 -p 830 -t ed25519,ecdsa,rsa 2001:db8::7"},
		{"10.99.0.1", 22, true, "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa,ssh-rsa 10.99.0.1"},
	} {
		if got := strings.Join(KeyscanCmd(c.addr, c.port, c.legacy).Argv(), " "); got != c.want {
			t.Errorf("%s:%d legacy=%v: %q", c.addr, c.port, c.legacy, got)
		}
	}
}

func TestScan(t *testing.T) {
	ed, rsa := testKey(t, "ed25519"), testKey(t, "rsa")
	ctx := context.Background()
	r := &fake.Runner{Strict: true}
	r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: []byte("10.99.0.1 " + rsa.String() + "\n10.99.0.1 " + ed.String() + "\n"),
		Stderr: []byte("# 10.99.0.1:22 SSH-2.0-OpenSSH_9.6\n")})
	keys, err := Scan(ctx, r, "10.99.0.1", 22, false)
	if err != nil || !reflect.DeepEqual(keys, []HostKey{ed, rsa}) {
		t.Errorf("scan: %v %v", keys, err)
	}
	if !r.Called("ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519,ecdsa,rsa", "10.99.0.1") {
		t.Errorf("argv %q", r.Argvs())
	}
	// No answer: ssh-keyscan prints nothing (its exit status says nothing).
	for _, code := range []int{0, 1} {
		r = &fake.Runner{Strict: true}
		r.On([]string{"ssh-keyscan"}, execx.Result{Code: code, Stderr: []byte("10.99.0.1: Connection timed out\n")})
		if _, err := Scan(ctx, r, "10.99.0.1", 22, false); !errors.Is(err, ErrNoAnswer) {
			t.Errorf("no answer (exit %d): %v", code, err)
		}
	}
	// Not installed: an error that says where it comes from.
	r = &fake.Runner{}
	r.Missing("ssh-keyscan")
	if _, err := Scan(ctx, r, "10.99.0.1", 22, false); err == nil || errors.Is(err, ErrNoAnswer) || !strings.Contains(err.Error(), "openssh-client") {
		t.Errorf("missing: %v", err)
	}
}

func TestMatchFingerprint(t *testing.T) {
	ed, ec := testKey(t, "ed25519"), testKey(t, "ecdsa")
	if k, ok := MatchFingerprint([]HostKey{ed, ec}, ec.Fingerprint()); !ok || k != ec {
		t.Error("match")
	}
	if _, ok := MatchFingerprint([]HostKey{ed}, ec.Fingerprint()); ok {
		t.Error("no match")
	}
	for _, fp := range []string{"SHA256:short", "MD5:" + strings.Repeat("A", 43), "SHA256:" + strings.Repeat("A", 44), ""} {
		if ValidFingerprint(fp) {
			t.Errorf("%q valid", fp)
		}
	}
}

func TestCompareAndHostPinAction(t *testing.T) {
	ed, ec, rsa := testKey(t, "ed25519"), testKey(t, "ecdsa"), testKey(t, "rsa")
	ec2 := testKey(t, "ecdsa384") // another ecdsa key
	pin := func(ks ...HostKey) []string { return KeyStrings(ks) }
	for _, c := range []struct {
		name    string
		pinned  []string
		offered []HostKey
		changed bool
		added   []HostKey
		missing []HostKey
		action  PinAction
	}{
		{"nothing pinned", nil, []HostKey{ed, rsa}, false, []HostKey{ed, rsa}, nil, PinFirst},
		{"same", pin(ed, rsa), []HostKey{ed, rsa}, false, nil, nil, PinKeep},
		{"a new type", pin(ed), []HostKey{ed, ec}, false, []HostKey{ec}, nil, PinAdded},
		{"a type dropped", pin(ed, rsa), []HostKey{ed}, false, nil, []HostKey{rsa}, PinKeep},
		{"replaced key", pin(ed), []HostKey{testKeyWithBlob(t, ed, rsa)}, true, nil, []HostKey{ed}, PinChanged},
		{"nothing pinned offered", pin(ed), []HostKey{ec, rsa}, true, []HostKey{ec, rsa}, []HostKey{ed}, PinChanged},
		{"one of two changed", pin(ed, ec), []HostKey{ed, {Type: ec.Type, Blob: ec2.Blob}}, true, nil, []HostKey{ec}, PinChanged},
	} {
		got := Compare(c.pinned, c.offered)
		if got.Changed != c.changed || !reflect.DeepEqual(got.Added, c.added) || !reflect.DeepEqual(got.Missing, c.missing) {
			t.Errorf("%s: %+v", c.name, got)
		}
		if a := HostPinAction(c.pinned, c.offered); a != c.action {
			t.Errorf("%s: action %d, want %d", c.name, a, c.action)
		}
	}
	if !Compare(pin(ed), []HostKey{ed}).Same() || Compare(pin(ed), []HostKey{ed, ec}).Same() {
		t.Error("Same")
	}
	if !KeysEqual(pin(rsa, ed), []HostKey{ed, rsa}) || KeysEqual(pin(ed), []HostKey{ed, rsa}) {
		t.Error("KeysEqual ignores order only")
	}
}

// testKeyWithBlob is a key of k's type holding another blob (not a valid
// key of that type, which Compare does not look at).
func testKeyWithBlob(t *testing.T, k, from HostKey) HostKey {
	t.Helper()
	return HostKey{Type: k.Type, Blob: from.Blob}
}

func TestVerifyHint(t *testing.T) {
	for v, want := range map[string]string{
		"cisco": "show ip ssh", "juniper": "show system ssh host-key", "wti": "verify on the device console",
		"linux": "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", "other": "fingerprint of its ssh host key", "": "fingerprint of its ssh host key",
	} {
		if !strings.Contains(VerifyHint(v), want) {
			t.Errorf("%q: %q", v, VerifyHint(v))
		}
	}
}

func TestHostKeyDisplay(t *testing.T) {
	ed, rsa := testKey(t, "ed25519"), testKey(t, "rsa")
	if got := ed.Display(); got != "ED25519  "+ed.Fingerprint() {
		t.Errorf("display %q", got)
	}
	if got := rsa.Display(); got != "RSA      "+rsa.Fingerprint() {
		t.Errorf("display %q", got)
	}
	if got := Displays([]HostKey{ed, rsa}); got != "ED25519 "+ed.Fingerprint()+", RSA "+rsa.Fingerprint() {
		t.Errorf("displays %q", got)
	}
}

func TestParsePubKeys(t *testing.T) {
	ed, rsa := testKey(t, "ed25519"), testKey(t, "rsa")
	out := "ssh-rsa " + rsa.Blob + " root@web1\n# comment\ncat: /etc/ssh/ssh_host_dsa_key.pub: Permission denied\n\n" +
		"ssh-ed25519 " + ed.Blob + "\nssh-dss AAAAB3NzaC1kc3M= old\nssh-ed25519 " + ed.Blob + " dup\n"
	if got := ParsePubKeys([]byte(out)); !reflect.DeepEqual(got, []HostKey{ed, rsa}) {
		t.Errorf("%v", got)
	}
	if got := ParsePubKeys(nil); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}

// Only keys both reads hold are pinned; a type with different keys is a
// conflict; a type one read lacks is reported on its side.
func TestCrossCheckKeys(t *testing.T) {
	ed, ec, rsa := testKey(t, "ed25519"), testKey(t, "ecdsa"), testKey(t, "rsa")
	other := testKeyWithBlob(t, ed, rsa)
	for _, c := range []struct {
		name                 string
		session, scan        []HostKey
		agreed, only1, only2 []HostKey
		conflict             bool
	}{
		{"match", []HostKey{rsa, ed}, []HostKey{ed, rsa}, []HostKey{ed, rsa}, nil, nil, false},
		{"partial overlap", []HostKey{ed, ec}, []HostKey{ed, rsa}, []HostKey{ed}, []HostKey{ec}, []HostKey{rsa}, false},
		{"mismatch", []HostKey{ed, rsa}, []HostKey{other, rsa}, []HostKey{rsa}, nil, nil, true},
		{"nothing shared", []HostKey{ec}, []HostKey{rsa}, nil, []HostKey{ec}, []HostKey{rsa}, false},
	} {
		got := CrossCheckKeys(c.session, c.scan)
		if !reflect.DeepEqual(got.Agreed, c.agreed) || !reflect.DeepEqual(got.OnlySession, c.only1) ||
			!reflect.DeepEqual(got.OnlyScan, c.only2) || got.Conflict != c.conflict {
			t.Errorf("%s: %+v", c.name, got)
		}
		if c.conflict && (!reflect.DeepEqual(got.Session, []HostKey{ed}) || !reflect.DeepEqual(got.Scan, []HostKey{other})) {
			t.Errorf("%s: sides %+v", c.name, got)
		}
	}
}
