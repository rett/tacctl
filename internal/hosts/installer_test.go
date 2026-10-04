package hosts

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/ui"
)

// The installer goldens (tests/fixtures/golden/linux-install.*.sh.head) are
// the header 0.1.16 writes, up to the TAC_USERS line, for the inputs of
// tests/integration/config_linux.bats (scope lab with the placeholder
// secret, alice superuser and bob readonly, server 192.0.2.10, the stand-in
// tarball "not really a tarball\n") at 2026-10-03T12:00:00Z. They were
// made with the bash of the 0.1.16 tag, never with this package:
//
//	tacctl config linux script --scope lab --server 192.0.2.10 -o x.sh            (tacplus)
//	tacctl config linux script --scope lab --server 192.0.2.10 --method radius ... (radius)
//	tacctl host enroll web1 --scope lab --server 192.0.2.10                        (prebuilt)
//
// with 'date' stubbed to that instant, and for the prebuilt one a cached
// module "not really a module\n" for docker.io/library/ubuntu:noble.

var goldenWhen = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const goldenUsers = "alice:superuser:20000\nbob:readonly:20001"

func golden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fixtureFiles writes the stand-in tarball and a cached prebuilt module.
func fixtureFiles(t *testing.T) (tarball, prebuilt string) {
	t.Helper()
	d := t.TempDir()
	tarball = filepath.Join(d, "pam_tacplus-1.7.0.tar.gz")
	if err := os.WriteFile(tarball, []byte("not really a tarball\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prebuilt = filepath.Join(d, "builds", "ubuntu-noble-x86_64")
	if err := os.MkdirAll(prebuilt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prebuilt+"/module.tar.gz", []byte("not really a module\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := "image=docker.io/library/ubuntu:noble\ndigest=sha256:feedface\narch=x86_64\nsource=x\nbuilt=2026-10-01T00:00:00Z\n"
	if err := os.WriteFile(prebuilt+"/info", []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	return tarball, prebuilt
}

func gnuBase64(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 0 {
		n := min(76, len(enc))
		b.WriteString(enc[:n] + "\n")
		enc = enc[n:]
	}
	return b.String()
}

// The installer is 0.1.16's byte for byte: the header against the golden,
// then client-install.sh and the base64 sections.
func TestScriptMatchesBashGolden(t *testing.T) {
	tarball, prebuilt := fixtureFiles(t)
	base := Script{Scope: "lab", Server: "192.0.2.10", Port: "49", Secret: "0123456789abcdef0123456789abcdef",
		Users: goldenUsers, Generated: goldenWhen.In(time.FixedZone("x", 7200))}
	for _, tc := range []struct {
		golden string
		edit   func(*Script)
		tail   string
	}{
		{"linux-install.tacplus.sh.head", func(s *Script) { s.Method, s.Tarball = Tacplus, tarball },
			"__TARBALL__\n" + gnuBase64([]byte("not really a tarball\n"))},
		{"linux-install.radius.sh.head", func(s *Script) { s.Method, s.Port, s.AcctPort = Radius, "1812", "1813" }, ""},
		{"linux-install.prebuilt.sh.head", func(s *Script) { s.Method, s.Tarball, s.Prebuilt = Tacplus, tarball, prebuilt },
			"__TARBALL__\n" + gnuBase64([]byte("not really a tarball\n")) +
				"__PREBUILT__\n" + gnuBase64([]byte("not really a module\n"))},
	} {
		s := base
		tc.edit(&s)
		want := golden(t, tc.golden)
		if got := s.Header(); got != want {
			t.Errorf("%s: header differs\n--- got\n%s--- want\n%s", tc.golden, got, want)
		}
		full := want + string(assets.LinuxInstallScript) + tc.tail
		if got := string(s.Bytes()); got != full {
			t.Errorf("%s: script differs from header + client-install.sh + sections", tc.golden)
		}
	}
}

func TestBase64WrapsAt76(t *testing.T) {
	d := t.TempDir()
	data := bytes.Repeat([]byte{0xab, 0x01, 0x7f}, 100)
	p := filepath.Join(d, "f")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	writeBase64(&b, p)
	if b.String() != gnuBase64(data) {
		t.Fatalf("base64: %q", b.String())
	}
	for _, l := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")[:3] {
		if len(l) != 76 {
			t.Fatalf("line of %d", len(l))
		}
	}
	b.Reset()
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeBase64(&b, p)
	if b.Len() != 0 {
		t.Fatalf("empty file: %q", b.String())
	}
}

func testEnv(t *testing.T) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	d := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(d, "tmp"))
	if err := os.MkdirAll(filepath.Join(d, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "linux"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	e := &Env{
		Paths:    Paths{Dir: filepath.Join(d, "linux"), UIDs: filepath.Join(d, "linux-uids"), Hosts: filepath.Join(d, "linux-hosts")},
		Out:      ui.Output{Stdout: &out, Stderr: &errb},
		Now:      func() time.Time { return goldenWhen },
		TTY:      func() bool { return false },
		StdinTTY: func() bool { return false },
		Machine:  func() string { return "x86_64" },
	}
	return e, &out, &errb
}

func TestWriteScriptChecksAndPorts(t *testing.T) {
	e, _, errb := testEnv(t)
	out := filepath.Join(t.TempDir(), "x.sh")
	rows := []string{"alice|15", "bob|1", "Dave|1", "root|15", "nopriv|", "sink|x"}
	req := ScriptRequest{Scope: "lab", Server: "192.0.2.10", Method: Tacplus, Output: out,
		Secret: "0123456789abcdef0123456789abcdef", Rows: rows}

	// No tarball: refused before anything else.
	if _, err := e.WriteScript(req); !errors.Is(err, ErrFailed) || !strings.Contains(errb.String(), "tacctl config linux build") {
		t.Fatalf("no tarball: %v %q", err, errb.String())
	}
	if err := os.WriteFile(e.Paths.Tarball(), []byte("not really a tarball\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "REPLACE_WITH_SHARED_SECRET", "has space", "semi;colon"} {
		errb.Reset()
		r := req
		r.Secret = bad
		if _, err := e.WriteScript(r); !errors.Is(err, ErrFailed) || !strings.Contains(errb.String(), "Regenerate it: tacctl scope secret lab generate") {
			t.Errorf("secret %q: %v %q", bad, err, errb.String())
		}
	}
	errb.Reset()
	r := req
	r.Method = Radius
	r.Secret = "has space"
	if _, err := e.WriteScript(r); err == nil || !strings.Contains(errb.String(), "in pam_radius_auth's server file") {
		t.Errorf("radius secret: %q", errb.String())
	}
	errb.Reset()
	r = req
	r.Server = "x;reboot"
	if _, err := e.WriteScript(r); err == nil || !strings.Contains(errb.String(), "Invalid server address 'x;reboot'") {
		t.Errorf("server: %q", errb.String())
	}

	errb.Reset()
	r = req
	r.Listeners = []backend.Listener{{Name: "default", Address: "192.0.2.10:4949"}, {Name: "mgmt", Address: "127.0.0.1:5050"}}
	res, err := e.WriteScript(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != "4949" || res.Users != "alice:superuser:20000\nbob:readonly:20001" {
		t.Errorf("result %+v", res)
	}
	for _, w := range []string{"Skipping 'Dave': not a valid Linux account name", "Skipping 'nopriv': its group has no priv-lvl", "Skipping 'sink'"} {
		if !strings.Contains(errb.String(), w) {
			t.Errorf("stderr lacks %q: %q", w, errb.String())
		}
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "TAC_PORT=4949\n") || !strings.Contains(string(data), "\n__TARBALL__\n") {
		t.Errorf("script lacks the port or tarball")
	}

	// radius: the auth and acct listeners, no tarball.
	r = req
	r.Method = Radius
	r.Listeners = []backend.Listener{{Name: "auth", Address: ":11812"}, {Name: "acct", Address: "[::]:11899"}}
	if res, err = e.WriteScript(r); err != nil || res.Port != "11812" {
		t.Fatalf("radius: %+v %v", res, err)
	}
	data, _ = os.ReadFile(out)
	if !strings.Contains(string(data), "TAC_ACCT_PORT=11899\n") || !bytes.HasSuffix(data, assets.LinuxInstallScript) {
		t.Errorf("radius script")
	}
	r.Listeners = nil
	if res, _ = e.WriteScript(r); res.Port != "1812" {
		t.Errorf("radius default port %q", res.Port)
	}
	// Accounts only: no tarball either.
	r = req
	r.AccountsOnly = true
	if _, err = e.WriteScript(r); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(out)
	if !bytes.HasSuffix(data, assets.LinuxInstallScript) || strings.Contains(string(data), "\nTARBALL_SHA256=") {
		t.Errorf("accounts-only carries the tarball")
	}
}

func TestWriteScriptOutputLikeInstall(t *testing.T) {
	e, _, errb := testEnv(t)
	if err := os.WriteFile(e.Paths.Tarball(), []byte("t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := ScriptRequest{Scope: "lab", Server: "192.0.2.10", Secret: "abcdefabcdefabcdef"}
	// A directory receives the file under the temp name; a missing
	// directory is install's complaint, and not a failure.
	dir := t.TempDir()
	req.Output = dir
	if _, err := e.WriteScript(req); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "tmp.") || len(ents[0].Name()) != 14 {
		t.Errorf("dir output: %v", ents)
	}
	req.Output = filepath.Join(dir, "no", "such.sh")
	if _, err := e.WriteScript(req); err != nil {
		t.Fatal(err)
	}
	want := "install: cannot create regular file '" + req.Output + "': No such file or directory\n"
	if errb.String() != want {
		t.Errorf("stderr %q, want %q", errb.String(), want)
	}
	// A file that exists is replaced (a new file, mode 0600).
	f := filepath.Join(dir, "old.sh")
	if err := os.WriteFile(f, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	req.Output = f
	if _, err := e.WriteScript(req); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 || st.Size() < 100 {
		t.Errorf("replaced: %v", st)
	}
}

func TestWriteRemoveScript(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "remove.sh")
	if err := WriteRemoveScript(p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !bytes.Equal(data, assets.LinuxRemoveScript) {
		t.Error("content")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode())
	}
	if err := WriteRemoveScript(d); err != nil {
		t.Fatal(err)
	}
	if !isRegular(filepath.Join(d, "client-remove.sh")) {
		t.Error("into a directory")
	}
	var ie *InstallError
	if err := WriteRemoveScript(filepath.Join(d, "x", "y")); !errors.As(err, &ie) ||
		ie.Msg != "install: cannot create regular file '"+filepath.Join(d, "x", "y")+"': No such file or directory" {
		t.Errorf("missing dir: %v", err)
	}
	p2 := filepath.Join(d, "own")
	if err := WriteRemoveScriptTo(p2); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p2); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestTempFiles(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	f, err := TempFile()
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 || !strings.HasPrefix(filepath.Base(f), "tmp.") || len(filepath.Base(f)) != 14 {
		t.Errorf("temp file %s %v", f, st.Mode())
	}
	d, err := TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d); !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Errorf("temp dir %v", st.Mode())
	}
}
