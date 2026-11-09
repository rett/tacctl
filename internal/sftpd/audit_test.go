package sftpd

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// 6. The audit events.

// describe lists "op path [-> to] [bytes] [!error]" for the events, in order.
func describe(ev []Event) []string {
	var out []string
	for _, e := range ev {
		s := e.Op + " " + e.Path
		if e.To != "" {
			s += " -> " + e.To
		}
		if e.Bytes != 0 {
			s += " " + strconv.FormatInt(e.Bytes, 10)
		}
		if e.Err != nil {
			s += " !" + e.Err.Error()
		}
		out = append(out, s)
	}
	return out
}

func wantEvents(t *testing.T, e *env, want ...string) {
	t.Helper()
	got := describe(e.rec.all())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("events:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestAuditUploadDownload(t *testing.T) {
	e := newEnv(t, nil)
	e.put("/up.txt", "hello world")
	wantEvents(t, e, "upload /up.txt 11")
	e.rec.reset()

	if got, err := e.get("up.txt"); err != nil || got != "hello world" {
		t.Fatal(got, err)
	}
	wantEvents(t, e, "download /up.txt 11")
	e.rec.reset()

	// An empty upload and a partial download are events too.
	e.put("empty", "")
	f, err := e.client.Open("up.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(make([]byte, 5), 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	wantEvents(t, e, "upload /empty", "download /up.txt 5")
	e.rec.reset()

	// A read-write handle audits both directions.
	h, err := e.client.OpenFile("rw", os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("abc"), 0)
	_, _ = h.ReadAt(make([]byte, 2), 0)
	_ = h.Close()
	wantEvents(t, e, "upload /rw 3", "download /rw 2")
}

func TestAuditUploadCutShortByTheSession(t *testing.T) {
	e := newEnv(t, nil)
	f, err := e.client.OpenFile("cut", os.O_WRONLY|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("12345"), 0); err != nil {
		t.Fatal(err)
	}
	// The client goes away without closing the handle.
	if err := e.stop(); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("Serve: %v", err)
	}
	got := e.rec.all()
	if len(got) != 1 || got[0].Op != "upload" || got[0].Bytes != 5 || got[0].Err == nil {
		t.Errorf("events = %v, want one upload of 5 bytes with the error", describe(got))
	}
}

func TestAuditChanges(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.client.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	e.rec.reset()
	if err := e.client.Mkdir("d/e"); err != nil {
		t.Fatal(err)
	}
	e.write("d/f", "x")
	if err := e.client.Rename("d/f", "d/g"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.PosixRename("d/g", "h"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Chmod("h", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Chtimes("h", time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Remove("h"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.RemoveDirectory("d/e"); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, e,
		"mkdir /d/e",
		"rename /d/f -> /d/g",
		"rename /d/g -> /h",
		"setstat /h",
		"setstat /h",
		"delete /h",
		"delete /d/e",
	)
}

func TestAuditFailedChanges(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.client.Remove("missing")
	_ = e.client.Mkdir("a/b")
	// The client retries a failed Remove as RemoveDirectory: two deletes.
	ev := e.rec.all()
	if len(ev) != 3 || ev[0].Op != "delete" || ev[1].Op != "delete" || ev[2].Op != "mkdir" {
		t.Fatalf("events = %v, want two deletes and a mkdir", describe(ev))
	}
	for _, x := range ev {
		if x.Err == nil {
			t.Errorf("event %+v has no error", x)
		}
	}
}

func TestAuditRefusals(t *testing.T) {
	e := sshEnv(t)
	_ = e.client.Remove("a/../.ssh/authorized_keys")
	_ = e.client.Rename("plain", ".ssh/x")
	_ = e.client.Symlink("plain", "l")
	_ = e.client.Link("plain", "h")
	_ = e.client.Chown("plain", 1, 1)
	_ = e.client.RemoveDirectory("/")
	if err := os.Symlink("plain", e.home+"/lnk"); err != nil {
		t.Fatal(err)
	}
	_, _ = e.client.Open("lnk")
	wantEvents(t, e,
		"refused /.ssh/authorized_keys !.ssh", // the client retries a Remove as RemoveDirectory
		"refused /.ssh/authorized_keys !.ssh",
		"refused /plain -> /.ssh/x !.ssh",
		"refused /plain -> /l !symlink",
		"refused /plain -> /h !unsupported",
		"refused /plain !unsupported",
		"refused / !outside the home",
		"refused /lnk !symlink",
	)
	for _, ev := range e.rec.all() {
		if ev.Op != "refused" || ev.Err == nil {
			t.Errorf("event %+v is not a refusal with a reason", ev)
		}
	}
}

func TestAuditNotForReadOnlyRequests(t *testing.T) {
	e := newEnv(t, nil)
	e.write("d/f", "x")
	_, _ = e.client.Stat("d/f")
	_, _ = e.client.Lstat("d")
	_, _ = e.client.ReadDir("d")
	_, _ = e.client.ReadDir("/")
	_, _ = e.client.RealPath("d/..")
	_, _ = e.client.Getwd()
	_, _ = e.client.Stat("missing")
	f, _ := e.client.Open("d/f")
	_, _ = f.Stat()
	wantEvents(t, e) // the download is audited at close, not before
	_ = f.Close()
	wantEvents(t, e, "download /d/f")
}

func TestAuditNilIsFine(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Audit = nil })
	e.put("f", "x")
	_ = e.client.Remove("../.ssh/x")
	_ = e.client.Symlink("f", "l")
	if _, err := e.get("f"); err != nil {
		t.Fatal(err)
	}
}

// 7. Hostile input.

func TestHostilePaths(t *testing.T) {
	e := newEnv(t, nil)
	long := strings.Repeat("a", 300)
	huge := strings.Repeat("d/", 3000)
	paths := []string{
		"a\x00b", "\x00", ".ssh\x00", "d/\x00/x", long, "d/" + long, huge, "/" + strings.Repeat("a/", 3000) + "x",
		"d/../" + long,
	}
	for _, p := range paths {
		check := func(op string, err error) {
			t.Helper()
			if err == nil {
				t.Errorf("%s %.20q succeeded", op, p)
			}
		}
		_, err := e.client.Stat(p)
		check("stat", err)
		_, err = e.client.Lstat(p)
		check("lstat", err)
		_, err = e.client.ReadDir(p)
		check("list", err)
		_, err = e.client.Open(p)
		check("open", err)
		_, err = e.client.Create(p)
		check("create", err)
		check("mkdir", e.client.Mkdir(p))
		check("remove", e.client.Remove(p))
		check("rename", e.client.Rename(p, "x"))
		check("rename to", e.client.Rename("plain", p))
		check("chmod", e.client.Chmod(p, 0o600))
	}
	// The session is alive and the home untouched.
	if _, err := e.client.RealPath("."); err != nil {
		t.Errorf("session after hostile paths: %v", err)
	}
	ents, _ := os.ReadDir(e.home)
	if len(ents) != 0 {
		t.Errorf("home has %d entries after the hostile paths", len(ents))
	}
	if _, err := e.client.RealPath("a\x00b"); err == nil {
		t.Error("RealPath of a path with a NUL succeeded")
	}
	for _, r := range refusals(e.rec.all()) {
		if r != "bad path" {
			t.Errorf("refusal %q, want bad path", r)
		}
	}
}

func TestHostileLegalNames(t *testing.T) {
	e := newEnv(t, nil)
	// Names that are odd but legal work like any other.
	for _, n := range []string{"\xff\xfe", "a\nb", "-rf", " ", "..."} {
		e.put(n, "x")
		if got, err := e.get(n); err != nil || got != "x" {
			t.Errorf("name %q: %q, %v", n, got, err)
		}
	}
}

func TestHandlerPanicBecomesAStatus(t *testing.T) {
	s := &server{cfg: Config{}}
	f := func() (err error) {
		defer s.guard(&err, &sftp.Request{Filepath: "/x"})
		panic("boom")
	}
	err := f()
	if !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Errorf("panic became %v, want a failure status", err)
	}
}

func TestBadAttributesGetAStatus(t *testing.T) {
	// A setstat whose attributes are cut short (as the library parses
	// them to nil) is a bad request, not a panic.
	e := newEnv(t, nil)
	e.write("f", "x")
	s := &server{home: mustHome(t, e.home), cfg: Config{}}
	r := &sftp.Request{Method: "Setstat", Filepath: "/f", Flags: 0x4 /* permissions */, Attrs: []byte{1}}
	err := s.Filecmd(r)
	if err == nil || reasonOf(err) != reasonBadPath {
		t.Errorf("setstat with short attributes = %v", err)
	}
}

func mustHome(t *testing.T, dir string) *home {
	t.Helper()
	h, err := openHome(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.close)
	return h
}

func TestServeWritesNothingToStdoutOrStderr(t *testing.T) {
	// Not parallel: it swaps the process's os.Stdout and os.Stderr.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	e := newEnv(t, nil)
	e.write(".ssh/k", "x")
	e.put("f", "x")
	_, _ = e.get("f")
	_, _ = e.client.Stat(".ssh/k")
	_ = e.client.Symlink("f", "l")
	_, _ = e.client.Open("a\x00b")
	_ = e.stop()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	b, _ := io.ReadAll(r)
	if len(b) != 0 {
		t.Errorf("Serve wrote %q", b)
	}
}

func TestServeEndsWhenTheClientDoes(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.stop(); err != nil {
		t.Errorf("Serve after a clean close = %v, want nil", err)
	}
}

// IsSubsystemCommand.

func TestIsSubsystemCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"/usr/lib/openssh/sftp-server", true},
		{"/usr/libexec/sftp-server", true},
		{"internal-sftp", true},
		{"/usr/lib/openssh/internal-sftp", true},
		{"sftp-server", true},
		{"sftp-server -l INFO", true},
		{"/usr/lib/openssh/sftp-server -f AUTH -l VERBOSE", true},
		{"  sftp-server", true},
		{"sftp-server\t-e", true},
		{"/opt/my dir/sftp-server", false}, // the first word is /opt/my
		{"'/opt/my dir/sftp-server'", false},
		{"sftp-server; id", false},
		{"sftp-server -l INFO; id", false},
		{"sftp-server && id", false},
		{"sftp-server | cat", false},
		{"sftp-server `id`", false},
		{"sftp-server $(id)", false},
		{"sftp-server > /x", false},
		{"sftp-server\nid", false},
		{"sftp-server;id", false},
		{"", false},
		{"   ", false},
		{"scp -t x", false},
		{"scp -f /etc/passwd", false},
		{"rsync --server", false},
		{"sftp", false},
		{"my-sftp-server", false},
		{"sftp-server2", false},
		{"/usr/lib/sftp-server/", false},
		{"/usr/lib/sftp-server/x", false},
		{"internal-sftp-x", false},
		{"SFTP-SERVER", false},
		{"id sftp-server", false},
		{"sh -c sftp-server", false},
	}
	for _, c := range cases {
		if got := IsSubsystemCommand(c.cmd); got != c.want {
			t.Errorf("IsSubsystemCommand(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}
