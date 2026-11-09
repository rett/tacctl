package cli

// The console's file transfer through consoleMain's seam (runConsoleWith):
// the sftp subsystem as a '-c' string, served by internal/sftpd on the
// process's streams, with a real pkg/sftp client on the other end of two
// pipes (console_sftp.go).

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/pkg/sftp"

	"github.com/rett/tacctl/internal/console"
)

// protocolTap keeps what the console wrote to its standard output, so that a
// test can check it is nothing but SFTP packets.
type protocolTap struct {
	mu  sync.Mutex
	buf bytes.Buffer
	w   *io.PipeWriter
}

func (p *protocolTap) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.buf.Write(b)
	p.mu.Unlock()
	return p.w.Write(b)
}

func (p *protocolTap) Close() error { return p.w.Close() }

func (p *protocolTap) bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf.Bytes()...)
}

// wholePackets reports whether b is a sequence of SFTP packets (a 4-byte
// length, then that many bytes) with nothing before, between or after them.
func wholePackets(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 4 {
			return false
		}
		n := int(binary.BigEndian.Uint32(b))
		if n < 1 || len(b) < 4+n {
			return false
		}
		b = b[4+n:]
	}
	return true
}

// sftpRig is the console serving the sftp subsystem to a client.
type sftpRig struct {
	t      *testing.T
	h      *harness
	home   string
	dotenv string // the directory $HOME names, which is not the home
	tap    *protocolTap
	in     *io.PipeWriter
	out    *io.PipeReader
	done   chan int
}

// startSFTP starts the console with '-c <line>' on pipes, as the account
// carol, whose home in the account database is home (not $HOME). policy is
// the answer of the root side ("": sudo fails).
func startSFTP(t *testing.T, policy, line string) *sftpRig {
	t.Helper()
	return startSFTPCtx(t, context.Background(), policy, line)
}

func startSFTPCtx(t *testing.T, ctx context.Context, policy, line string) *sftpRig {
	t.Helper()
	return startSFTPSetup(t, ctx, policy, line, nil)
}

// startSFTPSetup is startSFTPCtx with a change to the harness (its fake
// commands) before the console starts.
func startSFTPSetup(t *testing.T, ctx context.Context, policy, line string, setup func(*harness)) *sftpRig {
	t.Helper()
	parallel(t)
	h, _ := consoleHarness(t, "", "carol tac-users tac-readonly", policy, "-c", line)
	if setup != nil {
		setup(h)
	}
	r := &sftpRig{t: t, h: h, home: t.TempDir(), done: make(chan int, 1)}
	r.dotenv = h.app.Env.Get("HOME")
	h.hooks.homeOfUID = func(uid int) (string, error) {
		if uid != 1000 {
			return "", errors.New("unexpected uid")
		}
		return r.home, nil
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	r.in, r.out = inW, outR
	r.tap = &protocolTap{w: outW}
	h.app.Stdin = inR
	h.app.Out.Stdout = r.tap
	go func() {
		r.done <- exitCode(runConsoleWith(ctx, h.app, BuildInfo{Version: "0.2.1-test"}, []string{"-c", line}, h.hooks), h.app.Out)
	}()
	return r
}

// client connects an SFTP client to the console.
func (r *sftpRig) client() *sftp.Client {
	r.t.Helper()
	c, err := sftp.NewClientPipe(r.out, r.in)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// finish closes the client, waits for the console to end and gives its status.
func (r *sftpRig) finish(c *sftp.Client) int {
	r.t.Helper()
	if c != nil {
		_ = c.Close()
	}
	return <-r.done
}

func sftpPolicy(ft console.FileTransfer) string {
	return strings.TrimSuffix(consoleTestPolicy, "\n") + console.FileTransferFields(ft) + "\n"
}

func put(t *testing.T, c *sftp.Client, name, content string) error {
	t.Helper()
	f, err := c.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(content)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func get(t *testing.T, c *sftp.Client, name string) (string, error) {
	t.Helper()
	f, err := c.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	return string(b), err
}

func TestConsoleSFTPServes(t *testing.T) {
	r := startSFTP(t, sftpPolicy(console.FileTransfer{Enabled: true}), "/usr/lib/openssh/sftp-server")
	// The home of the account database is the root, not $HOME's directory.
	if err := os.WriteFile(filepath.Join(r.home, "existing.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dotenv, "decoy.txt"), []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := r.client()
	infos, err := c.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	if !slices.Equal(names, []string{"existing.txt"}) {
		t.Errorf("the root lists %q, want the passwd home's files only", names)
	}
	if err := put(t, c, "up.txt", "hello"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(r.home, "up.txt")); err != nil || string(b) != "hello" {
		t.Errorf("the uploaded file: %q %v", b, err)
	}
	if got, err := get(t, c, "/existing.txt"); err != nil || got != "old" {
		t.Errorf("download: %q %v", got, err)
	}
	if err := c.Mkdir("d"); err != nil {
		t.Errorf("mkdir: %v", err)
	}
	if err := c.Rename("up.txt", "d/moved.txt"); err != nil {
		t.Errorf("rename: %v", err)
	}
	if err := c.Remove("existing.txt"); err != nil {
		t.Errorf("remove: %v", err)
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d, stderr %q", status, r.h.err.String())
	}
	if r.h.err.String() != "" {
		t.Errorf("stderr %q", r.h.err.String())
	}
	if !wholePackets(r.tap.bytes()) {
		t.Errorf("standard output holds more than SFTP packets: %q", r.tap.bytes())
	}
	// Run as the user: no sudo for the transfer but the policy question.
	if n := r.h.runner.Count("sudo"); n != 1 {
		t.Errorf("sudo ran %d times, want the policy question only: %q", n, r.h.runner.Argvs())
	}
	log := consoleLog(r.h.runner)
	want := []string{
		"auth.info console start session=",
		"auth.info console sftp start session=",
		"auth.info console sftp upload session=",
		"auth.info console sftp download session=",
		"auth.info console sftp mkdir session=",
		"auth.info console sftp rename session=",
		"auth.info console sftp delete session=",
		"auth.info console sftp end session=",
		"auth.info console end session=",
	}
	if len(log) != len(want) {
		t.Fatalf("log:\n%s", strings.Join(log, "\n"))
	}
	for i, w := range want {
		if !strings.HasPrefix(log[i], w) {
			t.Errorf("log[%d] = %q, want it to start with %q", i, log[i], w)
		}
	}
	for _, frag := range []struct {
		i    int
		text string
	}{
		{0, "mode=sftp"},
		{1, " user=carol tier=readonly from=192.0.2.9 home=" + `"` + r.home + `"` + " quota=unlimited rate=off"},
		{2, ` user=carol tier=readonly path="/up.txt" bytes=5`},
		{3, ` user=carol tier=readonly path="/existing.txt" bytes=3`},
		{4, ` user=carol tier=readonly path="/d"`},
		{5, ` user=carol tier=readonly path="/up.txt" to="/d/moved.txt"`},
		{6, ` user=carol tier=readonly path="/existing.txt"`},
		{7, " up=5 down=3 ops=5 refused=0"},
		{8, " user=carol reason=sftp lines=5 status=0"},
	} {
		if !strings.Contains(log[frag.i], frag.text) {
			t.Errorf("log[%d] = %q, want it to contain %q", frag.i, log[frag.i], frag.text)
		}
	}
}

// logger failing is not a reason to stop a transfer: the warning is on
// standard error, standard output stays the protocol's, and the transfer
// goes on unaudited (the same as for a command of the console).
func TestConsoleSFTPLoggerDownKeepsStdoutTheProtocol(t *testing.T) {
	r := startSFTPSetup(t, context.Background(), sftpPolicy(console.FileTransfer{Enabled: true}), "internal-sftp",
		func(h *harness) { h.runner.Missing("logger") })
	c := r.client()
	if err := put(t, c, "up.txt", "hello"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got, err := get(t, c, "up.txt"); err != nil || got != "hello" {
		t.Errorf("download: %q %v", got, err)
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d, stderr %q", status, r.h.err.String())
	}
	if b, err := os.ReadFile(filepath.Join(r.home, "up.txt")); err != nil || string(b) != "hello" {
		t.Errorf("the uploaded file: %q %v", b, err)
	}
	if !wholePackets(r.tap.bytes()) {
		t.Errorf("standard output holds more than SFTP packets: %q", r.tap.bytes())
	}
	if !strings.Contains(r.h.err.String(), "The audit line was not written (logger: not found); the command continues.") {
		t.Errorf("stderr lacks the warning: %q", r.h.err.String())
	}
}

func TestConsoleSFTPQuotaRateAndTheStartLine(t *testing.T) {
	r := startSFTP(t, sftpPolicy(console.FileTransfer{Enabled: true, Quota: 100, Rate: 1 << 30}), "internal-sftp")
	c := r.client()
	if err := put(t, c, "ok", strings.Repeat("a", 100)); err != nil {
		t.Fatalf("a file that fits: %v", err)
	}
	err := put(t, c, "over", "b")
	if err == nil || !strings.Contains(err.Error(), "quota") {
		t.Errorf("one byte over the quota: %v", err)
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d", status)
	}
	log := strings.Join(consoleLog(r.h.runner), "\n")
	for _, want := range []string{
		" quota=100 rate=1G",
		"auth.warning console sftp DENY session=",
		` user=carol tier=readonly path="/over"`, " reason=quota",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	if !strings.Contains(log, "refused=1") {
		t.Errorf("the end line counts no refusal:\n%s", log)
	}
}

func TestConsoleSFTPRefusesSSHAndAudits(t *testing.T) {
	r := startSFTP(t, sftpPolicy(console.FileTransfer{Enabled: true}), "sftp-server")
	if err := os.Mkdir(filepath.Join(r.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.home, ".ssh", "authorized_keys"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := r.client()
	infos, err := c.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, fi := range infos {
		if fi.Name() == ".ssh" {
			t.Error(".ssh is listed")
		}
	}
	if _, err := get(t, c, ".ssh/authorized_keys"); err == nil {
		t.Error(".ssh/authorized_keys was read")
	}
	if err := put(t, c, ".ssh/authorized_keys", "mine"); err == nil {
		t.Error(".ssh/authorized_keys was written")
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d", status)
	}
	if b, _ := os.ReadFile(filepath.Join(r.home, ".ssh", "authorized_keys")); string(b) != "key" {
		t.Errorf("authorized_keys is %q", b)
	}
	log := strings.Join(consoleLog(r.h.runner), "\n")
	if !strings.Contains(log, `auth.warning console sftp DENY session=`) || !strings.Contains(log, ` tier=readonly path="/.ssh/authorized_keys"`) ||
		!strings.Contains(log, "reason=.ssh") {
		t.Errorf("the refusals are not audited:\n%s", log)
	}
}

func TestConsoleSFTPAuditSanitisesNames(t *testing.T) {
	r := startSFTP(t, sftpPolicy(console.FileTransfer{Enabled: true}), "internal-sftp")
	c := r.client()
	evil := "a\nconsole sftp DENY session=forged\x1b[31m\"x"
	if err := put(t, c, evil, "x"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	long := strings.Repeat("n", 230)
	if err := c.Mkdir(long); err != nil {
		t.Fatalf("mkdir of a long name: %v", err)
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d", status)
	}
	var upload, mkdir string
	for _, l := range consoleLog(r.h.runner) {
		switch {
		case strings.Contains(l, "console sftp upload"):
			upload = l
		case strings.Contains(l, "console sftp mkdir"):
			mkdir = l
		}
	}
	if !strings.Contains(upload, ` path="/a\nconsole sftp DENY session=forged\x1b[31m\"x" bytes=1`) {
		t.Errorf("the upload line is not escaped: %q", upload)
	}
	for _, l := range consoleLog(r.h.runner) {
		if strings.ContainsAny(l, "\n\r\x1b") {
			t.Errorf("a control character reached the log: %q", l)
		}
	}
	if !strings.Contains(mkdir, ` path="/`+strings.Repeat("n", console.NameMax-1)+`"... `) && !strings.HasSuffix(mkdir, ` path="/`+strings.Repeat("n", console.NameMax-1)+`"...`) {
		t.Errorf("the long name is not cut: %q", mkdir)
	}
}

// A failed request on a hostile long name is one line that keeps its
// trailing fields (logger cuts a line at 1 KiB), and the error text does not
// repeat the path.
func TestConsoleSFTPAuditLineOfAFailedLongNameFits(t *testing.T) {
	r := startSFTP(t, sftpPolicy(console.FileTransfer{Enabled: true}), "internal-sftp")
	c := r.client()
	hostile := "/" + strings.Repeat("\x01", 100) + strings.Repeat("n", 100)
	if err := c.Remove(hostile); err == nil {
		t.Fatal("removing a file that is not there worked")
	}
	if err := c.Rename(hostile, hostile+"2"); err == nil {
		t.Fatal("renaming a file that is not there worked")
	}
	if status := r.finish(c); status != 0 {
		t.Fatalf("status %d", status)
	}
	seen := 0
	for _, l := range consoleLog(r.h.runner) {
		if !strings.Contains(l, "console sftp delete") && !strings.Contains(l, "console sftp rename") {
			continue
		}
		seen++
		if len(l) >= 1000 {
			t.Errorf("%d bytes: %s", len(l), l)
		}
		_, errField, ok := strings.Cut(l, " error=")
		if !ok || strings.Contains(errField, `\x01`) || strings.Contains(errField, "nnnn") {
			t.Errorf("the error repeats the path, or is lost: %s", l)
		}
	}
	if seen < 2 {
		t.Errorf("%d event lines, want at least 2", seen)
	}
}

func TestErrTextDropsThePath(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("plain"), "plain"},
		{&fs.PathError{Op: "open", Path: "/home/user/x", Err: syscall.ENOENT}, "open: no such file or directory"},
		{&os.LinkError{Op: "rename", Old: "/a", New: "/b", Err: syscall.EEXIST}, "rename: file exists"},
		{fmt.Errorf("wrapped: %w", &fs.PathError{Op: "unlink", Path: "/x", Err: syscall.EACCES}), "unlink: permission denied"},
	} {
		if got := errText(c.err); got != c.want {
			t.Errorf("errText(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestConsoleSFTPPolicyOff(t *testing.T) {
	for name, policy := range map[string]string{
		"not enabled": consoleTestPolicy,
		"quota only":  strings.TrimSuffix(consoleTestPolicy, "\n") + " ft_quota=100 ft_rate=100\n",
		"enabled: no": strings.TrimSuffix(consoleTestPolicy, "\n") + " file_transfer=no\n",
	} {
		for _, line := range []string{"/usr/lib/openssh/sftp-server", "internal-sftp", "sftp-server -l INFO"} {
			h, run := consoleHarness(t, "", "carol tac-users tac-readonly", policy, "-c", line)
			if code := exitCode(run(), h.app.Out); code != console.RefusedStatus {
				t.Errorf("%s %q: status %d", name, line, code)
			}
			if h.err.String() != console.SFTPOffText+"\n" || h.out.String() != "" {
				t.Errorf("%s %q: stderr %q stdout %q", name, line, h.err.String(), h.out.String())
			}
			log := consoleLog(h.runner)
			if len(log) != 3 || !strings.Contains(log[0], "mode=sftp") ||
				!strings.Contains(log[1], "auth.warning console DENY session=") || !strings.HasSuffix(log[1], " user=carol reason=file-transfer subsystem=sftp") ||
				!strings.HasSuffix(log[2], "reason=sftp lines=0 status=126") {
				t.Errorf("%s %q: log %q", name, line, log)
			}
		}
	}
	// The text says what is off and who can switch it on.
	for _, want := range []string{"not enabled", "administrator", "switch it on"} {
		if !strings.Contains(console.SFTPOffText, want) {
			t.Errorf("the refusal does not say %q: %q", want, console.SFTPOffText)
		}
	}
}

func TestConsoleSFTPHeldToAPasswordChange(t *testing.T) {
	pol := strings.TrimSuffix(sftpPolicy(console.FileTransfer{Enabled: true}), "\n") + " password_change=yes\n"
	h, run := consoleHarness(t, "", "carol tac-users tac-readonly", pol, "-c", "internal-sftp")
	if code := exitCode(run(), h.app.Out); code != console.RefusedStatus {
		t.Errorf("status %d", code)
	}
	if h.err.String() != sftpPasswordText+"\n" || h.out.String() != "" {
		t.Errorf("stderr %q stdout %q", h.err.String(), h.out.String())
	}
	log := consoleLog(h.runner)
	if len(log) != 3 || !strings.HasSuffix(log[1], " reason=password-change subsystem=sftp") {
		t.Errorf("log %q", log)
	}
}

func TestConsoleSFTPNoHome(t *testing.T) {
	policy := sftpPolicy(console.FileTransfer{Enabled: true})
	for name, home := range map[string]func(int) (string, error){
		"no account":    func(int) (string, error) { return "", errors.New("no such user") },
		"relative home": func(int) (string, error) { return "home/carol", nil },
		"empty home":    func(int) (string, error) { return "", nil },
	} {
		h, run := consoleHarness(t, "", "carol tac-users tac-readonly", policy, "-c", "internal-sftp")
		h.hooks.homeOfUID = home
		if code := exitCode(run(), h.app.Out); code != 1 {
			t.Errorf("%s: status %d", name, code)
		}
		if !strings.Contains(h.err.String(), "cannot find the home directory") || h.out.String() != "" {
			t.Errorf("%s: stderr %q stdout %q", name, h.err.String(), h.out.String())
		}
		if log := consoleLog(h.runner); len(log) != 3 || !strings.HasSuffix(log[1], " reason=home subsystem=sftp") {
			t.Errorf("%s: log %q", name, log)
		}
	}
}

// Everything but the subsystem keeps the old refusal, whatever the policy.
func TestConsoleSFTPOnlyTheSubsystem(t *testing.T) {
	policy := sftpPolicy(console.FileTransfer{Enabled: true})
	for _, line := range []string{
		"scp -f x", "scp -t .", "scp -O -f x", "rsync --server -e.LsfxC . .", "bash", "sh -c id", "/bin/sh",
		"internal-sftp; id", "sftp-server && id", "/usr/lib/openssh/sftp-server `id`", "$(sftp-server)", "sftp", "sftp-server\nid",
	} {
		h, run := consoleHarness(t, "", "carol tac-users tac-readonly", policy, "-c", line)
		if code := exitCode(run(), h.app.Out); code != console.RefusedStatus {
			t.Errorf("%q: status %d", line, code)
		}
		if h.err.String() != console.RefusedText+"\n" || h.out.String() != "" {
			t.Errorf("%q: stderr %q stdout %q", line, h.err.String(), h.out.String())
		}
		if h.runner.Count("sudo") != 0 {
			t.Errorf("%q: ran %q", line, h.runner.Argvs())
		}
		if log := consoleLog(h.runner); len(log) != 3 || !strings.Contains(log[0], "mode=command") ||
			!strings.Contains(log[1], " reason=command ") {
			t.Errorf("%q: log %q", line, log)
		}
	}
	// The refusal's text no longer says that file transfer is unavailable, and
	// says what the console does serve.
	if strings.Contains(console.RefusedText, "not available") || !strings.Contains(console.RefusedText, "SFTP") ||
		!strings.Contains(console.RefusedText, "OpenSSH 9") {
		t.Errorf("RefusedText: %q", console.RefusedText)
	}
}

// A client that ends the connection ends the session with status 0, the one
// that sends nothing keeps it open (the console's idle time is no part of it),
// and a protocol error is a short line on standard error and status 1.
func TestConsoleSFTPEnds(t *testing.T) {
	policy := sftpPolicy(console.FileTransfer{Enabled: true})
	t.Run("closed input", func(t *testing.T) {
		r := startSFTP(t, policy, "internal-sftp")
		if status := r.finish(r.client()); status != 0 {
			t.Errorf("status %d, stderr %q", status, r.h.err.String())
		}
		if log := consoleLog(r.h.runner); len(log) != 4 || !strings.HasSuffix(log[2], " up=0 down=0 ops=0 refused=0") {
			t.Errorf("log %q", log)
		}
	})
	t.Run("silent client", func(t *testing.T) {
		r := startSFTP(t, policy, "internal-sftp")
		select {
		case status := <-r.done:
			t.Fatalf("the session ended by itself with status %d", status)
		default:
		}
		_ = r.in.Close()
		if status := <-r.done; status != 0 {
			t.Errorf("status %d, stderr %q", status, r.h.err.String())
		}
	})
	t.Run("protocol error", func(t *testing.T) {
		r := startSFTP(t, policy, "internal-sftp")
		// a packet that claims more bytes than arrive, then the end
		go func() {
			_, _ = r.in.Write([]byte{0, 0, 0, 40, 1, 0, 0})
			_ = r.in.Close()
		}()
		go func() { _, _ = io.Copy(io.Discard, r.out) }()
		status := <-r.done
		if status != console.SFTPStatus {
			t.Errorf("status %d", status)
		}
		msg := r.h.err.String()
		if !strings.HasPrefix(msg, "tacctl-console: sftp: ") || strings.Count(msg, "\n") != 1 || len(msg) > 260 {
			t.Errorf("stderr %q", msg)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		r := startSFTPCtx(t, ctx, policy, "internal-sftp")
		c := r.client()
		if _, err := c.ReadDir("/"); err != nil {
			t.Fatal(err)
		}
		// a signal (sshd closing the session) ends the transfer like a closed connection
		cancel()
		if status := <-r.done; status != 0 {
			t.Errorf("status %d, stderr %q", status, r.h.err.String())
		}
	})
}

// Without an answer from the root side the transfer is not served: a caller
// who is no superuser is held as the console holds every line, a superuser
// (who is never held) is told the policy could not be read.
func TestConsoleSFTPWithoutAPolicyAnswer(t *testing.T) {
	for _, c := range []struct {
		groups, text, why string
	}{
		{"carol tac-users tac-readonly", sftpUnknownText, "password-change"},
		{"carol tac-users", sftpUnknownText, "password-change"},
		{"carol tac-users tac-superuser", sftpPolicyText, "policy"},
	} {
		h, run := consoleHarness(t, "", c.groups, "", "-c", "internal-sftp")
		if code := exitCode(run(), h.app.Out); code != console.RefusedStatus {
			t.Errorf("%s: status %d", c.groups, code)
		}
		if h.err.String() != c.text+"\n" || h.out.String() != "" {
			t.Errorf("%s: stderr %q stdout %q", c.groups, h.err.String(), h.out.String())
		}
		if log := consoleLog(h.runner); len(log) != 3 || !strings.HasSuffix(log[1], " reason="+c.why+" subsystem=sftp") {
			t.Errorf("%s: log %q", c.groups, log)
		}
	}
}
