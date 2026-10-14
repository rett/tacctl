package fakedev

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const baseSet = `# a capture header comment
set system host-name sw-lab-1
set system login class eng permissions view
set system login user alice class super-user
set system login user alice uid 2001
set system tacplus-server 192.0.2.10 secret "$9$abc"
set system authentication-order tacplus
set system authentication-order password
set snmp community public authorization read-only
set firewall family inet filter MGMT term a from source-address 192.0.2.0/24
set firewall family inet filter MGMT term a then accept
set firewall family inet filter MGMT term b then discard
`

var promptRE = regexp.MustCompile(`\S+@\S+[>#%] $`)

// jclient is a minimal interactive ssh client for the model's tests.
type jclient struct {
	t    *testing.T
	conn *ssh.Client
	sess *ssh.Session
	in   io.WriteCloser
	out  io.Reader
	all  string
}

func dialJunos(t *testing.T, srv *Server, user, pw string) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", srv.Addr(), &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.Password(pw)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
}

// shell logs in and reads up to the first prompt, returning that text too.
func shell(t *testing.T, srv *Server, user, pw string) (*jclient, string) {
	t.Helper()
	conn, err := dialJunos(t, srv, user, pw)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	c := &jclient{t: t, conn: conn, sess: sess, in: in, out: out}
	return c, c.read()
}

// read reads until a prompt ends the text; it fails the test after a few
// seconds without one.
func (c *jclient) read() string {
	c.t.Helper()
	done := make(chan string, 1)
	go func() {
		var got []byte
		b := make([]byte, 4096)
		for {
			n, err := c.out.Read(b)
			got = append(got, b[:n]...)
			if promptRE.Match(bytes.ReplaceAll(got, []byte("\r"), nil)) || err != nil {
				done <- string(got)
				return
			}
		}
	}()
	select {
	case s := <-done:
		s = strings.ReplaceAll(s, "\r", "")
		c.all += s
		return s
	case <-time.After(5 * time.Second):
		c.t.Fatal("no prompt")
		return ""
	}
}

// send types a command and returns what it printed, the echo and the
// prompt block dropped; the prompt that followed is in c.prompt().
func (c *jclient) send(cmd string) string {
	c.t.Helper()
	if _, err := io.WriteString(c.in, cmd+"\n"); err != nil {
		c.t.Fatal(err)
	}
	return c.strip(cmd, c.read())
}

func (c *jclient) strip(cmd, raw string) string {
	lines := strings.Split(raw, "\n")
	// the echo (with its trailing space)
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == cmd {
		lines = lines[1:]
	}
	// the prompt, the [edit] / {master} lines and the blank before them
	for len(lines) > 0 {
		l := lines[len(lines)-1]
		if l == "" || promptRE.MatchString(l) || strings.HasPrefix(l, "{") || strings.HasPrefix(l, "[edit") {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	// "{master:0}[edit]" collapses into one line handled above
	return strings.Join(lines, "\n")
}

func (c *jclient) lastPrompt() string {
	ls := strings.Split(c.all, "\n")
	return ls[len(ls)-1]
}

func newJunos(t *testing.T, files map[string]string, opts ...Option) (*Server, string, *FakeClock) {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["config.set"]; !ok {
		files["config.set"] = baseSet
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clk := NewFakeClock(time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC))
	opts = append([]Option{WithClock(clk)}, opts...)
	srv := New(dir, opts...)
	t.Cleanup(srv.Stop)
	return srv, dir, clk
}

func execOut(t *testing.T, srv *Server, user, pw, cmd string) (string, error) {
	t.Helper()
	conn, err := dialJunos(t, srv, user, pw)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	defer func() { _ = conn.Close() }()
	s, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Output(cmd)
	return string(out), err
}

func mustContain(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, got)
		}
	}
}

func TestJunosPromptAndModes(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, first := shell(t, srv, DefaultUser, DefaultPassword)
	if first != "\n{master:0}\ngotest@sw-lab-1> " {
		t.Errorf("first prompt %q", first)
	}
	raw := ""
	if _, err := io.WriteString(c.in, "configure\n"); err != nil {
		t.Fatal(err)
	}
	raw = c.read()
	if raw != "configure \nEntering configuration mode\n\n{master:0}[edit]\ngotest@sw-lab-1# " {
		t.Errorf("configure: %q", raw)
	}
	c.send("edit system login")
	if !strings.HasSuffix(c.lastPrompt(), "gotest@sw-lab-1# ") {
		t.Errorf("prompt %q", c.lastPrompt())
	}
	if !strings.Contains(c.all, "{master:0}[edit system login]\n") {
		t.Errorf("no nested edit line:\n%s", c.all)
	}
	c.send("top")
	if _, err := io.WriteString(c.in, "exit\n"); err != nil {
		t.Fatal(err)
	}
	raw = c.read()
	if raw != "exit \nExiting configuration mode\n\n{master:0}\ngotest@sw-lab-1> " {
		t.Errorf("exit: %q", raw)
	}
}

func TestJunosSwitchOffAndPlainEcho(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"switch": "off\n", "echo.plain": ""})
	c, first := shell(t, srv, DefaultUser, DefaultPassword)
	if first != "\ngotest@sw-lab-1> " {
		t.Errorf("first prompt %q", first)
	}
	if _, err := io.WriteString(c.in, "show cli authorization\n"); err != nil {
		t.Fatal(err)
	}
	raw := c.read()
	if !strings.HasPrefix(raw, "show cli authorization\n") {
		t.Errorf("echo: %q", raw)
	}
}

// an empty line echoes as nothing, not as a lone space: the prompt is
// simply reprinted, as on a device
func TestJunosEmptyLineEchoesNothing(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if _, err := io.WriteString(c.in, "configure\n"); err != nil {
		t.Fatal(err)
	}
	c.read()
	if _, err := io.WriteString(c.in, "\n"); err != nil {
		t.Fatal(err)
	}
	raw := c.read()
	if raw != "\n{master:0}[edit]\ngotest@sw-lab-1# " {
		t.Errorf("empty line: %q", raw)
	}
}

func TestJunosConfirmedCommitExpiresOnTheClock(t *testing.T) {
	srv, dir, clk := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	if out := c.send("set system login idle-timeout 30"); out != "" {
		t.Errorf("set printed %q", out)
	}
	c.send("set system tacplus-server 192.0.2.10 secret plaintext-secret")
	c.send("delete snmp community public")
	cmp := c.send("show | compare")
	mustContain(t, "compare", cmp,
		"[edit system login]\n+   idle-timeout 30;\n",
		"[edit system tacplus-server 192.0.2.10]\n",
		"-   secret \"$9$abc\"; ## SECRET-DATA\n",
		"+   secret \"$9$", "[edit]\n-   snmp {\n-       community public {\n-           authorization read-only;\n-       }\n-   }\n")
	if strings.Contains(cmp, "plaintext-secret") {
		t.Errorf("the compare shows the secret:\n%s", cmp)
	}
	if got := c.send("commit check"); got != "configuration check succeeds" {
		t.Errorf("commit check: %q", got)
	}
	if strings.Contains(srv.Committed(), "idle-timeout") {
		t.Error("a commit check committed")
	}
	if got := c.send(`commit confirmed 2 comment "tacctl apply x"`); got != "commit confirmed will be rolled back in 2 minutes\ncommit complete" {
		t.Errorf("commit confirmed: %q", got)
	}
	if !strings.Contains(srv.Committed(), "set system login idle-timeout 30\n") {
		t.Error("not committed")
	}
	until, ok := srv.PendingUntil()
	if !ok || !until.Equal(clk.Now().Add(2*time.Minute)) {
		t.Errorf("pending until %v %v", until, ok)
	}
	// the history, over an exec channel of another connection
	h, err := execOut(t, srv, DefaultUser, DefaultPassword, "show system commit")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "0   2026-10-12 02:00:00 UTC by gotest via cli commit confirmed, rollback in 2mins\n    tacctl apply x\n1   ") {
		t.Errorf("history:\n%s", h)
	}
	// the session is closed: the timer is not
	c.send("exit")
	_ = c.conn.Close()
	clk.Advance(119 * time.Second)
	if _, ok := srv.PendingUntil(); !ok {
		t.Fatal("rolled back early")
	}
	clk.Advance(2 * time.Second)
	if _, ok := srv.PendingUntil(); ok {
		t.Fatal("still pending after the window")
	}
	if got := srv.Committed(); got != parseSetText(baseSet).setText() {
		t.Errorf("not rolled back:\n%s", got)
	}
	hist := srv.History()
	if len(hist) != 3 || hist[0].User != "root" || hist[0].Via != "other" || hist[1].RollbackIn != 2 {
		t.Errorf("history %+v", hist)
	}
	b, err := os.ReadFile(filepath.Join(dir, "committed.set"))
	if err != nil || string(b) != srv.Committed() {
		t.Errorf("committed.set %q %v", b, err)
	}
	// the rollback compare after the expiry: 1 -> 0 undoes the change
	out, err := execOut(t, srv, DefaultUser, DefaultPassword, "show system rollback compare 1 0 | no-more")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "rollback compare", out, "[edit system login]\n-   idle-timeout 30;\n", "[edit]\n+   snmp {\n")
}

func TestJunosCommitConfirms(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	c.send("commit confirmed 5")
	if got := c.send(`commit comment "confirm"`); got != "commit complete" {
		t.Errorf("commit: %q", got)
	}
	if _, ok := srv.PendingUntil(); ok {
		t.Error("still pending")
	}
	h := srv.History()
	if h[0].Comment != "confirm" || h[0].RollbackIn != 0 || h[1].RollbackIn != 5 {
		t.Errorf("history %+v", h)
	}
	clk.Advance(time.Hour)
	if !strings.Contains(srv.Committed(), "idle-timeout 30") {
		t.Error("rolled back after the confirm")
	}
}

func TestJunosCommitCheckConfirmsAPendingCommit(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure")
	c.send("set system login idle-timeout 30")
	c.send("commit confirmed 5")
	other, _ := shell(t, srv, DefaultUser, DefaultPassword)
	other.send("configure")
	if got := other.send("commit check"); got != "configuration check succeeds" {
		t.Errorf("commit check: %q", got)
	}
	if _, ok := srv.PendingUntil(); ok {
		t.Error("a stranger's commit check did not confirm (the plan's rule)")
	}
	if h := srv.History(); h[0].RollbackIn != 0 || h[1].RollbackIn != 5 {
		t.Errorf("history %+v", h)
	}
}

func TestJunosExclusiveKeepsAStrangersCommitCheckOut(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	c.send("commit confirmed 5")
	other, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if got := other.send("configure"); !strings.HasPrefix(got, "error: configuration database locked by:") {
		t.Errorf("configure under the lock: %q", got)
	}
	if _, ok := srv.PendingUntil(); !ok {
		t.Error("the pending commit was confirmed by a session the lock keeps out")
	}
}

func TestJunosRollbackCancelsAPendingCommit(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	c.send("commit confirmed 5")
	if got := c.send("rollback 1"); got != "load complete" {
		t.Errorf("rollback 1: %q", got)
	}
	if cmp := c.send("show | compare"); cmp != "[edit system login]\n-   idle-timeout 30;" {
		t.Errorf("compare after rollback 1:\n%s", cmp)
	}
	c.send(`commit comment "cancel"`)
	if _, ok := srv.PendingUntil(); ok {
		t.Error("still pending after rollback 1 and commit")
	}
	if strings.Contains(srv.Committed(), "idle-timeout") {
		t.Error("the change is still there")
	}
	clk.Advance(time.Hour)
	c.send("rollback 0")
	if got := c.send("show | compare"); got != "" {
		t.Errorf("compare after rollback 0: %q", got)
	}
}

func TestJunosExclusiveLockAndDirtyShared(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	a, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if got := a.send("configure exclusive"); got != "Entering configuration mode" {
		t.Errorf("configure exclusive: %q", got)
	}
	if srv.ExclusiveHolder() != DefaultUser {
		t.Errorf("holder %q", srv.ExclusiveHolder())
	}
	b, _ := shell(t, srv, DefaultUser, DefaultPassword)
	got := b.send("configure exclusive")
	mustContain(t, "second exclusive", got, "error: configuration database locked by:", DefaultUser, "exclusive [edit]")
	if got := b.send("configure"); !strings.HasPrefix(got, "error: configuration database locked by:") {
		t.Errorf("shared configure under the lock: %q", got)
	}
	a.send("set system login idle-timeout 30")
	a.send("exit")
	if srv.ExclusiveHolder() != "" {
		t.Error("the lock outlived exit")
	}
	if strings.Contains(srv.Candidate(), "idle-timeout") {
		t.Error("the exclusive session's staged change survived exit")
	}
	// a shared session's staged change dirties the candidate
	b.send("configure")
	b.send("set system login idle-timeout 30")
	a2, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if got := a2.send("configure exclusive"); got != "error: configuration database modified" {
		t.Errorf("exclusive over staged: %q", got)
	}
	got = a2.send("configure")
	mustContain(t, "users", got, "Users currently editing the configuration:", "[edit]")
	a2.send("show | compare")
	if got := a2.send("show | compare"); !strings.Contains(got, "idle-timeout 30") {
		t.Errorf("the shared candidate is shared: %q", got)
	}
	a2.send("exit")
	// closing the session that staged it does not discard a shared candidate
	if !strings.Contains(srv.Candidate(), "idle-timeout 30") {
		t.Error("the shared candidate went with the session")
	}
}

func TestJunosKnobHeldByAndDirtyShared(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{
		"exclusive.held-by": "carol\n",
		"dirty.shared":      "user dave\nset system login idle-timeout 5\n",
	})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	got := c.send("configure exclusive")
	mustContain(t, "held-by", got, "locked by:", "carol")
	if srv.ExclusiveHolder() != "carol" {
		t.Errorf("holder %q", srv.ExclusiveHolder())
	}
	if !strings.Contains(srv.Candidate(), "idle-timeout 5") {
		t.Error("the stranger's staged change is not in the candidate")
	}
}

func TestJunosDirtySharedGate(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"dirty.shared": "user dave\nset system login idle-timeout 5\n"})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	got := c.send("configure")
	mustContain(t, "gate", got, "Entering configuration mode", "Users currently editing the configuration:", "dave")
	cmp := c.send("show | compare | no-more")
	mustContain(t, "gate compare", cmp, "+   idle-timeout 5;")
	got = c.send("exit")
	mustContain(t, "gate exit", got, "The configuration has been changed but not committed", "Exiting configuration mode")
	c2, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if got := c2.send("configure exclusive"); got != "error: configuration database modified" {
		t.Errorf("exclusive: %q", got)
	}
}

func TestJunosStatementAnswers(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{
		"load.errors":  "set system login idle-timeout => error: syntax error, expecting <class-name>\n",
		"version-gate": "set system ntp threshold\nset system login class eng idle-timeout => check\n",
		"check.errors": "set snmp location => error: snmp location too long\n",
	})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure")
	if got := c.send("set system login idle-timeout 30"); got != "error: syntax error, expecting <class-name>" {
		t.Errorf("load error: %q", got)
	}
	if got := c.send("set system ntp threshold 1"); !strings.Contains(got, "syntax error.") {
		t.Errorf("gate: %q", got)
	}
	if got := c.send("show | compare"); got != "" {
		t.Errorf("a refused statement was applied: %q", got)
	}
	if got := c.send("delete system domain-name"); got != "warning: statement not found" {
		t.Errorf("delete absent: %q", got)
	}
	if got := c.send("show | compare"); got != "" {
		t.Errorf("a delete of an absent node changed the candidate: %q", got)
	}
	c.send("set system login class eng idle-timeout 5")
	if got := c.send("commit check"); !strings.Contains(got, "syntax error.") || !strings.Contains(got, "error: configuration check-out failed") {
		t.Errorf("check gate: %q", got)
	}
	c.send("rollback 0")
	c.send("set snmp location Rack-2")
	got := c.send("commit confirmed 3")
	if got != "error: snmp location too long\nerror: configuration check-out failed" {
		t.Errorf("check.errors: %q", got)
	}
	if _, ok := srv.PendingUntil(); ok || strings.Contains(srv.Committed(), "Rack-2") {
		t.Error("a failed check committed")
	}
}

func TestJunosPrivateAndNoConfirmed(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"private.no-confirmed": ""})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure private")
	c.send("set system login idle-timeout 30")
	got := c.send("commit confirmed 2")
	if !strings.Contains(got, "commit confirmed not supported for private") {
		t.Errorf("private confirmed: %q", got)
	}
	// private changes are isolated from the shared candidate
	if strings.Contains(srv.Candidate(), "idle-timeout") {
		t.Error("a private change reached the shared candidate")
	}
	if got := c.send("commit"); got != "commit complete" {
		t.Errorf("private commit: %q", got)
	}
	if !strings.Contains(srv.Committed(), "idle-timeout 30") {
		t.Error("private commit not applied")
	}
}

func TestJunosUIDAssignedAtCommit(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login user bob class super-user")
	cmp := c.send("show | compare")
	if strings.Contains(cmp, "uid") {
		t.Errorf("the candidate has a uid:\n%s", cmp)
	}
	c.send("commit")
	out, _ := execOut(t, srv, DefaultUser, DefaultPassword, "show system rollback compare 1 0")
	mustContain(t, "landed compare", out, "uid 2000;")
}

func TestJunosInsertAndOrder(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set firewall family inet filter MGMT term c then accept")
	if got := c.send("insert firewall family inet filter MGMT term c before term a"); got != "" {
		t.Errorf("insert: %q", got)
	}
	got := c.send("show firewall family inet filter MGMT")
	if i, j := strings.Index(got, "term c"), strings.Index(got, "term a"); i < 0 || j < 0 || i > j {
		t.Errorf("order after insert:\n%s", got)
	}
	got = c.send("show | display set | no-more")
	mustContain(t, "display set", got, "set system authentication-order tacplus\nset system authentication-order password\n")
	if got := c.send("show system authentication-order"); got != "authentication-order [ tacplus password ];" {
		t.Errorf("leaf list: %q", got)
	}
}

func TestJunosLoginsAndClasses(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{
		"local": "ops-local secret-1 read-only\n",
		"class": "super-user\n" + DefaultUser + " super-user\n",
	})
	c, _ := shell(t, srv, "ops-local", "secret-1")
	got := c.send("show cli authorization")
	mustContain(t, "authorization", got, "class: read-only", "view-configuration")
	if got := c.send("configure"); !strings.Contains(got, "unknown command.") {
		t.Errorf("a read-only class configured: %q", got)
	}
	if _, err := dialJunos(t, srv, "ops-local", "wrong"); err == nil {
		t.Error("a wrong local password was accepted")
	}
	if _, err := dialJunos(t, srv, "root", "x"); err == nil {
		t.Error("root with no root file was accepted")
	}
}

func TestJunosRootCsh(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"root": "rootpw\n", "banner": "Authorized use only\n"})
	c, first := shell(t, srv, "root", "rootpw")
	if !strings.HasPrefix(first, "Authorized use only\n") || !strings.HasSuffix(first, "root@sw-lab-1% ") {
		t.Errorf("csh login: %q", first)
	}
	if got := c.send("show version"); got != "show: Command not found." {
		t.Errorf("csh: %q", got)
	}
	got := c.send("cli")
	if !strings.HasSuffix(c.lastPrompt(), "root@sw-lab-1> ") {
		t.Errorf("cli prompt %q (%q)", c.lastPrompt(), got)
	}
	c.send("quit")
	if !strings.HasSuffix(c.lastPrompt(), "root@sw-lab-1% ") {
		t.Errorf("back in csh: %q", c.lastPrompt())
	}
	// the exec form starts the CLI at once
	conn, err := dialJunos(t, srv, "root", "rootpw")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	s, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	var out bytes.Buffer
	s.Stdout = &out
	if err := s.Start(`sh -c 'PATH=/usr/sbin:/usr/bin; exec cli'`); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(in, "show cli authorization\nquit\n")
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "exec cli", out.String(), "root@sw-lab-1> ", "class: super-user")
}

func TestJunosVerifyFailRefusesLoginsWhilePending(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{"verify.fail": "\n"})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	c.send("commit confirmed 2")
	if _, err := dialJunos(t, srv, DefaultUser, DefaultPassword); err == nil {
		t.Fatal("a login was accepted under verify.fail")
	}
	// the session that holds the lock still works, and confirming ends it
	if got := c.send("commit"); got != "commit complete" {
		t.Errorf("confirm: %q", got)
	}
	conn, err := dialJunos(t, srv, DefaultUser, DefaultPassword)
	if err != nil {
		t.Fatalf("after the confirm: %v", err)
	}
	_ = conn.Close()
	_ = clk
}

func TestJunosCommitDropKeepsThePendingCommit(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{"commit.drop": ""})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	if _, err := io.WriteString(c.in, "commit confirmed 2\n"); err != nil {
		t.Fatal(err)
	}
	// the connection closes, with no answer
	done := make(chan error, 1)
	go func() { done <- c.sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was not dropped")
	}
	if _, ok := srv.PendingUntil(); !ok {
		t.Error("the confirmed commit was not applied")
	}
	if srv.ExclusiveHolder() != "" {
		t.Error("the lock outlived the connection")
	}
	clk.Advance(2 * time.Minute)
	if strings.Contains(srv.Committed(), "idle-timeout") {
		t.Error("not rolled back at expiry")
	}
}

func TestJunosSlowAnswersWaitOnTheClock(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{"slow": "show cli authorization => 30\n"})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if _, err := io.WriteString(c.in, "show cli authorization\n"); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		b := make([]byte, 1)
		var s []byte
		for !promptRE.Match(bytes.ReplaceAll(s, []byte("\r"), nil)) {
			n, err := c.out.Read(b)
			if err != nil {
				break
			}
			s = append(s, b[:n]...)
		}
		got <- string(s)
	}()
	// the answer waits on a timer of the clock until the clock moves
	for i := 0; clk.Timers() == 0; i++ {
		if i > 500 {
			t.Fatal("the slow answer set no timer")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case s := <-got:
		t.Fatalf("answered before the clock moved: %q", s)
	default:
	}
	clk.Advance(30 * time.Second)
	select {
	case s := <-got:
		mustContain(t, "slow answer", s, "class: super-user")
	case <-time.After(5 * time.Second):
		t.Fatal("no answer after the clock moved")
	}
}

func TestJunosDropKnob(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"drop": "show cli authorization\n"})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	if _, err := io.WriteString(c.in, "show cli authorization\n"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not dropped")
	}
}

func TestJunosReadsServeTheModel(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	out, err := execOut(t, srv, DefaultUser, DefaultPassword,
		"show configuration | display inheritance no-comments | display set | no-more")
	if err != nil {
		t.Fatal(err)
	}
	if out != parseSetText(baseSet).setText() {
		t.Errorf("read:\n%s", out)
	}
	out, _ = execOut(t, srv, DefaultUser, DefaultPassword, "show version")
	mustContain(t, "show version", out, "Hostname: sw-lab-1", "Model: ex4300-48mp", "Junos: 25.4R1.12")
	if _, err := execOut(t, srv, DefaultUser, DefaultPassword, "frobnicate"); err == nil {
		t.Error("an unknown command exits 0")
	}
}

func TestJunosBraceForm(t *testing.T) {
	c := parseSetText(baseSet)
	got := c.braceText(nil)
	want := `system {
    host-name sw-lab-1;
    login {
        class eng {
            permissions view;
        }
        user alice {
            class super-user;
            uid 2001;
        }
    }
    tacplus-server 192.0.2.10 {
        secret "$9$abc"; ## SECRET-DATA
    }
    authentication-order [ tacplus password ];
}
snmp {
    community public {
        authorization read-only;
    }
}
firewall {
    family inet {
        filter MGMT {
            term a {
                from {
                    source-address {
                        192.0.2.0/24;
                    }
                }
                then accept;
            }
            term b {
                then discard;
            }
        }
    }
}
`
	if got != want {
		t.Errorf("brace form:\n%s\nwant:\n%s", got, want)
	}
}
