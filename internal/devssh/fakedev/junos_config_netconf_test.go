package fakedev

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var xmlText = strings.NewReplacer("&#xA;", "\n", "&#39;", "'", "&#34;", `"`, "&lt;", "<", "&gt;", ">", "&amp;", "&")

// ncClient is a minimal NETCONF client (base:1.0 framing) for the model's
// tests.
type ncClient struct {
	t    *testing.T
	conn *ssh.Client
	sess *ssh.Session
	in   io.WriteCloser
	out  *bufio.Reader
	id   int
}

func netconfLogin(t *testing.T, srv *Server, user, pw string) *ncClient {
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
	if err := sess.RequestSubsystem("netconf"); err != nil {
		t.Fatalf("netconf subsystem: %v", err)
	}
	c := &ncClient{t: t, conn: conn, sess: sess, in: in, out: bufio.NewReader(out)}
	if h := c.read(); !strings.Contains(h, "<hello") {
		t.Fatalf("no hello: %q", h)
	}
	if _, err := io.WriteString(in, `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>`+
		`<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>`); err != nil {
		t.Fatal(err)
	}
	return c
}

// read reads up to the end-of-message marker.
func (c *ncClient) read() string {
	c.t.Helper()
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := c.out.ReadString('>')
			b.WriteString(line)
			if strings.HasSuffix(b.String(), "]]>]]>") {
				ch <- res{strings.TrimSuffix(b.String(), "]]>]]>"), nil}
				return
			}
			if err != nil {
				ch <- res{b.String(), err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		// the text entities of a reply read back as the text they stand for
		return xmlText.Replace(r.s)
	case <-time.After(5 * time.Second):
		c.t.Fatal("no NETCONF reply")
		return ""
	}
}

// rpc sends one RPC and returns the reply document.
func (c *ncClient) rpc(body string) string {
	c.t.Helper()
	c.id++
	msg := fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">%s</rpc>]]>]]>`, c.id, body)
	if _, err := io.WriteString(c.in, msg); err != nil {
		c.t.Fatal(err)
	}
	return c.read()
}

func (c *ncClient) open(mode string) string {
	c.t.Helper()
	body := "<open-configuration/>"
	if mode != "" {
		body = "<open-configuration><" + mode + "/></open-configuration>"
	}
	return c.rpc(body)
}

func (c *ncClient) load(lines ...string) string {
	c.t.Helper()
	return c.rpc(`<load-configuration action="set" format="text"><configuration-set>` +
		strings.Join(lines, "\n") + `</configuration-set></load-configuration>`)
}

func (c *ncClient) command(cmd string) string {
	c.t.Helper()
	return c.rpc("<command>" + cmd + "</command>")
}

func (c *ncClient) compare() string {
	c.t.Helper()
	return c.rpc(`<get-configuration compare="rollback" rollback="0" format="text"/>`)
}

// waitFor polls cond for a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasStmt(set, stmt string) bool {
	for _, l := range strings.Split(set, "\n") {
		if l == stmt {
			return true
		}
	}
	return false
}

func TestNetconfPrivateLoadCompareCommit(t *testing.T) {
	srv, dir, _ := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	if got := c.open("private"); !strings.Contains(got, "<ok/>") || strings.Contains(got, "rpc-error") {
		t.Errorf("open private: %s", got)
	}
	got := c.load("set system login idle-timeout 30", "set snmp community example-ro authorization read-only")
	mustContain(t, "load", got, "<load-configuration-results>", "<ok/>")
	if strings.Contains(got, "rpc-error") {
		t.Errorf("load errors: %s", got)
	}
	mustContain(t, "compare", c.compare(),
		"<configuration-information><configuration-output>", "[edit system login]", "+   idle-timeout 30;",
		"[edit snmp]\n+   community example-ro {")
	// a private session's change is invisible to the committed set
	if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Error("committed before the commit")
	}
	got = c.rpc("<commit-configuration><check/></commit-configuration>")
	mustContain(t, "check", got, "<commit-check-success/>")
	if len(srv.History()) != 1 {
		t.Errorf("a check left a history entry: %d", len(srv.History()))
	}
	got = c.rpc("<commit-configuration><log>tacctl apply 1 by alice</log></commit-configuration>")
	mustContain(t, "commit", got, "<commit-success/>")
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Errorf("not committed:\n%s", srv.Committed())
	}
	h := srv.History()
	if len(h) != 2 || h[0].Via != "netconf" || h[0].Comment != "tacctl apply 1 by alice" || h[0].User != DefaultUser {
		t.Errorf("history: %+v", h)
	}
	b, err := os.ReadFile(filepath.Join(dir, "committed.set"))
	if err != nil || !strings.Contains(string(b), "set system login idle-timeout 30\n") {
		t.Errorf("committed.set: %v\n%s", err, b)
	}
	// the candidate is the committed configuration again
	if got := c.compare(); strings.Contains(got, "idle-timeout") {
		t.Errorf("compare after commit: %s", got)
	}
	if got := c.rpc("<close-configuration/>"); !strings.Contains(got, "<ok/>") {
		t.Errorf("close: %s", got)
	}
}

func TestNetconfLoadIsNotAtomic(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{
		"load.errors": "set system login class bad => range: bad value\n",
	})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	got := c.load(
		"set system login idle-timeout 30",
		"set system login class bad permissions view",
		"delete snmp community nosuch",
		"frobnicate x",
		"set snmp community example-ro authorization read-only",
	)
	mustContain(t, "load", got, "<ok/>",
		"<error-severity>error</error-severity><error-path>[edit]</error-path><error-message>range: bad value</error-message>",
		"<bad-element>view</bad-element>",
		"<error-severity>warning</error-severity><error-path>[edit]</error-path><error-message>statement not found</error-message>",
		"<error-message>syntax error</error-message>")
	cmp := c.compare()
	mustContain(t, "compare", cmp, "+   idle-timeout 30;", "[edit snmp]\n+   community example-ro {")
	if strings.Contains(cmp, "class bad") {
		t.Errorf("the refused statement was applied:\n%s", cmp)
	}
}

func TestNetconfPrivateSessionsAreIsolated(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	a := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	b := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	a.open("private")
	b.open("private")
	a.load("set system login idle-timeout 30")
	if got := b.compare(); strings.Contains(got, "idle-timeout") {
		t.Errorf("b sees a's change: %s", got)
	}
	cand := b.rpc(`<get-configuration database="candidate" format="set"/>`)
	if strings.Contains(cand, "idle-timeout 30") {
		t.Errorf("b's candidate holds a's change: %s", cand)
	}
	// b commits something else; a's private candidate still commits its own
	// delta on top of it
	b.load("set snmp community example-ro authorization read-only")
	mustContain(t, "b commit", b.rpc("<commit-configuration/>"), "<commit-success/>")
	mustContain(t, "a commit", a.rpc("<commit-configuration/>"), "<commit-success/>")
	set := srv.Committed()
	if !hasStmt(set, "set system login idle-timeout 30") || !hasStmt(set, "set snmp community example-ro authorization read-only") {
		t.Errorf("committed:\n%s", set)
	}
}

func TestNetconfContentionWithAnExclusiveCLI(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"local": "local-admin pw super-user\n"})
	cli, _ := shell(t, srv, DefaultUser, DefaultPassword)
	cli.send("configure exclusive")
	c := netconfLogin(t, srv, "local-admin", "pw")
	got := c.open("exclusive")
	mustContain(t, "exclusive", got, "<error-tag>lock-denied</error-tag>", "locked by: "+DefaultUser)
	if got := c.rpc("<lock><target><candidate/></target></lock>"); !strings.Contains(got, "lock-denied") {
		t.Errorf("lock: %s", got)
	}
	// a private session opens with a warning, loads, and cannot commit
	got = c.open("private")
	mustContain(t, "private", got, "<error-severity>warning</error-severity>",
		"changes cannot be committed while 'configure exclusive' is active", "<ok/>")
	if got := c.load("set system login idle-timeout 30"); strings.Contains(got, "rpc-error") {
		t.Errorf("private load under a lock: %s", got)
	}
	got = c.rpc("<commit-configuration><check/></commit-configuration>")
	mustContain(t, "check", got, "<error-tag>lock-denied</error-tag>")
	if got := c.rpc("<commit-configuration/>"); !strings.Contains(got, "lock-denied") {
		t.Errorf("commit: %s", got)
	}
	// a shared load is refused
	d := netconfLogin(t, srv, "local-admin", "pw")
	if got := d.load("set system login idle-timeout 30"); !strings.Contains(got, "lock-denied") {
		t.Errorf("shared load under a lock: %s", got)
	}
}

func TestNetconfLockHeldByNetconf(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"local": "local-admin pw super-user\n"})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	mustContain(t, "lock", c.rpc("<lock><target><candidate/></target></lock>"), "<ok/>")
	if h := srv.ExclusiveHolder(); h != DefaultUser {
		t.Errorf("holder %q", h)
	}
	cli, _ := shell(t, srv, "local-admin", "pw")
	if got := cli.send("configure exclusive"); !strings.Contains(got, "configuration database locked by:") {
		t.Errorf("CLI under a NETCONF lock: %q", got)
	}
	mustContain(t, "unlock", c.rpc("<unlock><target><candidate/></target></unlock>"), "<ok/>")
	if h := srv.ExclusiveHolder(); h != "" {
		t.Errorf("holder after unlock %q", h)
	}
	if got := c.rpc("<unlock><target><candidate/></target></unlock>"); !strings.Contains(got, "rpc-error") {
		t.Errorf("second unlock: %s", got)
	}
}

func TestNetconfConfirmedCommitConfirmedBySameSession(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{"timer.minute": "60\n"})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout><log>tacctl apply 1</log></commit-configuration>")
	mustContain(t, "confirmed commit", got, "<commit-success/>")
	until, pending := srv.PendingUntil()
	if !pending || !until.Equal(clk.Now().Add(2*time.Minute)) {
		t.Errorf("pending %v until %v", pending, until)
	}
	h := srv.History()
	if h[0].RollbackIn != 2 || h[0].Comment != "tacctl apply 1" {
		t.Errorf("history: %+v", h[0])
	}
	// the history as the device prints it, over the command and the RPC
	mustContain(t, "show system commit", c.command("show system commit"),
		"by "+DefaultUser+" via netconf commit confirmed, rollback in 2mins", "tacctl apply 1")
	info := c.rpc("<get-commit-information/>")
	mustContain(t, "commit information", info, "<sequence-number>0</sequence-number>",
		"<client>netconf</client>", "<log>tacctl apply 1</log>", "<rollback-in>2</rollback-in>")
	// the confirming commit on the same session
	got = c.rpc("<commit/>")
	if !strings.Contains(got, "<ok/>") {
		t.Errorf("confirming commit: %s", got)
	}
	if _, pending := srv.PendingUntil(); pending {
		t.Error("still pending after the confirming commit")
	}
	// the window's end changes nothing now, nor does closing the session
	clk.Advance(5 * time.Minute)
	_ = c.conn.Close()
	time.Sleep(50 * time.Millisecond)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Errorf("rolled back after the confirmation:\n%s", srv.Committed())
	}
}

func TestNetconfConfirmedCommitRollsBackWhenTheSessionCloses(t *testing.T) {
	srv, dir, clk := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	mustContain(t, "commit", c.rpc("<commit-configuration><confirmed/><confirm-timeout>5</confirm-timeout></commit-configuration>"), "<commit-success/>")
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Fatal("not committed")
	}
	// closed without confirming: back at once, the window is not waited for
	_ = c.conn.Close()
	waitFor(t, "the rollback", func() bool { return !hasStmt(srv.Committed(), "set system login idle-timeout 30") })
	if _, pending := srv.PendingUntil(); pending {
		t.Error("still pending")
	}
	h := srv.History()
	if len(h) != 3 || h[0].User != "root" || h[0].Via != "other" {
		t.Errorf("history: %+v", h)
	}
	if clk.Timers() != 0 {
		t.Errorf("a timer is left: %d", clk.Timers())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "committed.set"))
	if strings.Contains(string(b), "idle-timeout") {
		t.Errorf("committed.set:\n%s", b)
	}
}

func TestNetconfConfirmedCommitRollsBackAtTheWindowsEnd(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	c.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration>")
	clk.Advance(time.Minute)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Fatal("rolled back early")
	}
	clk.Advance(2 * time.Minute)
	if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Error("not rolled back at the window's end")
	}
	// the session is still there and works
	if got := c.command("show system commit"); !strings.Contains(got, "by root via other") {
		t.Errorf("history: %s", got)
	}
}

func TestNetconfConfirmedCommitInAPrivateSessionKnob(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"netconf.private.confirm": "refuse\n"})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration>")
	mustContain(t, "refused", got, "<error-severity>error</error-severity>",
		"commit confirmed not supported for private configuration")
	if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Error("committed")
	}
	// an exclusive session may confirm
	d := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	if got := d.open("exclusive"); !strings.Contains(got, "<ok/>") {
		t.Fatalf("exclusive: %s", got)
	}
	d.load("set system login idle-timeout 30")
	mustContain(t, "exclusive confirmed", d.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration>"), "<commit-success/>")
}

func TestNetconfAndCommandLineShareOneConfiguration(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	cli, _ := shell(t, srv, DefaultUser, DefaultPassword)
	cli.send("configure exclusive")
	cli.send("set system login idle-timeout 30")
	cli.send("commit")
	cli.send("exit")
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	got := c.rpc(`<get-configuration database="committed" format="set"/>`)
	mustContain(t, "set read", got, "<configuration-set>", "set system login idle-timeout 30")
	got = c.rpc(`<get-configuration format="text"><configuration><system><login/></system></configuration></get-configuration>`)
	mustContain(t, "text read with a filter", got, "<configuration-text>", "idle-timeout 30;")
	if strings.Contains(got, "snmp") {
		t.Errorf("the filter let the rest through: %s", got)
	}
	got = c.rpc(`<get-configuration database="committed" format="set"><configuration><snmp/></configuration></get-configuration>`)
	if !strings.Contains(got, "set snmp community public authorization read-only") || strings.Contains(got, "idle-timeout") {
		t.Errorf("filtered set read: %s", got)
	}
	// a NETCONF commit is visible on the command line, with its way
	c.open("private")
	c.load("set snmp community example-ro authorization read-only")
	c.rpc("<commit-configuration><log>over netconf</log></commit-configuration>")
	cli2, _ := shell(t, srv, DefaultUser, DefaultPassword)
	mustContain(t, "cli read", cli2.send("show configuration | display set"), "set snmp community example-ro authorization read-only")
	mustContain(t, "cli history", cli2.send("show system commit"), "via netconf", "over netconf")
	// the operational commands of the CLI model, over <command>
	mustContain(t, "authorization", c.command("show cli authorization"), "Current user:", "Permissions:")
	mustContain(t, "version", c.command("show version"), "Hostname: sw-lab-1")
	if got := c.command("show nonsense"); !strings.Contains(got, "<rpc-error>") {
		t.Errorf("an unknown command: %s", got)
	}
}

func TestNetconfDiscardAndCloseConfiguration(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	mustContain(t, "discard", c.rpc("<discard-changes/>"), "<ok/>")
	if got := c.compare(); strings.Contains(got, "idle-timeout") {
		t.Errorf("discard left it: %s", got)
	}
	c.load("set system login idle-timeout 30")
	c.rpc("<close-configuration/>")
	// opening again starts from the committed configuration
	c.open("private")
	if got := c.compare(); strings.Contains(got, "idle-timeout") {
		t.Errorf("close kept the private candidate: %s", got)
	}
	if got := c.open("private"); !strings.Contains(got, "already open") {
		t.Errorf("a second open: %s", got)
	}
}

func TestNetconfSharedCandidatePersistsAndExclusiveDropsOnClose(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.load("set system login idle-timeout 30") // a shared load, no open
	if !strings.Contains(srv.Candidate(), "set system login idle-timeout 30") {
		t.Errorf("shared candidate:\n%s", srv.Candidate())
	}
	if strings.Contains(srv.Committed(), "idle-timeout") {
		t.Error("committed")
	}
	_ = c.conn.Close()
	waitFor(t, "the session's end", func() bool { return len(srv.junosSessions()) == 0 })
	// a shared candidate stays staged, as on a device
	if !strings.Contains(srv.Candidate(), "idle-timeout 30") {
		t.Errorf("staged change lost:\n%s", srv.Candidate())
	}
	d := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	if got := d.open("exclusive"); !strings.Contains(got, "configuration database modified") {
		t.Errorf("exclusive over a staged change: %s", got)
	}
}

func TestNetconfKnobsAct(t *testing.T) {
	t.Run("check.errors", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"check.errors": "set system login idle-timeout => idle-timeout is out of range\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.open("private")
		c.load("set system login idle-timeout 30")
		mustContain(t, "check", c.rpc("<commit-configuration><check/></commit-configuration>"),
			"<error-severity>error</error-severity>", "idle-timeout is out of range")
		mustContain(t, "commit", c.rpc("<commit-configuration/>"), "idle-timeout is out of range")
		if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
			t.Error("committed past a failed check")
		}
	})
	t.Run("version-gate", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"version-gate": "set system services netconf traceoptions\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.open("private")
		got := c.load("set system services netconf traceoptions file x")
		mustContain(t, "gate", got, "<error-severity>error</error-severity>", "syntax error")
	})
	t.Run("exclusive.held-by", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"exclusive.held-by": "bob\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		mustContain(t, "exclusive", c.open("exclusive"), "lock-denied", "locked by: bob")
	})
	t.Run("commit.drop", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"commit.drop": "\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.open("private")
		c.load("set system login idle-timeout 30")
		// the connection closes before the answer: no reply, and the
		// unconfirmed commit goes with the session
		c.id++
		_, _ = io.WriteString(c.in, fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">`+
			`<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration></rpc>]]>]]>`, c.id))
		done := make(chan error, 1)
		go func() { done <- c.sess.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the connection was not closed")
		}
		waitFor(t, "the rollback", func() bool { return len(srv.History()) == 3 })
		if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
			t.Errorf("not rolled back:\n%s", srv.Committed())
		}
	})
	t.Run("commit.drop after-output", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"commit.drop": "after-output\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.open("private")
		c.load("set system login idle-timeout 30")
		got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration>")
		mustContain(t, "reply", got, "<commit-success/>")
		waitFor(t, "the rollback", func() bool { return !hasStmt(srv.Committed(), "set system login idle-timeout 30") })
	})
	t.Run("verify.fail", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"verify.fail": "deny\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.open("private")
		c.load("set system login idle-timeout 30")
		c.rpc("<commit-configuration><confirmed/><confirm-timeout>2</confirm-timeout></commit-configuration>")
		if _, err := dialJunos(t, srv, DefaultUser, DefaultPassword); err == nil {
			t.Fatal("a new login was accepted while the commit is pending")
		}
		// the same session confirms; a login works again
		c.rpc("<commit/>")
		conn, err := dialJunos(t, srv, DefaultUser, DefaultPassword)
		if err != nil {
			t.Fatalf("login after the confirmation: %v", err)
		}
		_ = conn.Close()
	})
	t.Run("drop", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"drop": "show system commit\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.id++
		_, _ = io.WriteString(c.in, fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">`+
			`<command>show system commit</command></rpc>]]>]]>`, c.id))
		done := make(chan error, 1)
		go func() { done <- c.sess.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the connection was not closed")
		}
	})
}

func TestNetconfRefusalsAndUnsupported(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"class": "read-only\n"})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	mustContain(t, "read-only open", c.open("private"), "access-denied")
	srv2, _, _ := newJunos(t, map[string]string{})
	d := netconfLogin(t, srv2, DefaultUser, DefaultPassword)
	d.open("private")
	mustContain(t, "persist", d.rpc("<commit-configuration><confirmed/><persist>x</persist></commit-configuration>"), "operation-not-supported")
	mustContain(t, "override", d.rpc(`<load-configuration action="override" format="text"><configuration-text>x</configuration-text></load-configuration>`), "operation-not-supported")
	mustContain(t, "bad timeout", d.rpc("<commit-configuration><confirmed/><confirm-timeout>0</confirm-timeout></commit-configuration>"), "invalid-value")
	mustContain(t, "bad rollback", d.rpc(`<get-configuration compare="rollback" rollback="99" format="text"/>`), "invalid-value")
}

// a canned reply of the transcript still wins over the model, and a plain
// committed read with a transcript file is the file's
func TestNetconfTranscriptStillWins(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{
		"rpc.commit-configuration.xml":         "<ok/>",
		"show configuration | display set.out": "set from transcript\n",
	})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	mustContain(t, "canned", c.rpc("<commit-configuration/>"), "<ok/>")
	if len(srv.History()) != 1 {
		t.Error("the canned reply was not used")
	}
	mustContain(t, "file", c.rpc(`<get-configuration format="set"/>`), "set from transcript")
	// a candidate read is the model's
	got := c.rpc(`<get-configuration database="candidate" format="set"/>`)
	mustContain(t, "candidate", got, "set system host-name sw-lab-1")
}

// junosSessions is how many sessions the model holds.
func (s *Server) junosSessions() []*jsession {
	d := s.junos()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*jsession
	for sess := range d.sessions {
		out = append(out, sess)
	}
	return out
}
