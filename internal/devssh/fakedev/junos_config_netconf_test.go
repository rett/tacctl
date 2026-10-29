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
	// the device answers an open with an EMPTY reply [C: plan N1]
	if got := c.open("private"); strings.Contains(got, "<ok/>") || strings.Contains(got, "rpc-error") ||
		!strings.Contains(got, `message-id="1"></rpc-reply>`) {
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
	// there is no exclusive <open-configuration> [C: plan N1]
	got := c.open("exclusive")
	mustContain(t, "exclusive form", got, "<error-tag>operation-failed</error-tag>",
		"syntax error, expecting <invoke-on>", "<bad-element>exclusive</bad-element>")
	// the lock is the exclusive analogue
	got = c.rpc("<lock-configuration/>")
	mustContain(t, "lock-configuration", got, "<error-tag>lock-denied</error-tag>", "locked by: "+DefaultUser)
	if got := c.rpc("<lock><target><candidate/></target></lock>"); !strings.Contains(got, "lock-denied") {
		t.Errorf("lock: %s", got)
	}
	// a private session opens with a warning, loads, and cannot commit
	got = c.open("private")
	mustContain(t, "private", got, "<error-severity>warning</error-severity>",
		"changes cannot be committed while 'configure exclusive' is active")
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
	// the lock is the form that may confirm [C: plan N1, N2]; the empty reply
	if got := c.rpc("<lock-configuration/>"); strings.Contains(got, "rpc-error") || strings.Contains(got, "<ok/>") {
		t.Fatalf("lock-configuration: %s", got)
	}
	c.load("set system login idle-timeout 30")
	got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout><log>tacctl apply 1</log></commit-configuration>")
	mustContain(t, "confirmed commit", got, "<commit-success/>")
	until, pending := srv.PendingUntil()
	if !pending || !until.Equal(clk.Now().Add(2*time.Minute)) {
		t.Errorf("pending %v until %v", pending, until)
	}
	h := srv.History()
	if h[0].RollbackIn != 2 || h[0].Comment != "tacctl apply 1" {
		t.Errorf("history: %+v", h[0])
	}
	// the history as the device prints it, over the command and the RPC:
	// the window is read in seconds (120 is two minutes) and the device's
	// own marker stands under the entry [lab: N5]
	mustContain(t, "show system commit", c.command("show system commit"),
		"by "+DefaultUser+" via netconf commit confirmed, rollback in 2mins", "tacctl apply 1", "rollback pending")
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
	if got := c.command("show system commit"); strings.Contains(got, "rollback pending") {
		t.Errorf("the marker stands after the confirm: %s", got)
	}
	mustContain(t, "unlock", c.rpc("<unlock-configuration/>"), `message-id="`)
	if h := srv.ExclusiveHolder(); h != "" {
		t.Errorf("holder after unlock-configuration %q", h)
	}
	// the window's end changes nothing now, nor does closing the session
	clk.Advance(5 * time.Minute)
	_ = c.conn.Close()
	time.Sleep(50 * time.Millisecond)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Errorf("rolled back after the confirmation:\n%s", srv.Committed())
	}
}

// TestNetconfConfirmedCommitStaysPendingWhenTheSessionCloses pins the lab
// switch's behaviour (plan N2): a session that closes or dies without
// confirming leaves the confirmed commit pending to the window's end; the
// earlier "rolled back at once" was a window of seconds.
func TestNetconfConfirmedCommitStaysPendingWhenTheSessionCloses(t *testing.T) {
	srv, dir, clk := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	mustContain(t, "commit", c.rpc("<commit-configuration><confirmed/><confirm-timeout>300</confirm-timeout></commit-configuration>"), "<commit-success/>")
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Fatal("not committed")
	}
	// closed without confirming: nothing happens at the close
	_ = c.conn.Close()
	time.Sleep(100 * time.Millisecond)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Fatal("rolled back by the close")
	}
	if _, pending := srv.PendingUntil(); !pending {
		t.Fatal("not pending after the close")
	}
	// and the window's end rolls it back
	clk.Advance(4 * time.Minute)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Fatal("rolled back before the window's end")
	}
	clk.Advance(2 * time.Minute)
	if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Errorf("not rolled back at the window's end:\n%s", srv.Committed())
	}
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

// The knob netconf.close.rollback=on is the model of a device that does roll
// a confirmed commit back at the close (the lab switch does not).
func TestNetconfCloseRollbackKnob(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"netconf.close.rollback": "on\n"})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	mustContain(t, "commit", c.rpc("<commit-configuration><confirmed/><confirm-timeout>300</confirm-timeout></commit-configuration>"), "<commit-success/>")
	_ = c.conn.Close()
	waitFor(t, "the rollback", func() bool { return !hasStmt(srv.Committed(), "set system login idle-timeout 30") })
	if _, pending := srv.PendingUntil(); pending {
		t.Error("still pending")
	}
}

// TestNetconfLoadRollbackCancelsAPendingCommit is the cancel that works on
// the lab switch (plan N2): in a locked session <load-configuration
// rollback="1"/> makes the candidate the configuration before the newest
// commit, the compare is the inverse of the change, and a commit ends the
// window at once as a normal entry. A new session does the same.
func TestNetconfLoadRollbackCancelsAPendingCommit(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		name := "held session"
		if fresh {
			name = "new session"
		}
		t.Run(name, func(t *testing.T) {
			srv, _, clk := newJunos(t, map[string]string{})
			before := srv.Committed()
			c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
			c.rpc("<lock-configuration/>")
			c.load("set system login idle-timeout 30")
			mustContain(t, "commit", c.rpc("<commit-configuration><confirmed/><confirm-timeout>600</confirm-timeout><log>apply</log></commit-configuration>"), "<commit-success/>")
			if fresh {
				_ = c.conn.Close()
				time.Sleep(100 * time.Millisecond)
				c = netconfLogin(t, srv, DefaultUser, DefaultPassword)
				c.rpc("<lock-configuration/>")
			}
			mustContain(t, "load", c.rpc(`<load-configuration rollback="1"/>`), "<ok/>")
			got := c.rpc(`<get-configuration compare="rollback" rollback="0" format="text"/>`)
			if !strings.Contains(got, "idle-timeout 30") || !strings.Contains(got, "-") {
				t.Errorf("compare is not the inverse: %s", got)
			}
			mustContain(t, "cancel", c.rpc("<commit><log>tacctl apply cancel x</log></commit>"), "<ok/>")
			if srv.Committed() != before {
				t.Errorf("not back to the configuration before the change:\n%s", srv.Committed())
			}
			if _, pending := srv.PendingUntil(); pending {
				t.Error("still pending after the cancel")
			}
			h := srv.History()
			if h[0].Comment != "tacctl apply cancel x" || h[0].Confirmed || h[0].RollbackIn != 0 {
				t.Errorf("history[0]: %+v", h[0])
			}
			got = c.command("show system commit")
			if strings.Contains(got, "rollback pending") {
				t.Errorf("a pending line stands:\n%s", got)
			}
			if clk.Timers() != 0 {
				t.Errorf("a timer is left: %d", clk.Timers())
			}
		})
	}
	// a rollback the device does not keep
	srv, _, _ := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	mustContain(t, "no such rollback", c.rpc(`<load-configuration rollback="99"/>`), "rpc-error")
}

func TestNetconfConfirmedCommitRollsBackAtTheWindowsEnd(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	c.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>")
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

// The lab switch refuses a confirmed commit in a private session with these
// words [C: plan N1], by default; the knob 'accept' is a device that allows
// it. The lock may confirm either way.
func TestNetconfConfirmedCommitInAPrivateSessionKnob(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.open("private")
	c.load("set system login idle-timeout 30")
	got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>")
	mustContain(t, "refused", got, "<error-type>protocol</error-type>", "<error-tag>operation-failed</error-tag>",
		"<error-severity>error</error-severity>",
		`<error-message>"commit confirmed" is not supported for private configuration</error-message>`)
	if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
		t.Error("committed")
	}
	// the lock may confirm
	d := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	if got := d.rpc("<lock-configuration/>"); strings.Contains(got, "rpc-error") {
		t.Fatalf("lock: %s", got)
	}
	d.load("set system login idle-timeout 30")
	mustContain(t, "locked confirmed", d.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>"), "<commit-success/>")
	// a device that allows it
	srv2, _, _ := newJunos(t, map[string]string{"netconf.private.confirm": "accept\n"})
	e := netconfLogin(t, srv2, DefaultUser, DefaultPassword)
	e.open("private")
	e.load("set system login idle-timeout 30")
	mustContain(t, "accepted", e.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>"), "<commit-success/>")
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
	if got := d.rpc("<lock-configuration/>"); !strings.Contains(got, "configuration database modified") {
		t.Errorf("the lock over a staged change: %s", got)
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
		mustContain(t, "lock", c.rpc("<lock-configuration/>"), "lock-denied", "locked by: bob")
	})
	t.Run("commit.drop", func(t *testing.T) {
		srv, _, clk := newJunos(t, map[string]string{"commit.drop": "\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.rpc("<lock-configuration/>")
		c.load("set system login idle-timeout 30")
		// the connection closes before the answer: no reply, and the
		// unconfirmed commit stays pending to the window's end
		c.id++
		_, _ = io.WriteString(c.in, fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">`+
			`<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration></rpc>]]>]]>`, c.id))
		done := make(chan error, 1)
		go func() { done <- c.sess.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the connection was not closed")
		}
		time.Sleep(100 * time.Millisecond)
		if _, p := srv.PendingUntil(); !p || !hasStmt(srv.Committed(), "set system login idle-timeout 30") {
			t.Errorf("the commit is not pending:\n%s", srv.Committed())
		}
		clk.Advance(3 * time.Minute)
		if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
			t.Errorf("not rolled back at the window's end:\n%s", srv.Committed())
		}
	})
	t.Run("commit.drop after-output", func(t *testing.T) {
		srv, _, clk := newJunos(t, map[string]string{"commit.drop": "after-output\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.rpc("<lock-configuration/>")
		c.load("set system login idle-timeout 30")
		got := c.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>")
		mustContain(t, "reply", got, "<commit-success/>")
		time.Sleep(100 * time.Millisecond)
		if _, p := srv.PendingUntil(); !p {
			t.Error("not pending after the dropped session")
		}
		clk.Advance(3 * time.Minute)
		if hasStmt(srv.Committed(), "set system login idle-timeout 30") {
			t.Errorf("not rolled back at the window's end:\n%s", srv.Committed())
		}
	})
	t.Run("verify.fail", func(t *testing.T) {
		srv, _, _ := newJunos(t, map[string]string{"verify.fail": "deny\n"})
		c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
		c.rpc("<lock-configuration/>")
		c.load("set system login idle-timeout 30")
		c.rpc("<commit-configuration><confirmed/><confirm-timeout>120</confirm-timeout></commit-configuration>")
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

// TestNetconfConfirmTimeoutIsSeconds pins the lab switch's reading of
// <confirm-timeout>: seconds, not the minutes its reference gives. 180 is
// 'rollback in 3mins'; five seconds is 'rollback in 0mins' and the
// commit is rolled back after five seconds, not five minutes.
func TestNetconfConfirmTimeoutIsSeconds(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	mustContain(t, "180", c.rpc("<commit><confirmed/><confirm-timeout>180</confirm-timeout></commit>"), "<ok/>")
	mustContain(t, "180 label", c.command("show system commit"), "rollback in 3mins", "rollback pending")
	until, pending := srv.PendingUntil()
	if !pending || !until.Equal(clk.Now().Add(180*time.Second)) {
		t.Errorf("window: pending %v until %v", pending, until)
	}
	mustContain(t, "confirm", c.rpc("<commit/>"), "<ok/>")

	c.load("set system login idle-timeout 31")
	mustContain(t, "5", c.rpc("<commit><confirmed/><confirm-timeout>5</confirm-timeout></commit>"), "<ok/>")
	mustContain(t, "5 label", c.command("show system commit"), "rollback in 0mins", "rollback pending")
	clk.Advance(4 * time.Second)
	if !hasStmt(srv.Committed(), "set system login idle-timeout 31") {
		t.Fatal("rolled back before five seconds")
	}
	clk.Advance(2 * time.Second)
	if hasStmt(srv.Committed(), "set system login idle-timeout 31") {
		t.Error("not rolled back after five seconds")
	}
}

// With the knob 'chassis' a NETCONF commit names the members as the command
// line's answer does: <routing-engine> elements, the check's and then the
// commit's; a member that fails its check holds an <rpc-error> and nothing is
// committed; the single device's reply is as it was.
func TestNetconfChassisMembers(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"chassis": chassisKnob})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	member := func(n, el string) string { return "<routing-engine><name>" + n + "</name>" + el + "</routing-engine>" }
	var chk, done string
	for _, n := range []string{"fpc0", "fpc1", "fpc2", "fpc3"} {
		chk += member(n, "<commit-check-success/>")
		done += member(n, "<commit-success/>")
	}
	if got := c.rpc("<commit-configuration><check/></commit-configuration>"); !strings.Contains(got, "<commit-results>"+chk+"</commit-results>") {
		t.Errorf("check: %s", got)
	}
	if got := c.rpc("<commit-configuration><log>x</log></commit-configuration>"); !strings.Contains(got, "<commit-results>"+chk+done+"</commit-results>") {
		t.Errorf("commit: %s", got)
	}
	if !strings.Contains(srv.Committed(), "idle-timeout 30") {
		t.Error("not committed")
	}

	srv, _, _ = newJunos(t, map[string]string{"chassis": chassisKnob, "chassis.check": "fpc2 => member is out of sync\n"})
	c = netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	got := c.rpc("<commit-configuration><log>x</log></commit-configuration>")
	if !strings.Contains(got, "<routing-engine><name>fpc2</name><rpc-error>") || !strings.Contains(got, "member is out of sync") ||
		!strings.Contains(got, member("fpc3", "<commit-check-success/>")) || strings.Contains(got, "<commit-success/>") {
		t.Errorf("failing member: %s", got)
	}
	if strings.Contains(srv.Committed(), "idle-timeout 30") || len(srv.History()) != 1 {
		t.Error("committed with a failing member")
	}

	srv, _, _ = newJunos(t, map[string]string{})
	c = netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	if got := c.rpc("<commit-configuration><log>x</log></commit-configuration>"); !strings.Contains(got, "<commit-results>"+member("re0", "<commit-success/>")+"</commit-results>") {
		t.Errorf("single device: %s", got)
	}
}

// A chassis of one member with 'chassis.plain' answers a NETCONF commit as a
// single device does: a plain <ok/> for <commit/>, and one element for the
// commit-configuration, named by the member.
func TestNetconfChassisOfOne(t *testing.T) {
	srv, _, _ := newJunos(t, map[string]string{"chassis": "fpc0 ex4600-40f 18.1R3-S6.1\n", "chassis.plain": ""})
	c := netconfLogin(t, srv, DefaultUser, DefaultPassword)
	c.rpc("<lock-configuration/>")
	c.load("set system login idle-timeout 30")
	if got := c.rpc("<commit-configuration><check/></commit-configuration>"); !strings.Contains(got, "<commit-results><routing-engine><name>fpc0</name><commit-check-success/></routing-engine></commit-results>") {
		t.Errorf("check: %s", got)
	}
	if got := c.rpc("<commit-configuration><log>x</log></commit-configuration>"); !strings.Contains(got, "<commit-results><routing-engine><name>fpc0</name><commit-success/></routing-engine></commit-results>") {
		t.Errorf("commit: %s", got)
	}
	if !strings.Contains(srv.Committed(), "idle-timeout 30") {
		t.Error("not committed")
	}
}
