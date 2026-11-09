package cli

// The console's file transfer: the sftp subsystem that sshd's ForceCommand
// hands to the console as a '-c' string (sftp-server, internal-sftp) is
// served by internal/sftpd on the process's standard input and output, as the
// logged-in user, rooted in the home directory the account database names.
// The protocol owns standard output: nothing is printed to it, and every
// refusal and error goes to standard error before the first protocol byte.
// The shell, its idle timeout and its history have no part in it.

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/sftpd"
	"github.com/rett/tacctl/internal/ui"
)

// The texts of the sftp subsystem refused before the protocol starts (the
// refusal for a policy that is off is console.SFTPOffText).
const (
	sftpPasswordText = "a password change is required of this account: log in to the console and change the password (passwd) before transferring files"
	sftpUnknownText  = "it could not be read whether a password change is required of this account, so file transfer is held: try again, or ask an administrator"
	sftpPolicyText   = "the console's policy could not be read, so file transfer is not available: try again, or ask an administrator"
)

// serveSFTP is the session of the sftp subsystem, after the start line of
// the console: the policy is asked, the caller is held to the same rules as
// a line of the console (a required password change, the policy's file
// transfer setting), and then sftpd serves the stream.
func (cs *consoleSession) serveSFTP(exe string) error {
	inv, a := cs.inv, cs.inv.app
	marker := console.EnvMarker + "=" + cs.sess.ID
	cs.pol = inv.consoleRemotePolicy(exe, marker)
	inv.hooks.adjustConsolePolicy(&cs.pol)
	groups := inv.callerGroups()
	cs.tier = sudoTier(groups)
	if cs.pol.Known {
		cs.tier = cs.pol.Tier
	}
	switch lock := lockedBy(cs.pol, groups); {
	case lock != nil && lock.unknown.Load():
		// it could not be read whether a password change is required of the
		// caller (no answer from the root side counts): nothing is served
		return cs.sftpRefused("password-change", sftpUnknownText, console.RefusedStatus)
	case lock != nil:
		// a password change is required: the session may run nothing but the
		// change itself
		return cs.sftpRefused("password-change", sftpPasswordText, console.RefusedStatus)
	case !cs.pol.Known:
		// a superuser, who is never held, with no policy to read
		return cs.sftpRefused("policy", sftpPolicyText, console.RefusedStatus)
	case !cs.pol.FileTransferSettings().Enabled:
		return cs.sftpRefused("file-transfer", console.SFTPOffText, console.RefusedStatus)
	}
	ft := cs.pol.FileTransferSettings()
	home, err := inv.hooks.homeOf(a.EUID)
	if err != nil || !filepath.IsAbs(home) {
		return cs.sftpRefused("home", "tacctl-console: cannot find the home directory of this account", 1)
	}
	if a.Stdin == nil || a.Out.Stdout == nil {
		return cs.sftpRefused("stream", "tacctl-console: no standard input or output", 1)
	}
	conn := &sftpConn{r: a.Stdin, w: sftpStdout(a.Out.Stdout)}
	// A signal (sshd closing the session) ends the transfer as a closed
	// connection does.
	stop := context.AfterFunc(inv.ctx, func() { _ = conn.Close() })
	defer stop()

	au := cs.newSFTPAudit()
	cs.log("auth.info", cs.sess.SFTPStartLine(string(cs.tier), home, ft.Quota, ft.Rate))
	err = sftpd.Serve(conn, sftpd.Config{Home: home, Quota: ft.Quota, Rate: ft.Rate, Audit: au.event})
	t := au.finish()
	cs.log("auth.info", cs.sess.SFTPEndLine(t.up, t.down, t.ops, t.refused))
	status := 0
	if err != nil && inv.ctx.Err() == nil {
		// the one short line of what went wrong; stdout is the protocol's and
		// is closed by now
		_, _ = io.WriteString(a.Out.Stderr, "tacctl-console: sftp: "+oneLine(err.Error())+"\n")
		status = console.SFTPStatus
	}
	cs.log("auth.info", cs.sess.EndLine(console.ReasonSFTP, t.ops, status))
	if status != 0 {
		return exit(status)
	}
	return nil
}

// sftpRefused answers the sftp subsystem with a refusal on standard error
// (the protocol has not started), logs it as a refused command is logged, and
// ends the session with status.
func (cs *consoleSession) sftpRefused(why, text string, status int) error {
	_, _ = io.WriteString(cs.inv.app.Out.Stderr, text+"\n")
	cs.log("auth.warning", cs.sess.SFTPDenyLine(why))
	cs.log("auth.info", cs.sess.EndLine(console.ReasonSFTP, 0, status))
	return exit(status)
}

// sftpStdout is the stream the protocol is written to: the file behind
// standard output. The console's own output is wrapped to take the colour out
// of what it prints (app.New), which would damage binary packets.
func sftpStdout(w io.Writer) io.Writer {
	if f, ok := ui.File(w); ok {
		return f
	}
	return w
}

// oneLine is s as one short line for standard error.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// sftpConn is standard input and output as the one stream sftpd serves. Close
// is safe to call from the signal handler and from Serve.
type sftpConn struct {
	r    io.Reader
	w    io.Writer
	once sync.Once
}

func (c *sftpConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *sftpConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// Close closes the input and the output when they can be closed (the
// process's own are: a read that waits is released).
func (c *sftpConn) Close() error {
	var err error
	c.once.Do(func() {
		if cl, ok := c.r.(io.Closer); ok {
			err = cl.Close()
		}
		if cl, ok := c.w.(io.Closer); ok {
			err = errors.Join(err, cl.Close())
		}
	})
	return err
}

// sftpTotals are what the audit of a session counted.
type sftpTotals struct {
	up, down     int64
	ops, refused int
}

// sftpAudit turns the events of the server into log lines, in order, off the
// goroutines that serve the requests (each line is a 'logger' process).
type sftpAudit struct {
	cs   *consoleSession
	ch   chan sftpd.Event
	done chan struct{}
	t    sftpTotals
}

func (cs *consoleSession) newSFTPAudit() *sftpAudit {
	au := &sftpAudit{cs: cs, ch: make(chan sftpd.Event, 256), done: make(chan struct{})}
	go au.run()
	return au
}

// event queues one event for the log.
func (au *sftpAudit) event(e sftpd.Event) { au.ch <- e }

// finish waits for the lines queued and gives the totals; no event follows.
func (au *sftpAudit) finish() sftpTotals {
	close(au.ch)
	<-au.done
	return au.t
}

func (au *sftpAudit) run() {
	defer close(au.done)
	for e := range au.ch {
		priority, line := au.cs.sess.SFTPEventLine(e.Op, e.Path, e.To, e.Bytes, errText(e.Err))
		au.cs.log(priority, line)
		au.t.ops++
		switch e.Op {
		case "refused":
			au.t.refused++
		case "upload":
			au.t.up += e.Bytes
		case "download":
			au.t.down += e.Bytes
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
