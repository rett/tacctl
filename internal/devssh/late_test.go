package devssh_test

import (
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devssh"
)

// A Junos device on a slow link, over a real channel: the answer to the
// retried empty line of the login is still on its way when the first
// command is typed, and arrives in front of its echo. What the device waits
// for is what the client typed, never a time.
func TestShellLateAnswerOfTheRetriedEmptyLine(t *testing.T) {
	t.Parallel()
	const ans = "\r\n{master:0}\r\nalice@rtr1> "
	d := &scripted{raw: func(ch ssh.Channel) {
		lines := make(chan string, 16)
		go func() {
			one := make([]byte, 1)
			var line []byte
			for {
				if _, err := ch.Read(one); err != nil {
					close(lines)
					return
				}
				if one[0] != '\n' {
					line = append(line, one[0])
					continue
				}
				lines <- string(line)
				line = nil
			}
		}()
		say := func(s string) { _, _ = io.WriteString(ch, s) }
		next := func() (string, bool) { l, ok := <-lines; return l, ok }
		say("banner\r\nalice@rtr1> ")
		if _, ok := next(); !ok { // the empty line
			return
		}
		if _, ok := next(); !ok { // and the retry, after a quiet period
			return
		}
		say(ans) // the answer to the first
		cmd, ok := next()
		if !ok {
			return
		}
		say(ans) // the answer to the retry, in front of the echo
		say(cmd + "\r\n")
		say("warning: uncommitted changes will be discarded on exit\r\nEntering configuration mode\r\n")
		say("\r\n{master:0}[edit]\r\nalice@rtr1# ")
		if _, ok := next(); !ok {
			return
		}
		say("\r\n{master:0}[edit]\r\nalice@rtr1# ")
		<-lines
	}}
	tg, stop := d.start(t)
	defer stop()
	tg.Quiet = 30 * time.Millisecond
	s, err := dial(t, tg).CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	want := "warning: uncommitted changes will be discarded on exit\nEntering configuration mode\n\n{master:0}[edit]\n"
	if got, err := s.Run(bg(), "configure exclusive"); err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}
