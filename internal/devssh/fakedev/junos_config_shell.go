package fakedev

// The sessions of the configure model: the shell channel's CLI (banner,
// prompts with the '{master:0}' and '[edit]' lines, echo, paging), the csh
// of a root login, and the exec channel's one-shot commands.

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// junosConn is what a session of the model knows of its connection.
type junosConn struct {
	user string
	exec bool   // the CLI was started by an exec request
	drop func() // closes the connection
}

// execCLI is the exec command a root login uses to start the CLI from its
// csh: "sh -c 'PATH=...; exec cli'".
var execCLI = regexp.MustCompile(`\bexec\s+cli\b`)

// promptText is the prompt of the session, with the lines before it: a
// blank line, the '{master:0}' line and, in configuration mode, the
// '[edit]' line.
func (d *junosDevice) promptText(sess *jsession) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	sw := d.switchLine()
	up := sess.user + "@" + d.hostname()
	switch {
	case sess.configure:
		return "\n" + sw + "[edit" + joinEditPath(sess.edit) + "]\n" + up + "# "
	case sw != "":
		return "\n" + sw + "\n" + up + "> "
	}
	return "\n" + up + "> "
}

// echoed is what the device echoes of a typed command: with a trailing
// space, as the capture showed, unless the 'echo.plain' knob says not.
func (d *junosDevice) echoed(cmd string) string {
	if d.s.t.exists("echo.plain") {
		return cmd
	}
	return cmd + " "
}

// dropsBefore reports whether the 'drop' knob closes the connection at cmd.
func (d *junosDevice) dropsBefore(cmd string) bool {
	for _, l := range d.rules("drop") {
		if hasPrefixWords(cmd, l) {
			return true
		}
	}
	return false
}

// delay waits on the server's clock for the 'slow' knob; it reports false
// when the server stopped meanwhile.
func (d *junosDevice) delay(cmd string) bool {
	for _, l := range d.rules("slow") {
		prefix, v, ok := splitRule(l)
		if !ok || (prefix != "*" && !hasPrefixWords(cmd, prefix)) {
			continue
		}
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil || secs <= 0 {
			continue
		}
		done := make(chan struct{})
		t := d.s.clock.AfterFunc(durationOf(secs), func() { close(done) })
		select {
		case <-done:
		case <-d.s.quit:
			t.Stop()
			return false
		}
	}
	return true
}

// junosShell is a shell channel: the CLI of a local or TACACS+ login, the
// csh of root.
func (s *Server) junosShell(d *junosDevice, ch ssh.Channel, jc junosConn) {
	in := bufio.NewReader(ch)
	if b, ok := s.t.read("banner"); ok {
		_, _ = io.WriteString(ch, crlf(b))
	}
	if jc.user == "root" {
		s.junosCsh(d, ch, in, jc)
		return
	}
	s.junosCLI(d, ch, in, jc)
}

func (s *Server) readCommand(d *junosDevice, ch ssh.Channel, in *bufio.Reader) (string, bool) {
	line, err := in.ReadString('\n')
	if err != nil {
		return "", false
	}
	cmd := strings.TrimSpace(line)
	// an empty line echoes as nothing: the prompt is simply reprinted
	if s.echo && cmd != "" {
		_, _ = io.WriteString(ch, d.echoed(cmd)+"\r\n")
	}
	return cmd, true
}

// junosCsh is the shell of a root login: 'cli' starts the CLI.
func (s *Server) junosCsh(d *junosDevice, ch ssh.Channel, in *bufio.Reader, jc junosConn) {
	for {
		d.mu.Lock()
		host := d.hostname()
		d.mu.Unlock()
		if _, err := io.WriteString(ch, fmt.Sprintf(jtCshPromptFmt, host)); err != nil {
			return
		}
		cmd, ok := s.readCommand(d, ch, in)
		if !ok {
			return
		}
		w := jsplit(cmd)
		if len(w) == 0 {
			continue
		}
		s.log(cmd)
		switch {
		case w[0] == "exit" || w[0] == "logout":
			return
		case len(w) == 1 && w[0] == "cli":
			if s.junosCLI(d, ch, in, jc) {
				return
			}
		case len(w) == 3 && w[0] == "cli" && w[1] == "-c":
			sess := d.newSession(jc.user)
			res := d.run(sess, w[2], true)
			d.endSession(sess)
			_, _ = io.WriteString(ch, crlf(res.out))
		default:
			_, _ = io.WriteString(ch, fmt.Sprintf(jtCshNotFoundFmt, w[0])+"\r\n")
		}
	}
}

// junosCLI is the Junos CLI on a channel. It reports whether the
// connection is gone (a drop or a closed channel), false for a 'quit'.
func (s *Server) junosCLI(d *junosDevice, ch ssh.Channel, in *bufio.Reader, jc junosConn) (gone bool) {
	sess := d.newSession(jc.user)
	defer d.endSession(sess)
	for {
		if _, err := io.WriteString(ch, crlf(d.promptText(sess))); err != nil {
			return true
		}
		cmd, ok := s.readCommand(d, ch, in)
		if !ok {
			return true
		}
		if cmd == "" {
			continue
		}
		s.log(cmd)
		if s.t.hangs(cmd) {
			<-s.quit
			return true
		}
		if d.dropsBefore(cmd) {
			jc.drop()
			return true
		}
		if !d.delay(cmd) {
			return true
		}
		res := d.run(sess, cmd, false)
		if res.drop == dropSilent {
			jc.drop()
			return true
		}
		pageLen := sess.pageLen
		if res.noMore {
			pageLen = 0
		}
		if !s.page(ch, in, crlf(res.out), pageLen, sess.junosPage) {
			return true
		}
		if res.drop == dropAfterOutput {
			jc.drop()
			return true
		}
		if res.quit {
			return jc.exec
		}
	}
}

// junosExec is an exec channel: a CLI command for a local or TACACS+
// login, a csh command for root (unless it starts the CLI).
func (s *Server) junosExec(d *junosDevice, ch ssh.Channel, jc junosConn, cmd string) {
	status := uint32(0)
	defer func() {
		if !s.noStatus {
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		}
	}()
	if jc.user == "root" {
		if execCLI.MatchString(cmd) {
			jc.exec = true
			s.log(cmd)
			s.junosCLI(d, ch, bufio.NewReader(ch), jc)
			return
		}
		s.log(cmd)
		w := strings.Fields(cmd)
		name := cmd
		if len(w) > 0 {
			name = w[0]
		}
		_, _ = io.WriteString(ch, fmt.Sprintf(jtCshNotFoundFmt, name)+"\n")
		status = 1
		return
	}
	s.log(cmd)
	if s.t.hangs(cmd) {
		<-s.quit
		return
	}
	if d.dropsBefore(cmd) {
		jc.drop()
		return
	}
	if !d.delay(cmd) {
		return
	}
	sess := d.newSession(jc.user)
	res := d.run(sess, cmd, true)
	d.endSession(sess)
	if res.drop == dropSilent {
		jc.drop()
		return
	}
	_, _ = io.WriteString(ch, res.out)
	if res.unknown {
		status = 1
	}
	if res.drop != dropNone {
		jc.drop()
	}
}
