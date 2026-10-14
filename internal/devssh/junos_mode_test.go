package devssh_test

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// A scripted Junos command line with the two modes of D131: the
// operational prompt 'gotest@sw1> ', the configure prompt 'gotest@sw1# ',
// and the location line '{master:0}[edit]' before the configure prompt.
// The texts are those of the first capture; the lab spike corrects them.

const (
	jOper = "gotest@sw1> "
	jConf = "gotest@sw1# "
	jLoc  = "{master:0}[edit]\r\n"
)

type junosFake struct {
	t      *testing.T
	ln     net.Listener
	signer ssh.Signer
	banner string
	// editEvery prints the location line before every configure prompt,
	// the reply to an empty line too; false only after commands that
	// print something or change the mode.
	editEvery bool
	// handle answers a command; it may write partial output with pauses.
	handle func(f *junosFake, cmd string, w io.Writer)

	mu    sync.Mutex
	conf  bool
	noLoc bool     // the command just answered prints no location line
	execs []string // exec requests received
	cmds  []string // command lines received
}

func newJunosFake(t *testing.T) *junosFake {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &junosFake{t: t, ln: ln, signer: signer, handle: defaultJunos}
	t.Cleanup(func() { _ = ln.Close() })
	go f.accept()
	return f
}

func (f *junosFake) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.serve(c)
	}
}

func (f *junosFake) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(f.signer)
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go f.session(ch, creqs)
	}
}

func (f *junosFake) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for r := range reqs {
		switch r.Type {
		case "shell":
			_ = r.Reply(true, nil)
			f.shell(ch)
			return
		case "exec":
			var p struct{ Cmd string }
			_ = ssh.Unmarshal(r.Payload, &p)
			f.mu.Lock()
			f.execs = append(f.execs, p.Cmd)
			f.mu.Unlock()
			_ = r.Reply(true, nil)
			if p.Cmd != "cli" {
				_, _ = io.WriteString(ch, "unknown\r\n")
				return
			}
			f.shell(ch)
			return
		default:
			_ = r.Reply(true, nil)
		}
	}
}

func (f *junosFake) prompt(afterOutput bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conf {
		if afterOutput || f.editEvery {
			return jLoc + jConf
		}
		return jConf
	}
	return "\r\n{master:0}\r\n" + jOper
}

func (f *junosFake) shell(ch ssh.Channel) {
	in := bufio.NewReader(ch)
	_, _ = io.WriteString(ch, f.banner)
	_, _ = io.WriteString(ch, f.prompt(true))
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			_, _ = io.WriteString(ch, "\r\n")
		} else {
			_, _ = io.WriteString(ch, cmd+" \r\n")
		}
		if cmd == "" {
			_, _ = io.WriteString(ch, f.prompt(false))
			continue
		}
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		f.handle(f, cmd, ch)
		f.mu.Lock()
		quiet := f.noLoc
		f.noLoc = false
		f.mu.Unlock()
		_, _ = io.WriteString(ch, f.prompt(!quiet))
	}
}

func (f *junosFake) setConf(on bool) {
	f.mu.Lock()
	f.conf = on
	f.mu.Unlock()
}

func (f *junosFake) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *junosFake) target() devssh.Target {
	host, port, _ := net.SplitHostPort(f.ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return devssh.Target{
		Host: host, Port: p, User: "gotest",
		HostKeys:       []string{fakedev.KeyText(f.signer.PublicKey())},
		ConnectTimeout: 5 * time.Second,
		Quiet:          100 * time.Millisecond,
		Password:       func() (string, error) { return goodPassword, nil },
	}
}

// open dials the fake and opens a Junos shell session.
func (f *junosFake) open(opts ...devssh.CLIOption) devssh.CLISession {
	f.t.Helper()
	c := dial(f.t, f.target())
	s, err := c.CLI(devssh.VendorJuniper, append([]devssh.CLIOption{devssh.WithMode(devssh.ModeShell)}, opts...)...)
	if err != nil {
		f.t.Fatalf("CLI: %v", err)
	}
	f.t.Cleanup(func() { _ = s.Close() })
	return s
}

func defaultJunos(f *junosFake, cmd string, w io.Writer) {
	f.mu.Lock()
	conf := f.conf
	f.mu.Unlock()
	out := func(s string) { _, _ = io.WriteString(w, strings.ReplaceAll(s, "\n", "\r\n")) }
	switch {
	case cmd == "configure" && !conf, cmd == "configure exclusive" && !conf:
		out("Entering configuration mode\n\n")
		f.setConf(true)
	case cmd == "exit" && conf:
		out("Exiting configuration mode\n\n")
		f.setConf(false)
	case cmd == "show version" && !conf:
		out("Hostname: sw1\nJunos: 25.4R1\n")
	case cmd == "show motd" && !conf:
		// A message that looks like the configure prompt, in the middle
		// of the output.
		out("Welcome\n" + jConf + "\nnotice follows\n")
	case cmd == "show slow" && !conf:
		// The output stops (longer than the quiet period) on a line that
		// is the configure prompt, then goes on.
		out("first\n" + jConf)
		time.Sleep(400 * time.Millisecond)
		out("\nlast\n")
	case cmd == "show | compare" && conf:
		// An empty candidate prints nothing.
	case cmd == "show | compare diff" && conf:
		out("\n[edit system]\n+  host-name x;\n")
	case strings.HasPrefix(cmd, "set ") && conf:
		f.mu.Lock()
		f.noLoc = true
		f.mu.Unlock()
	default:
		out("syntax error: " + cmd + "\n")
	}
}

func TestJunosConfigureModeSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		editEvery bool
	}{
		{"location line after output", false},
		{"location line before every prompt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJunosFake(t)
			f.editEvery = tc.editEvery
			f.banner = "Last login from 192.0.2.7\r\n"
			s := f.open()

			if got, err := s.Run(bg(), "show version"); err != nil || got != "Hostname: sw1\nJunos: 25.4R1\n\n" {
				t.Fatalf("show version = %q, %v", got, err)
			}
			// The mode change ends when the configure prompt matches; the
			// location line is output of it.
			got, err := s.Run(bg(), "configure exclusive")
			if err != nil || got != "Entering configuration mode\n\n{master:0}[edit]\n" {
				t.Fatalf("configure = %q, %v", got, err)
			}
			// The location line printed for the prompt of configure is
			// not output of the command after it.
			got, err = s.Run(bg(), "set system host-name x")
			want := ""
			if tc.editEvery {
				want = "{master:0}[edit]\n"
			}
			if err != nil || got != want {
				t.Fatalf("set = %q, %v; want %q", got, err, want)
			}
			got, err = s.Run(bg(), "show | compare diff")
			if err != nil || got != "\n[edit system]\n+  host-name x;\n{master:0}[edit]\n" {
				t.Fatalf("show | compare = %q, %v", got, err)
			}
			if n := strings.Count(got, "{master:0}[edit]"); n != 1 {
				t.Errorf("%d location lines in one output", n)
			}
			got, err = s.Run(bg(), "show | compare")
			if err != nil || strings.TrimSpace(got) != "{master:0}[edit]" || !devssh.LocationLine(strings.TrimSpace(got)) {
				t.Fatalf("empty compare = %q, %v", got, err)
			}
			// And back: the operational prompt ends it.
			got, err = s.Run(bg(), "exit")
			if err != nil || !strings.HasPrefix(got, "Exiting configuration mode\n\n") {
				t.Fatalf("exit = %q, %v", got, err)
			}
			if got, err := s.Run(bg(), "show version"); err != nil || !strings.HasPrefix(got, "Hostname: sw1\n") {
				t.Fatalf("show version after exit = %q, %v", got, err)
			}
			want2 := []string{"show version", "configure exclusive", "set system host-name x", "show | compare diff", "show | compare", "exit", "show version"}
			if got := s.Commands(); !equalStrings(got, want2) {
				t.Errorf("Commands() = %q, want %q", got, want2)
			}
			if got := f.received(); !equalStrings(got, want2) {
				t.Errorf("the device received %q, want %q", got, want2)
			}
		})
	}
}

// A message that looks like a prompt of the other mode is output, in the
// middle of it and at the end of a pause, and the session stays in its mode.
func TestJunosPromptLookalikeIsOutput(t *testing.T) {
	f := newJunosFake(t)
	s := f.open()

	got, err := s.Run(bg(), "show motd")
	if err != nil || !strings.HasPrefix(got, "Welcome\ngotest@sw1# \nnotice follows\n") {
		t.Fatalf("show motd = %q, %v", got, err)
	}
	got, err = s.Run(bg(), "show slow")
	if err != nil || !strings.HasPrefix(got, "first\ngotest@sw1# \nlast\n") {
		t.Fatalf("show slow = %q, %v", got, err)
	}
	// Still operational: a configure-mode command is not understood and
	// the next command still ends.
	got, err = s.Run(bg(), "set system host-name y")
	if err != nil || !strings.HasPrefix(got, "syntax error: set system host-name y\n") {
		t.Fatalf("set in operational mode = %q, %v", got, err)
	}
	if got, err := s.Run(bg(), "show version"); err != nil || !strings.HasPrefix(got, "Hostname: sw1\n") {
		t.Fatalf("show version = %q, %v", got, err)
	}
}

// A login message that is the configure prompt does not make the session
// take it for its prompt.
func TestJunosLoginBannerLookalike(t *testing.T) {
	f := newJunosFake(t)
	f.banner = jConf + "\r\nWelcome\r\n"
	s := f.open()
	if got, err := s.Run(bg(), "show version"); err != nil || !strings.HasPrefix(got, "Hostname: sw1\n") {
		t.Fatalf("show version = %q, %v", got, err)
	}
	if _, err := s.Run(bg(), "configure"); err != nil {
		t.Fatalf("configure: %v", err)
	}
}

func TestWithCommand(t *testing.T) {
	f := newJunosFake(t)
	s := f.open(devssh.WithCommand("cli"))
	if got, err := s.Run(bg(), "show version"); err != nil || !strings.HasPrefix(got, "Hostname: sw1\n") {
		t.Fatalf("show version = %q, %v", got, err)
	}
	f.mu.Lock()
	execs := append([]string(nil), f.execs...)
	f.mu.Unlock()
	if !equalStrings(execs, []string{"cli"}) {
		t.Errorf("exec requests %q, want [cli]", execs)
	}
	if got := s.Commands(); !equalStrings(got, []string{"show version"}) {
		t.Errorf("Commands() = %q: the wrapper command is not a command line", got)
	}

	c := dial(t, f.target())
	if _, err := c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeExec), devssh.WithCommand("cli")); err == nil {
		t.Error("WithCommand on an exec session must be refused")
	}
	if _, err := c.CLI(devssh.VendorJuniper, devssh.WithCommand("cli\nreboot")); err == nil {
		t.Error("a two-line command must be refused")
	}
	// Without WithMode the command makes it a shell session.
	s2, err := c.CLI(devssh.VendorJuniper, devssh.WithCommand("cli"))
	if err != nil {
		t.Fatalf("CLI with WithCommand: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if got, err := s2.Run(bg(), "show version"); err != nil || !strings.HasPrefix(got, "Hostname: sw1\n") {
		t.Fatalf("show version = %q, %v", got, err)
	}
}

func TestShellRefusesQuestionMarkInConfigure(t *testing.T) {
	f := newJunosFake(t)
	s := f.open()
	if _, err := s.Run(bg(), "configure"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(bg(), "set system ?"); err == nil {
		t.Error("'?' must be refused in a shell session")
	}
	if got := s.Commands(); !equalStrings(got, []string{"configure"}) {
		t.Errorf("a refused command was logged: %q", got)
	}
}

func TestClientLocalAddr(t *testing.T) {
	f := newJunosFake(t)
	c := dial(t, f.target())
	if ip := c.LocalAddr(); !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("LocalAddr() = %v, want 127.0.0.1", ip)
	}
}

func TestAlgorithmMismatchIsItsOwnError(t *testing.T) {
	dir := transcript(t, map[string]string{"prompt": "rtr1#"})
	srv := serve(t, dir, fakedev.WithKeyExchanges(ssh.InsecureKeyExchangeDH1SHA1))
	_, err := devssh.Dial(bg(), target(t, srv, nil))
	var ae devssh.AlgorithmError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want an AlgorithmError", err)
	}
	if !errors.Is(err, devssh.ErrHandshake) {
		t.Errorf("an AlgorithmError is an ErrHandshake: %v", err)
	}
	if !strings.Contains(ae.Detail, "no common algorithm for key exchange") || strings.Contains(ae.Detail, "offered") {
		t.Errorf("detail = %q", ae.Detail)
	}
	if errors.Is(err, devssh.ErrAuth) || errors.Is(err, devssh.ErrTimeout) {
		t.Errorf("wrong class: %v", err)
	}
	// A device that closes the connection is an ErrHandshake and no
	// AlgorithmError.
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tg := target(t, srv, nil)
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	tg.Host = host
	tg.Port, _ = strconv.Atoi(port)
	_, err = devssh.Dial(bg(), tg)
	if !errors.Is(err, devssh.ErrHandshake) || errors.As(err, &ae) {
		t.Errorf("a closed connection: err = %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A shell session tells its prompt area (PromptArea): the lines the device
// prints before every prompt, which Run drops from the output. While a
// confirmed commit is pending a Junos device prints its banner there in
// every session (0.2.9 lab L2), and the banner is not in Run's output.
func TestPromptAreaHoldsThePendingBanner(t *testing.T) {
	dir := transcript(t, map[string]string{"config.set": "set system host-name sw1\nset snmp contact a\n"})
	clk := fakedev.NewFakeClock(time.Date(2026, 10, 13, 14, 0, 0, 0, time.UTC))
	srv := serve(t, dir, fakedev.WithClock(clk))
	c := dial(t, target(t, srv, nil))
	held, err := c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	area := func(s devssh.CLISession) []string {
		t.Helper()
		pa, ok := s.(devssh.PromptArea)
		if !ok {
			t.Fatal("a shell session is no PromptArea")
		}
		l, ok := pa.PromptArea()
		if !ok {
			t.Fatal("no prompt area after a command")
		}
		return l
	}
	if _, ok := held.(devssh.PromptArea).PromptArea(); ok {
		t.Error("a prompt area before any command")
	}
	if _, err := other.Run(bg(), "show system commit"); err != nil {
		t.Fatal(err)
	}
	if got := area(other); !equalStrings(got, []string{"{master:0}"}) {
		t.Errorf("no commit pending: %q", got)
	}
	for _, cmd := range []string{"configure exclusive", "set snmp contact b"} {
		if _, err := held.Run(bg(), cmd); err != nil {
			t.Fatal(err)
		}
	}
	out, err := held.Run(bg(), "commit confirmed 5")
	if err != nil {
		t.Fatal(err)
	}
	banner := "# commit confirmed will be rolled back in 5 minutes"
	if strings.Contains(out, banner) || !strings.HasSuffix(out, "commit complete\n\n{master:0}[edit]\n") {
		t.Errorf("the output holds the banner or lost its end: %q", out)
	}
	if got := area(held); !equalStrings(got, []string{banner}) {
		t.Errorf("the held session's prompt area: %q", got)
	}
	out, err = other.Run(bg(), "show system commit")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, banner) {
		t.Errorf("the output holds the banner: %q", out)
	}
	if got := area(other); !equalStrings(got, []string{banner, "{master:0}"}) {
		t.Errorf("another session's prompt area: %q", got)
	}
}
