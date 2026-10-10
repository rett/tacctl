package devssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// step is one write of a scripted device and the pause after it.
type step struct {
	data  string
	pause time.Duration
	// key: after the write, read one byte of input and discard it (a
	// pager waiting for a key).
	key bool
}

// scripted is a device that does what its script says, byte for byte:
// the hostile and the merely odd devices fakedev's transcripts cannot be.
type scripted struct {
	login   []step
	perCmd  func(cmd string) []step // shell: the answer to one line
	rounds  [][]string              // keyboard-interactive: prompts per round
	version string
	// freezeAfterBlanks: after this many empty lines the device stops
	// reading its input for good (0: never).
	freezeAfterBlanks int

	mu      sync.Mutex
	answers [][]string // what the client answered, per round
	pwSeen  []string   // passwords presented by the password method
	recv    []byte     // everything the shell read
	quit    chan struct{}
}

// received is what the device's shell has read so far.
func (d *scripted) received() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return string(d.recv)
}

// start runs the device and returns the Target for it (its key pinned).
func (d *scripted) start(t *testing.T) (devssh.Target, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	d.quit = make(chan struct{})
	cfg := &ssh.ServerConfig{ServerVersion: d.version}
	if d.rounds != nil {
		cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for _, prompts := range d.rounds {
				ans, err := ch("", "", prompts, make([]bool, len(prompts)))
				if err != nil {
					return nil, err
				}
				d.mu.Lock()
				d.answers = append(d.answers, ans)
				d.mu.Unlock()
			}
			return nil, errors.New("denied")
		}
	}
	cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		d.mu.Lock()
		d.pwSeen = append(d.pwSeen, string(pw))
		d.mu.Unlock()
		if string(pw) == fakedev.DefaultPassword {
			return nil, nil
		}
		return nil, errors.New("denied")
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	quit := make(chan struct{})
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = nc.Close() }()
				go func() { <-quit; _ = nc.Close() }()
				d.serve(nc, cfg)
			}()
		}
	}()
	stop := func() {
		close(quit)
		close(d.quit)
		_ = ln.Close()
		wg.Wait()
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return devssh.Target{
		Host: host, Port: p, User: fakedev.DefaultUser,
		HostKeys: []string{fakedev.KeyText(signer.PublicKey())}, ConnectTimeout: 5 * time.Second,
		Password: func() (string, error) { return fakedev.DefaultPassword, nil },
	}, stop
}

func (d *scripted) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newc := range chans {
		ch, rq, err := newc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range rq {
				_ = r.Reply(true, nil)
				if r.Type == "shell" && d.perCmd != nil {
					go d.shell(ch)
				}
			}
		}()
	}
}

func (d *scripted) shell(ch ssh.Channel) {
	one := make([]byte, 1)
	read := func() bool {
		if _, err := ch.Read(one); err != nil {
			return false
		}
		d.mu.Lock()
		d.recv = append(d.recv, one[0])
		d.mu.Unlock()
		return true
	}
	play := func(ss []step) bool {
		for _, s := range ss {
			_, _ = io.WriteString(ch, s.data)
			time.Sleep(s.pause)
			if s.key && !read() {
				return false
			}
		}
		return true
	}
	play(d.login)
	var line []byte
	blanks := 0
	for {
		if !read() {
			return
		}
		if one[0] != '\n' {
			line = append(line, one[0])
			continue
		}
		if len(line) == 0 {
			blanks++
		}
		if !play(d.perCmd(string(line))) {
			return
		}
		line = line[:0]
		if d.freezeAfterBlanks > 0 && blanks >= d.freezeAfterBlanks {
			<-d.quit
			return
		}
	}
}

// A last line of the output that is the prompt, at a write boundary: the
// device's real prompt follows. The sentinel's answer then makes three
// prompts for two commands' worth, and the read ends in an error, never in
// the truncated output; the session is closed.
func TestShellLastLineIsPrompt(t *testing.T) {
	d := &scripted{
		login: []step{{data: "banner\r\nrtr1#"}},
		perCmd: func(cmd string) []step {
			switch cmd {
			case "":
				return []step{{data: "\r\nrtr1#"}}
			case "show running-config":
				return []step{
					{data: cmd + "\r\nhostname rtr1\r\nrtr1#", pause: 100 * time.Millisecond},
					{data: "\r\nrtr1#"},
				}
			}
			return []step{{data: cmd + "\r\nout of " + cmd + "\r\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	c := dial(t, tg)
	s, err := c.CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show running-config")
	if !errors.Is(err, devssh.ErrProtocol) || got != "" {
		t.Fatalf("got %q, %v; want ErrProtocol and no output", got, err)
	}
	if _, err := s.Run(bg(), "show version"); !errors.Is(err, devssh.ErrClosed) {
		t.Fatalf("after the error: %v, want ErrClosed", err)
	}
}

// A prompt-looking line in the middle of the output, with more output
// after it, in two writes.
func TestShellPromptLookalikeMidOutput(t *testing.T) {
	d := &scripted{
		login: []step{{data: "banner\r\nrtr1#"}},
		perCmd: func(cmd string) []step {
			switch cmd {
			case "":
				return []step{{data: "\r\nrtr1#"}}
			case "show running-config":
				return []step{
					{data: cmd + "\r\nhostname rtr1\r\nbanner motd ^C\r\nrtr1#", pause: 200 * time.Millisecond},
					{data: "\r\n^C\r\nusername admin secret 9 HASH\r\nend\r\nrtr1#"},
				}
			}
			return []step{{data: cmd + "\r\nout of " + cmd + "\r\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	s, err := dial(t, tg).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show running-config")
	if err == nil {
		// Never a truncated output: it is whole or it is an error.
		if !strings.Contains(got, "username admin secret 9 HASH") || !strings.HasSuffix(got, "end\n") {
			t.Fatalf("truncated output returned as success: %q", got)
		}
	} else if !errors.Is(err, devssh.ErrProtocol) {
		t.Fatalf("err = %v", err)
	}
}

// A banner line that reads like the prompt, at a pause, is not the prompt:
// a short pause is bridged, a long one fails the login, and neither ever
// learns the banner line.
func TestShellBannerIsNotThePrompt(t *testing.T) {
	for name, pause := range map[string]time.Duration{
		"pause shorter than the quiet period": 40 * time.Millisecond,
		"pause longer than the quiet period":  400 * time.Millisecond,
	} {
		t.Run(name, func(t *testing.T) {
			d := &scripted{
				login: []step{{data: "##########", pause: pause}, {data: "\r\nAuthorized only\r\n##########\r\nrtr1#"}},
				perCmd: func(cmd string) []step {
					if cmd == "" {
						return []step{{data: "\r\nrtr1#"}}
					}
					return []step{{data: cmd + "\r\nout\r\nrtr1#"}}
				},
			}
			tg, stop := d.start(t)
			defer stop()
			tg.Quiet = 100 * time.Millisecond
			s, err := dial(t, tg).CLI(devssh.VendorCisco)
			if err != nil {
				if !errors.Is(err, devssh.ErrHandshake) {
					t.Fatalf("err = %v, want ErrHandshake or success", err)
				}
				return
			}
			if got, err := s.Run(bg(), "show version"); err != nil || got != "out\n" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

// Two banner lines that read like the prompt, at a pause.
func TestShellTwoBannerLinesAreNotThePrompt(t *testing.T) {
	for name, pause := range map[string]time.Duration{
		"short pause": 40 * time.Millisecond,
		"long pause":  400 * time.Millisecond,
	} {
		t.Run(name, func(t *testing.T) {
			d := &scripted{
				login: []step{{data: "####\r\n####", pause: pause}, {data: "\r\nrtr1#"}},
				perCmd: func(cmd string) []step {
					if cmd == "" {
						return []step{{data: "\r\nrtr1#"}}
					}
					return []step{{data: cmd + "\r\nout\r\nrtr1#"}}
				},
			}
			tg, stop := d.start(t)
			defer stop()
			tg.Quiet = 100 * time.Millisecond
			s, err := dial(t, tg).CLI(devssh.VendorCisco)
			if err != nil {
				if !errors.Is(err, devssh.ErrHandshake) {
					t.Fatalf("err = %v, want ErrHandshake or success", err)
				}
				return
			}
			if got, err := s.Run(bg(), "show version"); err != nil || got != "out\n" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

// Learning fails closed when it cannot be sure: a device that answers an
// empty line with two prompts, or with none.
func TestShellLearningAmbiguousOrSilent(t *testing.T) {
	for name, answer := range map[string][]step{
		"two prompts": {{data: "\r\nrtr1#\r\nrtr1#"}},
		"no prompt":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			d := &scripted{
				login:  []step{{data: "banner\r\nrtr1#"}},
				perCmd: func(string) []step { return answer },
			}
			tg, stop := d.start(t)
			defer stop()
			tg.Quiet = 60 * time.Millisecond
			start := time.Now()
			_, err := dial(t, tg).CLI(devssh.VendorCisco)
			if !errors.Is(err, devssh.ErrHandshake) {
				t.Fatalf("err = %v, want ErrHandshake", err)
			}
			if time.Since(start) > 3*time.Second {
				t.Error("login did not fail promptly")
			}
		})
	}
}

// A device that flushes what was typed ahead at login loses the first
// empty line: it is sent once more.
func TestShellLearningRetriesOnce(t *testing.T) {
	var blanks atomic.Int32
	d := &scripted{
		login: []step{{data: "banner\r\nrtr1#"}},
		perCmd: func(cmd string) []step {
			if cmd == "" {
				if blanks.Add(1) == 1 {
					return nil // flushed
				}
				return []step{{data: "\r\nrtr1#"}}
			}
			return []step{{data: cmd + "\r\nout\r\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	tg.Quiet = 60 * time.Millisecond
	s, err := dial(t, tg).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Run(bg(), "show version"); err != nil || got != "out\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// Junos switches print a line before every prompt.
func TestShellLinePrintedBeforeEachPrompt(t *testing.T) {
	d := &scripted{
		login: []step{{data: "Last login\r\n\r\n{master:0}\r\nu@sw1> "}},
		perCmd: func(cmd string) []step {
			if cmd == "" {
				return []step{{data: "\r\n{master:0}\r\nu@sw1> "}}
			}
			return []step{{data: cmd + "\r\nHostname: sw1\r\n{master:0}\r\nu@sw1> "}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	s, err := dial(t, tg).CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got, err := s.Run(bg(), "show version"); err != nil || got != "Hostname: sw1\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	}
}

// A more-prompt takes the empty line that was typed ahead (as the key
// that scrolls one line); the count starts again after it.
func TestShellPagerConsumesTypedAheadLine(t *testing.T) {
	const erase = "\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b"
	d := &scripted{
		login: []step{{data: "rtr1#"}},
		perCmd: func(cmd string) []step {
			switch cmd {
			case "":
				return []step{{data: "\r\nrtr1#"}}
			case "show big":
				return []step{
					{data: cmd + "\r\nline1\r\nrtr1#", pause: 100 * time.Millisecond},
					{data: "\r\nline2\r\n --More-- ", key: true}, // reads the typed-ahead blank
					{data: erase + "line3\r\n --More-- ", key: true},
					{data: erase + "line4\r\nrtr1#"},
				}
			}
			return []step{{data: cmd + "\r\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	tg.Quiet = 100 * time.Millisecond
	s, err := dial(t, tg).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show big")
	if err != nil || got != "line1\nrtr1#\nline2\nline3\nline4\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A more-prompt look-alike that is followed by more output at once is not
// answered: nothing is typed ahead into the next command.
func TestShellPagerLookalikeIsNotAnswered(t *testing.T) {
	d := &scripted{
		login: []step{{data: "rtr1#"}},
		perCmd: func(cmd string) []step {
			switch cmd {
			case "":
				return []step{{data: "\r\nrtr1#"}}
			case "show x":
				return []step{
					{data: cmd + "\r\na\r\n --More-- ", pause: 3 * time.Millisecond},
					{data: "\r\nb\r\nrtr1#"},
				}
			}
			return []step{{data: cmd + "\r\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	tg.Quiet = 200 * time.Millisecond
	s, err := dial(t, tg).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show x")
	if err != nil || got != "a\n --More-- \nb\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	// What the device read: the two empty lines (login, command) and the
	// command itself; no key.
	if r := d.received(); r != "\nshow x\n\n" {
		t.Errorf("the device read %q", r)
	}
}

// A device that stops reading: a write that blocks ends with the context
// (the client is closed), and Close returns promptly.
func TestShellWriteBlockedOnDevice(t *testing.T) {
	d := &scripted{
		login:             []step{{data: "rtr1#"}},
		perCmd:            func(string) []step { return []step{{data: "\r\nrtr1#"}} },
		freezeAfterBlanks: 1,
	}
	tg, stop := d.start(t)
	defer stop()
	tg.Quiet = 60 * time.Millisecond
	c := dial(t, tg)
	s, err := c.CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.Run(ctx, "show "+strings.Repeat("x", 3<<20))
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Run returned after %v", d)
	}
	closed := make(chan struct{})
	go func() { _ = s.Close(); _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked")
	}
}

// A device that does not echo the empty line answers it with the prompt
// on the same line.
func TestShellNoEchoOfEmptyLine(t *testing.T) {
	d := &scripted{
		login: []step{{data: "rtr1#"}},
		perCmd: func(cmd string) []step {
			if cmd == "" {
				return []step{{data: "rtr1#"}}
			}
			return []step{{data: "out of " + cmd + "\nrtr1#"}}
		},
	}
	tg, stop := d.start(t)
	defer stop()
	s, err := dial(t, tg).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got, err := s.Run(bg(), "show version"); err != nil || got != "out of show version\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	}
}

func TestKeyboardInteractiveRoundsAndOTP(t *testing.T) {
	t.Run("a repeated password prompt gets the password once", func(t *testing.T) {
		d := &scripted{rounds: [][]string{{"Password: "}, {"Password: "}, {"Password: "}}}
		tg, stop := d.start(t)
		defer stop()
		var calls atomic.Int32
		src := tg.Password
		tg.Password = func() (string, error) { calls.Add(1); return src() }
		if _, err := devssh.Dial(bg(), tg); !errors.Is(err, devssh.ErrAuth) {
			t.Fatalf("err = %v, want ErrAuth", err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.answers) < 2 || d.answers[0][0] != fakedev.DefaultPassword {
			t.Fatalf("answers %q", d.answers)
		}
		for _, a := range d.answers[1:] {
			if a[0] != "" {
				t.Errorf("the password was sent again: %q", d.answers)
			}
		}
		if len(d.pwSeen) != 0 || calls.Load() != 1 {
			t.Errorf("password method saw %q, source called %d times", d.pwSeen, calls.Load())
		}
	})
	t.Run("a one-time password prompt gets nothing", func(t *testing.T) {
		d := &scripted{rounds: [][]string{{"Enter one-time password: "}}}
		tg, stop := d.start(t)
		defer stop()
		// The device then offers the password method, which is where the
		// password is sent, once; the OTP prompt itself got nothing.
		c, err := devssh.Dial(bg(), tg)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.answers) != 1 || d.answers[0][0] != "" {
			t.Errorf("answers %q", d.answers)
		}
		if len(d.pwSeen) != 1 || d.pwSeen[0] != fakedev.DefaultPassword {
			t.Errorf("password method saw %q", d.pwSeen)
		}
	})
}

func TestServerVersionIsCleaned(t *testing.T) {
	d := &scripted{version: "SSH-2.0-evil\x1b[2Jtext"}
	tg, stop := d.start(t)
	defer stop()
	c, err := devssh.Dial(bg(), tg)
	if err != nil {
		t.Skipf("the client refuses such a banner outright: %v", err)
	}
	defer func() { _ = c.Close() }()
	if v := c.ServerVersion(); strings.ContainsFunc(v, unicode.IsControl) {
		t.Errorf("ServerVersion holds a control character: %q", v)
	}
}
