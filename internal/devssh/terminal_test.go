package devssh_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devssh"
)

// openTerm starts the scripted device and opens a terminal session on it.
func openTerm(t *testing.T, d *scripted, quiet time.Duration) (devssh.TermSession, *devssh.Client) {
	t.Helper()
	tg, stop := d.start(t)
	t.Cleanup(stop)
	tg.Quiet = quiet
	c := dial(t, tg)
	s, err := c.Terminal(bg())
	if err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c
}

func contains(sub string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, sub) }
}

func suffix(sub string) func(string) bool {
	return func(s string) bool { return strings.HasSuffix(s, sub) }
}

func never(string) bool { return false }

// within is a context with a deadline, for a call that must not hang.
func within(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg(), d)
	t.Cleanup(cancel)
	return ctx
}

const (
	esc       = "\x1b"
	clearScr  = esc + "[2J" + esc + "[H"
	pagerHelp = "Enter: SPACE for page, ENTER for line"
	footer    = "Enter: #<CR> to change,\r\n<ESC> to exit and save configuration"
)

// menuProgram is a tiny menu device: a banner and a continue question, the
// port list and the prompt 'DSM> ', commands that start with '/', a help
// that pages and a network menu that repaints a whole screen per key.
func menuProgram(d *scripted) func(ch ssh.Channel) {
	return func(ch ssh.Channel) {
		w := func(s string) { _, _ = io.WriteString(ch, s) }
		key := func() (byte, bool) { return d.readByte(ch) }
		w(esc + "[1mWELCOME" + esc + "[0m\r\nAuthorized users only\r\n" +
			"Do you wish to continue? (<CR> to continue, /X to exit)")
		for {
			b, ok := key()
			if !ok {
				return
			}
			if b == '\r' {
				break
			}
		}
		w("\r\nPORT  NAME\r\n 1    console\r\nDSM> ")
		var line []byte
		for {
			b, ok := key()
			if !ok {
				return
			}
			if b != '\r' {
				line = append(line, b)
				continue
			}
			cmd := string(line)
			line = line[:0]
			switch cmd {
			case "/H":
				pages := []string{"HELP 1\r\n/H help\r\n/N network\r\n", "HELP 2\r\n/F system\r\n", "HELP 3\r\n/X exit\r\n"}
				for i, p := range pages {
					w(clearScr + p)
					if i == len(pages)-1 {
						break
					}
					w(pagerHelp)
					k, ok := key()
					if !ok {
						return
					}
					if k == 0x1b {
						break
					}
					w("\r" + strings.Repeat(" ", len(pagerHelp)) + "\r")
				}
				w("\r\nDSM> ")
			case "/N":
				w(clearScr + "NETWORK PARAMETERS\r\n 1.  IP Address:  192.0.2.7\r\n 2.  Subnet Mask:  255.255.255.0\r\n" + footer)
				for {
					k, ok := key()
					if !ok {
						return
					}
					if k == '>' {
						w(clearScr + "NETWORK PARAMETERS (2)\r\n 5.  IP Tables:  On\r\n" + footer)
						continue
					}
					if k == 0x1b {
						w("\r\nSaving configuration to flash - Please wait...\r\nDSM> ")
						break
					}
				}
			case "/X":
				_ = ch.Close()
				return
			default:
				w("\r\nDSM> ")
			}
		}
	}
}

func TestTerminalMenuSession(t *testing.T) {
	d := &scripted{}
	d.raw = menuProgram(d)
	s, _ := openTerm(t, d, 100*time.Millisecond)
	ctx := within(t, 20*time.Second)

	// The banner: styled text, one question, no prompt.
	got, err := s.Expect(ctx, contains("Do you wish to continue?"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "WELCOME\nAuthorized users only\nDo you wish to continue? (<CR> to continue, /X to exit)"; got != want {
		t.Fatalf("banner = %q, want %q", got, want)
	}
	if err := s.Send(ctx, []byte("\r")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, suffix("DSM> "))
	if err != nil || got != "\nPORT  NAME\n 1    console\nDSM> " {
		t.Fatalf("port list = %q, %v", got, err)
	}

	// A paged help: the pager is answered with SPACE, ESC ends it.
	if err := s.Send(ctx, []byte("/H\r")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, contains(pagerHelp))
	if err != nil || got != "HELP 1\n/H help\n/N network\n"+pagerHelp {
		t.Fatalf("help 1 = %q, %v", got, err)
	}
	if err := s.Send(ctx, []byte(" ")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, contains(pagerHelp))
	if err != nil || got != strings.Repeat(" ", len(pagerHelp))+"\nHELP 2\n/F system\n"+pagerHelp {
		// The erase of the pager prompt (CR, blanks, CR) and the next
		// page are the text since the SPACE, in order.
		t.Fatalf("help 2 = %q, %v", got, err)
	}
	if err := s.Send(ctx, []byte(" ")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, suffix("DSM> "))
	if err != nil || !strings.Contains(got, "HELP 3\n/X exit\n") || !strings.HasSuffix(got, "\nDSM> ") {
		t.Fatalf("help 3 = %q, %v", got, err)
	}

	// A menu page that repaints per key; ESC and '>' reach the device.
	if err := s.Send(ctx, []byte("/N\r")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, contains("<ESC> to exit and save configuration"))
	if err != nil || !strings.HasPrefix(got, "NETWORK PARAMETERS\n 1.  IP Address:  192.0.2.7\n") {
		t.Fatalf("network = %q, %v", got, err)
	}
	if err := s.Send(ctx, []byte(">")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Expect(ctx, contains("5.  IP Tables:  On"))
	if err != nil || strings.Contains(got, "IP Address") {
		t.Fatalf("network 2 = %q, %v", got, err)
	}
	if err := s.Send(ctx, []byte(esc)); err != nil {
		t.Fatal(err)
	}
	// No predicate: the screen ends when the device falls silent.
	got, err = s.Expect(ctx, nil)
	if err != nil || got != "\nSaving configuration to flash - Please wait...\nDSM> " {
		t.Fatalf("after ESC = %q, %v", got, err)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if r, want := d.received(), "\r/H\r  /N\r>"+esc; r != want {
		t.Errorf("the device read %q, want %q", r, want)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ptys) != 1 || d.ptys[0] != "vt100 80x24" {
		t.Errorf("pty requests %q, want one vt100 80x24", d.ptys)
	}
}

// What the scanner makes of a device's bytes, as the text since the Send.
func TestTerminalScreenText(t *testing.T) {
	type chunks []string
	cases := []struct {
		name string
		raw  chunks
		want string
	}{
		{"plain lines", chunks{"plain\r\ntext\r\n"}, "plain\ntext\n"},
		{"lone line feed", chunks{"a\nb"}, "a\nb"},
		{"colour", chunks{esc + "[1;31mred" + esc + "[0m done"}, "red done"},
		{"carriage return overwrites", chunks{"abc\rX"}, "Xbc"},
		{"pager erase", chunks{"--More--\r        \rnext\r\n"}, "next    \n"},
		{"backspace", chunks{"abc\b\bX"}, "aXc"},
		{"clear screen starts a line", chunks{"x" + esc + "[2Jy"}, "x\ny"},
		{"home then clear", chunks{"title" + esc + "[H" + esc + "[2Jbody\r\n"}, "title\nbody\n"},
		{"erase to end of line", chunks{"keep" + esc + "[2D" + esc + "[Kz"}, "kez"},
		{"cursor forward is a gap", chunks{"x" + esc + "[5Cy"}, "x y"},
		{"escape split over reads", chunks{"a" + esc, "[3", "1mb"}, "ab"},
		{"osc with bel", chunks{esc + "]0;title\x07shown"}, "shown"},
		{"osc with st", chunks{esc + "]0;t" + esc + "\\shown"}, "shown"},
		{"charset select", chunks{esc + "(Bx"}, "x"},
		{"two byte escape", chunks{esc + "7x" + esc + "8y"}, "xy"},
		{"control bytes", chunks{"a\x00\x07\x7fb"}, "ab"},
		{"tab", chunks{"a\tb"}, "a b"},
		{"utf-8", chunks{"caf\xc3\xa9"}, "café"},
		{"a bare escape ends the sequence", chunks{"a" + esc + esc + "[0mb"}, "ab"},
	}
	var all [][]string
	for _, c := range cases {
		all = append(all, c.raw)
	}
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for _, parts := range all {
			if b, ok := d.readByte(ch); !ok || b != '\r' {
				return
			}
			for _, p := range parts {
				_, _ = io.WriteString(ch, p)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
	s, _ := openTerm(t, d, 120*time.Millisecond)
	ctx := within(t, 30*time.Second)
	for _, c := range cases {
		if err := s.Send(ctx, []byte("\r")); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := s.Expect(ctx, nil)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

// An Expect that returned on its predicate leaves the rest of the paint
// behind: the next Send starts a clean screen.
func TestTerminalSendStartsANewScreen(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for _, answer := range []string{"SCREEN1" + esc + "[24;1HTRAILER", "SCREEN2"} {
			if _, ok := d.readByte(ch); !ok {
				return
			}
			_, _ = io.WriteString(ch, answer)
		}
		// A third key is answered by nothing: the Expect below sees a
		// screen of its own or none.
	}
	s, _ := openTerm(t, d, 100*time.Millisecond)
	ctx := within(t, 10*time.Second)
	if err := s.Send(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Expect(ctx, contains("SCREEN1")); err != nil || !strings.HasPrefix(got, "SCREEN1") {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := s.Send(ctx, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Expect(ctx, contains("SCREEN2")); err != nil || got != "SCREEN2" {
		t.Fatalf("got %q, %v; want only the second screen", got, err)
	}
	// A second Expect with no Send continues the screen.
	if got, err := s.Expect(ctx, contains("SCREEN2")); err != nil || got != "SCREEN2" {
		t.Fatalf("second Expect: %q, %v", got, err)
	}
}

func TestTerminalSendRefusals(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for {
			if _, ok := d.readByte(ch); !ok {
				return
			}
		}
	}
	s, _ := openTerm(t, d, 50*time.Millisecond)
	for name, p := range map[string][]byte{
		"empty":         nil,
		"ctrl-c":        []byte("a\x03"),
		"ctrl-d":        []byte("\x04"),
		"nul":           []byte("a\x00b"),
		"tab":           []byte("a\tb"),
		"backspace":     []byte("\b"),
		"del":           []byte("\x7f"),
		"c1 control":    []byte("a\u009bb"),
		"invalid utf-8": []byte("a\xffb"),
		"too long":      []byte(strings.Repeat("x", 64<<10+1)),
	} {
		if err := s.Send(bg(), p); err == nil || errors.Is(err, devssh.ErrClosed) {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
	}
	// Refusing leaves the session usable, and nothing was written.
	if err := s.Send(bg(), []byte("ok"+esc+"<>\r\n /N 28 8\r")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	want := "ok" + esc + "<>\r\n /N 28 8\r"
	for d.received() != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := d.received(); got != want {
		t.Errorf("the device read %q, want %q", got, want)
	}
}

// A quiet device: the contract of waiting. Output that stops is a screen
// (the caller checks it); no output at all is the deadline.
func TestTerminalQuietAndHang(t *testing.T) {
	t.Run("output then silence returns after the quiet period", func(t *testing.T) {
		d := &scripted{}
		d.raw = func(ch ssh.Channel) { _, _ = io.WriteString(ch, "partial") }
		s, _ := openTerm(t, d, 80*time.Millisecond)
		start := time.Now()
		got, err := s.Expect(within(t, 10*time.Second), never)
		if err != nil || got != "partial" {
			t.Fatalf("got %q, %v", got, err)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("returned after %v", el)
		}
		// The session is still usable.
		if err := s.Send(bg(), []byte("\r")); err != nil {
			t.Errorf("Send after a quiet return: %v", err)
		}
	})
	t.Run("a device that says nothing costs the deadline and closes", func(t *testing.T) {
		d := &scripted{}
		d.raw = func(ch ssh.Channel) {
			for {
				if _, ok := d.readByte(ch); !ok {
					return
				}
			}
		}
		s, _ := openTerm(t, d, 50*time.Millisecond)
		start := time.Now()
		got, err := s.Expect(within(t, 400*time.Millisecond), nil)
		if !errors.Is(err, devssh.ErrTimeout) || got != "" {
			t.Fatalf("got %q, %v; want ErrTimeout", got, err)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("returned after %v", el)
		}
		if err := s.Send(bg(), []byte("x")); !errors.Is(err, devssh.ErrClosed) {
			t.Errorf("Send after the deadline: %v, want ErrClosed", err)
		}
		if _, err := s.Expect(bg(), nil); !errors.Is(err, devssh.ErrClosed) {
			t.Errorf("Expect after the deadline: %v, want ErrClosed", err)
		}
	})
	t.Run("a device that drips output past the quiet period is waited for", func(t *testing.T) {
		d := &scripted{}
		d.raw = func(ch ssh.Channel) {
			for range 6 {
				_, _ = io.WriteString(ch, "tick ")
				time.Sleep(40 * time.Millisecond)
			}
			_, _ = io.WriteString(ch, "END")
		}
		s, _ := openTerm(t, d, 300*time.Millisecond)
		got, err := s.Expect(within(t, 10*time.Second), suffix("END"))
		if err != nil || got != "tick tick tick tick tick tick END" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

func TestTerminalEOFMidScreen(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "SNMP Read-Only Community:  hunter2-community")
		_ = ch.Close()
	}
	s, _ := openTerm(t, d, 60*time.Millisecond)
	got, err := s.Expect(within(t, 10*time.Second), never)
	if !errors.Is(err, devssh.ErrClosed) || got != "" {
		t.Fatalf("got %q, %v; want ErrClosed and no screen", got, err)
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "Community") {
		t.Errorf("the error carries the screen: %v", err)
	}
	if err := s.Send(bg(), []byte("x")); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("Send: %v, want ErrClosed", err)
	}
}

// The predicate wins over the channel ending in the same read: a screen
// that was complete is not lost to the close behind it.
func TestTerminalLastScreenBeforeClose(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "Goodbye\r\n")
		_ = ch.Close()
	}
	s, _ := openTerm(t, d, 60*time.Millisecond)
	got, err := s.Expect(within(t, 10*time.Second), contains("Goodbye"))
	if err != nil && !errors.Is(err, devssh.ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	if err == nil && got != "Goodbye\n" {
		t.Fatalf("got %q", got)
	}
}

func TestTerminalHugeSingleLine(t *testing.T) {
	line := strings.Repeat("y", 3<<20)
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for off := 0; off < len(line); off += 16 << 10 {
			_, _ = io.WriteString(ch, line[off:min(off+16<<10, len(line))])
		}
		_, _ = io.WriteString(ch, "\r\nDSM> ")
	}
	s, _ := openTerm(t, d, 100*time.Millisecond)
	calls := 0
	got, err := s.Expect(within(t, 60*time.Second), func(sc string) bool { calls++; return strings.HasSuffix(sc, "DSM> ") })
	if err != nil || len(got) != len(line)+len("\nDSM> ") || !strings.HasSuffix(got, "yyy\nDSM> ") {
		t.Fatalf("len %d, err %v", len(got), err)
	}
	// The predicate is not run once per kilobyte of a huge line.
	if calls > 400 {
		t.Errorf("the predicate ran %d times", calls)
	}
}

// A device cannot make the client hold more than MaxOutput since the last
// Send; the session is closed and the error names no output.
func TestTerminalOutputOverflow(t *testing.T) {
	if testing.Short() {
		t.Skip("writes more than MaxOutput")
	}
	for name, chunk := range map[string]string{
		"one endless line": strings.Repeat("z", 256<<10),
		"many lines":       strings.Repeat(strings.Repeat("z", 99)+"\r\n", 2600),
	} {
		t.Run(name, func(t *testing.T) {
			d := &scripted{}
			d.raw = func(ch ssh.Channel) {
				for sent := 0; sent <= devssh.MaxOutput+len(chunk); sent += len(chunk) {
					if _, err := io.WriteString(ch, chunk); err != nil {
						return
					}
				}
			}
			s, _ := openTerm(t, d, 100*time.Millisecond)
			start := time.Now()
			got, err := s.Expect(within(t, 90*time.Second), never)
			if !errors.Is(err, devssh.ErrOutputTooLarge) || got != "" {
				t.Fatalf("len %d, err %v; want ErrOutputTooLarge", len(got), err)
			}
			if strings.Contains(err.Error(), "zzzz") {
				t.Errorf("the error carries output")
			}
			t.Logf("overflow detected after %v", time.Since(start))
			if err := s.Send(bg(), []byte("x")); !errors.Is(err, devssh.ErrClosed) {
				t.Errorf("Send after the overflow: %v, want ErrClosed", err)
			}
		})
	}
}

func TestTerminalContextCancel(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "Enter: SPACE for page")
		for {
			if _, ok := d.readByte(ch); !ok {
				return
			}
		}
	}
	// A long quiet period: the cancel is what ends the call.
	s, _ := openTerm(t, d, 30*time.Second)
	ctx, cancel := context.WithCancel(bg())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	start := time.Now()
	got, err := s.Expect(ctx, never)
	if !errors.Is(err, context.Canceled) || got != "" {
		t.Fatalf("got %q, %v; want context.Canceled", got, err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("returned after %v", el)
	}
	if err := s.Send(bg(), []byte("x")); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("Send after the cancel: %v, want ErrClosed", err)
	}
	if got := d.received(); got != "" {
		t.Errorf("the device read %q", got)
	}
}

// A context that is done touches nothing: no key is typed.
func TestTerminalDoneContextSendsNothing(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for {
			if _, ok := d.readByte(ch); !ok {
				return
			}
		}
	}
	s, _ := openTerm(t, d, 50*time.Millisecond)
	done, cancel := context.WithCancel(bg())
	cancel()
	if err := s.Send(done, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Errorf("Send with a done context: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := d.received(); got != "" {
		t.Errorf("the device read %q", got)
	}
}

// Close may come at any time, from another goroutine, and sends nothing.
func TestTerminalCloseAnytime(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "MENU")
		for {
			if _, ok := d.readByte(ch); !ok {
				return
			}
		}
	}
	s, _ := openTerm(t, d, 5*time.Second)
	// MENU has arrived but the quiet period is long: Expect is waiting.
	res := make(chan error, 1)
	go func() {
		_, err := s.Expect(within(t, 30*time.Second), never)
		res <- err
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case err := <-res:
		if !errors.Is(err, devssh.ErrClosed) {
			t.Errorf("Expect after Close: %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Expect did not return after Close")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("Close took %v", el)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := s.Send(bg(), []byte("x")); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("Send after Close: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := d.received(); got != "" {
		t.Errorf("Close sent %q", got)
	}
}

// The client's context ending ends the session.
func TestTerminalClientContext(t *testing.T) {
	d := &scripted{}
	d.raw = func(ch ssh.Channel) {
		for {
			if _, ok := d.readByte(ch); !ok {
				return
			}
		}
	}
	tg, stop := d.start(t)
	defer stop()
	ctx, cancel := context.WithCancel(bg())
	c, err := devssh.Dial(ctx, tg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := c.Terminal(bg())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := s.Expect(bg(), nil); err == nil {
		t.Error("Expect on a cancelled client succeeded")
	}
	if _, err := c.Terminal(bg()); err == nil {
		t.Error("Terminal on a cancelled client succeeded")
	}
}
