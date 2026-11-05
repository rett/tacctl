package devssh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A shell whose device is a script in the test: the shell types into a pipe,
// the script reads the lines it typed and writes the output in chunks of its
// own, each one a separate write into the shell's sink, as the channel
// delivers them. A script waits for something the shell typed, not for a
// time, wherever it can: slowLogin reads both empty lines of the login before
// it answers, so the shell's retry is certain, and the late answer is then
// released by the test or by the command the shell types. Two places depend
// on the shell's quiet period, the real timer, and say so: the gaps of
// TestGapsInTheAnswerAreNoMatter are sleeps on purpose, and a login that
// answers its one line at once (loginAnsweredAtOnce) can be slowed by a
// stalled machine into the retry, which the script then answers like the
// first line (command).

// lateAns is what a Junos virtual chassis answers an empty line with: the
// line the device prints before every prompt, and the prompt.
const lateAns = "\r\n{master:0}\r\nalice@rtr1> "

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// lineDev is the device end of a pipe.
type lineDev struct {
	out   *sink
	mu    sync.Mutex
	part  []byte
	lines chan string
	done  chan struct{}
}

func newLineDev(t *testing.T) *lineDev {
	d := &lineDev{out: newSink(), lines: make(chan string, 64), done: make(chan struct{})}
	t.Cleanup(func() { close(d.done) })
	return d
}

// Write is the shell's input: the lines it types.
func (d *lineDev) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, b := range p {
		if b != '\n' {
			d.part = append(d.part, b)
			continue
		}
		d.lines <- string(d.part)
		d.part = d.part[:0]
	}
	return len(p), nil
}

// say is one chunk of output.
func (d *lineDev) say(s string) { _, _ = d.out.Write([]byte(s)) }

// next is the next line the shell typed; "" and false when the test is over.
// The wait for it is not a measure of time: a shell that never types it fails
// the test by what it returned.
func (d *lineDev) next() (string, bool) {
	select {
	case l := <-d.lines:
		return l, true
	case <-d.done:
		return "", false
	}
}

// arrived waits until the shell's sink holds n bytes at least (the chunk
// has reached it and nobody has taken it).
func (d *lineDev) arrived(t *testing.T, n int) {
	t.Helper()
	for {
		d.out.mu.Lock()
		got := len(d.out.buf)
		d.out.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-d.out.notify:
		case <-time.After(10 * time.Second):
			t.Fatalf("the chunk of %d bytes never reached the shell's sink", n)
		}
	}
}

// openScripted opens a Junos shell on a device that plays script; the script
// goes on running after the shell is open.
func openScripted(t *testing.T, quiet time.Duration, script func(d *lineDev)) (*shell, *lineDev) {
	t.Helper()
	d := newLineDev(t)
	go script(d)
	c := &Client{addr: "rtr1", ctx: context.Background(), quiet: quiet, timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sh, err := c.learnShell(ctx, profiles[VendorJuniper], d.out, nopCloser{}, d)
	if err != nil {
		t.Fatalf("learning the prompt: %v", err)
	}
	t.Cleanup(func() { sh.broken.Store(true) })
	return sh, d
}

// slowLogin plays the login of a device whose answers to the two empty lines
// the shell types come late: the first one after the shell sent the second
// (so the shell sees one answer to two lines, and the other still on its
// way). It returns when both lines have been read.
func slowLogin(d *lineDev) bool {
	d.say("banner\r\nalice@rtr1> ")
	if _, ok := d.next(); !ok { // the empty line
		return false
	}
	if _, ok := d.next(); !ok { // and, when nothing came back, once more
		return false
	}
	d.say(lateAns) // the answer to the first
	return true
}

// command is the next command the shell types. A login that answers its
// first empty line without a stall never sees the retry; on a machine that
// stalls longer than the quiet period the shell types a second empty line
// first, and the script answers it like the first (the device answers every
// line it is given), so the answers account for the lines either way.
func command(d *lineDev) (string, bool) {
	for {
		l, ok := d.next()
		if !ok {
			return "", false
		}
		if l != "" {
			return l, true
		}
		d.say(lateAns)
	}
}

// answer plays the command's answer after its echo: the output, the prompt,
// the typed-ahead empty line and the prompt it is answered with.
func answer(d *lineDev, cmd string) {
	d.say(cmd + "\r\n")
	d.say("out\r\n")
	d.say("\r\n{master:0}\r\nalice@rtr1> ")
	if _, ok := d.next(); !ok {
		return
	}
	d.say(lateAns)
}

const wantOut = "out\n\n"

func runCmd(t *testing.T, sh *shell, cmd string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := sh.Run(ctx, cmd)
	if err != nil {
		t.Fatalf("Run(%q): %v", cmd, err)
	}
	return got
}

// The device answers the second empty line, the retry, after the shell has
// learned the prompt from the answer to the first: the answer is in flight
// when the first command is typed, and it arrives in front of the command's
// echo. The first line of the command's answer must still be the echo, not
// the prompt followed by the echo ('configure exclusive' failed on a
// satellite link with 'alice@rtr1> configure exclusive' as its first line).
func TestLateAnswerArrivesAfterTheCommandWasTyped(t *testing.T) {
	t.Parallel()
	sh, _ := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
		if !slowLogin(d) {
			return
		}
		cmd, ok := d.next()
		if !ok {
			return
		}
		d.say(lateAns) // the answer to the retry, at last, before the echo
		answer(d, cmd)
	})
	if got := runCmd(t, sh, "show system commit"); got != wantOut {
		t.Errorf("got %q, want %q", got, wantOut)
	}
}

// The same, with the late answer in the sink before the command is typed:
// the shell takes it for output between commands.
func TestLateAnswerArrivesBeforeTheCommandIsTyped(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	sh, d := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
		if !slowLogin(d) {
			return
		}
		select {
		case <-release:
		case <-d.done:
			return
		}
		d.say(lateAns)
		cmd, ok := d.next()
		if !ok {
			return
		}
		answer(d, cmd)
	})
	close(release)
	d.arrived(t, len(lateAns))
	if got := runCmd(t, sh, "show system commit"); got != wantOut {
		t.Errorf("got %q, want %q", got, wantOut)
	}
}

// The late answer in pieces, at the places that matter: the first piece is
// in the sink when the command is typed, the others arrive after it, in
// front of the echo.
func TestLateAnswerInPieces(t *testing.T) {
	t.Parallel()
	for name, pieces := range map[string][2]string{
		"the line break first":        {"\r\n", "{master:0}\r\nalice@rtr1> "},
		"the area line first":         {"\r\n{master:0}\r\n", "alice@rtr1> "},
		"the area line and the start": {"\r\n{master:0}\r\nalice@r", "tr1> "},
		"all but the last blank":      {"\r\n{master:0}\r\nalice@rtr1>", " "},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			release := make(chan struct{})
			sh, d := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
				if !slowLogin(d) {
					return
				}
				select {
				case <-release:
				case <-d.done:
					return
				}
				d.say(pieces[0])
				cmd, ok := d.next()
				if !ok {
					return
				}
				d.say(pieces[1])
				answer(d, cmd)
			})
			close(release)
			d.arrived(t, len(pieces[0]))
			if got := runCmd(t, sh, "show system commit"); got != wantOut {
				t.Errorf("got %q, want %q", got, wantOut)
			}
		})
	}
}

// While a confirmed commit is pending a Junos device prints a banner line
// before every prompt, the minutes left in it (singular for one). The login
// that verifies a change runs in that state, so the late answer holds it:
// before the command is typed, after, and in pieces cut at the banner.
func TestLateAnswerWithAPendingConfirmedCommit(t *testing.T) {
	t.Parallel()
	for _, mins := range []string{"1 minute", "5 minutes", "12 minutes"} {
		banner := "# commit confirmed will be rolled back in " + mins
		area := "\r\n" + banner + "\r\n{master:0}\r\n"
		ans := area + "alice@rtr1> "
		for name, pieces := range map[string][2]string{
			"before the command is typed": {ans, ""},
			"after the command is typed":  {"", ans},
			"cut after the banner line":   {"\r\n" + banner + "\r\n", "{master:0}\r\nalice@rtr1> "},
			"cut after the line break":    {"\r\n", banner + "\r\n{master:0}\r\nalice@rtr1> "},
		} {
			t.Run(mins+", "+name, func(t *testing.T) {
				t.Parallel()
				release := make(chan struct{})
				sh, d := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
					d.say(ans[2:]) // the login's own prompt has the banner too
					if _, ok := d.next(); !ok {
						return
					}
					if _, ok := d.next(); !ok { // and the retry
						return
					}
					d.say(ans) // the answer to the first
					select {
					case <-release:
					case <-d.done:
						return
					}
					d.say(pieces[0])
					cmd, ok := d.next()
					if !ok {
						return
					}
					d.say(pieces[1])
					d.say(cmd + "\r\nout\r\n")
					d.say(ans)
					if _, ok := d.next(); !ok {
						return
					}
					d.say(ans)
				})
				close(release)
				d.arrived(t, len(pieces[0]))
				if got := runCmd(t, sh, "show system commit"); got != wantOut {
					t.Errorf("got %q, want %q", got, wantOut)
				}
			})
		}
	}
}

// A session that has the late answer in front of the echo of the command that
// leads to the other mode (the 'configure exclusive' of the report) is in
// that mode afterwards.
func TestLateAnswerInFrontOfAModeChange(t *testing.T) {
	t.Parallel()
	sh, _ := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
		if !slowLogin(d) {
			return
		}
		cmd, ok := d.next()
		if !ok {
			return
		}
		d.say(lateAns)
		d.say(cmd + "\r\n")
		d.say("warning: uncommitted changes will be discarded on exit\r\n")
		d.say("Entering configuration mode\r\n")
		d.say("\r\n{master:0}[edit]\r\nalice@rtr1# ")
		if _, ok := d.next(); !ok {
			return
		}
		d.say("\r\n{master:0}[edit]\r\nalice@rtr1# ")
	})
	want := "warning: uncommitted changes will be discarded on exit\nEntering configuration mode\n\n{master:0}[edit]\n"
	if got := runCmd(t, sh, "configure exclusive"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if sh.prompt != "alice@rtr1# " {
		t.Errorf("the session is in the mode of %q", sh.prompt)
	}
}

// What stands in front of the echo is the late answer and nothing else: any
// other output between the commands is still refused, and so is a prompt
// more than the commands account for.
func TestLateAnswerIsOnlyWhatLooksLikeOne(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		before string
		late   bool // the login ended with an answer outstanding
	}{
		"output between commands, late answer possible": {"\r\nsomething else\r\n", true},
		"the answer, and no answer was outstanding":     {lateAns, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// A login with one answer per line has no answer outstanding only
			// if the shell does not retry, and it retries when the quiet
			// period passes before the answer arrives: a quiet period far
			// longer than the script needs keeps that from happening (the
			// login takes two of them), and a retry is answered anyway.
			quiet := 30 * time.Millisecond
			if !c.late {
				quiet = 300 * time.Millisecond
			}
			release := make(chan struct{})
			sh, d := openScripted(t, quiet, func(d *lineDev) {
				if c.late {
					if !slowLogin(d) {
						return
					}
				} else {
					d.say("banner\r\nalice@rtr1> ")
					if _, ok := d.next(); !ok {
						return
					}
					d.say(lateAns)
					go func() { // a retry typed all the same is answered too
						for {
							l, ok := d.next()
							if !ok {
								return
							}
							if l == "" {
								d.say(lateAns)
							}
						}
					}()
				}
				select {
				case <-release:
				case <-d.done:
					return
				}
				d.say(c.before)
			})
			close(release)
			d.arrived(t, len(c.before))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := sh.Run(ctx, "show system commit"); !errors.Is(err, ErrProtocol) {
				t.Errorf("err = %v, want ErrProtocol", err)
			}
		})
	}
}

// More prompts than commands stay an error with the late answer allowed: the
// late answer and then one prompt too many.
func TestLateAnswerAndOnePromptTooMany(t *testing.T) {
	t.Parallel()
	sh, _ := openScripted(t, 30*time.Millisecond, func(d *lineDev) {
		if !slowLogin(d) {
			return
		}
		cmd, ok := d.next()
		if !ok {
			return
		}
		d.say(lateAns)
		d.say(cmd + "\r\nout\r\n")
		d.say("\r\n{master:0}\r\nalice@rtr1> ")
		if _, ok := d.next(); !ok {
			return
		}
		d.say(lateAns)
		d.say(lateAns) // one prompt too many
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sh.Run(ctx, "show system commit"); !errors.Is(err, ErrProtocol) {
		t.Errorf("err = %v, want ErrProtocol", err)
	}
}

// A device whose answers come in chunks with gaps longer than the quiet
// period, at the places the output has: the answer is the same. The gap is
// time on purpose, it is what the quiet period is measured against.
func TestGapsInTheAnswerAreNoMatter(t *testing.T) {
	t.Parallel()
	const quiet = 20 * time.Millisecond
	gap := func() { time.Sleep(4 * quiet) }
	for name, play := range map[string]func(d *lineDev, cmd string){
		"between the echo and the answer": func(d *lineDev, cmd string) {
			d.say(cmd + "\r\n")
			gap()
			d.say("out\r\n\r\n{master:0}\r\nalice@rtr1> ")
		},
		"between the answer and the prompt": func(d *lineDev, cmd string) {
			d.say(cmd + "\r\nout\r\n")
			gap()
			d.say("\r\n{master:0}\r\nalice@rtr1> ")
		},
		"between the area line and the prompt": func(d *lineDev, cmd string) {
			d.say(cmd + "\r\nout\r\n\r\n{master:0}\r\n")
			gap()
			d.say("alice@rtr1> ")
		},
		"inside the prompt": func(d *lineDev, cmd string) {
			d.say(cmd + "\r\nout\r\n\r\n{master:0}\r\nalice@rt")
			gap()
			d.say("r1> ")
		},
		"inside the echo": func(d *lineDev, cmd string) {
			n := min(5, len(cmd))
			d.say(cmd[:n])
			gap()
			d.say(cmd[n:] + "\r\nout\r\n\r\n{master:0}\r\nalice@rtr1> ")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sh, _ := openScripted(t, quiet, func(d *lineDev) {
				d.say("banner\r\nalice@rtr1> ")
				if _, ok := d.next(); !ok {
					return
				}
				d.say(lateAns)
				cmd, ok := command(d)
				if !ok {
					return
				}
				play(d, cmd)
				if _, ok := d.next(); !ok {
					return
				}
				gap() // and the answer to the empty line is late too
				d.say("\r\n{master:0}\r\n")
				gap()
				d.say("alice@rtr1> ")
			})
			if got := runCmd(t, sh, "show system commit"); got != wantOut {
				t.Errorf("got %q, want %q", got, wantOut)
			}
		})
	}
}

// The prompt and the echo on one line, in front of the echo's answer.
func TestBodyDropsTheLateAnswerInFrontOfTheEcho(t *testing.T) {
	t.Parallel()
	const cmd = "show system commit"
	tail := "\r\nalice@rtr1> \r\nalice@rtr1> "
	for name, c := range map[string]struct{ in, want string }{
		"the prompt and the echo": {
			"alice@rtr1> show system commit\r\nout" + tail, "out\n"},
		"the line break, the area line, the prompt and the echo": {
			"\r\n{master:0}\r\nalice@rtr1> show system commit\r\nout" + tail, "out\n"},
		"the location line of the configure mode": {
			"\r\n{master:0}[edit]\r\nalice@rtr1> show system commit\r\nout" + tail, "out\n"},
		"the plain echo": {
			"show system commit\r\nout" + tail, "out\n"},
		"the prompt typed twice": {
			"alice@rtr1> alice@rtr1> show system commit\r\nout" + tail, "out\n"},
		"a line before it that is not the device's": {
			"surprise\r\nalice@rtr1> show system commit\r\nout" + tail,
			"surprise\nalice@rtr1> show system commit\nout\n"},
		"the prompt and another command": {
			"alice@rtr1> show version\r\nout" + tail, "alice@rtr1> show version\nout\n"},
		"the same line later in the output is output": {
			"show system commit\r\nalice@rtr1> show system commit" + tail, "alice@rtr1> show system commit\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &shell{}
			o := outBuf{prev: -1, prompt: "alice@rtr1> ", alt: "alice@rtr1# ", echo: cmd}
			o.add([]byte(c.in))
			if got := stripEcho(s.body(&o, 0), cmd); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
