package shell

// Interactive in this process, on a pseudo-terminal the test drives: the
// line editor, the long-list question, the pager, the idle end and the
// system-shell word, measured by the coverage of this package (the pty
// tests of pty_test.go run the shell in a process of its own). The pty is
// not this process's controlling terminal, so nothing here depends on
// signals of the line discipline.

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/ui"
)

type inproc struct {
	t      *testing.T
	master *os.File
	mu     sync.Mutex
	buf    []byte
	mark   int
	notify chan struct{}
	done   chan int
	sh     *Shell
}

// startInProcess runs Interactive with o on the slave end of a new pty of
// rows x cols; the test types on the master.
func startInProcess(t *testing.T, o Options, rows, cols uint16) *inproc {
	t.Helper()
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil {
		t.Fatal(err)
	}
	o.Out = ui.Output{Stdout: slave, Stderr: slave}
	p := &inproc{t: t, master: master, notify: make(chan struct{}, 1), done: make(chan int, 1), sh: New(o)}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			if n > 0 {
				p.mu.Lock()
				p.buf = append(p.buf, b[:n]...)
				p.mu.Unlock()
				select {
				case p.notify <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { p.done <- p.sh.Interactive(context.Background(), slave) }()
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	p.expect(regexp.QuoteMeta(p.sh.o.Prompt))
	return p
}

func (p *inproc) send(s string) {
	p.t.Helper()
	if _, err := p.master.WriteString(s); err != nil {
		p.t.Fatal(err)
	}
}

// expect waits (at most 5 s) for re in the output after the last match.
func (p *inproc) expect(re string) {
	p.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		loc := rx.FindIndex(p.buf[p.mark:])
		if loc != nil {
			p.mark += loc[1]
		}
		out := string(p.buf)
		p.mu.Unlock()
		if loc != nil {
			return
		}
		select {
		case <-p.notify:
		case <-deadline.C:
			p.t.Fatalf("timed out waiting for %q; output %q", re, out)
		}
	}
}

// ends waits for Interactive to return and gives its status.
func (p *inproc) ends() int {
	p.t.Helper()
	select {
	case s := <-p.done:
		return s
	case <-time.After(5 * time.Second):
		p.t.Fatal("the shell did not end")
	}
	return -1
}

func TestInProcessInteractive(t *testing.T) {
	var ran []string
	var sys []bool
	o := Options{
		Prompt:   "host> ",
		Complete: testCompleter,
		ListMax:  10,
		Exec: func(_ context.Context, words []string, _ io.Reader) int {
			ran = append(ran, strings.Join(words, " "))
			return 3
		},
		SystemShell: func(_ context.Context, interactive bool) int {
			sys = append(sys, interactive)
			return 0
		},
	}
	p := startInProcess(t, o, 8, 60)
	p.send("user list\r")
	p.expect(`\[exit 3\]`)
	p.expect(`host> `)
	// A long list asks first; n: the hint instead.
	p.send("many \t\t")
	p.expect(`Show all 45 devices\? \[y/N\] `)
	p.send("n")
	p.expect(`type more letters to narrow it \(e\.g\. n0…<Tab>\)`)
	// y: the list, a screenful at a time ('?': with descriptions).
	p.send("?")
	p.expect(`Show all 45 devices\? \[y/N\] `)
	p.send("y")
	p.expect(regexp.QuoteMeta(morePrompt))
	p.send("\r")
	p.expect(regexp.QuoteMeta(morePrompt))
	p.send(" ")
	p.expect(regexp.QuoteMeta(morePrompt))
	p.send("q")
	p.expect(`host> many n`)
	p.send("\x15")
	p.expect(` {6}\x1b\[6D`)
	p.send("system-shell\r")
	p.expect(`system-shell\r\n`)
	p.expect(`host> `)
	p.send("exit\r")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	if reason, lines := p.sh.End(); reason != EndExit || lines != 3 {
		t.Errorf("End = %s %d", reason, lines)
	}
	if len(ran) != 1 || ran[0] != "user list" || len(sys) != 1 || !sys[0] {
		t.Errorf("ran %q, system shell %v", ran, sys)
	}
}

func TestInProcessIdleAndEOF(t *testing.T) {
	p := startInProcess(t, Options{Idle: 200 * time.Millisecond, Exec: func(context.Context, []string, io.Reader) int { return 0 }}, 24, 80)
	p.expect(`idle timeout after 200ms`)
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	if reason, _ := p.sh.End(); reason != EndIdle {
		t.Errorf("reason %s", reason)
	}
	if idleText(30*time.Minute) != "30 min" {
		t.Error("idleText")
	}

	p = startInProcess(t, Options{Exec: func(context.Context, []string, io.Reader) int { return 0 }}, 24, 80)
	p.send("\x04")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	if reason, _ := p.sh.End(); reason != EndEOF {
		t.Errorf("reason %s", reason)
	}
}
