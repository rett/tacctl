package ui

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got, ok := File(f); !ok || got != f {
		t.Errorf("a file: %v %v", got, ok)
	}
	p := Plain(f)
	if got, ok := File(p); !ok || got != f {
		t.Errorf("a plain stream over a file: %v %v", got, ok)
	}
	if got, ok := File(Plain(Plain(f))); !ok || got != f {
		t.Errorf("a plain stream over a plain stream: %v %v", got, ok)
	}
	var b bytes.Buffer
	if got, ok := File(&b); ok || got != nil {
		t.Errorf("a buffer: %v %v", got, ok)
	}
	if got, ok := File(Plain(&b)); ok || got != nil {
		t.Errorf("a plain stream over a buffer: %v %v", got, ok)
	}
	var nilFile *os.File
	if _, ok := File(nilFile); ok {
		t.Error("a nil file is not a file")
	}
	if _, ok := File(nil); ok {
		t.Error("nil is not a file")
	}
}

// Plain strips SGR, holds a split sequence across writes, and is safe for
// concurrent writers (an *os.File is, and it stands in for one).
func TestPlain(t *testing.T) {
	var b bytes.Buffer
	p := Plain(&b)
	_, _ = io.WriteString(p, "a\033[1;3")
	_, _ = io.WriteString(p, "1mb\033[0m\033[K")
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "ab\033[K" {
		t.Errorf("got %q", got)
	}

	var out lockedBuffer
	q := Plain(&out)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = io.WriteString(q, "\033[0;32mline\033[0m\n")
			}
		}()
	}
	wg.Wait()
	_ = q.Close()
	if got := strings.Count(out.String(), "line\n"); got != 1600 || strings.Contains(out.String(), "\033") {
		t.Errorf("%d lines, escapes %v", got, strings.Contains(out.String(), "\033"))
	}
}

// lockedBuffer is a buffer whose Write can be called at once; the sink under
// test is what serialises the writers, so the lock is only for reading.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
