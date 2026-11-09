package sftpd

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// recorder collects the audit events of a session.
type recorder struct {
	mu sync.Mutex
	ev []Event
}

func (r *recorder) add(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

func (r *recorder) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.ev...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = nil
}

// env is one session: a real home directory, Serve on one end of a pipe and
// a pkg/sftp client on the other.
type env struct {
	t      *testing.T
	root   string // the directory that holds the home; files in it are outside the home
	home   string
	client *sftp.Client
	rec    *recorder
	done   chan error
	sm     seams
}

// newEnv starts a session. tweak, when not nil, changes the Config before
// Serve gets it.
func newEnv(t *testing.T, tweak func(*Config)) *env {
	t.Helper()
	return newEnvSeams(t, tweak, seams{})
}

// newEnvSeams is newEnv with the clock (and whatever else a test replaces).
func newEnvSeams(t *testing.T, tweak func(*Config), sm seams) *env {
	t.Helper()
	e := &env{t: t, rec: &recorder{}, done: make(chan error, 1), sm: sm}
	e.root = t.TempDir()
	e.home = filepath.Join(e.root, "home")
	if err := os.Mkdir(e.home, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Home: e.home, Audit: e.rec.add}
	if tweak != nil {
		tweak(&cfg)
	}
	e.start(cfg)
	return e
}

// start serves cfg on a new pipe and connects the client.
func (e *env) start(cfg Config) {
	e.t.Helper()
	cs, ss := net.Pipe()
	e.done = make(chan error, 1)
	go func() { e.done <- serve(ss, cfg, e.sm) }()
	c, err := sftp.NewClientPipe(cs, cs)
	if err != nil {
		e.t.Fatal(err)
	}
	e.client = c
	e.t.Cleanup(func() { _ = e.stop() })
}

// stop ends the session and returns what Serve returned.
func (e *env) stop() error {
	if e.client == nil {
		return nil
	}
	_ = e.client.Close()
	e.client = nil
	return <-e.done
}

// write makes a file in the home (or below it) directly.
func (e *env) write(rel, content string) {
	e.t.Helper()
	p := filepath.Join(e.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// read returns the content of a file in the home.
func (e *env) read(rel string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.home, rel))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// exists reports whether the entry (a link counts as itself) is in the home.
func (e *env) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(e.home, rel))
	return err == nil
}

// put uploads content through the client and fails the test on an error.
func (e *env) put(path, content string) {
	e.t.Helper()
	if err := putFile(e.client, path, content); err != nil {
		e.t.Fatalf("upload %s: %v", path, err)
	}
}

func putFile(c *sftp.Client, path, content string) error {
	f, err := c.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(content)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// get downloads a file through the client.
func (e *env) get(path string) (string, error) {
	f, err := e.client.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	return string(b), err
}

// code is the SFTP status code of err. The client turns the codes no such
// file and permission denied into os.ErrNotExist and os.ErrPermission, and
// keeps the others as a *sftp.StatusError; -1 is anything else.
func code(err error) int {
	var se *sftp.StatusError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, os.ErrNotExist):
		return fxNoSuchFile
	case errors.Is(err, os.ErrPermission):
		return fxPermissionDenied
	case errors.As(err, &se):
		return int(se.Code)
	}
	return -1
}

const (
	fxNoSuchFile       = 2
	fxPermissionDenied = 3
	fxFailure          = 4
	fxOpUnsupported    = 8
)

// refusals are the "refused" events, with their reasons.
func refusals(ev []Event) []string {
	var out []string
	for _, e := range ev {
		if e.Op == "refused" {
			out = append(out, e.Err.Error())
		}
	}
	return out
}

// pipePair is two connected ends.
func pipePair() (net.Conn, net.Conn) { return net.Pipe() }

// clock is a clock a test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 12, 13, 11, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
