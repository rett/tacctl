package fakedev

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStripCaptureHeader(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"# vendor: juniper\n# os: junos 25.4\n# ---\nset a\n", "set a\n"},
		{"set a\nset b\n", "set a\nset b\n"},
		{"# not a capture\nset a\n", "# not a capture\nset a\n"},
		{"# vendor: x\n", "# vendor: x\n"},
		{"", ""},
	} {
		if got := stripCaptureHeader(c.in); got != c.want {
			t.Errorf("stripCaptureHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFileNameEncodesSlash(t *testing.T) {
	if got := fileName("show interfaces ge-0/0/0 100%", ".out"); got != "show interfaces ge-0%2F0%2F0 100%25.out" {
		t.Errorf("got %q", got)
	}
	if got := fileName("../../etc/passwd", ".out"); strings.Contains(got, "/") {
		t.Errorf("a command must not name a path: %q", got)
	}
}

func TestTranscriptReads(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tr := transcript{dir: dir}
	if tr.prompt() != "fake#" {
		t.Errorf("default prompt %q", tr.prompt())
	}
	write("prompt", "u@sw> \n")
	if tr.prompt() != "u@sw> " {
		t.Errorf("prompt %q", tr.prompt())
	}
	if n, j := tr.paging(); n != 0 || j {
		t.Errorf("paging without a file: %d %v", n, j)
	}
	write("paging", "")
	if n, _ := tr.paging(); n != 24 {
		t.Errorf("empty paging file: %d", n)
	}
	write("paging", "10 junos\n")
	if n, j := tr.paging(); n != 10 || !j {
		t.Errorf("paging %d %v", n, j)
	}
	write("login", "alice pw1\n")
	if u, p, ok := tr.login(); !ok || u != "alice" || p != "pw1" {
		t.Errorf("login %q %q %v", u, p, ok)
	}
	write("show a.out", "A\n")
	write("show b.err", "denied\n")
	if out, _, ok := tr.command("show a | no-more"); !ok || out != "A\n" {
		t.Errorf("no-more fallback: %q %v", out, ok)
	}
	if _, deny, ok := tr.command("show b"); !ok || deny != "denied" {
		t.Errorf("deny %q %v", deny, ok)
	}
	if _, _, ok := tr.command("show c"); ok {
		t.Error("an absent command is unknown")
	}
}

func TestServeAndStop(t *testing.T) {
	addr, stop := Serve(t.TempDir())
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SSH-2.0-") {
		t.Fatalf("banner %q %v", line, err)
	}
	stop()
	stop() // idempotent
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("the listener is still open after stop")
	}
	_ = c.Close()
}

func TestRPCReplyNamesNeverFormAPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rpc.get-configuration.xml"), []byte("<ok/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "x.xml"), []byte("<secret/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := transcript{dir: dir}
	if r, ok := tr.rpcReply("get-configuration", "set"); !ok || r != "<ok/>" {
		t.Errorf("fallback to the plain file: %q %v", r, ok)
	}
	// A format with a path in it is no format; an element with one is no
	// element.
	if r, ok := tr.rpcReply("get-configuration", "../sub/x"); !ok || r != "<ok/>" {
		t.Errorf("a path-like format must be ignored: %q %v", r, ok)
	}
	if _, ok := tr.rpcReply("../sub/x", ""); ok {
		t.Error("a path-like element must not be read")
	}
	if _, ok := tr.rpcReply("get-configuration.set", ""); ok {
		t.Error("a dotted element must not be read")
	}
}
