package fakedev

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The transcript directory (docs/plans/0.2.4-plan.md D74), the layout of
// tests/fixtures/devconf/<vendor>/<case>/. Every file is optional and is
// read when it is needed, so a test may change the directory under a
// running server.
//
//	prompt                 the prompt, exactly (one trailing newline is
//	                       dropped, a trailing blank is kept); default 'fake#'
//	banner                 text sent before the first prompt of a shell
//	login                  '<user> <password>' that the server accepts
//	paging                 shell output is paged: '<lines per page>' and,
//	                       after a blank, 'junos' for '---(more)---' instead
//	                       of ' --More-- '; an empty file is 24 lines
//	<command>.out          the output of <command> (a '/' is written '%2F'
//	                       and a '%' '%25' in the file name); a capture of
//	                       tests/fixtures/devconf keeps its '# ' header,
//	                       which is dropped up to the '# ---' line
//	<command>.hang         the command is never answered (the session stays
//	                       open until the server stops)
//	<command>.err          the command is denied with this message (an
//	                       rpc-error over NETCONF, the text over the CLI)
//	netconf.off            the netconf subsystem is refused
//	netconf.hello          the device's hello document, whole (the default
//	                       one advertises base:1.0 and, when the server
//	                       chunks, base:1.1)
//	rpc.<element>.xml      the inner XML of the reply to an RPC whose first
//	                       element is <element>; rpc.<element>.<format>.xml
//	                       is tried first, <format> being its 'format'
//	                       attribute
//
// 'terminal length 0', 'terminal width 0' and 'set cli screen-length 0'
// need no file (they switch paging off for the session); 'exit', 'quit'
// and 'logout' end the session.
type transcript struct{ dir string }

func (t transcript) read(name string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(t.dir, name))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func (t transcript) exists(name string) bool {
	_, err := os.Stat(filepath.Join(t.dir, name))
	return err == nil
}

// prompt is the prompt of a shell session.
func (t transcript) prompt() string {
	p, ok := t.read("prompt")
	if !ok {
		return "fake#"
	}
	return strings.TrimSuffix(p, "\n")
}

// login is the user and password the transcript sets, if it does.
func (t transcript) login() (user, password string, ok bool) {
	s, found := t.read("login")
	if !found {
		return "", "", false
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return "", "", false
	}
	return f[0], f[1], true
}

// paging is the page length and the marker style; n 0 is no paging.
func (t transcript) paging() (n int, junos bool) {
	s, ok := t.read("paging")
	if !ok {
		return 0, false
	}
	f := strings.Fields(s)
	n = 24
	if len(f) > 0 {
		if v, err := strconv.Atoi(f[0]); err == nil && v > 0 {
			n = v
		}
	}
	return n, len(f) > 1 && f[1] == "junos"
}

// fileName is the name of a command's file with the given suffix.
func fileName(cmd, suffix string) string {
	cmd = strings.ReplaceAll(cmd, "%", "%25")
	cmd = strings.ReplaceAll(cmd, "/", "%2F")
	return cmd + suffix
}

// command is the transcript's answer to cmd: its output, or the message it
// is denied with, or neither (unknown). A trailing ' | no-more' is
// ignored when the command with it has no file.
func (t transcript) command(cmd string) (out, deny string, known bool) {
	cmd = strings.TrimSpace(cmd)
	for _, c := range []string{cmd, strings.TrimSuffix(cmd, " | no-more")} {
		if s, ok := t.read(fileName(c, ".err")); ok {
			return "", strings.TrimSpace(s), true
		}
		if s, ok := t.read(fileName(c, ".out")); ok {
			return stripCaptureHeader(s), "", true
		}
	}
	return "", "", false
}

// stripCaptureHeader drops the '# key: value' header block of a capture
// (plan section 7.3) up to and including its '# ---' line.
func stripCaptureHeader(s string) string {
	if !strings.HasPrefix(s, "# ") {
		return s
	}
	rest := s
	for strings.HasPrefix(rest, "#") {
		line, after, found := strings.Cut(rest, "\n")
		if !found {
			return s
		}
		rest = after
		if strings.TrimSpace(line) == "# ---" {
			return rest
		}
	}
	return s
}

// hangs reports whether cmd is one the transcript never answers.
func (t transcript) hangs(cmd string) bool {
	return t.exists(fileName(strings.TrimSpace(cmd), ".hang"))
}

// reName is what an RPC element or format may be to name a file: a command
// from the wire never forms a path.
var reName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// rpcReply is the canned reply body of an RPC element (and format).
func (t transcript) rpcReply(elem, format string) (string, bool) {
	if !reName.MatchString(elem) {
		return "", false
	}
	if format != "" && reName.MatchString(format) {
		if s, ok := t.read("rpc." + elem + "." + format + ".xml"); ok {
			return s, true
		}
	}
	return t.read("rpc." + elem + ".xml")
}
