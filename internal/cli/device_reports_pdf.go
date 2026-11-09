package cli

// The PDF format of 'device reports generate': the report is built as an
// HTML document (internal/reports.RenderHTML) and an external tool,
// weasyprint, turns it into the PDF. tacctl runs the tool as the person who
// ran sudo (as root only in a root session that has no sudo caller), with a
// minimal environment, a time limit and a limit on what it may write, and
// finds it in fixed directories only.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

const (
	// pdfToolName is the PDF tool.
	pdfToolName = "weasyprint"
	// pdfInstallLine installs the tool and the font the report is set in.
	pdfInstallLine = "sudo apt-get install -y weasyprint fonts-dejavu-core"
	// pdfTimeout is how long the tool may run, pdfMaxOutput the most it may
	// write to standard output, pdfStderrMax the most of its standard error
	// that is kept.
	pdfTimeout   = 120 * time.Second
	pdfMaxOutput = 64 << 20
	pdfStderrMax = 64 << 10
	// pdfErrLines is how many lines of the tool's standard error an error
	// shows, pdfErrLineMax the longest of them.
	pdfErrLines   = 5
	pdfErrLineMax = 200
	// pdfPath is the PATH the tool gets: its own interpreter is found there.
	pdfPath = "/usr/local/bin:/usr/bin:/bin"
)

// pdfToolDirs are the only directories the tool is looked for in, never the
// caller's PATH or the current directory.
var pdfToolDirs = []string{"/usr/bin", "/usr/local/bin", "/opt/weasyprint/bin"}

// pdfMissingText is the refusal of a PDF report when the tool is not there.
const pdfMissingText = "PDF reports need weasyprint, which is not installed here. Install it: " + pdfInstallLine

// pdfBinaryExport is the refusal to print a PDF report to a terminal.
const pdfBinaryExport = "PDF is binary: use --out FILE or redirect"

// pdfDirs are the directories to look in.
func (h *hooks) pdfDirs() []string {
	if h != nil && h.pdfToolDirs != nil {
		return h.pdfToolDirs
	}
	return pdfToolDirs
}

// pdfLimits are the time and the output the tool is held to.
func (h *hooks) pdfLimits() (time.Duration, int64) {
	timeout, maxOut := pdfTimeout, int64(pdfMaxOutput)
	if h != nil && h.pdfTimeout > 0 {
		timeout = h.pdfTimeout
	}
	if h != nil && h.pdfMaxOutput > 0 {
		maxOut = h.pdfMaxOutput
	}
	return timeout, maxOut
}

// pdfTool finds the tool: the path a test build's knob names, else the first
// regular, executable file called weasyprint in the fixed directories that
// root owns, as every directory above it, none of them writable by group or
// others (as the secure_path of sudo is held to). A tool that is there and
// does not meet that is not used; rejected says so, for the error of a search
// that finds nothing else.
func (inv *invocation) pdfTool() (path string, ok bool, rejected string) {
	if p := inv.app.Knobs.PDFTool(); p != "" {
		// the knob's stub is the test's own: no rule about its owner
		return p, isExecutable(p), ""
	}
	for _, d := range inv.hooks.pdfDirs() {
		p := filepath.Join(d, pdfToolName)
		real, err := filepath.EvalSymlinks(p)
		if err != nil || !isExecutable(real) {
			continue
		}
		if !inv.hooks.pdfTrusted(p) || !inv.hooks.pdfTrusted(real) {
			if rejected == "" {
				rejected = pdfToolName + " at " + p + " is not owned by root or is writable by others: not used"
			}
			continue
		}
		return p, true, ""
	}
	return "", false, rejected
}

// isExecutable says whether path is, after links, a regular file somebody may
// run.
func isExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// pdfStatOf is the owner and the permission bits of a file or directory, links
// followed (nil: the system's).
func (h *hooks) pdfStatOf(path string) (uint32, fs.FileMode, error) {
	if h != nil && h.pdfStat != nil {
		return h.pdfStat(path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("no owner to be read")
	}
	return sys.Uid, st.Mode().Perm(), nil
}

// pdfTrusted says whether path and every directory above it up to / is owned
// by root and cannot be written by its group or by others.
func (h *hooks) pdfTrusted(path string) bool {
	for p := path; ; p = filepath.Dir(p) {
		uid, perm, err := h.pdfStatOf(p)
		if err != nil || uid != 0 || perm&0o022 != 0 {
			return false
		}
		if p == "/" || filepath.Dir(p) == p {
			return true
		}
	}
}

// pdfRequire is the check that comes before any report data is read or
// anything is written: the tool is there, and a PDF for standard output has
// somewhere to go that is no terminal.
func (inv *invocation) pdfRequire(stdout bool) (string, error) {
	if stdout && inv.hooks.terminalWriter(inv.app.Out.Stdout) {
		return "", inv.usageErr("A PDF is binary: redirect --stdout to a file, or leave it out to store the report.")
	}
	tool, ok, rejected := inv.pdfTool()
	if !ok {
		if rejected != "" {
			return "", inv.usageErr(rejected)
		}
		return "", inv.usageErr(pdfMissingText)
	}
	return tool, nil
}

// pdfIdentity is who the tool runs as and where its home is. A process that is
// root through sudo runs it as the person sudo was run by (the user and group
// of SUDO_UID and SUDO_GID, no supplementary groups), after checking that
// SUDO_USER is that account. A process that is not root runs it as itself. A
// root session that has no usable sudo caller (no SUDO_UID, or one that is not
// a number, is negative or is 0) runs it as root, with the home of root from
// the account database (else /), never the home of the account SUDO_USER names.
func (inv *invocation) pdfIdentity() (*syscall.Credential, string, error) {
	if inv.hooks.euid() != 0 {
		home := inv.app.Env.Get("HOME")
		if acct, err := inv.hooks.account(inv.sudoUser()); err == nil && acct.Home != "" && filepath.IsAbs(acct.Home) {
			home = acct.Home
		}
		return nil, pdfHome(home), nil
	}
	uid, gid, ok := inv.callerIDs()
	if !ok || uid <= 0 || gid < 0 {
		home, _ := inv.hooks.homeOf(0)
		return nil, pdfHome(home), nil
	}
	user := inv.sudoUser()
	acct, err := inv.hooks.account(user)
	if err != nil || int(acct.UID) != uid {
		return nil, "", errors.New("the account of '" + user + "' is not the one sudo ran this for")
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, pdfHome(acct.Home), nil
}

// pdfHome is home when it is an absolute path, else the root directory.
func pdfHome(home string) string {
	if home == "" || !filepath.IsAbs(home) {
		return "/"
	}
	return home
}

// pdfEnv is the whole environment of the tool. Its caches go to ~/.cache (not
// into a directory of the home that fontconfig would make there) and it reads
// no user site directory, where a .pth file would run code.
func pdfEnv(home string) []string {
	return []string{"PATH=" + pdfPath, "LANG=C.UTF-8", "HOME=" + home, "XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "PYTHONNOUSERSITE=1"}
}

// renderPDF makes the PDF of an HTML document with the tool at path. The tool
// writes to standard output only and the result is returned, not stored, so a
// failure leaves nothing behind. The error is a clause without a full stop.
func (inv *invocation) renderPDF(tool string, doc []byte) ([]byte, error) {
	cred, home, err := inv.pdfIdentity()
	if err != nil {
		return nil, err
	}
	timeout, maxOut := inv.hooks.pdfLimits()
	ctx, cancel := context.WithTimeout(inv.ctx, timeout)
	defer cancel()
	out := &pdfCapture{max: maxOut, cancel: cancel}
	errOut := &pdfStderr{}
	res, err := inv.app.Runner.Run(ctx, execx.Cmd{Name: tool, Args: []string{"--quiet", "-", "-"},
		Stdin: bytes.NewReader(doc), Env: pdfEnv(home), Dir: "/", Credential: cred, Stdout: out, Stderr: errOut, KillGroup: true})
	stderr := errOut.lines()
	switch {
	case out.over:
		return nil, fmt.Errorf("the PDF tool (%s) wrote more than %s and was stopped", pdfToolName, reportSize(maxOut))
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("the PDF tool (%s) did not finish in %s and was stopped", pdfToolName, timeout.Round(time.Millisecond))
	case inv.ctx.Err() != nil:
		return nil, inv.ctx.Err()
	case err != nil:
		return nil, fmt.Errorf("the PDF tool (%s) cannot be run: %s", pdfToolName, cleanLine(err.Error()))
	case res.Code != 0:
		return nil, errors.New("the PDF tool (" + pdfToolName + ") failed with exit status " + strconv.Itoa(res.Code) + pdfStderrText(stderr))
	}
	b := out.buf.Bytes()
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		return nil, errors.New("the PDF tool (" + pdfToolName + ") made no PDF" + pdfStderrText(stderr))
	}
	return b, nil
}

// pdfStderrText is the part of an error message that carries what the tool
// said: ": <line>; <line>", or nothing.
func pdfStderrText(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return ": " + strings.Join(lines, "; ")
}

// pdfCapture collects the tool's standard output up to a limit; a write over
// it stops the tool (cancel) and fails.
type pdfCapture struct {
	buf    bytes.Buffer
	max    int64
	cancel context.CancelFunc
	over   bool
}

func (c *pdfCapture) Write(p []byte) (int, error) {
	if int64(c.buf.Len())+int64(len(p)) > c.max {
		c.over = true
		c.cancel()
		return 0, errors.New("the PDF is over the limit")
	}
	return c.buf.Write(p)
}

// pdfStderr keeps the start of the tool's standard error.
type pdfStderr struct{ buf bytes.Buffer }

func (s *pdfStderr) Write(p []byte) (int, error) {
	if room := pdfStderrMax - s.buf.Len(); room > 0 {
		s.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// lines are the first lines of the tool's standard error as an error shows
// them: cleaned, cut short, and without a line that holds markup (the tool
// can quote the document it was given, which is the report's text and not for
// an error message).
func (s *pdfStderr) lines() []string {
	var out []string
	for _, l := range strings.Split(s.buf.String(), "\n") {
		l = strings.TrimSpace(cleanLine(l))
		if l == "" || strings.ContainsAny(l, "<>") {
			continue
		}
		if r := []rune(l); len(r) > pdfErrLineMax {
			l = string(r[:pdfErrLineMax]) + "..."
		}
		out = append(out, l)
		if len(out) == pdfErrLines {
			break
		}
	}
	return out
}

// writeRaw writes bytes to standard output as they are. The stream tacctl
// holds for a pipe or a file takes terminal colour sequences out, which a PDF
// may contain by chance, so the file behind it is written when there is one.
// A write that fails or falls short is an error: a cut-off PDF is no success.
func (inv *invocation) writeRaw(b []byte) error {
	w := inv.app.Out.Stdout
	if f, ok := ui.File(w); ok {
		w = f
	}
	n, err := w.Write(b)
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// rawWriteErr is the failure of a PDF that could not be written to standard
// output: exit 1.
func (inv *invocation) rawWriteErr(err error) error {
	return inv.usageErr("Cannot write the PDF to standard output: " + cleanLine(err.Error()) + ".")
}
