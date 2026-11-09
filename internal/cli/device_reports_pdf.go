package cli

// The PDF format of 'device reports generate': the report is built as an
// HTML document (internal/reports.RenderHTML) and an external tool,
// weasyprint, turns it into the PDF. tacctl runs the tool as the person who
// ran sudo, never as root, with a minimal environment, a time limit and a
// limit on what it may write, and finds it in fixed directories only.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
// regular, executable file called weasyprint in the fixed directories.
func (inv *invocation) pdfTool() (string, bool) {
	if p := inv.app.Knobs.PDFTool(); p != "" {
		return p, isExecutable(p)
	}
	for _, d := range inv.hooks.pdfDirs() {
		if p := filepath.Join(d, pdfToolName); isExecutable(p) {
			return p, true
		}
	}
	return "", false
}

// isExecutable says whether path is, after links, a regular file somebody may
// run.
func isExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// pdfRequire is the check that comes before any report data is read or
// anything is written: the tool is there, and a PDF for standard output has
// somewhere to go that is no terminal.
func (inv *invocation) pdfRequire(stdout bool) (string, error) {
	if stdout && inv.hooks.terminalWriter(inv.app.Out.Stdout) {
		return "", inv.usageErr("A PDF is binary: redirect --stdout to a file, or leave it out to store the report.")
	}
	tool, ok := inv.pdfTool()
	if !ok {
		return "", inv.usageErr(pdfMissingText)
	}
	return tool, nil
}

// pdfIdentity is who the tool runs as and where its home is. A process that is
// root through sudo runs it as the person sudo was run by (the user and group
// of SUDO_UID and SUDO_GID, no supplementary groups), after checking that
// SUDO_USER is that account. A process that is not root runs it as itself, and
// a root session without sudo is the person's own.
func (inv *invocation) pdfIdentity() (*syscall.Credential, string, error) {
	home := inv.app.Env.Get("HOME")
	user := inv.sudoUser()
	acct, aerr := inv.hooks.account(user)
	if aerr == nil && acct.Home != "" && filepath.IsAbs(acct.Home) {
		home = acct.Home
	}
	if home == "" || !filepath.IsAbs(home) {
		home = "/"
	}
	if inv.hooks.euid() != 0 {
		return nil, home, nil
	}
	uid, gid, ok := inv.callerIDs()
	if !ok || uid == 0 {
		return nil, home, nil
	}
	if aerr != nil || int(acct.UID) != uid {
		return nil, "", errors.New("the account of '" + user + "' is not the one sudo ran this for")
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, home, nil
}

// pdfEnv is the whole environment of the tool.
func pdfEnv(home string) []string {
	return []string{"PATH=" + pdfPath, "LANG=C.UTF-8", "HOME=" + home, "XDG_CACHE_HOME=" + home}
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
func (inv *invocation) writeRaw(b []byte) {
	w := inv.app.Out.Stdout
	if f, ok := ui.File(w); ok {
		w = f
	}
	_, _ = w.Write(b)
}
