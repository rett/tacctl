package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/reports"
)

// The PDF format of 'device reports generate', on the box of
// device_reports_test.go. The PDF tool is a file in a directory of the test
// (the tool is looked for in the directories hooks.pdfToolDirs names) and the
// fake runner answers for it: a stub that writes %PDF-1.7 and copies the HTML
// it was given, so that a test reads what the tool was given.

// pdfTool puts an executable file called weasyprint in a directory of the
// test, makes it the only place the tool is looked for, and returns its path.
func (b *reportsBox) pdfTool() string {
	b.t.Helper()
	dir := b.t.TempDir()
	tool := filepath.Join(dir, "weasyprint")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		b.t.Fatal(err)
	}
	b.sb.hooks.pdfToolDirs = []string{dir}
	return tool
}

// pdfStub is the fake runner's answer for the tool: %PDF-1.7, then its input.
func pdfStub(tool string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.OnFunc([]string{tool}, func(c execx.Cmd) (execx.Result, error) {
			in, _ := io.ReadAll(c.Stdin)
			return execx.Result{Stdout: append([]byte("%PDF-1.7\n"), in...)}, nil
		})
	}
}

// asWith is as with more rules for the fake runner and more environment.
func (b *reportsBox) asWith(script func(*fake.Runner), env []string, user, groups string, args ...string) string {
	b.t.Helper()
	return plain(b.sb.cfgRun("", append([]string{"device", "reports"}, args...), func(r *fake.Runner) {
		idAs(user, "tac-users "+groups)(r)
		if script != nil {
			script(r)
		}
	}, append([]string{"SUDO_USER=" + user}, env...)...))
}

// toolCalls are the runs of the tool.
func toolCalls(r *fake.Runner, tool string) []fake.Record {
	var out []fake.Record
	for _, rec := range r.Records() {
		if rec.Cmd.Name == tool {
			out = append(out, rec)
		}
	}
	return out
}

func TestReportsPDFStdoutForEveryType(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	for _, typ := range reports.Types() {
		out := b.asWith(pdfStub(tool), nil, "alice", asSuper, "generate", "--type", typ, "--format", "pdf", "--stdout")
		if b.sb.code != 0 || !strings.HasPrefix(out, "%PDF-1.7\n<!DOCTYPE html>") {
			t.Fatalf("%s: exit %d %.80q %q", typ, b.sb.code, out, b.sb.stderr())
		}
		calls := toolCalls(b.sb.runner, tool)
		if len(calls) != 1 {
			t.Fatalf("%s: %d runs of the tool", typ, len(calls))
		}
		html := string(calls[0].Stdin)
		for _, want := range []string{"<title>Device " + typ + " report</title>", "<th>" + reports.Columns(typ)[0] + "</th>", "jsw1"} {
			if !strings.Contains(html, want) {
				t.Errorf("%s: no %q in the HTML the tool was given", typ, want)
			}
		}
		// the whole document is what the tool reads, and the tool is run as
		// documented: HTML on standard input, the PDF on standard output
		c := calls[0].Cmd
		if got := strings.Join(c.Args, " "); got != "--quiet - -" || c.Dir != "/" || c.Credential != nil {
			t.Errorf("%s: args %q dir %q credential %v", typ, got, c.Dir, c.Credential)
		}
	}
	// --stdout stores nothing
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Errorf("--stdout made the directory: %v", err)
	}
}

// The tool gets a minimal environment of its own: not the caller's.
func TestReportsPDFEnvironment(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	b.asWith(pdfStub(tool), []string{"PATH=/home/user/bin:/usr/bin", "LD_PRELOAD=/home/user/x.so", "HOME=/home/user/other", "WEASYPRINT_X=1"},
		"alice", asSuper, "generate", "--type", "software", "--format", "pdf", "--stdout")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	home := filepath.Join(b.sb.dir, "home", "alice")
	want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + home, "XDG_CACHE_HOME=" + home}
	if got := toolCalls(b.sb.runner, tool)[0].Cmd.Env; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("environment %q, want %q", got, want)
	}
}

func TestReportsPDFStored(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	out := b.asWith(pdfStub(tool), nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--scope", "lab")
	m := writtenRE.FindStringSubmatch(out)
	if b.sb.code != 0 || m == nil {
		t.Fatalf("exit %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	file := filepath.Join(b.dir("alice"), m[1]+".pdf")
	if m[2] != file {
		t.Errorf("written to %q, want %q", m[2], file)
	}
	body, err := os.ReadFile(file)
	if err != nil || !strings.HasPrefix(string(body), "%PDF-1.7\n") {
		t.Fatalf("%v %.40q", err, body)
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// the metadata stays JSON and says pdf, the rows and the size
	mb, err := os.ReadFile(file + ".meta")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := reports.ParseMeta(mb)
	if err != nil || meta.Format != "pdf" || meta.Type != "inventory" || meta.Size != int64(len(body)) || meta.Filters["scope"] != "lab" {
		t.Errorf("meta %+v, %v", meta, err)
	}
	if meta.Count != strings.Count(string(body), "<tr>")-1 {
		t.Errorf("meta rows %d, the document has %d", meta.Count, strings.Count(string(body), "<tr>")-1)
	}
	if !strings.Contains(plain(b.sb.out.String()), "See it with: tacctl device reports show "+m[1]) {
		t.Errorf("output %q", b.sb.out.String())
	}
}

// Without the tool a PDF report is refused first: before the registry is
// read (a registry that cannot be read would be another message), before a
// pull, and with nothing written.
func TestReportsPDFNeedsTheTool(t *testing.T) {
	b := newReportsBox(t)
	b.sb.write("state/devices.yaml", "version: [not a registry\n", 0o600)
	for _, args := range [][]string{
		{"generate", "--type", "inventory", "--format", "pdf"},
		{"generate", "--type", "inventory", "--format", "pdf", "--stdout"},
		{"generate", "--type", "members", "--format", "pdf", "--name", "x", "--scope", "lab"},
	} {
		b.as("alice", asSuper, args...)
		want := "[ERROR] PDF reports need weasyprint, which is not installed here. Install it: sudo apt-get install -y weasyprint fonts-dejavu-core"
		if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), want) || strings.Count(b.sb.stderr(), "[ERROR]") != 1 {
			t.Errorf("%v: exit %d %q", args, b.sb.code, b.sb.stderr())
		}
		if b.sb.out.Len() != 0 {
			t.Errorf("%v: stdout %q", args, b.sb.out.String())
		}
		if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
			t.Errorf("%v: the directory was made: %v", args, err)
		}
	}
	// a tool that is a directory, or not executable, is not a tool
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "weasyprint"), 0o755); err != nil {
		t.Fatal(err)
	}
	b.sb.hooks.pdfToolDirs = []string{dir}
	b.as("alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "PDF reports need weasyprint") {
		t.Errorf("a directory: exit %d %q", b.sb.code, b.sb.stderr())
	}
	if err := os.Remove(filepath.Join(dir, "weasyprint")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weasyprint"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.as("alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "PDF reports need weasyprint") {
		t.Errorf("not executable: exit %d %q", b.sb.code, b.sb.stderr())
	}
}

// The tool is looked for in the fixed directories and nowhere else: not in
// the caller's PATH, not in the current directory.
func TestReportsPDFToolIsNotFoundInPathOrTheCurrentDirectory(t *testing.T) {
	b := newReportsBox(t)
	b.sb.hooks.pdfToolDirs = nil // the real list
	want := []string{"/usr/bin", "/usr/local/bin", "/opt/weasyprint/bin"}
	if got := b.sb.hooks.pdfDirs(); strings.Join(got, ":") != strings.Join(want, ":") {
		t.Errorf("directories %q, want %q", got, want)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "weasyprint"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b.sb.hooks.pdfToolDirs = []string{t.TempDir()}
	b.asWith(nil, []string{"PATH=" + bin + ":/usr/bin"}, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "PDF reports need weasyprint") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	for _, c := range b.sb.runner.Calls() {
		if strings.HasSuffix(c.Name, "weasyprint") {
			t.Errorf("ran %q", c.Name)
		}
	}
}

// A PDF is binary: at a terminal it is not written, and nothing is read.
func TestReportsPDFStdoutRefusesATerminal(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	b.asWith(pdfStub(tool), nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "A PDF is binary: redirect --stdout to a file, or leave it out to store the report.") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.sb.out.Len() != 0 || len(toolCalls(b.sb.runner, tool)) != 0 {
		t.Errorf("stdout %q, %d runs of the tool", b.sb.out.String(), len(toolCalls(b.sb.runner, tool)))
	}
	// storing the report at a terminal is what the verb is for
	out := b.asWith(pdfStub(tool), nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
	if b.sb.code != 0 || writtenRE.FindStringSubmatch(out) == nil {
		t.Errorf("stored: exit %d %q %q", b.sb.code, out, b.sb.stderr())
	}
}

// What the tool prints is not trusted and not shown in full: five lines at the
// most, none that holds markup, cleaned, and nothing is written.
func TestReportsPDFToolFails(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	script := func(r *fake.Runner) {
		r.On([]string{tool}, execx.Result{Code: 3, Stderr: []byte("ERROR: one\n<td>sw1 SN000001</td> quoted\ntwo\x1b[31m\nthree\nfour\nfive\nsix\n")})
	}
	for _, args := range [][]string{
		{"generate", "--type", "inventory", "--format", "pdf"},
		{"generate", "--type", "inventory", "--format", "pdf", "--stdout"},
	} {
		b.asWith(script, nil, "alice", asSuper, args...)
		e := b.sb.stderr()
		if b.sb.code != 1 || !strings.Contains(e, "[ERROR] Cannot make the PDF: the PDF tool (weasyprint) failed with exit status 3: ERROR: one; two?[31m; three; four; five.") ||
			!strings.Contains(e, "Nothing was written.") {
			t.Errorf("%v: exit %d %q", args, b.sb.code, e)
		}
		if strings.Contains(e, "SN000001") || strings.Contains(e, "six") || strings.Contains(e, "\x1b") {
			t.Errorf("%v: too much of the tool's error: %q", args, e)
		}
		if b.sb.out.Len() != 0 {
			t.Errorf("%v: stdout %q", args, b.sb.out.String())
		}
	}
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Errorf("the directory was made: %v", err)
	}
}

func TestReportsPDFToolMakesNoPDF(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	for name, res := range map[string]execx.Result{
		"empty":     {},
		"not a pdf": {Stdout: []byte("<html>hello</html>")},
	} {
		b.asWith(func(r *fake.Runner) { r.On([]string{tool}, res) }, nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
		if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the PDF tool (weasyprint) made no PDF") {
			t.Errorf("%s: exit %d %q", name, b.sb.code, b.sb.stderr())
		}
	}
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Errorf("the directory was made: %v", err)
	}
}

func TestReportsPDFToolCannotBeRun(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	b.asWith(func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == tool }, func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Code: 126}, os.ErrPermission
		})
	}, nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Cannot make the PDF: the PDF tool (weasyprint) cannot be run: permission denied") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
}

// A tool that does not end in time is stopped; one that writes too much is
// too. Neither leaves a file.
func TestReportsPDFTimeoutAndOutputLimit(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	b.sb.hooks.pdfTimeout = 20 * time.Millisecond
	b.asWith(func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == tool }, func(execx.Cmd) (execx.Result, error) {
			time.Sleep(200 * time.Millisecond)
			return execx.Result{Code: 137}, context.DeadlineExceeded
		})
	}, nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Cannot make the PDF: the PDF tool (weasyprint) did not finish in 20ms and was stopped.") ||
		!strings.Contains(b.sb.stderr(), "Nothing was written.") {
		t.Errorf("timeout: exit %d %q", b.sb.code, b.sb.stderr())
	}
	b.sb.hooks.pdfTimeout = 0
	b.sb.hooks.pdfMaxOutput = 100
	b.asWith(func(r *fake.Runner) {
		r.On([]string{tool}, execx.Result{Stdout: append([]byte("%PDF-1.7\n"), make([]byte, 200)...)})
	}, nil, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the PDF tool (weasyprint) wrote more than 100 B and was stopped.") {
		t.Errorf("limit: exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.sb.out.Len() != 0 {
		t.Errorf("stdout %q", b.sb.out.String())
	}
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Errorf("the directory was made: %v", err)
	}
}

// The defaults are the documented ones.
func TestReportsPDFDefaultLimits(t *testing.T) {
	var h *hooks
	if d, n := h.pdfLimits(); d != 120*time.Second || n != 64<<20 {
		t.Errorf("limits %v %d", d, n)
	}
}

// Run as root through sudo, the tool runs as the person who ran sudo: their
// user and group, no supplementary groups, their home; never as root, and not
// for an account that is not the one sudo ran this for.
func TestReportsPDFRunsAsTheCaller(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	home := filepath.Join(b.sb.dir, "home")
	b.sb.hooks.editEuid = func() int { return 0 }
	b.sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		return sshAccount{UID: 1001, GID: 1001, Groups: []uint32{27, 1001}, Home: filepath.Join(home, name)}, nil
	}
	sudo := []string{"SUDO_UID=1001", "SUDO_GID=1001"}
	b.asWith(pdfStub(tool), sudo, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	c := toolCalls(b.sb.runner, tool)[0].Cmd
	if c.Credential == nil || c.Credential.Uid != 1001 || c.Credential.Gid != 1001 || len(c.Credential.Groups) != 0 || c.Credential.NoSetGroups {
		t.Errorf("credential %+v", c.Credential)
	}
	wantEnv := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + filepath.Join(home, "alice"), "XDG_CACHE_HOME=" + filepath.Join(home, "alice")}
	if strings.Join(c.Env, "\n") != strings.Join(wantEnv, "\n") {
		t.Errorf("environment %q", c.Env)
	}
	// SUDO_GID is the group: a different one from the account's is the one used
	b.asWith(pdfStub(tool), []string{"SUDO_UID=1001", "SUDO_GID=2002"}, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if c := toolCalls(b.sb.runner, tool)[0].Cmd; c.Credential == nil || c.Credential.Gid != 2002 {
		t.Errorf("credential %+v", c.Credential)
	}
	// an account that is not SUDO_UID's: refused, the tool is not run
	b.sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		return sshAccount{UID: 4242, GID: 4242, Home: filepath.Join(home, name)}, nil
	}
	b.asWith(pdfStub(tool), sudo, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the account of 'alice' is not the one sudo ran this for") || len(toolCalls(b.sb.runner, tool)) != 0 {
		t.Errorf("mismatch: exit %d %q", b.sb.code, b.sb.stderr())
	}
	// a process that is not root runs the tool as itself
	b.sb.hooks.editEuid = func() int { return 1000 }
	b.asWith(pdfStub(tool), sudo, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if c := toolCalls(b.sb.runner, tool); b.sb.code != 0 || len(c) != 1 || c[0].Cmd.Credential != nil {
		t.Errorf("not root: exit %d %q", b.sb.code, b.sb.stderr())
	}
}

// With the real runner, a program that never stops writing is stopped by the
// limit (the capture cancels the run), and one that never stops is stopped by
// the deadline; neither is waited for.
func TestPDFCaptureStopsARealProgram(t *testing.T) {
	if _, err := (execx.Real{}).LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run, stop := context.WithCancel(ctx)
	out := &pdfCapture{max: 1000, cancel: stop}
	start := time.Now()
	_, err := execx.Real{}.Run(run, execx.Cmd{Name: "sh", Args: []string{"-c", "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"}, Stdout: out})
	if !out.over || out.buf.Len() > 1000 || err == nil || time.Since(start) > 20*time.Second {
		t.Errorf("over %v, %d bytes, err %v, after %v", out.over, out.buf.Len(), err, time.Since(start))
	}
	short, stop2 := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop2()
	start = time.Now()
	_, err = execx.Real{}.Run(short, execx.Cmd{Name: "sh", Args: []string{"-c", "while :; do :; done"}})
	if short.Err() == nil || err == nil || time.Since(start) > 20*time.Second {
		t.Errorf("err %v after %v", err, time.Since(start))
	}
}

// Tab offers the four formats, pdf included.
func TestReportsPDFFormatIsCompleted(t *testing.T) {
	got, _ := completeWords(t, liveNames, "device", "reports", "generate", "--type", "inventory", "--format", "")
	if strings.Join(got, " ") != "text csv json pdf" {
		t.Errorf("offered %q", got)
	}
	got, _ = completeWords(t, liveNames, "device", "reports", "generate", "--format", "p")
	if strings.Join(got, " ") != "pdf" {
		t.Errorf("offered %q for p", got)
	}
}
