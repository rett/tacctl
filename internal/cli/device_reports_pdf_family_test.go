package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/reports"
	"github.com/rett/tacctl/internal/ui"
)

// A PDF report in the rest of the family: list, show, export, rename, remove,
// prune, the superuser's reach and the completion of names. A PDF is binary,
// so it is never printed to a terminal, and the extension is the one the
// metadata file says.

// binaryStub is the tool that makes a PDF with bytes a terminal would act on:
// %PDF-1.7, the HTML it was given, then a colour sequence, a NUL and a byte
// that is no UTF-8.
func binaryStub(tool string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.OnFunc([]string{tool}, func(c execx.Cmd) (execx.Result, error) {
			in, _ := io.ReadAll(c.Stdin)
			out := append([]byte("%PDF-1.7\n"), in...)
			return execx.Result{Stdout: append(out, "\x1b[31m\x00\xff\x1b]0;title\x07"...)}, nil
		})
	}
}

// genPDF makes a PDF report of a user and returns its name and file.
func (b *reportsBox) genPDF(tool, user, groups string, args ...string) (name, file string) {
	b.t.Helper()
	out := b.asWith(binaryStub(tool), nil, user, groups, append([]string{"generate", "--format", "pdf"}, args...)...)
	m := writtenRE.FindStringSubmatch(out)
	if b.sb.code != 0 || m == nil {
		b.t.Fatalf("generate pdf %v: %d %q %q", args, b.sb.code, out, b.sb.stderr())
	}
	return m[1], m[2]
}

// seedPDF writes a PDF report of a user straight into the directory, generated
// ago before now.
func (b *reportsBox) seedPDF(user, name string, ago time.Duration) string {
	b.t.Helper()
	dir := b.dir(user)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.t.Fatal(err)
	}
	body := []byte("%PDF-1.7\nseeded " + name + "\n")
	mb, err := reports.MarshalMeta(reports.Meta{Name: name, Type: "inventory", Format: reports.FormatPDF, User: user,
		Command: "tacctl device reports generate --type inventory --format pdf", Generated: time.Now().Add(-ago).UTC(), Size: int64(len(body)), Count: 3})
	if err != nil {
		b.t.Fatal(err)
	}
	p := filepath.Join(dir, name+".pdf")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(p+".meta", mb, 0o600); err != nil {
		b.t.Fatal(err)
	}
	return p
}

func TestReportsPDFListShowAndExport(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	name, file := b.genPDF(tool, "alice", asSuper, "--type", "inventory")
	want, err := os.ReadFile(file)
	if err != nil || !bytes.Contains(want, []byte("\x1b[31m\x00\xff")) {
		t.Fatalf("%v %.40q", err, want)
	}

	// list: the format is pdf, in the text and in the JSON
	out := b.as("alice", asSuper, "list")
	if b.sb.code != 0 || !strings.Contains(out, name) || !strings.Contains(out, "pdf") || !strings.Contains(out, "inventory") {
		t.Errorf("list: %d %q", b.sb.code, out)
	}
	out = b.as("alice", asSuper, "list", "--json")
	for _, w := range []string{`"file": "` + name + `.pdf"`, `"format": "pdf"`, `"type": "inventory"`, `"other": false`} {
		if !strings.Contains(out, w) {
			t.Errorf("list --json lacks %q:\n%s", w, out)
		}
	}

	// show: the facts; --content says what it is and prints no byte of it
	out = b.as("alice", asSuper, "show", name)
	for _, w := range []string{"  Format:       pdf", "  File:         " + file, "  Download:     scp ", name + ".pdf ."} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	out = b.as("alice", asSuper, "show", name, "--content")
	if b.sb.code != 0 || !strings.Contains(out, "binary PDF, "+strconv.Itoa(len(want))+" bytes: use export") {
		t.Errorf("show --content: %d %q", b.sb.code, out)
	}
	for _, not := range []string{"%PDF", "<html", "\x1b", "\x00", "more line"} {
		if strings.Contains(out, not) {
			t.Errorf("show --content printed %q:\n%q", not, out)
		}
	}
	// by its file name too
	if out = b.as("alice", asSuper, "show", name+".pdf", "--content"); !strings.Contains(out, "binary PDF, ") {
		t.Errorf("show by file name: %q", out)
	}

	// export to a pipe or a file: every byte as stored
	// (as strips colour sequences from what it returns: the raw output is compared)
	b.as("alice", asSuper, "export", name)
	if got := b.sb.out.String(); b.sb.code != 0 || got != string(want) {
		t.Errorf("export: %d %q, want %q", b.sb.code, got, want)
	}
	// export to a terminal: refused, nothing printed
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	out = b.as("alice", asSuper, "export", name)
	if b.sb.code != 1 || out != "" || !strings.Contains(b.sb.stderr(), "[ERROR] PDF is binary: use --out FILE or redirect") {
		t.Errorf("export at a terminal: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	// --out is the way at a terminal, and writes the bytes
	home := filepath.Join(b.sb.dir, "home", "alice")
	copyTo := filepath.Join(home, "copy.pdf")
	b.as("alice", asSuper, "export", name, "--out", copyTo)
	if got, err := os.ReadFile(copyTo); b.sb.code != 0 || err != nil || !bytes.Equal(got, want) {
		t.Errorf("export --out: %d %v", b.sb.code, err)
	}
}

func TestReportsPDFRenameRemovePrune(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	name, file := b.genPDF(tool, "alice", asSuper, "--type", "software", "--name", "sw-pdf")
	dir := b.dir("alice")

	// rename keeps the extension and rewrites the name in the metadata
	out := b.as("alice", asSuper, "rename", name, "sw-renamed")
	if b.sb.code != 0 || !strings.Contains(out+b.sb.stderr(), "Report sw-pdf is now sw-renamed (sw-renamed.pdf).") {
		t.Fatalf("rename: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if exists(t, file) || exists(t, file+".meta") || !exists(t, filepath.Join(dir, "sw-renamed.pdf")) {
		t.Error("the files after the rename")
	}
	mb, err := os.ReadFile(filepath.Join(dir, "sw-renamed.pdf.meta"))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := reports.ParseMeta(mb); err != nil || m.Name != "sw-renamed" || m.Format != "pdf" {
		t.Errorf("meta %+v %v", m, err)
	}
	// a name is taken in any format
	b.genPDF(tool, "alice", asSuper, "--type", "config", "--name", "other-pdf")
	b.as("alice", asSuper, "rename", "other-pdf", "sw-renamed")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "exists: a report is never overwritten") {
		t.Errorf("rename over a name: %d %q", b.sb.code, b.sb.stderr())
	}
	b.as("alice", asSuper, "export", "sw-renamed")
	if b.sb.code != 0 {
		t.Errorf("export after rename: %d %q", b.sb.code, b.sb.stderr())
	}

	// remove takes the file and its metadata
	b.asYes("", "alice", asSuper, "remove", "other-pdf", "--yes")
	if b.sb.code != 0 || exists(t, filepath.Join(dir, "other-pdf.pdf")) || exists(t, filepath.Join(dir, "other-pdf.pdf.meta")) {
		t.Errorf("remove: %d %q", b.sb.code, b.sb.stderr())
	}

	// prune goes by the generated date in the metadata and removes both files
	old := b.seedPDF("alice", "old-pdf", 10*day)
	young := b.seedPDF("alice", "young-pdf", time.Hour)
	out = b.as("alice", asSuper, "prune", "--older-than", "7d", "--dry-run")
	if b.sb.code != 0 || !strings.Contains(out, "old-pdf") || strings.Contains(out, "young-pdf") || !exists(t, old) {
		t.Errorf("prune --dry-run: %d %q", b.sb.code, out)
	}
	b.asYes("", "alice", asSuper, "prune", "--older-than", "7d", "--yes")
	if b.sb.code != 0 || exists(t, old) || exists(t, old+".meta") || !exists(t, young) || !exists(t, young+".meta") || !exists(t, filepath.Join(dir, "sw-renamed.pdf")) {
		t.Errorf("prune: %d %q", b.sb.code, b.sb.stderr())
	}
}

// A file that is not a report but ends in .pdf is binary too.
func TestReportsPDFFileOfYourOwn(t *testing.T) {
	b := newReportsBox(t)
	dir := b.dir("alice")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mine.pdf"), []byte("%PDF-1.4\n\x1b[2J\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := b.as("alice", asSuper, "list")
	if !strings.Contains(out, "mine") || !strings.Contains(out, "other") || !strings.Contains(out, "pdf") {
		t.Errorf("list: %q", out)
	}
	out = b.as("alice", asSuper, "show", "mine", "--content")
	if b.sb.code != 0 || !strings.Contains(out, "binary PDF, 14 bytes: use export") || strings.Contains(out, "\x1b") || strings.Contains(out, "%PDF") {
		t.Errorf("show --content: %d %q", b.sb.code, out)
	}
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	if out = b.as("alice", asSuper, "export", "mine"); b.sb.code != 1 || out != "" || !strings.Contains(b.sb.stderr(), "PDF is binary: use --out FILE or redirect") {
		t.Errorf("export at a terminal: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	b.as("alice", asSuper, "rename", "mine", "yours")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "did not make") {
		t.Errorf("rename: %d %q", b.sb.code, b.sb.stderr())
	}
}

// The superuser reads another user's PDF report with the same audit line as
// any report, and it too is refused at a terminal; to a pipe it is the bytes
// as they are (the cleaning of lines is for text).
func TestReportsPDFSuperuserReach(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	name, file := b.genPDF(tool, "bob", asOperator, "--type", "software")
	want, _ := os.ReadFile(file)

	out := b.as("alice", asSuper, "list", "--all-users")
	if b.sb.code != 0 || !strings.Contains(out, "bob") || !strings.Contains(out, name) || !strings.Contains(out, "pdf") {
		t.Errorf("list --all-users: %d %q", b.sb.code, out)
	}
	out = b.as("alice", asSuper, "show", "bob/"+name, "--content")
	if b.sb.code != 0 || !strings.Contains(out, "binary PDF, "+strconv.Itoa(len(want))+" bytes: use export") || strings.Contains(out, "%PDF") {
		t.Errorf("show: %d %q", b.sb.code, out)
	}
	b.as("alice", asSuper, "export", "bob/"+name)
	if got := b.sb.out.String(); b.sb.code != 0 || got != string(want) {
		t.Errorf("export to a pipe: %d %q", b.sb.code, got)
	}
	if l := b.audits(); len(l) != 1 || !strings.Contains(l[0], "device reports access verb=export owner=bob report="+name+" by=alice") {
		t.Errorf("audit: %v", l)
	}
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	out = b.as("alice", asSuper, "export", "bob/"+name)
	if b.sb.code != 1 || out != "" || !strings.Contains(b.sb.stderr(), "PDF is binary: use --out FILE or redirect") {
		t.Errorf("export at a terminal: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if l := b.audits(); len(l) != 1 || !strings.Contains(l[0], "verb=export owner=bob") {
		t.Errorf("audit of the refused export: %v", l)
	}
	// --out copies the bytes, at a terminal too
	if err := os.MkdirAll(filepath.Join(b.sb.dir, "home", "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	copyTo := filepath.Join(b.sb.dir, "home", "alice", "bobs.pdf")
	b.as("alice", asSuper, "export", "bob/"+name, "--out", copyTo)
	if got, err := os.ReadFile(copyTo); b.sb.code != 0 || err != nil || !bytes.Equal(got, want) {
		t.Errorf("export --out: %d %v", b.sb.code, err)
	}
}

// The names that completion offers include the PDF reports, by name.
func TestReportsPDFCompletion(t *testing.T) {
	b := newReportsBox(t)
	tool := b.pdfTool()
	name, _ := b.genPDF(tool, "alice", asSuper, "--type", "inventory")
	other := b.generate("alice", asSuper, "--type", "software", "--format", "csv")
	out := b.sb.asUser("alice", asSuper, "_completion-names", "reports")
	if b.sb.code != 0 || !strings.Contains(out, name+"\n") || !strings.Contains(out, other+"\n") || strings.Contains(out, ".pdf") {
		t.Errorf("completion: %d %q", b.sb.code, out)
	}
}

// A PDF goes to the file behind the output, past the filter that takes colour
// sequences out of the stream, which would cut them out of a PDF too.
func TestWriteRawBypassesTheColourFilter(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	plainOut := ui.Plain(f)
	inv := &invocation{app: &app.App{Out: ui.Output{Stdout: plainOut, Stderr: io.Discard}}}
	data := []byte("%PDF-1.7\n\x1b[31mred\x1b[0m\x00\xff")
	if err := inv.writeRaw(data); err != nil {
		t.Fatal(err)
	}
	_ = plainOut.Close()
	if got, err := os.ReadFile(f.Name()); err != nil || !bytes.Equal(got, data) {
		t.Errorf("%q %v", got, err)
	}
	// through the filter the sequences would be gone
	var kept bytes.Buffer
	filtered := ui.Plain(&kept)
	_, _ = filtered.Write(data)
	_ = filtered.Close()
	if bytes.Equal(kept.Bytes(), data) {
		t.Error("the filter keeps colour sequences: writeRaw has no reason to bypass it")
	}
}

// What another user wrote is not trusted with the superuser's terminal,
// whatever their metadata file says: a text file whose metadata says pdf, or a
// .pdf file that holds no PDF, is cleaned line by line as any other text.
func TestReportsPDFMetaDoesNotUnlockTheTerminalForASuperuser(t *testing.T) {
	b := newReportsBox(t)
	dir := b.dir("bob")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	evil := "hello \x1b[31mred\x1b]0;title\x07 end\n"
	for _, file := range []string{"fake.txt", "fake2.pdf"} {
		name := strings.TrimSuffix(file, filepath.Ext(file))
		mb, err := reports.MarshalMeta(reports.Meta{Name: name, Type: "inventory", Format: reports.FormatPDF, User: "bob",
			Command: "tacctl device reports generate --type inventory --format pdf", Generated: time.Now().UTC(), Size: int64(len(evil)), Count: 1})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, file)
		if err := os.WriteFile(p, []byte(evil), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+".meta", mb, 0o600); err != nil {
			t.Fatal(err)
		}
		out := b.as("alice", asSuper, "export", "bob/"+file)
		if b.sb.code != 0 || out != "hello ?[31mred?]0;title? end\n" {
			t.Errorf("%s: exit %d %q %q", file, b.sb.code, out, b.sb.stderr())
		}
	}
}

// A file whose extension is not .pdf is not a PDF, whatever its metadata says.
func TestReportsIsPDFNeedsTheExtension(t *testing.T) {
	for _, c := range []struct {
		f    reportFile
		want bool
	}{
		{reportFile{File: "a.pdf"}, true},
		{reportFile{File: "a.PDF"}, true},
		{reportFile{File: "a.pdf", Meta: &reports.Meta{Format: reports.FormatPDF}}, true},
		{reportFile{File: "a.pdf", Meta: &reports.Meta{Format: reports.FormatText}}, false},
		{reportFile{File: "a.txt", Meta: &reports.Meta{Format: reports.FormatPDF}}, false},
		{reportFile{File: "a.txt"}, false},
	} {
		if got := c.f.isPDF(); got != c.want {
			t.Errorf("%+v: isPDF %v, want %v", c.f, got, c.want)
		}
	}
}

// failingWriter takes at most room bytes and then fails (a full disk, a closed
// pipe).
type failingWriter struct{ room int }

func (w *failingWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.room)
	w.room -= n
	if n < len(p) {
		return n, errors.New("no space left on device")
	}
	return n, nil
}

// runTo is cfgRun with the standard output given, for a user of a group.
func (b *reportsBox) runTo(stdout io.Writer, script func(*fake.Runner), user, groups string, args ...string) int {
	b.t.Helper()
	sb := b.sb
	sb.err.Reset()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	fakePasswd(sb.runner)
	idAs(user, "tac-users "+groups)(sb.runner)
	script(sb.runner)
	a := app.New(append([]string{"device", "reports"}, args...), paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER="+user)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: stdout, Stderr: &sb.err}, sb.runner)
	a.SNMP = sb.snmp
	a.Resolve = sb.resolve
	a.Paths.ConsoleCommand = sb.consoleCommand()
	a.Paths.EditDir = sb.editDir()
	sb.code = exitCode(runWith(sb.runCtx(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}, sb.hooks), a.Out)
	return sb.code
}

// A PDF that cannot be written to standard output (a full disk, a closed pipe)
// is a failure: the exit status is 1 and the error says so, not a truncated
// file with exit status 0.
func TestWriteRawReportsAFailedWrite(t *testing.T) {
	inv := &invocation{app: &app.App{Out: ui.Output{Stdout: &failingWriter{room: 4}, Stderr: io.Discard}}}
	if err := inv.writeRaw([]byte("%PDF-1.7\n")); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Errorf("a failing writer: %v", err)
	}
	var ok bytes.Buffer
	inv.app.Out.Stdout = &ok
	if err := inv.writeRaw([]byte("%PDF-1.7\n")); err != nil || ok.String() != "%PDF-1.7\n" {
		t.Errorf("a writer that works: %v %q", err, ok.String())
	}

	b := newReportsBox(t)
	tool := b.pdfTool()
	// generate --stdout
	code := b.runTo(&failingWriter{room: 10}, pdfStub(tool), "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if code != 1 || !strings.Contains(b.sb.stderr(), "[ERROR] Cannot write the PDF to standard output: no space left on device") {
		t.Errorf("generate --stdout: exit %d %q", code, b.sb.stderr())
	}
	// export of a stored report, own and another user's
	_, _ = b.genPDF(tool, "alice", asSuper, "--type", "inventory", "--name", "mine")
	_, _ = b.genPDF(tool, "bob", asOperator, "--type", "inventory", "--name", "his")
	for _, ref := range []string{"mine", "bob/his"} {
		code = b.runTo(&failingWriter{room: 10}, func(*fake.Runner) {}, "alice", asSuper, "export", ref)
		if code != 1 || !strings.Contains(b.sb.stderr(), "[ERROR] Cannot write the PDF to standard output: no space left on device") {
			t.Errorf("export %s: exit %d %q", ref, code, b.sb.stderr())
		}
	}
	// and it still works when the writer does
	var good bytes.Buffer
	if code = b.runTo(&good, func(*fake.Runner) {}, "alice", asSuper, "export", "mine"); code != 0 || !strings.HasPrefix(good.String(), "%PDF-1.7\n") {
		t.Errorf("export: exit %d %.40q %q", code, good.String(), b.sb.stderr())
	}
}
