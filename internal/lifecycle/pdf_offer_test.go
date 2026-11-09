package lifecycle_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
)

// The offer of the PDF tools at the end of an upgrade: weasyprint and
// fonts-dejavu-core are optional, so the upgrade asks once (default no) at a
// terminal, says the command without one, remembers a no in a marker of the
// state directory, and never fails because of it.

// pdfHost is an upgrade host with VarLib in place and the PDF tools not
// installed (everything else is). terminal says whether a terminal answers.
func pdfHost(t *testing.T, terminal bool, answer string, installed ...string) *ohost {
	t.Helper()
	o := newOhost(t)
	o.cloned()
	o.write(filepath.Join(o.p.VarLib, "devices-seen.json"), "{}\n")
	o.dpkg(slices.Concat(allDeps(), installed)...)
	o.terminal = func() bool { return terminal }
	o.stdin = answer
	return o
}

// aptInstalls are the apt-get install commands of the last run.
func aptInstalls(o *ohost) []string {
	var out []string
	for _, c := range o.run.Calls() {
		if c.Name == "apt-get" && len(c.Args) > 0 && c.Args[0] == "install" {
			out = append(out, strings.Join(c.Args, " "))
		}
	}
	return out
}

// mentionsPDF says whether a text speaks of the PDF tools (the sandbox paths
// of a test hold the word too, so the words of the offer are looked for).
func mentionsPDF(s string) bool {
	return strings.Contains(s, "as PDF") || strings.Contains(s, "weasyprint") || strings.Contains(s, "PDF tools")
}

const pdfLine = "sudo apt-get install -y weasyprint fonts-dejavu-core"

func TestPDFOfferWhenInstalledSaysNothing(t *testing.T) {
	o := pdfHost(t, true, "y\n", "weasyprint", "fonts-dejavu-core")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if mentionsPDF(o.text()+o.stderr.String()) || len(aptInstalls(o)) != 0 || lifecycle.PDFOfferDone(o.p) {
		t.Errorf("out %q err %q installs %v", o.text(), o.stderr, aptInstalls(o))
	}
}

// Without a terminal nothing is asked and nothing is installed: the command is
// printed, at every upgrade, and no marker is written.
func TestPDFOfferWithoutATerminalPrintsTheCommand(t *testing.T) {
	for _, have := range [][]string{nil, {"weasyprint"}, {"fonts-dejavu-core"}} {
		o := pdfHost(t, false, "y\n", have...)
		for i := 0; i < 2; i++ {
			if code := upgrade(o); code != 0 {
				t.Fatalf("exit %d\n%s", code, o.stderr)
			}
			if got := strings.Count(o.text(), "tacctl can write device reports as PDF. To install what it needs: "+pdfLine+"\n"); got != 1 {
				t.Errorf("have %v, run %d: %d lines:\n%s", have, i, got, o.text())
			}
			if len(aptInstalls(o)) != 0 || lifecycle.PDFOfferDone(o.p) {
				t.Errorf("installs %v, marker %v", aptInstalls(o), lifecycle.PDFOfferDone(o.p))
			}
		}
	}
}

func TestPDFOfferYesInstallsWhatIsMissing(t *testing.T) {
	o := pdfHost(t, true, "y\n", "fonts-dejavu-core")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if got := aptInstalls(o); len(got) != 1 || got[0] != "install -y -qq weasyprint" {
		t.Errorf("installs %v", got)
	}
	var env []string
	for _, c := range o.run.Calls() {
		if c.Name == "apt-get" && c.Args[0] == "install" {
			env = c.Env
		}
	}
	if !slices.Contains(env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("apt-get ran with %q", env)
	}
	if !strings.Contains(o.text(), "Installed weasyprint: 'tacctl device reports generate --format pdf' works now.") {
		t.Errorf("no report of the install:\n%s", o.text())
	}
	if lifecycle.PDFOfferDone(o.p) {
		t.Error("a yes left a marker")
	}
	// both missing: both are installed, in one call
	o = pdfHost(t, true, "Y\n")
	upgrade(o)
	if got := aptInstalls(o); len(got) != 1 || got[0] != "install -y -qq weasyprint fonts-dejavu-core" {
		t.Errorf("installs %v", got)
	}
}

// A failed install is a warning with the command; the upgrade is done and
// exits 0, no marker is written (the person said yes), and the update retry of
// the other installs happens.
func TestPDFOfferInstallFailureNeverFailsTheUpgrade(t *testing.T) {
	o := pdfHost(t, true, "y\n")
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "apt-get" }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Code: 100}, nil
	})
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if got := aptInstalls(o); len(got) != 2 || !o.run.Called("apt-get", "update", "-qq") {
		t.Errorf("installs %v, calls %v", got, o.run.Argvs())
	}
	if !strings.Contains(o.text(), "Could not install: weasyprint fonts-dejavu-core. PDF reports need them; install them with: "+pdfLine) {
		t.Errorf("stderr: %s", o.stderr)
	}
	if lifecycle.PDFOfferDone(o.p) {
		t.Error("a failure left a marker")
	}
	if !strings.Contains(o.text(), "Upgrade Complete") && !strings.Contains(o.text(), "Managed scripts") {
		t.Errorf("the upgrade did not finish:\n%s", o.text())
	}
}

// y, Y and yes (in any case, blanks around it ignored) install; see
// TestPDFOfferNoIsRemembered for what does not.
func TestPDFOfferYesWordInstalls(t *testing.T) {
	for _, answer := range []string{"yes\n", "YES\n", "Yes\n", "  yes \n", "y\n", "Y\n", "yes"} {
		o := pdfHost(t, true, answer)
		if code := upgrade(o); code != 0 {
			t.Fatalf("%q: exit %d\n%s", answer, code, o.stderr)
		}
		if got := aptInstalls(o); len(got) != 1 || got[0] != "install -y -qq weasyprint fonts-dejavu-core" || lifecycle.PDFOfferDone(o.p) {
			t.Errorf("%q: installs %v, marker %v", answer, got, lifecycle.PDFOfferDone(o.p))
		}
	}
}

// Anything but y, Y or yes is no: the default, an n, no, other words and the end of
// input. A no is remembered, so the next upgrade does not ask or install, and
// deleting the marker asks again.
func TestPDFOfferNoIsRemembered(t *testing.T) {
	for name, answer := range map[string]string{"default": "\n", "n": "n\n", "word": "no thanks\n", "yes please": "yes please\n", "eof": ""} {
		t.Run(name, func(t *testing.T) {
			o := pdfHost(t, true, answer)
			if code := upgrade(o); code != 0 {
				t.Fatalf("exit %d\n%s", code, o.stderr)
			}
			if len(aptInstalls(o)) != 0 || !lifecycle.PDFOfferDone(o.p) {
				t.Fatalf("installs %v, marker %v", aptInstalls(o), lifecycle.PDFOfferDone(o.p))
			}
			if !strings.Contains(o.stderr.String()+o.text(), "Not installed; install them later with: "+pdfLine) {
				t.Errorf("no word of the way later:\n%s\n%s", o.text(), o.stderr)
			}
			fi, err := os.Stat(o.p.PDFOfferMarker)
			if err != nil || fi.Mode().Perm() != 0o600 || filepath.Base(o.p.PDFOfferMarker) != "pdf-tools-offered" || filepath.Dir(o.p.PDFOfferMarker) != o.p.VarLib {
				t.Fatalf("marker %v %v", o.p.PDFOfferMarker, err)
			}
			// the next upgrade neither asks nor says: even a y is not read
			o.stdin = "y\n"
			upgrade(o)
			if len(aptInstalls(o)) != 0 || mentionsPDF(o.text()+o.stderr.String()) {
				t.Errorf("second run: installs %v\n%s", aptInstalls(o), o.text())
			}
			// nor without a terminal
			o.terminal = func() bool { return false }
			upgrade(o)
			if mentionsPDF(o.text()) {
				t.Errorf("no terminal, marker standing:\n%s", o.text())
			}
			// the documented way to be asked again
			if err := os.Remove(o.p.PDFOfferMarker); err != nil {
				t.Fatal(err)
			}
			o.terminal = func() bool { return true }
			upgrade(o)
			if got := aptInstalls(o); len(got) != 1 || got[0] != "install -y -qq weasyprint fonts-dejavu-core" {
				t.Errorf("after deleting the marker: installs %v", got)
			}
		})
	}
}

// The offer is for a Debian or Ubuntu system, where apt-get and dpkg-query
// are: elsewhere it says nothing.
func TestPDFOfferNeedsAptAndDpkg(t *testing.T) {
	for _, missing := range []string{"apt-get", "dpkg-query"} {
		o := pdfHost(t, true, "y\n")
		o.run.Missing(missing)
		upgrade(o)
		if mentionsPDF(o.text()+o.stderr.String()) || len(aptInstalls(o)) != 0 || lifecycle.PDFOfferDone(o.p) {
			t.Errorf("without %s: %q %q", missing, o.text(), o.stderr)
		}
	}
}

// A state directory that is not there is no failure: the no is asked again
// the next time.
func TestPDFOfferNoStateDirectory(t *testing.T) {
	o := pdfHost(t, true, "n\n")
	if err := os.RemoveAll(o.p.VarLib); err != nil {
		t.Fatal(err)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if lifecycle.PDFOfferDone(o.p) {
		t.Error("a marker without a directory")
	}
}

// The question, its default and the line without a terminal are the documented
// ones; the install itself is not part of the first step of an upgrade
// (EnsureDependencies leaves the PDF tools alone) and a fresh install does not
// offer them.
func TestPDFOfferText(t *testing.T) {
	if lifecycle.PDFOfferQuestion != "tacctl can write device reports as PDF. Install weasyprint and fonts-dejavu-core now? [y/N]: " {
		t.Errorf("question %q", lifecycle.PDFOfferQuestion)
	}
	if strings.Join(lifecycle.DepsPDF, " ") != "weasyprint fonts-dejavu-core" {
		t.Errorf("DepsPDF %v", lifecycle.DepsPDF)
	}
	for _, p := range lifecycle.DepsPDF {
		if slices.Contains(allDeps(), p) {
			t.Errorf("%s is a dependency the upgrade installs", p)
		}
	}
	o := newOhost(t)
	o.dpkg(allDeps()...)
	if deps(o) != 0 || o.run.Called("apt-get") || strings.Contains(o.text(), "weasyprint") {
		t.Errorf("EnsureDependencies and the PDF tools: %q %v", o.text(), o.run.Argvs())
	}
}
