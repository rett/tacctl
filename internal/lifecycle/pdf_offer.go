package lifecycle

// The offer of the PDF tools (0.2.27). 'tacctl device reports generate
// --format pdf' needs weasyprint and the DejaVu fonts (DepsPDF), which are
// optional: 'install' and the dependency step of 'upgrade' leave them alone.
// The last step of a successful upgrade offers them once. At a terminal it
// asks (default no); without one it prints the command that installs them.
// A "no" is remembered in a marker of the state directory, so that it is not
// asked at every upgrade. Nothing here can fail the upgrade, and a rollback
// neither reads nor writes the marker.

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/paths"
)

// PDFOfferDone reports whether the offer was declined (the marker
// p.PDFOfferMarker). An empty path is always done: nothing records it.
func PDFOfferDone(p paths.Paths) bool {
	if p.PDFOfferMarker == "" {
		return true
	}
	_, err := os.Stat(p.PDFOfferMarker)
	return err == nil
}

// MarkPDFOffer records that the offer was declined (the marker, 0600, in
// VarLib). Deleting it asks again at the next upgrade.
func MarkPDFOffer(p paths.Paths) error {
	if p.PDFOfferMarker == "" {
		return nil
	}
	if err := paths.MkVarLib(filepath.Dir(p.PDFOfferMarker)); err != nil {
		return err
	}
	return os.WriteFile(p.PDFOfferMarker, []byte("tacctl 0.2.27 offered, at an upgrade, to install weasyprint and fonts-dejavu-core for the PDF device reports, and the answer was no. Delete this file only to be asked again.\n"), 0o600)
}

// PDFOfferQuestion is what an upgrade asks at a terminal (the default is no).
const PDFOfferQuestion = "tacctl can write device reports as PDF. Install weasyprint and fonts-dejavu-core now? [y/N]: "

// terminal says whether a terminal can answer a question of the upgrade.
func (h *Host) terminal() bool {
	if h.Terminal != nil {
		return h.Terminal()
	}
	return h.Prompt().Interactive()
}

// pdfYes says whether an answer is a yes: y or yes, in any case.
func pdfYes(answer string) bool {
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

// pdfInstallLine is the command that installs the PDF tools.
func pdfInstallLine() string {
	return "sudo apt-get install -y " + strings.Join(DepsPDF, " ")
}

// pdfOffer is the last step of an upgrade: when apt-get and dpkg-query are
// there and a package of DepsPDF is not installed, and the offer was not
// declined before, it asks (at a terminal) to install them, or says the
// command to (without one). The default is no.
func (h *Host) pdfOffer(ctx context.Context) {
	if PDFOfferDone(h.Paths) || !h.has("apt-get") || !h.has("dpkg-query") {
		return
	}
	var missing []string
	for _, p := range DepsPDF {
		if !h.pkgInstalled(ctx, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return
	}
	out := h.Out
	if !h.terminal() {
		h.echo("tacctl can write device reports as PDF. To install what it needs: " + pdfInstallLine())
		h.echo("")
		return
	}
	if !pdfYes(h.Prompt().Ask(PDFOfferQuestion)) {
		if _, err := os.Stat(filepath.Dir(h.Paths.PDFOfferMarker)); err == nil {
			if err := MarkPDFOffer(h.Paths); err != nil {
				out.Warn("Could not record the answer in " + h.Paths.PDFOfferMarker + ": " + strings.TrimSpace(err.Error()))
			}
		}
		out.Info("Not installed; install them later with: " + pdfInstallLine())
		h.echo("")
		return
	}
	out.Info("Installing the PDF tools: " + strings.Join(missing, " "))
	if h.aptInstall(ctx, missing) {
		out.Info("Installed " + strings.Join(missing, " ") + ": 'tacctl device reports generate --format pdf' works now.")
	} else {
		out.Warn("Could not install: " + strings.Join(missing, " ") + ". PDF reports need them; install them with: " + pdfInstallLine())
	}
	h.echo("")
}
