package lifecycle

// templates_sync (lib/lifecycle.sh at 0.1.16): the device config templates
// in the state directory.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/execx"
)

// TemplateManifest is TEMPLATE_MANIFEST_NAME: the record, in the templates
// directory, of what tacctl wrote there.
const TemplateManifest = ".shipped.sha256"

// TemplateSync is what TemplatesSync did.
type TemplateSync struct {
	// Updated counts the templates written in place (installed or
	// updated): its share of SCRIPTS_UPDATED.
	Updated int
	// Customised are the templates kept as the operator's, in order
	// (TEMPLATES_CUSTOMISED); this release's version of each is beside it
	// as <name>.template.new.
	Customised []string
}

// shippedTemplate is one template this release ships.
type shippedTemplate struct {
	file string // <name>.template
	text []byte
}

// shippedTemplates are the templates this binary carries
// (config/templates/*.template, embedded), in the order 0.1.16's glob
// lists the files: by file name.
func shippedTemplates() []shippedTemplate {
	var out []shippedTemplate
	for _, n := range assets.TemplateNames() {
		text, _ := assets.Template(n)
		out = append(out, shippedTemplate{file: n + ".template", text: []byte(text)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file < out[j].file })
	return out
}

var manifestLine = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TemplatesSync is templates_sync <tree>: bring the templates directory
// (paths.Templates) in line with the templates this release ships. A
// template not there yet is installed; one that is byte for byte this
// release's is left alone; one tacctl wrote earlier (its sha256 is the one
// the manifest recorded, or, with no record, it is some version of that
// template in the git history of tree) is updated; any other is the
// operator's customisation: it stays, and this release's version is written
// beside it as <name>.template.new (rewritten only when it differs), with a
// warning. The manifest (TemplateManifest: '<sha256>  <name>.template'
// lines sorted by name, as sha256sum prints them) then records every
// template that is the shipped one, and is rewritten only when that
// changes. Idempotent: a second run writes nothing.
//
// The error (a file that could not be written; reported) leaves what was
// done counted.
func (h *Host) TemplatesSync(ctx context.Context, tree string) (TemplateSync, error) {
	var res TemplateSync
	out, dir := h.Out, h.Paths.Templates
	manifest := filepath.Join(dir, TemplateManifest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, h.failed("mkdir: cannot create directory '" + dir + "': " + errno(err))
	}
	recorded := map[string]string{}
	have := ""
	if data, err := os.ReadFile(manifest); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && manifestLine.MatchString(f[0]) && strings.HasSuffix(f[1], ".template") {
				recorded[f[1]] = f[0]
			}
		}
		have = strings.TrimRight(string(data), "\n")
	}

	for _, t := range shippedTemplates() {
		dest := filepath.Join(dir, t.file)
		sum := sha256Hex(t.text)
		cur, err := os.ReadFile(dest)
		exists := err == nil && isRegular(dest)
		switch {
		case exists && string(cur) == string(t.text):
			out.Info("  Unchanged: template: " + t.file)
		case !exists || h.templateIsShipped(ctx, tree, t.file, dest, cur, recorded[t.file]):
			line := "Installed"
			if exists {
				line = "Updated"
			}
			if err := writeKeepMode(dest, t.text, 0o600); err != nil {
				return res, h.failed("cp: cannot create regular file '" + dest + "': " + errno(err))
			}
			out.Info("  " + line + ": template: " + t.file)
			res.Updated++
		default:
			// Customised: kept. This release's version goes beside it,
			// rewritten only when it is not already there.
			if prev, err := os.ReadFile(dest + ".new"); err != nil || string(prev) != string(t.text) {
				if err := writeKeepMode(dest+".new", t.text, 0o600); err != nil {
					return res, h.failed("cp: cannot create regular file '" + dest + ".new': " + errno(err))
				}
			}
			out.Warn("  Customised template kept: " + dest)
			out.Warn("    This release's version is beside it: " + dest + ".new")
			out.Warn("    Compare: diff " + dest + " " + dest + ".new  (to take it: mv " + dest + ".new " + dest + ")")
			res.Customised = append(res.Customised, t.file)
			continue
		}
		// The file is the shipped one now: record it, and drop a .new an
		// earlier run left beside it.
		recorded[t.file] = sum
		_ = os.Remove(dest + ".new")
	}

	names := make([]string, 0, len(recorded))
	for n := range recorded {
		names = append(names, n)
	}
	sort.Strings(names)
	var lines []string
	for _, n := range names {
		lines = append(lines, recorded[n]+"  "+n)
	}
	if want := strings.Join(lines, "\n"); want != have {
		tmp := manifest + ".tacctl-new"
		if err := writeKeepMode(tmp, []byte(want+"\n"), 0o600); err != nil {
			return res, h.failed("cannot create " + tmp + ": " + errno(err))
		}
		if err := os.Rename(tmp, manifest); err != nil {
			return res, h.failed("mv: cannot move '" + tmp + "' to '" + manifest + "': " + errno(err))
		}
	}
	return res, nil
}

// templateIsShipped is _template_is_shipped: is the installed file (cur) a
// version of the template that tacctl wrote? With a recorded sha256: it
// is that. Without one (a release before the manifest wrote it): it is the
// content of some commit of config/templates/<file> in the git history of
// tree; no history (not a clone) means no.
func (h *Host) templateIsShipped(ctx context.Context, tree, file, dest string, cur []byte, recorded string) bool {
	if recorded != "" {
		return sha256Hex(cur) == recorded
	}
	if h.cmd(ctx, execx.Cmd{Name: "git", Args: []string{"-C", tree, "rev-parse", "--git-dir"},
		Stdout: io.Discard, Stderr: io.Discard}).Code != 0 {
		return false
	}
	res := h.cmd(ctx, execx.Cmd{Name: "git", Args: []string{"-C", tree, "hash-object", "--no-filters", "--", dest}, Stderr: io.Discard})
	blob := strings.TrimSpace(string(res.Stdout))
	if res.Code != 0 || blob == "" {
		return false
	}
	// Every content the path had: the new-side blob of each change to it.
	res = h.cmd(ctx, execx.Cmd{Name: "git", Args: []string{"-C", tree, "log", "-m", "--format=", "--raw", "--no-abbrev",
		"--no-renames", "--", "config/templates/" + file}, Stderr: io.Discard})
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[3] == blob {
			return true
		}
	}
	return false
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// customisedNote is the summary note of 'tacctl upgrade' for the
// templates kept as the operator's ("" for none).
func customisedNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return "Templates: kept " + strconv.Itoa(len(names)) + " customised (" + strings.Join(names, " ") +
		"); this release's version of each is beside it as <name>.template.new (see above)"
}
