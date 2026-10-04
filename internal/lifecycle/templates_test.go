package lifecycle_test

// tests/integration/upgrade_templates.bats, the parts the coarser
// TestTemplatesSync* tests in orchestrate_test.go leave out: the manifest
// records and the .new files of a customised template, a re-run that
// writes nothing, a customised template brought back to the shipped one,
// and the manifest-less (pre-0.1.16) install judged against the tree's git
// history.
//
// The bats tree had two commits of cisco.template ("release 1" and
// "release 2"); here "release 2" is always the template this binary
// embeds, and "release 1" an older text: recorded in the manifest (an
// install by release 1), or in the fake git history of the tree (an
// install from before the manifest).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
)

const ciscoV1 = "hostname ${SERVER_IP} -- release 1\n"

// shippedTemplate is the text this binary ships as <name>.template.
func shippedTemplate(t *testing.T, name string) string {
	t.Helper()
	text, ok := assets.Template(name)
	if !ok {
		t.Fatalf("no shipped template %s", name)
	}
	return text
}

// hashText is the sha256 of text in hex (sha256sum's first field).
func hashText(text string) string {
	d := sha256.Sum256([]byte(text))
	return hex.EncodeToString(d[:])
}

// recorded is the manifest's record for name ("" when it has none, or
// there is no manifest).
func (o *ohost) recorded(name string) string {
	data, err := os.ReadFile(filepath.Join(o.p.Templates, lifecycle.TemplateManifest))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == name {
			return f[0]
		}
	}
	return ""
}

// installedByRelease1 is the templates directory as release 1 left it: all
// templates synced, then cisco.template the release-1 text, recorded so in
// the manifest.
func (o *ohost) installedByRelease1() {
	o.t.Helper()
	if _, code := templatesSync(o); code != 0 {
		o.t.Fatalf("first sync: %s", o.stderr)
	}
	manifest := filepath.Join(o.p.Templates, lifecycle.TemplateManifest)
	m := readFile(o.t, manifest)
	o.write(filepath.Join(o.p.Templates, "cisco.template"), ciscoV1)
	o.write(manifest, strings.Replace(m, fixtureSum(o.t, m, "cisco.template"), hashText(ciscoV1), 1))
}

// preManifestInstall is pre_manifest_install: cisco.template with text and
// juniper.template the shipped one, no manifest.
func (o *ohost) preManifestInstall(cisco string) {
	o.t.Helper()
	o.write(filepath.Join(o.p.Templates, "cisco.template"), cisco)
	o.write(filepath.Join(o.p.Templates, "juniper.template"), shippedTemplate(o.t, "juniper"))
}

// history makes the tree a clone whose config/templates/<file> had the
// contents of hist[file] (and only those): 'git hash-object' answers a
// blob id made from the file's sha256, 'git log -- <path>' the new-side
// blob of each of that path's changes.
func (o *ohost) history(hist map[string][]string) {
	blob := func(text string) string { return "blob" + hashText(text)[:36] }
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" && slices.Contains(c.Args, "hash-object") },
		func(c execx.Cmd) (execx.Result, error) {
			data, err := os.ReadFile(c.Args[len(c.Args)-1])
			if err != nil {
				return execx.Result{Code: 128}, nil
			}
			return execx.Result{Stdout: []byte(blob(string(data)) + "\n")}, nil
		})
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" && slices.Contains(c.Args, "log") },
		func(c execx.Cmd) (execx.Result, error) {
			path := c.Args[len(c.Args)-1]
			var b strings.Builder
			for _, text := range hist[strings.TrimPrefix(path, "config/templates/")] {
				b.WriteString(":100644 100644 0000000000000000000000000000000000000000 " + blob(text) + " M\t" + path + "\n")
			}
			return execx.Result{Stdout: []byte(b.String())}, nil
		})
}

// manifestChecks is 'sha256sum -c --quiet .shipped.sha256' in the
// templates directory: every line '<sha256>  <name>' and each file's
// sha256 the one recorded. It returns the number of lines.
func (o *ohost) manifestChecks() int {
	o.t.Helper()
	text := readFile(o.t, filepath.Join(o.p.Templates, lifecycle.TemplateManifest))
	if !strings.HasSuffix(text, "\n") {
		o.t.Errorf("manifest does not end in a newline: %q", text)
	}
	line := regexp.MustCompile(`^([0-9a-f]{64})  (\S+\.template)$`)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for _, l := range lines {
		m := line.FindStringSubmatch(l)
		if m == nil {
			o.t.Errorf("manifest line %q is not sha256sum's format", l)
			continue
		}
		if got := sha(o.t, filepath.Join(o.p.Templates, m[2])); got != m[1] {
			o.t.Errorf("%s: FAILED (sha256 %s, recorded %s)", m[2], got, m[1])
		}
	}
	return len(lines)
}

func (o *ohost) dotNews() []string {
	m, _ := filepath.Glob(filepath.Join(o.p.Templates, "*.new"))
	return m
}

// install over a templates directory that is already there (no manifest)
// keeps a customised template: its content, the shipped one beside it as
// .new, no record for it; the unmodified one is recorded.
func TestTemplatesInstallOverAnExistingDirectoryKeepsACustomisedTemplate(t *testing.T) {
	o := newOhost(t)
	o.preManifestInstall("my own cisco\n")
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	res, code := templatesSync(o)
	if code != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) {
		t.Fatalf("exit %d res %+v\n%s", code, res, o.text())
	}
	if readFile(t, cisco) != "my own cisco\n" {
		t.Error("the customised template was not kept")
	}
	if readFile(t, cisco+".new") != shippedTemplate(t, "cisco") {
		t.Error(".new is not the shipped template")
	}
	if r := o.recorded("cisco.template"); r != "" {
		t.Errorf("the customised template is recorded: %s", r)
	}
	if r := o.recorded("juniper.template"); r == "" || r != sha(t, filepath.Join(o.p.Templates, "juniper.template")) {
		t.Errorf("juniper.template recorded as %q", r)
	}
}

// upgrade: a customised template is kept; this release's version replaces
// a stale .new beside it, with the warning; the record still says what
// tacctl last wrote there.
func TestTemplatesACustomisedTemplateIsKeptAndAStaleNewIsReplaced(t *testing.T) {
	o := newOhost(t)
	o.installedByRelease1()
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	v1sum := o.recorded("cisco.template")
	if v1sum != hashText(ciscoV1) {
		t.Fatalf("setup: record %s", v1sum)
	}
	o.write(cisco, "my own cisco\n")
	o.write(cisco+".new", "stale\n")
	res, code := templatesSync(o)
	if code != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) || res.Updated != 0 {
		t.Fatalf("exit %d res %+v\n%s", code, res, o.text())
	}
	if readFile(t, cisco) != "my own cisco\n" {
		t.Error("the customised template was not kept")
	}
	if readFile(t, cisco+".new") != shippedTemplate(t, "cisco") {
		t.Errorf(".new %q is not this release's template", readFile(t, cisco+".new"))
	}
	inOrder(t, o.text(), "[WARN]   Customised template kept: "+cisco+"\n",
		"[WARN]     This release's version is beside it: "+cisco+".new\n",
		"[WARN]     Compare: diff "+cisco+" "+cisco+".new  (to take it: mv "+cisco+".new "+cisco+")\n")
	if r := o.recorded("cisco.template"); r != v1sum {
		t.Errorf("record %s, want release 1's %s", r, v1sum)
	}
}

// upgrade: re-running changes nothing (no file rewritten, the .new
// included); the only output beyond 'Unchanged' is the still-customised
// notice, once.
func TestTemplatesReRunningChangesNothing(t *testing.T) {
	o := newOhost(t)
	o.installedByRelease1()
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	o.write(cisco, "my own cisco\n")
	if res, _ := templatesSync(o); !slices.Equal(res.Customised, []string{"cisco.template"}) {
		t.Fatalf("setup: %+v", res)
	}
	// Every file two minutes old; what is there, with inode, mtime and size.
	old := time.Now().Add(-2 * time.Minute)
	type fstate struct {
		fi   os.FileInfo
		size int64
		mod  time.Time
	}
	snap := func() map[string]fstate {
		m := map[string]fstate{}
		ents, err := os.ReadDir(o.p.Templates)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			fi, err := os.Stat(filepath.Join(o.p.Templates, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			m[e.Name()] = fstate{fi: fi, size: fi.Size(), mod: fi.ModTime()}
		}
		return m
	}
	ents, _ := os.ReadDir(o.p.Templates)
	for _, e := range ents {
		if err := os.Chtimes(filepath.Join(o.p.Templates, e.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}
	before := snap()
	if _, ok := before["cisco.template.new"]; !ok {
		t.Fatal("setup: no .new")
	}
	res, code := templatesSync(o)
	if code != 0 || res.Updated != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) {
		t.Errorf("exit %d res %+v", code, res)
	}
	after := snap()
	if len(after) != len(before) {
		t.Errorf("files %d, were %d", len(after), len(before))
	}
	for name, b := range before {
		a, ok := after[name]
		if !ok || !os.SameFile(a.fi, b.fi) || a.size != b.size || !a.mod.Equal(b.mod) {
			t.Errorf("%s was rewritten", name)
		}
	}
	allowed := regexp.MustCompile(`^(\[INFO\]   Unchanged: template: |\[WARN\]   Customised template kept: |\[WARN\]     (This release|Compare))`)
	for _, l := range strings.Split(strings.TrimSuffix(o.text(), "\n"), "\n") {
		if !allowed.MatchString(l) {
			t.Errorf("unexpected line %q", l)
		}
	}
	if o.stderr.Len() != 0 {
		t.Errorf("stderr %q", o.stderr)
	}
	if n := strings.Count(o.text(), "Customised template kept"); n != 1 {
		t.Errorf("customised notice %d times", n)
	}
}

// upgrade: a customised template that is brought back to the shipped one
// ('mv .new' as the warning says) is recorded again, no .new is left, and
// nothing is warned.
func TestTemplatesACustomisedTemplateBroughtBackIsRecordedAgain(t *testing.T) {
	o := newOhost(t)
	o.installedByRelease1()
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	o.write(cisco, "my own cisco\n")
	templatesSync(o)
	if err := os.Rename(cisco+".new", cisco); err != nil {
		t.Fatal(err)
	}
	if o.recorded("cisco.template") != hashText(ciscoV1) {
		t.Fatal("setup: the record moved while the template was customised")
	}
	res, code := templatesSync(o)
	if code != 0 || len(res.Customised) != 0 || res.Updated != 0 {
		t.Errorf("exit %d res %+v", code, res)
	}
	hasNot(t, o.text(), "WARN")
	has(t, o.text(), "[INFO]   Unchanged: template: cisco.template\n")
	if r := o.recorded("cisco.template"); r != sha(t, cisco) || r != hashText(shippedTemplate(t, "cisco")) {
		t.Errorf("record %s, file %s", r, sha(t, cisco))
	}
	if exists(cisco + ".new") {
		t.Error(".new left")
	}
	// From then on it follows the release: the record is the only thing
	// the next release's sync goes by (a file whose sha256 is the record is
	// tacctl's), and the manifest is the release's own again.
	if readFile(t, filepath.Join(o.p.Templates, lifecycle.TemplateManifest)) != fixture(t, "golden/templates.manifest") {
		t.Errorf("manifest %s", readFile(t, filepath.Join(o.p.Templates, lifecycle.TemplateManifest)))
	}
}

// manifest-less: a template that is an older shipped version (in the
// tree's history) is refreshed, with no warning and no .new, and the
// manifest is written: every template, sha256sum's format.
func TestTemplatesManifestLessAnOlderShippedVersionIsRefreshed(t *testing.T) {
	o := newOhost(t)
	o.preManifestInstall(ciscoV1)
	o.history(map[string][]string{"cisco.template": {ciscoV1, shippedTemplate(t, "cisco")},
		"juniper.template": {shippedTemplate(t, "juniper")}})
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	manifest := filepath.Join(o.p.Templates, lifecycle.TemplateManifest)
	if exists(manifest) {
		t.Fatal("setup: a manifest")
	}
	res, code := templatesSync(o)
	if code != 0 || len(res.Customised) != 0 {
		t.Fatalf("exit %d res %+v\n%s", code, res, o.text())
	}
	if readFile(t, cisco) != shippedTemplate(t, "cisco") {
		t.Error("not refreshed")
	}
	has(t, o.text(), "[INFO]   Updated: template: cisco.template\n")
	has(t, o.text(), "[INFO]   Unchanged: template: juniper.template\n")
	hasNot(t, o.text(), "WARN")
	if n := o.dotNews(); len(n) != 0 {
		t.Errorf(".new files %v", n)
	}
	if n := o.manifestChecks(); n != len(assets.TemplateNames()) {
		t.Errorf("manifest has %d lines, want %d", n, len(assets.TemplateNames()))
	}
}

// manifest-less: a customised template (not in the history) is kept, with
// .new and the warning; nothing is recorded for it, the unmodified one is.
func TestTemplatesManifestLessACustomisedTemplateIsKept(t *testing.T) {
	o := newOhost(t)
	o.preManifestInstall("my own cisco\n")
	o.history(map[string][]string{"cisco.template": {ciscoV1, shippedTemplate(t, "cisco")},
		"juniper.template": {shippedTemplate(t, "juniper")}})
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	res, code := templatesSync(o)
	if code != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) {
		t.Fatalf("exit %d res %+v\n%s", code, res, o.text())
	}
	if readFile(t, cisco) != "my own cisco\n" || readFile(t, cisco+".new") != shippedTemplate(t, "cisco") {
		t.Error("content or .new")
	}
	has(t, o.text(), "[WARN]   Customised template kept: "+cisco+"\n")
	if r := o.recorded("cisco.template"); r != "" {
		t.Errorf("the customised template is recorded: %s", r)
	}
	if r := o.recorded("juniper.template"); r == "" {
		t.Error("juniper.template not recorded")
	}
}

// A template that holds some other template's shipped content is not
// taken for a shipped version of its own: the history is that of its own
// path. (With cisco's own older text, the same history does update it.)
func TestTemplatesAnotherTemplatesShippedContentIsNotItsOwn(t *testing.T) {
	juniper := shippedTemplate(t, "juniper")
	hist := map[string][]string{"cisco.template": {ciscoV1, shippedTemplate(t, "cisco")}, "juniper.template": {juniper}}
	o := newOhost(t)
	o.history(hist)
	o.preManifestInstall(juniper)
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	res, code := templatesSync(o)
	if code != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) {
		t.Errorf("exit %d res %+v\n%s", code, res, o.text())
	}
	if readFile(t, cisco) != juniper {
		t.Error("cisco.template was replaced")
	}
	if !o.run.Called("git", "-C", o.p.Tree, "log", "-m", "--format=", "--raw", "--no-abbrev", "--no-renames", "--",
		"config/templates/cisco.template") {
		t.Errorf("cisco.template not looked up by its own path: %v", o.run.Argvs())
	}
	// The control: the same history takes cisco's own release 1 for tacctl's.
	o = newOhost(t)
	o.history(hist)
	o.preManifestInstall(ciscoV1)
	if res, _ := templatesSync(o); len(res.Customised) != 0 {
		t.Errorf("control: res %+v", res)
	}
}
