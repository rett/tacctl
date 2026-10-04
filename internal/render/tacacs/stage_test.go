package tacacs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/rendered"
)

// Ported from tests/integration/config_render.bats: the stage and commit
// steps behind 'tacctl config render [--force]', with their cmp checks
// against the golden tacquito.yaml, and the drop-ins' commit from
// tests/integration/listeners.bats. (Exit codes, the CLI's messages around
// these steps and the restart are internal/backend's and internal/cli's.)

type env struct {
	t      *testing.T
	w      string
	r      *Renderer
	stderr *bytes.Buffer
	chowns []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	w := t.TempDir()
	for _, d := range []string{"etc", "state/backups", "systemd/tacquito.service.d"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{t: t, w: w, stderr: &bytes.Buffer{}}
	e.r = testRenderer(t, w, filepath.Join(w, "log"))
	e.r.Stderr = e.stderr
	e.r.Chown = func(p string) { e.chowns = append(e.chowns, p) }
	e.r.Now = func() time.Time { return time.Date(2026, 10, 3, 12, 34, 56, 789_999_999, time.Local) }
	return e
}

func (e *env) store(name string) {
	writeFile(e.t, e.r.Paths.StoreFile, string(readFile(e.t, filepath.Join(fixDir, name))))
}

func (e *env) tacctl(text string) {
	writeFile(e.t, e.r.Conf.Path, text)
	e.r.Conf.Reload()
}

// render is Stage then CommitConfig and CommitUnits, as store_apply runs
// them; it returns what changed.
func (e *env) render(force bool) (bool, []string, error) {
	e.t.Helper()
	dir := e.t.TempDir()
	if err := e.r.Stage(dir, force, true); err != nil {
		return false, nil, err
	}
	changed, err := e.r.CommitConfig(dir)
	if err != nil {
		return changed, nil, err
	}
	units, err := e.r.CommitUnits(dir)
	return changed, units, err
}

func (e *env) golden() []byte {
	return readFile(e.t, filepath.Join(goldenDir, "tacquito.multiscope.rendered.yaml"))
}

func (e *env) cmpGolden() {
	e.t.Helper()
	diffText(e.t, readFile(e.t, e.r.Paths.Config), e.golden(), "live tacquito.yaml")
}

func (e *env) savedCopies() []string {
	m, _ := filepath.Glob(filepath.Join(e.r.Paths.BackupDir, "legacy", "tacquito.yaml.drift.*"))
	sort.Strings(m)
	return m
}

// rendered_install: a store plus the tacquito.yaml tacctl rendered from it.
func (e *env) renderedInstall() {
	e.t.Helper()
	e.store("store.multiscope.yaml")
	if _, _, err := e.render(false); err != nil {
		e.t.Fatalf("%v: %s", err, e.stderr)
	}
	e.stderr.Reset()
	e.chowns = nil
}

func (e *env) dropIn() string { return DropIn(e.r.Paths, "default") }

func TestStageWithoutAStoreFailsAndTouchesNothing(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.r.Paths.Config, "legacy\n")
	if _, _, err := e.render(true); !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(e.stderr.String(), "tacctl render: "+e.r.Paths.StoreFile+": No such file or directory") {
		t.Fatalf("stderr %q", e.stderr)
	}
	if string(readFile(t, e.r.Paths.Config)) != "legacy\n" {
		t.Fatal("touched")
	}
	if _, err := os.Stat(e.r.Paths.Rendered); err == nil {
		t.Fatal("rendered.json written")
	}
}

func TestRenderWritesTheConfigWhenThereIsNoneAndRecordsIt(t *testing.T) {
	e := newEnv(t)
	e.store("store.multiscope.yaml")
	changed, units, err := e.render(false)
	if err != nil || !changed {
		t.Fatalf("%v %v: %s", changed, err, e.stderr)
	}
	if strings.Join(units, " ") != "tacquito.service" {
		t.Fatalf("units %v", units)
	}
	e.cmpGolden()
	if st, _ := os.Stat(e.r.Paths.Config); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(e.r.Paths.Rendered); st.Mode().Perm() != 0o600 {
		t.Fatalf("rendered.json mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(e.dropIn()); st.Mode().Perm() != 0o644 {
		t.Fatalf("drop-in mode %v", st.Mode().Perm())
	}
	// The staged copy was given to tacquito before it was renamed into place.
	if len(e.chowns) == 0 || e.chowns[len(e.chowns)-1] != e.r.Paths.Config+".tacctl-new" {
		t.Fatalf("chown calls %v", e.chowns)
	}
	entries, _ := os.ReadDir(filepath.Dir(e.r.Paths.Config))
	if len(entries) != 1 {
		t.Fatalf("etc holds %v", entries)
	}
	for _, p := range []string{e.r.Paths.Config, e.dropIn()} {
		if w, _ := rendered.Check(e.r.Paths.Rendered, p); w != rendered.OK {
			t.Fatalf("%s: %s", p, w)
		}
	}
	if e.stderr.Len() != 0 {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestASecondRenderChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	before := readFile(t, e.r.Paths.Rendered)
	changed, units, err := e.render(false)
	if err != nil || changed || len(units) != 0 {
		t.Fatalf("%v %v %v", changed, units, err)
	}
	if !bytes.Equal(before, readFile(t, e.r.Paths.Rendered)) || len(e.savedCopies()) != 0 {
		t.Fatal("something changed")
	}
	if w, err := e.r.Check(true); err != nil || w != rendered.Current {
		t.Fatalf("%s %v", w, err)
	}
}

func TestAStoreChangeIsRenderedWithoutForce(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	s := strings.Replace(string(readFile(t, e.r.Paths.StoreFile)), "juniper_class: OP-CLASS", "juniper_class: OPS", 1)
	writeFile(t, e.r.Paths.StoreFile, s)
	if w, err := e.r.Check(false); err != nil || w != rendered.OK {
		t.Fatalf("%s %v", w, err)
	}
	changed, _, err := e.render(false)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if !strings.Contains(string(readFile(t, e.r.Paths.Config)), `values: ["OPS"]`) || len(e.savedCopies()) != 0 {
		t.Fatal("not rendered, or a copy was saved")
	}
	if got := rendered.CheckDrift(e.r.Paths.Rendered); got != nil {
		t.Fatalf("drift %v", got)
	}
}

func TestAHandEditedFileIsRefusedForceOverwritesAndKeepsACopy(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	edited := string(e.golden()) + "# hand edit\n"
	writeFile(t, e.r.Paths.Config, edited)

	_, _, err := e.render(false)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("got %v", err)
	}
	cfg := e.r.Paths.Config
	want := "\033[0;31m[ERROR]\033[0m " + cfg + " was edited since tacctl rendered it; rendering would discard those edits.\n" +
		"\033[0;31m[ERROR]\033[0m To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'.\n" +
		"\033[0;31m[ERROR]\033[0m To discard it: 'tacctl config render --force' alone. Either way the current file is saved under " +
		e.r.Paths.BackupDir + "/legacy/ first.\n"
	if e.stderr.String() != want {
		t.Fatalf("stderr\n%q\nwant\n%q", e.stderr, want)
	}
	if string(readFile(t, cfg)) != edited || len(e.savedCopies()) != 0 {
		t.Fatal("touched")
	}
	if got := rendered.CheckDrift(e.r.Paths.Rendered); len(got) != 1 || got[0].Line() != "drift\t"+cfg {
		t.Fatalf("drift %v", got)
	}

	e.stderr.Reset()
	changed, _, err := e.render(true)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	copies := e.savedCopies()
	stamp := "20261003_123456_789"
	if len(copies) != 1 || copies[0] != e.r.Paths.BackupDir+"/legacy/tacquito.yaml.drift."+stamp {
		t.Fatalf("copies %v", copies)
	}
	if e.stderr.String() != "\033[1;33m[WARN]\033[0m Previous "+cfg+" saved to "+copies[0]+"\n" {
		t.Fatalf("stderr %q", e.stderr)
	}
	e.cmpGolden()
	if string(readFile(t, copies[0])) != edited {
		t.Fatal("copy")
	}
	if st, _ := os.Stat(copies[0]); st.Mode().Perm() != 0o600 {
		t.Fatalf("copy mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Dir(copies[0])); st.Mode().Perm() != 0o700 {
		t.Fatalf("legacy dir mode %v", st.Mode().Perm())
	}
	if changed, _, err := e.render(false); err != nil || changed {
		t.Fatalf("%v %v", changed, err)
	}
}

func TestAFileTacctlNeverRenderedIsRefusedForceUsesThePreStoreCopy(t *testing.T) {
	e := newEnv(t)
	// The state right after 'store import' on an existing install.
	legacy := string(readFile(t, filepath.Join(fixDir, "tacquito.multiscope.yaml")))
	writeFile(t, e.r.Paths.Config, legacy)
	pre := e.r.Paths.BackupDir + "/legacy/tacquito.yaml.pre-store.20261001_000000_000"
	writeFile(t, pre, legacy)
	writeFile(t, e.r.Paths.BackupDir+"/legacy/tacquito.yaml.pre-store.20251001_000000_000", "older\n")
	e.store("store.multiscope.yaml")

	if _, _, err := e.render(false); !errors.Is(err, ErrRefused) || !strings.Contains(e.stderr.String(), "was not rendered by tacctl; rendering would replace it.") {
		t.Fatalf("%v: %q", err, e.stderr)
	}
	if string(readFile(t, e.r.Paths.Config)) != legacy {
		t.Fatal("touched")
	}
	if _, err := os.Stat(e.r.Paths.Rendered); err == nil {
		t.Fatal("rendered.json written")
	}
	e.stderr.Reset()
	if _, _, err := e.render(true); err != nil {
		t.Fatal(err)
	}
	e.cmpGolden()
	if !strings.Contains(e.stderr.String(), "\033[0;32m[INFO]\033[0m Previous "+e.r.Paths.Config+" is already kept as "+pre+"\n") {
		t.Fatalf("stderr %q", e.stderr)
	}
	if len(e.savedCopies()) != 0 {
		t.Fatal("a second copy was saved")
	}
	if got, ok := PreStoreLatest(e.r.Paths.BackupDir); !ok || got != pre {
		t.Fatalf("%s %v", got, ok)
	}
}

func TestAnUnrecordedFileThatEqualsTheRenderIsAdopted(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	if err := os.Remove(e.r.Paths.Rendered); err != nil {
		t.Fatal(err)
	}
	changed, units, err := e.render(false)
	if err != nil || changed || len(units) != 0 {
		t.Fatalf("%v %v %v", changed, units, err)
	}
	for _, p := range []string{e.r.Paths.Config, e.dropIn()} {
		if w, _ := rendered.Check(e.r.Paths.Rendered, p); w != rendered.OK {
			t.Fatalf("%s: %s", p, w)
		}
	}
}

func TestADeletedConfigIsRecreatedWithoutForce(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	if err := os.Remove(e.r.Paths.Config); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := e.render(false); err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	e.cmpGolden()
	if len(e.savedCopies()) != 0 {
		t.Fatal("copies")
	}
}

func TestUnreadableRecordsRefuseAnOverwrite(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	writeFile(t, e.r.Paths.Rendered, "{not json\n")
	s := strings.Replace(string(readFile(t, e.r.Paths.StoreFile)), "juniper_class: OP-CLASS", "juniper_class: OPS", 1)
	writeFile(t, e.r.Paths.StoreFile, s)
	if _, _, err := e.render(false); !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
	if e.stderr.String() != "\033[0;31m[ERROR]\033[0m Cannot read "+e.r.Paths.Rendered+"; refusing to overwrite "+e.r.Paths.Config+".\n" {
		t.Fatalf("stderr %q", e.stderr)
	}
	e.cmpGolden()
}

func TestAStoreThatFailsValidationRendersNothing(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	s := strings.Replace(string(readFile(t, e.r.Paths.StoreFile)), "group: operator", "group: nosuch", 1)
	writeFile(t, e.r.Paths.StoreFile, s)
	if _, _, err := e.render(false); !errors.Is(err, ErrFailed) || !strings.Contains(e.stderr.String(), "cannot render an invalid model") {
		t.Fatalf("%v %q", err, e.stderr)
	}
	e.cmpGolden()
	if _, err := e.r.Check(true); !errors.Is(err, ErrFailed) {
		t.Fatalf("check: %v", err)
	}
}

// listeners.bats: "render: a listener removed from tacctl.yaml loses its
// drop-in, its record and its instance" and "a listener model that cannot
// be served fails the render and changes nothing".
func TestInstanceDropInsAreWrittenAndRemoved(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	e.tacctl("listeners:\n  tacacs:\n    default: {network: tcp, address: '10.1.0.1:49'}\n    mgmt: {network: tcp, address: '127.0.0.1:4949'}\n")
	if w, err := e.r.Check(true); err != nil || w != rendered.Missing {
		t.Fatalf("check %s %v", w, err)
	}
	changed, units, err := e.render(false)
	if err != nil || changed || strings.Join(units, " ") != "tacquito.service tacquito@mgmt.service" {
		t.Fatalf("%v %v %v", changed, units, err)
	}
	mgmt := DropIn(e.r.Paths, "mgmt")
	if !strings.Contains(string(readFile(t, e.dropIn())), `Environment="TACQUITO_ADDRESS=10.1.0.1:49"`) {
		t.Fatal("default drop-in")
	}
	if w, _ := rendered.Check(e.r.Paths.Rendered, mgmt); w != rendered.OK {
		t.Fatal(w)
	}
	if st, _ := os.Stat(filepath.Dir(mgmt)); st.Mode().Perm() != 0o755 {
		t.Fatalf("dir mode %v", st.Mode().Perm())
	}

	before := []string{string(readFile(t, e.dropIn())), string(readFile(t, e.r.Paths.Config)), string(readFile(t, e.r.Paths.Rendered))}
	e.tacctl("listeners:\n  tacacs:\n    tls: {network: tcp, address: ':300', tls: {enabled: true}}\n")
	if _, _, err := e.render(false); !errors.Is(err, ErrFailed) || !strings.Contains(e.stderr.String(), "tls.enabled: true is reserved for a future release") {
		t.Fatalf("%v %q", err, e.stderr)
	}
	after := []string{string(readFile(t, e.dropIn())), string(readFile(t, e.r.Paths.Config)), string(readFile(t, e.r.Paths.Rendered))}
	if strings.Join(before, "") != strings.Join(after, "") {
		t.Fatal("changed")
	}

	if err := os.Remove(e.r.Conf.Path); err != nil {
		t.Fatal(err)
	}
	e.r.Conf.Reload()
	_, units, err = e.render(false)
	if err != nil || strings.Join(units, " ") != "tacquito.service tacquito@mgmt.service" {
		t.Fatalf("%v %v", units, err)
	}
	if _, err := os.Stat(filepath.Dir(mgmt)); err == nil {
		t.Fatal("the instance's drop-in directory is still there")
	}
	if strings.Contains(string(readFile(t, e.r.Paths.Rendered)), "tacquito@mgmt") {
		t.Fatal("still recorded")
	}
	// A directory holding a drop-in of the operator's own stays.
	other := filepath.Join(e.r.Paths.UnitDir, "tacquito@x.service.d")
	writeFile(t, filepath.Join(other, DropInName), "x\n")
	writeFile(t, filepath.Join(other, "mine.conf"), "x\n")
	if _, units, err = e.render(false); err != nil || strings.Join(units, " ") != "tacquito@x.service" {
		t.Fatalf("%v %v", units, err)
	}
	if _, err := os.Stat(filepath.Join(other, "mine.conf")); err != nil {
		t.Fatal("the operator's drop-in went")
	}
}

// listeners.bats: "render: a hand-edited drop-in is reported as drift,
// never refuses a command, and is replaced with a copy kept".
func TestAHandEditedDropInIsReplacedWithACopyKept(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	writeFile(t, e.dropIn(), string(readFile(t, e.dropIn()))+`Environment="TACQUITO_LEVEL=30"`+"\n")
	if got := rendered.CheckDrift(e.r.Paths.Rendered); len(got) != 1 || got[0].Line() != "drift\t"+e.dropIn() {
		t.Fatalf("drift %v", got)
	}
	if w, err := e.r.Check(true); err != nil || w != rendered.Drift {
		t.Fatalf("check %s %v", w, err)
	}
	changed, units, err := e.render(false)
	if err != nil || changed || strings.Join(units, " ") != "tacquito.service" {
		t.Fatalf("%v %v %v", changed, units, err)
	}
	copies, _ := filepath.Glob(filepath.Join(e.r.Paths.BackupDir, "legacy", "tacctl.conf.drift.*"))
	if len(copies) != 1 || !strings.Contains(e.stderr.String(), "Previous "+e.dropIn()+" saved to "+copies[0]) {
		t.Fatalf("%v %q", copies, e.stderr)
	}
	if strings.Count(string(readFile(t, e.dropIn())), "TACQUITO_LEVEL") != 1 || rendered.CheckDrift(e.r.Paths.Rendered) != nil {
		t.Fatal("not replaced")
	}
}

func TestCommitUnitsRefusesOverUnreadableRecords(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	e.tacctl("backends:\n  tacacs:\n    level: 30\n")
	dir := t.TempDir()
	if err := e.r.Stage(dir, false, true); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.r.Paths.Rendered, "{not json\n")
	writeFile(t, filepath.Join(dir, UnitsDir, IndexName), "default\tunreadable\t"+e.dropIn()+"\n")
	if _, err := e.r.CommitUnits(dir); !errors.Is(err, ErrFailed) ||
		e.stderr.String() != "\033[0;31m[ERROR]\033[0m Cannot read "+e.r.Paths.Rendered+"; refusing to overwrite "+e.dropIn()+".\n" {
		t.Fatalf("%v %q", err, e.stderr)
	}
	// Without units staged there is nothing to commit, not even removals.
	writeFile(t, filepath.Join(e.r.Paths.UnitDir, "tacquito@gone.service.d", DropInName), "x\n")
	if units, err := e.r.CommitUnits(t.TempDir()); err != nil || units != nil {
		t.Fatalf("%v %v", units, err)
	}
	if _, err := os.Stat(filepath.Join(e.r.Paths.UnitDir, "tacquito@gone.service.d", DropInName)); err != nil {
		t.Fatal("removed")
	}
}

func TestStageWithoutUnits(t *testing.T) {
	e := newEnv(t)
	e.store("store.multiscope.yaml")
	dir := t.TempDir()
	if err := e.r.Stage(dir, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, UnitsDir)); err == nil {
		t.Fatal("units staged")
	}
	if string(readFile(t, filepath.Join(dir, StatusName))) != "missing\n" {
		t.Fatal("status")
	}
	if units, err := e.r.CommitUnits(dir); err != nil || units != nil {
		t.Fatalf("%v %v", units, err)
	}
	if w, err := e.r.Check(false); err != nil || w != rendered.Missing {
		t.Fatalf("%s %v", w, err)
	}
}

// The render gate of store_apply.
func TestGate(t *testing.T) {
	e := newEnv(t)
	e.store("store.multiscope.yaml")
	if g := e.r.Gate(); g != GateOK || g.Code() != 0 {
		t.Fatalf("missing: %v", g)
	}
	e.renderedInstall()
	if g := e.r.Gate(); g != GateOK {
		t.Fatalf("ok: %v", g)
	}
	cfg := e.r.Paths.Config
	tail := "\033[0;31m[ERROR]\033[0m Nothing was changed. To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'.\n" +
		"\033[0;31m[ERROR]\033[0m To discard it: 'tacctl config render --force' alone. Then run this command again.\n"

	writeFile(t, cfg, string(e.golden())+"# edit\n")
	if g := e.r.Gate(); g != GateRefused || g.Code() != 3 {
		t.Fatalf("drift: %v", g)
	}
	if e.stderr.String() != "\033[0;31m[ERROR]\033[0m "+cfg+" was edited since tacctl rendered it; this command would discard those edits.\n"+tail {
		t.Fatalf("stderr %q", e.stderr)
	}

	// Never rendered, but saying what the store says: adopt.
	e.stderr.Reset()
	writeFile(t, cfg, string(e.golden()))
	if err := os.Remove(e.r.Paths.Rendered); err != nil {
		t.Fatal(err)
	}
	if g := e.r.Gate(); g != GateAdopt || g.Code() != 10 || e.stderr.Len() != 0 {
		t.Fatalf("adopt: %v %q", g, e.stderr)
	}
	// Never rendered and saying something else.
	writeFile(t, cfg, string(readFile(t, filepath.Join(fixDir, "golden", "tacquito.minimal.rendered.yaml"))))
	if g := e.r.Gate(); g != GateRefused {
		t.Fatalf("foreign: %v", g)
	}
	if e.stderr.String() != "\033[0;31m[ERROR]\033[0m "+cfg+" was not rendered by tacctl and does not say what the store says; this command would replace it.\n"+tail {
		t.Fatalf("stderr %q", e.stderr)
	}
	// Records that cannot be read.
	e.stderr.Reset()
	writeFile(t, e.r.Paths.Rendered, "[]")
	if g := e.r.Gate(); g != GateFailed || g.Code() != 1 {
		t.Fatalf("unreadable: %v", g)
	}
	if e.stderr.String() != "tacctl render: "+e.r.Paths.Rendered+": not a path-to-sha256 mapping\n"+
		"\033[0;31m[ERROR]\033[0m Cannot read "+e.r.Paths.Rendered+"; refusing to overwrite "+cfg+".\n" {
		t.Fatalf("stderr %q", e.stderr)
	}
	// Without a store nothing matches it.
	if err := os.Remove(e.r.Paths.Rendered); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg, string(e.golden()))
	if err := os.Remove(e.r.Paths.StoreFile); err != nil {
		t.Fatal(err)
	}
	if g := e.r.Gate(); g != GateRefused {
		t.Fatalf("no store: %v", g)
	}
}

// The check word with units is the artifact furthest from the render.
func TestCheckWithUnitsIsTheFurthestWord(t *testing.T) {
	e := newEnv(t)
	e.renderedInstall()
	if w, _ := e.r.Check(true); w != rendered.Current {
		t.Fatal(w)
	}
	if err := os.Remove(e.dropIn()); err != nil {
		t.Fatal(err)
	}
	if w, _ := e.r.Check(true); w != rendered.Missing {
		t.Fatal(w)
	}
	if w, _ := e.r.Check(false); w != rendered.Current {
		t.Fatal(w)
	}
	writeFile(t, e.r.Paths.Rendered, "{bad")
	if w, _ := e.r.Check(true); w != rendered.Unreadable {
		t.Fatal(w)
	}
	// Nothing is left in TMPDIR.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if _, err := e.r.Check(true); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Fatalf("TMPDIR holds %v", entries)
	}
}

func TestDriftStamp(t *testing.T) {
	if got := DriftStamp(time.Date(1999, 1, 2, 3, 4, 5, 6_999_999, time.UTC)); got != "19990102_030405_006" {
		t.Fatal(got)
	}
}

func TestPathsFromAndGateCodes(t *testing.T) {
	p := productionPaths()
	if p.Config != "/etc/tacquito/tacquito.yaml" || p.StoreFile != "/etc/tacctl/store.yaml" || p.Rendered != "/etc/tacctl/rendered.json" ||
		p.BackupDir != "/etc/tacctl/backups" || p.LogDir != "/var/log/tacquito" || p.OverrideDir != "/etc/systemd/system/tacquito.service.d" {
		t.Fatalf("%+v", p)
	}
	if GateResult(99).Code() != 1 {
		t.Fatal("unknown verdict")
	}
}

// ChownTacquito never fails: without the account, or without the right to
// chown (an unprivileged test run), the file stays as it is.
func TestChownTacquitoIsBestEffort(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	writeFile(t, p, "x")
	before, _ := os.Stat(p)
	ChownTacquito(p)
	ChownTacquito(filepath.Join(t.TempDir(), "missing"))
	after, err := os.Stat(p)
	if err != nil || after.Mode() != before.Mode() || string(readFile(t, p)) != "x" {
		t.Fatalf("%v %v", after, err)
	}
}
