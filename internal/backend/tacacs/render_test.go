package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
)

// The render steps as the module runs them (tests/integration/listeners.bats
// "The drop-in in the render machinery", "drop-in: rendering is
// deterministic"); the render itself is internal/render/tacacs's.

// "render: the drop-in is an artifact of the backend, staged and recorded
// with tacquito.yaml".
func TestConfigRenderRendersConfigAndDropIn(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	dropin := e.dropIn("default")
	if err := e.set.ConfigRender(context.Background(), true); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	mustContain(t, e.stdout.String(), "Rendered "+e.p.Config+", "+dropin+".")
	if !e.recorded(e.p.Config) || !e.recorded(dropin) {
		t.Fatal("not recorded")
	}
	text := readFile(t, dropin)
	mustLine(t, text, "[Service]")
	mustLine(t, text, `Environment="TACQUITO_ADDRESS=:49"`)
	mustLine(t, text, `Environment="TACQUITO_ACCT_LOG=`+e.p.Log+`/accounting.log"`)
	if st, _ := os.Stat(dropin); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	if st, _ := os.Stat(e.p.Config); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	// No unit file yet: nothing to reload; the restart follows the change.
	if e.called("^systemctl daemon-reload") || !e.called("^systemctl restart tacquito$") {
		t.Fatal(e.run.Argvs())
	}
	if w, err := e.b.RenderCheck(context.Background()); err != nil || w != rendered.Current {
		t.Fatalf("check %q %v", w, err)
	}

	// "drop-in: rendering is deterministic, and a second render changes
	// nothing".
	e.reset()
	before := state(dropin, e.p.Rendered)
	if err := e.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "already up to date")
	if state(dropin, e.p.Rendered) != before || len(e.run.Calls()) != 0 {
		t.Fatalf("changed: %v", e.run.Argvs())
	}
}

// "render: a tacctl.yaml changed by hand is applied by 'config render':
// reload, restart, instance started".
func TestConfigRenderAppliesAHandChangedTacctlYAML(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.render(true)
	writeFile(t, e.b.serviceFile(), "")
	e.writeOverrides("listeners:\n  tacacs:\n    default: {network: tcp, address: \"10.1.0.1:49\"}\n    mgmt: {network: tcp, address: \"127.0.0.1:4949\"}\n")
	if w, _ := e.b.RenderCheck(context.Background()); w != rendered.Missing {
		t.Fatalf("check %q", w)
	}
	if err := e.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if envOf(t, e.dropIn("default"), "TACQUITO_ADDRESS") != "10.1.0.1:49" || !exists(e.dropIn("mgmt")) {
		t.Fatal("not rendered")
	}
	for _, re := range []string{`^systemctl daemon-reload$`, `^systemctl restart tacquito$`, `^systemctl enable --quiet --now tacquito@mgmt\.service$`} {
		if !e.called(re) {
			t.Fatalf("no %s in %v", re, e.run.Argvs())
		}
	}
	// daemon-reload's output goes to stderr with the rest of the render.
	for _, c := range e.run.Calls() {
		if c.Name == "systemctl" && c.Args[0] == "daemon-reload" && (c.Stdout != e.env.Out.Stderr || c.Stderr != e.env.Out.Stderr) {
			t.Fatal("daemon-reload does not write to stderr")
		}
	}
	if !e.recorded(e.dropIn("mgmt")) {
		t.Fatal("instance drop-in not recorded")
	}
	if got := e.b.Describe().Units; len(got) != 2 || got[1] != "tacquito@mgmt.service" {
		t.Fatalf("units %v", got)
	}
}

// "render: a listener removed from tacctl.yaml loses its drop-in, its
// record and its instance".
func TestConfigRenderRemovesAListenerThatIsGone(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.writeOverrides("listeners:\n  tacacs:\n    mgmt: {network: tcp, address: \"127.0.0.1:4949\"}\n")
	e.render(true)
	writeFile(t, e.b.serviceFile(), "")
	wants := filepath.Join(e.p.TacacsUnitDir, "tacquito.service.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/tacquito@.service", filepath.Join(wants, "tacquito@mgmt.service")); err != nil {
		t.Fatal(err)
	}
	mgmt := e.dropIn("mgmt")
	if err := os.Remove(e.p.Overrides); err != nil {
		t.Fatal(err)
	}
	e.env.Conf.Reload()
	if err := e.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if exists(mgmt) || exists(filepath.Dir(mgmt)) {
		t.Fatal("the instance's drop-in is still there")
	}
	if w, _ := rendered.Check(e.p.Rendered, mgmt); w == rendered.OK {
		t.Fatal("still recorded")
	}
	if !e.called(`^systemctl daemon-reload$`) || !e.called(`^systemctl disable --quiet --now tacquito@mgmt\.service$`) {
		t.Fatal(e.run.Argvs())
	}
}

// "render: a hand-edited drop-in is reported as drift, never refuses a
// command, and is replaced with a copy kept".
func TestHandEditedDropInIsDriftAndIsReplaced(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.render(true)
	dropin := e.dropIn("default")
	f, _ := os.OpenFile(dropin, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("Environment=\"TACQUITO_LEVEL=30\"\n")
	_ = f.Close()
	if w, _ := e.b.RenderCheck(context.Background()); w != rendered.Drift {
		t.Fatalf("check %q", w)
	}
	if g := e.b.RenderGate(context.Background()); g != backend.GateOK {
		t.Fatalf("gate %v", g)
	}
	if _, err := e.set.StoreApply(context.Background(), backend.ApplyOptions{}, func() error { return nil }); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	mustContain(t, e.stderr.String(), "Previous "+dropin+" saved to")
	if m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "legacy", "tacctl.conf.drift.*")); len(m) != 1 {
		t.Fatalf("copies %v", m)
	}
	if w, _ := e.b.RenderCheck(context.Background()); w != rendered.Current {
		t.Fatalf("check %q", w)
	}
}

// The gate: a hand-edited tacquito.yaml refuses a mutation (3); a file
// tacctl never rendered that says what the store says is adopted.
func TestRenderGate(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	ctx := context.Background()
	if g := e.b.RenderGate(ctx); g != backend.GateOK {
		t.Fatalf("gate %v", g)
	}
	e.render(true)
	f, _ := os.OpenFile(e.p.Config, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# edited\n")
	_ = f.Close()
	if g := e.b.RenderGate(ctx); g != backend.GateRefused {
		t.Fatalf("gate %v", g)
	}
	mustContain(t, e.stderr.String(), "was edited since tacctl rendered it; this command would discard those edits.")
	if e.stdout.Len() != 0 {
		t.Fatalf("stdout %q", e.stdout)
	}
	err := e.b.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 3)

	// Unrecorded, and the same as the store: adopt.
	e.reset()
	if err := os.Remove(e.p.Rendered); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.p.Config); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := e.b.RenderStage(ctx, stage, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.RenderCommit(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.p.Rendered); err != nil {
		t.Fatal(err)
	}
	if g := e.b.RenderGate(ctx); g != backend.GateAdopt {
		t.Fatalf("gate %v: %s", g, e.stderr)
	}
}

// RenderStage needs the store (render_tacacs_config's refusal); an install
// that is not converted stages no drop-ins.
func TestRenderStage(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	err := e.b.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 1)
	mustContain(t, e.stderr.String(), store.NotInitialisedMsg)
	e.withStore("store.multiscope.yaml")
	e.legacyDropIn("TACQUITO_LEVEL=30")
	stage := t.TempDir()
	if err := e.b.RenderStage(ctx, stage, false); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(stage, "units")) || !exists(filepath.Join(stage, "tacquito.yaml")) {
		t.Fatal("staged drop-ins for an install that is not converted")
	}
	changed, err := e.b.RenderCommit(ctx, stage)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if exists(e.dropIn("default")) {
		t.Fatal("a rendered drop-in beside the hand-managed one")
	}
	if w, _ := e.b.RenderCheck(ctx); w != rendered.Current {
		t.Fatalf("check %q", w)
	}
}

// "render: a listener model that cannot be served fails the render and
// changes nothing".
func TestRenderOfAListenerModelThatCannotBeServed(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.render(true)
	before := state(e.dropIn("default"), e.p.Config, e.p.Rendered)
	e.writeOverrides("listeners:\n  tacacs:\n    tls: {network: tcp, address: \":300\", tls: {enabled: true}}\n")
	err := e.set.ConfigRender(context.Background(), false)
	wantCode(t, err, 1)
	mustContain(t, e.stderr.String(), "tls.enabled: true is reserved for a future release")
	if state(e.dropIn("default"), e.p.Config, e.p.Rendered) != before {
		t.Fatal("changed")
	}
	if _, err := e.b.RenderCheck(context.Background()); err == nil {
		t.Fatal("check passed")
	}
}

// backend_tacacs_render_notes.
func TestRenderNotes(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.b.RenderNotes(context.Background())
	if e.stdout.Len() != 0 {
		t.Fatalf("%q", e.stdout)
	}
	e.withStore("store.minimal.yaml")
	e.b.RenderNotes(context.Background())
	mustContain(t, e.stdout.String(), "The store has no users or no scopes; tacquito refuses to serve such a config.")
}
