package radius_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
)

// Ports of the render, gate, drift and mutation tests of
// tests/integration/radius.bats: what the module does between a store and
// its three files, through the same machinery (backend.Set) as a command.

// A first render writes the three artifacts, recorded, 0640 with the
// dictionary's directory 0750; the owner asked for is root and the daemon's
// group; the daemon's own check ran on a copy beside the live files, readable
// by that group, with the copy of the dictionary, and the copy is gone.
// (enable's render step, without the package manager and the generic enable.)
func TestFirstRenderInstallsTheThreeArtifacts(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("tacacs, radius")
	if err := r.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatalf("config render: %v\n%s", err, r.stderr)
	}
	m := r.m
	for _, f := range []string{m.L.Conf, m.L.Users, m.L.Dict} {
		if got := r.mode(f); got != 0o640 {
			t.Errorf("%s is %o", f, got)
		}
		if w, _ := rendered.Check(r.p.Rendered, f); w != rendered.OK {
			t.Errorf("%s is %s in rendered.json", f, w)
		}
	}
	if got := r.mode(m.L.DictDir); got != 0o750 {
		t.Errorf("dictionary directory is %o", got)
	}
	// Owner root:<group>, asked for the staged copies and the new directory.
	for _, want := range []string{m.L.Conf + ".tacctl-new", m.L.Users + ".tacctl-new", m.L.Dict + ".tacctl-new", m.L.DictDir} {
		if !slices.Contains(r.chowns, want) {
			t.Errorf("no chown of %s in %v", want, r.chowns)
		}
	}
	if !r.hasLine(m.L.Conf, "\tuser = freerad") {
		t.Errorf("conf does not name the debian account")
	}
	if !r.hasLine(m.L.Dict, "$INCLUDE "+m.L.SystemDict) {
		t.Errorf("dictionary does not include the package's")
	}

	// The check: on a copy beside the live files (0750, files 0640), with the
	// copy of the dictionary as -D; gone afterwards.
	if len(r.checks) == 0 {
		t.Fatal("the daemon's check did not run")
	}
	c := r.checks[0]
	if !regexp.MustCompile(`^` + regexp.QuoteMeta(m.L.Dir) + `/\.tacctl-check\.[A-Za-z0-9]+$`).MatchString(c.Dir) {
		t.Errorf("check dir %q", c.Dir)
	}
	if c.DDir != c.Dir+"/dictionary.d" {
		t.Errorf("check dictionary dir %q", c.DDir)
	}
	want := []string{"-C", "-lstdout", "-d", c.Dir, "-D", c.DDir, "-n", "tacctl-radius"}
	if strings.Join(c.Argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv %v", c.Argv)
	}
	if c.DirMode != 0o750 || c.DDirMode != 0o750 {
		t.Errorf("scratch dirs are %o and %o", c.DirMode, c.DDirMode)
	}
	for name, mode := range c.FileModes {
		if mode != 0o640 {
			t.Errorf("scratch %s is %o", name, mode)
		}
	}
	if len(c.FileModes) != 3 {
		t.Errorf("the check saw %v", c.FileModes)
	}
	for _, f := range []string{c.Dir, c.DDir} {
		if !slices.Contains(r.chowns, f) {
			t.Errorf("scratch %s not given to the group (%v)", f, r.chowns)
		}
	}
	r.noLeftovers()
	// Nothing is validated as drift afterwards.
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift after a render: %v", lines)
	}
}

// The RHEL layout renders the radiusd account and paths.
func TestRenderRHELLayout(t *testing.T) {
	r := newEnv(t, rhel)
	r.useStore("store.radius.yaml")
	r.enableList("tacacs, radius")
	if err := r.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatalf("config render: %v\n%s", err, r.stderr)
	}
	conf := r.read(r.m.L.Conf)
	for _, want := range []string{"\tuser = radiusd\n", "\nlibdir = /usr/lib64/freeradius\n", "\npidfile = /run/radiusd/radiusd.pid\n"} {
		contains(t, conf, want)
	}
	if !slices.Contains(r.chowns, r.m.L.Conf+".tacctl-new") {
		t.Errorf("chowns: %v", r.chowns)
	}
	if got := r.m.L.Unit; got != "radiusd.service" {
		t.Errorf("unit %s", got)
	}
}

// "enable: the warnings of the rendered state are shown (command rules,
// secrets)": backend_radius_render_notes, after 'config render'.
func TestRenderNotesWarn(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("tacacs, radius")
	if err := r.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	out := r.out()
	contains(t, out, "RADIUS does not enforce the command rules (commands.<group>) of: operator.")
	contains(t, out, "The secret of scope lab, prod-inner is longer than 63 characters or has a space")
	contains(t, out, "Over RADIUS no vendor attribute is sent to the devices of scope(s) lab, prod, prod-inner, wifi: an Access-Accept carries Service-Type only.")
	// The warnings go to stdout (warn), and 'Rendered ...' names the three files.
	contains(t, strip(r.stdout.String()), "[WARN] RADIUS does not enforce")
	contains(t, out, "Rendered "+r.m.L.Conf+", "+r.m.L.Users+", "+r.m.L.Dict+".")
}

// The dictionary is committed first, then the users file, then the config
// that carries the render id.
func TestCommitOrderDictionaryUsersConf(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	dir := t.TempDir()
	ctx := context.Background()
	if err := r.m.RenderStage(ctx, dir, false); err != nil {
		t.Fatalf("stage: %v\n%s", err, r.stderr)
	}
	for _, f := range []string{"conf", "users", "dictionary", "status"} {
		if !r.exists(filepath.Join(dir, f)) {
			t.Errorf("stage left no %s", f)
		}
	}
	if got := strings.TrimSpace(r.read(filepath.Join(dir, "status"))); got != "missing missing missing" {
		t.Errorf("status %q", got)
	}
	// The staged files are 0600 (they hold secrets and hashes).
	for _, f := range []string{"conf", "users", "dictionary"} {
		if got := r.mode(filepath.Join(dir, f)); got != 0o600 {
			t.Errorf("staged %s is %o", f, got)
		}
	}
	// Nothing outside dir was touched by the stage.
	for _, f := range r.m.Artifacts() {
		if r.exists(f) {
			t.Errorf("stage wrote %s", f)
		}
	}
	r.chowns = nil // the check's scratch directory was given to the group too
	changed, err := r.m.RenderCommit(ctx, dir)
	if err != nil || !changed {
		t.Fatalf("commit: %v %v", changed, err)
	}
	// The order of the commit, read off the owner changes it makes: the
	// dictionary's new directory and file first (the other two need its
	// attributes), then the users file, then the config that carries the
	// render id.
	wantOrder := []string{r.m.L.DictDir, r.m.L.Dict + ".tacctl-new", r.m.L.Users + ".tacctl-new", r.m.L.Conf + ".tacctl-new"}
	if got := r.chowns; strings.Join(got, "\n") != strings.Join(wantOrder, "\n") {
		t.Errorf("commit order:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantOrder, "\n"))
	}
	for _, f := range r.m.Artifacts() {
		if w, _ := rendered.Check(r.p.Rendered, f); w != rendered.OK {
			t.Errorf("%s: %s", f, w)
		}
	}
	// A second commit of the same stage replaces nothing: every file is current.
	dir2 := t.TempDir()
	if err := r.m.RenderStage(ctx, dir2, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(r.read(filepath.Join(dir2, "status"))); got != "current current current" {
		t.Errorf("status %q", got)
	}
	changed, err = r.m.RenderCommit(ctx, dir2)
	if err != nil || changed {
		t.Errorf("recommit: %v %v", changed, err)
	}
}

// The three states other than "write": a file identical to the render that
// tacctl has no record of is recorded and not rewritten ('same'); a file
// recorded and unchanged but different from the render is replaced ('ok');
// a file somebody edited is refused without force, and with force it is
// saved under backups/legacy/ first.
func TestStageStatesAndForce(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	ctx := context.Background()
	if _, err := r.set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		t.Fatalf("render: %v\n%s", err, r.stderr)
	}
	r.reset()

	// same: drop the record of the users file.
	if err := rendered.Forget(r.p.Rendered, r.m.L.Users); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := r.m.RenderStage(ctx, dir, false); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got := strings.TrimSpace(r.read(filepath.Join(dir, "status"))); got != "current same current" {
		t.Errorf("status %q", got)
	}
	changed, err := r.m.RenderCommit(ctx, dir)
	if err != nil || changed {
		t.Errorf("commit of 'same': %v %v", changed, err)
	}
	if w, _ := rendered.Check(r.p.Rendered, r.m.L.Users); w != rendered.OK {
		t.Errorf("'same' was not recorded: %s", w)
	}

	// drift: an edit of the users file.
	f, _ := os.OpenFile(r.m.L.Users, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# hand edit\n")
	_ = f.Close()
	r.reset()
	dir = t.TempDir()
	err = r.m.RenderStage(ctx, dir, false)
	wantCode(t, err, 3)
	out := r.out()
	contains(t, out, r.m.L.Conf+", "+r.m.L.Users+" or "+r.m.L.Dict+" was edited since tacctl rendered it; rendering would discard those edits.")
	contains(t, out, "There is no way to adopt an edit of the RADIUS files into the store. To discard it: 'tacctl config render --force' (the current files are saved under "+r.p.BackupDir+"/legacy/ first).")
	if r.exists(filepath.Join(dir, "status")) {
		t.Error("a refused stage left a status")
	}
	if len(r.checks) != 0 {
		t.Error("the daemon was asked about a render that was refused")
	}

	r.reset()
	dir = t.TempDir()
	if err := r.m.RenderStage(ctx, dir, true); err != nil {
		t.Fatalf("forced stage: %v\n%s", err, r.stderr)
	}
	if got := strings.TrimSpace(r.read(filepath.Join(dir, "status"))); got != "current drift current" {
		t.Errorf("status %q", got)
	}
	changed, err = r.m.RenderCommit(ctx, dir)
	if err != nil || !changed {
		t.Fatalf("commit: %v %v", changed, err)
	}
	if strings.Contains(r.read(r.m.L.Users), "hand edit") {
		t.Error("the edit survived the forced render")
	}
	saved, _ := filepath.Glob(filepath.Join(r.p.BackupDir, "legacy", "tacctl-radius.users.drift.*"))
	if len(saved) != 1 {
		t.Fatalf("saved copies: %v", saved)
	}
	if !strings.Contains(r.read(saved[0]), "hand edit") {
		t.Error("the saved copy lacks the edit")
	}
	if got := r.mode(saved[0]); got != 0o600 {
		t.Errorf("saved copy is %o", got)
	}
	if got := r.mode(filepath.Dir(saved[0])); got != 0o700 {
		t.Errorf("legacy directory is %o", got)
	}
	contains(t, r.out(), "Previous "+r.m.L.Users+" saved to "+saved[0])
	if !regexp.MustCompile(`\.drift\.20261002_120000_000$`).MatchString(saved[0]) {
		t.Errorf("saved name %s", saved[0])
	}
	// The warning is on stderr (warn ... >&2).
	contains(t, r.stderr.String(), "Previous ")
}

// "Cannot read rendered.json; refusing to overwrite": records that cannot be
// read are never "ok".
func TestStageRefusesWhenRecordsAreUnreadable(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	if err := os.WriteFile(r.p.Rendered, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := r.m.RenderStage(context.Background(), t.TempDir(), true)
	wantCode(t, err, 1)
	contains(t, r.out(), "Cannot read "+r.p.Rendered+"; refusing to overwrite "+r.m.L.Conf+".")
	// And the gate says the same, as a failure rather than a refusal.
	r.reset()
	if got := r.m.RenderGate(context.Background()); got != backend.GateFailed {
		t.Errorf("gate %v", got)
	}
	contains(t, r.out(), "Cannot read "+r.p.Rendered+"; refusing to overwrite "+r.m.L.Conf+".")
}

// "enable: a config the daemon rejects is not installed; nothing is
// changed" (the render half: the generic enable's own messages are WP3.3c's).
func TestDaemonRejectsTheConfigNothingChanges(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("tacacs, radius")
	r.setFailCheck(true)
	before := r.state()
	err := r.set.ConfigRender(context.Background(), false)
	wantCode(t, err, 1)
	out := r.out()
	contains(t, out, "FreeRADIUS rejects the rendered configuration ('radiusd -C'):")
	// The daemon's message names the live path, not the scratch copy.
	contains(t, out, r.m.L.Conf+"[12]: Parse error")
	notContains(t, out, ".tacctl-check.")
	if r.state() != before {
		t.Errorf("state changed:\n%s\nwas\n%s", r.state(), before)
	}
	if r.exists(r.m.L.Conf) || r.exists(r.m.L.Users) {
		t.Error("artifacts were installed")
	}
	if r.called(`^systemctl (start|enable) `) {
		t.Errorf("calls: %v", r.calls())
	}
	r.noLeftovers()
}

// The error report is the last five lines that mention an error, case
// blind, with the scratch paths turned into the live ones.
func TestDaemonErrorReportIsTheLastFiveErrorLines(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	r.run.OnFunc([]string{r.m.L.Bin}, func(c execx.Cmd) (execx.Result, error) {
		dir := c.Args[3]
		var b strings.Builder
		b.WriteString("Starting - reading configuration files ...\n")
		for i := 1; i <= 7; i++ {
			b.WriteString("Error: " + dir + "/tacctl-radius.conf[" + string(rune('0'+i)) + "]: problem\n")
		}
		b.WriteString("Info: not shown\nERROR in " + dir + "/dictionary.d/dictionary: x\n")
		return execx.Result{Stdout: []byte(b.String()), Code: 1}, nil
	})
	err := r.set.ConfigRender(context.Background(), false)
	wantCode(t, err, 1)
	var got []string
	for _, l := range strings.Split(r.stderr.String(), "\n") {
		if strings.Contains(l, "problem") || strings.Contains(l, "ERROR in") {
			got = append(got, l)
		}
	}
	want := []string{
		"Error: " + r.m.L.Dir + "/tacctl-radius.conf[4]: problem",
		"Error: " + r.m.L.Dir + "/tacctl-radius.conf[5]: problem",
		"Error: " + r.m.L.Dir + "/tacctl-radius.conf[6]: problem",
		"Error: " + r.m.L.Dir + "/tacctl-radius.conf[7]: problem",
		"ERROR in " + r.m.L.DictDir + "/dictionary: x",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// With no daemon on the machine the check is skipped, and the render goes
// through; the package's main dictionary missing is a clear failure that
// changes nothing.
func TestDaemonCheckSkippedAndMissingDictionary(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Remove(r.m.L.Bin); err != nil {
		t.Fatal(err)
	}
	checked, err := r.m.DaemonCheck(ctx, dir)
	if checked || err != nil {
		t.Errorf("no daemon: %v %v", checked, err)
	}
	if err := r.m.RenderStage(ctx, t.TempDir(), false); err != nil {
		t.Fatalf("stage without a daemon: %v", err)
	}
	if len(r.checks) != 0 {
		t.Error("a missing daemon was run")
	}

	r.packagePresent()
	if err := os.Remove(r.m.L.SystemDict); err != nil {
		t.Fatal(err)
	}
	r.reset()
	before := r.state()
	err = r.m.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 1)
	contains(t, r.out(), "FreeRADIUS's main dictionary is not at "+r.m.L.SystemDict+"; tacctl's dictionary ("+r.m.L.Dict+") includes it.")
	contains(t, r.out(), "The freeradius package is incomplete")
	if r.state() != before || len(r.checks) != 0 {
		t.Error("a render without the package dictionary changed something or ran the daemon")
	}
}

// RenderCheck: the trial render with the daemon's check, and the state
// furthest from the render; nothing is installed.
func TestRenderCheck(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	ctx := context.Background()
	got, err := r.m.RenderCheck(ctx)
	if err != nil || got != "missing" {
		t.Fatalf("before the first render: %q %v", got, err)
	}
	for _, f := range r.m.Artifacts() {
		if r.exists(f) {
			t.Errorf("RenderCheck wrote %s", f)
		}
	}
	if len(r.checks) != 1 {
		t.Errorf("the daemon was asked %d times", len(r.checks))
	}
	if _, err := r.set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := r.m.RenderCheck(ctx); err != nil || got != "current" {
		t.Errorf("after a render: %q %v", got, err)
	}
	// The store changes: the live files are recorded and unedited, but not
	// what the store renders.
	if _, err := store.Mutate(r.p.StoreFile, store.MutateOptions{}, func(s *store.Store) error { return s.UserSet("bob", "disabled=true") }); err != nil {
		t.Fatal(err)
	}
	if got, err := r.m.RenderCheck(ctx); err != nil || got != "ok" {
		t.Errorf("after a store change: %q %v", got, err)
	}
	f, _ := os.OpenFile(r.m.L.Conf, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# edit\n")
	_ = f.Close()
	if got, err := r.m.RenderCheck(ctx); err != nil || got != "drift" {
		t.Errorf("after an edit: %q %v", got, err)
	}
	r.noLeftovers()
	// A render the daemon rejects, or a store that does not render, is an error.
	r.setFailCheck(true)
	if _, err := r.m.RenderCheck(ctx); backend.ExitCode(err) != 1 {
		t.Errorf("rejected: %v", err)
	}
	r.setFailCheck(false)
	if err := os.WriteFile(r.p.StoreFile, []byte("version: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if _, err := r.m.RenderCheck(ctx); backend.ExitCode(err) != 1 {
		t.Errorf("bad store: %v", err)
	}
	contains(t, r.stderr.String(), "tacctl render: ")
	r.noLeftovers()
}

// --- the gate and the drift report, through mutations -----------------------

// "drift: a hand edit of either RADIUS file refuses mutations (exit 3) until
// 'config render --force', which keeps a copy".
func TestDriftRefusesMutationsUntilForcedRender(t *testing.T) {
	r := newEnv(t)
	r.up()
	appendTo(t, r.m.L.Users, "# hand edit\n")
	before := r.state()
	_, err := r.apply(r.userSet("bob", "disabled=true"))
	wantCode(t, err, 3)
	out := r.out()
	contains(t, out, r.m.L.Users+" was edited since tacctl rendered it")
	contains(t, out, "no way to adopt an edit of the RADIUS files")
	if r.state() != before {
		t.Error("a refused mutation changed state")
	}

	// config validate's DRIFT lines.
	lines := strip(strings.Join(r.set.DriftLines(backend.DriftAll), ""))
	contains(t, lines, "DRIFT:")
	contains(t, lines, r.m.L.Users+" — edited since tacctl rendered it")
	contains(t, lines, "there is no way to adopt them into the store")

	ctx := context.Background()
	wantCode(t, r.set.ConfigRender(ctx, false), 3)
	if err := r.set.ConfigRender(ctx, true); err != nil {
		t.Fatalf("forced: %v\n%s", err, r.stderr)
	}
	if strings.Contains(r.read(r.m.L.Users), "hand edit") {
		t.Error("the edit survived")
	}
	saved, _ := filepath.Glob(filepath.Join(r.p.BackupDir, "legacy", "tacctl-radius.users.drift.*"))
	if len(saved) != 1 || !strings.Contains(r.read(saved[0]), "hand edit") {
		t.Errorf("saved: %v", saved)
	}
	if _, err := r.apply(r.userSet("bob", "disabled=true")); err != nil {
		t.Fatalf("after the forced render: %v\n%s", err, r.stderr)
	}
}

// "drift: a file tacctl has no record of is refused too, and replaced only
// with --force".
func TestUnrecordedFileIsRefusedToo(t *testing.T) {
	r := newEnv(t)
	r.up()
	if err := rendered.Forget(r.p.Rendered, r.m.L.Conf); err != nil {
		t.Fatal(err)
	}
	appendTo(t, r.m.L.Conf, "# not ours\n")
	_, err := r.apply(r.userSet("bob", "disabled=true"))
	wantCode(t, err, 3)
	contains(t, r.out(), r.m.L.Conf+" was not rendered by tacctl")
}

// "dictionary: a hand edit of it refuses mutations like the other two; a
// missing package dictionary fails clearly and changes nothing".
func TestDictionaryEditRefusesAndMissingPackageDictionaryFails(t *testing.T) {
	r := newEnv(t)
	r.up()
	appendTo(t, r.m.L.Dict, "ATTRIBUTE X 3000 string\n")
	_, err := r.apply(r.userSet("bob", "disabled=true"))
	wantCode(t, err, 3)
	contains(t, r.out(), r.m.L.Dict+" was edited since tacctl rendered it")
	if err := r.set.ConfigRender(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.read(r.m.L.Dict), "ATTRIBUTE X") {
		t.Error("edit survived")
	}
	saved, _ := filepath.Glob(filepath.Join(r.p.BackupDir, "legacy", "dictionary.drift.*"))
	if len(saved) != 1 {
		t.Errorf("saved: %v", saved)
	}

	if err := os.Remove(r.m.L.SystemDict); err != nil {
		t.Fatal(err)
	}
	r.reset()
	before := r.state()
	_, err = r.apply(r.userSet("bob", "disabled=true"))
	wantCode(t, err, 1)
	contains(t, r.out(), "FreeRADIUS's main dictionary is not at "+r.m.L.SystemDict)
	if r.state() != before {
		t.Error("state changed")
	}
}

// "validate: a missing artifact is reported for radius, and 'config render'
// puts it back".
func TestMissingArtifactIsReportedAndRenderPutsItBack(t *testing.T) {
	r := newEnv(t)
	r.up()
	if err := os.Remove(r.m.L.Users); err != nil {
		t.Fatal(err)
	}
	lines := strip(strings.Join(r.set.DriftLines(backend.DriftOf("radius")), ""))
	contains(t, lines, r.m.L.Users+" — rendered by tacctl but no longer there")
	if got := r.m.RenderGate(context.Background()); got != backend.GateOK {
		t.Errorf("gate for a missing file: %v", got)
	}
	if err := r.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatalf("render: %v\n%s", err, r.stderr)
	}
	if !r.exists(r.m.L.Users) {
		t.Error("not put back")
	}
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("still drifted: %v", lines)
	}
}

// The gate's exact messages and answers: never "adopt".
func TestGateAnswers(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	if got := r.m.RenderGate(ctx); got != backend.GateOK {
		t.Fatalf("clean: %v", got)
	}
	appendTo(t, r.m.L.Conf, "# x\n")
	if got := r.m.RenderGate(ctx); got != backend.GateRefused {
		t.Fatalf("edited: %v", got)
	}
	out := r.out()
	contains(t, out, r.m.L.Conf+" was edited since tacctl rendered it; this command would discard those edits.")
	contains(t, out, "Nothing was changed. There is no way to adopt an edit of the RADIUS files into the store; to discard it: 'tacctl config render --force'. Then run this command again.")
	r.reset()
	if err := rendered.Forget(r.p.Rendered, r.m.L.Conf); err != nil {
		t.Fatal(err)
	}
	if got := r.m.RenderGate(ctx); got != backend.GateRefused {
		t.Fatalf("unrecorded: %v", got)
	}
	contains(t, r.out(), r.m.L.Conf+" was not rendered by tacctl; this command would replace it.")
	// The gate writes on stderr only.
	if r.stdout.Len() != 0 {
		t.Errorf("gate wrote on stdout: %q", r.stdout)
	}
}

// --- what a mutation renders ------------------------------------------------

// "mutation: both backends are rendered and restarted; the users file
// follows the store".
func TestMutationRendersAndRestartsBothBackends(t *testing.T) {
	r := newEnv(t)
	r.up()
	if !r.hasLine(r.m.L.Users, "bob") {
		t.Fatal("bob has no entry to begin with")
	}
	if _, err := r.apply(r.userSet("bob", "disabled=true")); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	if r.hasLine(r.m.L.Users, "bob") {
		t.Error("bob is still served")
	}
	if !r.tac.Called("service restart") {
		t.Errorf("tacacs not restarted: %v", r.tac.Calls())
	}
	if r.restarts("freeradius.service") != 1 {
		t.Errorf("calls: %v", r.calls())
	}
	if len(r.checks) == 0 {
		t.Error("the check did not run on the new render")
	}
	contains(t, r.out(), "Service restarted (freeradius).")
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift: %v", lines)
	}
	r.noLeftovers()
}

// "mutation: a change RADIUS does not see (a TACACS+-only scope's secret)
// restarts tacquito only".
func TestMutationRadiusDoesNotSeeRestartsTacacsOnly(t *testing.T) {
	r := newEnv(t)
	r.up()
	w := r.mutate(func(s *store.Store) error { return s.ScopeSet("legacy", "secret=another-legacy-secret-0123456789") })
	if _, err := r.apply(w); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	if !r.tac.Called("service restart") {
		t.Errorf("tacacs not restarted: %v", r.tac.Calls())
	}
	if r.called(`^systemctl restart freeradius`) {
		t.Errorf("radius restarted: %v", r.calls())
	}
}

// "mutation: a render the daemon rejects changes nothing, in either backend".
func TestMutationDaemonRejectsChangesNothing(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.setFailCheck(true)
	before := r.state()
	_, err := r.apply(r.userSet("bob", "disabled=true"))
	wantCode(t, err, 1)
	contains(t, r.out(), "FreeRADIUS rejects the rendered configuration")
	if r.state() != before {
		t.Errorf("state changed:\n%s\nwas\n%s", r.state(), before)
	}
	if r.called(`^systemctl restart`) || r.tac.Called("service restart") {
		t.Errorf("restarted after a failed render: %v %v", r.calls(), r.tac.Calls())
	}
	r.noLeftovers()
}

// "mutation: a secret FreeRADIUS cannot carry is refused and the store keeps
// the old one".
func TestMutationUnwritableSecretIsRefused(t *testing.T) {
	r := newEnv(t)
	r.up()
	before := r.state()
	w := r.mutate(func(s *store.Store) error { return s.ScopeSet("prod", `secret=back\slash-and-$dollar-0123456789`) })
	_, err := r.apply(w)
	wantCode(t, err, 1)
	contains(t, r.out(), "scope 'prod': its secret holds both a backslash and a dollar sign")
	if r.state() != before {
		t.Error("state changed")
	}
}

// "scope protocols: taking radius off a scope removes its clients and its
// users' entries; putting it back restores them".
func TestScopeProtocolsRemovesAndRestoresClients(t *testing.T) {
	r := newEnv(t)
	r.up()
	conf := func() string { return r.read(r.m.L.Conf) }
	contains(t, conf(), `tacctl_scope = "lab"`)
	set := func(fields ...string) {
		t.Helper()
		if _, err := r.apply(r.mutate(func(s *store.Store) error { return s.ScopeSet("lab", fields...) })); err != nil {
			t.Fatalf("apply %v: %v\n%s", fields, err, r.stderr)
		}
	}
	set("protocols=tacacs")
	notContains(t, conf(), `tacctl_scope = "lab"`)
	notContains(t, r.read(r.m.L.Users), `/lab"`)
	if r.hasLine(r.m.L.Users, "bob") || !r.hasLine(r.m.L.Users, "alice") {
		t.Error("users entries after taking radius off lab")
	}
	set("protocols=")
	contains(t, conf(), `tacctl_scope = "lab"`)
	if !r.hasLine(r.m.L.Users, "bob") {
		t.Error("bob did not come back")
	}
	// A RADIUS-only scope is in the RADIUS files.
	contains(t, conf(), `tacctl_scope = "wifi"`)
}

// "rendered: disabled users and the sink are absent; overlapping prefixes
// are ordered most specific first".
func TestRenderedDisabledUsersAndOverlapOrder(t *testing.T) {
	r := newEnv(t)
	r.up()
	for _, name := range []string{"carol", "root"} {
		if r.hasLine(r.m.L.Users, name) {
			t.Errorf("%s has an entry", name)
		}
	}
	conf := r.read(r.m.L.Conf)
	inner := strings.Index(conf, "ipaddr = 10.10.99.0/24")
	outer := strings.Index(conf, "ipaddr = 10.0.0.0/8")
	if inner < 0 || outer < 0 || inner > outer {
		t.Errorf("order: %d %d", inner, outer)
	}
}

// "vendor attributes: a change re-renders and restarts RADIUS only;
// tacquito.yaml is byte-identical".
func TestVendorAttributeChangeRestartsRadiusOnly(t *testing.T) {
	r := newEnv(t)
	r.up()
	if _, err := r.apply(r.mutate(func(s *store.Store) error { return s.ScopeSet("lab", "vendor_attrs=cisco,wti") })); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	if r.restarts("freeradius.service") != 1 {
		t.Errorf("calls: %v", r.calls())
	}
	if r.tac.Called("service restart") {
		t.Errorf("tacacs restarted: %v", r.tac.Calls())
	}
	conf := r.read(r.m.L.Conf)
	i := strings.Index(conf, "\tclient lab.1 {")
	if i < 0 || !strings.Contains(conf[i:i+400], `tacctl_send_cisco = "yes"`) {
		t.Errorf("lab.1 does not send cisco:\n%s", conf[max(i, 0):])
	}
	r.reset()
	if _, err := r.apply(r.mutate(func(s *store.Store) error { return s.ScopeSet("prod", "devices=10.9.9.9/32=juniper") })); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	if r.restarts("freeradius.service") != 1 || r.tac.Called("service restart") {
		t.Errorf("calls: %v %v", r.calls(), r.tac.Calls())
	}
	contains(t, r.read(r.m.L.Conf), "\tclient prod.juniper.1 {")
	var b strings.Builder
	if err := r.m.Status(context.Background(), backend.StatusSummary, &b); err != nil {
		t.Fatal(err)
	}
	contains(t, strip(b.String()), "Vendor attributes:    enabled for 1 of 4 scope(s), 1 tagged address(es)")
}

// "the next mutation after the code changed: all three rendered, the drop-in
// brought in line before the restart": the files of the release before the
// dictionary are what tacctl rendered then, so the next render replaces
// them without a word about drift, and the restart brings the drop-in along.
func TestNextMutationAfterTheCodeChanged(t *testing.T) {
	r := newEnv(t)
	r.up()
	l := r.m.L
	r.preVendorState()
	if _, err := r.apply(r.userSet("bob", "disabled=true")); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	notContains(t, r.out(), "edited since")
	if !r.exists(l.Dict) {
		t.Error("no dictionary")
	}
	if w, _ := rendered.Check(r.p.Rendered, l.Dict); w != rendered.OK {
		t.Errorf("dictionary: %s", w)
	}
	contains(t, r.read(l.DropIn), "-D "+l.DictDir+" -n tacctl-radius\n")
	// daemon-reload, then exactly one restart of the unit.
	var seq []string
	for _, c := range r.calls() {
		if c == "systemctl daemon-reload" || c == "systemctl restart freeradius.service" {
			seq = append(seq, c)
		}
	}
	if strings.Join(seq, ";") != "systemctl daemon-reload;systemctl restart freeradius.service" {
		t.Errorf("sequence %v", seq)
	}
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift: %v", lines)
	}
	r.noLeftovers()
}

// preVendorState is pre_vendor_state: the state the release before the
// dictionary leaves: its two files (a real render of that release, recorded
// as what tacctl rendered), no dictionary, and its drop-in, which starts
// the daemon without -D.
func (r *renv) preVendorState() {
	r.t.Helper()
	l := r.m.L
	for f, fix := range map[string]string{l.Conf: "radius.pre-vendor.conf", l.Users: "radius.pre-vendor.users"} {
		data, err := os.ReadFile(fixtures + fix)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(f, data, 0o640); err != nil {
			r.t.Fatal(err)
		}
		if err := rendered.Record(r.p.Rendered, f); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := os.RemoveAll(l.DictDir); err != nil {
		r.t.Fatal(err)
	}
	if err := rendered.Forget(r.p.Rendered, l.Dict); err != nil {
		r.t.Fatal(err)
	}
	old := "# Installed by tacctl ('tacctl backend enable radius'), removed by 'tacctl backend disable radius'.\n" +
		"[Service]\nExecStartPre=\nExecStartPre=" + l.Bin + " -C -lstdout -d " + l.Dir + " -n tacctl-radius\n" +
		"ExecStart=\nExecStart=" + l.Bin + " -f -d " + l.Dir + " -n tacctl-radius\n"
	if err := os.WriteFile(l.DropIn, []byte(old), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.reset()
}

// "disable: while disabled its artifacts are not rendered, and the store can
// change"; enabling renders the current store.
func TestDisabledBackendIsNotRenderedAndIsAgainWhenEnabled(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	// The generic 'backend disable': the list, then the module's disable.
	r.enableList("tacacs")
	if _, err := r.m.Service(ctx, backend.ServiceStop, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.m.Service(ctx, backend.ServiceDisable, ""); err != nil {
		t.Fatal(err)
	}
	before := r.read(r.m.L.Users)
	if _, err := r.apply(r.userSet("bob", "disabled=true")); err != nil {
		t.Fatalf("apply: %v\n%s", err, r.stderr)
	}
	if r.read(r.m.L.Users) != before {
		t.Error("a disabled backend was rendered")
	}
	// Enabling renders the current store.
	r.enableList("tacacs, radius")
	if _, err := r.m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.set.ConfigRender(ctx, false); err != nil {
		t.Fatalf("render: %v\n%s", err, r.stderr)
	}
	if r.hasLine(r.m.L.Users, "bob") {
		t.Error("bob is served after being disabled")
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(text)
	_ = f.Close()
}
