package tacacs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/rendered"
)

// tests/integration/units_convert.bats: the systemd side of install,
// upgrade and uninstall (unitsInstall, upgradeUnits, upgradeFinish, the
// uninstall phases), against a scratch unit directory with systemctl
// scripted. The running daemon is never touched by the unit install
// itself: the tests pin that it makes no systemctl call other than
// daemon-reload and a 'show'.

type uconv struct {
	*ltenv
	tree, shipped                            string
	unit, tmpl, dropin, oldDropin, overrides string
}

func newUnitsEnv(t *testing.T) *uconv {
	t.Helper()
	e := newLifeTenv(t).withStoreLife("store.multiscope.yaml")
	writeFile(t, e.p.Config, readFile(t, filepath.Join(fixDir, "tacquito.multiscope.yaml")))
	tree := repoRoot(t)
	return &uconv{
		ltenv: e, tree: tree, shipped: filepath.Join(tree, Share),
		unit: e.b.serviceFile(), tmpl: e.b.templateFile(), dropin: e.dropIn("default"),
		oldDropin: e.b.overrideFile(), overrides: e.p.Overrides,
	}
}

func (e *ltenv) withStoreLife(name string) *ltenv {
	e.withStore(name)
	return e
}

// oldInstall is old_install: the unit of a release from before the
// listener model and (with arguments) its hand-managed drop-in.
func (u *uconv) oldInstall(kv ...string) {
	u.t.Helper()
	writeFile(u.t, u.unit, readFile(u.t, filepath.Join(fixDir, "systemd", "tacquito.service.pre-listeners")))
	if len(kv) > 0 {
		u.legacyDropIn(kv...)
	}
}

func (u *uconv) install() bool { return u.b.unitsInstall(context.Background(), u.tree) }

// treeState is tree_state: what the conversion may write, plus the
// instances' drop-in directories.
func (u *uconv) treeState() string {
	s := state(u.unit, u.tmpl, u.dropin, u.oldDropin, u.overrides)
	m, _ := filepath.Glob(filepath.Join(u.p.TacacsUnitDir, "tacquito@*.service.d"))
	return s + strings.Join(m, "\n")
}

func (u *uconv) noSystemctl(re string) {
	u.t.Helper()
	if u.called(re) {
		u.t.Fatalf("unexpected %s in %q", re, u.run.Argvs())
	}
}

// assertUntouched: the old install is exactly as it was and nothing new
// exists.
func (u *uconv) assertUntouched(before string) {
	u.t.Helper()
	if got := u.treeState(); got != before {
		u.t.Fatalf("changed:\n%s\nwas\n%s", got, before)
	}
	if exists(u.tmpl) || exists(u.dropin) {
		u.t.Fatal("new files")
	}
	u.noKeep()
	u.noSystemctl(`^systemctl (restart|start|stop|enable|disable)`)
}

// --- fresh machine -------------------------------------------------------

func TestUnitsInstallFresh(t *testing.T) {
	u := newUnitsEnv(t)
	if !u.install() {
		t.Fatal(u.out())
	}
	u.b.unitsKeepDiscard()
	// The second run has nothing to do.
	if !u.install() || u.b.life.unitsState != "" {
		t.Fatal(u.b.life.unitsState)
	}
	if !sameBytes(u.unit, filepath.Join(u.shipped, "tacquito.service")) || !sameBytes(u.tmpl, filepath.Join(u.shipped, "tacquito@.service")) {
		t.Fatal("unit files differ from the shipped ones")
	}
	for _, f := range []string{u.unit, u.dropin} {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o644 {
			t.Fatal(f, st.Mode())
		}
	}
	for k, v := range map[string]string{"TACQUITO_NETWORK": "tcp", "TACQUITO_ADDRESS": ":49", "TACQUITO_LEVEL": "20",
		"TACQUITO_METRICS_ADDRESS": "127.0.0.1:8080", "TACQUITO_ACCT_LOG": u.p.Log + "/accounting.log"} {
		if got := envOf(t, u.dropin, k); got != v {
			t.Fatalf("%s=%q", k, got)
		}
	}
	if exists(u.overrides) || exists(u.unit+".bak") || exists(u.oldDropin) {
		t.Fatal("imported or backed up something")
	}
	if !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.run.Argvs())
	}
	u.noSystemctl(`^systemctl (restart|start|stop|enable|disable)`)
}

func TestUnitsInstallFirstRunReportsChanged(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	if u.b.life.unitsState != unitsChanged || !isDir(u.b.life.unitsKeep) {
		t.Fatal(u.b.life)
	}
	for _, n := range []string{"Installed: tacquito.service", "Installed: tacquito@.service", "Rendered: the listener drop-in of tacquito.service"} {
		if !slices.Contains(u.b.life.unitsNotes, n) {
			t.Fatal(u.b.life.unitsNotes)
		}
	}
	u.b.unitsKeepDiscard()
	u.noKeep()
}

// --- conversion ----------------------------------------------------------------

func TestUnitsConvertMovesTheDropInIntoTacctlYAML(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_NETWORK=tcp", "TACQUITO_ADDRESS=10.1.0.1:4949", "TACQUITO_LEVEL=30", "TACQUITO_METRICS_ADDRESS=:9090")
	old := readFile(t, u.oldDropin)
	if !u.install() {
		t.Fatal(u.out())
	}
	mustContain(t, u.out(), "settings moved from "+u.oldDropin+" into "+u.overrides)

	// tacctl.yaml is the source of truth now...
	c := u.env.Conf
	if v, _ := c.GetJSON("listeners.tacacs.default"); v != `{"network": "tcp", "address": "10.1.0.1:4949"}` {
		t.Fatal(v)
	}
	if v, _ := c.Get("backends.tacacs.level", ""); v != "30" {
		t.Fatal(v)
	}
	if v, _ := c.Get("backends.tacacs.metrics_address", ""); v != ":9090" {
		t.Fatal(v)
	}
	// ...the rendered drop-in says what the hand-managed one said...
	for k, v := range map[string]string{"TACQUITO_NETWORK": "tcp", "TACQUITO_ADDRESS": "10.1.0.1:4949", "TACQUITO_LEVEL": "30",
		"TACQUITO_METRICS_ADDRESS": ":9090", "TACQUITO_ACCT_LOG": u.p.Log + "/accounting.log"} {
		if got := envOf(t, u.dropin, k); got != v {
			t.Fatalf("%s=%q", k, got)
		}
	}
	// ...and the old one is gone, with a copy kept and the old unit backed up.
	if exists(u.oldDropin) {
		t.Fatal("the hand-managed drop-in is still there")
	}
	kept, _ := filepath.Glob(filepath.Join(u.p.BackupDir, "legacy", "tacctl-overrides.conf.*"))
	if len(kept) != 1 || readFile(t, kept[0]) != old {
		t.Fatal(kept)
	}
	if !sameBytes(u.unit+".bak", filepath.Join(fixDir, "systemd", "tacquito.service.pre-listeners")) ||
		!sameBytes(u.unit, filepath.Join(u.shipped, "tacquito.service")) ||
		!sameBytes(u.tmpl, filepath.Join(u.shipped, "tacquito@.service")) {
		t.Fatal("unit files")
	}

	s := show(t, u.tenv, "")
	mustLine(t, s, "  Current listener: tcp 10.1.0.1:4949")
	mustLine(t, s, "  (override in "+u.overrides+")")
	u.reset()
	_ = u.b.LogLevel(context.Background(), "")
	mustContain(t, u.stdout.String(), "debug (30)")
	u.reset()
	_ = u.b.Metrics(context.Background(), "show", "")
	mustContain(t, u.stdout.String(), ":9090  (override)")
}

// "convert: only what the drop-in set is written (a log level alone, as on
// the dev server)".
func TestUnitsConvertWritesOnlyWhatTheDropInSet(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	if !u.install() {
		t.Fatal(u.out())
	}
	var kept []string
	for _, l := range strings.Split(readFile(t, u.overrides), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			kept = append(kept, l)
		}
	}
	if got := strings.Join(kept, "\n"); got != "backends:\n  tacacs:\n    level: 30" {
		t.Fatalf("%q", got)
	}
	if envOf(t, u.dropin, "TACQUITO_ADDRESS") != ":49" || envOf(t, u.dropin, "TACQUITO_LEVEL") != "30" {
		t.Fatal(readFile(t, u.dropin))
	}
}

func TestUnitsConvertWithoutADropIn(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall()
	if !u.install() {
		t.Fatal(u.out())
	}
	mustNotContain(t, u.out(), "settings moved")
	if exists(u.overrides) || !sameBytes(u.unit, filepath.Join(u.shipped, "tacquito.service")) || envOf(t, u.dropin, "TACQUITO_LEVEL") != "20" {
		t.Fatal("not converted as expected")
	}
}

// "convert: the drop-in is the truth while it exists; values tacctl.yaml
// held for those keys give way".
func TestUnitsConvertDropInIsTheTruth(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49")
	c := u.env.Conf
	if err := c.Set("backends.tacacs.level", "30"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set("password.max_age_days", "45"); err != nil {
		t.Fatal(err)
	}
	if !u.install() {
		t.Fatal(u.out())
	}
	// level was not in the drop-in: it was 20 in effect, and stays 20.
	if envOf(t, u.dropin, "TACQUITO_LEVEL") != "20" || envOf(t, u.dropin, "TACQUITO_ADDRESS") != "10.1.0.1:49" {
		t.Fatal(readFile(t, u.dropin))
	}
	if strings.Contains(readFile(t, u.overrides), "level") {
		t.Fatal(readFile(t, u.overrides))
	}
	if v, _ := c.Get("password.max_age_days", ""); v != "45" {
		t.Fatal(v)
	}
}

func TestUnitsConvertNeedsNoStore(t *testing.T) {
	u := newUnitsEnv(t)
	if err := os.Remove(u.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=10")
	if !u.install() {
		t.Fatal(u.out())
	}
	if envOf(t, u.dropin, "TACQUITO_ADDRESS") != "10.1.0.1:49" || envOf(t, u.dropin, "TACQUITO_LEVEL") != "10" {
		t.Fatal(readFile(t, u.dropin))
	}
	if exists(u.oldDropin) || exists(u.p.StoreFile) {
		t.Fatal("old drop-in kept or store made")
	}
}

// "convert: unquoted and multi-assignment Environment= lines are read as
// systemd reads them".
func TestUnitsConvertReadsEnvironmentAsSystemdDoes(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall()
	writeFile(t, u.oldDropin, "[Service]\n# by hand\nEnvironment=TACQUITO_LEVEL=30\nEnvironment=\"TACQUITO_NETWORK=tcp6\" \"TACQUITO_ADDRESS=[::]:49\"\n")
	if !u.install() {
		t.Fatal(u.out())
	}
	if envOf(t, u.dropin, "TACQUITO_LEVEL") != "30" || envOf(t, u.dropin, "TACQUITO_NETWORK") != "tcp6" ||
		envOf(t, u.dropin, "TACQUITO_ADDRESS") != "[::]:49" {
		t.Fatal(readFile(t, u.dropin))
	}
}

// "convert: literal flags of a unit from before the drop-in are kept".
func TestUnitsConvertKeepsLiteralFlags(t *testing.T) {
	u := newUnitsEnv(t)
	writeFile(t, u.unit, readFile(t, filepath.Join(fixDir, "systemd", "tacquito.service.literal-flags")))
	if !u.install() {
		t.Fatal(u.out())
	}
	mustContain(t, u.out(), "  Migrated custom -network/-address flags of tacquito.service to "+u.overrides)
	mustContain(t, u.out(), "  Migrated the custom -level flag of tacquito.service to "+u.overrides)
	if envOf(t, u.dropin, "TACQUITO_ADDRESS") != "10.1.0.1:49" || envOf(t, u.dropin, "TACQUITO_LEVEL") != "30" {
		t.Fatal(readFile(t, u.dropin))
	}
	if !sameBytes(u.unit, filepath.Join(u.shipped, "tacquito.service")) {
		t.Fatal("unit not replaced")
	}
}

// "convert: the daemon is not touched; only systemd's view of the files is
// reloaded".
func TestUnitsConvertDoesNotTouchTheDaemon(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	u.install()
	var calls []string
	for _, a := range u.run.Argvs() {
		if strings.HasPrefix(a, "systemctl") && !strings.HasPrefix(a, "systemctl show ") {
			calls = append(calls, a)
		}
	}
	if !slices.Equal(calls, []string{"systemctl daemon-reload"}) {
		t.Fatal(u.run.Argvs())
	}
}

// --- already converted, and re-runs ---------------------------------------

func TestUnitsConvertedSecondRunChangesNothing(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	u.install()
	u.b.unitsKeepDiscard()
	before := u.treeState() + state(u.p.Rendered) + listing(t, u.p.TacacsUnitDir, u.p.OverrideDir)
	u.reset()
	if !u.install() {
		t.Fatal(u.out())
	}
	if u.out() != "" {
		t.Fatalf("%q", u.out())
	}
	l := u.b.life
	if l.unitsState != "" || l.unitsKeep != "" || len(l.unitsNotes) != 0 {
		t.Fatal(l)
	}
	if got := u.treeState() + state(u.p.Rendered) + listing(t, u.p.TacacsUnitDir, u.p.OverrideDir); got != before {
		t.Fatalf("changed:\n%s\nwas\n%s", got, before)
	}
	u.noSystemctl(`^systemctl daemon-reload`)
	u.noKeep()
}

func TestUnitsConvertedReloadThatNeverHappened(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	u.b.unitsKeepDiscard()
	sd := u.systemd()
	sd.needReload = true
	u.reset()
	u.install()
	if u.b.life.unitsState != "" || !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.b.life.unitsState, u.run.Argvs())
	}
}

// referenceState is reference_state: what a straight conversion of this
// install ends as, then the install from before again.
func (u *uconv) referenceState() string {
	u.t.Helper()
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	u.install()
	u.b.unitsKeepDiscard()
	ref := u.treeState()
	for _, p := range []string{u.p.TacacsUnitDir, u.overrides, u.p.Rendered, filepath.Join(u.p.BackupDir, "legacy")} {
		if err := os.RemoveAll(p); err != nil {
			u.t.Fatal(err)
		}
	}
	if err := os.MkdirAll(u.p.TacacsUnitDir, 0o755); err != nil {
		u.t.Fatal(err)
	}
	u.env.Conf.Reload()
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	return ref
}

func (u *uconv) assertConverged(ref string) {
	u.t.Helper()
	if !u.install() {
		u.t.Fatal(u.out())
	}
	u.b.unitsKeepDiscard()
	if got := u.treeState(); got != ref {
		u.t.Fatalf("not converged:\n%s\nwant\n%s", got, ref)
	}
	if exists(u.oldDropin) {
		u.t.Fatal("the hand-managed drop-in is still there")
	}
	u.noKeep()
	if d := u.set.CheckDrift(backend.DriftSelection{}); len(d) != 0 {
		u.t.Fatal(d)
	}
}

func TestUnitsInterruptedAfterTheImport(t *testing.T) {
	u := newUnitsEnv(t)
	ref := u.referenceState()
	if !u.b.legacyImport() {
		t.Fatal(u.out())
	}
	mustContain(t, readFile(t, u.overrides), "level: 30")
	// Readers still show the drop-in, which is what is in effect.
	mustLine(t, show(t, u.tenv, ""), "  (override in "+u.oldDropin+")")
	u.assertConverged(ref)
}

func TestUnitsInterruptedUnitFilesInPlace(t *testing.T) {
	u := newUnitsEnv(t)
	ref := u.referenceState()
	u.b.legacyImport()
	writeFile(t, u.unit, readFile(t, filepath.Join(u.shipped, "tacquito.service")))
	writeFile(t, u.tmpl, readFile(t, filepath.Join(u.shipped, "tacquito@.service")))
	u.assertConverged(ref)
}

func TestUnitsInterruptedBothDropIns(t *testing.T) {
	u := newUnitsEnv(t)
	ref := u.referenceState()
	u.b.legacyImport()
	writeFile(t, u.unit, readFile(t, filepath.Join(u.shipped, "tacquito.service")))
	stage := filepath.Join(u.dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if !u.b.unitsStage(stage) {
		t.Fatal(u.out())
	}
	if _, err := u.b.renderer().CommitUnits(stage); err != nil {
		t.Fatal(err)
	}
	if !exists(u.dropin) || !exists(u.oldDropin) {
		t.Fatal("both drop-ins expected")
	}
	u.assertConverged(ref)
}

func TestUnitsInterruptedCopiesLeftBehind(t *testing.T) {
	u := newUnitsEnv(t)
	ref := u.referenceState()
	writeFile(t, filepath.Join(u.p.StateDir, ".units.DEAD01", "keep", "1"), "stale\n")
	u.assertConverged(ref)
}

// --- failures leave the old unit and its files in place ---------------------

func TestUnitsFailureForeignDropInLine(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	appendFile(t, u.oldDropin, "LimitNOFILE=65536\nEnvironment=\"HTTP_PROXY=http://proxy:3128\"\n")
	before := u.treeState()
	if u.install() {
		t.Fatal("converted")
	}
	out := u.out()
	mustContain(t, out, "holds lines tacctl did not write and cannot carry over")
	mustContain(t, out, "line 3: LimitNOFILE=65536")
	mustContain(t, out, `line 4: Environment="HTTP_PROXY=http://proxy:3128"`)
	mustContain(t, out, "Unit update stopped: its settings could not be moved into "+u.overrides+".")
	mustContain(t, out, "the running daemon were left as they are")
	u.assertUntouched(before)
	if len(u.run.Calls()) != 0 {
		t.Fatal(u.run.Argvs())
	}
	// The install keeps working from the old files, and says so.
	u.install()
	if u.b.life.unitsState != unitsStopped {
		t.Fatal(u.b.life.unitsState)
	}
	u.reset()
	_ = u.b.LogLevel(context.Background(), "")
	mustContain(t, u.stdout.String(), "debug (30)")
}

func TestUnitsFailureValueTheSchemaRefuses(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=not-an-address", "TACQUITO_LEVEL=30")
	if err := u.env.Conf.Set("password.max_age_days", "45"); err != nil {
		t.Fatal(err)
	}
	before := u.treeState()
	if u.install() {
		t.Fatal("converted")
	}
	mustContain(t, u.out(), "listeners.tacacs.default: address 'not-an-address'")
	mustContain(t, u.out(), "Unit update stopped")
	u.assertUntouched(before)
	if strings.Contains(readFile(t, u.overrides), "level") {
		t.Fatal(readFile(t, u.overrides))
	}
}

func TestUnitsFailureListenerModelThatCannotBeServed(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall()
	u.writeOverrides("listeners:\n  tacacs:\n    tls: {network: tcp, address: \":300\", tls: {enabled: true}}\n")
	before := u.treeState()
	if u.install() {
		t.Fatal("converted")
	}
	mustContain(t, u.out(), "tls.enabled: true is reserved for a future release")
	mustContain(t, u.out(), "Unit update stopped: the drop-ins could not be rendered")
	u.assertUntouched(before)
}

// "failure: an error after files were replaced puts every one of them
// back": the unit and the template are written, then recording the
// drop-in fails.
func TestUnitsFailureAfterFilesWereReplaced(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49")
	before := u.treeState()
	real := u.b.renderer().CommitUnits
	u.b.life.commitUnits = func(dir string) ([]string, error) {
		w, _ := real(dir)
		return w, errors.New("rendered_record failed")
	}
	if u.install() {
		t.Fatal("converted")
	}
	mustContain(t, u.out(), "Unit update stopped: a drop-in could not be installed.")
	if got := u.treeState(); got != before {
		t.Fatalf("not put back:\n%s\nwas\n%s", got, before)
	}
	if !sameBytes(u.unit, filepath.Join(fixDir, "systemd", "tacquito.service.pre-listeners")) ||
		!exists(u.oldDropin) || exists(u.dropin) || exists(u.tmpl) {
		t.Fatal("files not as they were")
	}
	u.noKeep()
	// systemd is told about the restored files; the daemon is not touched.
	if !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.run.Argvs())
	}
	u.noSystemctl(`^systemctl (restart|start|stop)`)
}

func TestUnitsFailureUnparsableTacctlYAML(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	u.writeOverrides("password: [unterminated\n")
	before := u.treeState()
	if u.install() {
		t.Fatal("converted")
	}
	mustContain(t, u.out(), u.overrides+" is not valid YAML")
	mustContain(t, u.out(), "Unit update stopped")
	u.assertUntouched(before)
	// The same for a settings command.
	u.reset()
	wantCode(t, u.b.LogLevel(context.Background(), "error"), 1)
	mustContain(t, u.out(), "is not valid YAML")
	if u.treeState() != before {
		t.Fatal("changed")
	}
}

func TestUnitsFailureShippedUnitFilesMissing(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	before := u.treeState()
	if u.b.unitsInstall(context.Background(), filepath.Join(u.dir, "no-such-tree")) {
		t.Fatal("installed")
	}
	mustContain(t, u.out(), "Unit update stopped: the unit files are not under "+filepath.Join(u.dir, "no-such-tree")+"/"+Share+".")
	u.assertUntouched(before)
}

// --- upgrade: report, restart, and the way back --------------------------

// unitsAndFinish is upgrade_units_and_finish: no new binary, no config
// change; the units phase, then finish.
func (u *uconv) unitsAndFinish(configChanged bool) error {
	l := &u.b.life
	l.skipBuild, l.currentCommit, l.newCommit = "true", "abc1234", "abc1234"
	l.report = UpgradeReport{}
	u.b.upgradeUnits(context.Background(), u.tree)
	l.configChanged = configChanged
	return u.b.upgradeFinish(context.Background())
}

func (u *uconv) reportLines() string {
	r := u.b.UpgradeReport()
	return strings.Join(append(append([]string{r.Head}, r.FilesNotes...), r.Notes...), "\n")
}

func TestUpgradeUnitsConversionReportedCountedRestartedOnce(t *testing.T) {
	u := newUnitsEnv(t)
	u.run.On([]string{"ss"}, execx.Result{Stdout: []byte("LISTEN 0 128 *:49 *:*\n")})
	u.oldInstall("TACQUITO_LEVEL=30")
	if err := u.unitsAndFinish(false); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	out := u.out()
	for _, s := range []string{
		"Updated: tacquito.service (previous backed up to " + u.unit + ".bak)",
		"Installed: tacquito@.service",
		"Rendered: the listener drop-in of tacquito.service",
		"Restarting tacquito service...",
		"Tacquito is running.",
		"Listening on port 49/tcp",
	} {
		mustContain(t, out, s)
	}
	mustContain(t, u.reportLines(), "Units: tacquito.service and its listener drop-in are current")
	if u.b.UpgradeReport().FilesUpdated != 1 {
		t.Fatal(u.b.UpgradeReport())
	}
	if n := u.countCalls(`^systemctl restart tacquito\.service$`); n != 1 {
		t.Fatal(u.run.Argvs())
	}
	// The reload comes before the restart.
	var order []string
	for _, a := range u.run.Argvs() {
		if regexp.MustCompile(`^systemctl (daemon-reload|restart tacquito\.service)$`).MatchString(a) {
			order = append(order, a)
		}
	}
	if len(order) == 0 || order[0] != "systemctl daemon-reload" {
		t.Fatal(order)
	}
	if exists(u.oldDropin) || !exists(u.dropin) {
		t.Fatal("not converted")
	}
	u.noKeep()
}

func TestUpgradeUnitsAlreadyConvertedIsNotRestarted(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	u.b.unitsKeepDiscard()
	u.reset()
	if err := u.unitsAndFinish(false); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Unchanged: tacquito.service")
	mustNotContain(t, u.out(), "Restarting")
	u.noSystemctl(`^systemctl (restart|daemon-reload)`)
	if r := u.b.UpgradeReport(); r.Head != "Scripts Updated (source unchanged at abc1234)" || len(r.Notes) != 0 {
		t.Fatal(r)
	}
}

// "upgrade: other files updated (README, logrotate, templates) do not
// restart an unchanged unit".
func TestUpgradeOtherFilesDoNotRestart(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	u.b.unitsKeepDiscard()
	u.reset()
	l := &u.b.life
	l.skipBuild, l.currentCommit, l.newCommit = "true", "abc1234", "abc1234"
	u.b.upgradeUnits(context.Background(), u.tree)
	l.report.FilesUpdated += 3
	if err := u.b.upgradeFinish(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, u.out(), "Restarting")
	u.noSystemctl(`^systemctl restart`)
}

func TestUpgradeReRenderedConfigRestartsAnUnchangedUnit(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	u.b.unitsKeepDiscard()
	u.reset()
	if err := u.unitsAndFinish(true); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Restarting tacquito service...")
	if n := u.countCalls(`^systemctl restart tacquito\.service$`); n != 1 {
		t.Fatal(u.run.Argvs())
	}
}

// "upgrade: a unit that will not start gets the old unit, drop-in and
// settings back, and is restarted on them".
func TestUpgradeUnitThatWillNotStartIsRolledBack(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	before := u.treeState()
	// is-active: down after the first restart, up after the second.
	restarts := 0
	u.run.Func(func(c execx.Cmd) bool { return c.Name == "systemctl" }, func(c execx.Cmd) (execx.Result, error) {
		switch c.Args[0] {
		case "restart":
			restarts++
		case "is-active":
			if restarts < 2 {
				return execx.Result{Code: 3}, nil
			}
		}
		return execx.Result{}, nil
	})
	wantCode(t, u.unitsAndFinish(false), 1)
	mustContain(t, u.out(), "Tacquito failed to start after upgrade. The previous unit files and settings were restored.")
	mustContain(t, u.out(), "Rolled back to the previous unit files. Service is running.")
	mustNotContain(t, u.out(), "Rolling back binary")

	if got := u.treeState(); got != before {
		t.Fatalf("not put back:\n%s\nwas\n%s", got, before)
	}
	if !sameBytes(u.unit, filepath.Join(fixDir, "systemd", "tacquito.service.pre-listeners")) ||
		!exists(u.oldDropin) || exists(u.dropin) || exists(u.tmpl) || exists(u.overrides) {
		t.Fatal("files not as they were")
	}
	u.noKeep()
	// restart (new files), reload (old files back), restart.
	var order []string
	for _, a := range u.run.Argvs() {
		if regexp.MustCompile(`^systemctl (daemon-reload|restart tacquito\.service)$`).MatchString(a) {
			order = append(order, a)
		}
	}
	if !slices.Equal(order, []string{"systemctl daemon-reload", "systemctl restart tacquito.service",
		"systemctl daemon-reload", "systemctl restart tacquito.service"}) {
		t.Fatal(order)
	}
	// The readers are back on the hand-managed drop-in.
	s := show(t, u.tenv, "")
	mustLine(t, s, "  Current listener: tcp 10.1.0.1:49")
	mustLine(t, s, "  (override in "+u.oldDropin+")")
}

func TestUpgradeUnitRollbackThatFailsToo(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	before := u.treeState()
	u.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3})
	wantCode(t, u.unitsAndFinish(false), 1)
	mustContain(t, u.out(), "Rollback failed. Check: journalctl -u tacquito")
	if u.treeState() != before {
		t.Fatal("half-converted")
	}
}

func TestUpgradeStoppedConversionDoesNotFailTheUpgrade(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	appendFile(t, u.oldDropin, "LimitNOFILE=65536\n")
	before := u.treeState()
	if err := u.unitsAndFinish(false); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Unit update stopped")
	mustContain(t, u.reportLines(), "Units: NOT updated")
	if !slices.Equal(u.b.UpgradeReport().FilesNotes,
		[]string{"Units: NOT updated — the previous unit files are in place (see 'Unit update stopped' above)"}) {
		t.Fatal(u.b.UpgradeReport())
	}
	// The closing summary of 'tacctl upgrade' keeps the note.
	if n := u.b.UpgradeSummary().Notes; len(n) == 0 || n[0] != "Units: NOT updated — the previous unit files are in place (see 'Unit update stopped' above)" {
		t.Fatalf("summary notes %q", n)
	}
	if u.treeState() != before {
		t.Fatal("changed")
	}
}

// --- a settings command on an install that is not converted ---------------
//
// "not converted: the first settings change converts, keeping the other
// settings" and "...a settings change whose unit does not come up puts the
// drop-in back" are settings_test.go's (TestFirstSettingsChangeConverts,
// TestConversionPutBackWhenTheUnitDoesNotComeUp).

// "not converted: readers show the drop-in; user mutations leave it alone
// and render no second one".
func TestNotConvertedUserMutationLeavesTheDropIn(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	s := show(t, u.tenv, "")
	mustLine(t, s, "  Current listener: tcp 10.1.0.1:49")
	mustLine(t, s, "  (override in "+u.oldDropin+")")
	if got := lines(func() []backend.Listener { l, _ := u.b.Listeners().List(); return l }()); !slices.Equal(got, []string{"default tcp 10.1.0.1:49"}) {
		t.Fatal(got)
	}
	if got := u.b.Artifacts(); !slices.Equal(got, []string{u.p.Config}) {
		t.Fatal(got)
	}
	before := u.treeState()
	u.render(true)
	if _, err := u.set.StoreApply(context.Background(), backend.ApplyOptions{}, func() error { return nil }); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	if u.treeState() != before || exists(u.dropin) {
		t.Fatal("the hand-managed layout changed")
	}
	if w, _ := rendered.Check(u.p.Rendered, u.dropin); w == rendered.OK {
		t.Fatal("a drop-in was recorded")
	}
}

// --- uninstall -------------------------------------------------------------

func TestUninstallTheLayoutFromBeforeTheListenerModel(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_LEVEL=30")
	writeFile(t, u.unit+".bak", readFile(t, u.unit))
	writeFile(t, filepath.Join(u.p.TacacsUnitDir, "sshd.service"), "")
	if err := u.b.uninstallStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !u.called(`^systemctl stop tacquito$`) || !u.called(`^systemctl disable tacquito$`) {
		t.Fatal(u.run.Argvs())
	}
	if err := u.b.uninstallUnits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := findAll(t, u.p.TacacsUnitDir); !slices.Equal(got, []string{filepath.Join(u.p.TacacsUnitDir, "sshd.service")}) {
		t.Fatal(got)
	}
	if !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.run.Argvs())
	}
}

func TestUninstallUnitsInstancesDropInsAndLinks(t *testing.T) {
	u := newUnitsEnv(t)
	ctx := context.Background()
	u.install()
	u.b.unitsKeepDiscard()
	if err := u.b.Listeners().Set(ctx, "mgmt", "tcp", "127.0.0.1:4949"); err != nil {
		t.Fatal(err)
	}
	if err := u.b.Listeners().Set(ctx, "oob", "tcp", "127.0.0.1:4950"); err != nil {
		t.Fatal(err)
	}
	dir := u.p.TacacsUnitDir
	// What 'systemctl enable' would have left, plus an instance tacctl.yaml
	// no longer knows.
	for _, d := range []string{"tacquito.service.wants", "multi-user.target.wants", "tacquito@stale.service.d"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"tacquito.service.wants/tacquito@mgmt.service": u.tmpl,
		"tacquito.service.wants/tacquito@oob.service":  u.tmpl,
		"multi-user.target.wants/tacquito.service":     u.unit,
		"multi-user.target.wants/other.service":        "/x",
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(dir, "tacquito.service.d", "local.conf"), "keep\n")
	writeFile(t, u.unit+".bak", readFile(t, u.unit))

	if got := u.b.instanceUnits(); !slices.Equal(got, []string{"tacquito@mgmt.service", "tacquito@oob.service", "tacquito@stale.service"}) {
		t.Fatal(got)
	}

	u.reset()
	u.run.On([]string{"systemctl", "is-active"}, execx.Result{})
	u.run.On([]string{"systemctl", "is-enabled"}, execx.Result{})
	if err := u.b.uninstallStop(ctx); err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{
		`^systemctl disable --quiet --now tacquito@mgmt\.service$`,
		`^systemctl disable --quiet --now tacquito@oob\.service$`,
		`^systemctl disable --quiet --now tacquito@stale\.service$`,
		`^systemctl stop tacquito$`,
		`^systemctl disable tacquito$`,
	} {
		if !u.called(re) {
			t.Fatal(re, u.run.Argvs())
		}
	}
	if err := u.b.uninstallUnits(ctx); err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, f := range findAll(t, dir) {
		if filepath.Base(f) != "multi-user.target.wants" {
			left = append(left, f)
		}
	}
	if !slices.Equal(left, []string{filepath.Join(dir, "multi-user.target.wants", "other.service")}) {
		t.Fatal(left)
	}
	if !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.run.Argvs())
	}
}

func TestUninstallNothingInstalledIsNotAnError(t *testing.T) {
	u := newUnitsEnv(t)
	u.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3})
	u.run.On([]string{"systemctl", "is-enabled"}, execx.Result{Code: 3})
	if err := u.b.uninstallStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.noSystemctl(`^systemctl (stop|disable)`)
	if err := u.b.uninstallUnits(context.Background()); err != nil {
		t.Fatal(err)
	}
}
