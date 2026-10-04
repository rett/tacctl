package radius_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/radius"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/rendered"
)

// Ports of the lifecycle tests of tests/integration/radius.bats: the
// install phases (what 'backend enable radius' runs around its render), the
// upgrade phases (the 'upgrade_radius' helper: config, files, finish and
// the summary), and the uninstall phases. 'backend enable|disable' itself
// is internal/cli's (backend_enable_test.go) and the CLI half of radius.bats
// runs against the binary (tests/blackbox.list).

// noPackage removes the daemon binary: the package is not installed.
func (r *renv) noPackage() {
	r.t.Helper()
	if err := os.Remove(r.m.L.Bin); err != nil {
		r.t.Fatal(err)
	}
}

// packageManagers scripts apt-get (through env, as the module runs it) and
// dnf: an install puts the "package" in place, and on Debian the package's
// unit starts at once (enabled and running).
func (r *renv) packageManagers() {
	r.run.OnFunc([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"}, func(execx.Cmd) (execx.Result, error) {
		r.packagePresent()
		r.setActive("freeradius", true)
		r.setEnabled("freeradius", true)
		return execx.Result{}, nil
	})
	r.run.OnFunc([]string{"dnf", "install"}, func(execx.Cmd) (execx.Result, error) {
		r.packagePresent()
		return execx.Result{}, nil
	})
}

// install runs install phases in order, stopping at the first failure.
func (r *renv) install(phases ...backend.Phase) error {
	for _, p := range phases {
		if err := r.m.Install(context.Background(), p, "/nonexistent"); err != nil {
			return err
		}
	}
	return nil
}

// enableRadius is what 'backend enable radius' does for a fresh install,
// with the generic half done by hand: build, files, account, the render with
// radius enabled, start.
func (r *renv) enableRadius() error {
	r.t.Helper()
	if err := r.install(backend.PhaseBuild, backend.PhaseFiles, backend.PhaseAccount); err != nil {
		return err
	}
	return r.renderAndStart()
}

// renderAndStart is the rest of enable: the render with radius enabled
// (StoreApply's, which defers radius's restart to the start phase), then
// start.
func (r *renv) renderAndStart() error {
	r.t.Helper()
	r.renderEnabled()
	return r.install(backend.PhaseStart)
}

// renderEnabled renders both backends with radius enabled, restarting
// nothing (enable's StoreApply defers the new backend's restart).
func (r *renv) renderEnabled() {
	r.t.Helper()
	r.enableList("tacacs, radius")
	if _, err := r.set.RenderAll(context.Background(), backend.RenderOptions{}); err != nil {
		r.t.Fatalf("render: %v\n%s", err, r.out())
	}
}

// "enable (Debian layout): installs the packages, stops the package's own
// unit, renders, installs the drop-in, starts".
func TestInstallPhasesDebian(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.tac.Render = tacRender
	r.noPackage()
	r.packageManagers()
	if err := r.enableRadius(); err != nil {
		t.Fatalf("enable: %v\n%s", err, r.out())
	}
	l := r.m.L
	out := r.out()
	contains(t, out, "[INFO] Installing FreeRADIUS (freeradius freeradius-utils)...")
	contains(t, out, "[INFO] FreeRADIUS installed; the package's own configuration in "+l.Dir+" is left as shipped and is not served.")
	contains(t, out, "[INFO] Starting freeradius...")
	contains(t, out, "[INFO] FreeRADIUS is running (freeradius.service, PAP only).")
	contains(t, out, "[INFO] Listening on port 1812/udp (auth)")
	contains(t, out, "[INFO] Listening on port 1813/udp (acct)")
	if !r.called(`^env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq freeradius freeradius-utils$`) {
		t.Errorf("no apt-get install: %v", r.calls())
	}
	if r.called(`^apt-get update`) {
		t.Error("apt-get update ran although the install worked")
	}
	// The unit the package started is stopped before anything of tacctl's
	// exists; then the drop-in, enable and start, in that order.
	var seq []string
	for _, c := range r.calls() {
		switch c {
		case "systemctl disable --quiet --now freeradius.service", "systemctl daemon-reload",
			"systemctl enable --quiet freeradius.service", "systemctl start freeradius.service":
			seq = append(seq, c)
		}
	}
	want := []string{"systemctl disable --quiet --now freeradius.service", "systemctl daemon-reload",
		"systemctl enable --quiet freeradius.service", "systemctl start freeradius.service"}
	if !slices.Equal(seq, want) {
		t.Errorf("sequence %q", seq)
	}
	if !r.isActive("freeradius") || !r.isEnabled("freeradius") {
		t.Error("the unit is not enabled and running")
	}
	if !r.hasLine(l.DropIn, "ExecStart="+l.Bin+" -f -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius") {
		t.Errorf("drop-in:\n%s", r.read(l.DropIn))
	}
	// The logrotate file names the three logs and the service account.
	if got := r.read(l.Logrotate); got != r.m.LogrotateText() || !strings.Contains(got, l.LogDir+"/tacctl-auth.log") ||
		!strings.Contains(got, "\tsu freerad freerad\n") {
		t.Errorf("logrotate:\n%s", got)
	}
	if r.mode(l.Logrotate) != 0o644 {
		t.Errorf("logrotate mode %o", r.mode(l.Logrotate))
	}
	if !slices.Contains(r.sleeps, 2*time.Second) {
		t.Errorf("no settle wait after the start: %v", r.sleeps)
	}
	r.noLeftovers()
}

// "enable (RHEL layout): dnf, radiusd.service, the radiusd account, a
// forking ExecStart".
func TestInstallPhasesRHEL(t *testing.T) {
	r := newEnv(t, rhel)
	r.useStore("store.radius.yaml")
	r.noPackage()
	r.packageManagers()
	if err := r.enableRadius(); err != nil {
		t.Fatalf("enable: %v\n%s", err, r.out())
	}
	l := r.m.L
	for _, want := range []string{`^dnf install -y -q freeradius freeradius-utils$`, `^systemctl enable --quiet radiusd.service$`,
		`^systemctl start radiusd.service$`, `^id radiusd$`} {
		if !r.called(want) {
			t.Errorf("no %s in %v", want, r.calls())
		}
	}
	if r.called(`apt-get`) {
		t.Error("apt-get on RHEL")
	}
	if !r.hasLine(l.DropIn, "ExecStart="+l.Bin+" -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius") ||
		!r.hasLine(l.DropIn, "ExecStartPre=-/bin/chown -R radiusd:radiusd /var/run/radiusd") {
		t.Errorf("drop-in:\n%s", r.read(l.DropIn))
	}
	contains(t, r.read(l.Logrotate), "\tsu radiusd radiusd\n")
}

// A stale package index: the first install fails, 'apt-get update' and one
// more try.
func TestInstallBuildRetriesAfterAptUpdate(t *testing.T) {
	r := newEnv(t)
	r.noPackage()
	r.run.On([]string{"apt-get", "update"}, execx.Result{})
	n := 0
	r.run.OnFunc([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"}, func(execx.Cmd) (execx.Result, error) {
		n++
		if n == 1 {
			return execx.Result{Code: 100, Stderr: []byte("E: Unable to locate package freeradius\n")}, nil
		}
		r.packagePresent()
		return execx.Result{}, nil
	})
	if err := r.install(backend.PhaseBuild); err != nil {
		t.Fatalf("build: %v\n%s", err, r.out())
	}
	if !r.called(`^apt-get update -qq$`) || r.run.Count("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install") != 2 {
		t.Errorf("calls %v", r.calls())
	}
	// apt's complaint reaches the operator; its output does not.
	contains(t, r.stderr.String(), "E: Unable to locate package freeradius")
}

// A package manager that cannot install it (or installs something without
// the daemon) stops the install.
func TestInstallBuildPackageFailure(t *testing.T) {
	r := newEnv(t)
	r.noPackage()
	r.run.On([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"}, execx.Result{Code: 100})
	err := r.install(backend.PhaseBuild)
	wantCode(t, err, 1)
	contains(t, r.out(), "[ERROR] Could not install freeradius freeradius-utils. Install them and run this again.")
	if r.called(`^systemctl`) {
		t.Error("systemctl ran after a failed install")
	}
	// apt "succeeds" but no daemon appears.
	r = newEnv(t)
	r.noPackage()
	wantCode(t, r.install(backend.PhaseBuild), 1)
	contains(t, r.out(), "Could not install freeradius freeradius-utils.")
	// No package manager at all.
	r = newEnv(t, rhel)
	r.noPackage()
	r.run.Missing("apt-get", "dnf", "yum")
	wantCode(t, r.install(backend.PhaseBuild), 1)
	contains(t, r.out(), "Could not install freeradius freeradius-utils.")
	if len(r.calls()) != 0 {
		t.Errorf("ran %v", r.calls())
	}
	// yum when there is no dnf.
	r = newEnv(t, rhel)
	r.noPackage()
	r.run.Missing("dnf")
	r.run.OnFunc([]string{"yum", "install"}, func(execx.Cmd) (execx.Result, error) {
		r.packagePresent()
		return execx.Result{}, nil
	})
	if err := r.install(backend.PhaseBuild); err != nil {
		t.Fatalf("yum: %v\n%s", err, r.out())
	}
	if !r.called(`^yum install -y -q freeradius freeradius-utils$`) {
		t.Errorf("calls %v", r.calls())
	}
}

// Neither family recognised: no install.
func TestInstallBuildUnknownFamily(t *testing.T) {
	r := newEnv(t)
	m := radius.NewModule(r.env, "")
	err := m.Install(context.Background(), backend.PhaseBuild, "/tree")
	wantCode(t, err, 1)
	contains(t, r.out(), "[ERROR] Neither a Debian/Ubuntu nor a RHEL-family system: tacctl does not know where FreeRADIUS lives here.")
	if len(r.calls()) != 0 {
		t.Errorf("ran %v", r.calls())
	}
}

// "enable: a FreeRADIUS that is already running is somebody's, and is
// neither taken nor stopped"; "so is one that is only enabled at boot; once
// handed over, enable goes through without the package manager".
func TestInstallBuildRefusesSomebodysServer(t *testing.T) {
	r := newEnv(t)
	r.setActive("freeradius", true)
	before := r.state()
	wantCode(t, r.install(backend.PhaseBuild), 1)
	contains(t, r.out(), "freeradius.service is running: somebody's RADIUS server")
	contains(t, r.out(), "systemctl disable --now freeradius.service")
	if r.state() != before || !r.isActive("freeradius") {
		t.Error("something was changed")
	}
	if r.called(`^systemctl (stop|disable|restart|start)`) || r.called(`apt-get`) {
		t.Errorf("calls %v", r.calls())
	}
	if r.exists(filepath.Dir(r.m.L.DropIn)) {
		t.Error("drop-in directory created")
	}

	r = newEnv(t)
	r.setEnabled("freeradius", true)
	wantCode(t, r.install(backend.PhaseBuild), 1)
	contains(t, r.out(), "freeradius.service is enabled at boot")
	r.setEnabled("freeradius", false)
	r.reset()
	if err := r.install(backend.PhaseBuild); err != nil {
		t.Fatalf("build: %v\n%s", err, r.out())
	}
	contains(t, r.out(), "[INFO] FreeRADIUS is already installed ("+r.m.L.Bin+"); freeradius.service is neither running nor enabled.")
	if r.called(`apt-get`) {
		t.Error("the package manager ran")
	}
}

// 'install account': the package's account, directories and dictionary.
func TestInstallAccountChecks(t *testing.T) {
	r := newEnv(t)
	if err := r.install(backend.PhaseAccount); err != nil {
		t.Fatalf("account: %v\n%s", err, r.out())
	}
	if !r.called(`^id freerad$`) {
		t.Errorf("calls %v", r.calls())
	}

	r = newEnv(t)
	r.run.Fail([]string{"id"}, 1, "id: 'freerad': no such user")
	wantCode(t, r.install(backend.PhaseAccount), 1)
	contains(t, r.out(), "[ERROR] The FreeRADIUS service account 'freerad' does not exist; the package did not install as expected.")

	r = newEnv(t)
	if err := os.RemoveAll(r.m.L.LogDir); err != nil {
		t.Fatal(err)
	}
	wantCode(t, r.install(backend.PhaseAccount), 1)
	contains(t, r.out(), "[ERROR] "+r.m.L.Dir+" or "+r.m.L.LogDir+" is missing; the package did not install as expected.")

	r = newEnv(t)
	if err := os.Remove(r.m.L.SystemDict); err != nil {
		t.Fatal(err)
	}
	wantCode(t, r.install(backend.PhaseAccount), 1)
	contains(t, r.out(), "[ERROR] FreeRADIUS's main dictionary is not at "+r.m.L.SystemDict+"; the package did not install as expected.")
}

// 'install files' writes the logrotate file, or warns when it cannot; a
// machine without logrotate's directory gets none.
func TestInstallFiles(t *testing.T) {
	r := newEnv(t)
	if err := r.install(backend.PhaseFiles); err != nil {
		t.Fatal(err)
	}
	if r.read(r.m.L.Logrotate) != r.m.LogrotateText() {
		t.Error("logrotate file")
	}
	// A directory where the file should be: it cannot be written.
	r = newEnv(t)
	if err := os.Mkdir(r.m.L.Logrotate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.install(backend.PhaseFiles); err != nil {
		t.Fatal(err)
	}
	contains(t, r.out(), "[WARN] Could not write "+r.m.L.Logrotate+".")
}

// 'install start' without the render, and a unit that does not come up.
func TestInstallStartFailures(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	wantCode(t, r.install(backend.PhaseStart), 1)
	contains(t, r.out(), "[ERROR] "+r.m.L.Conf+" was not rendered.")
	if len(r.calls()) != 0 {
		t.Errorf("ran %v", r.calls())
	}

	// "enable: a daemon that does not come up": the start phase says so.
	r = newEnv(t)
	r.useStore("store.radius.yaml")
	r.renderEnabled()
	r.setFailStart(true)
	r.reset()
	wantCode(t, r.install(backend.PhaseStart), 1)
	contains(t, r.out(), "[ERROR] FreeRADIUS failed to start. Check: journalctl -u freeradius and "+r.m.L.DaemonLog)
	notContains(t, r.out(), "is running")

	// A listener nobody answers on is warned about, not a failure.
	r = newEnv(t)
	r.useStore("store.radius.yaml")
	r.renderEnabled()
	r.run.On([]string{"ss"}, execx.Result{})
	r.reset()
	if err := r.install(backend.PhaseStart); err != nil {
		t.Fatalf("start: %v\n%s", err, r.out())
	}
	contains(t, r.out(), "[WARN] Port 1812/udp (auth) not detected — check "+r.m.L.DaemonLog+".")
	// The warnings of the rendered state follow ("enable: the warnings of
	// the rendered state are shown").
	contains(t, r.out(), "RADIUS does not enforce the command rules (commands.<group>) of: operator.")
	contains(t, r.out(), "Over RADIUS no vendor attribute is sent to the devices of scope(s) lab, prod, prod-inner, wifi")
}

// --- upgrade ---------------------------------------------------------------------

// upgrade is the upgrade_radius helper: the three phases, then the notes
// for the closing summary.
func (r *renv) upgrade() []string {
	r.t.Helper()
	for _, p := range []backend.Phase{backend.PhaseConfig, backend.PhaseFiles, backend.PhaseFinish} {
		if err := r.m.Upgrade(context.Background(), p, "/nonexistent"); err != nil {
			r.t.Fatalf("upgrade %s: %v", p, err)
		}
	}
	return r.m.UpgradeNotes()
}

// "upgrade: an install from the release before the dictionary is
// re-rendered, not taken for drift; the drop-in gains -D, then one restart".
func TestUpgradeFromBeforeTheDictionary(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.preVendorState()
	l := r.m.L
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift before the upgrade: %v", lines)
	}
	notes := r.upgrade()
	out := r.out()
	contains(t, out, "[INFO] RADIUS: re-rendered "+l.Conf+", "+l.Users+", "+l.Dict+".")
	contains(t, out, "[WARN] RADIUS: no scope enables a vendor attribute, so an Access-Accept carries Service-Type only.")
	contains(t, out, "[WARN] Enable what each scope's devices need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti (or tag addresses: tacctl scope devices).")
	contains(t, out, "[INFO] RADIUS: updated "+l.DropIn+".")
	contains(t, out, "[INFO] Restarting freeradius...\n")
	contains(t, out, "[INFO] FreeRADIUS is running.\n")
	if !slices.Equal(notes, []string{"RADIUS: config re-rendered for this release, FreeRADIUS restarted"}) {
		t.Errorf("notes %q", notes)
	}
	if !r.exists(l.Dict) {
		t.Error("no dictionary")
	}
	if w, _ := rendered.Check(r.p.Rendered, l.Dict); w != rendered.OK {
		t.Errorf("dictionary %s", w)
	}
	if !r.hasLine(l.DropIn, "ExecStart="+l.Bin+" -f -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius") {
		t.Errorf("drop-in:\n%s", r.read(l.DropIn))
	}
	if strings.Contains(r.read(l.Users), "Cisco-AVPair = ") {
		t.Error("vendor attributes for everyone")
	}
	// Artifacts, then the drop-in (daemon-reload), then exactly one restart.
	var seq []string
	for _, c := range r.calls() {
		if c == "systemctl daemon-reload" || c == "systemctl restart freeradius.service" {
			seq = append(seq, c)
		}
	}
	if !slices.Equal(seq, []string{"systemctl daemon-reload", "systemctl restart freeradius.service"}) {
		t.Errorf("sequence %v", seq)
	}
	if !slices.Contains(r.sleeps, 2*time.Second) {
		t.Errorf("no wait after the restart: %v", r.sleeps)
	}
	if lines := r.set.DriftLines(backend.DriftAll); len(lines) != 0 {
		t.Errorf("drift after the upgrade: %v", lines)
	}
	r.noLeftovers()
}

// "upgrade: nothing to do when the artifacts and the drop-in are current (no
// restart, no summary line)". The logrotate file is rewritten as this
// release writes it.
func TestUpgradeNothingToDo(t *testing.T) {
	r := newEnv(t)
	r.up()
	if err := os.WriteFile(r.m.L.Logrotate, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := r.upgrade()
	notContains(t, r.out(), "re-rendered")
	if len(notes) != 0 {
		t.Errorf("notes %q", notes)
	}
	if r.restarts("freeradius.service") != 0 {
		t.Error("restarted")
	}
	if r.read(r.m.L.Logrotate) != r.m.LogrotateText() {
		t.Error("logrotate file not refreshed")
	}
}

// "upgrade: a hand-edited artifact is not replaced, and neither the drop-in
// nor the daemon is touched".
func TestUpgradeHandEditedArtifact(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.preVendorState()
	appendTo(t, r.m.L.Users, "# hand edit\n")
	before := r.state() + r.read(r.m.L.DropIn)
	notes := r.upgrade()
	contains(t, r.out(), "was edited since tacctl rendered it")
	contains(t, r.out(), "[WARN] The RADIUS files were not re-rendered; FreeRADIUS keeps serving the previous ones. Run 'tacctl config render' once the problem above is fixed.")
	if !slices.Equal(notes, []string{"RADIUS: NOT brought in line with this release (see above); 'tacctl config validate' says what stands"}) {
		t.Errorf("notes %q", notes)
	}
	if r.state()+r.read(r.m.L.DropIn) != before {
		t.Error("something changed")
	}
	if r.called(`^systemctl (restart|daemon-reload)`) {
		t.Errorf("calls %v", r.calls())
	}
	r.noLeftovers()
}

// "upgrade: a disabled backend (no drop-in) is left alone".
func TestUpgradeDisabledBackendLeftAlone(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	r.enableList("tacacs")
	if _, err := r.m.Service(ctx, backend.ServiceStop, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.m.Service(ctx, backend.ServiceDisable, ""); err != nil {
		t.Fatal(err)
	}
	// Its files are those of the release before (so there would be
	// something to re-render), but it has no drop-in.
	if err := os.MkdirAll(filepath.Dir(r.m.L.DropIn), 0o755); err != nil {
		t.Fatal(err)
	}
	r.preVendorState()
	if err := os.RemoveAll(filepath.Dir(r.m.L.DropIn)); err != nil {
		t.Fatal(err)
	}
	r.reset()
	before := r.state()
	if notes := r.upgrade(); len(notes) != 0 {
		t.Errorf("notes %q", notes)
	}
	if r.state() != before || r.exists(filepath.Dir(r.m.L.DropIn)) {
		t.Error("something changed")
	}
	if r.called(`^systemctl`) {
		t.Errorf("calls %v", r.calls())
	}
	// Without a store there is nothing to render either.
	r = newEnv(t)
	r.up()
	if err := os.Remove(r.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	if notes := r.upgrade(); len(notes) != 0 || len(r.calls()) != 0 {
		t.Errorf("notes %q, calls %v", notes, r.calls())
	}
}

// A unit that does not come back after the re-render is said, and the
// summary says the backend is not in line; the upgrade goes on.
func TestUpgradeRestartFails(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.preVendorState()
	r.setFailStart(true)
	notes := r.upgrade()
	contains(t, r.out(), "[ERROR] FreeRADIUS did not start after the re-render. Check: journalctl -u freeradius and "+r.m.L.DaemonLog)
	if !slices.Equal(notes, []string{"RADIUS: NOT brought in line with this release (see above); 'tacctl config validate' says what stands"}) {
		t.Errorf("notes %q", notes)
	}
}

// Only the drop-in is behind (the artifacts are current): it is brought in
// line and the unit restarted, without the vendor warning.
func TestUpgradeDropinOnly(t *testing.T) {
	r := newEnv(t)
	r.up()
	l := r.m.L
	writeFile(t, l.DropIn, "# an older drop-in\n[Service]\n")
	r.reset()
	notes := r.upgrade()
	out := r.out()
	notContains(t, out, "re-rendered")
	notContains(t, out, "no scope enables a vendor attribute")
	contains(t, out, "[INFO] RADIUS: updated "+l.DropIn+".")
	if r.read(l.DropIn) != r.m.DropinText()+"\n" && r.read(l.DropIn) != r.m.DropinText() {
		t.Errorf("drop-in:\n%s", r.read(l.DropIn))
	}
	if r.restarts("freeradius.service") != 1 || len(notes) != 1 {
		t.Errorf("restarts %d, notes %q", r.restarts("freeradius.service"), notes)
	}
}

// --- uninstall -------------------------------------------------------------------

// plantLogs is plant_logs: tacctl's three logs and a rotated one.
func (r *renv) plantLogs() {
	r.t.Helper()
	for _, f := range []string{r.m.L.AuthLog, r.m.L.AcctLog, r.m.L.DaemonLog, r.m.L.AuthLog + ".1"} {
		writeFile(r.t, f, "log line\n")
	}
}

// "uninstall: the unit is stopped and handed back, tacctl's files and logs
// are removed, the package stays".
func TestUninstallPhases(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.plantLogs()
	l := r.m.L
	writeFile(t, filepath.Join(l.Dir, "radiusd.conf"), "kept\n")
	writeFile(t, filepath.Join(l.LogDir, "radius.log"), "kept\n")
	ctx := context.Background()
	if err := r.m.Uninstall(ctx, backend.PhaseStop, false); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !r.called(`^systemctl stop freeradius.service$`) {
		t.Errorf("calls %v", r.calls())
	}
	contains(t, r.out(), "[INFO] Stopping freeradius...")
	if r.isActive("freeradius") || r.isEnabled("freeradius") || r.exists(filepath.Dir(l.DropIn)) {
		t.Error("the unit is not handed back")
	}
	for _, p := range []backend.Phase{backend.PhaseProgram, backend.PhaseData, backend.PhaseAccount} {
		if err := r.m.Uninstall(ctx, p, false); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	out := r.out()
	contains(t, out, "[INFO] Removing tacctl's RADIUS logs from "+l.LogDir+"...")
	contains(t, out, "[INFO] FreeRADIUS itself (freeradius freeradius-utils) is left installed, with the package's configuration in "+l.Dir+" as shipped.")
	for _, f := range []string{l.Conf, l.Users, l.DictDir, l.Logrotate} {
		if r.exists(f) {
			t.Errorf("%s left", f)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(l.LogDir, "tacctl-*")); len(m) != 0 {
		t.Errorf("logs left: %v", m)
	}
	if !r.exists(l.Bin) || r.read(filepath.Join(l.Dir, "radiusd.conf")) != "kept\n" || r.read(filepath.Join(l.LogDir, "radius.log")) != "kept\n" {
		t.Error("the package's files were touched")
	}
	if r.called(`^tar`) || len(r.m.UninstallSaved()) != 0 {
		t.Error("logs archived without --keep-logs")
	}
}

// --keep-logs archives tacctl's logs (only those) under /root before they
// go, and says where for the closing list.
func TestUninstallDataKeepLogs(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.plantLogs()
	l := r.m.L
	if err := r.m.Uninstall(context.Background(), backend.PhaseData, true); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(r.w, "root", "tacctl-radius-logs-20261002_120000.tar.gz")
	want := "tar czf " + archive + " -C " + l.LogDir + " tacctl-accounting.log tacctl-auth.log tacctl-auth.log.1 tacctl-radius.log"
	if !slices.Contains(r.calls(), want) {
		t.Errorf("calls %v", r.calls())
	}
	contains(t, r.out(), "[INFO] RADIUS logs saved to "+archive+"\n")
	if got := r.m.UninstallSaved(); !slices.Equal(got, []string{"RADIUS logs saved to: " + archive}) {
		t.Errorf("saved %q", got)
	}
	// The order: saved, then removed, then the package line.
	out := r.out()
	if i, j := strings.Index(out, "logs saved to"), strings.Index(out, "Removing tacctl's RADIUS logs"); i < 0 || j < i {
		t.Errorf("order:\n%s", out)
	}
}

// "uninstall: a disabled RADIUS backend is still found (its rendered files
// hold secrets) and somebody else's running unit is not stopped".
func TestUninstallDisabledBackendSomebodysUnit(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	r.enableList("tacacs")
	_, _ = r.m.Service(ctx, backend.ServiceStop, "")
	_, _ = r.m.Service(ctx, backend.ServiceDisable, "")
	if !r.m.Installed() {
		t.Fatal("a disabled backend with rendered files is not installed")
	}
	if got := r.set.Present(); !slices.Equal(got, []string{"tacacs", "radius"}) {
		t.Errorf("present %v", got)
	}
	r.setActive("freeradius", true)
	r.reset()
	if err := r.m.Uninstall(ctx, backend.PhaseStop, false); err != nil {
		t.Fatal(err)
	}
	if !r.isActive("freeradius") || r.called(`^systemctl (stop|disable)`) {
		t.Errorf("somebody's unit was touched: %v", r.calls())
	}
	if err := r.m.Uninstall(ctx, backend.PhaseData, false); err != nil {
		t.Fatal(err)
	}
	if r.exists(r.m.L.Conf) || r.exists(r.m.L.Users) {
		t.Error("rendered files left")
	}
}

// "uninstall: a machine that merely has the FreeRADIUS package is not
// touched": it is not selected, and its data phase says nothing.
func TestUninstallPackageOnly(t *testing.T) {
	r := newEnv(t)
	if r.m.Installed() {
		t.Fatal("the package alone counts as tacctl's install")
	}
	if got := r.set.Present(); !slices.Equal(got, []string{"tacacs"}) {
		t.Errorf("present %v", got)
	}
	writeFile(t, filepath.Join(r.m.L.LogDir, "radius.log"), "kept\n")
	if err := r.m.Uninstall(context.Background(), backend.PhaseData, true); err != nil {
		t.Fatal(err)
	}
	if r.out() != "" || len(r.calls()) != 0 {
		t.Errorf("said %q, ran %v", r.out(), r.calls())
	}
}

// The phases radius has no work in, and the ones no module knows, are
// no-ops (the contract).
func TestLifecyclePhasesWithoutWork(t *testing.T) {
	r := newEnv(t)
	ctx := context.Background()
	if r.m.Install(ctx, "nope", "/tree") != nil || r.m.Upgrade(ctx, "nope", "/tree") != nil || r.m.Uninstall(ctx, "nope", false) != nil {
		t.Error("an unknown phase is not a no-op")
	}
	if r.m.Upgrade(ctx, backend.PhasePreflight, "/tree") != nil || r.m.Upgrade(ctx, backend.PhaseBuild, "/tree") != nil ||
		r.m.Uninstall(ctx, backend.PhaseProgram, false) != nil || r.m.Uninstall(ctx, backend.PhaseAccount, false) != nil {
		t.Error("a phase without work failed")
	}
	if len(r.calls()) != 0 || r.out() != "" {
		t.Errorf("ran %v, said %q", r.calls(), r.out())
	}
}
