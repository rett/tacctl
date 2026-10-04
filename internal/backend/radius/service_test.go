package radius_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
)

// Tests of the unit, its drop-in and the service verbs: the parts of
// 'backend enable|disable' and of the install and uninstall phases that are
// the module's contract verbs rather than the lifecycle's.

// "enable (Debian layout)": the drop-in runs the daemon in the foreground
// under the package's unit, names tacctl's instance and dictionary; then
// daemon-reload, enable and start, in that order.
func TestServiceEnableDebianDropIn(t *testing.T) {
	r := newEnv(t)
	r.packagePresent()
	l := r.m.L
	ctx := context.Background()
	if _, err := r.m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatalf("enable: %v\n%s", err, r.stderr)
	}
	if _, err := r.m.Service(ctx, backend.ServiceStart, ""); err != nil {
		t.Fatalf("start: %v", err)
	}
	drop := r.read(l.DropIn)
	contains(t, drop, "\nExecStart="+l.Bin+" -f -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius\n")
	contains(t, drop, "\nExecStartPre="+l.Bin+" -C -lstdout -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius\n")
	contains(t, drop, "\nExecReload=/bin/kill -HUP $MAINPID\n")
	if got := r.mode(l.DropIn); got != 0o644 {
		t.Errorf("drop-in is %o", got)
	}
	want := []string{"systemctl daemon-reload", "systemctl enable --quiet freeradius.service", "systemctl reset-failed freeradius.service", "systemctl start freeradius.service"}
	var got []string
	for _, c := range r.calls() {
		if strings.HasPrefix(c, "systemctl is-") {
			continue
		}
		got = append(got, c)
	}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Errorf("calls %v, want %v", got, want)
	}
	if !r.isActive("freeradius") || !r.isEnabled("freeradius") {
		t.Error("the unit is not enabled and running")
	}
}

// "enable (RHEL layout)": radiusd.service, the radiusd account, a forking
// ExecStart.
func TestServiceEnableRHELDropIn(t *testing.T) {
	r := newEnv(t, rhel)
	l := r.m.L
	ctx := context.Background()
	if _, err := r.m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(l.DropIn, "radiusd.service.d/tacctl.conf") {
		t.Errorf("drop-in at %s", l.DropIn)
	}
	drop := r.read(l.DropIn)
	contains(t, drop, "\nExecStart="+l.Bin+" -d "+l.Dir+" -D "+l.DictDir+" -n tacctl-radius\n")
	contains(t, drop, "\nExecStartPre=-/bin/chown -R radiusd:radiusd /var/run/radiusd\n")
	if !r.called(`^systemctl enable --quiet radiusd.service$`) {
		t.Errorf("calls %v", r.calls())
	}
}

// The drop-in is written once: installing what is already there writes
// nothing and reloads nothing; a drop-in of an older release is replaced.
func TestDropinInstallIsIdempotent(t *testing.T) {
	r := newEnv(t)
	ctx := context.Background()
	changed, err := r.m.DropinInstall(ctx)
	if err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	if r.run.Count("systemctl", "daemon-reload") != 1 {
		t.Errorf("calls %v", r.calls())
	}
	changed, err = r.m.DropinInstall(ctx)
	if err != nil || changed || r.run.Count("systemctl", "daemon-reload") != 1 {
		t.Errorf("second: %v %v %v", changed, err, r.calls())
	}
	if err := os.WriteFile(r.m.L.DropIn, []byte("# older\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err = r.m.DropinInstall(ctx); err != nil || !changed {
		t.Errorf("third: %v %v", changed, err)
	}
	if strings.Contains(r.read(r.m.L.DropIn), "# older") {
		t.Error("the old drop-in stayed")
	}
	if r.exists(r.m.L.DropIn + ".tacctl-new") {
		t.Error("left a .tacctl-new")
	}
	// A failing daemon-reload: the file is written, the install reports it.
	r.run.On([]string{"systemctl", "daemon-reload"}, failedResult())
	_ = os.Remove(r.m.L.DropIn)
	changed, err = r.m.DropinInstall(ctx)
	if !changed || err == nil {
		t.Errorf("failing reload: %v %v", changed, err)
	}
}

// "enable: a FreeRADIUS that is already running is somebody's, and is
// neither taken nor stopped" (the module's half).
func TestServiceEnableRefusesRunningUnit(t *testing.T) {
	r := newEnv(t)
	r.setActive("freeradius", true)
	before := r.state()
	_, err := r.m.Service(context.Background(), backend.ServiceEnable, "")
	wantCode(t, err, 1)
	out := r.out()
	contains(t, out, "FreeRADIUS is already installed on this machine and freeradius.service is running: somebody's RADIUS server.")
	contains(t, out, "tacctl runs its own configuration under that unit (the files in "+r.m.L.Dir+" stay as they are, but are no longer served).")
	contains(t, out, "systemctl disable --now freeradius.service")
	if r.state() != before {
		t.Error("state changed")
	}
	if !r.isActive("freeradius") {
		t.Error("the unit was stopped")
	}
	if r.called(`^systemctl (stop|disable|restart|start) .*freeradius`) {
		t.Errorf("calls %v", r.calls())
	}
	if r.exists(filepath.Dir(r.m.L.DropIn)) {
		t.Error("a drop-in directory was made")
	}
	// Errors go to stderr.
	if r.stdout.Len() != 0 {
		t.Errorf("stdout: %q", r.stdout)
	}
	r.noLeftovers()
}

// "enable: so is one that is only enabled at boot; once handed over, enable
// goes through".
func TestServiceEnableRefusesEnabledUnitThenGoesThrough(t *testing.T) {
	r := newEnv(t)
	r.setEnabled("freeradius", true)
	_, err := r.m.Service(context.Background(), backend.ServiceEnable, "")
	wantCode(t, err, 1)
	contains(t, r.out(), "freeradius.service is enabled at boot")
	r.setEnabled("freeradius", false)
	r.reset()
	if _, err := r.m.Service(context.Background(), backend.ServiceEnable, ""); err != nil {
		t.Fatalf("after the hand-over: %v\n%s", err, r.stderr)
	}
	if !r.exists(r.m.L.DropIn) {
		t.Error("no drop-in")
	}
}

// "re-enable: refused while somebody runs the package's configuration under
// the unit, which is left running": with tacctl's drop-in gone and the unit
// active again.
func TestServiceReenableRefusedWhileSomebodyRunsTheUnit(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	for _, a := range []backend.ServiceAction{backend.ServiceStop, backend.ServiceDisable} {
		if _, err := r.m.Service(ctx, a, ""); err != nil {
			t.Fatal(err)
		}
	}
	r.setActive("freeradius", true)
	r.reset()
	_, err := r.m.Service(ctx, backend.ServiceEnable, "")
	wantCode(t, err, 1)
	contains(t, r.out(), "somebody's RADIUS server")
	if !r.isActive("freeradius") || r.called(`^systemctl (stop|disable) .*freeradius`) {
		t.Errorf("the unit was touched: %v", r.calls())
	}
}

// "disable: stops and disables the unit, removes the drop-in, keeps the
// rendered files".
func TestServiceStopDisableKeepsRenderedFiles(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	if _, err := r.m.Service(ctx, backend.ServiceStop, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.m.Service(ctx, backend.ServiceDisable, ""); err != nil {
		t.Fatal(err)
	}
	if !r.called(`^systemctl stop freeradius.service$`) || !r.called(`^systemctl disable --quiet freeradius.service$`) {
		t.Errorf("calls %v", r.calls())
	}
	if r.isActive("freeradius") || r.isEnabled("freeradius") {
		t.Error("still active or enabled")
	}
	if r.exists(filepath.Dir(r.m.L.DropIn)) {
		t.Error("the drop-in directory stayed")
	}
	if !r.exists(r.m.L.Conf) || !r.exists(r.m.L.Users) {
		t.Error("the rendered files were removed")
	}
	// Installed: its rendered config is still tacctl's.
	if !r.m.Installed() {
		t.Error("a disabled backend with rendered files is not installed")
	}
}

// stop and disable do nothing without the drop-in: the unit is then not
// running tacctl's instance, and whatever it does is not tacctl's to stop
// ("uninstall: ... somebody else's running unit is not stopped").
func TestServiceStopAndDisableWithoutDropInDoNothing(t *testing.T) {
	r := newEnv(t)
	r.setActive("freeradius", true)
	r.reset()
	ctx := context.Background()
	for _, a := range []backend.ServiceAction{backend.ServiceStop, backend.ServiceDisable} {
		if _, err := r.m.Service(ctx, a, ""); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if len(r.calls()) != 0 || !r.isActive("freeradius") {
		t.Errorf("calls %v", r.calls())
	}
}

// restart/reload: the drop-in is brought in line first when the dictionary
// is there; success and failure are reported and never fail the caller.
func TestServiceRestartReports(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	for _, a := range []backend.ServiceAction{backend.ServiceRestart, backend.ServiceReload} {
		r.reset()
		if _, err := r.m.Service(ctx, a, "ignored-listener"); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		contains(t, r.out(), "Service restarted (freeradius).")
		if r.restarts("freeradius.service") != 1 {
			t.Errorf("%s calls %v", a, r.calls())
		}
	}
	r.setFailStart(true)
	r.reset()
	if _, err := r.m.Service(ctx, backend.ServiceRestart, ""); err != nil {
		t.Fatalf("a failing restart failed the caller: %v", err)
	}
	contains(t, r.out(), "Service restart failed — run: sudo systemctl restart freeradius")
	contains(t, r.stdout.String(), "[WARN]")
}

// An older drop-in is replaced by the restart, but only once the dictionary
// it names is there.
func TestRestartBringsTheDropInInLine(t *testing.T) {
	r := newEnv(t)
	r.up()
	l := r.m.L
	old := "[Service]\nExecStart=" + l.Bin + " -f -d " + l.Dir + " -n tacctl-radius\n"
	if err := os.WriteFile(l.DropIn, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(l.Dict, l.Dict+".away"); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if _, err := r.m.Service(context.Background(), backend.ServiceRestart, ""); err != nil {
		t.Fatal(err)
	}
	if r.read(l.DropIn) != old {
		t.Error("the drop-in was replaced although the dictionary it names is not there")
	}
	if err := os.Rename(l.Dict+".away", l.Dict); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if _, err := r.m.Service(context.Background(), backend.ServiceRestart, ""); err != nil {
		t.Fatal(err)
	}
	contains(t, r.read(l.DropIn), " -D "+l.DictDir+" ")
	got := r.calls()
	if len(got) < 3 || got[0] != "systemctl daemon-reload" || got[1] != "systemctl reset-failed freeradius.service" || got[2] != "systemctl restart freeradius.service" {
		t.Errorf("calls %v", got)
	}
}

// is-active, since and pid return systemd's answers; start fails when
// systemctl does; unknown actions are unsupported and run nothing.
func TestServiceQueries(t *testing.T) {
	r := newEnv(t)
	ctx := context.Background()
	word, err := r.m.Service(ctx, backend.ServiceIsActive, "")
	if word != "inactive" || err == nil {
		t.Errorf("inactive: %q %v", word, err)
	}
	r.setActive("freeradius", true)
	word, err = r.m.Service(ctx, backend.ServiceIsActive, "")
	if word != "active" || err != nil {
		t.Errorf("active: %q %v", word, err)
	}
	if v, _ := r.m.Service(ctx, backend.ServiceSince, ""); v != "Fri 2026-10-02 10:00:00 UTC" {
		t.Errorf("since %q", v)
	}
	if v, _ := r.m.Service(ctx, backend.ServicePID, ""); v != "4242" {
		t.Errorf("pid %q", v)
	}
	r.setActive("freeradius", false)
	if v, _ := r.m.Service(ctx, backend.ServicePID, ""); v != "0" {
		t.Errorf("pid %q", v)
	}
	r.setFailStart(true)
	if _, err := r.m.Service(ctx, backend.ServiceStart, ""); backend.ExitCode(err) != 1 {
		t.Errorf("start: %v", err)
	}
	r.reset()
	if _, err := r.m.Service(ctx, "frobnicate", ""); backend.ExitCode(err) != 2 {
		t.Errorf("unknown: %v", err)
	}
	if len(r.calls()) != 0 || r.stdout.Len()+r.stderr.Len() != 0 {
		t.Errorf("an unknown action ran or wrote something")
	}
}

// The logrotate file names the three logs and the service account.
func TestLogrotateText(t *testing.T) {
	r := newEnv(t)
	l := r.m.L
	want := "# Installed by tacctl: the logs of its FreeRADIUS instance.\n" +
		l.LogDir + "/tacctl-radius.log " + l.LogDir + "/tacctl-auth.log " + l.LogDir + "/tacctl-accounting.log {\n" +
		"\tweekly\n\trotate 12\n\tmissingok\n\tnotifempty\n\tcompress\n\tdelaycompress\n\tcopytruncate\n\tsu freerad freerad\n}\n"
	if got := r.m.LogrotateText(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if err := r.m.LogrotateInstall(); err != nil {
		t.Fatal(err)
	}
	if r.read(l.Logrotate) != want || r.mode(l.Logrotate) != 0o644 {
		t.Errorf("installed %q (%o)", r.read(l.Logrotate), r.mode(l.Logrotate))
	}
	// Without logrotate's directory nothing is written.
	if err := os.RemoveAll(filepath.Dir(l.Logrotate)); err != nil {
		t.Fatal(err)
	}
	if err := r.m.LogrotateInstall(); err != nil || r.exists(l.Logrotate) {
		t.Errorf("no directory: %v", err)
	}
	r2 := newEnv(t, rhel)
	contains(t, r2.m.LogrotateText(), "\tsu radiusd radiusd\n")
}
