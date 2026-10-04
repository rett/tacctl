package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// "tacacs service: restart reports and never fails; other actions pass
// systemctl through" (tests/unit/backend.bats).
func TestServiceRestartReportsAndNeverFails(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	if _, err := e.b.Service(ctx, backend.ServiceRestart, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Service restarted.")
	if !e.called(`^systemctl restart tacquito$`) {
		t.Fatal(e.run.Argvs())
	}
	e.reset()
	e.run.On([]string{"systemctl"}, execx.Result{Code: 1})
	e.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3, Stdout: []byte("inactive\n")})
	if _, err := e.b.Service(ctx, backend.ServiceReload, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Service restart failed — run: sudo systemctl restart tacquito")
	word, err := e.b.Service(ctx, backend.ServiceIsActive, "")
	wantCode(t, err, 3)
	if word != "inactive" {
		t.Fatalf("word %q", word)
	}
	_, err = e.b.Service(ctx, "frobnicate", "")
	wantCode(t, err, 2)
	_, err = e.b.Service(ctx, backend.ServiceStop, "")
	wantCode(t, err, 1)
}

// "service verb: an optional listener addresses its unit; none is the
// whole backend" (tests/integration/listeners.bats).
func TestServiceListenerAddressesItsUnit(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	e.writeOverrides("listeners:\n  tacacs:\n    mgmt: {network: tcp, address: \"127.0.0.1:4949\"}\n")
	if _, err := e.b.Service(ctx, backend.ServiceRestart, "mgmt"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Service restarted.")
	if !e.called(`^systemctl restart tacquito@mgmt\.service$`) || e.called(`^systemctl restart tacquito$`) ||
		e.called(`enable`) {
		t.Fatal(e.run.Argvs())
	}
	e.run.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte("active\n")})
	if w, err := e.b.Service(ctx, backend.ServiceIsActive, "mgmt"); err != nil || w != "active" {
		t.Fatalf("%q %v", w, err)
	}
	if _, err := e.b.Service(ctx, backend.ServiceStop, "mgmt"); err != nil {
		t.Fatal(err)
	}
	if !e.called(`^systemctl is-active tacquito@mgmt\.service$`) || !e.called(`^systemctl stop tacquito@mgmt\.service$`) {
		t.Fatal(e.run.Argvs())
	}

	e.reset()
	_, _ = e.b.Service(ctx, backend.ServiceRestart, "")
	if !e.called(`^systemctl restart tacquito$`) || !e.called(`^systemctl enable --quiet --now tacquito@mgmt\.service$`) {
		t.Fatal(e.run.Argvs())
	}
	e.reset()
	_, _ = e.b.Service(ctx, backend.ServiceRestart, "default")
	if !e.called(`^systemctl restart tacquito$`) {
		t.Fatal(e.run.Argvs())
	}
	if got := e.b.Describe().Units; !slices.Equal(got, []string{"tacquito.service", "tacquito@mgmt.service"}) {
		t.Fatalf("units %v", got)
	}
	if got := e.b.Artifacts(); len(got) != 3 || got[2] != e.dropIn("mgmt") {
		t.Fatalf("artifacts %v", got)
	}

	// Enable and disable reach every listener's unit at boot.
	e.reset()
	if _, err := e.b.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.Service(ctx, backend.ServiceDisable, "mgmt"); err != nil {
		t.Fatal(err)
	}
	if got := e.run.Argvs(); !slices.Equal(got, []string{"systemctl enable tacquito.service tacquito@mgmt.service",
		"systemctl disable tacquito@mgmt.service"}) {
		t.Fatal(got)
	}
}

// since and pid are 'systemctl show <unit> --property=<p> | cut -d= -f2'.
func TestServiceSinceAndPID(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	e.run.On([]string{"systemctl", "show", "tacquito", "--property=ActiveEnterTimestamp"},
		execx.Result{Stdout: []byte("ActiveEnterTimestamp=Mon 2026-04-21 10:00:00 UTC\n")})
	e.run.On([]string{"systemctl", "show", "tacquito", "--property=MainPID"}, execx.Result{Stdout: []byte("MainPID=4242\n")})
	if s, _ := e.b.Service(ctx, backend.ServiceSince, ""); s != "Mon 2026-04-21 10:00:00 UTC" {
		t.Fatalf("since %q", s)
	}
	if s, _ := e.b.Service(ctx, backend.ServicePID, ""); s != "4242" {
		t.Fatalf("pid %q", s)
	}
	for in, want := range map[string]string{"": "", "a=b=c\n": "b", "plain\n": "plain", "x=1\ny=2\n": "1\n2"} {
		if got := cutField2(in); got != want {
			t.Fatalf("cut %q: %q, want %q", in, got, want)
		}
	}
}

// _tacacs_instances_sync: a listener's instance that cannot be started is
// warned about; an enabled instance without a listener is stopped and
// disabled; a wants entry that is not a link is not an instance.
func TestInstancesSync(t *testing.T) {
	e := newTenv(t)
	e.writeOverrides("listeners:\n  tacacs:\n    mgmt: {network: tcp, address: \"127.0.0.1:4949\"}\n")
	wants := filepath.Join(e.p.TacacsUnitDir, "tacquito.service.wants")
	_ = os.MkdirAll(wants, 0o755)
	for _, n := range []string{"mgmt", "old"} {
		if err := os.Symlink("/x", filepath.Join(wants, "tacquito@"+n+".service")); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(wants, "tacquito@file.service"), "")
	e.run.Fail([]string{"systemctl", "enable"}, 1, "no")
	e.b.instancesSync(context.Background())
	mustContain(t, e.stdout.String(), "Could not enable and start tacquito@mgmt.service — check: systemctl status tacquito@mgmt.service")
	if got := e.run.Argvs(); !slices.Equal(got, []string{"systemctl enable --quiet --now tacquito@mgmt.service",
		"systemctl disable --quiet --now tacquito@old.service"}) {
		t.Fatal(got)
	}
	if e.stderr.Len() != 0 {
		t.Fatalf("stderr %q", e.stderr)
	}
}

// TACCTL_SETTLE_SECONDS, with sleep(1)'s suffixes.
func TestSettle(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": 0, "0.5": 500 * time.Millisecond, "2": 2 * time.Second,
		"1.5s": 1500 * time.Millisecond, "1m": time.Minute, "abc": 0, "-1": 0, "": 0} {
		e := &Backend{env: &backend.Env{}}
		e.env.Paths.SettleSeconds = in
		if got := e.settle(); got != want {
			t.Fatalf("%q: %v, want %v", in, got, want)
		}
	}
}
