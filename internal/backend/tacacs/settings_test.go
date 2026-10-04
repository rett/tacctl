package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/snapshot"
)

// 'tacctl config loglevel' and 'tacctl config metrics' below their
// argument parsing (tests/integration/config_setters.bats,
// config_metrics_sudoers.bats, listeners.bats "loglevel and metrics are per
// backend"), and the conversion of an install from before the listener
// model by its first settings change (tests/integration/units_convert.bats
// "not converted", "failure").

// "config loglevel: shows current level (default info/20)", "sets debug in
// tacctl.yaml and the rendered drop-in", "setting back to info (default)
// clears the override", "rejects unknown level"; listeners.bats "config
// loglevel: lives in tacctl.yaml and reaches every listener's drop-in".
func TestLogLevel(t *testing.T) {
	e := newTenv(t).withStore("store.minimal.yaml")
	ctx := context.Background()
	if err := e.b.LogLevel(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.stdout.String(); got != "\n  Current log level: info (20)\n\n  Usage: tacctl config loglevel <debug|info|error>\n\n" {
		t.Fatalf("%q", got)
	}
	if err := e.b.Listeners().Set(ctx, "mgmt", "tcp", "127.0.0.1:4949"); err != nil {
		t.Fatal(err)
	}
	e.reset()
	if err := e.b.LogLevel(ctx, "debug"); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	mustContain(t, e.stdout.String(), "Log level changed to debug (30). Service restarted.")
	mustContain(t, readFile(t, e.p.Overrides), "level: 30")
	mustLine(t, readFile(t, e.dropIn("default")), `Environment="TACQUITO_LEVEL=30"`)
	mustLine(t, readFile(t, e.dropIn("mgmt")), `Environment="TACQUITO_LEVEL=30"`)
	if !e.called(`^systemctl restart tacquito$`) || !e.called(`^systemctl enable --quiet --now tacquito@mgmt\.service$`) {
		t.Fatal(e.run.Argvs())
	}
	e.reset()
	_ = e.b.LogLevel(ctx, "")
	mustContain(t, e.stdout.String(), "Current log level: debug (30)")
	e.reset()
	_ = e.b.LogLevel(ctx, "debug")
	mustContain(t, e.stdout.String(), "Already at debug (30).")
	if len(e.run.Calls()) != 0 {
		t.Fatal(e.run.Argvs())
	}
	if err := e.b.LogLevel(ctx, "info"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, e.p.Overrides), "level") {
		t.Fatal(readFile(t, e.p.Overrides))
	}
	mustLine(t, readFile(t, e.dropIn("default")), `Environment="TACQUITO_LEVEL=20"`)
	e.reset()
	wantCode(t, e.b.LogLevel(ctx, "verbose"), 1)
	mustContain(t, e.stderr.String(), "Invalid level: verbose. Use: debug, info, or error")
}

func TestSettleWaitsBeforeTheCheck(t *testing.T) {
	e := newTenv(t, "TACCTL_SETTLE_SECONDS=0.25")
	if err := e.b.LogLevel(context.Background(), "debug"); err != nil {
		t.Fatal(err)
	}
	if len(e.sleeps) != 1 || e.sleeps[0] != 250*time.Millisecond {
		t.Fatal(e.sleeps)
	}
}

// config_metrics_sudoers.bats, the metrics half.
func TestMetrics(t *testing.T) {
	e := newTenv(t).withStore("store.minimal.yaml")
	ctx := context.Background()
	run := func(sub, arg string) error {
		e.reset()
		return e.b.Metrics(ctx, sub, arg)
	}
	dropin := e.dropIn("default")

	// "default show reports loopback-only default", "show: prints scrape
	// URL for enabled state".
	if err := run("", ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "enabled (loopback-only)")
	mustContain(t, e.stdout.String(), "  Address:  127.0.0.1:8080  (default)")
	_ = run("show", "")
	mustContain(t, e.stdout.String(), "  Scrape URL: http://127.0.0.1:8080/metrics")
	mustContain(t, e.stdout.String(), "tacctl config metrics reset                Clear override (revert to unit default)")

	// "enable: no-op on fresh install".
	_ = run("enable", "")
	mustContain(t, e.stdout.String(), "Already enabled on default (127.0.0.1:8080).")

	// "address: pins a custom host:port in tacctl.yaml and the rendered
	// drop-in".
	if err := run("address", "10.1.0.1:9090"); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	mustContain(t, readFile(t, e.p.Overrides), "metrics_address: 10.1.0.1:9090")
	mustLine(t, readFile(t, dropin), `Environment="TACQUITO_METRICS_ADDRESS=10.1.0.1:9090"`)
	if !e.called(`systemctl daemon-reload`) || !e.called(`systemctl restart tacquito`) {
		t.Fatal(e.run.Argvs())
	}
	mustContain(t, e.stdout.String(), "Metrics listen address set to 10.1.0.1:9090. Service restarted.")
	mustContain(t, e.stdout.String(), "externally reachable")
	_ = run("", "")
	mustContain(t, e.stdout.String(), "enabled (externally reachable)")
	mustContain(t, e.stdout.String(), "10.1.0.1:9090  (override)")

	// listeners.bats "config metrics: a bad address is refused with
	// everything as it was".
	before := state(dropin, e.p.Overrides)
	wantCode(t, run("address", "bad host:9090"), 1)
	mustContain(t, e.stderr.String(), "must be host:port")
	mustContain(t, e.stderr.String(), "Nothing was changed.")
	if state(dropin, e.p.Overrides) != before {
		t.Fatal("changed")
	}
	for _, a := range e.run.Argvs() {
		if strings.HasPrefix(a, "systemctl") {
			t.Fatal(e.run.Argvs())
		}
	}

	// "address: setting default clears the override".
	if err := run("address", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, e.stdout.String(), "externally reachable")
	if exists(e.p.Overrides) && strings.Contains(readFile(t, e.p.Overrides), "metrics_address") {
		t.Fatal(readFile(t, e.p.Overrides))
	}
	mustLine(t, readFile(t, dropin), `Environment="TACQUITO_METRICS_ADDRESS=127.0.0.1:8080"`)
	_ = run("", "")
	mustContain(t, e.stdout.String(), "127.0.0.1:8080  (default)")

	// "address: externally reachable address emits a warning".
	_ = run("address", ":9090")
	mustContain(t, e.stdout.String(), "externally reachable")
	_ = run("show", "")
	mustContain(t, e.stdout.String(), "Scrape URL: http://localhost:9090/metrics")

	// "address: rejects missing argument", "rejects address with no port".
	wantCode(t, run("address", ""), 1)
	mustContain(t, e.stderr.String(), "Examples:")
	wantCode(t, run("address", "127.0.0.1"), 1)
	mustContain(t, e.stderr.String(), "must include a port")

	// "disable: sinks exporter to 127.0.0.1:0", "no-op when already
	// disabled".
	if err := run("disable", ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Metrics exporter sunk to 127.0.0.1:0 — no scraper can reach it.")
	mustLine(t, readFile(t, dropin), `Environment="TACQUITO_METRICS_ADDRESS=127.0.0.1:0"`)
	_ = run("", "")
	mustContain(t, e.stdout.String(), "disabled")
	mustContain(t, e.stdout.String(), "Note: tacquito still runs the exporter goroutine")
	mustNotContain(t, e.stdout.String(), "Scrape URL")
	_ = run("disable", "")
	mustContain(t, e.stdout.String(), "Already disabled (sunk to 127.0.0.1:0).")

	// enable from disabled.
	if err := run("enable", ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Metrics exporter enabled on 127.0.0.1:8080/metrics.")

	// "reset: clears the override".
	_ = run("address", "10.1.0.1:9090")
	if err := run("reset", ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.stdout.String(), "Metrics override cleared. Using unit default (127.0.0.1:8080).")
	mustLine(t, readFile(t, dropin), `Environment="TACQUITO_METRICS_ADDRESS=127.0.0.1:8080"`)

	// "rejects unknown subcommand".
	wantCode(t, run("bogus", ""), 1)
	mustContain(t, e.stderr.String(), "Unknown subcommand: 'bogus'")
}

// units_convert.bats "not converted: the first settings change converts,
// keeping the other settings".
func TestFirstSettingsChangeConverts(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.legacyDropIn("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	old := e.b.overrideFile()
	// The readers show the hand-managed drop-in.
	if v, over := e.b.setting("level"); v != "30" || !over {
		t.Fatal(v, over)
	}
	if err := e.b.Metrics(context.Background(), "disable", ""); err != nil {
		t.Fatalf("%v\n%s", err, e.stderr)
	}
	mustContain(t, e.stdout.String(), "settings moved from "+old+" into "+e.p.Overrides)
	if exists(old) {
		t.Fatal("the hand-managed drop-in is still there")
	}
	d := e.dropIn("default")
	if envOf(t, d, "TACQUITO_ADDRESS") != "10.1.0.1:49" || envOf(t, d, "TACQUITO_LEVEL") != "30" ||
		envOf(t, d, "TACQUITO_METRICS_ADDRESS") != "127.0.0.1:0" {
		t.Fatal(readFile(t, d))
	}
	if m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "legacy", "tacctl-overrides.conf.*")); len(m) != 1 {
		t.Fatal(m)
	}
	if v, _ := e.b.setting("level"); v != "30" {
		t.Fatal(v)
	}
	e.noKeep()
}

// "not converted: a settings change whose unit does not come up puts the
// drop-in back".
func TestConversionPutBackWhenTheUnitDoesNotComeUp(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	writeFile(t, e.b.serviceFile(), "[Unit]\n")
	e.legacyDropIn("TACQUITO_ADDRESS=10.1.0.1:49")
	files := []string{e.b.serviceFile(), e.b.templateFile(), e.dropIn("default"), e.b.overrideFile(), e.p.Overrides}
	before := state(files...)
	e.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3})
	wantCode(t, e.b.LogLevel(context.Background(), "debug"), 1)
	if state(files...) != before {
		t.Fatalf("not put back:\n%s\nwas\n%s", state(files...), before)
	}
	e.noKeep()
}

// "failure: a drop-in line tacctl did not write stops the conversion, by
// line", for a settings command.
func TestConversionRefusesForeignLines(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.legacyDropIn("TACQUITO_LEVEL=30")
	old := e.b.overrideFile()
	f, _ := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("LimitNOFILE=65536\nEnvironment=\"HTTP_PROXY=http://proxy:3128\"\n")
	_ = f.Close()
	files := []string{e.dropIn("default"), old, e.p.Overrides}
	before := state(files...)
	wantCode(t, e.b.LogLevel(context.Background(), "error"), 1)
	errs := e.stderr.String()
	mustContain(t, errs, "tacctl render: "+old+" holds lines tacctl did not write and cannot carry over")
	mustContain(t, errs, "line 3: LimitNOFILE=65536")
	mustContain(t, errs, `line 4: Environment="HTTP_PROXY=http://proxy:3128"`)
	mustContain(t, errs, "Nothing was changed.")
	if state(files...) != before {
		t.Fatal("changed")
	}
	for _, a := range e.run.Argvs() {
		if strings.HasPrefix(a, "systemctl") {
			t.Fatal(e.run.Argvs())
		}
	}
	// The install keeps working from the old drop-in.
	_ = e.b.LogLevel(context.Background(), "")
	mustContain(t, e.stdout.String(), "debug (30)")
}

// "failure: a value the schema refuses stops the conversion".
func TestConversionRefusesAValueTheSchemaRefuses(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.legacyDropIn("TACQUITO_ADDRESS=not-an-address", "TACQUITO_LEVEL=30")
	before := state(e.b.overrideFile(), e.p.Overrides)
	wantCode(t, e.b.Metrics(context.Background(), "disable", ""), 1)
	mustContain(t, e.stderr.String(), "listeners.tacacs.default: address 'not-an-address'")
	mustContain(t, e.stderr.String(), "Nothing was changed.")
	if state(e.b.overrideFile(), e.p.Overrides) != before {
		t.Fatal("changed")
	}
}

// "failure: a tacctl.yaml that does not parse is not written into", for a
// settings command.
func TestSettingsRefuseAnUnparsableTacctlYAML(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.writeOverrides("password: [unterminated\n")
	before := state(e.p.Overrides, e.dropIn("default"))
	wantCode(t, e.b.LogLevel(context.Background(), "error"), 1)
	mustContain(t, e.stderr.String(), e.p.Overrides+" is not valid YAML ('tacctl config validate' shows where); fix it first.")
	if state(e.p.Overrides, e.dropIn("default")) != before || len(e.run.Calls()) != 0 || len(e.snapshots()) != 0 {
		t.Fatal("changed")
	}
	e.noKeep()
}

// A snapshot that cannot be made refuses the change before anything is
// written.
func TestSettingsRefuseWhenTheSnapshotFails(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	writeFile(t, e.p.BackupDir, "not a directory")
	wantCode(t, e.b.LogLevel(context.Background(), "debug"), 1)
	mustContain(t, e.stderr.String(), "Nothing was changed: the pre-change snapshot could not be made.")
	if exists(e.p.Overrides) || exists(e.dropIn("default")) || len(e.run.Calls()) != 0 {
		t.Fatal("changed")
	}
	if ids := snapshot.IDs(e.p.BackupDir); len(ids) != 0 {
		t.Fatal(ids)
	}
	e.noKeep()
}

// An error after files were replaced puts every one of them back
// ("failure: an error after files were replaced", the settings path):
// a drop-in that cannot be installed.
func TestSettingsCommitFailurePutsBack(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	// The default listener's drop-in directory is a file: the drop-in
	// cannot be installed.
	writeFile(t, e.p.OverrideDir, "x")
	before := state(e.p.Overrides, e.p.Rendered)
	wantCode(t, e.b.LogLevel(context.Background(), "debug"), 1)
	mustContain(t, e.stderr.String(), "The change could not be installed. Settings and drop-ins are as they were.")
	if state(e.p.Overrides, e.p.Rendered) != before {
		t.Fatal("not put back")
	}
	if !e.called(`^systemctl daemon-reload$`) || e.called(`restart`) {
		t.Fatal(e.run.Argvs())
	}
	if readFile(t, e.p.OverrideDir) != "x" {
		t.Fatal("the restore removed a file that is not an empty directory")
	}
	e.noKeep()
}
