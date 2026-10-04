package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
)

// The load-smoke tests of tests/unit/render_tacacs.bats: with the scripted
// runner (stderr lines as tacquito logs them), and with a stand-in tacquito
// script run for real, as the bats tests do (fake_tacquito).

func (e *tenv) smokeBin() string {
	e.t.Helper()
	bin := e.b.tacquitoBin()
	writeFile(e.t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		e.t.Fatal(err)
	}
	return bin
}

func (e *tenv) renderedFile() string {
	p := filepath.Join(e.w, "out.yaml")
	writeFile(e.t, p, "users: []\n")
	return p
}

// argValue is the value following flag in argv.
func argValue(argv []string, flag string) string {
	if i := slices.Index(argv, flag); i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

// "smoke: skipped (2) when the daemon binary is absent".
func TestSmokeSkippedWithoutTheDaemon(t *testing.T) {
	e := newTenv(t)
	if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokeSkipped || int(got) != 2 {
		t.Fatal(got)
	}
	if e.stderr.Len()+e.stdout.Len() != 0 || len(e.run.Calls()) != 0 {
		t.Fatal("output or calls")
	}
}

// "smoke: passes when the daemon serves; runs isolated" (scripted).
func TestSmokePassesWhenTheDaemonServes(t *testing.T) {
	e := newTenv(t)
	bin := e.smokeBin()
	var cfgSeen string
	e.run.OnFunc([]string{bin}, func(c execx.Cmd) (execx.Result, error) {
		data, _ := os.ReadFile(argValue(c.Args, "-config"))
		cfgSeen = string(data)
		return execx.Result{Stderr: []byte("INFO: main.go:135: serve on 127.0.0.1:40001\n" +
			"INFO: loader.go:241: updated all providers from config source\n")}, nil
	})
	out := e.renderedFile()
	if got := e.b.LoadSmoke(context.Background(), out); got != SmokePassed {
		t.Fatalf("%v: %s", got, e.stderr)
	}
	argv := e.run.Calls()[0].Args
	// Loopback, kernel-chosen ports: never the production listener.
	if argValue(argv, "-network") != "tcp" || argValue(argv, "-address") != "127.0.0.1:0" ||
		argValue(argv, "-metrics-address") != "127.0.0.1:0" || argValue(argv, "-level") != "20" {
		t.Fatal(argv)
	}
	// A private copy of the config and a private accounting log, apart,
	// both removed.
	cfg, acct := argValue(argv, "-config"), argValue(argv, "-acct-log-path")
	if cfg == out || cfg == e.p.Config || acct == e.p.AcctLog || strings.HasPrefix(acct, "/var/log/") ||
		filepath.Dir(cfg) == filepath.Dir(acct) || cfgSeen != "users: []\n" {
		t.Fatal(cfg, acct, cfgSeen)
	}
	if exists(cfg) || exists(acct) || exists(e.p.AcctLog) {
		t.Fatal("left behind")
	}
	if ents, _ := os.ReadDir(filepath.Join(e.w, "tmp")); len(ents) != 0 {
		t.Fatal(ents)
	}
	if e.stderr.Len() != 0 {
		t.Fatal(e.stderr)
	}
}

// "smoke: a config the daemon rejects fails, with the reason and without
// its log", for each cause.
func TestSmokeNamesTheCause(t *testing.T) {
	for log, msg := range map[string]string{
		"FATAL: main.go:98: error fetching config; loader failed: no users were unmarshalled from config, cannot serve": "Load-smoke: tacquito refuses a config with no users.",
		"FATAL: main.go:98: error fetching config; no secret providers were unmarshalled":                               "Load-smoke: tacquito refuses a config with no scopes.",
		"FATAL: main.go:98: error fetching config; yaml: line 3: mapping values are not allowed":                        "Load-smoke: tacquito could not parse the config.",
		"INFO: main.go:135: serve on 127.0.0.1:40001":                                                                   "Load-smoke: tacquito did not start serving within 5s.",
	} {
		e := newTenv(t)
		bin := e.smokeBin()
		e.run.On([]string{bin}, execx.Result{Stderr: []byte(log + "\n")})
		if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokeFailed {
			t.Fatal(got)
		}
		if got := e.stderr.String(); !strings.Contains(got, msg) || strings.Contains(got, "main.go") {
			t.Fatalf("%q", got)
		}
	}
}

// A daemon that cannot be started, and a rendered file that is not there.
func TestSmokeFailures(t *testing.T) {
	e := newTenv(t)
	e.smokeBin()
	if got := e.b.LoadSmoke(context.Background(), filepath.Join(e.w, "nope.yaml")); got != SmokeFailed {
		t.Fatal(got)
	}
	mustContain(t, e.stderr.String(), "Load-smoke: "+filepath.Join(e.w, "nope.yaml")+" not found.")
	e.reset()
	e.run.Missing(e.b.tacquitoBin())
	e.b.SmokeTime = 2 * time.Second
	if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokeFailed {
		t.Fatal(got)
	}
	mustContain(t, e.stderr.String(), "Load-smoke: tacquito did not start serving within 2s.")
	if seconds(1500*time.Millisecond) != "1.5" {
		t.Fatal(seconds(1500 * time.Millisecond))
	}
}

// fakeTacquito is fake_tacquito of render_tacacs.bats: a stand-in that
// records its argv and pid, then serves (logs like a healthy daemon and
// stays up), logs a loader failure and exits 0, or hangs.
func (e *tenv) fakeTacquito(mode string) {
	e.t.Helper()
	var body string
	switch mode {
	case "serve":
		body = "echo 'INFO: main.go:135: serve on 127.0.0.1:40001' >&2\n" +
			"echo 'INFO: loader.go:241: updated all providers from config source' >&2\nexec sleep 30\n"
	case "fatal":
		body = "echo 'FATAL: main.go:98: error fetching config; loader failed: no users were unmarshalled from config, cannot serve' >&2\nexit 0\n"
	case "hang":
		body = "exec sleep 30\n"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + filepath.Join(e.w, "smoke.argv") + "'\n" +
		"echo $$ > '" + filepath.Join(e.w, "smoke.pid") + "'\n" + body
	bin := e.b.tacquitoBin()
	writeFile(e.t, bin, script)
	if err := os.Chmod(bin, 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.env.Runner = execx.Real{}
}

// gone reports whether the stand-in's process no longer exists.
func (e *tenv) gone() bool {
	e.t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(readFile(e.t, filepath.Join(e.w, "smoke.pid"))))
	if err != nil {
		e.t.Fatal(err)
	}
	return syscall.Kill(pid, 0) != nil
}

// "smoke: passes when the daemon serves; ... the daemon is gone afterwards"
// (a real process).
func TestSmokeRealDaemonServesAndIsStopped(t *testing.T) {
	e := newTenv(t)
	e.fakeTacquito("serve")
	start := time.Now()
	if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokePassed {
		t.Fatalf("%v: %s", got, e.stderr)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("waited too long")
	}
	argv := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(e.w, "smoke.argv"))), "\n")
	if cfg := argValue(argv, "-config"); exists(cfg) || exists(argValue(argv, "-acct-log-path")) {
		t.Fatal("left behind")
	}
	if !e.gone() {
		t.Fatal("the daemon is still running")
	}
}

// "smoke: a config the daemon rejects fails" (a real process that exits).
func TestSmokeRealDaemonRejects(t *testing.T) {
	e := newTenv(t)
	e.fakeTacquito("fatal")
	if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokeFailed {
		t.Fatal(got)
	}
	mustContain(t, e.stderr.String(), "tacquito refuses a config with no users")
	mustNotContain(t, e.stderr.String(), "main.go")
}

// "smoke: a daemon that never serves fails after the time limit and is
// killed".
func TestSmokeRealDaemonThatNeverServes(t *testing.T) {
	e := newTenv(t)
	e.fakeTacquito("hang")
	e.b.SmokeTime = time.Second
	if got := e.b.LoadSmoke(context.Background(), e.renderedFile()); got != SmokeFailed {
		t.Fatal(got)
	}
	mustContain(t, e.stderr.String(), "did not start serving within 1s")
	if !e.gone() {
		t.Fatal("the daemon is still running")
	}
}
