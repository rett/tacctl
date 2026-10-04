package cli

// The per-backend sections of 'status', 'config validate', 'config show',
// 'log', 'backend list|status', 'store rollback' and 'backup restore' with
// a second backend: ports of tests/integration/backend_cli.bats, whose
// stand-in 'fake' backend (sourced into bash) is internal/backend/faketest
// here, registered for the length of one test beside the shipped modules
// (sectionsSandbox). The commands run end to end in the sandbox of
// native_test.go, with systemctl reporting every unit active and ss
// answering as the bats setup's stubs did: tacquito on tcp 49, the
// stand-in on udp 1812 and 1813.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// sectionsSandbox is the sandbox with the stand-in registered (its artifact
// etc/fake.conf, its state under fake/), tacquito installed, and the
// answers of systemctl and ss the bats setup gave.
type sectionsSandbox struct {
	*sandbox
	fk *faketest.Backend
	// tcp and udp are what 'ss -tlnp' and 'ss -ulnp' print.
	tcp, udp string
	// inactive: systemctl is-active says inactive (exit 3).
	inactive bool
}

// withFakeBackend registers b in the default registry until the test ends:
// the shipped modules keep their factories (and their order), b comes
// after them. The registry has no removal, so the whole value is swapped
// back by the cleanup.
func withFakeBackend(t *testing.T, b *faketest.Backend) {
	t.Helper()
	orig := *backend.Default()
	shipped := &orig
	r := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	for _, id := range shipped.IDs() {
		id := id
		if err := r.Add(id, func(env *backend.Env) backend.Backend {
			mod, err := backend.NewSet(shipped, env).Get(id)
			if err != nil {
				panic(err)
			}
			return mod
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Add(b.ID(), faketest.Factory(b)); err != nil {
		t.Fatal(err)
	}
	*backend.Default() = *r
	t.Cleanup(func() { *backend.Default() = orig })
}

func newSectionsSandbox(t *testing.T, withStore bool) *sectionsSandbox {
	t.Helper()
	sb := newSandbox(t, withStore)
	sandboxRADIUS(sb)
	s := &sectionsSandbox{
		sandbox: sb,
		fk:      faketest.New("fake", filepath.Join(sb.dir, "etc", "fake.conf"), filepath.Join(sb.dir, "fake")),
		tcp:     "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))\n",
		udp:     "UNCONN 0 0 *:1812 *:*\nUNCONN 0 0 *:1813 *:*\n",
	}
	withFakeBackend(t, s.fk)
	// tacquito is installed.
	sb.write("bin/tacquito", "#!/bin/sh\n", 0o755)
	sb.write("systemd/tacquito.service", "[Unit]\n", 0o644)
	if withStore {
		s.run("", "config", "render")
		s.expect(0, "", "")
	}
	return s
}

// run is sandbox.run with the answers of this sandbox scripted.
func (s *sectionsSandbox) run(stdin string, args ...string) string {
	s.t.Helper()
	sb := s.sandbox
	sb.out.Reset()
	sb.err.Reset()
	r := &fake.Runner{}
	r.On([]string{"systemctl"}, execx.Result{})
	if s.inactive {
		r.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte("inactive\n"), Code: 3})
	} else {
		r.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte("active\n")})
	}
	r.Func(func(c execx.Cmd) bool { return c.Name == "systemctl" && slices.Contains(c.Args, "show") },
		func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), "MainPID") {
				return execx.Result{Stdout: []byte("MainPID=4242\n")}, nil
			}
			return execx.Result{Stdout: []byte("ActiveEnterTimestamp=Fri 2026-10-02 10:00:00 UTC\n")}, nil
		})
	r.On([]string{"logger"}, execx.Result{})
	r.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	r.On([]string{"ss"}, execx.Result{Stdout: []byte(s.tcp)})
	r.Func(func(c execx.Cmd) bool { return c.Name == "ss" && len(c.Args) > 0 && strings.Contains(c.Args[0], "u") },
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(s.udp)}, nil })
	sb.runner = r
	a := app.New(args, paths.NewEnv(append([]string(nil), sb.env...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(stdin), Stdout: &sb.out, Stderr: &sb.err}, r)
	a.Paths = a.Paths.Reroot(sb.dir)
	sb.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}), a.Out)
	if n := len(r.Execs()); n != 0 {
		s.t.Errorf("%q: exec'd (%d execs)", args, n)
	}
	return plain(sb.out.String())
}

// all is stdout and stderr of the last run, colours stripped.
func (s *sectionsSandbox) all() string { return plain(s.out.String() + s.err.String()) }

// fakeUp is fake_up: the stand-in installed, enabled ('backend enable fake
// -y'), rendered, running; its call log emptied.
func (s *sectionsSandbox) fakeUp() {
	s.t.Helper()
	s.fk.SetInstalled(true)
	s.run("", "backend", "enable", "fake", "-y")
	if s.code != 0 {
		s.t.Fatalf("backend enable fake: %d\n%s", s.code, s.all())
	}
	if s.fk.Active() != "active" {
		s.t.Fatalf("the stand-in is %s after its enable", s.fk.Active())
	}
	s.fk.ResetCalls()
}

// state is the bats state(): a line per canonical file and artifact.
func (s *sectionsSandbox) state() string {
	var b strings.Builder
	for _, rel := range []string{"state/store.yaml", "state/tacctl.yaml", "etc/tacquito.yaml", "etc/fake.conf", "state/rendered.json"} {
		data, err := os.ReadFile(s.path(rel))
		if err != nil {
			b.WriteString(rel + " absent\n")
			continue
		}
		sum := sha256.Sum256(data)
		b.WriteString(rel + " " + hex.EncodeToString(sum[:]) + "\n")
	}
	return b.String()
}

// between is the text from the first line containing from up to the
// first later line containing to (both included; to "" is the end): the
// bats sed -n '/from/,/to/p'.
func between(out, from, to string) string {
	i := strings.Index(out, from)
	if i < 0 {
		return ""
	}
	rest := out[i:]
	if to == "" {
		return rest
	}
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return rest
	}
	j := strings.Index(rest[nl:], to)
	if j < 0 {
		return rest
	}
	end := nl + j
	if k := strings.IndexByte(rest[end:], '\n'); k >= 0 {
		end += k + 1
	} else {
		end = len(rest)
	}
	return rest[:end]
}

func mustContain(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, text)
		}
	}
}

func mustNotContain(t *testing.T, what, text string, bads ...string) {
	t.Helper()
	for _, b := range bads {
		if strings.Contains(text, b) {
			t.Errorf("%s has %q:\n%s", what, b, text)
		}
	}
}

func mustMatch(t *testing.T, what, text string, patterns ...string) {
	t.Helper()
	for _, p := range patterns {
		if !regexp.MustCompile("(?m)" + p).MatchString(text) {
			t.Errorf("%s has no line matching %q:\n%s", what, p, text)
		}
	}
}

// writeCalls is whether the stand-in was started, stopped, restarted,
// enabled or disabled.
func (s *sectionsSandbox) fakeServiceChanged() []string {
	var out []string
	for _, c := range s.fk.Calls() {
		for _, verb := range []string{"start", "stop", "restart", "reload", "enable", "disable"} {
			if c == "service "+verb || strings.HasPrefix(c, "service "+verb+" ") {
				out = append(out, c)
			}
		}
	}
	return out
}

const systemdChange = `^systemctl (start|stop|restart|reload|enable|disable)`

// --- backend list and status --------------------------------------------------

// backend_cli.bats #3: 'backend list' needs no store and writes nothing.
func TestSectionsBackendListNeedsNoStore(t *testing.T) {
	s := newSectionsSandbox(t, true)
	if err := os.Remove(s.path("state/store.yaml")); err != nil {
		t.Fatal(err)
	}
	before := s.state()
	out := s.run("", "backend", "list")
	s.expect(0, "IMPLEMENTATION", "")
	mustMatch(t, "backend list", out,
		`ID +PROTOCOL +IMPLEMENTATION +INSTALLED +ENABLED +SERVICE`,
		`^  tacacs +tacacs +tacquito +yes +yes +active`,
		`^  fake +fake +faked +no +no +-`)
	if s.state() != before {
		t.Errorf("backend list without a store wrote:\n%s\n%s", before, s.state())
	}
	if s.runner.CalledRegexp(systemdChange) {
		t.Errorf("systemctl: %q", s.runner.Argvs())
	}
}

// backend_cli.bats #4: every backend's service and listeners, the tcp ones
// probed with ss -tlnp, the udp ones with ss -ulnp.
func TestSectionsBackendStatusTCPAndUDPListeners(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	out := s.run("", "backend", "status")
	s.expect(0, "", "")
	mustContain(t, "backend status", out, "== Backend: tacacs (tacacs, tacquito) ==", "== Backend: fake (fake, faked) ==")
	fk := between(out, "== Backend: fake", "")
	mustMatch(t, "the fake section", fk,
		`State:.*installed, enabled`,
		`Service:.*active`,
		`Listener auth:.* udp :1812 — unit active, .*listening on \*:1812`,
		`Listener acct:.* udp :1813 — unit active, .*listening on \*:1813`)
	mustMatch(t, "the tacacs section", between(out, "== Backend: tacacs", "== Backend: radius"),
		`State:.*installed, enabled`,
		`Listener default:.* tcp :49 — unit active, .*listening on \*:49`)
	if !s.runner.Called("ss", "-ulnp") || !s.runner.Called("ss", "-tlnp") {
		t.Errorf("ss probes: %q", s.runner.Argvs())
	}
}

// backend_cli.bats #6: list and status with a second backend enabled and
// running write nothing and start, stop or restart nothing.
func TestSectionsBackendListStatusReadOnlyWithTwo(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	before := s.state()
	for _, args := range [][]string{{"backend", "list"}, {"backend", "status"}, {"backend", "status", "fake"}} {
		s.run("", args...)
		s.expect(0, "", "")
		if s.runner.CalledRegexp(systemdChange) {
			t.Errorf("%q: systemctl %q", args, s.runner.Argvs())
		}
	}
	if s.state() != before {
		t.Errorf("state changed:\n%s\n%s", before, s.state())
	}
	if c := s.fakeServiceChanged(); len(c) != 0 {
		t.Errorf("the stand-in's service was touched: %q", c)
	}
	if s.fk.Active() != "active" {
		t.Errorf("the stand-in is %s", s.fk.Active())
	}
}

// backend_cli.bats #37: 'store rollback' is refused while another backend
// is enabled, and changes nothing.
func TestSectionsStoreRollbackRefusedWithAnotherBackend(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	before := s.state()
	s.run("y\n", "store", "rollback")
	s.expect(1, "", "Backend(s) fake are enabled")
	s.expect(1, "", "tacctl backend disable <id>")
	if s.state() != before {
		t.Errorf("state changed:\n%s\n%s", before, s.state())
	}
	if c := s.fakeServiceChanged(); len(c) != 0 {
		t.Errorf("the stand-in's service was touched: %q", c)
	}
	if s.runner.CalledRegexp(systemdChange) {
		t.Errorf("systemctl: %q", s.runner.Argvs())
	}
}
