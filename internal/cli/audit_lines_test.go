package cli

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// The central audit lines (docs/plans/0.2.17-plan.md D249-D251, D255): the
// cmd start / cmd end pair of an action, the pair of a mixed command that
// wrote, nothing for a read, the cmd DENY line of a refusal inside a verb.

// centralLines are the run's lines of the central pair and the DENY line, in
// order.
func centralLines(r *fake.Runner) []string {
	var out []string
	for _, l := range auditLines(r) {
		if strings.HasPrefix(l, "cmd ") {
			out = append(out, l)
		}
	}
	return out
}

// asAlice runs tacctl as alice (superuser, SUDO_UID as sudo sets it).
func (sb *sandbox) asAlice(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.run(stdin, args, "SUDO_USER=alice", "SUDO_UID=1001"))
}

const (
	reDuration = `\d+\.\d{3}s`
	reSnapshot = `\d{8}_\d{6}_\d{3}`
)

// An action writes the pair: the start line before the verb runs, the end
// line where the status is decided, both with the actor, the command, the
// session id and (the end) the snapshot the command took.
func TestCentralPairOfAnAction(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "disable", "bob")
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	lines := centralLines(sb.runner)
	if len(lines) != 2 {
		t.Fatalf("central lines %q", lines)
	}
	const start = `cmd start v=1 user=alice uid=1001 origin=sudo tier=unrestricted tty=- console=- cmd="user disable" args=bob`
	if lines[0] != start {
		t.Errorf("start\n got %s\nwant %s", lines[0], start)
	}
	if !regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=ok status=0 duration=` + reDuration + ` snapshot=` + reSnapshot + `$`).MatchString(lines[1]) {
		t.Errorf("end %s", lines[1])
	}
	for _, c := range auditCalls(sb.runner) {
		if strings.HasPrefix(c.Line, "cmd ") && c.Priority != "auth.info" {
			t.Errorf("%q at %s, want auth.info", c.Line, c.Priority)
		}
	}
	// Every line of the run, the verb's own too, ends in the one session id.
	if sid, ok := auditSID(sb.runner); !ok || sid == "" {
		t.Errorf("sid %q shared %v", sid, ok)
	}
	// The start line comes before anything the verb wrote, the end after.
	all := auditLines(sb.runner)
	if all[0] != start || !strings.HasPrefix(all[len(all)-1], "cmd end ") {
		t.Errorf("order %q", all)
	}
}

// A command that is run as root without sudo says so; a console session is
// named, and a marker that is no session id is '?'.
func TestCentralLinesActorAndConsole(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "disable", "bob"})
	if got := centralLines(sb.runner)[0]; !strings.HasPrefix(got, "cmd start v=1 user=root uid=0 origin=root tier=unrestricted tty=- console=- ") {
		t.Errorf("root shell: %s", got)
	}
	sb.run("", []string{"user", "enable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001", "TACCTL_CONSOLE=0123456789ab")
	if got := centralLines(sb.runner)[0]; !strings.Contains(got, " user=alice uid=1001 origin=sudo tier=unrestricted tty=- console=0123456789ab cmd=\"user enable\"") {
		t.Errorf("console: %s", got)
	}
	sb.run("", []string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001", "TACCTL_CONSOLE=bad value")
	if got := centralLines(sb.runner)[0]; !strings.Contains(got, " console=invalid ") {
		t.Errorf("bad marker: %s", got)
	}
	sb.hooks.terminalLine = func() string { return "pts/3" }
	sb.run("", []string{"user", "enable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001")
	if got := centralLines(sb.runner)[0]; !strings.Contains(got, " tty=pts/3 console=- ") {
		t.Errorf("tty: %s", got)
	}
}

// A command that fails ends in result=failed with its status; one that took
// no snapshot says '-'.
func TestCentralEndOfAFailedAction(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "disable", "nosuchuser")
	if sb.code != 1 {
		t.Fatalf("exit %d", sb.code)
	}
	lines := centralLines(sb.runner)
	if len(lines) != 2 || !regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=failed status=1 duration=`+reDuration+` snapshot=-$`).MatchString(lines[1]) {
		t.Errorf("lines %q", lines)
	}
	if c := auditCalls(sb.runner); c[len(c)-1].Priority != "auth.warning" {
		t.Errorf("the failed end is at %s, want auth.warning", c[len(c)-1].Priority)
	}
}

// The commands that read write no central line, and a mixed command that
// only read writes none either; the same command with a value writes the
// pair (the first write choke point it reaches writes the start line).
func TestMixedCommandWritesTheLinesOnlyWhenItWrites(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw", "192.168.1.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "lab-sw2", "192.168.1.2", "--vendor", "cisco", "--no-host-key")
	for _, c := range []struct {
		name  string
		read  []string
		write []string
	}{
		{"scope default", []string{"scope", "default"}, []string{"scope", "default", "lab"}},
		{"scope prefixes", []string{"scope", "prefixes", "lab", "list"}, []string{"scope", "prefixes", "lab", "add", "10.200.0.0/16"}},
		{"scope protocols", []string{"scope", "protocols", "lab"}, []string{"scope", "protocols", "lab", "set", "tacacs"}},
		{"scope aaa-order", []string{"scope", "aaa-order", "lab"}, []string{"scope", "aaa-order", "lab", "local-first"}},
		{"scope secret", []string{"scope", "secret", "lab", "show"}, []string{"scope", "secret", "lab", "generate"}},
		{"user scope", []string{"user", "scope", "alice", "list"}, []string{"user", "scope", "alice", "add", "dmz"}},
		{"config loglevel", []string{"config", "loglevel"}, []string{"config", "loglevel", "debug"}},
		{"console idle-timeout", []string{"console", "idle-timeout"}, []string{"console", "idle-timeout", "30"}},
		{"device port", []string{"device", "port", "lab-sw"}, []string{"device", "port", "lab-sw", "2222"}},
		{"device description", []string{"device", "description", "lab-sw"}, []string{"device", "description", "lab-sw", "the", "lab", "switch"}},
		{"device legacy-ssh", []string{"device", "legacy-ssh", "lab-sw"}, []string{"device", "legacy-ssh", "lab-sw", "enable"}},
		{"device vendor", []string{"device", "vendor", "lab-sw"}, []string{"device", "vendor", "lab-sw", "juniper"}},
		{"device stale-days", []string{"device", "stale-days"}, []string{"device", "stale-days", "9"}},
		{"scope snmp", []string{"scope", "snmp", "lab", "show"}, []string{"scope", "snmp", "lab", "port", "1161"}},
		{"config allow", []string{"config", "allow", "list"}, []string{"config", "allow", "add", "10.9.0.0/16"}},
		{"config mgmt-acl", []string{"config", "mgmt-acl", "list"}, []string{"config", "mgmt-acl", "add", "10.7.0.0/16"}},
		{"config password-age", []string{"config", "password-age"}, []string{"config", "password-age", "100"}},
		{"config metrics", []string{"config", "metrics", "show"}, []string{"config", "metrics", "address", "127.0.0.1:9100"}},
		{"config snmp", []string{"config", "snmp", "show"}, []string{"config", "snmp", "port", "1161"}},
		{"config cisco", []string{"config", "cisco", "--scope", "lab"}, []string{"config", "cisco", "source-interface", "lab", "Loopback0"}},
		{"console tiers", []string{"console", "tiers"}, []string{"console", "tiers", "operator", "enable"}},
		{"console user", []string{"console", "user", "bob"}, []string{"console", "user", "bob", "enable"}},
		{"console system-shell", []string{"console", "system-shell", "tiers"}, []string{"console", "system-shell", "tiers", "superuser"}},
		{"group commands", []string{"group", "commands", "list", "operator"}, []string{"group", "commands", "default", "operator", "deny"}},
		{"group privilege", []string{"group", "privilege", "list", "operator"}, []string{"group", "privilege", "add", "operator", "exec: show"}},
		{"group reset", []string{"group", "reset", "operator", "--preset", "--dry-run"}, []string{"group", "reset", "operator", "--preset", "--yes"}},
		{"scope netconf", []string{"scope", "netconf", "lab"}, []string{"scope", "netconf", "lab", "enable"}},
		{"scope breakglass", []string{"scope", "breakglass", "lab", "list"}, []string{"scope", "breakglass", "lab", "add", "labadmin"}},
		{"scope mgmt-acl", []string{"scope", "mgmt-acl", "lab", "list"}, []string{"scope", "mgmt-acl", "lab", "add", "10.1.1.1/32"}},
		{"device hostname", []string{"device", "hostname", "lab-sw"}, []string{"device", "hostname", "lab-sw", "lab-sw.example.net"}},
		{"device location", []string{"device", "location", "lab-sw"}, []string{"device", "location", "lab-sw", "rack 9"}},
		{"device config-syntax", []string{"device", "config-syntax", "lab-sw2"}, []string{"device", "config-syntax", "lab-sw2", "ios12"}},
		{"device snmp", []string{"device", "snmp", "lab-sw", "show"}, []string{"device", "snmp", "lab-sw", "port", "1161"}},
		{"host default-method", []string{"host", "default-method"}, []string{"host", "default-method", "tacplus"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb.asAlice("", c.read...)
			if sb.code != 0 || len(centralLines(sb.runner)) != 0 {
				t.Errorf("read %v: exit %d %q, lines %q", c.read, sb.code, sb.stderr(), centralLines(sb.runner))
			}
			sb.asAlice("", c.write...)
			lines := centralLines(sb.runner)
			if sb.code != 0 || len(lines) != 2 ||
				!strings.HasPrefix(lines[0], "cmd start v=1 user=alice ") || !strings.Contains(lines[0], ` cmd="`+c.name+`" `) ||
				!strings.HasPrefix(lines[1], `cmd end v=1 user=alice cmd="`+c.name+`" result=ok status=0 `) {
				t.Errorf("write %v: exit %d %q, lines %q", c.write, sb.code, sb.stderr(), lines)
			}
			if sid, ok := auditSID(sb.runner); !ok || sid == "" {
				t.Errorf("sid %q shared %v", sid, ok)
			}
		})
	}
}

// Commands of class read write no central line.
func TestReadCommandsWriteNoCentralLine(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{{"user", "list"}, {"user", "show", "alice"}, {"scope", "show", "lab"}, {"scope", "list"},
		{"group", "list"}, {"version"}, {"config", "get", "backends.enabled"}, {"device", "list"}, {"host", "list"}, {"user"}, {"frobnicate"}} {
		sb.asAlice("", args...)
		if len(centralLines(sb.runner)) != 0 {
			t.Errorf("%v: %q", args, centralLines(sb.runner))
		}
	}
}

// A secret on the command line is <redacted> in args=: the value of a flag
// marked Secret, the positional after 'scope secret <scope> set'.
func TestCentralLinesRedactSecrets(t *testing.T) {
	sb := newSandbox(t, true)
	const secret = "marker-secret-0123456789abcdef"
	sb.asAlice("", "scope", "secret", "lab", "set", secret)
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if got := centralLines(sb.runner)[0]; !strings.HasSuffix(got, ` cmd="scope secret" args="lab set <redacted>"`) {
		t.Errorf("start %s", got)
	}
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab")
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if got := centralLines(sb.runner)[0]; !strings.HasSuffix(got, ` cmd="user add" args="dave operator --hash <redacted> --scopes lab"`) {
		t.Errorf("start %s", got)
	}
	sb.asAlice("", "user", "passwd", "dave", "--hash="+testHash)
	if got := centralLines(sb.runner)[0]; !strings.HasSuffix(got, ` cmd="user passwd" args="dave --hash=<redacted>"`) {
		t.Errorf("start %s", got)
	}
	sb.asAlice("", "scope", "add", "x1", "--prefixes", "10.77.0.0/16", "--secret", secret)
	for _, c := range sb.runner.Calls() {
		if c.Name == "logger" && (strings.Contains(strings.Join(c.Args, " "), secret) || strings.Contains(strings.Join(c.Args, " "), testHash)) {
			t.Errorf("a secret reached logger: %q", c.Args)
		}
	}
	if got := centralLines(sb.runner)[0]; !strings.HasSuffix(got, ` cmd="scope add" args="x1 --prefixes 10.77.0.0/16 --secret <redacted>"`) {
		t.Errorf("start %s", got)
	}
}

// A long command line is kept to 512 bytes, each word to 64.
func TestCentralLinesCapTheArguments(t *testing.T) {
	sb := newSandbox(t, true)
	long := strings.Repeat("a", 100)
	sb.asAlice("", "user", "disable", long)
	got := centralLines(sb.runner)[0]
	if !strings.HasSuffix(got, ` cmd="user disable" args=`+strings.Repeat("a", 64)+`...`) {
		t.Errorf("start %s", got)
	}
}

// A refusal inside a verb is the typed denial: the message and the status
// are as they were, the line is cmd DENY at auth.warning with the reason,
// and a verb that wrote nothing has no start and no end line.
func TestInVerbDenialWritesTheDenyLine(t *testing.T) {
	sb := engineerSandbox(t)
	const secret = "marker-secret-0123456789abcdef"
	sb.asEngineer("", "scope", "secret", "lab", "set", secret)
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads a scope's secret: tacctl scope secret lab show. Changing it is the superuser's. Nothing was changed.") {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	const deny = `cmd DENY v=1 user=bob uid=- tier=engineer cmd="scope secret" args="lab set <redacted>" reason=superuser`
	if !hasAudit(sb.runner, "auth.warning", deny) || len(centralLines(sb.runner)) != 1 {
		t.Errorf("lines %q, want %s alone", centralLines(sb.runner), deny)
	}
	for _, c := range sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), secret) {
			t.Errorf("the secret reached logger: %q", c.Args)
		}
	}
	// A device in another scope: the same message as one that is not there.
	sb.asEngineer("", "device", "port", "prod-sw", "2222")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found.") ||
		!hasAudit(sb.runner, "auth.warning", `cmd DENY v=1 user=bob uid=- tier=engineer cmd="device port" args="prod-sw 2222" reason=scope`) {
		t.Errorf("scope: exit %d %q, lines %q", sb.code, sb.stderr(), centralLines(sb.runner))
	}
	// A device that does not exist is not a denial.
	sb.asEngineer("", "device", "port", "nosuch", "2222")
	if sb.code != 1 || len(centralLines(sb.runner)) != 0 {
		t.Errorf("not found: exit %d, lines %q", sb.code, centralLines(sb.runner))
	}
}

// A refusal by the gate keeps its words and has the session id; it writes no
// central line (the command never started).
func TestGateDenialWritesNoCentralLine(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"user", "remove", "bob"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}, "SUDO_USER=carol", "SUDO_UID=1002")
	if sb.code != 1 || !hasAudit(sb.runner, "auth.warning", "tier DENY user=carol tier=readonly cmd=user remove") || len(centralLines(sb.runner)) != 0 {
		t.Errorf("exit %d, lines %q", sb.code, auditLines(sb.runner))
	}
}

// auditInv is an invocation of args on the sandbox's state, for the tests of
// the dispatcher itself.
func (sb *sandbox) auditInv(args []string, extraEnv ...string) (*invocation, *app.App) {
	sb.t.Helper()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	sb.runner.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(sb.runner)
	a := app.New(args, paths.NewEnv(append(append([]string(nil), sb.env...), extraEnv...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, sb.runner)
	a.Paths = a.Paths.Reroot(sb.dir)
	a.SetContext(sb.runCtx())
	inv := &invocation{ctx: sb.runCtx(), app: a, hooks: sb.hooks}
	inv.root = newRoot(inv)
	return inv, a
}

// The end line says how the command ended: interrupted for 130, denied for
// the gate's refusal, aborted (status 2) when the command panicked.
func TestCentralEndResults(t *testing.T) {
	for _, c := range []struct {
		name   string
		run    func(inv *invocation) error
		result string
		status string
	}{
		{"interrupted", func(*invocation) error { return ui.ErrInterrupted }, "interrupted", "130"},
		{"reported", func(*invocation) error { return ui.ErrReported }, "failed", "1"},
		{"exit code", func(*invocation) error { return exit(3) }, "failed", "3"},
		{"ok", func(*invocation) error { return nil }, "ok", "0"},
		{"denied", func(inv *invocation) error { return inv.denied(reasonSuperuser, exit(1)) }, "denied", "1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := newSandbox(t, true)
			inv, a := sb.auditInv([]string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001")
			err := inv.dispatch(func() error {
				if err := inv.prelude(withPreflight); err != nil {
					t.Fatal(err)
				}
				return c.run(inv)
			})
			_ = err
			lines := centralLines(sb.runner)
			if len(lines) < 2 {
				t.Fatalf("lines %q", lines)
			}
			if want := regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=` + c.result + ` status=` + c.status + ` `); !want.MatchString(lines[len(lines)-1]) {
				t.Errorf("end %s", lines[len(lines)-1])
			}
			_ = a
		})
	}
}

// A panic in the command leaves an end line (result=aborted, status 2) and
// goes on.
func TestCentralEndOfAPanic(t *testing.T) {
	sb := newSandbox(t, true)
	inv, _ := sb.auditInv([]string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001")
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Errorf("recovered %v, want the panic to go on", r)
			}
		}()
		_ = inv.dispatch(func() error {
			if err := inv.prelude(withPreflight); err != nil {
				t.Fatal(err)
			}
			panic("boom")
		})
	}()
	lines := centralLines(sb.runner)
	if len(lines) != 2 || !regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=aborted status=2 `).MatchString(lines[1]) {
		t.Errorf("lines %q", lines)
	}
}

// The end line is written with the invocation's context cancelled, as a
// signal leaves it: the writer's context takes no cancellation (D244).
func TestCentralEndAfterACancelledContext(t *testing.T) {
	sb := newSandbox(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	sb.ctx = ctx
	inv, _ := sb.auditInv([]string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001")
	_ = inv.dispatch(func() error {
		if err := inv.prelude(withPreflight); err != nil {
			return err
		}
		cancel() // SIGINT: the invocation's context is over
		return ui.ErrInterrupted
	})
	if lines := centralLines(sb.runner); len(lines) != 2 || !strings.Contains(lines[1], " result=interrupted status=130 ") {
		t.Errorf("lines %q", lines)
	}
}

// A command classified read that reaches a write is a classification bug:
// the test binary panics there, a production one writes the start line with
// class=unexpected (D249, D255 4).
func TestReadCommandReachingAWritePanics(t *testing.T) {
	sb := newSandbox(t, true)
	inv, _ := sb.auditInv([]string{"user", "list"}, "SUDO_USER=alice", "SUDO_UID=1001")
	if err := inv.prelude(withPreflight); err != nil {
		t.Fatal(err)
	}
	if lines := centralLines(sb.runner); len(lines) != 0 {
		t.Fatalf("a read wrote %q", lines)
	}
	func() {
		defer func() {
			if r := recover(); r == nil || !strings.Contains(r.(string), "'user list' is classified read") {
				t.Errorf("recovered %v", r)
			}
		}()
		_ = inv.storeApply(func(*store.Store) error { return nil })
	}()
	lines := centralLines(sb.runner)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "cmd start v=1 ") || !strings.HasSuffix(lines[0], " class=unexpected") {
		t.Errorf("lines %q", lines)
	}
	if c := auditCalls(sb.runner); c[len(c)-1].Priority != "auth.warning" {
		t.Errorf("at %s", c[len(c)-1].Priority)
	}
}

// Touch is idempotent: the start line is written once however many write
// choke points the command reaches.
func TestTouchWritesTheStartOnce(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "scope", "prefixes", "lab", "add", "10.201.0.0/16")
	n := 0
	for _, l := range centralLines(sb.runner) {
		if strings.HasPrefix(l, "cmd start ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("start lines %d in %q", n, centralLines(sb.runner))
	}
}

// A logger that is missing does not change the status of the command or
// stop its lines from being tried (D248).
func TestCentralLinesWithoutLogger(t *testing.T) {
	sb := newSandbox(t, true)
	sb.script = func(r *fake.Runner) { r.Missing("logger") }
	sb.asAlice("", "user", "disable", "bob")
	if sb.code != 0 || strings.Count(sb.stderr(), "The audit line was not written (logger: not found)") != 1 {
		t.Errorf("exit %d %q", sb.code, sb.stderr())
	}
}

// An end line is written at most once: the self-update's hand-over writes it
// before the exec, and an exec that fails does not write a second.
func TestCentralEndIsWrittenOnce(t *testing.T) {
	sb := newSandbox(t, true)
	inv, _ := sb.auditInv([]string{"upgrade"}, "SUDO_USER=alice", "SUDO_UID=1001")
	_ = inv.dispatch(func() error {
		if err := inv.prelude(noPreflight); err != nil {
			return err
		}
		inv.lifecycleHost().BeforeExec() // the hand-over, then the exec fails
		return &backend.Error{Code: 126, Reason: "exec"}
	})
	lines := centralLines(sb.runner)
	if len(lines) != 2 || !strings.HasPrefix(lines[1], `cmd end v=1 user=alice cmd=upgrade result=ok status=0 `) {
		t.Errorf("lines %q, want the start and one end", lines)
	}
}

// 'device add --pull' refused for the tier is the typed denial. The gate's
// row for 'device add' (engineer) already implies the pull's tier, so the
// check is asked directly for a caller below it.
func TestDeviceAddPullRefusalIsADenial(t *testing.T) {
	sb := newSandbox(t, true)
	inv, _ := sb.auditInv([]string{"device", "add", "x1", "192.168.1.77", "--pull"}, "SUDO_USER=carol")
	sb.runner.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	p, err := Parse(deviceSpecs["add"], []string{"x1", "192.168.1.77", "--pull"})
	if err != nil {
		t.Fatal(err)
	}
	err = inv.deviceAddPullCheck(p)
	var de *deniedError
	if !errors.As(err, &de) || de.Reason != reasonSuperuser || !strings.Contains(sb.stderr(), "--pull runs 'tacctl device config pull', which is not permitted for the readonly tier.") {
		t.Errorf("err %v, stderr %q", err, sb.stderr())
	}
}

// A scope an engineer does not have is a denial when it exists and a plain
// refusal when it is a typo.
func TestScopeRefusalIsADenialOnlyForAScopeThatExists(t *testing.T) {
	sb := engineerSandbox(t)
	sb.asEngineer("", "scope", "snmp", "prod", "show")
	if sb.code != 1 || !hasAudit(sb.runner, "auth.warning", `cmd DENY v=1 user=bob uid=- tier=engineer cmd="scope snmp" args="prod show" reason=scope`) {
		t.Errorf("existing foreign scope: exit %d, lines %q", sb.code, auditLines(sb.runner))
	}
	sb.asEngineer("", "scope", "snmp", "nosuchscope", "show")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'nosuchscope' does not exist.") || hasAuditPrefix(sb.runner, "", "cmd DENY") {
		t.Errorf("typo: exit %d %q, lines %q", sb.code, sb.stderr(), auditLines(sb.runner))
	}
}
