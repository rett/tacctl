package cli

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// audit.strict and the verbs that show a secret (docs/plans/0.2.17-plan.md
// D257, WP17.6b): a reveal whose secret-read line cannot be written is
// refused before any secret is printed; 'config audit-strict' sets the key
// and is never refused by it.

const strictRevealRefusal = "The audit line cannot be written (logger: %s) and audit.strict is set; nothing was shown."

// revealSandbox is a sandbox whose scope lab, SNMP default, scope and device
// credentials hold markers, with the device lab-sw1.
func revealSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	for _, c := range []struct {
		stdin string
		args  []string
	}{
		{"", []string{"scope", "secret", "lab", "set", markerSecret}},
		{markerSecret2 + "\n", []string{"config", "snmp", "community", "--stdin"}},
		{markerSecret2 + "\n", []string{"scope", "snmp", "lab", "community", "--stdin"}},
		{markerSecret2 + "\n", []string{"device", "snmp", "lab-sw1", "community", "--stdin"}},
	} {
		sb.asAlice(c.stdin, c.args...)
		if sb.code != 0 {
			t.Fatalf("%v: exit %d %q", c.args, sb.code, sb.stderr())
		}
	}
	return sb
}

// revealCases are the verbs that show a secret, with the secret-read line
// each writes (by=alice). backup diff is added with the snapshot's id.
var revealCases = []struct {
	args []string
	line string
}{
	{[]string{"scope", "secret", "lab", "show"}, "secret-read kind=scope name=lab by=alice"},
	{[]string{"config", "cisco", "--scope", "lab"}, "secret-read kind=scope name=lab by=alice"},
	{[]string{"config", "juniper", "--scope", "lab"}, "secret-read kind=scope name=lab by=alice"},
	{[]string{"config", "wti", "--scope", "lab"}, "secret-read kind=scope name=lab by=alice"},
	{[]string{"device", "config", "show", "lab-sw1"}, "secret-read kind=scope name=lab by=alice"},
	{[]string{"scope", "snmp", "lab", "show", "--reveal"}, "secret-read kind=snmp name=lab by=alice"},
	{[]string{"config", "snmp", "show", "--reveal"}, "secret-read kind=snmp-default name=default by=alice"},
	{[]string{"device", "snmp", "lab-sw1", "show", "--reveal"}, "secret-read kind=snmp-device name=lab-sw1 by=alice"},
	{[]string{"store", "show"}, "secret-read kind=store name=model by=alice"},
	{[]string{"config", "dump"}, "secret-read kind=config name=dump by=alice"},
}

// noMarker fails the test when the run's stdout or stderr holds a marker.
func noMarker(t *testing.T, what string, sb *sandbox) {
	t.Helper()
	for _, m := range []string{markerSecret, markerSecret2} {
		if strings.Contains(sb.out.String(), m) || strings.Contains(sb.err.String(), m) {
			t.Errorf("%s: the secret %q was printed: stdout %q stderr %q", what, m, sb.out.String(), sb.err.String())
		}
	}
}

// With audit.strict and a logger that cannot write, every reveal is refused
// before anything is printed: exit 1, the one refusal line on stderr, no
// secret on either stream, no D248 warning beside it, nothing written. With
// a logger that works the same verbs run and write their secret-read line;
// without audit.strict a logger that cannot write is the warning and the
// secret is shown, as before.
func TestStrictRefusesARevealWhoseLineCannotBeWritten(t *testing.T) {
	sb := revealSandbox(t)
	sb.asAlice("", "user", "disable", "bob")
	id := sb.snapshotID()
	cases := append(revealCases[:len(revealCases):len(revealCases)], struct {
		args []string
		line string
	}{[]string{"backup", "diff", id}, "secret-read kind=snapshot name=" + id + " by=alice"})
	missing := func(r *fake.Runner) { r.Missing("logger") }
	refused := func(r *fake.Runner) {
		r.Fail([]string{"logger"}, 1, "logger: socket /dev/log: Connection refused")
	}
	for _, c := range cases {
		name := strings.Join(c.args, " ")
		// Strict off, logger down: unchanged (the warning, the secret shown).
		sb.script = missing
		sb.asAlice("", c.args...)
		if sb.code != 0 || !strings.Contains(sb.stderr(), "The audit line was not written (logger: not found); the command continues.") ||
			strings.Contains(sb.stderr(), "audit.strict") || strings.TrimSpace(sb.out.String()) == "" {
			t.Errorf("%s, strict off: exit %d %q", name, sb.code, sb.stderr())
		}

		sb.strictOn()
		// Strict, logger working: runs, and the line is written.
		sb.script = nil
		sb.asAlice("", c.args...)
		if sb.code != 0 || !hasAudit(sb.runner, "auth.info", c.line) || strings.Contains(sb.stderr(), "audit") {
			t.Errorf("%s, strict with logger: exit %d %q lines %q", name, sb.code, sb.stderr(), auditLines(sb.runner))
		}
		for _, s := range []struct {
			script func(*fake.Runner)
			reason string
		}{{missing, "not found"}, {refused, "exit status 1: logger: socket /dev/log: Connection refused"}} {
			sb.script = s.script
			before := tree(t, sb.dir)
			sb.asAlice("", c.args...)
			e := plain(sb.stderr())
			if sb.code != 1 || !strings.Contains(e, "[ERROR] "+fmt.Sprintf(strictRevealRefusal, s.reason)) {
				t.Errorf("%s, strict without logger (%s): exit %d %q", name, s.reason, sb.code, e)
			}
			if strings.Contains(e, "the command continues") {
				t.Errorf("%s: the D248 warning beside the refusal: %q", name, e)
			}
			if strings.TrimSpace(plain(sb.out.String())) != "" {
				t.Errorf("%s: printed %q", name, sb.out.String())
			}
			noMarker(t, name, sb)
			noLoggerHas(t, name, sb.runner, markerSecret, markerSecret2)
			if after := tree(t, sb.dir); !reflect.DeepEqual(before, after) {
				t.Errorf("%s: the refused reveal changed %q", name, changedFiles(before, after))
			}
		}
		sb.script = nil
		if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil {
			t.Fatal(err)
		}
	}
}

// The refusal holds for every caller tier: an engineer's reveal of a scope
// of their own is refused as a superuser's is.
func TestStrictRefusesAnEngineersReveal(t *testing.T) {
	sb := engineerSandbox(t)
	sb.asAlice("", "scope", "secret", "lab", "set", markerSecret)
	if sb.code != 0 {
		t.Fatalf("set: exit %d %q", sb.code, sb.stderr())
	}
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\naudit:\n  strict: true\n", 0o600)
	asBob := func(args []string, logger bool) {
		sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
			if !logger {
				r.Missing("logger")
			}
		}, "SUDO_USER=bob")
	}
	for _, args := range [][]string{{"scope", "secret", "lab", "show"}, {"config", "cisco", "--scope", "lab"}} {
		name := strings.Join(args, " ")
		asBob(args, false)
		if sb.code != 1 || !strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRevealRefusal, "not found")) {
			t.Errorf("%s: exit %d %q", name, sb.code, sb.stderr())
		}
		if strings.TrimSpace(plain(sb.out.String())) != "" {
			t.Errorf("%s: printed %q", name, sb.out.String())
		}
		noMarker(t, name, sb)
		asBob(args, true)
		if sb.code != 0 || !hasAudit(sb.runner, "auth.info", "secret-read kind=scope name=lab by=bob") || !strings.Contains(sb.out.String(), markerSecret) {
			t.Errorf("%s with logger: exit %d %q %q", name, sb.code, sb.stderr(), auditLines(sb.runner))
		}
	}
}

// A refused reveal writes no central line, as the read it is writes none
// (and none could be written); a refused reveal inside a command that had
// already written its start line ends with result=failed when logger takes
// the end line.
func TestStrictRevealRefusalLines(t *testing.T) {
	sb := revealSandbox(t)
	sb.strictOn()
	sb.script = func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), "secret-read") {
				return execx.Result{Code: 1, Stderr: []byte("busy")}, nil
			}
			return execx.Result{}, nil
		})
	}
	sb.asAlice("", "scope", "secret", "lab", "show")
	if sb.code != 1 || !strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRevealRefusal, "exit status 1: busy")) {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if lines := centralLines(sb.runner); len(lines) != 0 {
		t.Errorf("central lines %q", lines)
	}
	noMarker(t, "scope secret show", sb)
}

// The refusal and every line around it hold no secret.
func TestStrictRevealRefusalHoldsNoSecret(t *testing.T) {
	sb := revealSandbox(t)
	sb.strictOn()
	sb.script = func(r *fake.Runner) { r.Fail([]string{"logger"}, 1, "logger: "+markerSecret2) }
	for _, c := range revealCases {
		sb.asAlice("", c.args...)
		name := strings.Join(c.args, " ")
		if sb.code != 1 || strings.Contains(sb.stderr(), markerSecret) || strings.Contains(sb.out.String(), markerSecret) {
			t.Errorf("%s: exit %d %q %q", name, sb.code, sb.out.String(), sb.stderr())
		}
		noLoggerHas(t, name, sb.runner, markerSecret)
	}
}

// --- config audit-strict ---

// 'config audit-strict' shows the value and where it comes from; on writes
// the key, off removes it (the default); a wrong word is refused with the
// usage; each change is the central pair and its detail line at auth.notice.
func TestConfigAuditStrict(t *testing.T) {
	sb := newSandbox(t, true)
	yaml := func() string {
		b, err := os.ReadFile(sb.path("state", "tacctl.yaml"))
		if err != nil {
			return ""
		}
		return string(b)
	}
	out := sb.asAlice("", "config", "audit-strict")
	if sb.code != 0 || !strings.Contains(out, "Audit strict: off   (default)") || len(centralLines(sb.runner)) != 0 {
		t.Fatalf("show: exit %d %q %q", sb.code, out, centralLines(sb.runner))
	}
	sb.asAlice("", "config", "audit-strict", "on")
	if sb.code != 0 || !strings.Contains(sb.stderr()+sb.out.String(), "audit.strict is on") || !strings.Contains(yaml(), "audit:\n  strict: true\n") {
		t.Fatalf("on: exit %d %q file %q", sb.code, sb.stderr(), yaml())
	}
	lines := centralLines(sb.runner)
	if len(lines) != 2 || !strings.Contains(lines[0], `cmd="config audit-strict" args=on`) ||
		!hasAudit(sb.runner, "auth.notice", "config audit-strict from=off to=on by=alice") {
		t.Errorf("on lines %q", auditLines(sb.runner))
	}
	if out := sb.asAlice("", "config", "audit-strict"); !strings.Contains(out, "Audit strict: on   (tacctl.yaml)") {
		t.Errorf("show on: %q", out)
	}
	if v := sb.asAlice("", "config", "get", "audit.strict"); strings.TrimSpace(v) != "true" {
		t.Errorf("config get: %q", v)
	}
	sb.asAlice("", "config", "audit-strict", "off")
	if sb.code != 0 || strings.Contains(yaml(), "audit") || !hasAudit(sb.runner, "auth.notice", "config audit-strict from=on to=off by=alice") {
		t.Errorf("off: exit %d %q file %q lines %q", sb.code, sb.stderr(), yaml(), auditLines(sb.runner))
	}
	for _, bad := range [][]string{{"yes"}, {"true"}, {"on", "now"}} {
		before := yaml()
		sb.asAlice("", append([]string{"config", "audit-strict"}, bad...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Usage: tacctl config audit-strict [on|off]") || yaml() != before {
			t.Errorf("%q: exit %d %q", bad, sb.code, sb.stderr())
		}
	}
	// A value the schema would refuse, written by hand, reads as off.
	sb.write("state/tacctl.yaml", "audit:\n  strict: \"true\"\n", 0o640)
	if out := sb.asAlice("", "config", "audit-strict"); !strings.Contains(out, "Audit strict: off   (tacctl.yaml holds a value that is not true or false") {
		t.Errorf("show invalid: %q", out)
	}
}

// 'config audit-strict' is never refused by audit.strict: with logger down
// and strict on, every other change is refused, and 'config audit-strict
// off' turns it off (with the D248 warning, the lines being lost); 'on' runs
// too. Afterwards the other change runs again.
func TestConfigAuditStrictIsTheWayOut(t *testing.T) {
	sb := newSandbox(t, true)
	sb.strictOn()
	sb.script = func(r *fake.Runner) { r.Missing("logger") }
	sb.asAlice("", "user", "disable", "bob")
	if sb.code != 1 || !strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRefusal, "not found")) {
		t.Fatalf("user disable: exit %d %q", sb.code, sb.stderr())
	}
	for _, v := range []string{"on", "off"} {
		sb.asAlice("", "config", "audit-strict", v)
		e := plain(sb.stderr())
		if sb.code != 0 || strings.Contains(e, "audit.strict is set") ||
			strings.Count(e, "The audit line was not written (logger: not found); the command continues.") != 1 {
			t.Errorf("audit-strict %s: exit %d %q", v, sb.code, e)
		}
	}
	if b, err := os.ReadFile(sb.path("state", "tacctl.yaml")); err == nil && strings.Contains(string(b), "audit") {
		t.Errorf("tacctl.yaml after off: %q", b)
	}
	sb.asAlice("", "user", "disable", "bob")
	if sb.code != 0 {
		t.Errorf("user disable after off: exit %d %q", sb.code, sb.stderr())
	}
}

// The verb is a mixed one, weighty and exempt from audit.strict; the other
// rows are not exempt.
func TestOnlyConfigAuditStrictIsExempt(t *testing.T) {
	parallel(t)
	for k, e := range auditTable {
		if e.NotStrict != (k == "config audit-strict") {
			t.Errorf("%q: NotStrict %v", k, e.NotStrict)
		}
	}
	if e := auditTable["config audit-strict"]; e.Class != classMixed || !e.isNotice(nil) {
		t.Errorf("config audit-strict: %+v", e)
	}
}

// strictAdd turns audit.strict on beside what the sandbox's tacctl.yaml holds
// (strictOn replaces the file).
func (sb *sandbox) strictAdd() {
	sb.t.Helper()
	text := ""
	if b, err := os.ReadFile(sb.path("state", "tacctl.yaml")); err == nil {
		text = string(b)
	}
	sb.write("state/tacctl.yaml", text+"audit:\n  strict: true\n", 0o640)
}

// failLines makes logger fail the lines that contain word (and write the
// others).
func failLines(word string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), word) {
				return execx.Result{Code: 1, Stderr: []byte("busy")}, nil
			}
			return execx.Result{}, nil
		})
	}
}

// pulledBox is a pull box with lab-j pulled and an SNMP community set for
// scope lab.
func pulledBox(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: exit %d %q", b.sb.code, b.sb.stderr())
	}
	b.sb.cfgRun(markerSecret2+"\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, nil, "SUDO_USER=alice")
	if b.sb.code != 0 {
		t.Fatalf("community: exit %d %q", b.sb.code, b.sb.stderr())
	}
	return b
}

// The device config verbs that build a render only to compare it or that
// elide the secrets print none: their secret-read lines (the SNMP
// credentials of the scope here) are uses, not reveals. With audit.strict and
// logger down 'device config list' (an operator's and the superuser's) and
// 'diff' run, the superuser's with the D248 warning of the lost line.
func TestStrictLetsTheManagedRendersRun(t *testing.T) {
	b := pulledBox(t)
	// With a logger that works, list and diff write the line of the SNMP read.
	for _, args := range [][]string{{"device", "config", "list"}, {"device", "config", "diff", "lab-j"}} {
		b.run(args...)
		if b.sb.code != 0 || !hasAuditPrefix(b.sb.runner, "auth.info", "secret-read kind=snmp name=lab") {
			t.Fatalf("%v with logger: exit %d %q", args, b.sb.code, auditLines(b.sb.runner))
		}
	}
	b.sb.strictAdd()
	run := func(args []string, env string, id func(*fake.Runner)) string {
		b.sb.cfgRun("", args, func(r *fake.Runner) {
			route(r)
			if id != nil {
				id(r)
			}
			r.Missing("logger")
		}, env)
		return plain(b.sb.stderr())
	}
	const lost = "The audit line was not written (logger: not found); the command continues."
	if e := run([]string{"device", "config", "list"}, "SUDO_USER=bob", idAs("bob", "tac-users tac-operator")); b.sb.code != 0 || strings.Contains(e, "audit.strict is set") {
		t.Errorf("operator's list: exit %d %q", b.sb.code, e)
	}
	for _, args := range [][]string{{"device", "config", "list"}, {"device", "config", "diff", "lab-j"}} {
		e := run(args, "SUDO_USER=alice", nil)
		if b.sb.code != 0 || strings.Contains(e, "audit.strict is set") || strings.Count(e, lost) != 1 {
			t.Errorf("%v: exit %d %q", args, b.sb.code, e)
		}
	}
}

// 'device config plan' prints the secrets of its region (the values, unless
// --no-secrets): its reads are reveals. With audit.strict and logger down it
// is refused before anything is shown; with --no-secrets its reads are uses,
// and it is refused by the start line of its store write, as any write is.
// Without strict it runs, writing its secret-read lines.
func TestStrictPlanRevealsUnlessNoSecrets(t *testing.T) {
	b := pulledBox(t)
	b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 || !hasAuditPrefix(b.sb.runner, "auth.info", "secret-read kind=snmp name=lab") {
		t.Fatalf("plan with logger: exit %d %q", b.sb.code, auditLines(b.sb.runner))
	}
	b.sb.strictAdd()
	down := func(args ...string) string {
		out := b.sb.cfgRun("", args, func(r *fake.Runner) { route(r); r.Missing("logger") }, "SUDO_USER=alice")
		return plain(out)
	}
	out := down("device", "config", "plan", "lab-j")
	if b.sb.code != 1 || !strings.Contains(plain(b.sb.stderr()), fmt.Sprintf(strictRevealRefusal, "not found")) {
		t.Errorf("plan: exit %d %q", b.sb.code, b.sb.stderr())
	}
	if strings.TrimSpace(out) != "" || strings.Contains(b.sb.stderr(), markerSecret2) || strings.Contains(b.sb.stderr(), "the command continues") {
		t.Errorf("plan printed %q %q", out, b.sb.stderr())
	}
	down("device", "config", "plan", "lab-j", "--no-secrets")
	if e := plain(b.sb.stderr()); b.sb.code != 1 || !strings.Contains(e, fmt.Sprintf(strictRefusal, "not found")) || strings.Contains(e, "nothing was shown") {
		t.Errorf("plan --no-secrets: exit %d %q", b.sb.code, e)
	}
	// The reveal line alone failing: the plan is refused before it prints.
	out = plain(b.sb.cfgRun("", []string{"device", "config", "plan", "lab-j"}, func(r *fake.Runner) { route(r); failLines("secret-read")(r) }, "SUDO_USER=alice"))
	if b.sb.code != 1 || strings.TrimSpace(out) != "" || !strings.Contains(plain(b.sb.stderr()), fmt.Sprintf(strictRevealRefusal, "exit status 1: busy")) {
		t.Errorf("plan, secret-read failing: exit %d %q %q", b.sb.code, out, b.sb.stderr())
	}
}

// 'block edit' opens the editor on the block in force: a reveal, logged
// before the editor opens; under audit.strict a line that cannot be written
// refuses before the editor runs.
func TestStrictRefusesABlockEditBeforeTheEditor(t *testing.T) {
	b := newEditBox(t)
	b.sb.blk("", "lab", "juniper", "set", "snmp", "--file", b.sb.blockFile("snmp.txt", verbSNMPFile), "-y")
	if b.sb.code != 0 {
		t.Fatal(b.sb.stderr())
	}
	ed := b.editor("ed-none", ":")
	b.edit("", ed, "snmp")
	if b.sb.code != 0 || b.ran() != 1 || !hasAuditPrefix(b.sb.runner, "auth.info", "secret-read kind=block name=lab/juniper/snmp ") {
		t.Fatalf("edit with logger: exit %d ran %d %q", b.sb.code, b.ran(), auditLines(b.sb.runner))
	}
	b.sb.strictAdd()
	for _, script := range []func(*fake.Runner){func(r *fake.Runner) { r.Missing("logger") }, failLines("secret-read")} {
		before := b.ran()
		out := b.runEnv("", ed, script, "scope", "block", "lab", "juniper", "edit", "snmp")
		e := plain(b.sb.stderr())
		if b.sb.code != 1 || b.ran() != before || !strings.Contains(e, "audit.strict is set; nothing was shown.") {
			t.Errorf("edit refused: exit %d ran %d->%d %q", b.sb.code, before, b.ran(), e)
		}
		noneOf(t, "refused edit", out+e, "nms-ro-secret", "nms-traps-secret")
	}
}

// The diff 'backup restore' and 'config restore' print is the snapshot's
// store, as 'backup diff' shows it: a reveal, logged before anything is
// printed and refused under audit.strict when its line cannot be written.
func TestStrictRefusesARestoreDiffWhoseLineCannotBeWritten(t *testing.T) {
	for _, verb := range [][]string{{"backup", "restore"}, {"config", "restore"}} {
		sb := hostsSandbox(t)
		args := append(verb, "20200101_000000_002")
		out := plain(sb.run("n\n", args, "SUDO_USER=alice"))
		if sb.code != 0 || !hasAudit(sb.runner, "auth.info", "secret-read kind=snapshot name=20200101_000000_002 by=alice") || !strings.Contains(out, "Restoring snapshot") {
			t.Errorf("%v with logger: exit %d %q", verb, sb.code, auditLines(sb.runner))
		}
		sb.strictAdd()
		sb.script = failLines("secret-read")
		out = plain(sb.run("n\n", args, "SUDO_USER=alice"))
		if sb.code != 1 || strings.Contains(out, "Restoring snapshot") || strings.Contains(out, "Diff") ||
			!strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRevealRefusal, "exit status 1: busy")) {
			t.Errorf("%v refused: exit %d %q %q", verb, sb.code, out, sb.stderr())
		}
	}
}

// 'config linux script' writes a file that holds the scope's secret: its
// secret-export line is written before the file, and under audit.strict a
// line that cannot be written refuses the script before it is written.
func TestStrictRefusesALinuxScriptWhoseLineCannotBeWritten(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxTarball(t, sb)
	script := sb.path("client.sh")
	args := []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", script}
	sb.cfgRun("", args, nil, "SUDO_USER=alice")
	lines := auditLines(sb.runner)
	if sb.code != 0 || len(lines) != 3 || !strings.HasPrefix(lines[0], "cmd start ") || !strings.HasPrefix(lines[1], "secret-export scope=lab file=") {
		t.Fatalf("with logger: exit %d %q", sb.code, lines)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	sb.strictAdd()
	sb.cfgRun("", args, failLines("secret-export"), "SUDO_USER=alice")
	if sb.code != 1 || !strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRevealRefusal, "exit status 1: busy")) {
		t.Errorf("refused: exit %d %q", sb.code, sb.stderr())
	}
	if _, err := os.Stat(script); err == nil {
		t.Error("the script was written")
	}
	// Without strict the line failing is the warning and the script is written.
	if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil {
		t.Fatal(err)
	}
	sb.cfgRun("", args, failLines("secret-export"), "SUDO_USER=alice")
	if _, err := os.Stat(script); sb.code != 0 || err != nil || !strings.Contains(sb.stderr(), "the command continues") {
		t.Errorf("strict off: exit %d %q %v", sb.code, sb.stderr(), err)
	}
}

// 'scope secret <s> generate' prints the value it generated: under
// audit.strict with logger down it is refused before the value is printed.
// Without strict the value is printed and set, as before.
func TestStrictGenerateRefusesBeforeTheValue(t *testing.T) {
	sb := newSandbox(t, true)
	sb.strictOn()
	sb.script = func(r *fake.Runner) { r.Missing("logger") }
	out := sb.asAlice("", "scope", "secret", "lab", "generate")
	if sb.code != 1 || strings.Contains(out, "Generated") || !strings.Contains(plain(sb.stderr()), fmt.Sprintf(strictRefusal, "not found")) {
		t.Errorf("strict: exit %d %q %q", sb.code, out, sb.stderr())
	}
	if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil {
		t.Fatal(err)
	}
	out = sb.asAlice("", "scope", "secret", "lab", "generate")
	if sb.code != 0 || !strings.Contains(out, "Generated: ") {
		t.Errorf("strict off: exit %d %q %q", sb.code, out, sb.stderr())
	}
}
