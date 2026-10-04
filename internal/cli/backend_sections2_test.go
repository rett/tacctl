package cli

// The report commands' per-backend sections (backend_cli.bats: status,
// config validate, config show, log, backup restore), with the stand-in of
// backend_sections_test.go; and the 'config validate' checks of
// migrate_dead_command_matches.bats and upgrade_store_flip.bats.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
)

// --- status -----------------------------------------------------------------------

// backend_cli.bats #43: each backend's lines in its own section, the
// report's own lines outside them.
func TestSectionsStatusEachBackendInItsSection(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	out := s.run("", "status")
	s.expect(0, "== Backend: tacacs (tacacs, tacquito) ==", "")
	s.expect(0, "== Backend: fake (fake, faked) ==", "")
	tac := between(out, "Backend: tacacs", "Backend: fake")
	fk := between(out, "Backend: fake", "Security Posture")
	gen := between(out, "Service Status", "Backend: tacacs")
	mustMatch(t, "the tacacs section", tac, `Config:.*tacquito\.yaml`)
	mustContain(t, "the tacacs section", tac, "Authentication Stats")
	mustNotContain(t, "the tacacs section", tac, "Fake ")
	mustMatch(t, "the fake section", fk, `Fake service:.*active`)
	mustContain(t, "the fake section", fk, "Fake config:", "Fake activity:")
	mustNotContain(t, "the fake section", fk, "tacquito.yaml", "Authentication Stats")
	mustContain(t, "the general part", gen, "Users:", "Config backups:")
	fkAt := strings.Index(out, "== Backend: fake")
	for _, w := range []string{"Security Posture:", "Password Age Warnings:"} {
		if i := strings.Index(out, w); i < fkAt {
			t.Errorf("%q is not after the backend sections:\n%s", w, out)
		}
	}
}

// backend_cli.bats #44: a hand edit of the stand-in's artifact is shown in
// its section, once, and not in the other's.
func TestSectionsStatusDriftInItsBackendsSectionOnce(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	appendFile(t, s.path("etc", "fake.conf"), "intruder\n")
	out := s.run("", "status")
	s.expect(0, "", "")
	if n := strings.Count(between(out, "Backend: fake", "Security Posture"), "DRIFT:"); n != 1 {
		t.Errorf("%d DRIFT lines in the fake section:\n%s", n, out)
	}
	if n := strings.Count(out, "DRIFT"); n != 1 {
		t.Errorf("the drift is reported %d times:\n%s", n, out)
	}
	mustNotContain(t, "the tacacs section", between(out, "Backend: tacacs", "Backend: fake"), "DRIFT")
}

// backend_cli.bats #46: with one backend the IPv6 parity line names no
// backend.
func TestSectionsStatusOneBackendIPv6ParityWording(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.run("y\n", "config", "listen", "tcp6", "[::]:49")
	s.expect(0, "", "")
	out := s.run("", "status")
	s.expect(0, "", "")
	mustContain(t, "status", out,
		"IPv6 ACL parity:    MISSING (listener is tcp6 but no IPv6 CIDRs — v4-mapped clients bypass ACLs)")
	mustNotContain(t, "status", out, "== Backend")
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// --- config validate ----------------------------------------------------------------

// backend_cli.bats #47: one backend, plain lines, no block heading.
func TestSectionsValidateOneBackendNoBlock(t *testing.T) {
	s := newSectionsSandbox(t, true)
	out := s.run("", "config", "validate")
	s.expect(0, "", "")
	mustMatch(t, "validate", out, `Rendered config:.* up to date`)
	mustNotContain(t, "validate", s.all(), "Backend ")
}

// backend_cli.bats #48: a block per backend; the stand-in's drift in its
// block, the other block still up to date, one error counted.
func TestSectionsValidateABlockPerBackendDrift(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	appendFile(t, s.path("etc", "fake.conf"), "intruder\n")
	out := s.run("", "config", "validate")
	s.expect(1, "Backend tacacs:", "Validation failed with 1 error(s).")
	s.expect(1, "Backend fake:", "")
	tac := between(out, "Backend tacacs:", "Backend fake:")
	fk := between(out, "Backend fake:", "Groups defined")
	mustMatch(t, "the tacacs block", tac, `Rendered config:.*up to date`)
	mustNotContain(t, "the tacacs block", tac, "DRIFT")
	mustMatch(t, "the fake block", fk, `DRIFT:.*`+regexp.QuoteMeta(s.path("etc", "fake.conf")))
	mustContain(t, "the fake block", fk, "discard the edits")
}

// backend_cli.bats #49: each backend's own render state: the stand-in's
// missing artifact in its block, the other block up to date.
func TestSectionsValidateEachBackendsRenderState(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	s.fk.Check = "missing"
	out := s.run("", "config", "validate")
	s.expect(1, "", "Validation failed with 1 error(s).")
	mustContain(t, "the fake block", between(out, "Backend fake:", "Groups defined"),
		s.path("etc", "fake.conf")+" is missing — run 'tacctl config render'")
	mustContain(t, "the tacacs block", between(out, "Backend tacacs:", "Backend fake:"), "up to date")
}

// backend_cli.bats #50: a disabled backend's edited leftovers are not an
// error.
func TestSectionsValidateDisabledBackendsLeftovers(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	s.run("", "backend", "disable", "fake", "-y")
	s.expect(0, "", "")
	appendFile(t, s.path("etc", "fake.conf"), "intruder\n")
	s.run("", "config", "validate")
	s.expect(0, "Configuration is valid.", "")
	mustNotContain(t, "validate", s.all(), "DRIFT", "Backend ")
}

// backend_cli.bats #51: an answer of RenderCheck tacctl does not know is
// 'out of date', that backend's error, in its block.
func TestSectionsValidateUnknownRenderStateIsOutOfDate(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	s.fk.Check = "bad"
	out := s.run("", "config", "validate")
	s.expect(1, "", "Validation failed with 1 error(s).")
	mustContain(t, "the fake block", between(out, "Backend fake:", "Groups defined"),
		s.path("etc", "fake.conf")+" is out of date with the store — run 'tacctl config render'")
	mustNotContain(t, "the tacacs block", between(out, "Backend tacacs:", "Backend fake:"), "out of date")
}

// migrate_dead_command_matches.bats #10: a hand-edited override whose match
// regex repeats the command word can never fire; validate fails on it.
func TestSectionsValidateDeadRegexOverride(t *testing.T) {
	sb := newSandbox(t, false)
	sandboxRADIUS(sb)
	sb.write("etc/tacquito.yaml", fixture(t, "tacquito.dead-matches.yaml"), 0o640)
	sb.write("state/tacctl.yaml", "commands:\n  operator:\n"+
		"    - { name: show,  action: permit, match: [\"^show .*$\"] }\n"+
		"    - { name: \"*\",   action: deny }\n", 0o640)
	sb.run("", []string{"config", "validate"})
	if sb.code == 0 {
		t.Fatalf("validate passed:\n%s%s", sb.out.String(), sb.err.String())
	}
	all := plain(sb.out.String() + sb.err.String())
	mustContain(t, "validate", all, "commands.operator", "can never match")
	mustMatch(t, "validate", all, `^  tacctl\.yaml: +commands\.operator: .*'\^show \.\*\$' repeats the command word.*can never match`)
}

// upgrade_store_flip.bats #2, as far as the CLI reaches: after the move
// into the store (here the operator's route, 'store import' and 'config
// render --force'; the gate of 'tacctl upgrade' needs the daemon's
// load-smoke) validate is clean, nothing drifted, and a mutation applies.
func TestSectionsValidateCleanAfterTheFlip(t *testing.T) {
	sb, _ := flippedSandbox(t)
	out := plain(sb.run("", []string{"config", "validate"}))
	sb.expect(0, "Configuration is valid.", "")
	mustMatch(t, "validate", out, `Rendered config:.* up to date$`)
	all := plain(sb.out.String() + sb.err.String())
	mustNotContain(t, "validate", all, "DRIFT", "not initialised")
	out = plain(sb.run("", []string{"user", "add", "alice", "superuser", "--hash", testHash}))
	sb.expect(0, "", "")
	mustNotContain(t, "user add", out+plain(sb.err.String()), "Previous")
	mustContain(t, "tacquito.yaml", sb.read("etc/tacquito.yaml"), "name: alice")
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("no restart: %q", sb.runner.Argvs())
	}
}

// --- config show ----------------------------------------------------------------------

// backend_cli.bats #52: one backend, its plain lines, no block.
func TestSectionsShowOneBackend(t *testing.T) {
	s := newSectionsSandbox(t, true)
	out := s.run("", "config", "show")
	s.expect(0, "", "")
	mustMatch(t, "config show", out,
		`^  Config file: +`+regexp.QuoteMeta(s.path("etc", "tacquito.yaml"))+`$`,
		`^  Service status: +active$`,
		`^  Listening on: +\*:49$`)
	mustNotContain(t, "config show", out, "Backend:")
}

// backend_cli.bats #53: the listener's own port is probed and named, not 49.
func TestSectionsShowProbesTheListenersOwnPort(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.run("y\n", "config", "listen", "tcp", "10.1.0.1:4901")
	s.expect(0, "", "")
	s.tcp = "LISTEN 0 128 10.1.0.1:4901 *:*\n"
	out := s.run("", "config", "show")
	mustMatch(t, "config show", out, `^  Listening on: +10\.1\.0\.1:4901$`)
	s.tcp = ""
	out = s.run("", "config", "show")
	mustMatch(t, "config show", out, `Listening on: +.*port 4901 not detected`)
}

// backend_cli.bats #54: a block per backend, tcp and udp listeners probed
// apart.
func TestSectionsShowABlockPerBackend(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	out := s.run("", "config", "show")
	s.expect(0, "Backend: tacacs", "")
	s.expect(0, "Backend: fake", "")
	tac := between(out, "Backend: tacacs", "Backend: fake")
	fk := between(out, "Backend: fake", "")
	mustMatch(t, "the tacacs block", tac, `Config file:.*tacquito\.yaml`, `Listening on:.*\*:49`)
	mustMatch(t, "the fake block", fk,
		`Config file:.*fake\.conf`,
		`Service status:.*active`,
		`Listening on \(auth\):.*\*:1812`,
		`Listening on \(acct\):.*\*:1813`)
	if !s.runner.Called("ss", "-ulnp") || !s.runner.Called("ss", "-tlnp") {
		t.Errorf("ss probes: %q", s.runner.Argvs())
	}
}

// --- log --------------------------------------------------------------------------------

// backend_cli.bats #55: one backend, no heading, the arguments passed on.
func TestSectionsLogOneBackendNoHeading(t *testing.T) {
	s := newSectionsSandbox(t, true)
	out := s.run("", "log", "tail", "5")
	s.expect(0, "", "")
	mustNotContain(t, "log tail", out, "== Backend")
	if !s.runner.Called("journalctl", "-u", "tacquito", "--no-pager", "-n", "5") {
		t.Errorf("journalctl: %q", s.runner.Argvs())
	}
}

// backend_cli.bats #56: tail, search, failures and accounting reach every
// enabled backend, each under its heading.
func TestSectionsLogEveryEnabledBackend(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	heads := []string{"== Backend: tacacs (tacacs, tacquito) ==", "== Backend: fake (fake, faked) =="}
	out := s.run("", "log", "tail", "7")
	s.expect(0, "", "")
	mustContain(t, "log tail", out, heads...)
	mustMatch(t, "log tail", out, `^fake log tail 7$`)
	if !s.runner.Called("journalctl", "-u", "tacquito", "--no-pager", "-n", "7") {
		t.Errorf("journalctl: %q", s.runner.Argvs())
	}
	for _, c := range []struct {
		args []string
		line string
	}{
		{[]string{"log", "search", "alice"}, `^fake log search alice$`},
		{[]string{"log", "failures"}, `^fake log failures$`},
		{[]string{"log", "accounting", "3"}, `^fake accounting tail 3$`},
	} {
		out := s.run("", c.args...)
		s.expect(0, "", "")
		mustContain(t, strings.Join(c.args, " "), out, heads...)
		mustMatch(t, strings.Join(c.args, " "), out, c.line)
		if strings.Index(out, heads[1]) < strings.Index(out, heads[0]) {
			t.Errorf("%q: sections out of order:\n%s", c.args, out)
		}
		if c.args[1] != "accounting" && !s.runner.Called("journalctl") {
			t.Errorf("%q: tacquito's journal not read: %q", c.args, s.runner.Argvs())
		}
	}
	mustContain(t, "log accounting", s.out.String(), "Recent Accounting Entries")
}

// backend_cli.bats #59: 'log clear' clears every enabled backend, each
// with its own confirmation; -y goes to each.
func TestSectionsLogClearEveryBackend(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	out := s.run("", "log", "clear", "-y")
	s.expect(0, "", "")
	mustMatch(t, "log clear -y", out, `^fake log clear -y$`)
	mustContain(t, "log clear -y", s.all(), "Clear tacquito logs", "[INFO] Logs cleared (journal + accounting).")
	if !s.runner.CalledRegexp(`^journalctl .*--vacuum`) {
		t.Errorf("tacquito's journal not vacuumed: %q", s.runner.Argvs())
	}
	// Without -y each backend asks for itself: 'no' to tacquito's question
	// leaves its logs, and the next backend is still asked (the stand-in
	// asks nothing and is called without -y).
	out = s.run("n\n", "log", "clear")
	s.expect(0, "", "")
	mustContain(t, "log clear, no", s.all(), "Clear tacquito logs", "[INFO] Cancelled.")
	mustMatch(t, "log clear, no", out, `^fake log clear$`)
	if s.runner.CalledRegexp(`^journalctl .*--vacuum`) {
		t.Errorf("a 'no' vacuumed the journal: %q", s.runner.Argvs())
	}
	if strings.Index(out, "fake log clear") < strings.Index(out, "Clear tacquito logs") {
		t.Errorf("sections out of order:\n%s", out)
	}
	out = s.run("", "log", "clear", "--backend", "fake")
	s.expect(0, "", "")
	mustMatch(t, "log clear --backend fake", out, `^fake log clear$`)
	mustNotContain(t, "log clear --backend fake", s.all(), "tacquito")
}

// --- backup restore -----------------------------------------------------------------------

// backend_cli.bats #62: the backends a snapshot enables follow it: one it
// leaves out is stopped and disabled, one it names is enabled at boot,
// and every enabled backend is restarted.
func TestSectionsBackupRestoreBackendsFollowTheSnapshot(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	storeNow := s.read("state/store.yaml")
	s.mkSnapshot("20200101_000000_001", storeNow, "backends:\n  enabled: [tacacs]\n")
	s.mkSnapshot("20200101_000000_002", storeNow, "backends:\n  enabled: [tacacs, fake]\n")

	s.run("y\n", "backup", "restore", "20200101_000000_001")
	s.expect(0, "Backend 'fake' is not enabled by this snapshot: stopping and disabling its service.", "")
	s.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if got := s.enabledNow(); got != "tacacs" {
		t.Errorf("enabled now: %q", got)
	}
	for _, c := range []string{"service stop", "service disable"} {
		if !s.fk.Called(c) {
			t.Errorf("no %q: %q", c, s.fk.Calls())
		}
	}
	if s.fk.Called("service restart") {
		t.Errorf("a backend the snapshot leaves out was restarted: %q", s.fk.Calls())
	}
	if s.fk.Active() != "inactive" || s.fk.Boot() != "disabled" {
		t.Errorf("the stand-in is %s, %s at boot", s.fk.Active(), s.fk.Boot())
	}
	if !s.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("tacquito not restarted: %q", s.runner.Argvs())
	}

	s.fk.ResetCalls()
	s.run("y\n", "backup", "restore", "20200101_000000_002")
	s.expect(0, "Backend 'fake' is enabled by this snapshot.", "")
	if got := s.enabledNow(); got != "tacacs fake" {
		t.Errorf("enabled now: %q", got)
	}
	for _, c := range []string{"service enable", "service restart"} {
		if !s.fk.Called(c) {
			t.Errorf("no %q: %q", c, s.fk.Calls())
		}
	}
	if s.fk.Active() != "active" || s.fk.Boot() != "enabled" {
		t.Errorf("the stand-in is %s, %s at boot", s.fk.Active(), s.fk.Boot())
	}
	// Every enabled backend is restarted, whether or not its bytes changed.
	if !s.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("tacquito not restarted: %q", s.runner.Argvs())
	}
}

// enabledNow is enabled_now: backends.enabled as tacctl.yaml says it.
func (s *sectionsSandbox) enabledNow() string {
	ids := conf.Load(s.path("state", "tacctl.yaml"), backend.Default().IDs()).GetList("backends.enabled")
	if len(ids) == 0 {
		ids = backend.DefaultEnabled
	}
	return strings.Join(ids, " ")
}
