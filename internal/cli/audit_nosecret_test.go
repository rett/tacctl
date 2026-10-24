package cli

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hash"
)

// The no-secret scan (docs/plans/0.2.17-plan.md D252, D255 5): every verb
// that takes a secret is run with a distinctive marker in each position the
// secret can be typed in (the flag, the positional, the prompt, standard
// input, and the places a mistaken positional lands), and the marker is in
// no logger argument of the run, of any tag. A case that should write a
// start line says what its args= must read, so the scan is not satisfied by
// a run that logged nothing.

const (
	markerSecret  = "MARKERsecret7f3a91c2e5d"
	markerSecret2 = "MARKERother4b8d60a1f93"
)

// noLoggerHas fails the test for every logger call of r (of any tag) whose
// arguments carry one of the markers.
func noLoggerHas(t *testing.T, what string, r *fake.Runner, markers ...string) {
	t.Helper()
	for _, c := range r.Calls() {
		if c.Name != "logger" {
			continue
		}
		joined := strings.Join(c.Args, " ")
		for _, m := range markers {
			if m != "" && strings.Contains(joined, m) {
				t.Errorf("%s: %q reached logger: %q", what, m, c.Args)
			}
		}
	}
}

func TestNoSecretReachesTheAuditLog(t *testing.T) {
	sb := newSandbox(t, true)
	markerHash, err := hash.Generate(markerSecret, 4)
	if err != nil {
		t.Fatal(err)
	}
	// A hash is logged hex-encoded (or as typed) and capped at 64 bytes, so
	// the whole of it never matches: scan for its first 40 characters, as
	// typed and in hex.
	hexHash := hex.EncodeToString([]byte(markerHash))
	markers := []string{markerSecret, markerSecret2, markerHash[:40], hexHash[:40]}
	// The marker as alice's own password, for the self-service path.
	sb.cfgRun("", []string{"user", "passwd", "alice", "--hash", markerHash}, nil)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")

	cases := []struct {
		name  string
		stdin string
		args  []string
		// start is what the start line must end in; "" is no check, "-" is no
		// start line (a read, or a usage error before the verb wrote).
		start string
	}{
		{"user add --hash", "", []string{"user", "add", "dave", "operator", "--hash", markerHash, "--scopes", "lab"},
			`args="dave operator --hash <redacted> --scopes lab"`},
		{"user add --hash=", "", []string{"user", "add", "erin", "operator", "--hash=" + markerHash},
			`args="erin operator --hash=<redacted>"`},
		{"user add --hash hex", "", []string{"user", "add", "hank", "operator", "--hash", hexHash},
			`args="hank operator --hash <redacted>"`},
		{"user add prompt", markerSecret + "\n" + markerSecret + "\n", []string{"user", "add", "frank", "operator", "--scopes", "lab"},
			`args="frank operator --scopes lab"`},
		{"user add positional", "", []string{"user", "add", "gina", "operator", markerSecret}, `args="gina operator <redacted>"`},
		{"user add dash positional", "", []string{"user", "add", "gina", "operator", "-" + markerSecret}, `args="gina operator <redacted>"`},
		{"user add --hash -", markerHash + "\n", []string{"user", "add", "ivan", "operator", "--hash", "-", "--scopes", "lab"},
			`args="ivan operator --hash <redacted> --scopes lab"`},
		{"user passwd --hash -", markerHash + "\n", []string{"user", "passwd", "dave", "--hash", "-"}, `args="dave --hash <redacted>"`},
		{"user passwd --hash", "", []string{"user", "passwd", "dave", "--hash", markerHash}, `args="dave --hash <redacted>"`},
		{"user passwd positional", "", []string{"user", "passwd", "dave", markerSecret}, `args="dave <redacted>"`},
		{"user passwd prompt", markerSecret2 + "\n" + markerSecret2 + "\n", []string{"user", "passwd", "dave"}, `args=dave`},
		{"scope add --secret", "", []string{"scope", "add", "x1", "--prefixes", "10.77.0.0/16", "--secret", markerSecret},
			`args="x1 --prefixes 10.77.0.0/16 --secret <redacted>"`},
		{"scope add --secret=", "", []string{"scope", "add", "x2", "--prefixes", "10.78.0.0/16", "--secret=" + markerSecret},
			`args="x2 --prefixes 10.78.0.0/16 --secret=<redacted>"`},
		{"scope secret set", "", []string{"scope", "secret", "lab", "set", markerSecret}, `args="lab set <redacted>"`},
		{"scope secret set --stdin", markerSecret + "\n", []string{"scope", "secret", "lab", "set", "--stdin"}, `args="lab set --stdin"`},
		{"scope secret --stdin set", markerSecret + "\n", []string{"scope", "secret", "lab", "--stdin", "set"}, `args="lab --stdin set"`},
		{"scope secret set --stdin and a value", markerSecret + "\n", []string{"scope", "secret", "lab", "set", "--stdin", markerSecret2},
			"-"},
		{"scope secret value as scope, --stdin", markerSecret + "\n", []string{"scope", "secret", markerSecret2, "--stdin"}, ""},
		{"scope secret --stdin, value as scope", markerSecret + "\n", []string{"scope", "secret", "--stdin", markerSecret2}, ""},
		{"scope secret set, two words", "", []string{"scope", "secret", "lab", "set", markerSecret, markerSecret2}, `args="lab set <redacted> <redacted>"`},
		{"scope secret value as sub-command", "", []string{"scope", "secret", "lab", markerSecret}, ""},
		{"scope secret without scope", "", []string{"scope", "secret", "set", markerSecret}, ""},
		{"scope secret generate extra", "", []string{"scope", "secret", "lab", "generate", markerSecret}, `args="lab generate <redacted>"`},
		{"hash", "", []string{"hash", markerSecret}, ""},
		{"hash stdin", markerSecret + "\n", []string{"hash"}, ""},
		{"passwd positional", "", []string{"passwd", markerSecret}, ""},
		{"config snmp community", markerSecret + "\n", []string{"config", "snmp", "community", "--stdin"}, `args="community --stdin"`},
		{"config snmp community positional", "", []string{"config", "snmp", "community", markerSecret}, ""},
		{"config snmp v3-user", markerSecret + "\n" + markerSecret2 + "\n", []string{"config", "snmp", "v3-user", "monitor", "--auth", "sha256", "--stdin"},
			`args="v3-user monitor --auth sha256 --stdin"`},
		{"config snmp v3-user positional", "", []string{"config", "snmp", "v3-user", "monitor", markerSecret, markerSecret2}, ""},
		{"scope snmp community", markerSecret + "\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, `args="lab community --stdin"`},
		{"scope snmp community positional", "", []string{"scope", "snmp", "lab", "community", markerSecret}, ""},
		{"scope snmp v3-user", markerSecret + "\n" + markerSecret2 + "\n", []string{"scope", "snmp", "lab", "v3-user", "monitor", "--stdin"},
			`args="lab v3-user monitor --stdin"`},
		{"scope snmp v3-user positional", "", []string{"scope", "snmp", "lab", "v3-user", "monitor", markerSecret, "-" + markerSecret2}, ""},
		{"device snmp community", markerSecret + "\n", []string{"device", "snmp", "lab-sw1", "community", "--stdin"}, `args="lab-sw1 community --stdin"`},
		{"device snmp community positional", "", []string{"device", "snmp", "lab-sw1", "community", markerSecret}, ""},
		{"device snmp v3-user", markerSecret + "\n" + markerSecret2 + "\n", []string{"device", "snmp", "lab-sw1", "v3-user", "monitor", "--stdin"},
			`args="lab-sw1 v3-user monitor --stdin"`},
		{"device snmp v3-user positional", "", []string{"device", "snmp", "lab-sw1", "v3-user", "monitor", markerSecret}, ""},
	}
	for _, c := range cases {
		sb.cfgRun(c.stdin, c.args, nil, "SUDO_USER=alice", "SUDO_UID=1001")
		noLoggerHas(t, c.name, sb.runner, markers...)
		start := auditLine(sb.runner, "cmd start ")
		switch {
		case c.start == "":
		case c.start == "-" && start != "":
			t.Errorf("%s: unexpected start line %s", c.name, start)
		case c.start != "-" && !strings.HasSuffix(start, c.start):
			t.Errorf("%s: start line\n got %s\nwant it to end in %s", c.name, start, c.start)
		}
	}

	// The self-service password change: the current and the new password are
	// prompts; the log carries the user and the result.
	sb.cfgRun(markerSecret+"\n"+markerSecret2+"\n"+markerSecret2+"\n", []string{"passwd"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	noLoggerHas(t, "passwd", sb.runner, markers...)
	if len(auditLines(sb.runner)) == 0 {
		t.Error("passwd wrote no line")
	}
	sb.cfgRun("wrong-"+markerSecret+"\n", []string{"passwd"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	noLoggerHas(t, "passwd, wrong current password", sb.runner, markers...)
	if !hasAuditPrefix(sb.runner, "auth.warning", "passwd FAIL user=alice") {
		t.Errorf("passwd FAIL line missing: %q", auditLines(sb.runner))
	}
	sb.cfgRun(markerSecret+"\n", []string{"user", "verify", "alice"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	noLoggerHas(t, "user verify", sb.runner, markers...)
}

// The detail lines (D253) name objects and counts, never a value: the verbs
// that write them are run with markers as the shared secret, the community
// and the hash they handle, and the verbs that reveal a secret are run after
// them. Every case says the line it must have written, so the scan is not
// satisfied by a run that logged nothing.
func TestNoSecretInTheDetailLines(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxTarball(t, sb)
	markerHash, err := hash.Generate(markerSecret, 4)
	if err != nil {
		t.Fatal(err)
	}
	markers := []string{markerSecret, markerSecret2, markerHash[:40], hex.EncodeToString([]byte(markerHash))[:40]}
	alice := []string{"SUDO_USER=alice", "SUDO_UID=1001"}
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	script := sb.path("client.sh")
	for _, c := range []struct {
		stdin string
		args  []string
		want  string
	}{
		{"", []string{"scope", "secret", "lab", "set", markerSecret}, "scope secret set scope=lab source=set by=alice"},
		{markerSecret2 + "\n", []string{"scope", "secret", "lab", "set", "--stdin"}, "scope secret set scope=lab source=set by=alice"},
		{markerSecret2 + "\n", []string{"config", "snmp", "community", "--stdin"}, "snmp set kind=community by=alice"},
		{markerSecret2 + "\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, "snmp set kind=community scope=lab by=alice"},
		{markerSecret2 + "\n", []string{"device", "snmp", "lab-sw1", "community", "--stdin"}, "snmp set kind=community device=lab-sw1 by=alice"},
		{markerSecret + "\n" + markerSecret2 + "\n", []string{"config", "snmp", "v3-user", "monitor", "--auth", "sha256", "--stdin"}, "snmp set kind=v3-user by=alice"},
		{"", []string{"user", "add", "dave", "operator", "--hash", markerHash, "--scopes", "lab"}, "user add name=dave group=operator scopes=lab by=alice"},
		{"", []string{"user", "passwd", "dave", "--hash", markerHash}, "user passwd name=dave source=hash by=alice"},
		{markerHash + "\n", []string{"user", "passwd", "dave", "--hash", "-"}, "user passwd name=dave source=hash by=alice"},
		{markerSecret + "\n" + markerSecret + "\n", []string{"user", "passwd", "dave"}, "user passwd name=dave source=prompt by=alice"},
		{"", []string{"scope", "secret", "lab", "show"}, "secret-read kind=scope name=lab by=alice"},
		{"", []string{"scope", "snmp", "lab", "show", "--reveal"}, "secret-read kind=snmp name=lab by=alice"},
		{"", []string{"config", "snmp", "show", "--reveal"}, "secret-read kind=snmp-default name=default by=alice"},
		{"", []string{"device", "snmp", "lab-sw1", "show", "--reveal"}, "secret-read kind=snmp-device name=lab-sw1 by=alice"},
		{"", []string{"store", "show"}, "secret-read kind=store name=model by=alice"},
		{"", []string{"config", "dump"}, "secret-read kind=config name=dump by=alice"},
		{"", []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", script}, "secret-export scope=lab file=" + script + " by=alice"},
	} {
		sb.cfgRun(c.stdin, c.args, nil, alice...)
		name := strings.Join(c.args[:min(3, len(c.args))], " ")
		if sb.code != 0 {
			t.Errorf("%s: exit %d %q", name, sb.code, sb.stderr())
		}
		noLoggerHas(t, name, sb.runner, markers...)
		if !hasAudit(sb.runner, "auth.info", c.want) {
			t.Errorf("%s: no %q in %q", name, c.want, auditLines(sb.runner))
		}
	}
	// A diff of a snapshot, which holds the secrets.
	id := sb.snapshotID()
	sb.cfgRun("", []string{"backup", "diff", id}, nil, alice...)
	noLoggerHas(t, "backup diff", sb.runner, markers...)
	if !hasAudit(sb.runner, "auth.info", "secret-read kind=snapshot name="+id+" by=alice") {
		t.Errorf("backup diff: %q", auditLines(sb.runner))
	}
}

// The denial line of a refused verb carries no secret: an engineer naming a
// scope's secret to change, or the community of a scope or a device that is
// not theirs, with the secret typed where the verb asks for a prompt. Each
// case reaches the cmd DENY line, which is where these mixed verbs write
// their first line.
func TestNoSecretInTheDenyLine(t *testing.T) {
	sb := engineerSandbox(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"scope", "secret", "lab", "set", markerSecret}, `cmd="scope secret" args="lab set <redacted>"`},
		{[]string{"scope", "secret", "lab", markerSecret}, `cmd="scope secret" args="lab <redacted>"`},
		// Refused as an unknown scope, which is no denial: no DENY line.
		{[]string{"scope", "secret", markerSecret}, ""},
		{[]string{"scope", "snmp", "prod", "community", markerSecret}, `cmd="scope snmp" args="prod community <redacted>"`},
		{[]string{"scope", "snmp", "prod", "v3-user", "monitor", markerSecret, markerSecret2}, `cmd="scope snmp" args="prod v3-user monitor <redacted> <redacted>"`},
		// The device verb parses before it looks at the scope: a surplus word is
		// a usage error with no DENY line.
		{[]string{"device", "snmp", "prod-sw", "community", markerSecret}, ""},
		{[]string{"device", "snmp", "prod-sw", "v3-user", "monitor", "--stdin=" + markerSecret}, ""},
		{[]string{"device", "snmp", "prod-sw", "community", "--stdin"}, `cmd="device snmp" args="prod-sw community --stdin"`},
	} {
		sb.asEngineer(markerSecret+"\n", c.args...)
		name := strings.Join(c.args[:3], " ")
		noLoggerHas(t, name, sb.runner, markerSecret, markerSecret2)
		var deny string
		for _, l := range auditLines(sb.runner) {
			if strings.HasPrefix(l, "cmd DENY ") {
				deny = l
			}
		}
		if c.want == "" {
			if deny != "" {
				t.Errorf("%s: unexpected DENY line %q", name, deny)
			}
		} else if !strings.Contains(deny, c.want) {
			t.Errorf("%s: DENY line %q (exit %d, %q), want one with %s", name, deny, sb.code, sb.stderr(), c.want)
		}
	}
}

// The console's refusal names a first word only when it is a verb: a
// password typed at the prompt of a -c session is never in the log.
func TestNoSecretInTheConsoleDenyLine(t *testing.T) {
	for _, line := range []string{
		markerSecret, markerSecret + " user list", "'" + markerSecret + "'", markerSecret + "\nuser list",
		markerSecret + " 'unterminated", "/usr/bin/" + markerSecret, markerSecret2 + "=" + markerSecret,
	} {
		h, run := consoleHarness(t, "", "carol tac-users tac-readonly", consoleTestPolicy, "-c", line)
		if code := exitCode(run(), h.app.Out); code != 126 {
			t.Errorf("%q: status %d", line, code)
		}
		noLoggerHas(t, "console -c "+line, h.runner, markerSecret, markerSecret2)
		log := consoleLog(h.runner)
		if len(log) < 2 || !strings.Contains(log[1], " reason=command first=- len=") {
			t.Errorf("%q: log %q", line, log)
		}
	}
	// A verb is named, and the refusal says what was attempted.
	h, run := consoleHarness(t, "", "carol tac-users tac-readonly", consoleTestPolicy, "-c", "exit")
	_ = run()
	if log := consoleLog(h.runner); len(log) < 2 || !strings.HasSuffix(log[1], "reason=command first=exit") {
		t.Errorf("a shell word: %q", log)
	}
}

// The words args= redacts, by verb: the flag values by the spec's Secret mark,
// the rest by the entry's rule.
func TestAuditRedactionRules(t *testing.T) {
	for _, c := range []struct {
		key  string
		rest []string
		want []int
	}{
		{"scope secret", []string{"lab", "set", "x"}, []int{2}},
		{"scope secret", []string{"lab", "set", "x", "y"}, []int{2, 3}},
		{"scope secret", []string{"lab", "show"}, nil},
		{"scope secret", []string{"lab", "generate"}, nil},
		{"scope secret", []string{"lab", "x"}, []int{1}},
		{"scope secret", []string{"set", "x"}, []int{1}},
		{"hash", []string{"x", "y"}, []int{0, 1}},
		{"passwd", []string{"x"}, []int{0}},
		{"passwd", nil, []int{}},
		{"user add", []string{"dave", "operator", "--hash", "H", "--scopes", "lab"}, nil},
		{"user add", []string{"dave", "operator", "x", "--scopes", "lab"}, []int{2}},
		{"user add", []string{"dave", "operator", "--scopes", "lab", "x"}, []int{4}},
		{"user add", []string{"dave", "operator", "-x"}, []int{2}},
		{"user add", []string{"dave", "operator", "--", "x"}, []int{3}},
		{"user passwd", []string{"dave", "x"}, []int{1}},
		{"user passwd", []string{"dave", "--hash=H"}, nil},
		{"scope add", []string{"x1", "--secret", "S", "y"}, []int{3}},
		{"scope add", []string{"x1", "--default=S3"}, []int{1}},
		{"scope snmp", []string{"prod", "community", "--stdin=S3"}, []int{2}},
		{"device snmp", []string{"sw1", "v3-user", "bob", "--stdin=S3"}, []int{3}},
		{"scope secret", []string{"S3"}, []int{0}},
		{"scope secret", []string{"show"}, nil},
		{"scope secret", []string{"--help"}, nil},
		{"config snmp", []string{"community", "--stdin"}, nil},
		{"config snmp", []string{"community", "x"}, []int{1}},
		{"config snmp", []string{"v3-user", "bob", "--auth", "sha", "--stdin", "x", "y"}, []int{5, 6}},
		{"config snmp", []string{"port", "x"}, nil},
		{"scope snmp", []string{"lab", "community", "--stdin", "x"}, []int{3}},
		{"scope snmp", []string{"lab", "v3-user", "bob", "x"}, []int{3}},
		{"scope snmp", []string{"lab", "clients", "add", "10.0.0.0/8"}, nil},
		{"device snmp", []string{"sw1", "community", "x"}, []int{2}},
		{"device snmp", []string{"sw1", "v3-user", "bob", "--stdin"}, nil},
		{"device snmp", []string{"sw1"}, nil},
	} {
		e, ok := auditTable[c.key]
		if !ok || e.Secret == nil {
			t.Errorf("%s: no secret rule", c.key)
			continue
		}
		got := e.Secret(c.rest)
		if len(got) != len(c.want) {
			t.Errorf("%s %q: redacts %v, want %v", c.key, c.rest, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s %q: redacts %v, want %v", c.key, c.rest, got, c.want)
			}
		}
	}
}

// The words of 'scope secret' that are redacted, with the flag anywhere.
func TestSecretScopeSecretWords(t *testing.T) {
	for _, c := range []struct {
		rest []string
		want []int
	}{
		{[]string{"lab", "set", "x"}, []int{2}},
		{[]string{"lab", "set", "--stdin"}, nil},
		{[]string{"lab", "--stdin", "set"}, nil},
		{[]string{"lab", "--stdin", "set", "x"}, []int{3}},
		{[]string{"--stdin", "lab", "set", "x"}, []int{3}},
		{[]string{"lab", "x"}, []int{1}},
		{[]string{"x"}, []int{0}},
		{[]string{"x", "--stdin"}, []int{0}},
		{[]string{"--stdin", "x"}, []int{1}},
		{[]string{"--stdin"}, nil},
		{[]string{"lab", "show", "x"}, []int{2}},
		{[]string{"set"}, nil},
	} {
		got := secretScopeSecret(c.rest)
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: %v, want %v", c.rest, got, c.want)
		}
	}
}
