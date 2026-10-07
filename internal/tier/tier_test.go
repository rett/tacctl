package tier

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/ui"
)

func TestForPrivLvl(t *testing.T) {
	for in, want := range map[string]Tier{
		"15": Superuser, "16": Superuser, "99999999999999999999": Superuser, "7": Operator, "14": Operator,
		"6": Readonly, "1": Readonly, "0": Readonly, "": None, "x": None, "-1": None, "7 ": None, "07": Operator,
	} {
		if got := ForPrivLvl(in); got != want {
			t.Errorf("ForPrivLvl(%q) = %s, want %s", in, got, want)
		}
	}
}

// testdata/permits.psv is tier_permits of the 0.1.16 tag for every tier
// and a list of command lines ('cmd|sub|readonly|operator|superuser|
// unrestricted|none'), written by sourcing bin/tacctl.sh, with 0.2.1's
// change: 'help', '-h' and '--help' alone are open to the lower tiers.
// The last rows (ssh, device) are the 0.2.1 table of docs/plans/operator-console.md 8.
func TestPermitsMatchesBash(t *testing.T) {
	f, err := os.Open("testdata/permits.psv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tiers := []Tier{Readonly, Operator, Superuser, Unrestricted, None}
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "|")
		if len(p) != 7 {
			t.Fatalf("bad line %q", sc.Text())
		}
		for i, tr := range tiers {
			if got := Permits(tr, p[0], p[1]); got != (p[2+i] == "1") {
				t.Errorf("Permits(%s, %q, %q) = %v, bash says %s", tr, p[0], p[1], got, p[2+i])
			}
		}
		n++
	}
	if n < 80 {
		t.Fatalf("only %d cases", n)
	}
	if Permits("bogus", "", "") {
		t.Error("an unknown tier is permitted")
	}
}

// testdata/sudoers.tiers is emit_tier_sudoers of the 0.1.16 tag plus
// 0.2.1's lines for 'help', '-h' and '--help', the ssh and device rows, and
// the env_keep line for SSH_AUTH_SOCK (no SETENV tag: it would let a caller
// set SUDO_USER), and 0.2.2's 'group show'.
func TestSudoersMatchesBash(t *testing.T) {
	want, err := os.ReadFile("testdata/sudoers.tiers")
	if err != nil {
		t.Fatal(err)
	}
	if got := Sudoers(); got != string(want) {
		t.Errorf("Sudoers differs from emit_tier_sudoers:\n--- got\n%s--- want\n%s", got, want)
	}
}

// aliasItems are the commands of one Cmnd_Alias of the drop-in, without the
// binary.
func aliasItems(t *testing.T, text, name string) []string {
	t.Helper()
	joined := strings.ReplaceAll(text, "\\\n", " ")
	m := regexp.MustCompile(`(?m)^Cmnd_Alias ` + name + ` = (.*)$`).FindStringSubmatch(joined)
	if m == nil {
		t.Fatalf("no alias %s", name)
	}
	var out []string
	for _, it := range strings.Split(m[1], ",") {
		it = strings.TrimSpace(it)
		if !strings.HasPrefix(it, Binary) {
			t.Fatalf("item %q does not name %s", it, Binary)
		}
		out = append(out, strings.TrimSpace(strings.TrimPrefix(it, Binary)))
	}
	return out
}

// The cross-check of tests/integration/tiers.bats ("tier gate and sudoers
// rules agree on every verb, for each lower tier"), here against the table
// both come from: every verb the usage texts offer is permitted by the gate
// exactly when a rule grants it, and the rules grant nothing the gate
// refuses.
func TestGateAndSudoersAgree(t *testing.T) {
	text := Sudoers()
	ro, op := aliasItems(t, text, "TACCTL_RO"), aliasItems(t, text, "TACCTL_OP")
	in := func(items []string, cmd, sub string) bool {
		re := regexp.MustCompile("^" + regexp.QuoteMeta(cmd+" "+sub) + `( \*)?$`)
		for _, it := range items {
			if re.MatchString(it) {
				return true
			}
		}
		return false
	}
	verbs := `user list|user show|user add|user remove|user passwd|group list|group add|scope list|scope show|
scope secret|scope protocols|backend list|backend status|backend enable|backend disable|store show|store import|
store rollback|config validate|config show|config render|config dump|config cisco|config sudoers|log tail|
log search|log failures|log accounting|log clear|backup list|backup diff|backup restore|host list|host enroll`
	for _, v := range strings.Split(strings.ReplaceAll(verbs, "\n", ""), "|") {
		cmd, sub, _ := strings.Cut(v, " ")
		inRO, inOP := in(ro, cmd, sub), in(op, cmd, sub)
		if Permits(Readonly, cmd, sub) != inRO {
			t.Errorf("readonly %s: gate %v, sudoers %v", v, Permits(Readonly, cmd, sub), inRO)
		}
		if Permits(Operator, cmd, sub) != (inRO || inOP) {
			t.Errorf("operator %s: gate %v, sudoers %v/%v", v, Permits(Operator, cmd, sub), inRO, inOP)
		}
	}
	for _, it := range append(append([]string(nil), ro...), op...) {
		if strings.HasPrefix(it, `""`) {
			continue
		}
		w := strings.Fields(strings.TrimSuffix(it, " *"))
		if len(w) < 2 {
			continue
		}
		if !Permits(Readonly, w[0], w[1]) && !Permits(Operator, w[0], w[1]) {
			t.Errorf("sudoers-only: %s", it)
		}
	}
	// store show never reaches a lower tier, in the gate or in sudoers.
	if strings.Contains(text, "store") || Permits(Readonly, "store", "show") || Permits(Operator, "store", "show") {
		t.Error("store show reaches a lower tier")
	}
}

type gateRun struct {
	run      *fake.Runner
	out, err bytes.Buffer
	gate     Gate
}

func newGate(sudoUser, groups string, privlvl map[string]string) *gateRun {
	g := &gateRun{run: &fake.Runner{}}
	if groups == "fail" {
		g.run.Fail([]string{"id"}, 1, "id: no such user\n")
	} else {
		g.run.On([]string{"id"}, execx.Result{Stdout: []byte(groups + "\n")})
	}
	g.run.On([]string{"logger"}, execx.Result{})
	g.gate = Gate{Runner: g.run, Out: ui.Output{Stdout: &g.out, Stderr: &g.err}, SudoUser: sudoUser,
		PrivLvl: func(u string) string { return privlvl[u] }}
	return g
}

func TestCaller(t *testing.T) {
	lv := map[string]string{"ro": "1", "op": "7", "su": "15"}
	for _, c := range []struct {
		user, groups string
		want         Tier
		ids          int
	}{
		{"", "", Unrestricted, 0},
		{"root", "", Unrestricted, 0},
		{"ro", "users sudo", Unrestricted, 1},
		{"ro", "fail", Unrestricted, 1},
		{"ro", "users tac-users", Readonly, 1},
		{"op", "tac-users", Operator, 1},
		{"su", "tac-users x", Superuser, 1},
		{"ghost", "tac-users", None, 1},
		{"bad.name", "tac-users", None, 1},
		{"ro", "tac-users-x", Unrestricted, 1},
	} {
		g := newGate(c.user, c.groups, lv)
		if got := g.gate.Caller(context.Background()); got != c.want {
			t.Errorf("%q in %q: %s, want %s", c.user, c.groups, got, c.want)
		}
		if n := g.run.Count("id", "-nG", "--", c.user); n != c.ids {
			t.Errorf("%q: %d id calls", c.user, n)
		}
	}
}

func TestEnforce(t *testing.T) {
	lv := map[string]string{"ro": "1", "op": "7"}
	g := newGate("ro", "tac-users", lv)
	if err := g.gate.Enforce(context.Background(), "user", "list"); err != nil || g.err.Len() != 0 || g.run.Called("logger") {
		t.Errorf("permitted: %v %q", err, g.err.String())
	}
	g = newGate("ro", "tac-users", lv)
	if err := g.gate.Enforce(context.Background(), "user", "remove"); err != ErrDenied {
		t.Fatalf("denied: %v", err)
	}
	if g.err.String() != "\033[0;31m[ERROR]\033[0m 'tacctl user remove' is not permitted for the readonly tier.\n" || g.out.Len() != 0 {
		t.Errorf("denial: %q", g.err.String())
	}
	if !g.run.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=ro tier=readonly cmd=user remove") {
		t.Errorf("not logged: %q", g.run.Argvs())
	}
	// No sub: the bash's trailing blank stays.
	g = newGate("op", "tac-users", lv)
	_ = g.gate.Enforce(context.Background(), "bogus", "")
	if !strings.Contains(g.err.String(), "'tacctl bogus ' is not permitted for the operator tier.") ||
		!g.run.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=op tier=operator cmd=bogus ") {
		t.Errorf("bogus: %q %q", g.err.String(), g.run.Argvs())
	}
	// The usage is open to both lower tiers; a word after it is not.
	for _, cmd := range []string{"help", "-h", "--help"} {
		for _, u := range []string{"ro", "op"} {
			g = newGate(u, "tac-users", lv)
			if err := g.gate.Enforce(context.Background(), cmd, ""); err != nil || g.err.Len() != 0 {
				t.Errorf("%s %s: %v %q", u, cmd, err, g.err.String())
			}
		}
		g = newGate("ro", "tac-users", lv)
		if err := g.gate.Enforce(context.Background(), cmd, "user"); err != ErrDenied {
			t.Errorf("%s user: %v", cmd, err)
		}
	}
	g = newGate("ghost", "tac-users", lv)
	if err := g.gate.Enforce(context.Background(), "version", ""); err != ErrDenied ||
		g.err.String() != "\033[0;31m[ERROR]\033[0m 'ghost' has no active tacctl user, so tacctl access is denied.\n" {
		t.Errorf("none: %v %q", err, g.err.String())
	}
	// A logger that fails changes nothing.
	g = newGate("ro", "tac-users", lv)
	g.run.Fail([]string{"logger"}, 1, "")
	if err := g.gate.Enforce(context.Background(), "store", "show"); err != ErrDenied {
		t.Errorf("logger failure: %v", err)
	}
}

func TestSudoersNoSetenv(t *testing.T) {
	text := Sudoers()
	if strings.Contains(text, "SETENV") || !strings.Contains(text, "\n"+EnvKeep) {
		t.Errorf("SETENV or no env_keep line:\n%s", text)
	}
	if EnvKeep != "Defaults!/usr/local/bin/tacctl env_keep += \"SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY\"\n" {
		t.Errorf("EnvKeep %q", EnvKeep)
	}
}

func TestVerifyCaller(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, user, uid, passwd string
		code                    int
		ok                      bool
		lookups                 int
	}{
		{"no uid: not checked", "anyone", "", "", 0, true, 0},
		{"match", "ro", "1001", "ro:x:1001:1001::/home/ro:/bin/bash\n", 0, true, 1},
		{"another account", "su", "1001", "ro:x:1001:1001::/home/ro:/bin/bash\n", 0, false, 1},
		{"root claimed by a user", "root", "1001", "ro:x:1001:1001::/home/ro:/bin/bash\n", 0, false, 1},
		{"empty user", "", "1001", "ro:x:1001:1001::/home/ro:/bin/bash\n", 0, false, 1},
		{"uid field differs", "ro", "1001", "ro:x:1002:1002::/home/ro:/bin/bash\n", 0, false, 1},
		{"no such uid", "ro", "1001", "", 2, false, 1},
		{"garbage", "ro", "1001", "garbage\n", 0, false, 1},
		{"uid not a number", "ro", "10x", "", 0, false, 0},
		{"root under sudo", "root", "0", "root:x:0:0:root:/root:/bin/bash\n", 0, true, 1},
	} {
		r := &fake.Runner{}
		r.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte(c.passwd), Code: c.code})
		err := VerifyCaller(ctx, r, c.user, c.uid)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if n := r.Count("getent", "passwd", c.uid); n != c.lookups || r.Count("getent") != c.lookups {
			t.Errorf("%s: %d lookups %q", c.name, n, r.Argvs())
		}
	}
}

// A SUDO_USER that is not SUDO_UID's account is denied everything, root
// included, before the tier is asked; the refusal is logged.
func TestGateRefusesSpoofedSudoUser(t *testing.T) {
	ctx := context.Background()
	lv := map[string]string{"ro": "1", "su": "15"}
	for _, claimed := range []string{"su", "root", "ops"} {
		g := newGate(claimed, "tac-users", lv)
		g.gate.SudoUID = "1001"
		g.run.On([]string{"getent", "passwd", "1001"}, execx.Result{Stdout: []byte("ro:x:1001:1001::/home/ro:/bin/bash\n")})
		if got := g.gate.Caller(ctx); got != None {
			t.Errorf("%s: Caller %s", claimed, got)
		}
		g.err.Reset()
		if err := g.gate.Enforce(ctx, "version", ""); err != ErrDenied {
			t.Fatalf("%s: %v", claimed, err)
		}
		want := "\033[0;31m[ERROR]\033[0m SUDO_USER '" + claimed + "' is not the account of SUDO_UID 1001, so tacctl access is denied.\n"
		if g.err.String() != want {
			t.Errorf("%s: %q", claimed, g.err.String())
		}
		if !g.run.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user="+claimed+" uid=1001 reason=sudo-user-mismatch cmd=version ") {
			t.Errorf("%s: not logged %q", claimed, g.run.Argvs())
		}
		if g.run.Called("id") {
			t.Errorf("%s: the tier was asked", claimed)
		}
	}
	// The genuine pair passes and the tier applies.
	g := newGate("ro", "tac-users", lv)
	g.gate.SudoUID = "1001"
	g.run.On([]string{"getent", "passwd", "1001"}, execx.Result{Stdout: []byte("ro:x:1001:1001::/home/ro:/bin/bash\n")})
	if err := g.gate.Enforce(ctx, "device", "ssh"); err != nil {
		t.Errorf("device ssh: %v %q", err, g.err.String())
	}
	if err := g.gate.Enforce(ctx, "user", "remove"); err != ErrDenied {
		t.Errorf("user remove: %v", err)
	}
}

// The login console's rows: every tier reads its policy, the operator tier
// shows the console and checks it, and nothing else of 'console' is open
// below the superuser.
func TestConsoleRows(t *testing.T) {
	for _, c := range []struct {
		t        Tier
		cmd, sub string
		want     bool
	}{
		{Readonly, "_console-policy", "", true},
		{Operator, "_console-policy", "", true},
		{None, "_console-policy", "", false},
		{Readonly, "console", "show", false},
		{Operator, "console", "show", true},
		{Operator, "console", "check", true},
		{Operator, "console", "tiers", false},
		{Operator, "console", "user", false},
		{Operator, "console", "system-shell", false},
		{Operator, "console", "", false},
		{Readonly, "console", "check", false},
		{Superuser, "console", "tiers", true},
		{Unrestricted, "console", "tiers", true},
	} {
		if got := Permits(c.t, c.cmd, c.sub); got != c.want {
			t.Errorf("Permits(%s, %s %s) = %v", c.t, c.cmd, c.sub, got)
		}
	}
	text := Sudoers()
	for _, want := range []string{
		"Cmnd_Alias TACCTL_RO = ", "/usr/local/bin/tacctl _console-policy",
		"/usr/local/bin/tacctl console show, /usr/local/bin/tacctl console check",
		`env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("sudoers lacks %q", want)
		}
	}
	if ro, _, _ := strings.Cut(text, "Cmnd_Alias TACCTL_OP"); strings.Contains(ro, "console show") {
		t.Error("console show is in the read-only alias")
	}
}
