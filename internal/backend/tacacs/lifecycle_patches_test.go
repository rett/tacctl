package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// tests/integration/tacquito_patches.bats: the patch overlay
// (applyPatches, patchesApplied) with the real patches/*.patch against a
// throwaway git checkout seeded with the pristine upstream files the
// patches target (tests/fixtures/tacquito-src). git is real: the fake
// runner passes every git call through to it, and records it.

const (
	stringyDir = "cmds/server/config/authorizers/stringy"
	acctDir    = "cmds/server/config/accounters"
	authenDir  = "cmds/server/config/authenticators"
)

type patchEnv struct {
	*ltenv
	session, local, syslog string
	bcrypt                 string
	acct                   string
}

func newPatchEnv(t *testing.T) *patchEnv {
	t.Helper()
	real := execx.Real{}
	if _, err := real.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := repoRoot(t)
	e := newLifeTenv(t, "TACCTL_PATCH_DIR="+filepath.Join(root, "patches"))
	src := e.src()
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(root, "tests", "fixtures", "tacquito-src"), src)
	e.run.Func(func(c execx.Cmd) bool { return c.Name == "git" }, func(c execx.Cmd) (execx.Result, error) {
		res, _ := real.Run(context.Background(), c)
		return res, nil
	})
	pe := &patchEnv{ltenv: e,
		session: filepath.Join(src, stringyDir, "session.go"),
		local:   filepath.Join(src, acctDir, "local", "local.go"),
		syslog:  filepath.Join(src, acctDir, "syslog", "syslog.go"),
		bcrypt:  filepath.Join(src, authenDir, "bcrypt", "bcrypt.go"),
		acct:    filepath.Join(src, "cmds", "server", "handlers", "acct.go"),
	}
	pe.git("init", "-q")
	pe.git("add", "-A")
	pe.git("commit", "-qm", "pristine")
	e.reset()
	return pe
}

// git runs real git in the checkout, outside the code under test.
func (p *patchEnv) git(args ...string) {
	p.t.Helper()
	argv := append([]string{"-C", p.src(), "-c", "user.email=t@t.local", "-c", "user.name=tester", "-c", "commit.gpgsign=false"}, args...)
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "git", Args: argv})
	if err != nil || res.Code != 0 {
		p.t.Fatalf("git %v: %v %s", args, err, res.Stderr)
	}
}

func (p *patchEnv) apply() (bool, error) { return p.b.applyPatches(context.Background()) }

func TestPatchesNotAppliedOnAPristineTree(t *testing.T) {
	p := newPatchEnv(t)
	if p.b.patchesApplied(context.Background()) {
		t.Fatal("applied")
	}
	if !p.called(`^git -C .* apply --reverse --check .*/patches/0001-`) {
		t.Fatal(p.run.Argvs())
	}
}

func TestPatchesApplyTheDefaultPermitPatch(t *testing.T) {
	p := newPatchEnv(t)
	if ok, err := p.apply(); err != nil || !ok {
		t.Fatal(ok, err, p.out())
	}
	mustContain(t, p.out(), "Applied tacquito patch: 0001")
	mustContain(t, readFile(t, p.session), "default service = permit")
}

func TestPatchesApplyTheEmptyAccountingServerMsgPatch(t *testing.T) {
	p := newPatchEnv(t)
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.out(), "Applied tacquito patch: 0002")
	// Success replies no longer carry a server_msg; failure replies still do.
	for _, f := range []string{p.local, p.syslog} {
		if strings.Contains(readFile(t, f), `SetAcctReplyServerMsg("success`) {
			t.Fatal(f)
		}
	}
	mustContain(t, readFile(t, p.local), `SetAcctReplyServerMsg("unexpected accounting flag")`)
}

func TestPatchesApplyTheAuthenticationNASAddressPatch(t *testing.T) {
	p := newPatchEnv(t)
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.out(), "Applied tacquito patch: 0003")
	src := readFile(t, p.bcrypt)
	mustContain(t, src, `"accepting user [%v] from [%v] using a bcrypt password"`)
	mustContain(t, src, `"failed to validate the user [%v] from [%v] using a bcrypt password"`)
	mustContain(t, src, "tq.ContextConnRemoteAddr")
	mustContain(t, src, `nasAddr := "unknown"`)
	// Idempotent: the reverse check sees it applied and nothing is re-applied.
	p.reset()
	if ok, err := p.apply(); err != nil || ok {
		t.Fatal(ok, err)
	}
	mustNotContain(t, p.out(), "Applied tacquito patch")
	if n := strings.Count(readFile(t, p.bcrypt), `nasAddr := "unknown"`); n != 1 {
		t.Fatal(n)
	}
}

func TestPatchesApplyTheAccountingSinkPatch(t *testing.T) {
	p := newPatchEnv(t)
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.out(), "Applied tacquito patch: 0005")
	src := readFile(t, p.acct)
	// A user the scope does not know is recorded through the scope's
	// accounter before the lookup failure is reported.
	mustContain(t, src, "tacctl patch 0005")
	sink := strings.Index(src, "c = sinkAccounter(a.configProvider)")
	fail := strings.Index(src, "does not have an accounter associated")
	if sink < 0 || fail < 0 || sink > fail {
		t.Fatalf("sink fallback at %d, failure at %d", sink, fail)
	}
	// root's records without a terminal are answered before the lookup,
	// with success, and not recorded.
	skip := strings.Index(src, "if internalSession(body) {")
	if skip < 0 || skip > sink || !strings.Contains(src[skip:sink], "tq.AcctReplyStatusSuccess") {
		t.Fatalf("internal-session skip at %d, sink at %d", skip, sink)
	}
	mustContain(t, src, `for _, p := range []string{"tty", "pts", "vty", "con", "aux", "/dev/"}`)
}

func TestPatchesApplyTheFailureWithoutServerMsgPatch(t *testing.T) {
	p := newPatchEnv(t)
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.out(), "Applied tacquito patch: 0004")
	src := readFile(t, p.bcrypt)
	// No failure reply names a server message any more: pam_tacplus would hand
	// it to sshd, which prints them all after the next successful login.
	mustNotContain(t, src, `SetAuthenReplyServerMsg("login failure")`)
	mustContain(t, src, "tacctl patch 0004")
	if n := strings.Count(src, "tq.SetAuthenReplyStatus(tq.AuthenStatusFail)"); n != 3 {
		t.Fatalf("%d failure replies, want 3", n)
	}
	p.reset()
	if ok, err := p.apply(); err != nil || ok {
		t.Fatal(ok, err)
	}
	mustNotContain(t, p.out(), "Applied tacquito patch")
}

func TestPatchesApplyIsIdempotent(t *testing.T) {
	p := newPatchEnv(t)
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	p.reset()
	if ok, err := p.apply(); err != nil || ok {
		t.Fatal(ok, err)
	}
	mustNotContain(t, p.out(), "Applied tacquito patch")
	// A sentinel that appears exactly once in the patched file.
	if n := strings.Count(readFile(t, p.session), "clientNamedCmd := false"); n != 1 {
		t.Fatal(n)
	}
}

func TestPatchesAppliedFlipsWithApplyAndRevert(t *testing.T) {
	p := newPatchEnv(t)
	ctx := context.Background()
	if _, err := p.apply(); err != nil {
		t.Fatal(err)
	}
	if !p.b.patchesApplied(ctx) {
		t.Fatal("not applied")
	}
	p.git("checkout", "--", ".")
	if p.b.patchesApplied(ctx) {
		t.Fatal("still applied")
	}
}

func TestPatchesAbortLoudlyOnUpstreamDrift(t *testing.T) {
	p := newPatchEnv(t)
	writeFile(t, p.session, "// upstream rewrote this file\n")
	p.git("commit", "-qam", "drift")
	_, err := p.apply()
	wantCode(t, err, 1)
	mustContain(t, p.out(), "tacquito patch will not apply cleanly: 0001-stringy-default-service-permit.patch.")
	mustContain(t, p.out(), "Upstream likely changed the patched file; refresh the diff in patches/.")
}

// No patch directory: nothing to apply, and every patch counts as applied.
func TestPatchesWithoutAPatchDirectory(t *testing.T) {
	e := newLifeTenv(t, "TACCTL_PATCH_DIR=/nonexistent/patches")
	if ok, err := e.b.applyPatches(context.Background()); ok || err != nil {
		t.Fatal(ok, err)
	}
	if !e.b.patchesApplied(context.Background()) || len(e.run.Calls()) != 0 {
		t.Fatal(e.run.Argvs())
	}
}
