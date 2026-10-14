package devapply

// The lab spike's findings (docs/plans/0.2.9-lab.md): the captured texts
// parse as the transport requires, the banner is the pending marker, and a
// secret the device prints in a compare never leaves the package.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
)

const capturedTexts = "../../tests/fixtures/devconf/juniper/apply/texts.txt"

// captured reads the capture file: each '## <command>' block's output.
func captured(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(capturedTexts)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	cur := ""
	for _, l := range strings.Split(string(b), "\n") {
		if h, ok := strings.CutPrefix(l, "## "); ok {
			cur = h
			out[cur] = ""
			continue
		}
		if cur != "" {
			out[cur] += l + "\n"
		}
	}
	return out
}

func TestCapturedTexts(t *testing.T) {
	c := captured(t)
	get := func(k string) string {
		t.Helper()
		v, ok := c[k]
		if !ok {
			t.Fatalf("no block %q", k)
		}
		return v
	}
	if b, ok := configAnswer(get("configure exclusive")); !ok || !exactly(b, textExclusiveWarning, textEnterConfig) {
		t.Errorf("configure exclusive: %q %v", b, ok)
	}
	b, ok := configAnswer(get("configure exclusive (held by another session)"))
	if ok || !containsLine(b, textLocked) || lockedBy(b) != "admin" {
		t.Errorf("locked: %q %v %q", b, ok, lockedBy(b))
	}
	if b, ok := configAnswer(get("commit check")); !ok || !exactly(b, textCheckOK) {
		t.Errorf("commit check: %q", b)
	}
	// the banner before the location line is the prompt's, not the answer's
	if b, ok := configAnswer(get(`commit confirmed 2 comment "zz-tacctl spike L2"`)); !ok || !committedAnswer(b, plan.ApplyConfirmedNote(2), textCommitComplete) {
		t.Errorf("commit confirmed: %q", b)
	}
	if b, ok := configAnswer(get("commit confirmed (private session)")); !ok || committedAnswer(b, plan.ApplyConfirmedNote(2), textCommitComplete) || classify(b) == "" {
		t.Errorf("private: %q", b)
	}
	if b, ok := configAnswer(get("rollback 1")); !ok || !exactly(b, textLoadComplete) {
		t.Errorf("rollback 1: %q", b)
	}
	if b, ok := configAnswer(get(`commit comment "zz-tacctl spike L2 cancel"`)); !ok || !committedAnswer(b, textCommitComplete) {
		t.Errorf("cancel: %q", b)
	}
	h, err := parseHistory(get("show system commit (a pending commit; its label stays after a check confirms it)"))
	if err != nil || len(h) != 2 || h[0].RollbackIn != 1 || h[0].Comment != "zz-tacctl spike L2b" || h[1].RollbackIn != 0 || h[0].User != "admin" {
		t.Errorf("history %+v %v", h, err)
	}
	if _, err := plan.ParseCompare(get("show configuration | compare rollback 1")); err != nil {
		t.Errorf("compare: %v", err)
	}
	// the banner line of the captures
	if p, n, err := parseBanner([]string{"# commit confirmed will be rolled back in 2 minutes", "{master:0}"}); !p || n != 2 || err != nil {
		t.Errorf("banner %v %d %v", p, n, err)
	}
}

func TestParseBannerFailsClosed(t *testing.T) {
	for _, c := range []struct {
		area    []string
		pending bool
		n       int
		bad     bool
	}{
		{nil, false, 0, false},
		{[]string{"{master:0}"}, false, 0, false},
		{[]string{"", "{backup:1}"}, false, 0, false},
		{[]string{"# commit confirmed will be rolled back in 1 minute"}, true, 1, false},
		{[]string{"# commit confirmed will be rolled back in 10 minutes", "{master:0}"}, true, 10, false},
		{[]string{"# commit confirmed will be rolled back soon"}, false, 0, true},
		{[]string{"Message from syslogd"}, false, 0, true},
		{[]string{"# commit confirmed will be rolled back in 1 minute", "# commit confirmed will be rolled back in 2 minutes"}, false, 0, true},
	} {
		p, n, err := parseBanner(c.area)
		if p != c.pending || n != c.n || (err != nil) != c.bad || (err != nil && !errors.Is(err, ErrUnrecognised)) {
			t.Errorf("%q: %v %d %v", c.area, p, n, err)
		}
	}
	// a banner whose minutes changed between two prompts stays in the
	// answer: it is the prompt's all the same
	if b, ok := configAnswer("load complete\n\n# commit confirmed will be rolled back in 3 minutes\n{master:0}[edit]\n"); !ok || !exactly(b, textLoadComplete) {
		t.Errorf("%q", b)
	}
	st := CommitState{Pending: true, Minutes: 1}
	if st.Until() != "for about 1 more minute" || (CommitState{}).Until() != "" {
		t.Errorf("%q", st.Until())
	}
}

// A TACACS+ login names its template account and the person apart [C].
func TestAuthorizationOfATacacsLogin(t *testing.T) {
	lg, err := parseAuthorization("Current user: 'EN-CLASS' login: 'gotesteng' class 'EN-CLASS'\nPermissions:\n    rollback view view-configuration\n")
	if err != nil || lg.Class != "EN-CLASS" || lg.User != "EN-CLASS" || lg.Name != "gotesteng" || lg.CanCommit() {
		t.Errorf("%+v %v", lg, err)
	}
	lg, err = parseAuthorization("Current user: gotest       login: gotest       class: super-user\nPermissions:\n    all\n")
	if err != nil || lg.Class != "super-user" || lg.Name != "gotest" || !lg.CanCommit() {
		t.Errorf("%+v %v", lg, err)
	}
	// a template account named like a class word is not a class
	if _, err := parseAuthorization("Current user: 'eng-class' login: 'x'\nPermissions:\n    all\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("no class read as one: %v", err)
	}
}

// bannerHeldT shows the banner in the held session's prompt from the
// compare on: the transport never types 'commit check' then.
type bannerHeldT struct{ *JunosCLI }

func (b bannerHeldT) Compare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	b.mu.Lock()
	b.held = bannerSession{b.held}
	b.mu.Unlock()
	return b.JunosCLI.Compare(ctx, d)
}

func TestCheckRefusedUnderTheBanner(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := check(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = bannerHeldT{in.Transport.(*JunosCLI)}
	})
	wantExit(t, o, ExitFailedCheck, ResultFailed)
	if indexOf(o.Log, plan.ApplyCommitCheck) >= 0 || !strings.Contains(o.Reason, "a confirmed commit is pending") || !o.Discarded {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
	if d.srv.Committed() != before {
		t.Error("changed")
	}
}

// noBannerT hides the banner after the confirmed commit: an answer the
// transport does not know is never taken for a commit, the state is read
// and the pending commit cancelled.
type noBannerT struct{ *JunosCLI }

// quietSession tells an empty prompt area once, then the session's own.
type quietSession struct {
	devssh.CLISession
	used *bool
}

func (q quietSession) PromptArea() ([]string, bool) {
	if !*q.used {
		*q.used = true
		return nil, true
	}
	return q.CLISession.(devssh.PromptArea).PromptArea()
}

func (n noBannerT) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	n.mu.Lock()
	n.held = quietSession{n.held, new(bool)}
	n.mu.Unlock()
	return n.JunosCLI.CommitConfirmed(ctx, minutes, id, user)
}

func TestCommitConfirmedWithoutBanner(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = noBannerT{in.Transport.(*JunosCLI)}
	})
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "shows no pending commit") || indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
	if d.srv.Committed() != before {
		t.Error("not rolled back")
	}
}

// A secret the device prints in a compare (a superuser sees password
// hashes and '$9$' strings in any statement) never reaches the outcome,
// the logs or the state: the candidate's compare and the landed compare.
const hashText = "$6$zzsalt$zzHashOfAPassword"

type hashExtraT struct {
	*JunosCLI
	done bool
}

func (e *hashExtraT) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	r, err := e.JunosCLI.Load(ctx, l)
	if err == nil && !e.done {
		e.done = true
		e.mu.Lock()
		held := e.held
		e.mu.Unlock()
		_, _ = held.Run(ctx, `set system login user zz-other class super-user authentication encrypted-password "`+hashText+`"`)
	}
	return r, err
}

type hashLandedT struct{ Reader }

func (l hashLandedT) LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	c, err := l.Reader.LandedCompare(ctx, d)
	c.Stmts = append(c.Stmts, plan.CompareStmt{Op: '+', Path: []string{"system", "root-authentication", "encrypted-password", `"` + hashText + `"`}})
	return c, err
}

func assertNoHash(t *testing.T, o Outcome, state string) {
	t.Helper()
	allSecrets = append(allSecrets, hashText, "zzHashOfAPassword")
	defer func() { allSecrets = allSecrets[:len(allSecrets)-2] }()
	assertNoSecret(t, o, state)
}

func TestDeviceSecretsNeverLeave(t *testing.T) {
	t.Run("candidate", func(t *testing.T) {
		d := newDevice(t, nil)
		o := check(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.Transport = &hashExtraT{JunosCLI: in.Transport.(*JunosCLI)}
		})
		wantExit(t, o, ExitFailedLoad, ResultFailed)
		if !strings.Contains(o.Reason, "a change outside the delta") || !strings.Contains(o.Reason, "encrypted-password <secret>") {
			t.Errorf("reason %q", o.Reason)
		}
		assertNoHash(t, o, d.state)
	})
	t.Run("landed", func(t *testing.T) {
		d := newDevice(t, nil)
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.Verify = func(ctx context.Context) (Reader, error) {
				r, err := d.verify(ctx)
				if err != nil {
					return nil, err
				}
				return hashLandedT{r}, nil
			}
		})
		wantExit(t, o, ExitRolledBack, ResultRolledBack)
		if !strings.Contains(o.Reason, "the landed compare holds 1 statement(s) outside the plan") {
			t.Errorf("reason %q", o.Reason)
		}
		assertNoHash(t, o, d.state)
		if d.srv.Committed() != before {
			t.Error("not rolled back")
		}
	})
	for in, out := range map[string]string{
		`encrypted-password "` + hashText + `"; ## SECRET-DATA`: `encrypted-password <secret>; ## SECRET-DATA`,
		`+   secret "$9$abcDEF.xyz"; ## SECRET-DATA`:            `+   secret <secret>; ## SECRET-DATA`,
		"community zz-private-ro {":                             "community <secret> {",
		"authentication-key s3cr3t;":                            "authentication-key <secret>;",
		"set snmp community <secret> authorization read-only":   "set snmp community <secret> authorization read-only",
		"a hash " + hashText + " stands alone":                  "a hash <secret> stands alone",
	} {
		if got := deviceSecrets(in); got != out {
			t.Errorf("%q -> %q, want %q", in, got, out)
		}
	}
}
