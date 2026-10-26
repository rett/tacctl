package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// 'device config apply' is the engineer's (0.2.19; the superuser's before:
// 0.2.9, D141) and 'device config shapes' the superuser's: the gate sees
// 'device config', which the engineer's rows open, so the verb's own table
// holds shapes back, with the gate's words, and sudoers has no line for it.
func TestDeviceConfigApplyIsTheEngineersAndShapesTheSuperusers(t *testing.T) {
	if deviceConfigNeeds["apply"] != tier.Engineer || deviceConfigNeeds["shapes"] != tier.Superuser {
		t.Errorf("apply needs %q, shapes %q", deviceConfigNeeds["apply"], deviceConfigNeeds["shapes"])
	}
	named := false
	for _, row := range tier.Rules {
		for _, p := range row.Sudoers {
			named = named || row.Tier == tier.Engineer && p == "device config apply *"
		}
	}
	if !named {
		t.Error("no Engineer sudoers row names device config apply")
	}
	for _, sub := range []string{"shapes", "shapes seed"} {
		for _, row := range tier.Rules {
			for _, p := range row.Sudoers {
				if strings.HasPrefix(p, "device config "+sub) {
					t.Errorf("sudoers row %q names device config %s", p, sub)
				}
			}
		}
	}

	sb := engineerSandbox(t)
	allowed := func(sudoUser, sub string) (string, error) {
		t.Helper()
		r := &fake.Runner{}
		r.On([]string{"logger"}, execx.Result{})
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
		env := append([]string(nil), sb.env...)
		if sudoUser != "" {
			env = append(env, "SUDO_USER="+sudoUser)
		}
		sb.out.Reset()
		sb.err.Reset()
		a := app.New(nil, paths.NewEnv(env), "/opt/x/dist/tacctl", 1000,
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, r)
		inv := &invocation{ctx: t.Context(), app: a, hooks: newTestHooks()}
		err := inv.deviceConfigAllowed(sub)
		_ = a.Close() // the plain-text filter holds what it has not passed on
		return plain(sb.err.String()), err
	}
	stderr, err := allowed("bob", "shapes")
	if !errors.Is(err, tier.ErrDenied) || !strings.Contains(stderr, "'tacctl device config shapes' is not permitted for the engineer tier.") {
		t.Errorf("engineer, shapes: %v %q", err, stderr)
	}
	for _, sub := range []string{"apply", "shapes"} {
		if stderr, err := allowed("", sub); err != nil || stderr != "" {
			t.Errorf("root, %s: %v %q", sub, err, stderr)
		}
	}
	// the engineer's own verbs of the family
	for _, sub := range []string{"show", "pull", "diff", "plan", "apply"} {
		if stderr, err := allowed("bob", sub); err != nil {
			t.Errorf("engineer, %s: %v %q", sub, err, stderr)
		}
	}
}
