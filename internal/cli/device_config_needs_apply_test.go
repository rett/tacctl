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

// 'device config apply' and 'device config shapes' are the superuser's
// (0.2.9, D141): the gate sees 'device config', which the engineer's rows
// open, so the verb's own table holds them back, with the gate's words, and
// sudoers has no line for them.
func TestDeviceConfigApplyAndShapesAreTheSuperusers(t *testing.T) {
	for _, sub := range []string{"apply", "shapes"} {
		if deviceConfigNeeds[sub] != tier.Superuser {
			t.Errorf("device config %s needs %q", sub, deviceConfigNeeds[sub])
		}
	}
	for _, sub := range []string{"apply", "shapes", "shapes seed"} {
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
	for _, sub := range []string{"apply", "shapes"} {
		stderr, err := allowed("bob", sub)
		if !errors.Is(err, tier.ErrDenied) || !strings.Contains(stderr, "'tacctl device config "+sub+"' is not permitted for the engineer tier.") {
			t.Errorf("engineer, %s: %v %q", sub, err, stderr)
		}
		if stderr, err := allowed("", sub); err != nil || stderr != "" {
			t.Errorf("root, %s: %v %q", sub, err, stderr)
		}
	}
	// the engineer's own verbs of the family stay theirs
	for _, sub := range []string{"show", "pull", "diff", "plan"} {
		if stderr, err := allowed("bob", sub); err != nil {
			t.Errorf("engineer, %s: %v %q", sub, err, stderr)
		}
	}
}
