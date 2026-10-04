package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
)

// lifecycleEnv is a lifecycle.Env over the sandbox's paths, for the steps
// 'tacctl upgrade' runs that no verb exposes on its own (the migrations
// and the regeneration of tacquito.yaml's commands: blocks).
func (sb *sandbox) lifecycleEnv(stderr *bytes.Buffer) (*app.App, *lifecycle.Env) {
	sb.t.Helper()
	a := app.New(nil, paths.NewEnv(append([]string(nil), sb.env...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: stderr, Stderr: stderr}, &fake.Runner{})
	a.Paths = a.Paths.Reroot(sb.dir)
	env := lifecycle.NewEnv(a.BackendEnv(), nil, false)
	env.Chown = func(string) {}
	return a, env
}

// tests/unit/render_tacacs.bats (0.1.18): "check: operator command
// overrides in tacctl.yaml are part of the proof". A commands.operator
// override that tacquito.yaml does not carry yet makes 'store import
// --check' fail; once the commands: blocks are regenerated it passes.
func TestStoreImportCheckOperatorCommandOverridesArePartOfTheProof(t *testing.T) {
	sb := newSandbox(t, false)
	ctx := context.Background()
	var log bytes.Buffer

	// place_fixture tacquito.minimal.yaml; upgrade_migrations.
	data, err := os.ReadFile("../../tests/fixtures/tacquito.minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a, env := sb.lifecycleEnv(&log)
	if err := os.WriteFile(a.Paths.Config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return lifecycle.MigrateExecServiceName(env) },
		func() error { return lifecycle.MigrateCommandRules(env) },
		func() error { return lifecycle.RegenerateCommands(ctx, env, "") },
	} {
		if err := step(); err != nil {
			t.Fatalf("migration: %v\n%s", err, log.String())
		}
	}
	sb.run("", []string{"store", "import", "--check"})
	sb.expect(0, "EQUIVALENT", "")

	// conf_set_json commands.operator ...
	if err := a.Conf().SetJSON("commands.operator", `[{"name": "show", "action": "permit"}, {"name": "*", "action": "deny"}]`); err != nil {
		t.Fatal(err)
	}
	out := sb.run("", []string{"store", "import", "--check"})
	sb.expect(1, `"name": "terminal"`, "")
	if !strings.Contains(out, "NOT EQUIVALENT") {
		t.Errorf("no NOT EQUIVALENT verdict:\n%s", out)
	}

	// regenerate_tacquito_commands, with the override now in tacctl.yaml.
	_, env = sb.lifecycleEnv(&log)
	if err := lifecycle.RegenerateCommands(ctx, env, ""); err != nil {
		t.Fatalf("regenerate: %v\n%s", err, log.String())
	}
	sb.run("", []string{"store", "import", "--check"})
	sb.expect(0, "EQUIVALENT", "")
	if _, err := os.Stat(filepath.Join(sb.dir, "state", "store.yaml")); err == nil {
		t.Error("--check wrote a store")
	}
}
