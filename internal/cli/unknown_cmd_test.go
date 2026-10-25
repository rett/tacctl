package cli

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// A word that is no command is answered before sudo runs (0.2.19): by the
// re-exec of a plain 'tacctl <word>' and by a line of the shell, with the
// same text as the root gives and without a password prompt (no sudo
// process).
func TestUnknownWordIsAnsweredBeforeSudo(t *testing.T) {
	parallel(t)
	const want = "[ERROR] Unknown command: 'enroll'\nDid you mean: tacctl device enroll, tacctl host enroll?\nRun 'tacctl' for the commands.\n"
	var out, errb bytes.Buffer
	runner := &fake.Runner{}
	a := app.New([]string{"enroll", "sw1"}, paths.NewEnv([]string{"PATH=/usr/bin"}), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}, runner)
	code := exitCode(runWith(context.Background(), a, BuildInfo{Version: "t"}, newTestHooks()), a.Out)
	if got := stripSGR(errb.String()); code != 1 || got != want || out.Len() != 0 || len(runner.Calls()) != 0 || len(runner.Execs()) != 0 {
		t.Errorf("re-exec: exit %d stdout %q stderr %q calls %v execs %v", code, out.String(), got, runner.Calls(), runner.Execs())
	}

	h := newHarness(t, nil)
	inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks()}
	exec := inv.shellExec(newRoot(inv), testExe, true, tier.Operator, nil)
	if code := exec(context.Background(), []string{"enroll", "sw1"}, nil); code != 1 || stripSGR(h.err.String()) != want || len(h.runner.Calls()) != 0 {
		t.Errorf("shell: exit %d stderr %q calls %v", code, stripSGR(h.err.String()), h.runner.Calls())
	}
	// a command, a hidden one and the usage words are the root's and sudo's
	root := newRoot(inv)
	for _, w := range []string{"device", "_completion-names", "help", "-h", "--help", "hash", "shell", ""} {
		if notACommand(root, w) {
			t.Errorf("%q is taken for unknown", w)
		}
	}
	for _, w := range []string{"enroll", "-x", "--", "devce"} {
		if !notACommand(root, w) {
			t.Errorf("%q is not taken for unknown", w)
		}
	}
}

// A top-level word that is no command (D277): one error line naming it on
// stderr, a suggestion when one fits, the pointer to 'tacctl', exit 1;
// nothing on stdout and nothing run.
func TestUnknownTopLevelCommand(t *testing.T) {
	const tail = "Run 'tacctl' for the commands.\n"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"enroll"}, "[ERROR] Unknown command: 'enroll'\nDid you mean: tacctl device enroll, tacctl host enroll?\n" + tail},
		{[]string{"enroll", "sw1", "10.0.0.1"}, "[ERROR] Unknown command: 'enroll'\nDid you mean: tacctl device enroll, tacctl host enroll?\n" + tail},
		{[]string{"apply"}, "[ERROR] Unknown command: 'apply'\nDid you mean: tacctl device config apply?\n" + tail},
		{[]string{"devce", "list"}, "[ERROR] Unknown command: 'devce'\nDid you mean: tacctl device?\n" + tail},
		{[]string{"Version"}, "[ERROR] Unknown command: 'Version'\nDid you mean: tacctl version?\n" + tail},
		{[]string{"User", "list"}, "[ERROR] Unknown command: 'User'\nDid you mean: tacctl user?\n" + tail},
		{[]string{"bogus"}, "[ERROR] Unknown command: 'bogus'\n" + tail},
		{[]string{"user-add"}, "[ERROR] Unknown command: 'user-add'\n" + tail},
		{[]string{"-x", "user", "list"}, "[ERROR] Unknown option: '-x'\n" + tail},
		{[]string{"--x=1"}, "[ERROR] Unknown option: '--x=1'\n" + tail},
		{[]string{"--", "version"}, "[ERROR] Unknown option: '--'\n" + tail},
	} {
		h := newHarness(t, c.args)
		code := exitCode(h.run(), h.app.Out)
		if got := stripSGR(h.err.String()); code != 1 || got != c.want || h.out.Len() != 0 || len(h.runner.Execs()) != 0 {
			t.Errorf("%q: exit %d stdout %q stderr %q, want %q", c.args, code, h.out.String(), got, c.want)
		}
	}
}

func TestCommandSuggestions(t *testing.T) {
	root := newRoot(&invocation{})
	for _, c := range []struct {
		w    string
		want []string
	}{
		{"enroll", []string{"device enroll", "host enroll"}},
		// a verb of many families: the first few, by name
		{"list", []string{"backend list", "backup list", "breakglass list", "device list"}},
		{"devce", []string{"device"}},
		{"scpe", []string{"scope"}},
		{"xyzzy", nil},
		{"q", nil},
		// hidden commands are never suggested
		{"_completion-name", nil},
		{"--help", nil},
	} {
		if got := commandSuggestions(root, c.w); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.w, got, c.want)
		}
	}
	if d := editDistance("devce", "device"); d != 1 {
		t.Errorf("editDistance = %d", d)
	}
}
