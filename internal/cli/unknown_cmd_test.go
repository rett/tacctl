package cli

import (
	"slices"
	"testing"
)

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
