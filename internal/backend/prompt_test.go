package backend

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/ui"
)

// Env.Prompt is the Env's Prompter, made once from Stdin when there is none.
func TestEnvPrompt(t *testing.T) {
	var out strings.Builder
	e := &Env{Stdin: strings.NewReader("y\nn\n"), Out: ui.Output{Stdout: &out, Stderr: &out}}
	if p := e.Prompt(); p != e.Prompt() || p != e.Prompter {
		t.Fatal("Prompt made two prompters")
	}
	if !e.Prompt().Confirm("? ") || e.Prompt().Confirm("? ") {
		t.Error("answers not read in order through one buffer")
	}
	given := ui.NewPrompter(strings.NewReader("y\n"), e.Out)
	e2 := &Env{Prompter: given}
	if e2.Prompt() != given {
		t.Error("a given Prompter is not used")
	}
	if (&Env{}).Prompt().Confirm("? ") {
		t.Error("no stdin answered yes")
	}
}
