package ui

import (
	"bytes"
	"errors"
	"testing"
)

type linesErr struct{}

func (linesErr) Error() string   { return "x" }
func (linesErr) Lines() []string { return []string{"one", "two"} }

func TestErrorLines(t *testing.T) {
	var out, errb bytes.Buffer
	o := Output{Stdout: &out, Stderr: &errb}
	o.ErrorLines(nil)
	o.ErrorLines(linesErr{})
	o.ErrorLines(errors.New("plain"))
	want := "\033[0;31m[ERROR]\033[0m one\n\033[0;31m[ERROR]\033[0m two\n\033[0;31m[ERROR]\033[0m plain\n"
	if errb.String() != want || out.Len() != 0 {
		t.Errorf("stderr = %q, stdout = %q", errb.String(), out.String())
	}
}
