package cli

import (
	"errors"
	"strconv"

	"github.com/rett/tacctl/internal/ui"
)

// ExitError ends a command with a specific exit status. Err, when set, is
// printed as an [ERROR] line first; a command that has printed its own
// messages returns an ExitError with a nil Err.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return "exit status " + strconv.Itoa(e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// exitCode maps a command's error to the process exit status (nil → 0,
// *ExitError → its Code, anything else → 1) and prints the error, if any,
// as [ERROR] on stderr. The table of codes in use is in
// docs/plans/go-rewrite.md 1.2 ("Exit codes in use").
func exitCode(err error, out ui.Output) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			out.Error(ee.Err.Error())
		}
		return ee.Code
	}
	out.Error(err.Error())
	return 1
}
