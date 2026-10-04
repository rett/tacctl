package cli

import (
	"errors"
	"io"
	"strconv"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
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

// exit is an ExitError of code whose messages have been written.
func exit(code int) error { return &ExitError{Code: code} }

// exitCode maps a command's error to the process exit status and prints
// whatever the error carries that has not been printed yet, the way 0.1.16
// prints it. The one table of exit statuses (docs/plans/go-rewrite.md 1.2,
// "Exit codes in use"):
//
//	nil                                   0
//	*ExitError                            its Code ([ERROR] Err first, when set)
//	ui.ErrInterrupted                     130, silently (Ctrl-C at a password prompt)
//	ui.ErrReported, tier.ErrDenied        1, silently (already printed)
//	backend.Reported (*backend.Error)     its Code, silently (1 failed, 3 refused, ...)
//	*backend.UnknownError                 2, [ERROR] <msg>
//	*store.ImportStatus                   its Code, silently
//	store.ErrNotInitialised, *store.ExistsError,
//	*store.NotFoundError, store.ErrSeedUsage,
//	*model.NoSourceError                  1, [ERROR] <msg>
//	*names.Error                          1, one [ERROR] line per message
//	*conf.ParseError                      1, its [ERROR] lines
//	*conf.ValidationError                 1, the plain line on stderr
//	*store.Error, a store file error      1, store.Report's 'tacctl store: ...' line
//	anything else                         1, [ERROR] <msg>
func exitCode(err error, out ui.Output) int {
	if err == nil {
		return 0
	}
	var (
		ee *ExitError
		ue *backend.UnknownError
		is *store.ImportStatus
		ex *store.ExistsError
		nf *store.NotFoundError
		ns *model.NoSourceError
		ne *names.Error
		pe *conf.ParseError
		ve *conf.ValidationError
	)
	switch {
	case errors.As(err, &ee):
		if ee.Err != nil {
			out.Error(ee.Err.Error())
		}
		return ee.Code
	case errors.Is(err, ui.ErrInterrupted):
		return 130
	case errors.Is(err, ui.ErrReported), errors.Is(err, tier.ErrDenied):
		return 1
	case backend.Reported(err):
		return backend.ExitCode(err)
	case errors.As(err, &ue):
		out.Error(ue.Error())
		return 2
	case errors.As(err, &is):
		return is.Code
	case errors.Is(err, store.ErrNotInitialised), errors.As(err, &ex), errors.As(err, &nf),
		errors.Is(err, store.ErrSeedUsage), errors.As(err, &ns):
		out.Error(err.Error())
		return 1
	case errors.As(err, &ne):
		out.ErrorLines(ne)
		return 1
	case errors.As(err, &pe):
		out.ErrorLines(pe)
		return 1
	case errors.As(err, &ve):
		_, _ = io.WriteString(out.Stderr, ve.Error()+"\n")
		return 1
	case store.Reportable(err):
		_, _ = io.WriteString(out.Stderr, store.Report(err)+"\n")
		return 1
	}
	out.Error(err.Error())
	return 1
}
