// Package ui is tacctl's terminal output: the colours and the
// info/warn/error lines of lib/core.sh. Colours are always on (the bash
// implementation has no isatty check, and tests pin the escape codes).
// Prompts (Confirm, Password) arrive with the packages that need them.
package ui

import (
	"fmt"
	"io"
)

// The escape sequences of lib/core.sh.
const (
	Red    = "\033[0;31m"
	Green  = "\033[0;32m"
	Yellow = "\033[1;33m"
	Cyan   = "\033[0;36m"
	Bold   = "\033[1m"
	NC     = "\033[0m"
)

// Output is where a command writes: Stdout for results, info and warn
// lines; Stderr for error lines (lib/core.sh: error() is the only helper
// that writes to stderr).
type Output struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Info writes "[INFO] msg" in green to Stdout.
func (o Output) Info(msg string) { line(o.Stdout, Green+"[INFO]"+NC, msg) }

// Warn writes "[WARN] msg" in yellow to Stdout.
func (o Output) Warn(msg string) { line(o.Stdout, Yellow+"[WARN]"+NC, msg) }

// Error writes "[ERROR] msg" in red to Stderr.
func (o Output) Error(msg string) { line(o.Stderr, Red+"[ERROR]"+NC, msg) }

// Infof, Warnf and Errorf format msg first.
func (o Output) Infof(format string, a ...any)  { o.Info(fmt.Sprintf(format, a...)) }
func (o Output) Warnf(format string, a ...any)  { o.Warn(fmt.Sprintf(format, a...)) }
func (o Output) Errorf(format string, a ...any) { o.Error(fmt.Sprintf(format, a...)) }

// line writes what 'echo -e "${TAG} $*"' writes. Write errors are ignored,
// as echo's are in the bash helpers.
func line(w io.Writer, tag, msg string) {
	_, _ = io.WriteString(w, tag+" "+msg+"\n")
}

// InfoE, WarnE and ErrorE are Info, Warn and Error exactly as lib/core.sh's
// helpers print: through 'echo -e', so a backslash escape in msg is
// interpreted (\t a tab, \c the end of the output). Use them for a message
// that carries a value from the command line.
func (o Output) InfoE(msg string)  { _, _ = io.WriteString(o.Stdout, Echo(Green+"[INFO]"+NC+" "+msg)) }
func (o Output) WarnE(msg string)  { _, _ = io.WriteString(o.Stdout, Echo(Yellow+"[WARN]"+NC+" "+msg)) }
func (o Output) ErrorE(msg string) { _, _ = io.WriteString(o.Stderr, Echo(Red+"[ERROR]"+NC+" "+msg)) }
