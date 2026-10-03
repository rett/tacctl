package pyyaml

import (
	"fmt"

	"github.com/rett/tacctl/internal/conf/py"
)

// Error is a yaml.YAMLError raised by safe_load: a ReaderError (an
// unprintable character) or a MarkedYAMLError (ScannerError, ParserError,
// ComposerError, ConstructorError) with its problem and problem mark.
type Error struct {
	Context     string
	ContextMark *Mark
	Problem     string
	ProblemMark *Mark

	reader bool   // a ReaderError: text is str(e)
	text   string // ReaderError text
}

// Error is str(e) without the snippets PyYAML adds to a mark of a string
// stream (a file stream has none).
func (e *Error) Error() string {
	if e.reader {
		return e.text
	}
	var lines []string
	if e.Context != "" {
		lines = append(lines, e.Context)
	}
	if e.ContextMark != nil && (e.Problem == "" || e.ProblemMark == nil ||
		e.ContextMark.Name != e.ProblemMark.Name || e.ContextMark.Line != e.ProblemMark.Line ||
		e.ContextMark.Column != e.ProblemMark.Column) {
		lines = append(lines, markString(*e.ContextMark))
	}
	if e.Problem != "" {
		lines = append(lines, e.Problem)
	}
	if e.ProblemMark != nil {
		lines = append(lines, markString(*e.ProblemMark))
	}
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

func markString(m Mark) string {
	return fmt.Sprintf("  in \"%s\", line %d, column %d", m.Name, m.Line+1, m.Column+1)
}

// Why is what lib/conf.sh's load_overrides (0.1.16) makes of the error:
//
//	why = ' '.join(str(getattr(e, 'problem', None) or e).split())
//	if e.problem_mark: why = f"line {line+1}, column {column+1}: {why}"
func (e *Error) Why() string {
	text := e.Problem
	if e.reader || text == "" {
		text = e.Error()
	}
	why := py.CollapseSpace(text)
	if !e.reader && e.ProblemMark != nil {
		why = fmt.Sprintf("line %d, column %d: %s", e.ProblemMark.Line+1, e.ProblemMark.Column+1, why)
	}
	return why
}

func scannerError(context string, cm *Mark, problem string, pm Mark) *Error {
	return &Error{Context: context, ContextMark: cm, Problem: problem, ProblemMark: &pm}
}

func markPtr(m Mark) *Mark { return &m }

// DecodeError is the UnicodeDecodeError that reading a file that is not
// UTF-8 raises; Error is its str().
type DecodeError struct{ Msg string }

func (e *DecodeError) Error() string { return e.Msg }

// Why is the text load_overrides gives: str(e) with whitespace collapsed.
func (e *DecodeError) Why() string { return py.CollapseSpace(e.Msg) }

// ValueError is a value safe_load cannot construct although it parses:
// '!!int abc', an implicit timestamp that is no date, '!!bool maybe'. In
// 0.1.16 these escaped load_overrides as a Python traceback; tacctl reports
// them like a parse error instead.
type ValueError struct {
	Mark Mark
	Msg  string
}

func (e *ValueError) Error() string { return e.Why() }

// Why is "line L, column C: <msg>".
func (e *ValueError) Why() string {
	return fmt.Sprintf("line %d, column %d: %s", e.Mark.Line+1, e.Mark.Column+1, e.Msg)
}

// UnsupportedError is YAML that safe_load reads but tacctl does not:
// anchors and aliases, merge keys, keys that are not strings, sets,
// ordered maps, binary data, timestamps with a time of day, integers
// beyond 64 bits. tacctl.yaml never holds them (tacctl writes plain YAML);
// a hand-edited file that does is refused like one that does not parse.
type UnsupportedError struct {
	Mark Mark
	What string
}

func (e *UnsupportedError) Error() string { return e.Why() }

// Why is "line L, column C: <what> is not supported in this file".
func (e *UnsupportedError) Why() string {
	return fmt.Sprintf("line %d, column %d: %s is not supported in this file", e.Mark.Line+1, e.Mark.Column+1, e.What)
}
