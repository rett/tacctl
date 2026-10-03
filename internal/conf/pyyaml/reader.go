package pyyaml

import (
	"fmt"
)

// Mark is error.Mark: where in the stream something is. Index counts
// characters (not bytes); Line and Column are 0-based, as in PyYAML.
type Mark struct {
	Name   string
	Index  int
	Line   int
	Column int
}

// readChunk is how many characters TextIOWrapper.read(size) is asked for
// by Reader.update_raw (its default size).
const readChunk = 4096

// reader is reader.Reader for a text stream (open(path) in text mode, as
// lib/conf.sh reads tacctl.yaml): the stream is consumed readChunk
// characters at a time, and each chunk is checked for unprintable
// characters only when it is read, so where a ReaderError surfaces among
// other errors is the same as in PyYAML.
type reader struct {
	name   string
	stream []rune // what the text file yields, newlines already translated
	sp     int    // stream position: characters handed out so far

	eof       bool
	buffer    []rune
	pointer   int
	rawBuffer []rune // nil is Python's None
	rawSet    bool
	index     int
	line      int
	column    int
}

// newReader is Reader.__init__ for a file stream. Errors are raised as
// panics of *Error (see fail), as everywhere in this package.
func newReader(text []rune, name string) *reader {
	r := &reader{name: name, stream: text}
	// determine_encoding: read until two characters are buffered or EOF.
	// A text stream yields str, so no codec is chosen.
	for !r.eof && (!r.rawSet || len(r.rawBuffer) < 2) {
		r.updateRaw()
	}
	r.update(1)
	return r
}

// peek returns the character at pointer+i ('\0' past the end, where Python
// would raise IndexError on a malformed buffer).
func (r *reader) peek(i int) rune {
	if r.pointer+i >= len(r.buffer) {
		r.update(i + 1)
	}
	if r.pointer+i < len(r.buffer) {
		return r.buffer[r.pointer+i]
	}
	return 0
}

func (r *reader) prefix(length int) string {
	if r.pointer+length >= len(r.buffer) {
		r.update(length)
	}
	end := min(r.pointer+length, len(r.buffer))
	return string(r.buffer[r.pointer:end])
}

func (r *reader) forward(length int) {
	if r.pointer+length+1 >= len(r.buffer) {
		r.update(length + 1)
	}
	for ; length > 0; length-- {
		if r.pointer >= len(r.buffer) {
			return
		}
		ch := r.buffer[r.pointer]
		r.pointer++
		r.index++
		next := rune(0)
		if r.pointer < len(r.buffer) {
			next = r.buffer[r.pointer]
		}
		if ch == '\n' || ch == '\x85' || ch == '\u2028' || ch == '\u2029' || (ch == '\r' && next != '\n') {
			r.line++
			r.column = 0
		} else if ch != '\uFEFF' {
			r.column++
		}
	}
}

func (r *reader) mark() Mark {
	return Mark{Name: r.name, Index: r.index, Line: r.line, Column: r.column}
}

func nonPrintable(c rune) bool {
	switch {
	case c == 0x09 || c == 0x0A || c == 0x0D:
		return false
	case c >= 0x20 && c <= 0x7E:
		return false
	case c == 0x85:
		return false
	case c >= 0xA0 && c <= 0xD7FF:
		return false
	case c >= 0xE000 && c <= 0xFFFD:
		return false
	case c >= 0x10000 && c <= 0x10FFFF:
		return false
	}
	return true
}

func (r *reader) checkPrintable(data []rune) {
	for i, c := range data {
		if nonPrintable(c) {
			pos := r.index + (len(r.buffer) - r.pointer) + i
			fail(&Error{reader: true, text: fmt.Sprintf(
				"unacceptable character #x%04x: special characters are not allowed\n  in \"%s\", position %d",
				c, r.name, pos)})
		}
	}
}

func (r *reader) update(length int) {
	if !r.rawSet {
		return
	}
	r.buffer = r.buffer[r.pointer:]
	r.pointer = 0
	for len(r.buffer) < length {
		if !r.eof {
			r.updateRaw()
		}
		data := r.rawBuffer
		r.checkPrintable(data)
		r.buffer = append(r.buffer, data...)
		r.rawBuffer = r.rawBuffer[len(data):]
		if r.eof {
			r.buffer = append(r.buffer, 0)
			r.rawBuffer, r.rawSet = nil, false
			break
		}
	}
}

func (r *reader) updateRaw() {
	end := min(r.sp+readChunk, len(r.stream))
	data := r.stream[r.sp:end]
	r.sp = end
	r.rawBuffer = append(r.rawBuffer, data...)
	r.rawSet = true
	if len(data) == 0 {
		r.eof = true
	}
}
