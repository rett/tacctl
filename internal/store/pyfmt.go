package store

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/yamlpy"
)

// Python's formatting of the values the store code puts into messages and
// views. The messages of lib/store.sh and lib/model.sh use repr() ({x!r})
// and str() of values that, in a hand-edited store, can be of any YAML
// type; these helpers give the same text for the types LoadRaw (and the
// legacy readers) return.

// PyRepr is Python's repr() of a decoded value: 'text' (or "text" when the
// string holds a single quote and no double quote), None, True, False,
// integers, floats, lists, dicts and datetime.date.
func PyRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return reprString(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return PyFloat(x)
	case yamlpy.Date:
		return fmt.Sprintf("datetime.date(%d, %d, %d)", x.Year, int(x.Month), x.Day)
	case []any:
		parts := make([]string, len(x))
		for i, it := range x {
			parts[i] = PyRepr(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(x))
		for i, it := range x {
			parts[i] = reprString(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *yamlpy.Map:
		parts := make([]string, 0, x.Len())
		for k, it := range x.All() {
			parts = append(parts, reprString(k)+": "+PyRepr(it))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprintf("%v", v)
}

// PyStr is Python's str(): a string as it is, anything else as repr().
func PyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return PyRepr(v)
}

// PyFloat is Python's repr(float).
func PyFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(e[strings.IndexByte(e, 'e')+1:])
	if exp >= -4 && exp < 16 {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return e
}

func reprString(s string) string {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Not valid UTF-8 (cannot come from YAML): show the byte.
			fmt.Fprintf(&b, "\\x%02x", s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == rune(quote):
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r < 0x80 || unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r < 0x10000:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			fmt.Fprintf(&b, "\\U%08x", r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pyStrip is Python's str.strip(): whitespace as str.isspace() sees it,
// which includes the separators U+001C..U+001F besides Go's set.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

// strerror is the C library's text for an errno, as Python puts it into
// OSError.strerror ("Permission denied"); Go's table has the same words
// in lower case.
func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		if s != "" {
			r, size := utf8.DecodeRuneInString(s)
			return string(unicode.ToUpper(r)) + s[size:]
		}
	}
	return err.Error()
}

// osErrorText is the dispatcher's report of an OSError
// ('{e.filename or "I/O"}: {e.strerror}', lib/store.sh _store_main_py).
func osErrorText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Path + ": " + strerror(pe.Err)
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Old + ": " + strerror(le.Err)
	}
	return "I/O: " + strerror(err)
}
