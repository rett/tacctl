package py

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/rett/tacctl/internal/yamlpy"
)

// ErrNotSerializable is json.dumps's TypeError: a value JSON has no form
// for (a date).
var ErrNotSerializable = errors.New("not JSON serializable")

// Dumps is json.dumps(v) with the defaults: ', ' and ': ' separators,
// ensure_ascii (non-ASCII as \uXXXX), NaN and Infinity allowed, keys in
// the mapping's order.
func Dumps(v any) (string, error) {
	var b strings.Builder
	if err := dumps(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func dumps(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int, int64, *big.Int:
		b.WriteString(Repr(x))
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(FloatRepr(x))
		}
	case string:
		jsonString(b, x)
	case *yamlpy.Map:
		b.WriteByte('{')
		first := true
		for k, val := range x.All() {
			if !first {
				b.WriteString(", ")
			}
			first = false
			jsonString(b, k)
			b.WriteString(": ")
			if err := dumps(b, val); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		l, ok := List(v)
		if !ok {
			return fmt.Errorf("object of type %s is %w", TypeName(v), ErrNotSerializable)
		}
		b.WriteByte('[')
		for i, val := range l {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := dumps(b, val); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	}
	return nil
}

// jsonString is py_encode_basestring_ascii.
func jsonString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r <= 0xffff):
				fmt.Fprintf(b, `\u%04x`, r)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// JSONError is json.JSONDecodeError: the message and where it applies.
type JSONError struct {
	Msg    string
	Pos    int // character index
	Line   int
	Column int
}

// Error is str(JSONDecodeError): "<msg>: line L column C (char P)".
func (e *JSONError) Error() string {
	return fmt.Sprintf("%s: line %d column %d (char %d)", e.Msg, e.Line, e.Column, e.Pos)
}

// Loads is json.loads(text): objects as *yamlpy.Map in document order (a
// repeated key keeps its first position and its last value), arrays as
// []any, integers as int (or *big.Int beyond int64), other numbers as
// float64, NaN and Infinity accepted. Errors are *JSONError with the
// messages of CPython 3.12's json scanner.
func Loads(text string) (any, error) {
	d := &jsonDecoder{s: []rune(text)}
	d.skipWS()
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	d.skipWS()
	if d.i != len(d.s) {
		return nil, d.errAt("Extra data", d.i)
	}
	return v, nil
}

type jsonDecoder struct {
	s []rune
	i int
}

func (d *jsonDecoder) errAt(msg string, pos int) *JSONError {
	line, last := 1, -1
	for i := 0; i < pos && i < len(d.s); i++ {
		if d.s[i] == '\n' {
			line++
			last = i
		}
	}
	return &JSONError{Msg: msg, Pos: pos, Line: line, Column: pos - last}
}

func (d *jsonDecoder) skipWS() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *jsonDecoder) has(lit string) bool {
	r := []rune(lit)
	if d.i+len(r) > len(d.s) {
		return false
	}
	for k, c := range r {
		if d.s[d.i+k] != c {
			return false
		}
	}
	return true
}

// value is scan_once at d.i.
func (d *jsonDecoder) value() (any, error) {
	if d.i >= len(d.s) {
		return nil, d.errAt("Expecting value", d.i)
	}
	switch c := d.s[d.i]; {
	case c == '"':
		d.i++
		return d.str()
	case c == '{':
		d.i++
		return d.object()
	case c == '[':
		d.i++
		return d.array()
	case c == 'n' && d.has("null"):
		d.i += 4
		return nil, nil
	case c == 't' && d.has("true"):
		d.i += 4
		return true, nil
	case c == 'f' && d.has("false"):
		d.i += 5
		return false, nil
	case c == 'N' && d.has("NaN"):
		d.i += 3
		return math.NaN(), nil
	case c == 'I' && d.has("Infinity"):
		d.i += 8
		return math.Inf(1), nil
	case c == '-' && d.has("-Infinity"):
		d.i += 9
		return math.Inf(-1), nil
	}
	return d.number()
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// number is the NUMBER_RE match: -?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?
func (d *jsonDecoder) number() (any, error) {
	start, i := d.i, d.i
	if i < len(d.s) && d.s[i] == '-' {
		i++
	}
	switch {
	case i < len(d.s) && d.s[i] == '0':
		i++
	case i < len(d.s) && d.s[i] >= '1' && d.s[i] <= '9':
		for i < len(d.s) && isASCIIDigit(d.s[i]) {
			i++
		}
	default:
		return nil, d.errAt("Expecting value", start)
	}
	isFloat := false
	if i+1 < len(d.s) && d.s[i] == '.' && isASCIIDigit(d.s[i+1]) {
		isFloat = true
		i += 2
		for i < len(d.s) && isASCIIDigit(d.s[i]) {
			i++
		}
	}
	if i < len(d.s) && (d.s[i] == 'e' || d.s[i] == 'E') {
		j := i + 1
		if j < len(d.s) && (d.s[j] == '+' || d.s[j] == '-') {
			j++
		}
		if j < len(d.s) && isASCIIDigit(d.s[j]) {
			for j < len(d.s) && isASCIIDigit(d.s[j]) {
				j++
			}
			isFloat = true
			i = j
		}
	}
	text := string(d.s[start:i])
	d.i = i
	if isFloat {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, d.errAt("Expecting value", start)
		}
		return f, nil
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return int(n), nil
	}
	n, _ := new(big.Int).SetString(text, 10)
	return n, nil
}

// str is scanstring, d.i just after the opening quote.
func (d *jsonDecoder) str() (string, error) {
	begin := d.i - 1
	var b strings.Builder
	for {
		if d.i >= len(d.s) {
			return "", d.errAt("Unterminated string starting at", begin)
		}
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return b.String(), nil
		case c == '\\':
			d.i++
			if d.i >= len(d.s) {
				return "", d.errAt("Unterminated string starting at", begin)
			}
			e := d.s[d.i]
			switch e {
			case '"', '\\', '/':
				b.WriteRune(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, err := d.hex4(d.i + 1)
				if err != nil {
					return "", err
				}
				d.i += 4
				if r >= 0xd800 && r < 0xdc00 && d.i+2 < len(d.s) && d.s[d.i+1] == '\\' && d.s[d.i+2] == 'u' {
					if r2, err := d.hex4(d.i + 3); err == nil && r2 >= 0xdc00 && r2 <= 0xdfff {
						r = utf16.DecodeRune(r, r2)
						d.i += 6
					}
				}
				b.WriteRune(r)
			default:
				return "", d.errAt("Invalid \\escape", d.i-1)
			}
			d.i++
		case c < 0x20:
			return "", d.errAt("Invalid control character at", d.i)
		default:
			b.WriteRune(c)
			d.i++
		}
	}
}

func (d *jsonDecoder) hex4(at int) (rune, error) {
	if at+4 > len(d.s) {
		return 0, d.errAt("Invalid \\uXXXX escape", at-1)
	}
	var r rune
	for k := 0; k < 4; k++ {
		c := d.s[at+k]
		var v rune
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, d.errAt("Invalid \\uXXXX escape", at-1)
		}
		r = r<<4 | v
	}
	return r, nil
}

func (d *jsonDecoder) object() (any, error) {
	m := yamlpy.NewMap()
	d.skipWS()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return m, nil
	}
	for {
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, d.errAt("Expecting property name enclosed in double quotes", d.i)
		}
		d.i++
		k, err := d.str()
		if err != nil {
			return nil, err
		}
		d.skipWS()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, d.errAt("Expecting ':' delimiter", d.i)
		}
		d.i++
		d.skipWS()
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		m.Set(k, v)
		d.skipWS()
		if d.i < len(d.s) && d.s[d.i] == '}' {
			d.i++
			return m, nil
		}
		if d.i >= len(d.s) || d.s[d.i] != ',' {
			return nil, d.errAt("Expecting ',' delimiter", d.i)
		}
		d.i++
		d.skipWS()
	}
}

func (d *jsonDecoder) array() (any, error) {
	out := []any{}
	d.skipWS()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return out, nil
	}
	for {
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		d.skipWS()
		if d.i < len(d.s) && d.s[d.i] == ']' {
			d.i++
			return out, nil
		}
		if d.i >= len(d.s) || d.s[d.i] != ',' {
			return nil, d.errAt("Expecting ',' delimiter", d.i)
		}
		d.i++
		d.skipWS()
	}
}
