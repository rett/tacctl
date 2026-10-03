// Package py reproduces the bits of Python 3.12's behaviour that tacctl's
// messages and tacctl.yaml handling depend on: repr() and str() of the
// values a YAML or JSON document holds, ==, str.split()/strip() whitespace,
// int()/float() of a command-line word, json.dumps and an order-keeping
// json.loads. lib/conf.sh (0.1.16) builds its messages with f-strings over
// such values ({value!r}, {extra}), so the Go messages are only identical
// when these are.
//
// Values are the types internal/yamlpy works with: nil, bool, int, int64,
// *big.Int (an integer beyond int64, as Python has), float64, string,
// yamlpy.Date, *yamlpy.Map, []any and []string.
package py

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/yamlpy"
)

// IsSpace is str.isspace() for one character: the Unicode whitespace
// characters plus the four separators U+001C..U+001F.
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Split is str.split() without arguments: the words between runs of
// whitespace, none for a blank string.
func Split(s string) []string {
	return strings.FieldsFunc(s, IsSpace)
}

// Strip is str.strip() without arguments.
func Strip(s string) string {
	return strings.TrimFunc(s, IsSpace)
}

// CollapseSpace is ' '.join(s.split()).
func CollapseSpace(s string) string {
	return strings.Join(Split(s), " ")
}

// isPrintable is str.isprintable() for one character: not in the
// categories Cc, Cf, Cs, Co, Cn, Zl, Zp or Zs, except the ASCII space.
func isPrintable(r rune) bool {
	return r == ' ' || unicode.IsPrint(r)
}

// ReprString is repr(s): single quotes unless s holds a single quote and
// no double quote, backslash escapes for the quote, the backslash, \t, \n,
// \r, and \xhh/\uhhhh/\Uhhhhhhhh for what is not printable. A string that
// is not valid UTF-8 is shown with its invalid bytes as \xhh (Python would
// hold surrogate escapes there).
func ReprString(s string) string {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < ' ' || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case isPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// FloatRepr is repr(f) (which str(f) equals): the shortest text that reads
// back as f, in positional notation for exponents -4..15 (always with a
// fractional part) and in scientific notation otherwise ('1e+16',
// '1e-05'); 'inf', '-inf', 'nan'.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	// Shortest round-trip digits and the decimal exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64) // -d.ddddde+/-XX
	sign := ""
	if e[0] == '-' {
		sign, e = "-", e[1:]
	}
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.Replace(mant, ".", "", 1)
	if exp < -4 || exp >= 16 {
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es, exp = "-", -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, out, es, exp)
	}
	var intPart, frac string
	switch {
	case exp < 0:
		intPart, frac = "0", strings.Repeat("0", -exp-1)+digits
	case exp+1 >= len(digits):
		intPart, frac = digits+strings.Repeat("0", exp+1-len(digits)), "0"
	default:
		intPart, frac = digits[:exp+1], digits[exp+1:]
	}
	return sign + intPart + "." + frac
}

// Repr is repr(v) for the values of a document.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return FloatRepr(x)
	case string:
		return ReprString(x)
	case yamlpy.Date:
		return fmt.Sprintf("datetime.date(%d, %d, %d)", x.Year, int(x.Month), x.Day)
	case *yamlpy.Map:
		parts := make([]string, 0, x.Len())
		for k, val := range x.All() {
			parts = append(parts, ReprString(k)+": "+Repr(val))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, val := range x {
			parts[i] = Repr(val)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(x))
		for i, val := range x {
			parts[i] = ReprString(val)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprintf("<%T>", v)
}

// Str is str(v): a string as it is, a date in ISO form, everything else as
// repr.
func Str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case yamlpy.Date:
		return x.String()
	}
	return Repr(v)
}

// TypeName is type(v).__name__.
func TypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int, int64, *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case yamlpy.Date:
		return "date"
	case *yamlpy.Map:
		return "dict"
	case []any, []string:
		return "list"
	}
	return fmt.Sprintf("%T", v)
}

// IsInt reports isinstance(v, int) and not isinstance(v, bool).
func IsInt(v any) bool {
	switch v.(type) {
	case int, int64, *big.Int:
		return true
	}
	return false
}

// BigInt returns an integer value as a *big.Int (nil if v is no integer;
// bools are not integers here).
func BigInt(v any) *big.Int {
	switch x := v.(type) {
	case int:
		return big.NewInt(int64(x))
	case int64:
		return big.NewInt(x)
	case *big.Int:
		return x
	}
	return nil
}

// numeric returns v as a number for ==: bools count as 0 and 1, as in
// Python. ok is false for a value that is not a number.
func numeric(v any) (i *big.Int, f float64, isFloat, ok bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewInt(1), 0, false, true
		}
		return big.NewInt(0), 0, false, true
	case float64:
		return nil, x, true, true
	}
	if b := BigInt(v); b != nil {
		return b, 0, false, true
	}
	return nil, 0, false, false
}

// List returns a sequence value as []any.
func List(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// Equal is Python's a == b: numbers by value (True == 1, 1 == 1.0),
// strings exactly, lists item by item, dicts as sets of keys with equal
// values (the order does not matter), dates by value, None only to None.
func Equal(a, b any) bool {
	if ai, af, aFloat, ok := numeric(a); ok {
		bi, bf, bFloat, ok := numeric(b)
		if !ok {
			return false
		}
		switch {
		case aFloat && bFloat:
			return af == bf
		case aFloat:
			return floatEqualsInt(af, bi)
		case bFloat:
			return floatEqualsInt(bf, ai)
		}
		return ai.Cmp(bi) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case yamlpy.Date:
		y, ok := b.(yamlpy.Date)
		return ok && x == y
	case *yamlpy.Map:
		y, ok := b.(*yamlpy.Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for k, v := range x.All() {
			w, ok := y.Get(k)
			if !ok || !Equal(v, w) {
				return false
			}
		}
		return true
	}
	la, ok := List(a)
	if !ok {
		return false
	}
	lb, ok := List(b)
	if !ok || len(la) != len(lb) {
		return false
	}
	for i := range la {
		if !Equal(la[i], lb[i]) {
			return false
		}
	}
	return true
}

func floatEqualsInt(f float64, i *big.Int) bool {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return false
	}
	bf := new(big.Float).SetFloat64(f)
	bi, _ := bf.Int(nil)
	return bi.Cmp(i) == 0
}

// Int is int(s) for a str: surrounding whitespace allowed, an optional
// sign, decimal digits of any script with single underscores between
// them. ok is false where Python raises ValueError.
func Int(s string) (*big.Int, bool) {
	t := Strip(s)
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	if t == "" {
		return nil, false
	}
	var digits strings.Builder
	prevUnderscore := true // no leading underscore
	for _, r := range t {
		if r == '_' {
			if prevUnderscore {
				return nil, false
			}
			prevUnderscore = true
			continue
		}
		d, ok := decimalValue(r)
		if !ok {
			return nil, false
		}
		digits.WriteByte(byte('0' + d))
		prevUnderscore = false
	}
	if prevUnderscore {
		return nil, false // trailing underscore
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	if !ok {
		return nil, false
	}
	if neg {
		n.Neg(n)
	}
	return n, true
}

// decimalValue is the digit value of a character of category Nd (Python's
// int() accepts the decimal digits of every script).
func decimalValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if !unicode.Is(unicode.Nd, r) {
		return 0, false
	}
	// Nd code points come in runs of whole 0..9 sequences, each starting at
	// a zero; walk back to the start of the run.
	z := r
	for z > 0 && unicode.Is(unicode.Nd, z-1) {
		z--
	}
	return int((r - z) % 10), true
}

// Float is float(s) for a str: surrounding whitespace, a sign, decimal
// digits (ASCII or any script) with single underscores between digits, an
// optional fraction and exponent, or inf/infinity/nan in any case. ok is
// false where Python raises ValueError.
func Float(s string) (float64, bool) {
	t := Strip(s)
	var b strings.Builder
	for _, r := range t {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		d, ok := decimalValue(r)
		if !ok {
			return 0, false
		}
		b.WriteByte(byte('0' + d))
	}
	t = b.String()
	body := strings.TrimLeft(t, "+-")
	if len(t)-len(body) > 1 {
		return 0, false
	}
	switch strings.ToLower(body) {
	case "inf", "infinity", "nan":
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	if !validFloatUnderscores(body) {
		return 0, false
	}
	clean := strings.ReplaceAll(t, "_", "")
	if strings.ContainsAny(clean, "xXpP") || clean == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, true // Python gives inf (or 0.0) too
		}
		return 0, false
	}
	return f, true
}

// validFloatUnderscores: an underscore only between two digits.
func validFloatUnderscores(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			continue
		}
		if i == 0 || i == len(s)-1 || !isDigit(s[i-1]) || !isDigit(s[i+1]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
