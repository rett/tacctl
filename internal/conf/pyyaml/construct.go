package pyyaml

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/conf/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// This file is constructor.py's SafeConstructor (PyYAML 6.0.1) for what
// matters to tacctl: the order in which values are constructed (a mapping
// or sequence is filled in a later round, as PyYAML's generators are), the
// ConstructorErrors, and the Python exceptions that escape safe_load
// (ValueError and friends, reported here as *ValueError). Values come out
// in yamlpy's types; what tacctl does not support (sets, ordered maps,
// binary, timestamps with a time, keys that are not strings, integers past
// 64 bits) is built far enough to find errors and then refused by the
// caller.

// seqVal is a Python list under construction: filled in a later round.
type seqVal struct{ items []any }

// setVal is a Python set (only its identity and hashability matter).
type setVal struct{}

// tupleList is the list of (key, value) tuples !!omap and !!pairs give.
type tupleList struct{}

// bytesVal is the bytes !!binary gives.
type bytesVal struct{}

// datetimeVal is a datetime.datetime (a timestamp with a time of day).
type datetimeVal struct{}

type constructor struct {
	constructed map[*node]any
	recursive   map[*node]bool
	generators  []func()
}

func constructorError(context string, cm *Mark, problem string, pm Mark) *Error {
	return &Error{Context: context, ContextMark: cm, Problem: problem, ProblemMark: &pm}
}

func (c *constructor) document(n *node) any {
	data := c.object(n)
	for len(c.generators) > 0 {
		gens := c.generators
		c.generators = nil
		for _, g := range gens {
			g()
		}
	}
	return data
}

func (c *constructor) object(n *node) any {
	if v, ok := c.constructed[n]; ok {
		return v
	}
	if c.recursive[n] {
		fail(constructorError("", nil, "found unconstructable recursive node", n.start))
	}
	c.recursive[n] = true
	var data any
	switch n.tag {
	case tagNull:
		c.scalar(n)
		data = nil
	case tagBool:
		data = c.yamlBool(n)
	case tagInt:
		data = c.yamlInt(n)
	case tagFloat:
		data = c.yamlFloat(n)
	case tagBinary:
		c.yamlBinary(n)
		data = &bytesVal{}
	case tagTimestamp:
		data = c.yamlTimestamp(n)
	case tagOmap, tagPairs:
		data = &tupleList{}
		c.generators = append(c.generators, func() { c.tuples(n) })
	case tagSet:
		data = &setVal{}
		c.generators = append(c.generators, func() { c.mapping(n, nil) })
	case tagStr:
		data = c.scalar(n)
	case tagSeq:
		s := &seqVal{}
		data = s
		c.generators = append(c.generators, func() { s.items = c.sequence(n) })
	case tagMap:
		m := yamlpy.NewMap()
		data = m
		c.generators = append(c.generators, func() { c.mapping(n, m) })
	default:
		fail(constructorError("", nil, fmt.Sprintf("could not determine a constructor for the tag %s", py.ReprString(n.tag)), n.start))
	}
	c.constructed[n] = data
	delete(c.recursive, n)
	return data
}

// scalar is SafeConstructor.construct_scalar.
func (c *constructor) scalar(n *node) string {
	if n.kind == nMapping {
		for _, p := range n.pairs {
			if p.key.tag == tagValue {
				return c.scalar(p.value)
			}
		}
	}
	if n.kind != nScalar {
		fail(constructorError("", nil, fmt.Sprintf("expected a scalar node, but found %s", n.id()), n.start))
	}
	return n.value
}

func (c *constructor) sequence(n *node) []any {
	if n.kind != nSequence {
		fail(constructorError("", nil, fmt.Sprintf("expected a sequence node, but found %s", n.id()), n.start))
	}
	out := make([]any, 0, len(n.items))
	for _, child := range n.items {
		out = append(out, c.object(child))
	}
	return out
}

func hashable(v any) bool {
	switch v.(type) {
	case *yamlpy.Map, *seqVal, *setVal, *tupleList:
		return false
	}
	return true
}

// mapping is SafeConstructor.construct_mapping (flatten, then the base
// class). Keys that are not strings are not stored (the caller refuses
// them); data is nil for a set.
func (c *constructor) mapping(n *node, data *yamlpy.Map) {
	if n.kind == nMapping {
		c.flatten(n)
	}
	if n.kind != nMapping {
		fail(constructorError("", nil, fmt.Sprintf("expected a mapping node, but found %s", n.id()), n.start))
	}
	for _, p := range n.pairs {
		key := c.object(p.key)
		if !hashable(key) {
			fail(constructorError("while constructing a mapping", markPtr(n.start), "found unhashable key", p.key.start))
		}
		value := c.object(p.value)
		if k, ok := key.(string); ok && data != nil {
			data.Set(k, value)
		}
	}
}

func (c *constructor) flatten(n *node) {
	var merge []pair
	index := 0
	for index < len(n.pairs) {
		key, value := n.pairs[index].key, n.pairs[index].value
		switch key.tag {
		case tagMerge:
			n.pairs = append(n.pairs[:index:index], n.pairs[index+1:]...)
			switch value.kind {
			case nMapping:
				c.flatten(value)
				merge = append(merge, value.pairs...)
			case nSequence:
				var submerge [][]pair
				for _, sub := range value.items {
					if sub.kind != nMapping {
						fail(constructorError("while constructing a mapping", markPtr(n.start),
							fmt.Sprintf("expected a mapping for merging, but found %s", sub.id()), sub.start))
					}
					c.flatten(sub)
					submerge = append(submerge, sub.pairs)
				}
				for i := len(submerge) - 1; i >= 0; i-- {
					merge = append(merge, submerge[i]...)
				}
			default:
				fail(constructorError("while constructing a mapping", markPtr(n.start),
					fmt.Sprintf("expected a mapping or list of mappings for merging, but found %s", value.id()), value.start))
			}
		case tagValue:
			key.tag = tagStr
			index++
		default:
			index++
		}
	}
	if len(merge) > 0 {
		n.pairs = append(merge, n.pairs...)
	}
}

func (c *constructor) tuples(n *node) {
	what := "an ordered map"
	if n.tag == tagPairs {
		what = "pairs"
	}
	if n.kind != nSequence {
		fail(constructorError("while constructing "+what, markPtr(n.start),
			fmt.Sprintf("expected a sequence, but found %s", n.id()), n.start))
	}
	for _, sub := range n.items {
		if sub.kind != nMapping {
			fail(constructorError("while constructing "+what, markPtr(n.start),
				fmt.Sprintf("expected a mapping of length 1, but found %s", sub.id()), sub.start))
		}
		if len(sub.pairs) != 1 {
			fail(constructorError("while constructing "+what, markPtr(n.start),
				fmt.Sprintf("expected a single mapping item, but found %d items", len(sub.pairs)), sub.start))
		}
		c.object(sub.pairs[0].key)
		c.object(sub.pairs[0].value)
	}
}

func valueError(n *node, format string, a ...any) {
	fail(&ValueError{Mark: n.start, Msg: fmt.Sprintf(format, a...)})
}

func (c *constructor) yamlBool(n *node) bool {
	v := c.scalar(n)
	switch strings.ToLower(v) {
	case "yes", "true", "on":
		return true
	case "no", "false", "off":
		return false
	}
	valueError(n, "%s is not a boolean", py.ReprString(v))
	return false
}

// yamlInt is construct_yaml_int: an int, or a *big.Int past int64.
func (c *constructor) yamlInt(n *node) any {
	value := strings.ReplaceAll(c.scalar(n), "_", "")
	bad := func(base int, text string) {
		valueError(n, "invalid literal for int() with base %d: %s", base, py.ReprString(text))
	}
	if value == "" {
		bad(10, "")
	}
	sign := int64(1)
	if value[0] == '-' {
		sign = -1
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	parse := func(text string, base int) *big.Int {
		b, ok := intBase(text, base)
		if !ok {
			bad(base, text)
		}
		return b
	}
	var out *big.Int
	switch {
	case value == "0":
		return 0
	case strings.HasPrefix(value, "0b"):
		out = parse(value[2:], 2)
	case strings.HasPrefix(value, "0x"):
		out = parse(value[2:], 16)
	case value != "" && value[0] == '0':
		out = parse(value, 8)
	case strings.Contains(value, ":"):
		out = new(big.Int)
		for _, part := range strings.Split(value, ":") {
			d, ok := py.Int(part)
			if !ok {
				bad(10, part)
			}
			out.Mul(out, big.NewInt(60))
			out.Add(out, d)
		}
	default:
		d, ok := py.Int(value)
		if !ok {
			bad(10, value)
		}
		out = d
	}
	out.Mul(out, big.NewInt(sign))
	if out.IsInt64() {
		return int(out.Int64())
	}
	return out
}

// intBase is int(text, base) for base 2, 8 or 16 (underscores already
// removed): surrounding whitespace, a sign, then the base's optional
// prefix (0b, 0o, 0x in either case) and at least one digit.
func intBase(text string, base int) (*big.Int, bool) {
	t := py.Strip(text)
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	prefix := map[int]string{2: "0b", 8: "0o", 16: "0x"}[base]
	if len(t) >= 2 && strings.EqualFold(t[:2], prefix) {
		t = t[2:]
	}
	if t == "" || strings.ContainsAny(t, "+-") {
		return nil, false
	}
	b, ok := new(big.Int).SetString(t, base)
	if !ok {
		return nil, false
	}
	if neg {
		b.Neg(b)
	}
	return b, true
}

func (c *constructor) yamlFloat(n *node) float64 {
	value := strings.ToLower(strings.ReplaceAll(c.scalar(n), "_", ""))
	if value == "" {
		valueError(n, "could not convert string to float: ''")
	}
	sign := 1.0
	if value[0] == '-' {
		sign = -1
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	conv := func(s string) float64 {
		f, ok := py.Float(s)
		if !ok {
			valueError(n, "could not convert string to float: %s", py.ReprString(s))
		}
		return f
	}
	switch {
	case value == ".inf":
		return sign * math.Inf(1)
	case value == ".nan":
		return math.NaN()
	case strings.Contains(value, ":"):
		parts := strings.Split(value, ":")
		total, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			total += conv(parts[i]) * base
			base *= 60
		}
		return sign * total
	}
	return sign * conv(value)
}

// yamlBinary checks what construct_yaml_binary would raise.
func (c *constructor) yamlBinary(n *node) {
	value := c.scalar(n)
	runes := []rune(value)
	for i, r := range runes {
		if r < 0x80 {
			continue
		}
		j := i
		for j+1 < len(runes) && runes[j+1] >= 0x80 {
			j++
		}
		var msg string
		if j == i {
			msg = fmt.Sprintf("'ascii' codec can't encode character %s in position %d: ordinal not in range(128)",
				charEscape(r), i)
		} else {
			msg = fmt.Sprintf("'ascii' codec can't encode characters in position %d-%d: ordinal not in range(128)", i, j)
		}
		fail(constructorError("", nil, "failed to convert base64 data into ascii: "+msg, n.start))
	}
	if why := base64Problem(value); why != "" {
		fail(constructorError("", nil, "failed to decode base64 data: "+why, n.start))
	}
}

// charEscape is how UnicodeEncodeError names one character: '\xe9'.
func charEscape(r rune) string {
	switch {
	case r <= 0xff:
		return fmt.Sprintf(`'\x%02x'`, r)
	case r <= 0xffff:
		return fmt.Sprintf(`'\u%04x'`, r)
	}
	return fmt.Sprintf(`'\U%08x'`, r)
}

// base64Problem is binascii.a2b_base64 (strict_mode=False, CPython 3.12):
// the error it raises, or "".
func base64Problem(s string) string {
	quadPos, pads, written := 0, 0, 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '=' {
			if quadPos >= 2 {
				pads++
				if quadPos+pads >= 4 {
					return ""
				}
			}
			continue
		}
		if !isBase64(ch) {
			continue
		}
		pads = 0
		switch quadPos {
		case 0:
			quadPos = 1
		case 1:
			quadPos = 2
			written++
		case 2:
			quadPos = 3
			written++
		case 3:
			quadPos = 0
			written++
		}
	}
	switch quadPos {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4",
			written/3*4+1)
	}
	return "Incorrect padding"
}

func isBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

var timestampRegexp = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])` +
	`-([0-9][0-9]?)` +
	`-([0-9][0-9]?)` +
	`(?:(?:[Tt]|[ \t]+)` +
	`([0-9][0-9]?)` +
	`:([0-9][0-9])` +
	`:([0-9][0-9])` +
	`(?:\.([0-9]*))?` +
	`(?:[ \t]*(Z|([-+])([0-9][0-9]?)` +
	`(?::([0-9][0-9]))?))?)?\n?$`)

func (c *constructor) yamlTimestamp(n *node) any {
	c.scalar(n)
	m := timestampRegexp.FindStringSubmatch(n.value)
	if m == nil {
		valueError(n, "%s is not a timestamp", py.ReprString(n.value))
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	checkDate(n, year, month, day)
	if m[4] == "" {
		return yamlpy.Date{Year: year, Month: time.Month(month), Day: day}
	}
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])
	switch {
	case hour > 23:
		valueError(n, "hour must be in 0..23")
	case minute > 59:
		valueError(n, "minute must be in 0..59")
	case second > 59:
		valueError(n, "second must be in 0..59")
	}
	if m[9] != "" {
		tzHour, _ := strconv.Atoi(m[10])
		tzMinute, _ := strconv.Atoi(m[11])
		if tzHour*60+tzMinute >= 24*60 {
			valueError(n, "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24)")
		}
	}
	return &datetimeVal{}
}

// checkDate raises datetime.date's ValueErrors.
func checkDate(n *node, year, month, day int) {
	switch {
	case year < 1:
		valueError(n, "year %d is out of range", year)
	case month < 1 || month > 12:
		valueError(n, "month must be in 1..12")
	}
	if t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC); day < 1 || t.Day() != day {
		valueError(n, "day is out of range for month")
	}
}
