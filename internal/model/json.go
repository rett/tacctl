package model

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// ErrNotJSON is returned for a value Python's json module cannot write (a
// YAML date anywhere but password_changed; json.dumps raises TypeError in
// 0.1.16).
var ErrNotJSON = errors.New("model: value is not JSON serializable")

// JSON is json.dumps(v, sort_keys=True): compact with Python's separators
// (', ' and ': '), keys sorted, non-ASCII escaped (ensure_ascii).
func JSON(v any) (string, error) {
	var b strings.Builder
	if err := writeJSON(&b, v, -1, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// JSONIndent is json.dumps(v, indent=n, sort_keys=True) (the format of
// 'store show --json' and of the model goldens, which are 'json.tool
// --sort-keys' output, indent 4). No trailing newline.
func JSONIndent(v any, n int) (string, error) {
	var b strings.Builder
	if err := writeJSON(&b, v, n, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// StoreJSON is the model JSON of a store document: what model_dump prints
// (JSON(s.Doc())).
func StoreJSON(s *store.Store) (string, error) { return JSON(s.Doc()) }

func newline(b *strings.Builder, indent, level int) {
	if indent < 0 {
		return
	}
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", indent*level))
}

func writeJSON(b *strings.Builder, v any, indent, level int) error {
	itemSep := ", "
	if indent >= 0 {
		itemSep = ","
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(x))
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(store.PyFloat(x))
		}
	case string:
		writeJSONString(b, x)
	case []string:
		items := make([]any, len(x))
		for i, s := range x {
			items[i] = s
		}
		return writeJSON(b, items, indent, level)
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				b.WriteString(itemSep)
			}
			newline(b, indent, level+1)
			if err := writeJSON(b, it, indent, level+1); err != nil {
				return err
			}
		}
		newline(b, indent, level)
		b.WriteByte(']')
	case *yamlpy.Map:
		if x.Len() == 0 {
			b.WriteString("{}")
			return nil
		}
		keys := x.Keys()
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(itemSep)
			}
			newline(b, indent, level+1)
			writeJSONString(b, k)
			b.WriteString(": ")
			val, _ := x.Get(k)
			if err := writeJSON(b, val, indent, level+1); err != nil {
				return err
			}
		}
		newline(b, indent, level)
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: %T", ErrNotJSON, v)
	}
	return nil
}

// writeJSONString is json's py_encode_basestring_ascii.
func writeJSONString(b *strings.Builder, s string) {
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
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(b, `\u%04x`, r)
			case r < utf8.RuneSelf:
				b.WriteRune(r)
			case r < 0x10000:
				fmt.Fprintf(b, `\u%04x`, r)
			default:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			}
		}
	}
	b.WriteByte('"')
}

// sortedCopy turns every mapping of v into one with sorted keys (the
// document 'store show' re-reads from the sorted JSON).
func sortedCopy(v any) any {
	switch x := v.(type) {
	case *yamlpy.Map:
		keys := x.Keys()
		sort.Strings(keys)
		out := yamlpy.NewMap()
		for _, k := range keys {
			val, _ := x.Get(k)
			out.Set(k, sortedCopy(val))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, it := range x {
			out[i] = sortedCopy(it)
		}
		return out
	}
	return v
}

// ShowJSON is 'store show --json': json.dumps(model, indent=4,
// sort_keys=True) plus the newline print adds.
func ShowJSON(s *store.Store) (string, error) {
	out, err := JSONIndent(s.Doc(), 4)
	if err != nil {
		return "", err
	}
	return out + "\n", nil
}

// ShowYAML is 'store show': the model (keys sorted at every level, as the
// JSON round trip of 0.1.16 leaves them) as yaml.safe_dump(sort_keys=False,
// default_flow_style=None, width=4096) writes it.
func ShowYAML(s *store.Store) ([]byte, error) {
	if _, err := JSON(s.Doc()); err != nil {
		return nil, err
	}
	return yamlpy.Emit(sortedCopy(s.Doc()), yamlpy.StoreOptions)
}
