package yamlpy

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Options are the safe_dump arguments that vary between tacctl's files.
// Both files are written with sort_keys=False (Map order is kept), indent 2,
// allow_unicode=False and no explicit document markers.
type Options struct {
	// FlowLeaves is default_flow_style=None: a collection whose members
	// (and keys) are all scalars is written in flow style ({a: 1}, [x, y]),
	// every other one in block style. False is default_flow_style=False:
	// block style throughout (an empty collection is still [] or {}).
	FlowLeaves bool
	// Width is safe_dump's width: plain and quoted scalars are folded, and
	// flow collections broken, past this column. A value of 4 or less
	// (including 0) means PyYAML's default, 80.
	Width int
}

// StoreOptions are the arguments of store.yaml's dump (lib/store.sh,
// store_dump_text): default_flow_style=None, width=4096.
var StoreOptions = Options{FlowLeaves: true, Width: 4096}

// ConfOptions are the arguments of tacctl.yaml's dump (lib/conf.sh,
// _conf_write): default_flow_style=False, default width.
var ConfOptions = Options{}

// Emit returns yaml.safe_dump(v, sort_keys=False, ...) for v with the
// options. v and everything inside it must be one of:
//
//	nil                         null
//	bool                        true / false
//	int, int8 ... int64,
//	uint, uint8 ... uint64      decimal (Python str(int))
//	float64                     Python repr, as PyYAML writes floats
//	string                      plain or quoted, as PyYAML decides
//	Date                        plain YYYY-MM-DD (a datetime.date)
//	*Map                        mapping, in insertion order
//	[]any, []string, []*Map     sequence
//
// Anything else is ErrUnsupportedValue, a string outside the verified
// domain (see checkDomain) is ErrUnsupportedScalar; both are wrapped with
// the path of the offending value (never the value itself). The output
// ends with a newline; tacctl's file headers are the caller's business.
func Emit(v any, opts Options) ([]byte, error) {
	r := representer{flowLeaves: opts.FlowLeaves, seen: map[*Map]bool{}}
	r.events = append(r.events, event{kind: evStreamStart}, event{kind: evDocumentStart})
	if err := r.represent(v, "", 0); err != nil {
		return nil, err
	}
	r.events = append(r.events, event{kind: evDocumentEnd}, event{kind: evStreamEnd})
	e := newEmitter(r.events, opts.Width)
	if err := e.run(); err != nil {
		return nil, err
	}
	return []byte(e.out.String()), nil
}

// representer is SafeRepresenter + Serializer: it turns a value into the
// event stream the emitter consumes, deciding each collection's flow style
// and each scalar's tag and implicit flags as PyYAML does.
type representer struct {
	flowLeaves bool
	events     []event
	seen       map[*Map]bool
}

func errAt(path string, err error) error {
	if path == "" {
		path = "(root)"
	}
	return fmt.Errorf("yamlpy: %s: %w", path, err)
}

func childPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// scalarText returns the tag and text SafeRepresenter gives a scalar
// value, and ok=false when v is not a scalar.
func scalarText(v any) (tag, text string, ok bool, err error) {
	switch x := v.(type) {
	case nil:
		return tagNull, "null", true, nil
	case bool:
		if x {
			return tagBool, "true", true, nil
		}
		return tagBool, "false", true, nil
	case int:
		return tagInt, strconv.FormatInt(int64(x), 10), true, nil
	case int8:
		return tagInt, strconv.FormatInt(int64(x), 10), true, nil
	case int16:
		return tagInt, strconv.FormatInt(int64(x), 10), true, nil
	case int32:
		return tagInt, strconv.FormatInt(int64(x), 10), true, nil
	case int64:
		return tagInt, strconv.FormatInt(x, 10), true, nil
	case uint:
		return tagInt, strconv.FormatUint(uint64(x), 10), true, nil
	case uint8:
		return tagInt, strconv.FormatUint(uint64(x), 10), true, nil
	case uint16:
		return tagInt, strconv.FormatUint(uint64(x), 10), true, nil
	case uint32:
		return tagInt, strconv.FormatUint(uint64(x), 10), true, nil
	case uint64:
		return tagInt, strconv.FormatUint(x, 10), true, nil
	case float64:
		return tagFloat, pyFloat(x), true, nil
	case string:
		if !checkDomain(x) {
			return "", "", true, ErrUnsupportedScalar
		}
		return tagStr, x, true, nil
	case Date:
		if x.Year < 1 || x.Year > 9999 || x.Time().Day() != x.Day || x.Time().Month() != x.Month {
			return "", "", true, fmt.Errorf("%w: invalid date", ErrUnsupportedValue)
		}
		return tagTimestamp, x.String(), true, nil
	}
	return "", "", false, nil
}

// pyFloat is SafeRepresenter.represent_float: Python's repr(float),
// lower-cased, with '.0' added to a mantissa without a dot.
func pyFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return ".nan"
	case math.IsInf(f, 1):
		return ".inf"
	case math.IsInf(f, -1):
		return "-.inf"
	}
	// repr uses the shortest digits that round-trip, in exponent form
	// when the decimal exponent is below -4 or at least 16.
	value := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(value[strings.IndexByte(value, 'e')+1:])
	if exp >= -4 && exp < 16 {
		value = strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(value, ".") {
			value += ".0"
		}
	}
	value = strings.ToLower(value)
	if !strings.Contains(value, ".") && strings.Contains(value, "e") {
		value = strings.Replace(value, "e", ".0e", 1)
	}
	return value
}

func isScalar(v any) bool {
	_, _, ok, _ := scalarText(v)
	return ok
}

func (r *representer) scalar(tag, text string) {
	// Serializer.serialize_node: implicit = (tag == the tag a plain scalar
	// with this text resolves to, tag == the default (str) tag).
	r.events = append(r.events, event{
		kind:     evScalar,
		tag:      tag,
		implicit: [2]bool{resolvePlain(text) == tag, tag == tagStr},
		value:    text,
	})
}

func (r *representer) represent(v any, path string, depth int) error {
	tag, text, ok, err := scalarText(v)
	if err != nil {
		return errAt(path, err)
	}
	if ok {
		r.scalar(tag, text)
		return nil
	}
	if depth >= MaxDepth {
		return errAt(path, fmt.Errorf("%w: nested deeper than %d", ErrUnsupportedValue, MaxDepth))
	}
	switch x := v.(type) {
	case *Map:
		return r.mapping(x, path, depth)
	case []any:
		return representSeq(r, x, path, depth)
	case []string:
		return representSeq(r, x, path, depth)
	case []*Map:
		return representSeq(r, x, path, depth)
	}
	return errAt(path, fmt.Errorf("%w: type %T", ErrUnsupportedValue, v))
}

// representSeq is represent_sequence: flow style (with FlowLeaves) when
// every item is a scalar, an empty sequence included.
func representSeq[T any](r *representer, items []T, path string, depth int) error {
	flow := r.flowLeaves
	for _, it := range items {
		if !isScalar(it) {
			flow = false
			break
		}
	}
	r.events = append(r.events, event{kind: evSequenceStart, flow: flow})
	for i, it := range items {
		if err := r.represent(it, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
			return err
		}
	}
	r.events = append(r.events, event{kind: evSequenceEnd})
	return nil
}

// mapping is represent_mapping with sort_keys=False: flow style (with
// FlowLeaves) when every value is a scalar (keys always are).
func (r *representer) mapping(m *Map, path string, depth int) error {
	if m == nil {
		return errAt(path, fmt.Errorf("%w: nil *Map", ErrUnsupportedValue))
	}
	if r.seen[m] {
		return errAt(path, fmt.Errorf("%w: the same *Map twice (PyYAML would write an alias)", ErrUnsupportedValue))
	}
	r.seen[m] = true
	flow := r.flowLeaves
	for _, v := range m.All() {
		if !isScalar(v) {
			flow = false
			break
		}
	}
	r.events = append(r.events, event{kind: evMappingStart, flow: flow})
	for k, v := range m.All() {
		if !checkDomain(k) {
			return errAt(path, fmt.Errorf("%w (a key)", ErrUnsupportedScalar))
		}
		kp := childPath(path, k)
		r.scalar(tagStr, k)
		if err := r.represent(v, kp, depth+1); err != nil {
			return err
		}
	}
	r.events = append(r.events, event{kind: evMappingEnd})
	return nil
}
