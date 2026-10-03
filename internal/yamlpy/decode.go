package yamlpy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Decode parses one YAML document with yaml.v3 and builds the value
// yaml.safe_load would, in the types Emit takes: *Map (document order; a
// repeated key keeps its first position and its last value, as a Python
// dict does), []any, string, int, float64, bool, nil and Date. Plain
// scalars are typed by PyYAML's YAML 1.1 resolver, not yaml.v3's, so
// 'yes' is true and '0123' is 83 as with safe_load. Empty input (or only
// comments) is nil. More than one document is an error, as for safe_load.
//
// What tacctl never writes is refused with ErrUnsupportedValue instead of
// being approximated: aliases, merge keys ('<<'), keys that are not
// strings, timestamps with a time of day, tags other than the standard
// scalar ones, integers outside int64. Syntax errors are yaml.v3's.
func Decode(data []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, errors.New("yamlpy: expected a single document in the stream")
	case !errors.Is(err, io.EOF):
		return nil, err
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil, nil
		}
		root = root.Content[0]
	}
	return decodeNode(root, "", 0)
}

func decodeNode(n *yaml.Node, path string, depth int) (any, error) {
	if depth >= MaxDepth {
		return nil, errAt(path, fmt.Errorf("%w: nested deeper than %d", ErrUnsupportedValue, MaxDepth))
	}
	switch n.Kind {
	case yaml.ScalarNode:
		v, err := decodeScalar(n, false)
		if err != nil {
			return nil, errAt(path, err)
		}
		return v, nil
	case yaml.SequenceNode:
		if err := plainCollectionTag(n, "!!seq"); err != nil {
			return nil, errAt(path, err)
		}
		out := make([]any, 0, len(n.Content))
		for i, c := range n.Content {
			v, err := decodeNode(c, fmt.Sprintf("%s[%d]", path, i), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		if err := plainCollectionTag(n, "!!map"); err != nil {
			return nil, errAt(path, err)
		}
		m := NewMap()
		for i := 0; i+1 < len(n.Content); i += 2 {
			kn, vn := n.Content[i], n.Content[i+1]
			if kn.Kind != yaml.ScalarNode {
				return nil, errAt(path, fmt.Errorf("%w: a key that is not a scalar", ErrUnsupportedValue))
			}
			kv, err := decodeScalar(kn, true)
			if err != nil {
				return nil, errAt(path, err)
			}
			k, ok := kv.(string)
			if !ok {
				return nil, errAt(path, fmt.Errorf("%w: a key that is not a string (%T)", ErrUnsupportedValue, kv))
			}
			v, err := decodeNode(vn, childPath(path, k), depth+1)
			if err != nil {
				return nil, err
			}
			m.Set(k, v)
		}
		return m, nil
	case yaml.AliasNode:
		return nil, errAt(path, fmt.Errorf("%w: an alias", ErrUnsupportedValue))
	}
	return nil, errAt(path, fmt.Errorf("%w: node kind %d", ErrUnsupportedValue, n.Kind))
}

func plainCollectionTag(n *yaml.Node, std string) error {
	if n.Style&yaml.TaggedStyle != 0 && n.Tag != std {
		return fmt.Errorf("%w: tag %s", ErrUnsupportedValue, n.Tag)
	}
	return nil
}

const quotedOrBlock = yaml.SingleQuotedStyle | yaml.DoubleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle

// decodeScalar is the composer's resolve plus SafeConstructor for one
// scalar. isKey applies flatten_mapping's rules for keys ('=' is the
// string '=', '<<' a merge).
func decodeScalar(n *yaml.Node, isKey bool) (any, error) {
	var tag string
	switch {
	case n.Style&yaml.TaggedStyle != 0:
		switch n.Tag {
		case "!!str":
			tag = tagStr
		case "!!int":
			tag = tagInt
		case "!!float":
			tag = tagFloat
		case "!!bool":
			tag = tagBool
		case "!!null":
			tag = tagNull
		case "!!timestamp":
			tag = tagTimestamp
		default:
			return nil, fmt.Errorf("%w: tag %s", ErrUnsupportedValue, n.Tag)
		}
	case n.Style&quotedOrBlock != 0:
		tag = tagStr
	default:
		tag = resolvePlain(n.Value)
	}
	switch tag {
	case tagStr:
		return n.Value, nil
	case tagNull:
		return nil, nil
	case tagBool:
		switch strings.ToLower(n.Value) {
		case "yes", "true", "on":
			return true, nil
		case "no", "false", "off":
			return false, nil
		}
		return nil, fmt.Errorf("%w: not a boolean", ErrUnsupportedValue)
	case tagInt:
		return constructInt(n.Value)
	case tagFloat:
		return constructFloat(n.Value)
	case tagTimestamp:
		return constructDate(n.Value)
	case tagValue:
		if isKey {
			return n.Value, nil
		}
		return nil, fmt.Errorf("%w: the value indicator '='", ErrUnsupportedValue)
	case tagMerge:
		return nil, fmt.Errorf("%w: a merge key '<<'", ErrUnsupportedValue)
	}
	return nil, fmt.Errorf("%w: tag %s", ErrUnsupportedValue, tag)
}

// constructInt is SafeConstructor.construct_yaml_int, limited to int64.
func constructInt(s string) (any, error) {
	value := strings.ReplaceAll(s, "_", "")
	if value == "" {
		return nil, fmt.Errorf("%w: not an integer", ErrUnsupportedValue)
	}
	neg := value[0] == '-'
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	var u uint64
	var err error
	switch {
	case value == "0":
		return 0, nil
	case strings.HasPrefix(value, "0b"):
		u, err = strconv.ParseUint(value[2:], 2, 64)
	case strings.HasPrefix(value, "0x"):
		u, err = strconv.ParseUint(value[2:], 16, 64)
	case strings.HasPrefix(value, "0"):
		u, err = strconv.ParseUint(value, 8, 64)
	case strings.Contains(value, ":"):
		// Sexagesimal: base 60, most significant part first.
		for _, part := range strings.Split(value, ":") {
			d, perr := strconv.ParseUint(part, 10, 64)
			if perr != nil || u > (math.MaxUint64-d)/60 {
				err = errors.New("out of range")
				break
			}
			u = u*60 + d
		}
	default:
		u, err = strconv.ParseUint(value, 10, 64)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: integer %s", ErrUnsupportedValue, err)
	}
	if neg {
		if u > 1<<63 {
			return nil, fmt.Errorf("%w: integer out of range", ErrUnsupportedValue)
		}
		return int(-int64(u-1) - 1), nil
	}
	if u > math.MaxInt64 {
		return nil, fmt.Errorf("%w: integer out of range", ErrUnsupportedValue)
	}
	return int(u), nil
}

// constructFloat is SafeConstructor.construct_yaml_float.
func constructFloat(s string) (any, error) {
	value := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	if value == "" {
		return nil, fmt.Errorf("%w: not a float", ErrUnsupportedValue)
	}
	sign := 1.0
	if value[0] == '-' {
		sign = -1
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	switch {
	case value == ".inf":
		return sign * math.Inf(1), nil
	case value == ".nan":
		return math.NaN(), nil
	case strings.Contains(value, ":"):
		parts := strings.Split(value, ":")
		total, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			d, err := strconv.ParseFloat(parts[i], 64)
			if err != nil {
				return nil, fmt.Errorf("%w: float %s", ErrUnsupportedValue, err)
			}
			total += d * base
			base *= 60
		}
		return sign * total, nil
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: float %s", ErrUnsupportedValue, err)
	}
	return sign * f, nil
}

// timestampRegexp is SafeConstructor.timestamp_regexp.
var timestampRegexp = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])` +
	`-([0-9][0-9]?)` +
	`-([0-9][0-9]?)` +
	`((?:[Tt]|[ \t]+)` +
	`[0-9][0-9]?` +
	`:[0-9][0-9]` +
	`:[0-9][0-9]` +
	`(?:\.[0-9]*)?` +
	`(?:[ \t]*(?:Z|[-+][0-9][0-9]?` +
	`(?::[0-9][0-9])?))?)?\n?$`)

// constructDate is SafeConstructor.construct_yaml_timestamp for a date
// without a time of day (datetime.date, which refuses an invalid date).
func constructDate(s string) (any, error) {
	m := timestampRegexp.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("%w: not a timestamp", ErrUnsupportedValue)
	}
	if m[4] != "" {
		return nil, fmt.Errorf("%w: a timestamp with a time of day", ErrUnsupportedValue)
	}
	y, _ := strconv.Atoi(m[1])
	mo, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[3])
	date := Date{Year: y, Month: time.Month(mo), Day: d}
	t := date.Time()
	if y < 1 || mo < 1 || mo > 12 || t.Day() != d || int(t.Month()) != mo {
		return nil, fmt.Errorf("%w: invalid date", ErrUnsupportedValue)
	}
	return date, nil
}
