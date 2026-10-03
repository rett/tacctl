package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rett/tacctl/internal/yamlpy"
)

// The two readers of a legacy tacquito.yaml (lib/model.sh at 0.1.16):
//
//   - ReadLegacyYAML is yaml.safe_load, what the legacy loader and the
//     renderer's read-back use. Unlike yamlpy.Decode (the store's reader)
//     it resolves anchors and aliases, because every tacquito.yaml tacctl
//     ever rendered uses them (&bcrypt_<user>, &exec_<group>, ...). An
//     alias yields the very value of its anchor, as PyYAML's does: a
//     *yamlpy.Map met twice is the same pointer, which is how the loader
//     tells the anchor holders at the top level from content nothing
//     refers to.
//   - ReadBaseYAML is yaml.load(Loader=yaml.BaseLoader), what the
//     equivalence check uses: every scalar is the text that was written.
//
// yaml.v3 parses both (it is also what tacquito reads the file with), so a
// syntax error is reported in yaml.v3's words, as for the store (go-rewrite
// plan 3.9). Scalars of ReadLegacyYAML are typed by PyYAML's YAML 1.1 rules
// through yamlpy.Decode, which refuses what tacctl never writes (merge keys,
// keys that are not strings, timestamps with a time of day, other tags);
// the one exception is an integer outside int64 (an unquoted bcrypt hex
// whose digits happen to be all decimal is one), which safe_load reads as a
// Python int and this reader keeps as a bigInt.

// bigInt is an integer yamlpy.Decode cannot hold: its canonical decimal
// text, as Python's str(int) prints it.
type bigInt string

// readYAMLFile reads path and parses its one document into a yaml.v3 node
// (nil for an empty stream). Errors are *Error, worded as yaml_problem.
func readYAMLFile(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{Msg: path + ": " + strerror(err)}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, yamlProblem(path, err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, &Error{Msg: path + ": expected a single document in the stream"}
	case !errors.Is(err, io.EOF):
		return nil, yamlProblem(path, err)
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil, nil
		}
		return doc.Content[0], nil
	}
	return &doc, nil
}

// unsupported is the error for content a reader refuses: '<path>: not
// supported by tacctl: <what> (line N)'. It never quotes the value.
func unsupported(path string, n *yaml.Node, what string) error {
	return &Error{Msg: fmt.Sprintf("%s: not supported by tacctl: %s (line %d)", path, what, n.Line)}
}

// ReadLegacyYAML is yaml.safe_load of a legacy tacquito.yaml (see above):
// *yamlpy.Map, []any, string, int, bigInt, float64, bool, nil and
// yamlpy.Date, with aliases sharing their anchor's value. An empty file is
// nil. Errors are *Error ('<path>: <problem>'), never quoting the file.
func ReadLegacyYAML(path string) (any, error) {
	root, err := readYAMLFile(path)
	if err != nil || root == nil {
		return nil, err
	}
	d := &nodeReader{path: path, typed: map[*yaml.Node]any{}}
	var scalars []*yaml.Node
	collectScalars(root, &scalars)
	if err := d.typeScalars(scalars); err != nil {
		return nil, err
	}
	return d.build(root, 0)
}

// ReadBaseYAML is yaml.load(f, Loader=yaml.BaseLoader): mappings
// (*yamlpy.Map), sequences ([]any) and strings, whatever the tags; a
// merge key '<<' is an ordinary key. An empty file is nil.
func ReadBaseYAML(path string) (any, error) {
	root, err := readYAMLFile(path)
	if err != nil || root == nil {
		return nil, err
	}
	d := &nodeReader{path: path, base: true}
	return d.build(root, 0)
}

// nodeReader builds values from a node tree.
type nodeReader struct {
	path  string
	base  bool               // BaseLoader: scalars are their text
	typed map[*yaml.Node]any // scalar node -> safe_load value
	memo  map[*yaml.Node]any // anchored node -> its value
	busy  map[*yaml.Node]bool
}

// collectScalars lists every scalar node of the tree, keys included, in
// document order (aliases are not followed: their target is listed where
// it stands).
func collectScalars(n *yaml.Node, out *[]*yaml.Node) {
	switch n.Kind {
	case yaml.ScalarNode:
		*out = append(*out, n)
	case yaml.DocumentNode, yaml.SequenceNode, yaml.MappingNode:
		for _, c := range n.Content {
			collectScalars(c, out)
		}
	}
}

// scalarCopy is n alone: no anchor, no comments, the same tag, style and
// text.
func scalarCopy(n *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: n.Tag, Style: n.Style, Value: n.Value}
}

// decodeScalars types scalar nodes with yamlpy.Decode, by writing them as
// one block sequence (yaml.v3 keeps each node's style and explicit tag) and
// reading that back.
func decodeScalars(nodes []*yaml.Node) ([]any, error) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, n := range nodes {
		seq.Content = append(seq.Content, scalarCopy(n))
	}
	text, err := yaml.Marshal(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{seq}})
	if err != nil {
		return nil, err
	}
	v, err := yamlpy.Decode(text)
	if err != nil {
		return nil, err
	}
	list, ok := v.([]any)
	if !ok || len(list) != len(nodes) {
		return nil, errors.New("internal: scalar read-back has the wrong shape")
	}
	return list, nil
}

// reYAMLInt is the int resolver of PyYAML's YAML 1.1 rules.
var reYAMLInt = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+` +
	`|[-+]?0[0-7_]+` +
	`|[-+]?(?:0|[1-9][0-9_]*)` +
	`|[-+]?0x[0-9a-fA-F_]+` +
	`|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)

// typeScalars fills d.typed for the plain and quoted scalars. A batch that
// yamlpy refuses is retried one scalar at a time to find the culprit.
func (d *nodeReader) typeScalars(nodes []*yaml.Node) error {
	var batch []*yaml.Node
	for _, n := range nodes {
		// A key's '=' is the string '=', '<<' a merge (flatten_mapping);
		// decodeScalars would read both as values.
		if n.Style&(yaml.TaggedStyle|yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0 &&
			(n.Value == "=" || n.Value == "<<") {
			continue
		}
		batch = append(batch, n)
	}
	if vals, err := decodeScalars(batch); err == nil {
		for i, n := range batch {
			d.typed[n] = vals[i]
		}
		return nil
	}
	for _, n := range batch {
		vals, err := decodeScalars([]*yaml.Node{n})
		if err == nil {
			d.typed[n] = vals[0]
			continue
		}
		if b, ok := plainBigInt(n); ok {
			d.typed[n] = b
			continue
		}
		what := err.Error()
		if i := strings.Index(what, "unsupported value: "); i >= 0 {
			what = what[i+len("unsupported value: "):]
		} else {
			what = "a scalar YAML 1.1 cannot type"
		}
		return unsupported(d.path, n, what)
	}
	return nil
}

// plainBigInt is construct_yaml_int for an untagged plain integer that
// yamlpy refused, i.e. one outside int64.
func plainBigInt(n *yaml.Node) (bigInt, bool) {
	if n.Style != 0 || !reYAMLInt.MatchString(n.Value) {
		return "", false
	}
	value := strings.ReplaceAll(n.Value, "_", "")
	neg := value[0] == '-'
	if value[0] == '-' || value[0] == '+' {
		value = value[1:]
	}
	var b big.Int
	ok := true
	switch {
	case strings.HasPrefix(value, "0b"):
		_, ok = b.SetString(value[2:], 2)
	case strings.HasPrefix(value, "0x"):
		_, ok = b.SetString(value[2:], 16)
	case len(value) > 1 && value[0] == '0':
		_, ok = b.SetString(value, 8)
	case strings.Contains(value, ":"):
		for _, part := range strings.Split(value, ":") {
			var d big.Int
			if _, ok = d.SetString(part, 10); !ok {
				break
			}
			b.Mul(&b, big.NewInt(60))
			b.Add(&b, &d)
		}
	default:
		_, ok = b.SetString(value, 10)
	}
	if !ok {
		return "", false
	}
	if neg {
		b.Neg(&b)
	}
	return bigInt(b.String()), true
}

// key is the mapping key of node k (always a string).
func (d *nodeReader) key(k *yaml.Node) (string, error) {
	if k.Kind == yaml.AliasNode && k.Alias != nil && k.Alias.Kind == yaml.ScalarNode {
		k = k.Alias
	}
	if k.Kind != yaml.ScalarNode {
		if d.base {
			return "", &Error{Msg: fmt.Sprintf("%s: found unhashable key (line %d)", d.path, k.Line)}
		}
		return "", unsupported(d.path, k, "a key that is not a scalar")
	}
	if d.base {
		return k.Value, nil
	}
	if k.Style&(yaml.TaggedStyle|yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0 {
		switch k.Value {
		case "=":
			return "=", nil
		case "<<":
			return "", unsupported(d.path, k, "a merge key '<<'")
		}
	}
	s, ok := d.typed[k].(string)
	if !ok {
		return "", unsupported(d.path, k, "a key that is not a string")
	}
	return s, nil
}

func (d *nodeReader) remember(n *yaml.Node, v any) {
	if n.Anchor == "" {
		return
	}
	if d.memo == nil {
		d.memo = map[*yaml.Node]any{}
	}
	d.memo[n] = v
}

func (d *nodeReader) build(n *yaml.Node, depth int) (any, error) {
	if depth >= yamlpy.MaxDepth {
		return nil, unsupported(d.path, n, fmt.Sprintf("collections nested deeper than %d", yamlpy.MaxDepth))
	}
	switch n.Kind {
	case yaml.AliasNode:
		t := n.Alias
		if t == nil {
			return nil, unsupported(d.path, n, "an alias without an anchor")
		}
		if d.busy[t] {
			return nil, unsupported(d.path, n, "an alias inside its own anchor")
		}
		if v, ok := d.memo[t]; ok {
			return v, nil
		}
		return d.build(t, depth)
	case yaml.ScalarNode:
		var v any = n.Value
		if !d.base {
			tv, ok := d.typed[n]
			if !ok { // a plain '=' or '<<' as a value
				return nil, unsupported(d.path, n, "the indicator "+PyRepr(n.Value)+" as a value")
			}
			v = tv
		}
		d.remember(n, v)
		return v, nil
	case yaml.SequenceNode:
		if !d.base && n.Style&yaml.TaggedStyle != 0 && n.Tag != "!!seq" {
			return nil, unsupported(d.path, n, "tag "+n.Tag)
		}
		d.enter(n)
		defer d.leave(n)
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := d.build(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		d.remember(n, out)
		return out, nil
	case yaml.MappingNode:
		if !d.base && n.Style&yaml.TaggedStyle != 0 && n.Tag != "!!map" {
			return nil, unsupported(d.path, n, "tag "+n.Tag)
		}
		m := yamlpy.NewMap()
		d.remember(n, m)
		d.enter(n)
		defer d.leave(n)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := d.key(n.Content[i])
			if err != nil {
				return nil, err
			}
			v, err := d.build(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			m.Set(k, v)
		}
		return m, nil
	}
	return nil, unsupported(d.path, n, fmt.Sprintf("node kind %d", n.Kind))
}

func (d *nodeReader) enter(n *yaml.Node) {
	if d.busy == nil {
		d.busy = map[*yaml.Node]bool{}
	}
	d.busy[n] = true
}

func (d *nodeReader) leave(n *yaml.Node) { delete(d.busy, n) }
