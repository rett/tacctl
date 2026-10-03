package pyyaml

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/rett/tacctl/internal/conf/py"
)

// This file is composer.py and the implicit part of resolver.py of PyYAML
// 6.0.1.

type nodeKind int

const (
	nScalar nodeKind = iota
	nSequence
	nMapping
)

// nodeIDs are the 'id' attributes of nodes.py.
var nodeIDs = [...]string{nScalar: "scalar", nSequence: "sequence", nMapping: "mapping"}

type pair struct{ key, value *node }

type node struct {
	kind       nodeKind
	tag        string
	value      string // scalar
	style      rune
	items      []*node // sequence
	pairs      []pair  // mapping
	start, end Mark
}

func (n *node) id() string { return nodeIDs[n.kind] }

const (
	tagPrefix    = "tag:yaml.org,2002:"
	tagStr       = tagPrefix + "str"
	tagSeq       = tagPrefix + "seq"
	tagMap       = tagPrefix + "map"
	tagBool      = tagPrefix + "bool"
	tagFloat     = tagPrefix + "float"
	tagInt       = tagPrefix + "int"
	tagMerge     = tagPrefix + "merge"
	tagNull      = tagPrefix + "null"
	tagTimestamp = tagPrefix + "timestamp"
	tagValue     = tagPrefix + "value"
	tagYAML      = tagPrefix + "yaml"
	tagBinary    = tagPrefix + "binary"
	tagOmap      = tagPrefix + "omap"
	tagPairs     = tagPrefix + "pairs"
	tagSet       = tagPrefix + "set"
)

// pyRegexp compiles a resolver.py pattern (re.X whitespace removed);
// Python's '$' also matches before a final newline.
func pyRegexp(body string) *regexp.Regexp {
	return regexp.MustCompile(`^(?:` + body + `)\n?$`)
}

type implicitResolver struct {
	tag   string
	re    *regexp.Regexp
	first string // the first characters it is registered for; "\x00" stands for the empty scalar
}

// implicitResolvers is resolver.Resolver in registration order.
var implicitResolvers = []implicitResolver{
	{tagBool, pyRegexp(`yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF`), "yYnNtTfFoO"},
	{tagFloat, pyRegexp(`[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?` +
		`|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?` +
		`|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*` +
		`|[-+]?\.(?:inf|Inf|INF)` +
		`|\.(?:nan|NaN|NAN)`), "-+0123456789."},
	{tagInt, pyRegexp(`[-+]?0b[0-1_]+` +
		`|[-+]?0[0-7_]+` +
		`|[-+]?(?:0|[1-9][0-9_]*)` +
		`|[-+]?0x[0-9a-fA-F_]+` +
		`|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+`), "-+0123456789"},
	{tagMerge, pyRegexp(`<<`), "<"},
	{tagNull, pyRegexp(`~|null|Null|NULL|`), "~nN\x00"},
	{tagTimestamp, pyRegexp(`[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]` +
		`|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?` +
		`(?:[Tt]|[ \t]+)[0-9][0-9]?` +
		`:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?` +
		`(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?`), "0123456789"},
	{tagValue, pyRegexp(`=`), "="},
	{tagYAML, pyRegexp(`!|&|\*`), "!&*"},
}

// resolve is BaseResolver.resolve without path resolvers.
func resolve(kind nodeKind, value string, implicit bool) string {
	switch kind {
	case nSequence:
		return tagSeq
	case nMapping:
		return tagMap
	}
	if implicit {
		first := rune(0)
		for _, r := range value {
			first = r
			break
		}
		for _, ir := range implicitResolvers {
			if slices.Contains([]rune(ir.first), first) && ir.re.MatchString(value) {
				return ir.tag
			}
		}
	}
	return tagStr
}

type composer struct {
	*parser
	anchors map[string]*node
	// aliased and merged are the first alias and the first merge key in
	// the document (tacctl supports neither); nil when there is none.
	aliased *Mark
	merged  *Mark
}

func (c *composer) getSingleNode() *node {
	c.getEvent() // STREAM-START
	var doc *node
	if !c.checkEvent(evStreamEnd) {
		doc = c.composeDocument()
	}
	if !c.checkEvent(evStreamEnd) {
		ev := c.getEvent()
		fail(&Error{Context: "expected a single document in the stream", ContextMark: markPtr(doc.start),
			Problem: "but found another document", ProblemMark: markPtr(ev.start)})
	}
	c.getEvent() // STREAM-END
	return doc
}

func (c *composer) composeDocument() *node {
	c.getEvent() // DOCUMENT-START
	n := c.composeNode()
	c.getEvent() // DOCUMENT-END
	c.anchors = map[string]*node{}
	return n
}

func (c *composer) composeNode() *node {
	if c.checkEvent(evAlias) {
		ev := c.getEvent()
		anchor := *ev.anchor
		n, ok := c.anchors[anchor]
		if !ok {
			fail(&Error{Problem: fmt.Sprintf("found undefined alias %s", py.ReprString(anchor)), ProblemMark: markPtr(ev.start)})
		}
		if c.aliased == nil {
			c.aliased = markPtr(ev.start)
		}
		return n
	}
	ev := c.peekEvent()
	if ev.anchor != nil {
		if first, ok := c.anchors[*ev.anchor]; ok {
			fail(&Error{Context: fmt.Sprintf("found duplicate anchor %s; first occurrence", py.ReprString(*ev.anchor)),
				ContextMark: markPtr(first.start), Problem: "second occurrence", ProblemMark: markPtr(ev.start)})
		}
	}
	switch {
	case c.checkEvent(evScalar):
		return c.composeScalarNode(ev.anchor)
	case c.checkEvent(evSequenceStart):
		return c.composeSequenceNode(ev.anchor)
	default:
		return c.composeMappingNode(ev.anchor)
	}
}

func (c *composer) register(anchor *string, n *node) {
	if anchor != nil {
		c.anchors[*anchor] = n
	}
}

func (c *composer) composeScalarNode(anchor *string) *node {
	ev := c.getEvent()
	tag := ""
	if ev.tag == nil || *ev.tag == "!" {
		tag = resolve(nScalar, ev.value, ev.implicit[0])
	} else {
		tag = *ev.tag
	}
	n := &node{kind: nScalar, tag: tag, value: ev.value, style: ev.style, start: ev.start, end: ev.end}
	c.register(anchor, n)
	return n
}

func (c *composer) composeSequenceNode(anchor *string) *node {
	ev := c.getEvent()
	tag := tagSeq
	if ev.tag != nil && *ev.tag != "!" {
		tag = *ev.tag
	}
	n := &node{kind: nSequence, tag: tag, start: ev.start}
	c.register(anchor, n)
	for !c.checkEvent(evSequenceEnd) {
		n.items = append(n.items, c.composeNode())
	}
	n.end = c.getEvent().end
	return n
}

func (c *composer) composeMappingNode(anchor *string) *node {
	ev := c.getEvent()
	tag := tagMap
	if ev.tag != nil && *ev.tag != "!" {
		tag = *ev.tag
	}
	n := &node{kind: nMapping, tag: tag, start: ev.start}
	c.register(anchor, n)
	for !c.checkEvent(evMappingEnd) {
		k := c.composeNode()
		if k.tag == tagMerge && c.merged == nil {
			c.merged = markPtr(k.start)
		}
		v := c.composeNode()
		n.pairs = append(n.pairs, pair{k, v})
	}
	n.end = c.getEvent().end
	return n
}
