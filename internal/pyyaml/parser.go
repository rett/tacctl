package pyyaml

import (
	"fmt"

	"github.com/rett/tacctl/internal/py"
)

// This file is parser.py of PyYAML 6.0.1, state by state.

type evKind int

const (
	evStreamStart evKind = iota
	evStreamEnd
	evDocumentStart
	evDocumentEnd
	evAlias
	evScalar
	evSequenceStart
	evSequenceEnd
	evMappingStart
	evMappingEnd
)

type event struct {
	kind       evKind
	start, end Mark
	anchor     *string
	tag        *string
	// implicit is (plain-implicit, quoted-implicit) for a scalar; a
	// collection uses implicit[0].
	implicit [2]bool
	value    string
	style    rune
}

var defaultTags = map[string]string{
	"!":  "!",
	"!!": "tag:yaml.org,2002:",
}

type stateFn func() *event

type parser struct {
	*scanner
	current    *event
	tagHandles map[string]string
	states     []stateFn
	marks      []Mark
	state      stateFn
}

func newParser(s *scanner) *parser {
	p := &parser{scanner: s}
	p.state = p.parseStreamStart
	return p
}

func (p *parser) checkEvent(kinds ...evKind) bool {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	if p.current != nil {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if p.current.kind == k {
				return true
			}
		}
	}
	return false
}

func (p *parser) peekEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	return p.current
}

func (p *parser) getEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	v := p.current
	p.current = nil
	return v
}

func (p *parser) popState() stateFn {
	st := p.states[len(p.states)-1]
	p.states = p.states[:len(p.states)-1]
	return st
}

func (p *parser) popMark() {
	p.marks = p.marks[:len(p.marks)-1]
}

func parserError(context string, cm *Mark, problem string, pm Mark) *Error {
	return &Error{Context: context, ContextMark: cm, Problem: problem, ProblemMark: &pm}
}

func (p *parser) parseStreamStart() *event {
	t := p.getToken()
	p.state = p.parseImplicitDocumentStart
	return &event{kind: evStreamStart, start: t.start, end: t.end}
}

func (p *parser) parseImplicitDocumentStart() *event {
	if !p.checkToken(tDirective, tDocumentStart, tStreamEnd) {
		p.tagHandles = defaultTags
		t := p.peekToken()
		p.states = append(p.states, p.parseDocumentEnd)
		p.state = p.parseBlockNode
		return &event{kind: evDocumentStart, start: t.start, end: t.start}
	}
	return p.parseDocumentStart()
}

func (p *parser) parseDocumentStart() *event {
	for p.checkToken(tDocumentEnd) {
		p.getToken()
	}
	if !p.checkToken(tStreamEnd) {
		start := p.peekToken().start
		p.processDirectives()
		if !p.checkToken(tDocumentStart) {
			t := p.peekToken()
			fail(parserError("", nil, fmt.Sprintf("expected '<document start>', but found %s", py.ReprString(t.id())), t.start))
		}
		t := p.getToken()
		p.states = append(p.states, p.parseDocumentEnd)
		p.state = p.parseDocumentContent
		return &event{kind: evDocumentStart, start: start, end: t.end}
	}
	t := p.getToken()
	p.state = nil
	return &event{kind: evStreamEnd, start: t.start, end: t.end}
}

func (p *parser) parseDocumentEnd() *event {
	t := p.peekToken()
	start, end := t.start, t.start
	if p.checkToken(tDocumentEnd) {
		t = p.getToken()
		end = t.end
	}
	p.state = p.parseDocumentStart
	return &event{kind: evDocumentEnd, start: start, end: end}
}

func (p *parser) parseDocumentContent() *event {
	if p.checkToken(tDirective, tDocumentStart, tDocumentEnd, tStreamEnd) {
		ev := p.processEmptyScalar(p.peekToken().start)
		p.state = p.popState()
		return ev
	}
	return p.parseBlockNode()
}

func (p *parser) processDirectives() {
	yamlVersion := false
	p.tagHandles = map[string]string{}
	for p.checkToken(tDirective) {
		t := p.getToken()
		switch t.value {
		case "YAML":
			if yamlVersion {
				fail(parserError("", nil, "found duplicate YAML directive", t.start))
			}
			if t.yamlMajor != 1 {
				fail(parserError("", nil, "found incompatible YAML document (version 1.* is required)", t.start))
			}
			yamlVersion = true
		case "TAG":
			if _, ok := p.tagHandles[t.tagHandle]; ok {
				fail(parserError("", nil, fmt.Sprintf("duplicate tag handle %s", py.ReprString(t.tagHandle)), t.start))
			}
			p.tagHandles[t.tagHandle] = t.tagPrefix
		}
	}
	for k, v := range defaultTags {
		if _, ok := p.tagHandles[k]; !ok {
			p.tagHandles[k] = v
		}
	}
}

func (p *parser) parseBlockNode() *event { return p.parseNode(true, false) }

func (p *parser) parseFlowNode() *event { return p.parseNode(false, false) }

func (p *parser) parseBlockNodeOrIndentlessSequence() *event { return p.parseNode(true, true) }

func (p *parser) parseNode(block, indentlessSequence bool) *event {
	if p.checkToken(tAlias) {
		t := p.getToken()
		p.state = p.popState()
		name := t.value
		return &event{kind: evAlias, anchor: &name, start: t.start, end: t.end}
	}
	var anchor, tag *string
	var start, end, tagMark *Mark
	var handle *string
	var suffix string
	hasTag := false
	if p.checkToken(tAnchor) {
		t := p.getToken()
		start, end = markPtr(t.start), markPtr(t.end)
		a := t.value
		anchor = &a
		if p.checkToken(tTag) {
			t := p.getToken()
			tagMark, end = markPtr(t.start), markPtr(t.end)
			handle, suffix, hasTag = t.handle, t.suffix, true
		}
	} else if p.checkToken(tTag) {
		t := p.getToken()
		start, tagMark, end = markPtr(t.start), markPtr(t.start), markPtr(t.end)
		handle, suffix, hasTag = t.handle, t.suffix, true
		if p.checkToken(tAnchor) {
			t := p.getToken()
			end = markPtr(t.end)
			a := t.value
			anchor = &a
		}
	}
	if hasTag {
		var full string
		if handle != nil {
			prefix, ok := p.tagHandles[*handle]
			if !ok {
				fail(parserError("while parsing a node", start,
					fmt.Sprintf("found undefined tag handle %s", py.ReprString(*handle)), *tagMark))
			}
			full = prefix + suffix
		} else {
			full = suffix
		}
		tag = &full
	}
	if start == nil {
		m := p.peekToken().start
		start, end = &m, &m
	}
	implicit := tag == nil || *tag == "!"
	if indentlessSequence && p.checkToken(tBlockEntry) {
		ev := &event{kind: evSequenceStart, anchor: anchor, tag: tag, start: *start, end: p.peekToken().end}
		ev.implicit[0] = implicit
		p.state = p.parseIndentlessSequenceEntry
		return ev
	}
	switch {
	case p.checkToken(tScalar):
		t := p.getToken()
		ev := &event{kind: evScalar, anchor: anchor, tag: tag, value: t.value, start: *start, end: t.end, style: t.style}
		switch {
		case (t.plain && tag == nil) || (tag != nil && *tag == "!"):
			ev.implicit = [2]bool{true, false}
		case tag == nil:
			ev.implicit = [2]bool{false, true}
		}
		p.state = p.popState()
		return ev
	case p.checkToken(tFlowSequenceStart):
		ev := &event{kind: evSequenceStart, anchor: anchor, tag: tag, start: *start, end: p.peekToken().end}
		ev.implicit[0] = implicit
		p.state = p.parseFlowSequenceFirstEntry
		return ev
	case p.checkToken(tFlowMappingStart):
		ev := &event{kind: evMappingStart, anchor: anchor, tag: tag, start: *start, end: p.peekToken().end}
		ev.implicit[0] = implicit
		p.state = p.parseFlowMappingFirstKey
		return ev
	case block && p.checkToken(tBlockSequenceStart):
		ev := &event{kind: evSequenceStart, anchor: anchor, tag: tag, start: *start, end: p.peekToken().start}
		ev.implicit[0] = implicit
		p.state = p.parseBlockSequenceFirstEntry
		return ev
	case block && p.checkToken(tBlockMappingStart):
		ev := &event{kind: evMappingStart, anchor: anchor, tag: tag, start: *start, end: p.peekToken().start}
		ev.implicit[0] = implicit
		p.state = p.parseBlockMappingFirstKey
		return ev
	case anchor != nil || tag != nil:
		ev := &event{kind: evScalar, anchor: anchor, tag: tag, value: "", start: *start, end: *end}
		ev.implicit = [2]bool{implicit, false}
		p.state = p.popState()
		return ev
	}
	node := "flow"
	if block {
		node = "block"
	}
	t := p.peekToken()
	fail(parserError("while parsing a "+node+" node", start,
		fmt.Sprintf("expected the node content, but found %s", py.ReprString(t.id())), t.start))
	return nil
}

func (p *parser) parseBlockSequenceFirstEntry() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseBlockSequenceEntry()
}

func (p *parser) parseBlockSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		t := p.getToken()
		if !p.checkToken(tBlockEntry, tBlockEnd) {
			p.states = append(p.states, p.parseBlockSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseBlockSequenceEntry
		return p.processEmptyScalar(t.end)
	}
	if !p.checkToken(tBlockEnd) {
		t := p.peekToken()
		fail(parserError("while parsing a block collection", markPtr(p.marks[len(p.marks)-1]),
			fmt.Sprintf("expected <block end>, but found %s", py.ReprString(t.id())), t.start))
	}
	t := p.getToken()
	p.state = p.popState()
	p.popMark()
	return &event{kind: evSequenceEnd, start: t.start, end: t.end}
}

func (p *parser) parseIndentlessSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		t := p.getToken()
		if !p.checkToken(tBlockEntry, tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseIndentlessSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseIndentlessSequenceEntry
		return p.processEmptyScalar(t.end)
	}
	t := p.peekToken()
	p.state = p.popState()
	return &event{kind: evSequenceEnd, start: t.start, end: t.start}
}

func (p *parser) parseBlockMappingFirstKey() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseBlockMappingKey()
}

func (p *parser) parseBlockMappingKey() *event {
	if p.checkToken(tKey) {
		t := p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseBlockMappingValue)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingValue
		return p.processEmptyScalar(t.end)
	}
	if !p.checkToken(tBlockEnd) {
		t := p.peekToken()
		fail(parserError("while parsing a block mapping", markPtr(p.marks[len(p.marks)-1]),
			fmt.Sprintf("expected <block end>, but found %s", py.ReprString(t.id())), t.start))
	}
	t := p.getToken()
	p.state = p.popState()
	p.popMark()
	return &event{kind: evMappingEnd, start: t.start, end: t.end}
}

func (p *parser) parseBlockMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseBlockMappingKey)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingKey
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseBlockMappingKey
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowSequenceFirstEntry() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseFlowSequenceEntry(true)
}

func (p *parser) parseFlowSequenceEntryNext() *event { return p.parseFlowSequenceEntry(false) }

func (p *parser) parseFlowSequenceEntry(first bool) *event {
	if !p.checkToken(tFlowSequenceEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				t := p.peekToken()
				fail(parserError("while parsing a flow sequence", markPtr(p.marks[len(p.marks)-1]),
					fmt.Sprintf("expected ',' or ']', but got %s", py.ReprString(t.id())), t.start))
			}
		}
		if p.checkToken(tKey) {
			t := p.peekToken()
			ev := &event{kind: evMappingStart, start: t.start, end: t.end}
			ev.implicit[0] = true
			p.state = p.parseFlowSequenceEntryMappingKey
			return ev
		} else if !p.checkToken(tFlowSequenceEnd) {
			p.states = append(p.states, p.parseFlowSequenceEntryNext)
			return p.parseFlowNode()
		}
	}
	t := p.getToken()
	p.state = p.popState()
	p.popMark()
	return &event{kind: evSequenceEnd, start: t.start, end: t.end}
}

func (p *parser) parseFlowSequenceEntryMappingKey() *event {
	t := p.getToken()
	if !p.checkToken(tValue, tFlowEntry, tFlowSequenceEnd) {
		p.states = append(p.states, p.parseFlowSequenceEntryMappingValue)
		return p.parseFlowNode()
	}
	p.state = p.parseFlowSequenceEntryMappingValue
	return p.processEmptyScalar(t.end)
}

func (p *parser) parseFlowSequenceEntryMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tFlowEntry, tFlowSequenceEnd) {
			p.states = append(p.states, p.parseFlowSequenceEntryMappingEnd)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowSequenceEntryMappingEnd
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseFlowSequenceEntryMappingEnd
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowSequenceEntryMappingEnd() *event {
	p.state = p.parseFlowSequenceEntryNext
	t := p.peekToken()
	return &event{kind: evMappingEnd, start: t.start, end: t.start}
}

func (p *parser) parseFlowMappingFirstKey() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseFlowMappingKey(true)
}

func (p *parser) parseFlowMappingKeyNext() *event { return p.parseFlowMappingKey(false) }

func (p *parser) parseFlowMappingKey(first bool) *event {
	if !p.checkToken(tFlowMappingEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				t := p.peekToken()
				fail(parserError("while parsing a flow mapping", markPtr(p.marks[len(p.marks)-1]),
					fmt.Sprintf("expected ',' or '}', but got %s", py.ReprString(t.id())), t.start))
			}
		}
		if p.checkToken(tKey) {
			t := p.getToken()
			if !p.checkToken(tValue, tFlowEntry, tFlowMappingEnd) {
				p.states = append(p.states, p.parseFlowMappingValue)
				return p.parseFlowNode()
			}
			p.state = p.parseFlowMappingValue
			return p.processEmptyScalar(t.end)
		} else if !p.checkToken(tFlowMappingEnd) {
			p.states = append(p.states, p.parseFlowMappingEmptyValue)
			return p.parseFlowNode()
		}
	}
	t := p.getToken()
	p.state = p.popState()
	p.popMark()
	return &event{kind: evMappingEnd, start: t.start, end: t.end}
}

func (p *parser) parseFlowMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tFlowEntry, tFlowMappingEnd) {
			p.states = append(p.states, p.parseFlowMappingKeyNext)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowMappingKeyNext
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseFlowMappingKeyNext
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowMappingEmptyValue() *event {
	p.state = p.parseFlowMappingKeyNext
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) processEmptyScalar(m Mark) *event {
	return &event{kind: evScalar, implicit: [2]bool{true, false}, value: "", start: m, end: m}
}
