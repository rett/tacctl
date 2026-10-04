package yamlpy

import (
	"fmt"
	"strings"
)

// eventKind is the class of an emitter.py event.
type eventKind int

const (
	evStreamStart eventKind = iota
	evStreamEnd
	evDocumentStart
	evDocumentEnd
	evScalar
	evSequenceStart
	evSequenceEnd
	evMappingStart
	evMappingEnd
)

// event carries what the emitter reads of a PyYAML event. There are no
// anchors, no explicit document markers, no version or tag directives and
// no scalar style requests (safe_dump sets none of them); collection tags
// are always implicit.
type event struct {
	kind     eventKind
	tag      string  // scalars
	implicit [2]bool // scalars: (plain, non-plain) as the serializer computes it
	value    string  // scalars
	flow     bool    // collection start: flow_style
}

// Scalar styles, as emitter.py's self.style: "" plain, "'" and '"'.
const (
	stylePlain  = ""
	styleSingle = "'"
	styleDouble = "\""
)

// noIndent stands for emitter.py's self.indent = None.
const noIndent = -1

// emitter is emitter.py's Emitter with the parts safe_dump never reaches
// left out (canonical output, anchors, tags directives, block scalar
// styles, encodings other than str). Every method keeps the name and the
// order of statements of the Python method it ports.
type emitter struct {
	out strings.Builder

	// The event list (built in full up front; emitter.py peeks at most at
	// the next event, events[0] there, events[pos+1] here).
	events []event
	pos    int
	ev     *event

	states []func() error
	state  func() error

	indents []int
	indent  int

	flowLevel int

	rootContext      bool
	sequenceContext  bool
	mappingContext   bool
	simpleKeyContext bool

	line       int
	column     int
	whitespace bool
	indention  bool

	openEnded bool

	bestIndent    int
	bestWidth     int
	bestLineBreak string
}

func newEmitter(events []event, width int) *emitter {
	e := &emitter{
		events:        events,
		indent:        noIndent,
		whitespace:    true,
		indention:     true,
		bestIndent:    2,
		bestWidth:     80,
		bestLineBreak: "\n",
	}
	if width > e.bestIndent*2 {
		e.bestWidth = width
	}
	e.state = e.expectStreamStart
	return e
}

// run feeds every event to the state machine (Emitter.emit).
func (e *emitter) run() error {
	for e.pos = 0; e.pos < len(e.events); e.pos++ {
		e.ev = &e.events[e.pos]
		if err := e.state(); err != nil {
			return err
		}
	}
	return nil
}

// next is emitter.py's self.events[0], or nil when there is none.
func (e *emitter) next() *event {
	if e.pos+1 < len(e.events) {
		return &e.events[e.pos+1]
	}
	return nil
}

func (e *emitter) popState() {
	e.state = e.states[len(e.states)-1]
	e.states = e.states[:len(e.states)-1]
}

func (e *emitter) pushState(s func() error) { e.states = append(e.states, s) }

func (e *emitter) popIndent() {
	e.indent = e.indents[len(e.indents)-1]
	e.indents = e.indents[:len(e.indents)-1]
}

func (e *emitter) increaseIndent(flow, indentless bool) {
	e.indents = append(e.indents, e.indent)
	if e.indent == noIndent {
		if flow {
			e.indent = e.bestIndent
		} else {
			e.indent = 0
		}
	} else if !indentless {
		e.indent += e.bestIndent
	}
}

func unexpected(want string, ev *event) error {
	return fmt.Errorf("yamlpy: internal error: expected %s, but got event %d", want, ev.kind)
}

// Stream handlers.

func (e *emitter) expectStreamStart() error {
	if e.ev.kind != evStreamStart {
		return unexpected("StreamStartEvent", e.ev)
	}
	e.state = e.expectFirstDocumentStart
	return nil
}

func (e *emitter) expectNothing() error { return unexpected("nothing", e.ev) }

// Document handlers.

func (e *emitter) expectFirstDocumentStart() error { return e.expectDocumentStart(true) }

func (e *emitter) expectDocumentStartNotFirst() error { return e.expectDocumentStart(false) }

func (e *emitter) expectDocumentStart(first bool) error {
	switch e.ev.kind {
	case evDocumentStart:
		implicit := first && !e.checkEmptyDocument()
		if !implicit {
			e.writeIndent()
			e.writeIndicator("---", true, false, false)
		}
		e.state = e.expectDocumentRoot
	case evStreamEnd:
		if e.openEnded {
			e.writeIndicator("...", true, false, false)
			e.writeIndent()
		}
		e.state = e.expectNothing
	default:
		return unexpected("DocumentStartEvent", e.ev)
	}
	return nil
}

func (e *emitter) expectDocumentEnd() error {
	if e.ev.kind != evDocumentEnd {
		return unexpected("DocumentEndEvent", e.ev)
	}
	e.writeIndent()
	e.state = e.expectDocumentStartNotFirst
	return nil
}

func (e *emitter) expectDocumentRoot() error {
	e.pushState(e.expectDocumentEnd)
	return e.expectNode(true, false, false, false)
}

// Node handlers.

func (e *emitter) expectNode(root, sequence, mapping, simpleKey bool) error {
	e.rootContext = root
	e.sequenceContext = sequence
	e.mappingContext = mapping
	e.simpleKeyContext = simpleKey
	switch e.ev.kind {
	case evScalar:
		return e.expectScalar()
	case evSequenceStart:
		if e.flowLevel > 0 || e.ev.flow || e.checkEmptySequence() {
			e.expectFlowSequence()
		} else {
			e.expectBlockSequence()
		}
	case evMappingStart:
		if e.flowLevel > 0 || e.ev.flow || e.checkEmptyMapping() {
			e.expectFlowMapping()
		} else {
			e.expectBlockMapping()
		}
	default:
		return unexpected("NodeEvent", e.ev)
	}
	return nil
}

func (e *emitter) expectScalar() error {
	e.increaseIndent(true, false)
	e.processScalar()
	e.popIndent()
	e.popState()
	return nil
}

// Flow sequence handlers.

func (e *emitter) expectFlowSequence() {
	e.writeIndicator("[", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = e.expectFirstFlowSequenceItem
}

func (e *emitter) expectFirstFlowSequenceItem() error {
	if e.ev.kind == evSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.popState()
		return nil
	}
	if e.column > e.bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	return e.expectNode(false, true, false, false)
}

func (e *emitter) expectFlowSequenceItem() error {
	if e.ev.kind == evSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.popState()
		return nil
	}
	e.writeIndicator(",", false, false, false)
	if e.column > e.bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	return e.expectNode(false, true, false, false)
}

// Flow mapping handlers.

func (e *emitter) expectFlowMapping() {
	e.writeIndicator("{", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = e.expectFirstFlowMappingKey
}

func (e *emitter) expectFirstFlowMappingKey() error {
	if e.ev.kind == evMappingEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("}", false, false, false)
		e.popState()
		return nil
	}
	if e.column > e.bestWidth {
		e.writeIndent()
	}
	return e.flowMappingKey()
}

func (e *emitter) expectFlowMappingKey() error {
	if e.ev.kind == evMappingEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("}", false, false, false)
		e.popState()
		return nil
	}
	e.writeIndicator(",", false, false, false)
	if e.column > e.bestWidth {
		e.writeIndent()
	}
	return e.flowMappingKey()
}

// flowMappingKey is the tail shared by expect_first_flow_mapping_key and
// expect_flow_mapping_key.
func (e *emitter) flowMappingKey() error {
	if e.checkSimpleKey() {
		e.pushState(e.expectFlowMappingSimpleValue)
		return e.expectNode(false, false, true, true)
	}
	e.writeIndicator("?", true, false, false)
	e.pushState(e.expectFlowMappingValue)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectFlowMappingSimpleValue() error {
	e.writeIndicator(":", false, false, false)
	e.pushState(e.expectFlowMappingKey)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectFlowMappingValue() error {
	if e.column > e.bestWidth {
		e.writeIndent()
	}
	e.writeIndicator(":", true, false, false)
	e.pushState(e.expectFlowMappingKey)
	return e.expectNode(false, false, true, false)
}

// Block sequence handlers.

func (e *emitter) expectBlockSequence() {
	indentless := e.mappingContext && !e.indention
	e.increaseIndent(false, indentless)
	e.state = e.expectFirstBlockSequenceItem
}

func (e *emitter) expectFirstBlockSequenceItem() error { return e.expectBlockSequenceItem(true) }

func (e *emitter) expectNextBlockSequenceItem() error { return e.expectBlockSequenceItem(false) }

func (e *emitter) expectBlockSequenceItem(first bool) error {
	if !first && e.ev.kind == evSequenceEnd {
		e.popIndent()
		e.popState()
		return nil
	}
	e.writeIndent()
	e.writeIndicator("-", true, false, true)
	e.pushState(e.expectNextBlockSequenceItem)
	return e.expectNode(false, true, false, false)
}

// Block mapping handlers.

func (e *emitter) expectBlockMapping() {
	e.increaseIndent(false, false)
	e.state = e.expectFirstBlockMappingKey
}

func (e *emitter) expectFirstBlockMappingKey() error { return e.expectBlockMappingKey(true) }

func (e *emitter) expectNextBlockMappingKey() error { return e.expectBlockMappingKey(false) }

func (e *emitter) expectBlockMappingKey(first bool) error {
	if !first && e.ev.kind == evMappingEnd {
		e.popIndent()
		e.popState()
		return nil
	}
	e.writeIndent()
	if e.checkSimpleKey() {
		e.pushState(e.expectBlockMappingSimpleValue)
		return e.expectNode(false, false, true, true)
	}
	e.writeIndicator("?", true, false, true)
	e.pushState(e.expectBlockMappingValue)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockMappingSimpleValue() error {
	e.writeIndicator(":", false, false, false)
	e.pushState(e.expectNextBlockMappingKey)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockMappingValue() error {
	e.writeIndent()
	e.writeIndicator(":", true, false, true)
	e.pushState(e.expectNextBlockMappingKey)
	return e.expectNode(false, false, true, false)
}

// Checkers.

func (e *emitter) checkEmptySequence() bool {
	n := e.next()
	return e.ev.kind == evSequenceStart && n != nil && n.kind == evSequenceEnd
}

func (e *emitter) checkEmptyMapping() bool {
	n := e.next()
	return e.ev.kind == evMappingStart && n != nil && n.kind == evMappingEnd
}

// checkEmptyDocument: emitter.py tests event.implicit, which for a
// ScalarEvent is a non-empty tuple and so always true, and event.tag is
// None, which a represented scalar never is. So it is always false.
func (e *emitter) checkEmptyDocument() bool { return false }

func (e *emitter) checkSimpleKey() bool {
	length := 0
	var a scalarAnalysis
	// A represented node always has a tag (only implicit, never written),
	// and emitter.py counts its prepared form ('!!str', 5 characters) too:
	// a key of 123 characters or more is written as a complex key ('? ').
	switch e.ev.kind {
	case evScalar:
		length += len(prepareTag(e.ev.tag))
		a = analyzeScalar(e.ev.value)
		length += len([]rune(a.scalar))
	case evSequenceStart:
		length += len(prepareTag(tagSeq))
	case evMappingStart:
		length += len(prepareTag(tagMap))
	}
	return length < 128 &&
		((e.ev.kind == evScalar && !a.empty && !a.multiline) ||
			e.checkEmptySequence() || e.checkEmptyMapping())
}

// Tag and scalar processors.

// processTag is Emitter.process_tag for a scalar (collections always
// have an implicit tag, so nothing is written for them).
func (e *emitter) processTag(style string) {
	if (style == stylePlain && e.ev.implicit[0]) || (style != stylePlain && e.ev.implicit[1]) {
		return
	}
	e.writeIndicator(prepareTag(e.ev.tag), true, false, false)
}

// prepareTag is Emitter.prepare_tag for the tags a represented scalar can
// carry, all under the default '!!' handle.
func prepareTag(tag string) string {
	return "!!" + strings.TrimPrefix(tag, "tag:yaml.org,2002:")
}

func (e *emitter) chooseScalarStyle(a scalarAnalysis) string {
	if e.ev.implicit[0] {
		// not (simple_key_context and (empty or multiline)) and ...
		if (!e.simpleKeyContext || (!a.empty && !a.multiline)) &&
			((e.flowLevel > 0 && a.allowFlowPlain) ||
				(e.flowLevel == 0 && a.allowBlockPlain)) {
			return stylePlain
		}
	}
	// allow_single_quoted and not (simple_key_context and multiline)
	if a.allowSingleQuoted && (!e.simpleKeyContext || !a.multiline) {
		return styleSingle
	}
	return styleDouble
}

func (e *emitter) processScalar() {
	a := analyzeScalar(e.ev.value)
	style := e.chooseScalarStyle(a)
	e.processTag(style)
	split := !e.simpleKeyContext
	switch style {
	case styleDouble:
		e.writeDoubleQuoted(a.scalar, split)
	case styleSingle:
		e.writeSingleQuoted(a.scalar, split)
	default:
		e.writePlain(a.scalar, split)
	}
}

// Writers.

func (e *emitter) write(data string) { e.out.WriteString(data) }

func (e *emitter) writeIndicator(indicator string, needWhitespace, whitespace, indention bool) {
	data := indicator
	if !e.whitespace && needWhitespace {
		data = " " + indicator
	}
	e.whitespace = whitespace
	e.indention = e.indention && indention
	e.column += len(data)
	e.openEnded = false
	e.write(data)
}

func (e *emitter) writeIndent() {
	indent := max(e.indent, 0)
	if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) {
		e.writeLineBreak("")
	}
	if e.column < indent {
		e.whitespace = true
		data := strings.Repeat(" ", indent-e.column)
		e.column = indent
		e.write(data)
	}
}

func (e *emitter) writeLineBreak(data string) {
	if data == "" {
		data = e.bestLineBreak
	}
	e.whitespace = true
	e.indention = true
	e.line++
	e.column = 0
	e.write(data)
}

// The scalar writers index the text by character (rune), as Python does.

func (e *emitter) writeSingleQuoted(s string, split bool) {
	text := []rune(s)
	e.writeIndicator("'", true, false, false)
	spaces := false
	breaks := false
	start, end := 0, 0
	for end <= len(text) {
		ch := rune(-1) // None
		if end < len(text) {
			ch = text[end]
		}
		switch {
		case spaces:
			if ch == -1 || ch != ' ' {
				if start+1 == end && e.column > e.bestWidth && split &&
					start != 0 && end != len(text) {
					e.writeIndent()
				} else {
					data := string(text[start:end])
					e.column += end - start
					e.write(data)
				}
				start = end
			}
		case breaks:
			if ch == -1 || !runeIn(ch, pyBreaks) {
				if text[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range text[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				start = end
			}
		default:
			if ch == -1 || runeIn(ch, " "+pyBreaks) || ch == '\'' {
				if start < end {
					data := string(text[start:end])
					e.column += end - start
					e.write(data)
					start = end
				}
			}
		}
		if ch == '\'' {
			e.column += 2
			e.write("''")
			start = end + 1
		}
		if ch != -1 {
			spaces = ch == ' '
			breaks = runeIn(ch, pyBreaks)
		}
		end++
	}
	e.writeIndicator("'", false, false, false)
}

// escapeReplacements is Emitter.ESCAPE_REPLACEMENTS.
var escapeReplacements = map[rune]string{
	'\x00':   "0",
	'\x07':   "a",
	'\x08':   "b",
	'\x09':   "t",
	'\x0A':   "n",
	'\x0B':   "v",
	'\x0C':   "f",
	'\x0D':   "r",
	'\x1B':   "e",
	'"':      "\"",
	'\\':     "\\",
	'\u0085': "N",
	'\u00A0': "_",
	'\u2028': "L",
	'\u2029': "P",
}

func (e *emitter) writeDoubleQuoted(s string, split bool) {
	text := []rune(s)
	e.writeIndicator("\"", true, false, false)
	start, end := 0, 0
	for end <= len(text) {
		ch := rune(-1) // None
		if end < len(text) {
			ch = text[end]
		}
		// allow_unicode is False: only printable ASCII goes through as is.
		if ch == -1 || runeIn(ch, "\"\\\u0085\u2028\u2029\uFEFF") || ch < '\x20' || ch > '\x7E' {
			if start < end {
				data := string(text[start:end])
				e.column += end - start
				e.write(data)
				start = end
			}
			if ch != -1 {
				var data string
				if r, ok := escapeReplacements[ch]; ok {
					data = "\\" + r
				} else if ch <= '\xFF' {
					data = fmt.Sprintf("\\x%02X", ch)
				} else if ch <= '\uFFFF' {
					data = fmt.Sprintf("\\u%04X", ch)
				} else {
					data = fmt.Sprintf("\\U%08X", ch)
				}
				e.column += len(data)
				e.write(data)
				start = end + 1
			}
		}
		if 0 < end && end < len(text)-1 && (ch == ' ' || start >= end) &&
			e.column+(end-start) > e.bestWidth && split {
			// text[start:end] is empty in Python when start > end (just
			// after an escape: start = end+1).
			data := "\\"
			if start < end {
				data = string(text[start:end]) + "\\"
			}
			if start < end {
				start = end
			}
			e.column += len([]rune(data))
			e.write(data)
			e.writeIndent()
			e.whitespace = false
			e.indention = false
			if text[start] == ' ' {
				e.column++
				e.write("\\")
			}
		}
		end++
	}
	e.writeIndicator("\"", false, false, false)
}

func (e *emitter) writePlain(s string, split bool) {
	if e.rootContext {
		e.openEnded = true
	}
	if s == "" {
		return
	}
	text := []rune(s)
	if !e.whitespace {
		e.column++
		e.write(" ")
	}
	e.whitespace = false
	e.indention = false
	spaces := false
	breaks := false
	start, end := 0, 0
	for end <= len(text) {
		ch := rune(-1) // None
		if end < len(text) {
			ch = text[end]
		}
		switch {
		case spaces:
			if ch != ' ' {
				if start+1 == end && e.column > e.bestWidth && split {
					e.writeIndent()
					e.whitespace = false
					e.indention = false
				} else {
					data := string(text[start:end])
					e.column += end - start
					e.write(data)
				}
				start = end
			}
		case breaks:
			if !runeIn(ch, pyBreaks) {
				if text[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range text[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				e.whitespace = false
				e.indention = false
				start = end
			}
		default:
			if ch == -1 || runeIn(ch, " "+pyBreaks) {
				data := string(text[start:end])
				e.column += end - start
				e.write(data)
				start = end
			}
		}
		if ch != -1 {
			spaces = ch == ' '
			breaks = runeIn(ch, pyBreaks)
		}
		end++
	}
}
