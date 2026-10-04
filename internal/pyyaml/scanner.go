package pyyaml

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/py"
)

// This file is scanner.py of PyYAML 6.0.1, method by method. Only the
// errors and the token stream matter here (values are built from the
// tokens by the parser, composer and constructor of this package).

type tokKind int

const (
	tDirective tokKind = iota
	tDocumentStart
	tDocumentEnd
	tStreamStart
	tStreamEnd
	tBlockSequenceStart
	tBlockMappingStart
	tBlockEnd
	tFlowSequenceStart
	tFlowMappingStart
	tFlowSequenceEnd
	tFlowMappingEnd
	tKey
	tValue
	tBlockEntry
	tFlowEntry
	tAlias
	tAnchor
	tTag
	tScalar
)

// tokenIDs are the 'id' attributes of tokens.py, which the parser's
// messages print with %r.
var tokenIDs = [...]string{
	tDirective:          "<directive>",
	tDocumentStart:      "<document start>",
	tDocumentEnd:        "<document end>",
	tStreamStart:        "<stream start>",
	tStreamEnd:          "<stream end>",
	tBlockSequenceStart: "<block sequence start>",
	tBlockMappingStart:  "<block mapping start>",
	tBlockEnd:           "<block end>",
	tFlowSequenceStart:  "[",
	tFlowMappingStart:   "{",
	tFlowSequenceEnd:    "]",
	tFlowMappingEnd:     "}",
	tKey:                "?",
	tValue:              ":",
	tBlockEntry:         "-",
	tFlowEntry:          ",",
	tAlias:              "<alias>",
	tAnchor:             "<anchor>",
	tTag:                "<tag>",
	tScalar:             "<scalar>",
}

type token struct {
	kind       tokKind
	start, end Mark

	value string // alias, anchor, scalar; directive name

	// DIRECTIVE
	yamlMajor, yamlMinor int
	tagHandle, tagPrefix string
	hasValue             bool

	// TAG: handle is nil for Python's None
	handle *string
	suffix string

	// SCALAR
	plain bool
	style rune // 0 is None
}

func (t *token) id() string { return tokenIDs[t.kind] }

type simpleKey struct {
	tokenNumber int
	required    bool
	index, line int
	column      int
	mark        Mark
}

type scanner struct {
	*reader
	done           bool
	flowLevel      int
	tokens         []*token
	tokensTaken    int
	indent         int
	indents        []int
	allowSimpleKey bool
	// possibleSimpleKeys keeps Python's dict order: levels in insertion
	// order (a deleted and re-added level moves to the end).
	keyLevels []int
	keys      map[int]*simpleKey
}

func newScanner(r *reader) *scanner {
	s := &scanner{reader: r, indent: -1, allowSimpleKey: true, keys: map[int]*simpleKey{}}
	s.fetchStreamStart()
	return s
}

func repr(c rune) string { return py.ReprString(string(c)) }

func in(c rune, set string) bool { return strings.ContainsRune(set, c) }

// The character classes of scanner.py ('\0' is the end of the stream).
const (
	zBreak      = "\x00\r\n\u0085\u2028\u2029"
	zSpaceBreak = "\x00 \r\n\u0085\u2028\u2029"
	zBlank      = "\x00 \t\r\n\u0085\u2028\u2029"
	breaks      = "\r\n\u0085\u2028\u2029"
)

// isAlnumDash is the anchor, directive-name and tag-handle character set.
func isAlnumDash(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-' || c == '_'
}

// --- Public methods ---

func (s *scanner) checkToken(kinds ...tokKind) bool {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if s.tokens[0].kind == k {
				return true
			}
		}
	}
	return false
}

func (s *scanner) peekToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		return s.tokens[0]
	}
	return nil
}

func (s *scanner) getToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		s.tokensTaken++
		t := s.tokens[0]
		s.tokens = s.tokens[1:]
		return t
	}
	return nil
}

// --- Private methods ---

func (s *scanner) needMoreTokens() bool {
	if s.done {
		return false
	}
	if len(s.tokens) == 0 {
		return true
	}
	s.stalePossibleSimpleKeys()
	n, ok := s.nextPossibleSimpleKey()
	return ok && n == s.tokensTaken
}

func (s *scanner) fetchMoreTokens() {
	s.scanToNextToken()
	s.stalePossibleSimpleKeys()
	s.unwindIndent(s.column)
	ch := s.peek(0)
	switch {
	case ch == 0:
		s.fetchStreamEnd()
		return
	case ch == '%' && s.checkDirective():
		s.fetchDirective()
		return
	case ch == '-' && s.checkDocumentStart():
		s.fetchDocumentIndicator(tDocumentStart)
		return
	case ch == '.' && s.checkDocumentEnd():
		s.fetchDocumentIndicator(tDocumentEnd)
		return
	case ch == '[':
		s.fetchFlowCollectionStart(tFlowSequenceStart)
		return
	case ch == '{':
		s.fetchFlowCollectionStart(tFlowMappingStart)
		return
	case ch == ']':
		s.fetchFlowCollectionEnd(tFlowSequenceEnd)
		return
	case ch == '}':
		s.fetchFlowCollectionEnd(tFlowMappingEnd)
		return
	case ch == ',':
		s.fetchFlowEntry()
		return
	case ch == '-' && s.checkBlockEntry():
		s.fetchBlockEntry()
		return
	case ch == '?' && s.checkKey():
		s.fetchKey()
		return
	case ch == ':' && s.checkValue():
		s.fetchValue()
		return
	case ch == '*':
		s.fetchAlias()
		return
	case ch == '&':
		s.fetchAnchor()
		return
	case ch == '!':
		s.fetchTag()
		return
	case ch == '|' && s.flowLevel == 0:
		s.fetchBlockScalar('|')
		return
	case ch == '>' && s.flowLevel == 0:
		s.fetchBlockScalar('>')
		return
	case ch == '\'':
		s.fetchFlowScalar('\'')
		return
	case ch == '"':
		s.fetchFlowScalar('"')
		return
	case s.checkPlain():
		s.fetchPlain()
		return
	}
	fail(scannerError("while scanning for the next token", nil,
		fmt.Sprintf("found character %s that cannot start any token", repr(ch)), s.mark()))
}

// --- Simple keys treatment ---

func (s *scanner) nextPossibleSimpleKey() (int, bool) {
	found := false
	minN := 0
	for _, level := range s.keyLevels {
		k := s.keys[level]
		if !found || k.tokenNumber < minN {
			minN, found = k.tokenNumber, true
		}
	}
	return minN, found
}

func (s *scanner) delKey(level int) {
	delete(s.keys, level)
	for i, l := range s.keyLevels {
		if l == level {
			s.keyLevels = append(s.keyLevels[:i:i], s.keyLevels[i+1:]...)
			break
		}
	}
}

func (s *scanner) stalePossibleSimpleKeys() {
	for _, level := range append([]int(nil), s.keyLevels...) {
		k := s.keys[level]
		if k.line != s.line || s.index-k.index > 1024 {
			if k.required {
				fail(scannerError("while scanning a simple key", markPtr(k.mark),
					"could not find expected ':'", s.mark()))
			}
			s.delKey(level)
		}
	}
}

func (s *scanner) savePossibleSimpleKey() {
	required := s.flowLevel == 0 && s.indent == s.column
	if s.allowSimpleKey {
		s.removePossibleSimpleKey()
		tokenNumber := s.tokensTaken + len(s.tokens)
		s.keys[s.flowLevel] = &simpleKey{tokenNumber, required, s.index, s.line, s.column, s.mark()}
		s.keyLevels = append(s.keyLevels, s.flowLevel)
	}
}

func (s *scanner) removePossibleSimpleKey() {
	if k, ok := s.keys[s.flowLevel]; ok {
		if k.required {
			fail(scannerError("while scanning a simple key", markPtr(k.mark),
				"could not find expected ':'", s.mark()))
		}
		s.delKey(s.flowLevel)
	}
}

// --- Indentation functions ---

func (s *scanner) unwindIndent(column int) {
	if s.flowLevel != 0 {
		return
	}
	for s.indent > column {
		m := s.mark()
		s.indent = s.indents[len(s.indents)-1]
		s.indents = s.indents[:len(s.indents)-1]
		s.tokens = append(s.tokens, &token{kind: tBlockEnd, start: m, end: m})
	}
}

func (s *scanner) addIndent(column int) bool {
	if s.indent < column {
		s.indents = append(s.indents, s.indent)
		s.indent = column
		return true
	}
	return false
}

// --- Fetchers ---

func (s *scanner) fetchStreamStart() {
	m := s.mark()
	s.tokens = append(s.tokens, &token{kind: tStreamStart, start: m, end: m})
}

func (s *scanner) fetchStreamEnd() {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	s.keys, s.keyLevels = map[int]*simpleKey{}, nil
	m := s.mark()
	s.tokens = append(s.tokens, &token{kind: tStreamEnd, start: m, end: m})
	s.done = true
}

func (s *scanner) fetchDirective() {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanDirective())
}

func (s *scanner) fetchDocumentIndicator(kind tokKind) {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	start := s.mark()
	s.forward(3)
	s.tokens = append(s.tokens, &token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowCollectionStart(kind tokKind) {
	s.savePossibleSimpleKey()
	s.flowLevel++
	s.allowSimpleKey = true
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowCollectionEnd(kind tokKind) {
	s.removePossibleSimpleKey()
	s.flowLevel--
	s.allowSimpleKey = false
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowEntry() {
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tFlowEntry, start: start, end: s.mark()})
}

func (s *scanner) fetchBlockEntry() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			fail(scannerError("", nil, "sequence entries are not allowed here", s.mark()))
		}
		if s.addIndent(s.column) {
			m := s.mark()
			s.tokens = append(s.tokens, &token{kind: tBlockSequenceStart, start: m, end: m})
		}
	}
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tBlockEntry, start: start, end: s.mark()})
}

func (s *scanner) fetchKey() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			fail(scannerError("", nil, "mapping keys are not allowed here", s.mark()))
		}
		if s.addIndent(s.column) {
			m := s.mark()
			s.tokens = append(s.tokens, &token{kind: tBlockMappingStart, start: m, end: m})
		}
	}
	s.allowSimpleKey = s.flowLevel == 0
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tKey, start: start, end: s.mark()})
}

func (s *scanner) insertToken(at int, t *token) {
	s.tokens = append(s.tokens, nil)
	copy(s.tokens[at+1:], s.tokens[at:])
	s.tokens[at] = t
}

func (s *scanner) fetchValue() {
	if k, ok := s.keys[s.flowLevel]; ok {
		s.delKey(s.flowLevel)
		s.insertToken(k.tokenNumber-s.tokensTaken, &token{kind: tKey, start: k.mark, end: k.mark})
		if s.flowLevel == 0 && s.addIndent(k.column) {
			s.insertToken(k.tokenNumber-s.tokensTaken, &token{kind: tBlockMappingStart, start: k.mark, end: k.mark})
		}
		s.allowSimpleKey = false
	} else {
		if s.flowLevel == 0 && !s.allowSimpleKey {
			fail(scannerError("", nil, "mapping values are not allowed here", s.mark()))
		}
		if s.flowLevel == 0 && s.addIndent(s.column) {
			m := s.mark()
			s.tokens = append(s.tokens, &token{kind: tBlockMappingStart, start: m, end: m})
		}
		s.allowSimpleKey = s.flowLevel == 0
		s.removePossibleSimpleKey()
	}
	start := s.mark()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tValue, start: start, end: s.mark()})
}

func (s *scanner) fetchAlias() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanAnchor(tAlias))
}

func (s *scanner) fetchAnchor() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanAnchor(tAnchor))
}

func (s *scanner) fetchTag() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanTag())
}

func (s *scanner) fetchBlockScalar(style rune) {
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	s.tokens = append(s.tokens, s.scanBlockScalar(style))
}

func (s *scanner) fetchFlowScalar(style rune) {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanFlowScalar(style))
}

func (s *scanner) fetchPlain() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanPlain())
}

// --- Checkers ---

func (s *scanner) checkDirective() bool { return s.column == 0 }

func (s *scanner) checkDocumentStart() bool {
	return s.column == 0 && s.prefix(3) == "---" && in(s.peek(3), zBlank)
}

func (s *scanner) checkDocumentEnd() bool {
	return s.column == 0 && s.prefix(3) == "..." && in(s.peek(3), zBlank)
}

func (s *scanner) checkBlockEntry() bool { return in(s.peek(1), zBlank) }

func (s *scanner) checkKey() bool {
	if s.flowLevel != 0 {
		return true
	}
	return in(s.peek(1), zBlank)
}

func (s *scanner) checkValue() bool {
	if s.flowLevel != 0 {
		return true
	}
	return in(s.peek(1), zBlank)
}

func (s *scanner) checkPlain() bool {
	ch := s.peek(0)
	return !in(ch, zBlank+"-?:,[]{}#&*!|>'\"%@`") ||
		(!in(s.peek(1), zBlank) && (ch == '-' || (s.flowLevel == 0 && in(ch, "?:"))))
}

// --- Scanners ---

func (s *scanner) scanToNextToken() {
	if s.index == 0 && s.peek(0) == '\uFEFF' {
		s.forward(1)
	}
	found := false
	for !found {
		for s.peek(0) == ' ' {
			s.forward(1)
		}
		if s.peek(0) == '#' {
			for !in(s.peek(0), zBreak) {
				s.forward(1)
			}
		}
		if s.scanLineBreak() != "" {
			if s.flowLevel == 0 {
				s.allowSimpleKey = true
			}
		} else {
			found = true
		}
	}
}

func (s *scanner) scanDirective() *token {
	start := s.mark()
	s.forward(1)
	name := s.scanDirectiveName(start)
	t := &token{kind: tDirective, value: name, start: start}
	switch name {
	case "YAML":
		t.yamlMajor, t.yamlMinor = s.scanYAMLDirectiveValue(start)
		t.hasValue = true
		t.end = s.mark()
	case "TAG":
		t.tagHandle, t.tagPrefix = s.scanTagDirectiveValue(start)
		t.hasValue = true
		t.end = s.mark()
	default:
		t.end = s.mark()
		for !in(s.peek(0), zBreak) {
			s.forward(1)
		}
	}
	s.scanDirectiveIgnoredLine(start)
	return t
}

func (s *scanner) scanDirectiveName(start Mark) string {
	length := 0
	ch := s.peek(length)
	for isAlnumDash(ch) {
		length++
		ch = s.peek(length)
	}
	if length == 0 {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected alphabetic or numeric character, but found %s", repr(ch)), s.mark()))
	}
	value := s.prefix(length)
	s.forward(length)
	ch = s.peek(0)
	if !in(ch, zSpaceBreak) {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected alphabetic or numeric character, but found %s", repr(ch)), s.mark()))
	}
	return value
}

func (s *scanner) scanYAMLDirectiveValue(start Mark) (int, int) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	major := s.scanYAMLDirectiveNumber(start)
	if s.peek(0) != '.' {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected a digit or '.', but found %s", repr(s.peek(0))), s.mark()))
	}
	s.forward(1)
	minor := s.scanYAMLDirectiveNumber(start)
	if !in(s.peek(0), zSpaceBreak) {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected a digit or ' ', but found %s", repr(s.peek(0))), s.mark()))
	}
	return major, minor
}

func (s *scanner) scanYAMLDirectiveNumber(start Mark) int {
	ch := s.peek(0)
	if ch < '0' || ch > '9' {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected a digit, but found %s", repr(ch)), s.mark()))
	}
	length := 0
	for c := s.peek(length); c >= '0' && c <= '9'; c = s.peek(length) {
		length++
	}
	v, err := strconv.Atoi(s.prefix(length))
	if err != nil {
		v = 1 << 30 // a number too long for int: only "!= 1" matters
	}
	s.forward(length)
	return v
}

func (s *scanner) scanTagDirectiveValue(start Mark) (string, string) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	handle := s.scanTagDirectiveHandle(start)
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	prefix := s.scanTagDirectivePrefix(start)
	return handle, prefix
}

func (s *scanner) scanTagDirectiveHandle(start Mark) string {
	value := s.scanTagHandle("directive", start)
	if ch := s.peek(0); ch != ' ' {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected ' ', but found %s", repr(ch)), s.mark()))
	}
	return value
}

func (s *scanner) scanTagDirectivePrefix(start Mark) string {
	value := s.scanTagURI("directive", start)
	if ch := s.peek(0); !in(ch, zSpaceBreak) {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected ' ', but found %s", repr(ch)), s.mark()))
	}
	return value
}

func (s *scanner) scanDirectiveIgnoredLine(start Mark) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), zBreak) {
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, zBreak) {
		fail(scannerError("while scanning a directive", markPtr(start),
			fmt.Sprintf("expected a comment or a line break, but found %s", repr(ch)), s.mark()))
	}
	s.scanLineBreak()
}

func (s *scanner) scanAnchor(kind tokKind) *token {
	start := s.mark()
	name := "anchor"
	if s.peek(0) == '*' {
		name = "alias"
	}
	s.forward(1)
	length := 0
	ch := s.peek(length)
	for isAlnumDash(ch) {
		length++
		ch = s.peek(length)
	}
	if length == 0 {
		fail(scannerError("while scanning an "+name, markPtr(start),
			fmt.Sprintf("expected alphabetic or numeric character, but found %s", repr(ch)), s.mark()))
	}
	value := s.prefix(length)
	s.forward(length)
	ch = s.peek(0)
	if !in(ch, zBlank+"?:,]}%@`") {
		fail(scannerError("while scanning an "+name, markPtr(start),
			fmt.Sprintf("expected alphabetic or numeric character, but found %s", repr(ch)), s.mark()))
	}
	return &token{kind: kind, value: value, start: start, end: s.mark()}
}

func (s *scanner) scanTag() *token {
	start := s.mark()
	ch := s.peek(1)
	var handle *string
	var suffix string
	switch {
	case ch == '<':
		s.forward(2)
		suffix = s.scanTagURI("tag", start)
		if s.peek(0) != '>' {
			fail(scannerError("while parsing a tag", markPtr(start),
				fmt.Sprintf("expected '>', but found %s", repr(s.peek(0))), s.mark()))
		}
		s.forward(1)
	case in(ch, zBlank):
		suffix = "!"
		s.forward(1)
	default:
		length := 1
		useHandle := false
		for !in(ch, zSpaceBreak) {
			if ch == '!' {
				useHandle = true
				break
			}
			length++
			ch = s.peek(length)
		}
		h := "!"
		if useHandle {
			h = s.scanTagHandle("tag", start)
		} else {
			s.forward(1)
		}
		handle = &h
		suffix = s.scanTagURI("tag", start)
	}
	if ch := s.peek(0); !in(ch, zSpaceBreak) {
		fail(scannerError("while scanning a tag", markPtr(start),
			fmt.Sprintf("expected ' ', but found %s", repr(ch)), s.mark()))
	}
	return &token{kind: tTag, handle: handle, suffix: suffix, start: start, end: s.mark()}
}

func (s *scanner) scanBlockScalar(style rune) *token {
	folded := style == '>'
	var chunks strings.Builder
	start := s.mark()
	s.forward(1)
	chomping, increment := s.scanBlockScalarIndicators(start)
	s.scanBlockScalarIgnoredLine(start)

	minIndent := s.indent + 1
	if minIndent < 1 {
		minIndent = 1
	}
	var brks []string
	var end Mark
	var indent int
	if increment == 0 {
		var maxIndent int
		brks, maxIndent, end = s.scanBlockScalarIndentation()
		indent = max(minIndent, maxIndent)
	} else {
		indent = minIndent + increment - 1
		brks, end = s.scanBlockScalarBreaks(indent)
	}
	lineBreak := ""

	for s.column == indent && s.peek(0) != 0 {
		for _, b := range brks {
			chunks.WriteString(b)
		}
		leadingNonSpace := !in(s.peek(0), " \t")
		length := 0
		for !in(s.peek(length), zBreak) {
			length++
		}
		chunks.WriteString(s.prefix(length))
		s.forward(length)
		lineBreak = s.scanLineBreak()
		brks, end = s.scanBlockScalarBreaks(indent)
		if s.column == indent && s.peek(0) != 0 {
			if folded && lineBreak == "\n" && leadingNonSpace && !in(s.peek(0), " \t") {
				if len(brks) == 0 {
					chunks.WriteString(" ")
				}
			} else {
				chunks.WriteString(lineBreak)
			}
		} else {
			break
		}
	}
	if chomping != chompStrip {
		chunks.WriteString(lineBreak)
	}
	if chomping == chompKeep {
		for _, b := range brks {
			chunks.WriteString(b)
		}
	}
	return &token{kind: tScalar, value: chunks.String(), plain: false, start: start, end: end, style: style}
}

const (
	chompClip  = 0 // None
	chompKeep  = 1 // True
	chompStrip = 2 // False
)

func (s *scanner) scanBlockScalarIndicators(start Mark) (int, int) {
	chomping, increment := chompClip, 0
	ch := s.peek(0)
	if in(ch, "+-") && ch != 0 {
		if ch == '+' {
			chomping = chompKeep
		} else {
			chomping = chompStrip
		}
		s.forward(1)
		ch = s.peek(0)
		if ch >= '0' && ch <= '9' {
			increment = int(ch - '0')
			if increment == 0 {
				fail(scannerError("while scanning a block scalar", markPtr(start),
					"expected indentation indicator in the range 1-9, but found 0", s.mark()))
			}
			s.forward(1)
		}
	} else if ch >= '0' && ch <= '9' {
		increment = int(ch - '0')
		if increment == 0 {
			fail(scannerError("while scanning a block scalar", markPtr(start),
				"expected indentation indicator in the range 1-9, but found 0", s.mark()))
		}
		s.forward(1)
		ch = s.peek(0)
		if in(ch, "+-") && ch != 0 {
			if ch == '+' {
				chomping = chompKeep
			} else {
				chomping = chompStrip
			}
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, zSpaceBreak) {
		fail(scannerError("while scanning a block scalar", markPtr(start),
			fmt.Sprintf("expected chomping or indentation indicators, but found %s", repr(ch)), s.mark()))
	}
	return chomping, increment
}

func (s *scanner) scanBlockScalarIgnoredLine(start Mark) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), zBreak) {
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, zBreak) {
		fail(scannerError("while scanning a block scalar", markPtr(start),
			fmt.Sprintf("expected a comment or a line break, but found %s", repr(ch)), s.mark()))
	}
	s.scanLineBreak()
}

func (s *scanner) scanBlockScalarIndentation() ([]string, int, Mark) {
	var chunks []string
	maxIndent := 0
	end := s.mark()
	for in(s.peek(0), " "+breaks) && s.peek(0) != 0 {
		if s.peek(0) != ' ' {
			chunks = append(chunks, s.scanLineBreak())
			end = s.mark()
		} else {
			s.forward(1)
			if s.column > maxIndent {
				maxIndent = s.column
			}
		}
	}
	return chunks, maxIndent, end
}

func (s *scanner) scanBlockScalarBreaks(indent int) ([]string, Mark) {
	var chunks []string
	end := s.mark()
	for s.column < indent && s.peek(0) == ' ' {
		s.forward(1)
	}
	for in(s.peek(0), breaks) && s.peek(0) != 0 {
		chunks = append(chunks, s.scanLineBreak())
		end = s.mark()
		for s.column < indent && s.peek(0) == ' ' {
			s.forward(1)
		}
	}
	return chunks, end
}

func (s *scanner) scanFlowScalar(style rune) *token {
	double := style == '"'
	var chunks strings.Builder
	start := s.mark()
	quote := s.peek(0)
	s.forward(1)
	s.scanFlowScalarNonSpaces(&chunks, double, start)
	for s.peek(0) != quote {
		s.scanFlowScalarSpaces(&chunks, double, start)
		s.scanFlowScalarNonSpaces(&chunks, double, start)
	}
	s.forward(1)
	return &token{kind: tScalar, value: chunks.String(), plain: false, start: start, end: s.mark(), style: style}
}

var escapeReplacements = map[rune]string{
	'0': "\x00", 'a': "\x07", 'b': "\x08", 't': "\x09", '\t': "\x09", 'n': "\x0A",
	'v': "\x0B", 'f': "\x0C", 'r': "\x0D", 'e': "\x1B", ' ': "\x20", '"': "\"",
	'\\': "\\", '/': "/", 'N': "\u0085", '_': "\u00A0", 'L': "\u2028", 'P': "\u2029",
}

var escapeCodes = map[rune]int{'x': 2, 'u': 4, 'U': 8}

func (s *scanner) scanFlowScalarNonSpaces(chunks *strings.Builder, double bool, start Mark) {
	for {
		length := 0
		for !in(s.peek(length), "'\"\\"+zBlank) {
			length++
		}
		if length > 0 {
			chunks.WriteString(s.prefix(length))
			s.forward(length)
		}
		ch := s.peek(0)
		switch {
		case !double && ch == '\'' && s.peek(1) == '\'':
			chunks.WriteString("'")
			s.forward(2)
		case (double && ch == '\'') || (!double && (ch == '"' || ch == '\\')):
			chunks.WriteRune(ch)
			s.forward(1)
		case double && ch == '\\':
			s.forward(1)
			ch = s.peek(0)
			if rep, ok := escapeReplacements[ch]; ok {
				chunks.WriteString(rep)
				s.forward(1)
			} else if n, ok := escapeCodes[ch]; ok {
				s.forward(1)
				for k := 0; k < n; k++ {
					if c := s.peek(k); !in(c, "0123456789ABCDEFabcdef") || c == 0 {
						fail(scannerError("while scanning a double-quoted scalar", markPtr(start),
							fmt.Sprintf("expected escape sequence of %d hexadecimal numbers, but found %s", n, repr(c)), s.mark()))
					}
				}
				code, _ := strconv.ParseUint(s.prefix(n), 16, 32)
				if code > utf8.MaxRune {
					// chr() raises ValueError; PyYAML lets it escape.
					fail(&ValueError{Mark: s.mark(), Msg: fmt.Sprintf("chr() arg not in range(0x110000): \\%c%s", ch, s.prefix(n))})
				}
				chunks.WriteRune(rune(code))
				s.forward(n)
			} else if in(ch, breaks) && ch != 0 {
				s.scanLineBreak()
				s.scanFlowScalarBreaks(chunks, double, start)
			} else {
				fail(scannerError("while scanning a double-quoted scalar", markPtr(start),
					fmt.Sprintf("found unknown escape character %s", repr(ch)), s.mark()))
			}
		default:
			return
		}
	}
}

func (s *scanner) scanFlowScalarSpaces(chunks *strings.Builder, double bool, start Mark) {
	length := 0
	for in(s.peek(length), " \t") && s.peek(length) != 0 {
		length++
	}
	whitespaces := s.prefix(length)
	s.forward(length)
	ch := s.peek(0)
	switch {
	case ch == 0:
		fail(scannerError("while scanning a quoted scalar", markPtr(start),
			"found unexpected end of stream", s.mark()))
	case in(ch, breaks):
		lineBreak := s.scanLineBreak()
		var brks strings.Builder
		s.scanFlowScalarBreaks(&brks, double, start)
		if lineBreak != "\n" {
			chunks.WriteString(lineBreak)
		} else if brks.Len() == 0 {
			chunks.WriteString(" ")
		}
		chunks.WriteString(brks.String())
	default:
		chunks.WriteString(whitespaces)
	}
}

func (s *scanner) scanFlowScalarBreaks(chunks *strings.Builder, double bool, start Mark) {
	for {
		p := s.prefix(3)
		if (p == "---" || p == "...") && in(s.peek(3), zBlank) {
			fail(scannerError("while scanning a quoted scalar", markPtr(start),
				"found unexpected document separator", s.mark()))
		}
		for in(s.peek(0), " \t") && s.peek(0) != 0 {
			s.forward(1)
		}
		if in(s.peek(0), breaks) && s.peek(0) != 0 {
			chunks.WriteString(s.scanLineBreak())
		} else {
			return
		}
	}
}

func (s *scanner) scanPlain() *token {
	var chunks strings.Builder
	start := s.mark()
	end := start
	indent := s.indent + 1
	var spaces []string
	for {
		length := 0
		if s.peek(0) == '#' {
			break
		}
		for {
			ch := s.peek(length)
			stop := zBlank
			if s.flowLevel != 0 {
				stop += ",[]{}"
			}
			if in(ch, zBlank) ||
				(ch == ':' && in(s.peek(length+1), stop)) ||
				(s.flowLevel != 0 && in(ch, ",?[]{}") && ch != 0) {
				break
			}
			length++
		}
		if length == 0 {
			break
		}
		s.allowSimpleKey = false
		for _, sp := range spaces {
			chunks.WriteString(sp)
		}
		chunks.WriteString(s.prefix(length))
		s.forward(length)
		end = s.mark()
		var ok bool
		spaces, ok = s.scanPlainSpaces(indent, start)
		if !ok || len(spaces) == 0 || s.peek(0) == '#' ||
			(s.flowLevel == 0 && s.column < indent) {
			break
		}
	}
	return &token{kind: tScalar, value: chunks.String(), plain: true, start: start, end: end}
}

// scanPlainSpaces returns the chunks, and false where Python returns None
// (a document separator at the start of the next line).
func (s *scanner) scanPlainSpaces(indent int, start Mark) ([]string, bool) {
	var chunks []string
	length := 0
	for s.peek(length) == ' ' {
		length++
	}
	whitespaces := s.prefix(length)
	s.forward(length)
	ch := s.peek(0)
	if in(ch, breaks) && ch != 0 {
		lineBreak := s.scanLineBreak()
		s.allowSimpleKey = true
		p := s.prefix(3)
		if (p == "---" || p == "...") && in(s.peek(3), zBlank) {
			return nil, false
		}
		var brks []string
		for in(s.peek(0), " "+breaks) && s.peek(0) != 0 {
			if s.peek(0) == ' ' {
				s.forward(1)
			} else {
				brks = append(brks, s.scanLineBreak())
				p := s.prefix(3)
				if (p == "---" || p == "...") && in(s.peek(3), zBlank) {
					return nil, false
				}
			}
		}
		if lineBreak != "\n" {
			chunks = append(chunks, lineBreak)
		} else if len(brks) == 0 {
			chunks = append(chunks, " ")
		}
		chunks = append(chunks, brks...)
	} else if whitespaces != "" {
		chunks = append(chunks, whitespaces)
	}
	return chunks, true
}

func (s *scanner) scanTagHandle(name string, start Mark) string {
	ch := s.peek(0)
	if ch != '!' {
		fail(scannerError("while scanning a "+name, markPtr(start),
			fmt.Sprintf("expected '!', but found %s", repr(ch)), s.mark()))
	}
	length := 1
	ch = s.peek(length)
	if ch != ' ' {
		for isAlnumDash(ch) {
			length++
			ch = s.peek(length)
		}
		if ch != '!' {
			s.forward(length)
			fail(scannerError("while scanning a "+name, markPtr(start),
				fmt.Sprintf("expected '!', but found %s", repr(ch)), s.mark()))
		}
		length++
	}
	value := s.prefix(length)
	s.forward(length)
	return value
}

func (s *scanner) scanTagURI(name string, start Mark) string {
	var chunks strings.Builder
	any := false
	length := 0
	ch := s.peek(length)
	for (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		(in(ch, "-;/?:@&=+$,_.!~*'()[]%") && ch != 0) {
		if ch == '%' {
			chunks.WriteString(s.prefix(length))
			s.forward(length)
			length = 0
			chunks.WriteString(s.scanURIEscapes(name, start))
			any = true
		} else {
			length++
		}
		ch = s.peek(length)
	}
	if length > 0 {
		chunks.WriteString(s.prefix(length))
		s.forward(length)
		any = true
	}
	if !any {
		fail(scannerError("while parsing a "+name, markPtr(start),
			fmt.Sprintf("expected URI, but found %s", repr(ch)), s.mark()))
	}
	return chunks.String()
}

func (s *scanner) scanURIEscapes(name string, start Mark) string {
	var codes []byte
	m := s.mark()
	for s.peek(0) == '%' {
		s.forward(1)
		for k := 0; k < 2; k++ {
			if c := s.peek(k); !in(c, "0123456789ABCDEFabcdef") || c == 0 {
				fail(scannerError("while scanning a "+name, markPtr(start),
					fmt.Sprintf("expected URI escape sequence of 2 hexadecimal numbers, but found %s", repr(c)), s.mark()))
			}
		}
		v, _ := strconv.ParseUint(s.prefix(2), 16, 8)
		codes = append(codes, byte(v))
		s.forward(2)
	}
	if !utf8.Valid(codes) {
		fail(scannerError("while scanning a "+name, markPtr(start), utf8ErrorText(codes), m))
	}
	return string(codes)
}

func (s *scanner) scanLineBreak() string {
	ch := s.peek(0)
	switch ch {
	case '\r', '\n', '\x85':
		if s.prefix(2) == "\r\n" {
			s.forward(2)
		} else {
			s.forward(1)
		}
		return "\n"
	case '\u2028', '\u2029':
		s.forward(1)
		return string(ch)
	}
	return ""
}
