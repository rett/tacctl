// Package pyyaml reads YAML the way tacctl 0.1.16 reads its own files,
// store.yaml (lib/store.sh store_load_raw) and tacctl.yaml (lib/conf.sh
// load_overrides): yaml.safe_load(open(path)) with PyYAML 6.0.1, including
// which documents it refuses and the exact problem and position it names.
// The Reader, Scanner, Parser, Composer and the safe Constructor are ported
// from PyYAML's pure-Python modules (/usr/lib/python3/dist-packages/yaml)
// method by method; the corpus in internal/conf/testdata compares the
// outcome with PyYAML for thousands of documents, and
// internal/store/testdata/load pins the store's messages.
//
// yaml.v3 (internal/yamlpy.Decode) accepts and refuses different documents
// and words its errors differently (it names no column); Decision 11e of
// docs/plans/go-rewrite.md makes 0.1.16's "could not parse <file>: line L,
// column C: <problem>" messages parity, and 3.3 makes this package the
// reader of both files (yaml.v3 stays only for tacquito.yaml, which
// tacquito reads with it). It is also the reader of the write-time
// self-check (LoadBytes, for yamlpy.EmitChecked).
//
// Values are the types internal/yamlpy works with. A document PyYAML reads
// but tacctl cannot represent (anchors and aliases, merge keys, keys that
// are not strings, sets, ordered maps, binary, timestamps with a time of
// day, integers past 64 bits) is an *UnsupportedError.
package pyyaml

import (
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/yamlpy"
)

// panicked carries an error out of the recursive-descent code.
type panicked struct{ err error }

func fail(err error) { panic(panicked{err}) }

// Unrepresentable is the value Load returns for a document whose top
// level is not a mapping and holds something tacctl cannot represent:
// only its Python type name is known.
type Unrepresentable struct{ TypeName string }

// Load is yaml.safe_load(open(name)) for data, the bytes of the file name.
// It returns the document's value (nil for an empty document) or one of
// *DecodeError (not UTF-8), *Error (PyYAML's YAMLError), *ValueError (a
// Python exception other than YAMLError) and *UnsupportedError.
func Load(data []byte, name string) (v any, err error) {
	if derr := checkUTF8(data); derr != nil {
		return nil, derr
	}
	text := []rune(universalNewlines(string(data)))
	defer func() {
		if r := recover(); r != nil {
			p, ok := r.(panicked)
			if !ok {
				panic(r)
			}
			v, err = nil, p.err
		}
	}()
	comp := &composer{parser: newParser(newScanner(newReader(text, name))), anchors: map[string]*node{}}
	root := comp.getSingleNode()
	if root == nil {
		return nil, nil
	}
	c := &constructor{constructed: map[*node]any{}, recursive: map[*node]bool{}}
	data0 := c.document(root)

	u := &unsupported{c: c}
	if comp.aliased != nil {
		u.note(*comp.aliased, "an alias")
	}
	if comp.merged != nil {
		u.note(*comp.merged, "a merge key ('<<')")
	}
	u.walk(root, map[*node]bool{})
	if _, isMap := data0.(*yamlpy.Map); !isMap {
		if u.mark != nil {
			return Unrepresentable{TypeName: typeName(data0)}, nil
		}
		return convert(data0), nil
	}
	if u.mark != nil {
		return nil, &UnsupportedError{Mark: *u.mark, What: u.what}
	}
	return convert(data0), nil
}

// LoadBytes is Load for bytes that are not a named file: the reader
// yamlpy.EmitChecked parses what tacctl is about to write with (a
// yamlpy.Reader), so the self-check reads the bytes as the next run will.
func LoadBytes(data []byte) (any, error) {
	return Load(data, "<bytes>")
}

// typeName is type(v).__name__ for constructed values.
func typeName(v any) string {
	switch v.(type) {
	case *seqVal, *tupleList:
		return "list"
	case *setVal:
		return "set"
	case *bytesVal:
		return "bytes"
	case *datetimeVal:
		return "datetime"
	case *yamlpy.Map:
		return "dict"
	case *big.Int, int:
		return "int"
	case float64:
		return "float"
	case bool:
		return "bool"
	case string:
		return "str"
	case yamlpy.Date:
		return "date"
	case nil:
		return "NoneType"
	}
	return fmt.Sprintf("%T", v)
}

func convert(v any) any {
	switch x := v.(type) {
	case *yamlpy.Map:
		for k, val := range x.All() {
			x.Set(k, convert(val))
		}
		return x
	case *seqVal:
		out := make([]any, len(x.items))
		for i, item := range x.items {
			out[i] = convert(item)
		}
		return out
	}
	return v
}

// unsupported finds the first thing (in document order) tacctl cannot
// represent.
type unsupported struct {
	c    *constructor
	mark *Mark
	what string
}

func (u *unsupported) note(m Mark, what string) {
	if u.mark == nil || m.Index < u.mark.Index {
		u.mark, u.what = &m, what
	}
}

func (u *unsupported) walk(n *node, seen map[*node]bool) {
	if seen[n] {
		return
	}
	seen[n] = true
	switch u.c.constructed[n].(type) {
	case *setVal:
		u.note(n.start, "a set (!!set)")
	case *tupleList:
		u.note(n.start, fmt.Sprintf("an ordered map (%s)", shortTag(n.tag)))
	case *bytesVal:
		u.note(n.start, "binary data (!!binary)")
	case *datetimeVal:
		u.note(n.start, "a timestamp with a time of day")
	case *big.Int:
		u.note(n.start, "an integer beyond 64 bits")
	case *yamlpy.Map:
		// A repeated key keeps only its last value (a Python dict): what
		// the earlier ones held is not in the document's value.
		last := map[string]int{}
		for i, p := range n.pairs {
			if k, ok := u.c.constructed[p.key].(string); ok {
				last[k] = i
			}
		}
		for i, p := range n.pairs {
			k, ok := u.c.constructed[p.key].(string)
			if !ok {
				u.note(p.key.start, "a key that is not a string")
			} else if last[k] != i {
				continue
			}
			u.walk(p.key, seen)
			u.walk(p.value, seen)
		}
	case *seqVal:
		for _, item := range n.items {
			u.walk(item, seen)
		}
	}
}

func shortTag(tag string) string {
	if strings.HasPrefix(tag, tagPrefix) {
		return "!!" + tag[len(tagPrefix):]
	}
	return tag
}

// universalNewlines is text-mode reading: '\r\n' and '\r' become '\n'.
func universalNewlines(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// decodeChunk is TextIOWrapper's read size: a decode error names the
// position within the chunk being decoded.
const decodeChunk = 8192

// checkUTF8 returns the UnicodeDecodeError reading data as UTF-8 raises,
// or nil. The position is the one CPython reports for a file read in
// 8 KiB chunks (exact for files that have no multi-byte character across
// a chunk boundary before the error).
func checkUTF8(data []byte) error {
	if utf8.Valid(data) {
		return nil
	}
	start, end, reason := firstUTF8Error(data)
	base := start / decodeChunk * decodeChunk
	return &DecodeError{Msg: utf8Message(data, start-base, end-base, start, reason)}
}

// utf8ErrorText is str(UnicodeDecodeError) for bytes decoded in one call.
func utf8ErrorText(b []byte) string {
	start, end, reason := firstUTF8Error(b)
	return utf8Message(b, start, end, start, reason)
}

func utf8Message(data []byte, start, end, abs int, reason string) string {
	if end-start == 1 {
		return fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: %s", data[abs], start, reason)
	}
	return fmt.Sprintf("'utf-8' codec can't decode bytes in position %d-%d: %s", start, end-1, reason)
}

// firstUTF8Error finds the first invalid sequence as CPython's UTF-8
// decoder reports it: [start, end) and the reason.
func firstUTF8Error(b []byte) (int, int, string) {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		var n int
		lo, hi := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			n = 2
		case c == 0xE0:
			n, lo = 3, 0xA0
		case c >= 0xE1 && c <= 0xEC, c == 0xEE, c == 0xEF:
			n = 3
		case c == 0xED:
			n, hi = 3, 0x9F
		case c == 0xF0:
			n, lo = 4, 0x90
		case c >= 0xF1 && c <= 0xF3:
			n = 4
		case c == 0xF4:
			n, hi = 4, 0x8F
		default:
			return i, i + 1, "invalid start byte"
		}
		for k := 1; k < n; k++ {
			if i+k >= len(b) {
				return i, len(b), "unexpected end of data"
			}
			d := b[i+k]
			l, h := byte(0x80), byte(0xBF)
			if k == 1 {
				l, h = lo, hi
			}
			if d < l || d > h {
				return i, i + k, "invalid continuation byte"
			}
		}
		i += n
	}
	return 0, 0, ""
}
