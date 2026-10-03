// Package yamlpy writes YAML byte for byte as PyYAML 6.0.1's yaml.safe_dump
// does, for the two files tacctl writes: store.yaml
// (default_flow_style=None, width=4096, sort_keys=False) and tacctl.yaml
// (default_flow_style=False, sort_keys=False, width 80). See
// docs/plans/go-rewrite.md 3.3.
//
// The emitter is a port of PyYAML's pipeline, not a re-invention of its
// output: the representer (which collections are flow style), the
// serializer's implicit-tag test (resolve.go: the Resolver regexes), the
// Emitter state machine and writers (emitter.go) and Emitter.analyze_scalar
// (analyze.go) follow /usr/lib/python3/dist-packages/yaml/*.py line by line.
// Values outside tacctl's domain are refused with an error instead of being
// guessed at (ErrUnsupportedScalar, ErrUnsupportedValue).
//
// tacctl reads its own files with internal/pyyaml (the PyYAML port), which
// is also the reader of EmitChecked's write-time self-check in production.
// Decode is a second reader, on yaml.v3 with plain scalars typed by
// PyYAML's YAML 1.1 resolver: the legacy tacquito.yaml importer types its
// scalars with it (tacquito reads that file with yaml.v3), and this
// package's own tests read back with it (they cannot import pyyaml, which
// imports this package).
package yamlpy

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"time"
)

// ErrUnsupportedScalar is returned (wrapped, with the path of the value)
// for a string outside the domain the emitter is verified on: invalid
// UTF-8, a control character other than tab and newline, or a leading or
// trailing newline (non-ASCII is written with PyYAML's escapes). The message never contains the value (it may be a secret).
var ErrUnsupportedScalar = errors.New("unsupported scalar")

// ErrUnsupportedValue is returned (wrapped, with the path of the value) for
// a Go value Emit cannot represent: a type outside the list in Emit, a
// collection nested deeper than MaxDepth or met twice (PyYAML would write
// an anchor and an alias), or, from Decode, YAML that safe_load would turn
// into something tacctl never writes (non-string keys, anchors and
// aliases, merge keys, full timestamps, other tags).
var ErrUnsupportedValue = errors.New("unsupported value")

// MaxDepth bounds the nesting of collections Emit and Decode accept.
const MaxDepth = 64

// Map is a mapping with string keys that keeps insertion order, as a
// Python dict does: Set on an existing key replaces the value in place,
// Set on a new key appends it, Delete removes it. The zero value is an
// empty map ready to use.
type Map struct {
	keys []string
	vals map[string]any
}

// NewMap returns an empty Map. Pairs, if given, alternate key and value
// ("k1", v1, "k2", v2, ...); a non-string key or an odd count panics, as
// it is a programming error.
func NewMap(pairs ...any) *Map {
	if len(pairs)%2 != 0 {
		panic("yamlpy.NewMap: odd number of arguments")
	}
	m := &Map{}
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			panic(fmt.Sprintf("yamlpy.NewMap: key %d is %T, not string", i/2, pairs[i]))
		}
		m.Set(k, pairs[i+1])
	}
	return m
}

// Set stores v under key: in place when the key exists, appended otherwise.
func (m *Map) Set(key string, v any) {
	if m.vals == nil {
		m.vals = make(map[string]any)
	}
	if _, ok := m.vals[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.vals[key] = v
}

// Get returns the value under key and whether it exists.
func (m *Map) Get(key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.vals[key]
	return v, ok
}

// Has reports whether key exists.
func (m *Map) Has(key string) bool {
	_, ok := m.Get(key)
	return ok
}

// Delete removes key and reports whether it existed.
func (m *Map) Delete(key string) bool {
	if m == nil {
		return false
	}
	if _, ok := m.vals[key]; !ok {
		return false
	}
	delete(m.vals, key)
	m.keys = slices.DeleteFunc(m.keys, func(k string) bool { return k == key })
	return true
}

// Len returns the number of keys.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Keys returns a copy of the keys in order.
func (m *Map) Keys() []string {
	if m == nil {
		return nil
	}
	return slices.Clone(m.keys)
}

// All iterates over the pairs in order.
func (m *Map) All() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {
		if m == nil {
			return
		}
		for _, k := range m.keys {
			if !yield(k, m.vals[k]) {
				return
			}
		}
	}
}

// Date is a calendar date, the value PyYAML's safe_load gives for an
// unquoted YYYY-MM-DD (datetime.date). Emit writes it plain, as
// safe_dump writes a datetime.date; a date held as a string is written
// quoted ('2026-10-01'), which is how tacctl itself stores dates.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// String is the ISO form, as Python's date.isoformat.
func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day)
}

// Time returns the date at midnight UTC (yaml.v3 decodes a date to
// time.Time; this is the same instant).
func (d Date) Time() time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
}
