package yamlpy

import (
	"errors"
	"fmt"
)

// ErrSelfCheck is returned by EmitChecked when the YAML it produced does
// not read back as the value it was given (an emitter defect; the caller
// must not write the bytes).
var ErrSelfCheck = errors.New("yamlpy: the emitted YAML does not read back as the value written")

// Reader parses the bytes of one YAML document into the types Emit takes.
// The production reader is internal/pyyaml's LoadBytes, the PyYAML port
// tacctl reads its own files with; Decode (yaml.v3) is one too.
type Reader func(data []byte) (any, error)

// EmitChecked is Emit followed by the write-time self-check of
// docs/plans/go-rewrite.md 3.3: the bytes are parsed again with read and
// must be Equal to v. Callers pass the reader the file is read with in
// production (pyyaml.LoadBytes), so a write that would not read back is
// refused. header, if not empty, is prepended to the output before the
// check (tacctl's files start with comment lines), so the bytes returned
// are exactly what the caller writes.
func EmitChecked(v any, opts Options, header string, read Reader) ([]byte, error) {
	body, err := Emit(v, opts)
	if err != nil {
		return nil, err
	}
	out := append([]byte(header), body...)
	back, err := read(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfCheck, err)
	}
	if !Equal(v, back) {
		return nil, ErrSelfCheck
	}
	return out, nil
}

// Equal reports whether a and b are the same value as Emit sees it: the
// same kinds, *Map keys in the same order with Equal values, sequences of
// any of the accepted slice types with Equal items, scalars that Emit
// would write the same way (so int(7) equals int64(7) and NaN equals NaN,
// but 7 does not equal "7" or 7.0). Strings outside the emitter's domain
// are compared as they are.
func Equal(a, b any) bool {
	return equal(a, b, 0)
}

func equal(a, b any, depth int) bool {
	if depth > MaxDepth {
		return false
	}
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		return ok && sa == sb
	}
	if _, ok := b.(string); ok {
		return false
	}
	ta, xa, oka, erra := scalarText(a)
	tb, xb, okb, errb := scalarText(b)
	if oka || okb {
		return oka && okb && erra == nil && errb == nil && ta == tb && xa == xb
	}
	if ma, ok := a.(*Map); ok {
		mb, ok := b.(*Map)
		if !ok || ma == nil || mb == nil || ma.Len() != mb.Len() {
			return false
		}
		for i, k := range ma.keys {
			if mb.keys[i] != k || !equal(ma.vals[k], mb.vals[k], depth+1) {
				return false
			}
		}
		return true
	}
	la, oka := asList(a)
	lb, okb := asList(b)
	if !oka || !okb || len(la) != len(lb) {
		return false
	}
	for i := range la {
		if !equal(la[i], lb[i], depth+1) {
			return false
		}
	}
	return true
}

func asList(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, true
	case []*Map:
		out := make([]any, len(x))
		for i, m := range x {
			out[i] = m
		}
		return out, true
	}
	return nil, false
}
