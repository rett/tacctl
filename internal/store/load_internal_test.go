package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

func TestHideValues(t *testing.T) {
	for in, want := range map[string]string{
		"invalid literal for int() with base 10: 'one'": "invalid literal for int() with base 10: (value not shown)",
		`"it's" is not a boolean`:                       "(value not shown) is not a boolean",
		`'a\'b' and 'c'`:                                "(value not shown) and (value not shown)",
		"could not convert string to float: ''":         "could not convert string to float: (value not shown)",
		"day is out of range for month":                 "day is out of range for month",
	} {
		if got := hideValues(in); got != want {
			t.Errorf("hideValues(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadProblemKinds(t *testing.T) {
	_, err := pyyaml.Load([]byte("a: !!int s3cret\n"), "F")
	if got := loadProblem("F", err).Error(); got != "F: line 1, column 4: invalid literal for int() with base 10: (value not shown)" {
		t.Errorf("ValueError: %q", got)
	}
	if got := loadProblem("F", errors.New("other 's3cret'")).Error(); got != "F: other (value not shown)" {
		t.Errorf("other: %q", got)
	}
}

// The write-time self-check reads with the port; a failure is an internal
// error that names no value.
func TestWriteRefusalSelfCheck(t *testing.T) {
	read := func([]byte) (any, error) { return nil, errors.New("'s3cret-value' is not a boolean") }
	_, err := yamlpy.EmitChecked(yamlpy.NewMap("a", "b"), yamlpy.StoreOptions, "", read)
	msg := writeRefusal(err).Error()
	if !strings.HasPrefix(msg, "internal: cannot write the store (the emitted YAML does not read back") ||
		strings.Contains(msg, "s3cret") || !strings.HasSuffix(msg, "; nothing was written") {
		t.Errorf("writeRefusal = %q", msg)
	}
	// Text checks with the port: a store reads back as written.
	s := Empty()
	if _, err := s.Text(); err != nil {
		t.Errorf("Text: %v", err)
	}
}
