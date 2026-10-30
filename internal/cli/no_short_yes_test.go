package cli

import (
	"errors"
	"regexp"
	"testing"
)

// reShortYes is '-y' as a word of the usage text: not part of '--yes', of a
// longer flag or of a name.
var reShortYes = regexp.MustCompile(`(^|[^[:alnum:]_-])-y($|[^[:alnum:]_-])`)

// --yes has no one-letter spelling: no flag of any verb is declared as -y,
// and -y is refused as an unknown flag by every verb that parses with a Spec
// (the verbs that read their words by hand are held by
// tests/tools/no-short-yes.sh and the bats files).
func TestNoShortYes(t *testing.T) {
	_, root, _ := shellTestInv(t)
	paths, _ := visibleLeaves(root)
	checked := 0
	for _, p := range paths {
		spec, ok := specFor(p)
		if !ok {
			continue
		}
		checked++
		for _, f := range spec.Flags {
			for _, n := range f.Names {
				if n == "-y" {
					t.Errorf("%v declares the flag spelling -y; --yes has no shorthand", p)
				}
			}
		}
		spec.MinArgs, spec.MaxArgs = 0, -1
		var unk *UnknownFlagError
		if _, err := Parse(spec, []string{"-y"}); !errors.As(err, &unk) || unk.Flag != "-y" {
			t.Errorf("%v: -y gives %v, want the unknown-flag refusal", p, err)
		}
	}
	if checked < 50 {
		t.Errorf("only %d verbs were checked", checked)
	}
	for id, text := range usageBlocks {
		if reShortYes.MatchString(plainBlock(text)) {
			t.Errorf("usage %q names the shorthand -y", id)
		}
	}
}
