// Package conf is tacctl.yaml, the operator's overrides of tacctl's
// tunables, as lib/conf.sh (tacctl 0.1.16) has it: the embedded defaults,
// the schema every write is validated against (with its wildcard paths and
// the listener model), the merged view readers see, the write path (prune
// to default, unlink when empty, the header, PyYAML's block style), the
// refusal of a file that does not parse and the warning readers give
// about it, the file scan behind 'tacctl config validate', the source-time
// tunables and 'tacctl config dump'.
//
// Messages are byte for byte those of 0.1.16. They are built from Python
// f-strings over the values in the file there, so internal/py
// reproduces repr() and friends, and internal/pyyaml reads the file
// as PyYAML does (what it accepts, and the "line L, column C: <problem>"
// it reports when it does not).
//
// The write path gains the store's safety (docs/plans/go-rewrite.md 3.9
// item 9): writes are serialised with flock on the file's directory, the
// temporary file and the directory are fsynced, and the bytes are checked
// to read back as the value written (yamlpy.EmitChecked, reading with
// pyyaml.LoadBytes as the next run will) before the rename. The bytes
// themselves do not change.
package conf

import (
	_ "embed"
	"sync"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// DefaultsText is conf_emit_defaults: the shipped tunables, printed as they
// are by 'tacctl config defaults' and 'tacctl config dump'.
//
//go:embed defaults.yaml
var DefaultsText string

// Header starts every tacctl.yaml tacctl writes.
const Header = "# tacctl overrides. Hand-edits are fine as long as the YAML stays\n" +
	"# valid. View effective posture: 'tacctl config dump'.\n\n"

var (
	defaultsOnce sync.Once
	defaultsMap  *yamlpy.Map
)

// Defaults is DefaultsText parsed, in its key order. It is shared: callers
// must not modify it.
func Defaults() *yamlpy.Map {
	defaultsOnce.Do(func() {
		v, err := pyyaml.Load([]byte(DefaultsText), "<defaults>")
		m, ok := v.(*yamlpy.Map)
		if err != nil || !ok {
			panic("conf: the embedded defaults do not parse")
		}
		defaultsMap = m
	})
	return defaultsMap
}
