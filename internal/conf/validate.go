package conf

import (
	"fmt"
	"os"

	"github.com/rett/tacctl/internal/conf/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// ValidateFile is _conf_validate_overrides_file: one "<path>: <reason>"
// line per problem of the file at path (not the merged view), nothing
// when it is clean or missing. A file that cannot be used is the single
// line "could not parse <path>: <why>". Every leaf outside listeners: is
// checked against the schema; the listeners section is checked as a whole
// (entries and collisions). The lines are as Python prints them; 'tacctl
// config validate' prints them through 'echo -e'.
func (s *Schema) ValidateFile(path string) []string {
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	data, problem := ReadOverrides(path)
	if problem != "" {
		return []string{fmt.Sprintf("could not parse %s: %s", path, problem)}
	}
	var lines []string
	rest := yamlpy.NewMap()
	for k, v := range data.All() {
		if k != "listeners" {
			rest.Set(k, v)
		}
	}
	walkLeaves(rest, "", func(p string, v any) {
		_, isList := py.List(v)
		if msg := s.Validate(p, v, isList); msg != "" {
			lines = append(lines, p+": "+msg)
		}
	})
	lines = append(lines, ListenersProblems(data, "", false)...)
	return lines
}

// walkLeaves yields every leaf (scalar or list) of a mapping with its
// dotted path; mappings are walked into, an empty one yields nothing.
func walkLeaves(m *yamlpy.Map, prefix string, yield func(string, any)) {
	for k, v := range m.All() {
		child := k
		if prefix != "" {
			child = prefix + "." + k
		}
		if sub, ok := v.(*yamlpy.Map); ok {
			walkLeaves(sub, child, yield)
		} else {
			yield(child, v)
		}
	}
}
