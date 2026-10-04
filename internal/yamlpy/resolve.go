package yamlpy

import (
	"regexp"
	"slices"
)

// The YAML 1.1 tags of PyYAML's implicit resolver.
const (
	tagStr       = "tag:yaml.org,2002:str"
	tagBool      = "tag:yaml.org,2002:bool"
	tagFloat     = "tag:yaml.org,2002:float"
	tagInt       = "tag:yaml.org,2002:int"
	tagMerge     = "tag:yaml.org,2002:merge"
	tagNull      = "tag:yaml.org,2002:null"
	tagTimestamp = "tag:yaml.org,2002:timestamp"
	tagValue     = "tag:yaml.org,2002:value"
	tagYAML      = "tag:yaml.org,2002:yaml"
	tagSeq       = "tag:yaml.org,2002:seq"
	tagMap       = "tag:yaml.org,2002:map"
)

// implicitResolver is one Resolver.add_implicit_resolver call of
// resolver.py: the tag, the regexp and the first characters it is
// registered for ("" is the empty scalar).
type implicitResolver struct {
	tag   string
	re    *regexp.Regexp
	first []string
}

// pyRegexp compiles a PyYAML resolver pattern. The patterns below are the
// re.X patterns of resolver.py with the insignificant whitespace removed
// (whitespace inside a character class is significant in re.X and kept).
// Python's '$' also matches just before a final newline; '\n?$' is that
// rule in RE2, whose '$' (without the m flag) is the end of the text.
func pyRegexp(body string) *regexp.Regexp {
	return regexp.MustCompile(`^(?:` + body + `)\n?$`)
}

func chars(s string) []string {
	out := make([]string, 0, len(s))
	for _, c := range s {
		out = append(out, string(c))
	}
	return out
}

// implicitResolvers is resolver.py's Resolver, in registration order (the
// order matters: the first match wins).
var implicitResolvers = []implicitResolver{
	{tagBool, pyRegexp(`yes|Yes|YES|no|No|NO` +
		`|true|True|TRUE|false|False|FALSE` +
		`|on|On|ON|off|Off|OFF`),
		chars("yYnNtTfFoO")},
	{tagFloat, pyRegexp(`[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?` +
		`|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?` +
		`|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*` +
		`|[-+]?\.(?:inf|Inf|INF)` +
		`|\.(?:nan|NaN|NAN)`),
		chars("-+0123456789.")},
	{tagInt, pyRegexp(`[-+]?0b[0-1_]+` +
		`|[-+]?0[0-7_]+` +
		`|[-+]?(?:0|[1-9][0-9_]*)` +
		`|[-+]?0x[0-9a-fA-F_]+` +
		`|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+`),
		chars("-+0123456789")},
	{tagMerge, pyRegexp(`<<`), chars("<")},
	{tagNull, pyRegexp(`~` +
		`|null|Null|NULL` +
		`|`),
		[]string{"~", "n", "N", ""}},
	{tagTimestamp, pyRegexp(`[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]` +
		`|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?` +
		`(?:[Tt]|[ \t]+)[0-9][0-9]?` +
		`:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?` +
		`(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?`),
		chars("0123456789")},
	{tagValue, pyRegexp(`=`), chars("=")},
	// resolver.py: "only for documentation purposes"; kept for fidelity.
	{tagYAML, pyRegexp(`!|&|\*`), chars("!&*")},
}

// resolvePlain is BaseResolver.resolve(ScalarNode, value, (True, False)):
// the tag a plain scalar with this text would be read as.
func resolvePlain(value string) string {
	first := ""
	if value != "" {
		// Python's value[0] is a character; only ASCII first characters
		// are registered, so the first byte decides the same way.
		first = value[:1]
	}
	for _, r := range implicitResolvers {
		if slices.Contains(r.first, first) && r.re.MatchString(value) {
			return r.tag
		}
	}
	return tagStr
}
