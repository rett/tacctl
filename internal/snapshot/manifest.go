package snapshot

import (
	"errors"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Manifest is the manifest file of a snapshot, as _backup_snapshot_fill's
// Python writes it:
//
//	print(json.dumps({"tacctl_version": version, "created": <UTC now>,
//	                  "rendered": <rendered.json>}, indent=2, sort_keys=True))
//
// "rendered" is the content of renderedPath as json.load reads it: {} when
// the file does not exist, null when it exists but cannot be read or is not
// JSON (say so rather than guess).
func Manifest(renderedPath, version string, now time.Time) []byte {
	m := yamlpy.NewMap()
	m.Set("tacctl_version", version)
	m.Set("created", now.UTC().Format("2006-01-02T15:04:05Z"))
	m.Set("rendered", loadRendered(renderedPath))
	var b strings.Builder
	dumpIndent(&b, m, 0)
	b.WriteByte('\n')
	return []byte(b.String())
}

// loadRendered is the manifest's json.load of rendered.json.
func loadRendered(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return yamlpy.NewMap()
		}
		return nil // OSError
	}
	if !utf8.Valid(data) {
		return nil // UnicodeDecodeError, a ValueError
	}
	// open() in text mode translates \r\n and \r to \n.
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	v, err := py.Loads(text)
	if err != nil {
		return nil
	}
	return v
}

// dumpIndent is json.dumps(v, indent=2, sort_keys=True) from the given
// nesting level: ',' then a newline between items, ': ' after a key, an
// empty container as {} or [], scalars as json.dumps writes them.
func dumpIndent(b *strings.Builder, v any, level int) {
	pad := func(n int) string { return strings.Repeat("  ", n) }
	switch x := v.(type) {
	case *yamlpy.Map:
		keys := x.Keys()
		if len(keys) == 0 {
			b.WriteString("{}")
			return
		}
		// Python sorts str keys by code point; UTF-8 byte order is the same.
		sort.Strings(keys)
		b.WriteString("{\n")
		for i, k := range keys {
			ks, _ := py.Dumps(k)
			b.WriteString(pad(level+1) + ks + ": ")
			val, _ := x.Get(k)
			dumpIndent(b, val, level+1)
			if i < len(keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(pad(level) + "}")
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, item := range x {
			b.WriteString(pad(level + 1))
			dumpIndent(b, item, level+1)
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(pad(level) + "]")
	default:
		s, err := py.Dumps(x)
		if err != nil {
			s = "null"
		}
		b.WriteString(s)
	}
}
