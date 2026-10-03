package conf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/rett/tacctl/internal/conf/py"
	"github.com/rett/tacctl/internal/conf/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// ReadOverrides is load_overrides(path) of lib/conf.sh: the overrides
// mapping and, when the file cannot be used, why (one line). A missing
// file, an empty one and one holding only comments are an empty mapping
// and no problem. A file that does not parse, cannot be read, or whose
// top level is not a mapping is an empty mapping and the reason:
//
//	line 4, column 1: expected ',' or ']', but got '<stream end>'
//	[Errno 13] Permission denied: '/etc/tacctl/tacctl.yaml'
//	the top level is a list, not a mapping
//
// Readers carry on with the defaults and say so once; writers refuse.
func ReadOverrides(path string) (*yamlpy.Map, string) {
	if path == "" {
		return yamlpy.NewMap(), ""
	}
	if _, err := os.Stat(path); err != nil {
		// os.path.exists: anything that cannot be stat'ed does not exist.
		return yamlpy.NewMap(), ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return yamlpy.NewMap(), osErrorText(err, path)
	}
	doc, err := pyyaml.Load(data, path)
	if err != nil {
		var why interface{ Why() string }
		if errors.As(err, &why) {
			return yamlpy.NewMap(), why.Why()
		}
		return yamlpy.NewMap(), py.CollapseSpace(err.Error())
	}
	if doc == nil {
		return yamlpy.NewMap(), ""
	}
	m, ok := doc.(*yamlpy.Map)
	if !ok {
		name := py.TypeName(doc)
		if u, isU := doc.(pyyaml.Unrepresentable); isU {
			name = u.TypeName
		}
		return yamlpy.NewMap(), fmt.Sprintf("the top level is a %s, not a mapping", name)
	}
	return m, ""
}

// osErrorText is str(OSError) as Python words it for a file it could not
// open or read: "[Errno 13] Permission denied: '<path>'", whitespace
// collapsed as load_overrides does.
func osErrorText(err error, path string) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// Go's errno texts are glibc's strerror() with a lower-case
		// first letter.
		msg := errno.Error()
		if msg != "" && msg[0] >= 'a' && msg[0] <= 'z' {
			msg = string(msg[0]-'a'+'A') + msg[1:]
		}
		return py.CollapseSpace(fmt.Sprintf("[Errno %d] %s: %s", int(errno), msg, py.ReprString(path)))
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return py.CollapseSpace(pe.Err.Error())
	}
	return py.CollapseSpace(err.Error())
}
