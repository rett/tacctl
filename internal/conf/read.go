package conf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/pyyaml"
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

// RenderProblem is the check radius_conf_view makes of tacctl.yaml before
// the RADIUS renderer takes the merged view (lib/backends/radius.sh, 0.1.16),
// in that program's words: "" when the file is absent, empty or a mapping,
// else the message. For a YAML error it is yaml_problem's
// "<path>: <problem> (line L, column C)", for a top level that is not a
// mapping "<path>: not a YAML mapping"; fixIt is true for both, and the
// caller appends " -- fix it before rendering". A file that cannot be read is
// "<path>: <strerror>" with fixIt false. What 0.1.16 answered with a Python
// traceback (a file that is not UTF-8, a value safe_load cannot construct,
// YAML tacctl does not support) is "<path>: <the usual reason>" with fixIt
// true.
func RenderProblem(path string) (msg string, fixIt bool) {
	if path == "" {
		return "", false
	}
	if _, err := os.Stat(path); err != nil {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			text := errno.Error()
			if text != "" && text[0] >= 'a' && text[0] <= 'z' {
				text = string(text[0]-'a'+'A') + text[1:]
			}
			return path + ": " + text, false
		}
		return path + ": I/O", false
	}
	doc, err := pyyaml.Load(data, path)
	if err != nil {
		var ye *pyyaml.Error
		if errors.As(err, &ye) {
			return path + ": " + ye.YAMLProblem(), true
		}
		var why interface{ Why() string }
		if errors.As(err, &why) {
			return path + ": " + why.Why(), true
		}
		return path + ": " + py.CollapseSpace(err.Error()), true
	}
	if doc == nil {
		return "", false
	}
	if _, ok := doc.(*yamlpy.Map); !ok {
		return path + ": not a YAML mapping", true
	}
	return "", false
}
