// Package assets is the files tacctl ships inside its binary
// (docs/plans/go-rewrite.md 3.7): the device templates of config/templates
// and the two Linux client scripts of config/linux. The embedding itself is
// the module root's (package tacctl, assets.go), because go:embed reads
// only below the embedding package's directory.
package assets

import (
	"io/fs"
	"sort"
	"strings"

	tacctl "github.com/rett/tacctl"
)

// templateDir is where the templates sit in the tree and in the embedded
// file system.
const templateDir = "config/templates"

// Template is the shipped <name>.template (name without the suffix, e.g.
// "cisco-radius"); ok is false when tacctl ships no such template.
func Template(name string) (text string, ok bool) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return "", false
	}
	b, err := fs.ReadFile(tacctl.Templates, templateDir+"/"+name+".template")
	if err != nil {
		return "", false
	}
	return string(b), true
}

// TemplateNames are the names of the shipped templates, sorted.
func TemplateNames() []string {
	entries, err := fs.ReadDir(tacctl.Templates, templateDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".template"); ok && !e.IsDir() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// The Linux client scripts run on the enrolled hosts under their own bash
// (docs/plans/go-rewrite.md 1.5): they stay shell and are shipped verbatim.
var (
	// LinuxInstallScript is config/linux/client-install.sh, the body of the
	// installer internal/hosts assembles ('config linux script', 'host
	// enroll|sync').
	LinuxInstallScript = mustRead(tacctl.LinuxScripts, "config/linux/client-install.sh")
	// LinuxRemoveScript is config/linux/client-remove.sh ('config linux
	// remove-script', 'host unenroll').
	LinuxRemoveScript = mustRead(tacctl.LinuxScripts, "config/linux/client-remove.sh")
)

func mustRead(f fs.FS, name string) []byte {
	b, err := fs.ReadFile(f, name)
	if err != nil {
		panic("assets: " + name + " is not embedded: " + err.Error())
	}
	return b
}
