package radius

import (
	"os"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
)

// Family names, as TACCTL_RADIUS_FAMILY and the layout use them.
const (
	FamilyDebian = "debian"
	FamilyRHEL   = "rhel"
)

// DetectFamily is _radius_family_detect: debian, rhel or "" (neither
// recognised). TACCTL_RADIUS_FAMILY=debian|rhel decides; else the raddb
// directory of a package that is installed (the fixed paths, whatever
// TACCTL_RADIUS_DIR says), else the package manager found in PATH (apt-get,
// then dnf or yum). isDir answers "is this a directory"; nil asks the file
// system. "" selects the Debian layout in Layout, as in bash.
func DetectFamily(env paths.Env, isDir func(string) bool, r execx.Runner) string {
	switch f := env.Get("TACCTL_RADIUS_FAMILY"); f {
	case FamilyDebian, FamilyRHEL:
		return f
	}
	if isDir == nil {
		isDir = func(p string) bool {
			st, err := os.Stat(p)
			return err == nil && st.IsDir()
		}
	}
	have := func(name string) bool {
		_, err := r.LookPath(name)
		return err == nil
	}
	switch {
	case isDir("/etc/freeradius/3.0"):
		return FamilyDebian
	case isDir("/etc/raddb"):
		return FamilyRHEL
	case have("apt-get"):
		return FamilyDebian
	case have("dnf") || have("yum"):
		return FamilyRHEL
	}
	return ""
}

// Layout is the FreeRADIUS layout of family on this machine, with the
// TACCTL_RADIUS_* overrides applied (paths.Paths.Radius): the RADIUS_*
// variables of radius.sh.
func Layout(p paths.Paths, family string) paths.RadiusPaths {
	return p.Radius(family)
}

// Params is what the renderer needs to know about this machine
// (_radius_params): the layout's name, service account and package paths.
type Params struct {
	Name       string // the daemon's instance name ('-n'), tacctl-radius
	User       string
	Group      string
	LogDir     string
	PIDFile    string
	LibDir     string
	SystemDict string // the package's main dictionary, included by tacctl's
}

// ParamsFor is _radius_params for a layout.
func ParamsFor(l paths.RadiusPaths) Params {
	return Params{
		Name: paths.RadiusName, User: l.User, Group: l.Group, LogDir: l.LogDir,
		PIDFile: l.PIDFile, LibDir: l.LibDir, SystemDict: l.SystemDict,
	}
}

// Worst is _radius_worst: the state furthest from the render among the
// words given, in the order unreadable, drift, unrecorded, missing, ok,
// same, current. ok is false when none of the words is one of those.
func Worst(states ...string) (worst string, ok bool) {
	for _, word := range []string{"unreadable", "drift", "unrecorded", "missing", "ok", "same", "current"} {
		for _, s := range states {
			if s == word {
				return word, true
			}
		}
	}
	return "", false
}

// DropinText is _radius_dropin_text: the drop-in that makes the package's
// unit run tacctl's instance, with tacctl's dictionary ('-D'). The package's
// pre-start and reload commands name its own configuration, so every Exec
// line is replaced. The text ends with a newline.
func DropinText(l paths.RadiusPaths) string {
	args := "-d " + l.Dir + " -D " + l.DictDir + " -n " + paths.RadiusName
	var b strings.Builder
	b.WriteString("# Installed by tacctl ('tacctl backend enable radius'), removed by 'tacctl backend disable radius'.\n")
	b.WriteString("# " + l.Unit + " runs tacctl's FreeRADIUS instance (" + l.Conf + ") instead of the package's radiusd.conf.\n")
	b.WriteString("[Service]\nExecStartPre=\n")
	if l.Family == FamilyRHEL {
		b.WriteString("ExecStartPre=-/bin/chown -R " + l.User + ":" + l.Group + " /var/run/radiusd\n")
		b.WriteString("ExecStartPre=" + l.Bin + " -C -lstdout " + args + "\n")
		b.WriteString("ExecStart=\n")
		b.WriteString("ExecStart=" + l.Bin + " " + args + "\n")
	} else {
		b.WriteString("ExecStartPre=" + l.Bin + " -C -lstdout " + args + "\n")
		b.WriteString("ExecStart=\n")
		b.WriteString("ExecStart=" + l.Bin + " -f " + args + "\n")
	}
	b.WriteString("ExecReload=\n")
	b.WriteString("ExecReload=" + l.Bin + " -C -lstdout " + args + "\n")
	b.WriteString("ExecReload=/bin/kill -HUP $MAINPID\n")
	return b.String()
}
