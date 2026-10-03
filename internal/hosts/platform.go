package hosts

import (
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// osValue is "sed -n 's/^<key>=//p' <<< text | head -1 | tr -d \"\\\"'\"":
// the first <key>= line's value with every quote removed.
func osValue(text, key string) string {
	return strings.NewReplacer(`"`, "", "'", "").Replace(firstValue(text, key))
}

// firstValue is "sed -n 's/^<key>=//p' <<< text | head -1".
func firstValue(text, key string) string {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return v
		}
	}
	return ""
}

var (
	reCodename = regexp.MustCompile(`^[a-z]+$`)
	reMajor    = regexp.MustCompile(`^[0-9]+$`)
)

// ImageForOS is linux_image_for_os: the container image that matches a
// host's userland from its /etc/os-release, or "" when tacctl knows none.
// Ubuntu derivatives (Mint, KDE neon, ...) name their base in
// UBUNTU_CODENAME; RHEL and its rebuilds share an ABI per major release, so
// one AlmaLinux image serves RHEL, CentOS Stream, Rocky, Alma and Oracle.
func ImageForOS(text string) string {
	id := osValue(text, "ID")
	codename := osValue(text, "VERSION_CODENAME")
	ubuntu := osValue(text, "UBUNTU_CODENAME")
	if id == "ubuntu" && ubuntu == "" {
		ubuntu = codename
	}
	switch {
	case reCodename.MatchString(ubuntu):
		return "docker.io/library/ubuntu:" + ubuntu
	case id == "debian" && reCodename.MatchString(codename):
		return "docker.io/library/debian:" + codename
	}
	like := osValue(text, "ID_LIKE")
	major, _, _ := strings.Cut(osValue(text, "VERSION_ID"), ".")
	rhel := strings.Contains(" rhel centos almalinux rocky ol ", " "+id+" ") || strings.Contains(" "+like+" ", " rhel ")
	if rhel && reMajor.MatchString(major) {
		return "docker.io/library/almalinux:" + major
	}
	return ""
}

// probe prints the host's os-release and its architecture.
const probe = `cat /etc/os-release 2>/dev/null; echo; echo "TACCTL_ARCH=$(uname -m)"`

var reArch = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// Platform is linux_host_platform: the container image for the host's OS
// release ("" when tacctl knows none) and its architecture. ok is false
// when the host did not answer (or answered nonsense).
func (e *Env) Platform(ctx context.Context, target, port, identity string) (image, arch string, ok bool) {
	var out string
	if target == Local {
		res, _ := e.Runner.Run(ctx, execx.Cmd{Name: "bash", Args: []string{"-c", probe}, Stderr: e.Out.Stderr})
		out = string(res.Stdout)
	} else {
		c := e.ssh(port, identity).Cmd("-T", target, probe)
		c.Stderr = io.Discard
		res, err := e.Runner.Run(ctx, c)
		if err != nil || res.Code != 0 {
			return "", "", false
		}
		out = string(res.Stdout)
	}
	out = strings.TrimRight(out, "\n")
	arch = firstValue(out, "TACCTL_ARCH")
	if !reArch.MatchString(arch) {
		return "", "", false
	}
	return ImageForOS(out), arch, true
}
