package console

import (
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/tier"
)

// Remote is the policy as the unprivileged console learns it: the answer
// of 'sudo -n TACCTL_CONSOLE=<session> tacctl _console-policy' (one line
// of key=value fields), or the defaults when there is none.
type Remote struct {
	Idle            time.Duration
	SystemShell     bool
	SystemShellPath string
	SSHEscape       bool
	Agent           bool
	// Forward reports whether the caller's tier may forward X11 and TCP
	// ports (console forwarding tiers): the console then hands DISPLAY on.
	Forward bool
	Tier    tier.Tier
	ListMax int
	// Known reports whether the answer was read (false: the defaults).
	Known bool
}

// DefaultRemote is the policy without an answer: idle 30 minutes, no
// system shell, no ssh escape, the default list threshold.
func DefaultRemote() Remote {
	return Remote{
		Idle:            DefaultIdle * time.Minute,
		SystemShellPath: DefaultSystemShell,
		Tier:            tier.None,
		ListMax:         DefaultListMax,
	}
}

// ParseRemote reads the _console-policy line. A key that is missing or
// malformed keeps its default; ok is false when no key at all was read.
func ParseRemote(out string) (r Remote, ok bool) {
	r = DefaultRemote()
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	for _, f := range strings.Fields(line) {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		switch k {
		case "idle":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= MaxIdle {
				r.Idle, ok = time.Duration(n)*time.Minute, true
			}
		case "system_shell":
			if b, good := yesNoValue(v); good {
				r.SystemShell, ok = b, true
			}
		case "system_shell_path":
			if ValidShellPath(v) == nil {
				r.SystemShellPath, ok = v, true
			}
		case "ssh_escape":
			if b, good := yesNoValue(v); good {
				r.SSHEscape, ok = b, true
			}
		case "agent":
			if b, good := yesNoValue(v); good {
				r.Agent, ok = b, true
			}
		case "forward":
			if b, good := yesNoValue(v); good {
				r.Forward, ok = b, true
			}
		case "tier":
			switch t := tier.Tier(v); t {
			case tier.Unrestricted, tier.Superuser, tier.Engineer, tier.Operator, tier.Readonly, tier.None:
				r.Tier, ok = t, true
			}
		case "list_max":
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= MaxListMax {
				r.ListMax, ok = n, true
			}
		case "shell":
			ok = ok || v == "console" || v == "system"
		}
	}
	r.Known = ok
	return r, ok
}

// ValidDisplay reports whether v looks like an X11 display name (such as
// localhost:10.0, the one sshd's X11 forwarding sets): the only DISPLAY the
// console hands on to tacctl.
func ValidDisplay(v string) bool {
	if v == "" || len(v) > 255 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.ContainsRune("._:/-", c):
		default:
			return false
		}
	}
	return true
}

func yesNoValue(v string) (bool, bool) {
	switch v {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return false, false
}
