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
	// Gate is the tier the root side's gate enforces for the caller (the
	// conf-problem cap applied, which Tier, the console's own view of an
	// engineer, ignores); "" when the answer has no gate field.
	Gate    tier.Tier
	ListMax int
	// SpaceCompletion: a typed space completes a fixed word (default on).
	SpaceCompletion bool
	// Known reports whether the answer was read (false: the defaults).
	Known bool
	// TierRead reports whether the answer named the caller's tier (a
	// 'tier=' or 'gate=' field): a tier of None is then the real answer,
	// not the default of an answer without one.
	TierRead bool
}

// DefaultRemote is the policy without an answer: idle 30 minutes, no
// system shell, no ssh escape, the default list threshold.
func DefaultRemote() Remote {
	return Remote{
		Idle:            DefaultIdle * time.Minute,
		SystemShellPath: DefaultSystemShell,
		Tier:            tier.None,
		ListMax:         DefaultListMax,
		SpaceCompletion: true,
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
			if t, good := tierValue(v); good {
				r.Tier, ok, r.TierRead = t, true, true
			}
		case "gate":
			if t, good := tierValue(v); good {
				r.Gate, ok, r.TierRead = t, true, true
			}
		case "list_max":
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= MaxListMax {
				r.ListMax, ok = n, true
			}
		case "space_completion":
			if b, good := yesNoValue(v); good {
				r.SpaceCompletion, ok = b, true
			}
		case "shell":
			ok = ok || v == "console" || v == "system"
		}
	}
	r.Known = ok
	return r, ok
}

// View is the tier whose verbs the shell lists for the caller (docs/plans/
// 0.2.3-plan.md D56): the gate's tier when the answer has one, else Tier.
// An answer that was not read gives None, which lists the read-only verbs
// only, never more.
func (r Remote) View() tier.Tier {
	t, _ := r.ViewRead()
	return t
}

// ViewRead is View and whether the tier was read from the answer: false for
// no answer, or an answer without a tier field (the tier is then None only
// by default, and the caller must not take it for the answer 'tier=none',
// a disabled account).
func (r Remote) ViewRead() (tier.Tier, bool) {
	switch {
	case !r.Known || !r.TierRead:
		return tier.None, false
	case r.Gate != "":
		return r.Gate, true
	}
	return r.Tier, true
}

func tierValue(v string) (tier.Tier, bool) {
	switch t := tier.Tier(v); t {
	case tier.Unrestricted, tier.Superuser, tier.Engineer, tier.Operator, tier.Readonly, tier.None:
		return t, true
	}
	return "", false
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
