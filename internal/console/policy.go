package console

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// SystemLoginShell is what a user without the console gets as a login shell.
const SystemLoginShell = "/bin/bash"

// NoLoginShell is the login shell of an account that gets neither the
// console nor a system shell: an engineer on a server whose console cannot
// be provisioned, and a user whose tier is none (docs/plans/0.2.3-plan.md B2).
const NoLoginShell = "/usr/sbin/nologin"

// Policy is console.yaml read as decisions. The console's own process asks
// it through 'tacctl _console-policy' (it cannot read root's file); the
// provisioning and 'console show' ask it directly.
type Policy struct {
	File *File
	// Command is the console's path (paths.ConsoleCommand), ShellsFile the
	// /etc/shells the system shell must be listed in.
	Command, ShellsFile string
}

// NewPolicy is the policy of f on the host whose locations are p.
func NewPolicy(f *File, p paths.Paths) *Policy {
	return &Policy{File: f, Command: p.ConsoleCommand, ShellsFile: p.ShellsFile}
}

// Decision is whether a user gets the console, and why.
type Decision struct {
	Console bool
	// Why is the reason in words: "user override", "tier readonly",
	// "tier readonly disabled", "no tier".
	Why string
}

// Decide is the console decision for user at tier t: the engineer tier has
// the console always (D18: an engineer has the console or no login on this
// server, so neither a user override nor the tier's switch applies), then
// the user's override wins, then the tier's switch. A caller with no tier
// (none, unrestricted) gets no console: it has no account the console
// provisions.
func (p *Policy) Decide(user string, t tier.Tier) Decision {
	switch t {
	case tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser:
	default:
		return Decision{false, "no tier"}
	}
	if t == tier.Engineer {
		return Decision{true, "tier engineer (always)"}
	}
	if on, ok := p.File.Users[user]; ok {
		return Decision{on, "user override"}
	}
	if p.File.TierOn[t] {
		return Decision{true, "tier " + string(t)}
	}
	return Decision{false, "tier " + string(t) + " disabled"}
}

// Shell is the login shell of user at tier t: the console's command, or
// what ShellWithout says.
func (p *Policy) Shell(user string, t tier.Tier) string {
	if p.Decide(user, t).Console {
		return p.Command
	}
	return ShellWithout(t)
}

// ShellWithout is the login shell of an account of tier t that does not get
// the console: bash, but nologin for an engineer (the console or no login)
// and for a tier that is none or unknown (no real shell for an account
// nobody may log in to).
func ShellWithout(t tier.Tier) string {
	switch t {
	case tier.Readonly, tier.Operator, tier.Superuser, tier.Unrestricted:
		return SystemLoginShell
	}
	return NoLoginShell
}

// SystemShell reports whether the console's system-shell word is open to
// tier t. A caller with no tier restriction is open to it; none and the
// Closed tiers are not, whatever the file says.
func (p *Policy) SystemShell(t tier.Tier) bool {
	switch {
	case t == tier.Unrestricted:
		return true
	case t == tier.None, slices.Contains(Closed, t):
		return false
	}
	for _, s := range p.File.SystemShellTiers {
		if s == t {
			return true
		}
	}
	return false
}

// Forwarding reports whether tier t's console logins may forward X11 and
// TCP ports (settings.forwarding_tiers). A caller with no tier restriction
// may; none and the Closed tiers may not.
func (p *Policy) Forwarding(t tier.Tier) bool {
	switch {
	case t == tier.Unrestricted:
		return true
	case t == tier.None, slices.Contains(Closed, t):
		return false
	}
	return slices.Contains(p.File.ForwardingTiers, t)
}

// ForwardingTiers are the tiers of settings.forwarding_tiers.
func (p *Policy) ForwardingTiers() []tier.Tier { return p.File.ForwardingTiers }

// Idle is the idle timeout (0: none).
func (p *Policy) Idle() time.Duration { return time.Duration(p.File.Idle) * time.Minute }

// ListMax is the number of completions the shell lists without asking.
func (p *Policy) ListMax() int { return p.File.ListMax }

// SpaceCompletion reports whether a typed space at the console's prompt
// completes a fixed word.
func (p *Policy) SpaceCompletion() bool { return p.File.SpaceCompletion }

// SSHEscape reports whether the console's ssh keeps its escape character.
func (p *Policy) SSHEscape() bool { return p.File.SSHEscape }

// AgentForwarding reports whether the sshd drop-in lets the console's
// users forward an agent.
func (p *Policy) AgentForwarding() bool { return p.File.AgentForwarding }

// GatewayPorts reports whether the forwarding tiers may bind forwarded
// ports to an address other than loopback.
func (p *Policy) GatewayPorts() bool { return p.File.GatewayPorts }

// SystemShellPath is the system shell, checked: see CheckShell.
func (p *Policy) SystemShellPath() (string, error) {
	return p.File.SystemShell, CheckShell(p.File.SystemShell, p.ShellsFile)
}

// CheckShell checks that path may be the system shell: absolute, an
// existing executable file, listed in shellsFile (/etc/shells).
func CheckShell(path, shellsFile string) error {
	if err := ValidShellPath(path); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return fail("'" + path + "' is not an existing file.")
	}
	if st.Mode().Perm()&0o111 == 0 {
		return fail("'" + path + "' is not executable.")
	}
	listed, err := ShellListed(shellsFile, path)
	if err != nil {
		return fail("Cannot read " + shellsFile + ": " + errText(err))
	}
	if !listed {
		return fail("'" + path + "' is not listed in " + shellsFile + ".")
	}
	return nil
}

// ShellListed reports whether shellsFile has a line that is exactly path
// (comments and blank lines are skipped, as getusershell(3) does).
func ShellListed(shellsFile, path string) (bool, error) {
	f, err := os.Open(filepath.Clean(shellsFile))
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") && l == path {
			return true, nil
		}
	}
	return false, sc.Err()
}
