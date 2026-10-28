// Package console is the model of the login console (docs/plans/
// operator-console-wp-console.md 5.1): /etc/tacctl/console.yaml, which says
// which tacctl users get the console as their login shell on the tacctl
// server and with what settings, and the policy read from it.
//
// Every managed user of every tier has the console as login shell; the file
// holds no switch for that. An absent file is the defaults: the system shell
// for superusers only. The file is written like devices.yaml: under
// an exclusive lock, through a temporary file (0600, fsync, rename) after
// the text has been read back with the reader it is read with.
package console

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Header starts console.yaml.
const Header = "# tacctl login console: which tacctl users get the console as their login shell on this server.\n" +
	"# Edit with 'tacctl console ...'; 'tacctl host sync <this server>' applies the shells.\n"

// LockName is the lock file beside console.yaml.
const LockName = ".console.lock"

// Version is the format of console.yaml.
const Version = 1

// The settings' defaults and limits.
const (
	DefaultIdle    = 30
	MaxIdle        = 1440
	DefaultListMax = 40
	MaxListMax     = 1000
	// ListMaxNever is settings.list_max of a console that never asks 'Show
	// all N?' before a long list (the shell's negative ListMax).
	ListMaxNever       = -1
	DefaultSystemShell = "/bin/bash"

	// The password cache's lifetimes (D70): idle minutes without a use,
	// and hours from the store.
	DefaultPasswordCacheIdle = 15
	MaxPasswordCacheIdle     = 120
	DefaultPasswordCacheMax  = 8
	MaxPasswordCacheMax      = 24
)

// The values of settings.color (File.Color): the terminal decides (auto),
// colour always (on), colour never (off).
const (
	ColorAuto = "auto"
	ColorOn   = "on"
	ColorOff  = "off"
)

// ColorWords are the words of 'console color'.
var ColorWords = []string{ColorAuto, ColorOn, ColorOff}

// Tiers are the tiers, lowest first.
var Tiers = []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser}

// Closed are the tiers neither system-shell nor forwarding is ever opened
// to (D18, D24): an engineer has the devices' and hosts' secrets of their
// own scopes through tacctl, and a shell or a forwarded port on this
// server would be a way to the rest; engineers reach devices with the
// console's ssh.
var Closed = []tier.Tier{tier.Engineer}

// On and Off are the words of a switch in the file and on the command line.
const (
	On  = "enable"
	Off = "disable"
)

// File is console.yaml, version 1.
type File struct {
	// IgnoredTiers and IgnoredUsers are the 'tiers' and 'users' mappings of
	// a file written before 0.2.20, which had a console switch per tier and
	// per user. Every managed user has the console now, so nothing reads
	// them: they are kept as they were read and written back unchanged
	// when the file is rewritten (an older release, after a rollback, reads
	// them as it always did), and a file that never had them does not get
	// them. Only the tiers and users the file names are in the maps.
	IgnoredTiers map[tier.Tier]bool
	IgnoredUsers map[string]bool
	// Idle is the idle timeout in minutes (0: none).
	Idle int
	// AgentForwarding and SSHEscape are the opt-ins of the sshd drop-in and
	// of the console's ssh.
	AgentForwarding, SSHEscape bool
	// SystemShell is the program the console's system-shell word starts.
	SystemShell string
	// SystemShellTiers are the tiers that may use it. The superuser tier
	// always may, whatever the list says, and the Closed tiers never (the
	// setter writes the superuser tier into the list so that an older
	// release reads the same).
	SystemShellTiers []tier.Tier
	// SystemShellUsers are the users with a setting of their own (settings.
	// system_shell_users): true gives the system shell to a user of a tier
	// that has none, false takes it from a user of a tier that has it. It
	// beats the tier's setting, but for the superuser tier (always) and the
	// Closed tiers (never). An enable is valid for the tier the user had when
	// it was set (SystemShellUserTiers): a user who moves to another tier has
	// no access from it, and it is listed as stale until it is set again, so a
	// demotion cannot leave a user with a shell the new tier does not give.
	// Written only when it is not empty, as 'enable:<tier>' and 'disable'; an
	// older release rejects the key, and the rollback removes it (Keys0220).
	SystemShellUsers map[string]bool
	// SystemShellUserTiers are the tiers (readonly or operator) the enables of
	// SystemShellUsers were set for; a disable has none.
	SystemShellUserTiers map[string]tier.Tier
	// PasswordCacheUsers are the users who turned the password cache on for
	// themselves (settings.password_cache_users, a map of user name to true):
	// the tiers of PasswordCacheTiers are the permission, this is the user's
	// choice, off until the user makes it. Only users who are on are stored.
	// Written only when not empty; an older release rejects the key, and the
	// rollback removes it (Keys0220).
	PasswordCacheUsers map[string]bool
	// ForwardingTiers are the tiers whose console logins may forward X11
	// and TCP ports (sshd's drop-in, and the console's ssh to a device).
	ForwardingTiers []tier.Tier
	// GatewayPorts lets the forwarding tiers bind forwarded ports to an
	// address other than loopback: sshd's GatewayPorts clientspecified for
	// their remote forwards, and -g and a bind address on the console's
	// ssh -L/-D.
	GatewayPorts bool
	// ListMax is the number of completions the shell lists without asking
	// ('Show all N?' above it); ListMaxNever (-1) never asks. A 0.2.19
	// reader rejects the -1 (and every release before it); the rollback to
	// them writes MaxListMax (RollbackSince0220).
	ListMax int
	// Color is whether the console's lists are in colour: ColorAuto (the
	// terminal decides, as everywhere else), ColorOn or ColorOff. The
	// console's environment holds neither NO_COLOR nor TACCTL_COLOR
	// (Scrub), so this is how the operator chooses. Written to the file
	// only when it is not auto, as true (on) or false (off); a file without
	// the key reads as auto. A 0.2.19 reader (and every release before it)
	// rejects the key, and the rollback removes it (RollbackSince0220).
	Color string
	// SpaceCompletion is whether a typed space at the console's prompt is
	// Junos-style (completes a fixed word, never doubles). Written to the
	// file only when off (doc); a file without the key reads as on. A 0.2.2
	// reader rejects the key, and the engineer tier's key too: going back
	// to 0.2.2 needed the rollback step of 0.2.3's tool (pinned by
	// TestRollbackToTheOldParser); 0.2.3 reads both.
	SpaceCompletion bool
	// PasswordCacheTiers are the tiers whose shell and console sessions
	// may keep the user's network password in memory for the session
	// (docs/plans/0.2.4-plan.md D70); none by default. PasswordCacheIdle is
	// the minutes without a use and PasswordCacheMax the hours from the
	// store. The settings.password_cache mapping is written only when one
	// of the three is not its default. A 0.2.3 reader (and a 0.2.2 one)
	// rejects the key, and 'tacctl rollback 0.2.3' (Text023) removes it.
	PasswordCacheTiers                  []tier.Tier
	PasswordCacheIdle, PasswordCacheMax int
}

// Defaults is the file that is not there.
func Defaults() *File {
	return &File{
		IgnoredTiers:         map[tier.Tier]bool{},
		IgnoredUsers:         map[string]bool{},
		Idle:                 DefaultIdle,
		SystemShell:          DefaultSystemShell,
		SystemShellTiers:     []tier.Tier{tier.Superuser},
		SystemShellUsers:     map[string]bool{},
		SystemShellUserTiers: map[string]tier.Tier{},
		PasswordCacheUsers:   map[string]bool{},
		ForwardingTiers:      []tier.Tier{tier.Superuser},
		ListMax:              DefaultListMax,
		SpaceCompletion:      true,
		Color:                ColorAuto,

		PasswordCacheIdle: DefaultPasswordCacheIdle,
		PasswordCacheMax:  DefaultPasswordCacheMax,
	}
}

// Clone is a deep copy.
func (f *File) Clone() *File {
	c := *f
	c.IgnoredTiers = map[tier.Tier]bool{}
	for k, v := range f.IgnoredTiers {
		c.IgnoredTiers[k] = v
	}
	c.IgnoredUsers = map[string]bool{}
	for k, v := range f.IgnoredUsers {
		c.IgnoredUsers[k] = v
	}
	c.SystemShellTiers = slices.Clone(f.SystemShellTiers)
	c.SystemShellUsers = map[string]bool{}
	for k, v := range f.SystemShellUsers {
		c.SystemShellUsers[k] = v
	}
	c.SystemShellUserTiers = map[string]tier.Tier{}
	for k, v := range f.SystemShellUserTiers {
		c.SystemShellUserTiers[k] = v
	}
	c.PasswordCacheUsers = map[string]bool{}
	for k, v := range f.PasswordCacheUsers {
		c.PasswordCacheUsers[k] = v
	}
	c.ForwardingTiers = slices.Clone(f.ForwardingTiers)
	c.PasswordCacheTiers = slices.Clone(f.PasswordCacheTiers)
	return &c
}

// SystemShellUserNames are the users with a system-shell setting of their
// own, by name.
func (f *File) SystemShellUserNames() []string {
	out := make([]string, 0, len(f.SystemShellUsers))
	for u := range f.SystemShellUsers {
		out = append(out, u)
	}
	slices.Sort(out)
	return out
}

// TierHas reports whether the file's list gives tier t the system shell (the
// superuser tier always has it, the Closed tiers never).
func TierHas(f *File, t tier.Tier) bool {
	return (&Policy{File: f}).SystemShell(t)
}

// SetSystemShell opens (on) or closes the system shell for tier t: the
// superuser tier always has it and the Closed tiers never can. The list
// that is written is the superuser tier and every tier that has it, lowest
// first.
func (f *File) SetSystemShell(t tier.Tier, on bool) error {
	switch {
	case slices.Contains(Closed, t) && on:
		return fail(ClosedText(t, "system-shell"))
	case t == tier.Superuser && !on:
		return fail("The superuser tier always has the system shell; it cannot be disabled. Nothing was changed.")
	}
	var out []tier.Tier
	for _, x := range Tiers {
		if slices.Contains(Closed, x) {
			continue
		}
		has := x == tier.Superuser || slices.Contains(f.SystemShellTiers, x)
		if x == t {
			has = on
		}
		if has {
			out = append(out, x)
		}
	}
	f.SystemShellTiers = out
	return nil
}

// SetSystemShellUser gives the user a system-shell setting of their own: an
// enable is recorded with the tier it is set for (readonly or operator; the
// superuser and engineer tiers need none), a disable with none.
func (f *File) SetSystemShellUser(name string, on bool, t tier.Tier) {
	f.SystemShellUsers[name] = on
	if on {
		f.SystemShellUserTiers[name] = t
	} else {
		delete(f.SystemShellUserTiers, name)
	}
}

// DropSystemShellUser removes the user's system-shell setting.
func (f *File) DropSystemShellUser(name string) {
	delete(f.SystemShellUsers, name)
	delete(f.SystemShellUserTiers, name)
}

// PasswordCacheUserNames are the users who turned the password cache on, by
// name.
func (f *File) PasswordCacheUserNames() []string {
	out := make([]string, 0, len(f.PasswordCacheUsers))
	for u, on := range f.PasswordCacheUsers {
		if on {
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return out
}

// IgnoredUserNames are the users the file has an (ignored) override for, by
// name.
func (f *File) IgnoredUserNames() []string {
	out := make([]string, 0, len(f.IgnoredUsers))
	for u := range f.IgnoredUsers {
		out = append(out, u)
	}
	slices.Sort(out)
	return out
}

func fail(lines ...string) error { return &names.Error{Msgs: lines} }

// ParseTier is the tier a word names (readonly, operator, engineer,
// superuser).
func ParseTier(s string) (tier.Tier, bool) {
	for _, t := range Tiers {
		if string(t) == s {
			return t, true
		}
	}
	return "", false
}

// ParseTiers is a comma-separated list of tiers, each once, for
// system-shell or forwarding ('what'); "none" and "" are the empty list.
// A tier of Closed is refused.
func ParseTiers(csv, what string) ([]tier.Tier, error) {
	if csv == "none" || csv == "" {
		return nil, nil
	}
	var out []tier.Tier
	for _, w := range strings.Split(csv, ",") {
		t, ok := ParseTier(w)
		if !ok {
			return nil, fail("Unknown tier '" + w + "': expected readonly, operator or superuser.")
		}
		if slices.Contains(Closed, t) {
			return nil, fail(ClosedText(t, what))
		}
		if slices.Contains(out, t) {
			return nil, fail("Tier '" + w + "' is listed twice.")
		}
		out = append(out, t)
	}
	return out, nil
}

// CacheTiers are the tiers the password cache can be opened to: the ones
// that log in to devices with their own password (D70). A read-only user
// has no pull, and the cache is not offered to it.
var CacheTiers = []tier.Tier{tier.Operator, tier.Engineer, tier.Superuser}

// ParsePasswordCacheTiers is a comma-separated list of tiers, each once,
// for password-cache tiers; "none" and "" are the empty list.
func ParsePasswordCacheTiers(csv string) ([]tier.Tier, error) {
	if csv == "none" || csv == "" {
		return nil, nil
	}
	var out []tier.Tier
	for _, w := range strings.Split(csv, ",") {
		t := tier.Tier(w)
		if !slices.Contains(CacheTiers, t) {
			return nil, fail("Unknown tier '" + w + "': the password cache can be opened to operator, engineer and superuser.")
		}
		if slices.Contains(out, t) {
			return nil, fail("Tier '" + w + "' is listed twice.")
		}
		out = append(out, t)
	}
	return out, nil
}

// ClosedText is the refusal of a Closed tier for system-shell or
// forwarding.
func ClosedText(t tier.Tier, what string) string {
	if what == "forwarding" {
		return "The " + string(t) + " tier cannot be given forwarding on this server: engineers reach devices with the console's ssh. Nothing was changed."
	}
	return "The " + string(t) + " tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed."
}

// ValidShellPath checks the shape of a system shell: an absolute, clean
// path. That it exists, may run and is listed in /etc/shells is
// CheckShell's business (the file may be read where the shell is not).
func ValidShellPath(p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, " \t\n\r:") {
		return fail("The system shell must be an absolute path (no spaces), such as /bin/bash.")
	}
	return nil
}

// validate is the invariants of a file.
func (f *File) validate() error {
	if f.Idle < 0 || f.Idle > MaxIdle {
		return fail("settings.idle_timeout must be 0-" + strconv.Itoa(MaxIdle) + ".")
	}
	if f.ListMax != ListMaxNever && (f.ListMax < 1 || f.ListMax > MaxListMax) {
		return fail("settings.list_max must be 1-" + strconv.Itoa(MaxListMax) + " (or " + strconv.Itoa(ListMaxNever) + ": never ask).")
	}
	if !slices.Contains(ColorWords, f.Color) {
		return fail("settings.color must be true (on), false (off) or absent (auto).")
	}
	if err := ValidShellPath(f.SystemShell); err != nil {
		return fail("settings.system_shell: " + strings.Join(msgs(err), " "))
	}
	for key, l := range map[string][]tier.Tier{"system_shell_tiers": f.SystemShellTiers, "forwarding_tiers": f.ForwardingTiers} {
		seen := map[tier.Tier]bool{}
		for _, t := range l {
			if _, ok := ParseTier(string(t)); !ok || seen[t] || slices.Contains(Closed, t) {
				return fail("settings." + key + ": invalid or repeated tier '" + string(t) + "'.")
			}
			seen[t] = true
		}
	}
	for u, on := range f.SystemShellUsers {
		if !names.MatchUser(u) {
			return fail("settings.system_shell_users: invalid user name '" + u + "'.")
		}
		if t := f.SystemShellUserTiers[u]; on && t != tier.Readonly && t != tier.Operator {
			return fail("settings.system_shell_users: '" + u + "' must be disable or enable:readonly|operator.")
		}
	}
	for u := range f.PasswordCacheUsers {
		if !names.MatchUser(u) {
			return fail("settings.password_cache_users: invalid user name '" + u + "'.")
		}
	}
	seenPC := map[tier.Tier]bool{}
	for _, t := range f.PasswordCacheTiers {
		if !slices.Contains(CacheTiers, t) || seenPC[t] {
			return fail("settings.password_cache.tiers: invalid or repeated tier '" + string(t) + "'.")
		}
		seenPC[t] = true
	}
	if f.PasswordCacheIdle < 1 || f.PasswordCacheIdle > MaxPasswordCacheIdle {
		return fail("settings.password_cache.idle must be 1-" + strconv.Itoa(MaxPasswordCacheIdle) + " (minutes).")
	}
	if f.PasswordCacheMax < 1 || f.PasswordCacheMax > MaxPasswordCacheMax {
		return fail("settings.password_cache.max must be 1-" + strconv.Itoa(MaxPasswordCacheMax) + " (hours).")
	}
	for u := range f.IgnoredUsers {
		if !names.MatchUser(u) {
			return fail("users: invalid user name '" + u + "'.")
		}
	}
	return nil
}

func msgs(err error) []string {
	var lines interface{ Lines() []string }
	if errors.As(err, &lines) {
		return lines.Lines()
	}
	return []string{err.Error()}
}

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// Load reads the file at path; a missing file is the defaults.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Defaults(), nil
	case err != nil:
		return nil, fail("Cannot read " + path + ": " + errText(err))
	}
	f, err := parse(data)
	if err != nil {
		return nil, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	return f, nil
}

func onOff(v any) (bool, bool) {
	s, ok := v.(string)
	if !ok || (s != On && s != Off) {
		return false, false
	}
	return s == On, true
}

func parse(data []byte) (*File, error) {
	v, err := pyyaml.LoadBytes(data)
	if err != nil {
		return nil, fail("not valid YAML: " + firstLine(err.Error()))
	}
	f := Defaults()
	if v == nil {
		return f, nil
	}
	root, ok := v.(*yamlpy.Map)
	if !ok {
		return nil, fail("expected a mapping at the top level.")
	}
	for k, val := range root.All() {
		switch k {
		case "version":
			if n, ok := val.(int); !ok || n != Version {
				return nil, fail("unsupported version (this tacctl reads version " + strconv.Itoa(Version) + ").")
			}
		case "tiers":
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("tiers must be a mapping of tier to enable|disable.")
			}
			for name, tv := range m.All() {
				t, known := ParseTier(name)
				on, valid := onOff(tv)
				if !known || !valid {
					return nil, fail("tiers: unknown tier or value for '" + name + "' (readonly, operator, engineer, superuser; enable or disable).")
				}
				f.IgnoredTiers[t] = on
			}
		case "users":
			if val == nil {
				continue
			}
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("users must be a mapping of user to enable|disable.")
			}
			for name, uv := range m.All() {
				on, valid := onOff(uv)
				if !valid {
					return nil, fail("users: '" + name + "' must be enable or disable.")
				}
				f.IgnoredUsers[name] = on
			}
		case "settings":
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("settings must be a mapping.")
			}
			if err := parseSettings(f, m); err != nil {
				return nil, err
			}
		default:
			return nil, fail("unknown key '" + k + "'.")
		}
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return f, nil
}

func parseSettings(f *File, m *yamlpy.Map) error {
	for k, v := range m.All() {
		bad := fail("settings: invalid value for '" + k + "'.")
		switch k {
		case "idle_timeout", "list_max":
			n, ok := v.(int)
			if !ok {
				return bad
			}
			if k == "idle_timeout" {
				f.Idle = n
			} else {
				f.ListMax = n
			}
		case "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion", "color":
			b, ok := v.(bool)
			if !ok {
				return bad
			}
			switch k {
			case "color":
				f.Color = ColorOff
				if b {
					f.Color = ColorOn
				}
			case "agent_forwarding":
				f.AgentForwarding = b
			case "ssh_escape":
				f.SSHEscape = b
			case "space_completion":
				f.SpaceCompletion = b
			default:
				f.GatewayPorts = b
			}
		case "password_cache":
			m, ok := v.(*yamlpy.Map)
			if !ok {
				return fail("settings.password_cache must be a mapping (tiers, idle, max).")
			}
			if err := parsePasswordCache(f, m); err != nil {
				return err
			}
		case "system_shell":
			s, ok := v.(string)
			if !ok {
				return bad
			}
			f.SystemShell = s
		case "system_shell_users":
			switch x := v.(type) {
			case nil:
			case *yamlpy.Map:
				for name, uv := range x.All() {
					s, ok := uv.(string)
					word, tr, hasTier := strings.Cut(s, ":")
					switch {
					case !ok, word != "disable" && word != "enable", word == "disable" && hasTier, word == "enable" && !hasTier:
						return fail("settings.system_shell_users: '" + name + "' must be disable or enable:readonly|operator.")
					}
					f.SystemShellUsers[name] = word == "enable"
					if word == "enable" {
						f.SystemShellUserTiers[name] = tier.Tier(tr)
					}
				}
			default:
				return fail("settings.system_shell_users must be a mapping of user to disable or enable:<tier>.")
			}
		case "password_cache_users":
			switch x := v.(type) {
			case nil:
			case *yamlpy.Map:
				for name, uv := range x.All() {
					b, ok := uv.(bool)
					if !ok {
						return fail("settings.password_cache_users: '" + name + "' must be true or false.")
					}
					f.PasswordCacheUsers[name] = b
				}
			default:
				return fail("settings.password_cache_users must be a mapping of user to true or false.")
			}
		case "system_shell_tiers", "forwarding_tiers":
			var l []tier.Tier
			switch x := v.(type) {
			case nil:
			case []any:
				for _, e := range x {
					s, ok := e.(string)
					if !ok {
						return bad
					}
					l = append(l, tier.Tier(s))
				}
			default:
				return bad
			}
			if k == "system_shell_tiers" {
				f.SystemShellTiers = l
			} else {
				f.ForwardingTiers = l
			}
		default:
			return fail("settings: unknown key '" + k + "'.")
		}
	}
	return nil
}

func parsePasswordCache(f *File, m *yamlpy.Map) error {
	for k, v := range m.All() {
		bad := fail("settings.password_cache: invalid value for '" + k + "'.")
		switch k {
		case "tiers":
			var l []tier.Tier
			switch x := v.(type) {
			case nil:
			case []any:
				for _, e := range x {
					s, ok := e.(string)
					if !ok {
						return bad
					}
					l = append(l, tier.Tier(s))
				}
			default:
				return bad
			}
			f.PasswordCacheTiers = l
		case "idle", "max":
			n, ok := v.(int)
			if !ok {
				return bad
			}
			if k == "idle" {
				f.PasswordCacheIdle = n
			} else {
				f.PasswordCacheMax = n
			}
		default:
			return fail("settings.password_cache: unknown key '" + k + "'.")
		}
	}
	return nil
}

func word(on bool) string {
	if on {
		return On
	}
	return Off
}

func (f *File) doc() *yamlpy.Map {
	words := func(l []tier.Tier) []string {
		out := make([]string, 0, len(l))
		for _, t := range l {
			out = append(out, string(t))
		}
		return out
	}
	settings := yamlpy.NewMap(
		"idle_timeout", f.Idle,
		"agent_forwarding", f.AgentForwarding,
		"ssh_escape", f.SSHEscape,
		"system_shell", f.SystemShell,
		"system_shell_tiers", words(f.SystemShellTiers),
		"forwarding_tiers", words(f.ForwardingTiers),
		"gateway_ports", f.GatewayPorts,
		"list_max", f.ListMax,
	)
	if !f.SpaceCompletion {
		// Only when off, so the file of a console that never turned it off
		// has no key of 0.2.3 beyond the engineer tier's.
		settings.Set("space_completion", false)
	}
	switch f.Color {
	case ColorOn:
		// Only when set, so a file that never chose is read by every release.
		settings.Set("color", true)
	case ColorOff:
		settings.Set("color", false)
	}
	if len(f.PasswordCacheTiers) > 0 || f.PasswordCacheIdle != DefaultPasswordCacheIdle || f.PasswordCacheMax != DefaultPasswordCacheMax {
		// Only when something is set, so a file that never touched the
		// cache is the file 0.2.3 wrote.
		settings.Set("password_cache", yamlpy.NewMap(
			"tiers", words(f.PasswordCacheTiers),
			"idle", f.PasswordCacheIdle,
			"max", f.PasswordCacheMax,
		))
	}
	if len(f.SystemShellUsers) > 0 {
		// Only when something is set, so a file that never gave a user a
		// system-shell setting is read by every release.
		users := yamlpy.NewMap()
		for _, u := range f.SystemShellUserNames() {
			if f.SystemShellUsers[u] {
				users.Set(u, "enable:"+string(f.SystemShellUserTiers[u]))
			} else {
				users.Set(u, "disable")
			}
		}
		settings.Set("system_shell_users", users)
	}
	if names := f.PasswordCacheUserNames(); len(names) > 0 {
		// Only users who are on, and only when there are some, so a file
		// that nobody turned the cache on in is read by every release.
		users := yamlpy.NewMap()
		for _, u := range names {
			users.Set(u, true)
		}
		settings.Set("password_cache_users", users)
	}
	doc := yamlpy.NewMap("version", Version)
	if len(f.IgnoredTiers) > 0 {
		tiers := yamlpy.NewMap()
		for _, t := range Tiers {
			if on, ok := f.IgnoredTiers[t]; ok {
				tiers.Set(string(t), word(on))
			}
		}
		doc.Set("tiers", tiers)
	}
	if len(f.IgnoredUsers) > 0 {
		users := yamlpy.NewMap()
		for _, u := range f.IgnoredUserNames() {
			users.Set(u, word(f.IgnoredUsers[u]))
		}
		doc.Set("users", users)
	}
	doc.Set("settings", settings)
	return doc
}

// Text is the file as it is written: the header and the YAML, checked by
// reading it back with the reader the file is read with.
func (f *File) Text() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	out, err := yamlpy.EmitChecked(f.doc(), yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the console settings (" + firstLine(err.Error()) + "); nothing was written")
	}
	return out, nil
}

// Lock takes the file's exclusive lock (<dir>/.console.lock, 0600) and
// returns the function that releases it.
func Lock(path string) (unlock func(), err error) {
	d := filepath.Dir(path)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, fail("Cannot create " + d + ": " + errText(err))
	}
	lf, err := os.OpenFile(filepath.Join(d, LockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fail("Cannot open the console lock: " + errText(err))
	}
	for {
		err = unix.Flock(int(lf.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lf.Close()
		return nil, fail("Cannot lock the console settings: " + err.Error())
	}
	return func() { _ = lf.Close() }, nil
}

// Mutate changes the file under its lock: before runs first (a snapshot; an
// error stops the write), then the file is loaded, fn changes it, and the
// result is validated, rendered, read back and written through a temporary
// file (0600, fsync, rename). Nothing is written when fn or the validation
// fails, or when the bytes would not change; changed reports whether the
// file was replaced.
func Mutate(path string, before func() error, fn func(*File) error) (changed bool, err error) {
	if before != nil {
		if err := before(); err != nil {
			return false, err
		}
	}
	unlock, err := Lock(path)
	if err != nil {
		return false, err
	}
	defer unlock()
	f, err := Load(path)
	if err != nil {
		return false, err
	}
	if err := fn(f); err != nil {
		return false, err
	}
	text, err := f.Text()
	if err != nil {
		return false, err
	}
	if cur, err := os.ReadFile(path); err != nil || !bytes.Equal(cur, text) {
		if err := atomicWrite(path, text, 0o600); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	d := filepath.Dir(path)
	tf, err := os.CreateTemp(d, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fail("Cannot write " + path + ": " + errText(err))
	}
	tmp := tf.Name()
	cleanup := func(err error) error {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return fail("Cannot write " + path + ": " + errText(err))
	}
	if err := tf.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if _, err := tf.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tf.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fail("Cannot write " + path + ": " + errText(err))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fail("Cannot write " + path + ": " + errText(err))
	}
	if df, err := os.Open(d); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}
