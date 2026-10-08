// Package console is the model of the login console (docs/plans/
// operator-console-wp-console.md 5.1): /etc/tacctl/console.yaml, which says
// which tacctl users get the console as their login shell on the tacctl
// server and with what settings, and the policy read from it.
//
// An absent file is the defaults: the console on for every tier, the system
// shell for superusers only. The file is written like devices.yaml: under
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
	DefaultIdle        = 30
	MaxIdle            = 1440
	DefaultListMax     = 40
	MaxListMax         = 1000
	DefaultSystemShell = "/bin/bash"
)

// Tiers are the tiers that have a console switch, lowest first. A file
// written before the engineer tier (0.2.2) has no switch for it: it is on,
// as for every tier by default.
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
	// TierOn is the console's switch per tier.
	TierOn map[tier.Tier]bool
	// Users are the per-user overrides: true forces the console, false the
	// system shell, whatever the tier says. Absent: the tier decides.
	Users map[string]bool
	// Idle is the idle timeout in minutes (0: none).
	Idle int
	// AgentForwarding and SSHEscape are the opt-ins of the sshd drop-in and
	// of the console's ssh.
	AgentForwarding, SSHEscape bool
	// SystemShell is the program the console's system-shell word starts.
	SystemShell string
	// SystemShellTiers are the tiers that may use it.
	SystemShellTiers []tier.Tier
	// ForwardingTiers are the tiers whose console logins may forward X11
	// and TCP ports (sshd's drop-in, and the console's ssh to a device).
	ForwardingTiers []tier.Tier
	// GatewayPorts lets the forwarding tiers bind forwarded ports to an
	// address other than loopback: sshd's GatewayPorts clientspecified for
	// their remote forwards, and -g and a bind address on the console's
	// ssh -L/-D.
	GatewayPorts bool
	// ListMax is the number of completions the shell lists without asking.
	ListMax int
}

// Defaults is the file that is not there.
func Defaults() *File {
	return &File{
		TierOn:           map[tier.Tier]bool{tier.Readonly: true, tier.Operator: true, tier.Engineer: true, tier.Superuser: true},
		Users:            map[string]bool{},
		Idle:             DefaultIdle,
		SystemShell:      DefaultSystemShell,
		SystemShellTiers: []tier.Tier{tier.Superuser},
		ForwardingTiers:  []tier.Tier{tier.Superuser},
		ListMax:          DefaultListMax,
	}
}

// Clone is a deep copy.
func (f *File) Clone() *File {
	c := *f
	c.TierOn = map[tier.Tier]bool{}
	for k, v := range f.TierOn {
		c.TierOn[k] = v
	}
	c.Users = map[string]bool{}
	for k, v := range f.Users {
		c.Users[k] = v
	}
	c.SystemShellTiers = slices.Clone(f.SystemShellTiers)
	c.ForwardingTiers = slices.Clone(f.ForwardingTiers)
	return &c
}

// UserNames are the users with an override, by name.
func (f *File) UserNames() []string {
	out := make([]string, 0, len(f.Users))
	for u := range f.Users {
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
	if f.ListMax < 1 || f.ListMax > MaxListMax {
		return fail("settings.list_max must be 1-" + strconv.Itoa(MaxListMax) + ".")
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
	for _, t := range Tiers {
		if _, ok := f.TierOn[t]; !ok {
			return fail("tiers: '" + string(t) + "' is missing.")
		}
	}
	for u := range f.Users {
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
				f.TierOn[t] = on
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
				f.Users[name] = on
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
		case "agent_forwarding", "ssh_escape", "gateway_ports":
			b, ok := v.(bool)
			if !ok {
				return bad
			}
			switch k {
			case "agent_forwarding":
				f.AgentForwarding = b
			case "ssh_escape":
				f.SSHEscape = b
			default:
				f.GatewayPorts = b
			}
		case "system_shell":
			s, ok := v.(string)
			if !ok {
				return bad
			}
			f.SystemShell = s
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

func word(on bool) string {
	if on {
		return On
	}
	return Off
}

func (f *File) doc() *yamlpy.Map {
	tiers := yamlpy.NewMap()
	for _, t := range Tiers {
		tiers.Set(string(t), word(f.TierOn[t]))
	}
	users := yamlpy.NewMap()
	for _, u := range f.UserNames() {
		users.Set(u, word(f.Users[u]))
	}
	words := func(l []tier.Tier) []string {
		out := make([]string, 0, len(l))
		for _, t := range l {
			out = append(out, string(t))
		}
		return out
	}
	return yamlpy.NewMap(
		"version", Version,
		"tiers", tiers,
		"users", users,
		"settings", yamlpy.NewMap(
			"idle_timeout", f.Idle,
			"agent_forwarding", f.AgentForwarding,
			"ssh_escape", f.SSHEscape,
			"system_shell", f.SystemShell,
			"system_shell_tiers", words(f.SystemShellTiers),
			"forwarding_tiers", words(f.ForwardingTiers),
			"gateway_ports", f.GatewayPorts,
			"list_max", f.ListMax,
		),
	)
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
