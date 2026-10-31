package snmpcred

// The credentials of a scope (D46 of docs/plans/0.2.3-plan.md): one file per
// scope, StateDir/snmp/<scope>.yaml (0600, the directory 0700), in the
// format of snmp.yaml, which stays the default beneath every scope and is
// unchanged: a 0.2.2 snmp.yaml loads as before, and 0.2.2 ignores the new
// directory. Resolve combines a scope's settings with the default's, one
// setting at a time (the scope's own, then the default's, then the built-in),
// and says where each came from.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/snmp"
)

// reScope is a scope name (names.MatchScope's shape): the file name must
// never be able to leave the directory.
var reScope = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)

// ScopeFile is the credentials file of a scope under dir.
func ScopeFile(dir, scope string) (string, error) {
	if !reScope.MatchString(scope) {
		return "", fail("Invalid scope name '" + scope + "'.")
	}
	return filepath.Join(dir, scope+".yaml"), nil
}

// LoadScope reads the scope's file; a missing one is no credentials.
func LoadScope(dir, scope string) (Creds, error) {
	p, err := ScopeFile(dir, scope)
	if err != nil {
		return Creds{}, err
	}
	return Load(p)
}

// SaveScope writes the scope's file (0600) in dir (0700); no credentials at
// all removes the file, and the directory when that leaves it empty.
func SaveScope(dir, scope string, c Creds) error {
	p, err := ScopeFile(dir, scope)
	if err != nil {
		return err
	}
	if c.Empty() {
		return RemoveScope(dir, scope)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("Cannot create " + dir + ": " + errText(err))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fail("Cannot protect " + dir + ": " + errText(err))
	}
	return Save(p, c)
}

// RemoveScope deletes the scope's file (a missing one is fine) and the
// directory when it is left empty.
func RemoveScope(dir, scope string) error {
	p, err := ScopeFile(dir, scope)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot remove " + p + ": " + errText(err))
	}
	_ = os.Remove(dir) // only when empty
	return nil
}

// RenameScope moves the scope's file to the new name (a scope renamed); no
// file is nothing to do. A file the new name already has is never
// overwritten: it is a leftover (a scope removed earlier, a directory a
// rollback kept), and the renamed scope would otherwise lose its own
// credentials to it or take it over (ErrScopeFileExists).
func RenameScope(dir, old, newName string) error {
	from, err := ScopeFile(dir, old)
	if err != nil {
		return err
	}
	to, err := ScopeFile(dir, newName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := CheckNoScopeFile(dir, newName); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot rename " + from + ": " + errText(err))
	}
	return nil
}

// CheckNoScopeFile is nil when the scope has no credentials file under dir.
// A new scope (or a scope renamed to the name) that finds one would pick up
// the credentials of an earlier scope of that name: a file left by a scope
// removed with the file restored, by a rollback of an older release, or by
// hand. The refusal names the file and how to go on.
func CheckNoScopeFile(dir, scope string) error {
	p, err := ScopeFile(dir, scope)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(p); err == nil {
		return fail("SNMP credentials for a scope named '"+scope+"' are already on disk: "+p+".",
			"They belong to an earlier scope of that name, and the new one would use them. Remove the file (or move it away), then run the command again.")
	}
	return nil
}

// Where a resolved setting came from.
const (
	FromDevice  = "device"
	FromScope   = "scope"
	FromDefault = "default"
	FromBuiltIn = "built-in"
	NotSet      = "not set"
)

// Layer is one level's settings: the device's own (the snmp map of
// devices.yaml and snmp/devices/<name>.yaml, D72 of docs/plans/0.2.4-
// plan.md), the scope's (snmp_scope.<scope>.* and its file) or the
// default's (snmp.* and snmp.yaml). The zero value of a field is "not set at
// this level".
type Layer struct {
	Version string
	Port    int
	Timeout int
	Auth    string
	Priv    string
	Creds   Creds
	// Name and Setter describe the level in the problems of the resolution:
	// "scope lab" and "tacctl scope snmp lab". Empty is a generic wording.
	Name, Setter string
}

// Empty reports whether the level sets nothing of its own (the name and the
// setter are no setting).
func (l Layer) Empty() bool {
	return l.Version == "" && l.Port == 0 && l.Timeout == 0 && l.Auth == "" && l.Priv == "" && l.Creds.Empty()
}

// Effective is the settings a device of a scope is read with, and where each
// came from.
type Effective struct {
	Version, VersionFrom string
	Port                 int
	PortFrom             string
	Timeout              int
	TimeoutFrom          string
	Auth, AuthFrom       string
	Priv, PrivFrom       string
	// The community (v2c).
	Community, CommunityFrom string
	// The v3 user (D304): the default of the device, else of its scope,
	// else of the default level, found in the pool of one of the levels it
	// may use. User is the name chosen (also when it cannot be found or
	// lacks a passphrase: V3Problem says so), the passphrases are the
	// user's, V3From the level whose pool holds the user, and DefaultFrom
	// the level whose default chose it. With no default anywhere User is
	// empty and both are "not set". Nothing falls back to another user.
	User, AuthPass, PrivPass string
	V3From, DefaultFrom      string
	// V3Problem is why the chosen user cannot be used, a fragment that ends
	// in the command that fixes it ("" when it can, or none is chosen).
	V3Problem string
}

// Resolve combines the scope's layer with the default's. A device in no
// scope passes the zero Layer as scope and gets the default.
func Resolve(scope, def Layer) Effective { return ResolveDevice(Layer{}, scope, def) }

// ResolveDevice combines a device's own layer (D72 of docs/plans/0.2.4-
// plan.md: its snmp map in devices.yaml and its file under snmp/devices)
// with its scope's and the default's: the device's value, then the scope's,
// then the default's, then the built-in, one setting at a time. The zero
// Layer as dev is Resolve. The v3 user is the one place that chooses
// differently (D304 of docs/plans/0.2.23-plan.md): the first default user,
// the device's, else the scope's, else the default level's, looked up in the
// pools it may use (a device's: its own, its scope's, the default level's; a
// scope's and the default level's: their own). A user that is not there, or
// lacks a passphrase, is a problem, never a reason to take the next default.
func ResolveDevice(dev, scope, def Layer) Effective {
	levels := []poolLevel{{dev, FromDevice}, {scope, FromScope}, {def, FromDefault}}
	str := func(get func(Layer) string, builtIn string) (string, string) {
		for _, lv := range levels {
			if v := get(lv.l); v != "" {
				return v, lv.from
			}
		}
		if builtIn != "" {
			return builtIn, FromBuiltIn
		}
		return "", NotSet
	}
	num := func(get func(Layer) int, builtIn int) (int, string) {
		for _, lv := range levels {
			if v := get(lv.l); v != 0 {
				return v, lv.from
			}
		}
		return builtIn, FromBuiltIn
	}
	var e Effective
	e.Version, e.VersionFrom = str(func(l Layer) string { return l.Version }, "")
	e.Port, e.PortFrom = num(func(l Layer) int { return l.Port }, snmp.DefaultPort)
	e.Timeout, e.TimeoutFrom = num(func(l Layer) int { return l.Timeout }, snmp.DefaultTimeout)
	e.Auth, e.AuthFrom = str(func(l Layer) string { return l.Auth }, snmp.AuthSHA)
	e.Priv, e.PrivFrom = str(func(l Layer) string { return l.Priv }, snmp.PrivAES128)
	e.Community, e.CommunityFrom = str(func(l Layer) string { return l.Creds.Community }, "")
	e.V3From, e.DefaultFrom = NotSet, NotSet
	for i, lv := range levels {
		if lv.l.Creds.Default == "" {
			continue
		}
		// A device's default may name a user of any of the three pools; a
		// scope's and the default level's only their own.
		from := levels[i : i+1]
		if i == 0 {
			from = levels
		}
		e.resolveUser(lv, from)
		break
	}
	return e
}

// poolLevel is a level with its origin.
type poolLevel struct {
	l    Layer
	from string
}

// resolveUser looks the user that the default of chooser names up in the
// pools of from.
func (e *Effective) resolveUser(chooser poolLevel, from []poolLevel) {
	name := chooser.l.Creds.Default
	e.User, e.DefaultFrom = name, chooser.from
	for _, pl := range from {
		u, ok := pl.l.Creds.Find(name)
		if !ok {
			continue
		}
		e.AuthPass, e.PrivPass, e.V3From = u.AuthPass, u.PrivPass, pl.from
		what := ""
		switch {
		case u.AuthPass == "" && u.PrivPass == "":
			what = "no passphrases"
		case u.AuthPass == "":
			what = "no authentication passphrase"
		case u.PrivPass == "":
			what = "no privacy passphrase"
		}
		if what != "" {
			e.V3Problem = "the SNMPv3 user '" + name + "' of " + levelName(pl.l, pl.from) + " has " + what +
				" ('" + setterOf(pl.l, pl.from) + " v3-user add " + name + "' sets them)"
		}
		return
	}
	e.V3From = chooser.from
	var where []string
	for _, pl := range from {
		where = append(where, levelName(pl.l, pl.from))
	}
	setter := setterOf(chooser.l, chooser.from)
	e.V3Problem = "the SNMPv3 user '" + name + "', the default of " + levelName(chooser.l, chooser.from) + ", is in no pool it may use (" +
		strings.Join(where, ", ") + "); '" + setter + " v3-user add " + name + "' adds it, '" + setter + " v3-user default <user>' chooses another"
}

// levelName is how a level is called in a problem.
func levelName(l Layer, from string) string {
	if l.Name != "" {
		return l.Name
	}
	switch from {
	case FromDevice:
		return "the device"
	case FromScope:
		return "the scope"
	}
	return "the config"
}

// setterOf is the verb family of a level.
func setterOf(l Layer, from string) string {
	if l.Setter != "" {
		return l.Setter
	}
	switch from {
	case FromDevice:
		return "tacctl device snmp <device>"
	case FromScope:
		return "tacctl scope snmp <scope>"
	}
	return "tacctl config snmp"
}

// HasV3 reports whether the user is found and both passphrases are set.
func (e Effective) HasV3() bool {
	return e.User != "" && e.AuthPass != "" && e.PrivPass != "" && e.V3Problem == ""
}

// CredFrom is where the credentials the version needs came from: the
// community's for v2c, the v3 user's for v3 ("not set" for no version or
// none).
func (e Effective) CredFrom() string {
	switch e.Version {
	case snmp.V2c:
		return e.CommunityFrom
	case snmp.V3:
		return e.V3From
	}
	return NotSet
}

// Config is the lookup the settings make: the snmp.Config for sysName
// reads, or why there is none (a fragment that ends in the command that
// fixes it; setter is the verb family, "tacctl config snmp" or "tacctl scope
// snmp <scope>").
func (e Effective) Config(setter string) (snmp.Config, string) {
	c := snmp.Config{Version: e.Version, Port: e.Port, Retries: 1}
	c.Timeout = time.Duration(e.Timeout) * time.Second
	switch c.Version {
	case "":
		return c, "SNMP is not configured ('" + setter + "')"
	case snmp.V2c, snmp.V3:
	default:
		return c, "snmp.version '" + c.Version + "' is not v2c or v3 ('" + setter + " version v2c|v3')"
	}
	if c.Version == snmp.V2c {
		if e.Community == "" {
			return c, "no SNMP community is set ('" + setter + " community')"
		}
		c.Community = e.Community
		return c, ""
	}
	if e.V3Problem != "" {
		return c, e.V3Problem
	}
	if !e.HasV3() {
		return c, "no SNMPv3 user is the default ('" + setter + " v3-user default <user>')"
	}
	c.User, c.AuthPass, c.PrivPass = e.User, e.AuthPass, e.PrivPass
	c.Auth, c.Priv = e.Auth, e.Priv
	return c, ""
}
