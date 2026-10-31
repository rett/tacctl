// Package snmpcred is StateDir/snmp.yaml (docs/plans/0.2.2-plan.md 5.10):
// the SNMP credentials 'device add' and 'device check' read sysName with,
// kept apart from tacctl.yaml (which holds only snmp.version, port, timeout
// and the v3 protocols) because they are a credential for every device.
// The file is root's, 0600, written through a temporary file (fsync,
// rename) after its text has been read back; tacctl never prints what it
// holds.
package snmpcred

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Header starts snmp.yaml.
const Header = "# tacctl SNMP credentials (the sysName name hint of 'tacctl device add'). Secret: 0600, never printed.\n" +
	"# Edit with 'tacctl config snmp community|v3-user|clear'.\n"

// Version is the format of the files this release writes: the v2c community
// and a pool of v3 users with a default user (D305 of docs/plans/0.2.23-
// plan.md). LegacyVersion is the format of 0.2.2 to 0.2.22, one v3 user with
// its passphrases: it loads as a pool of one user that is the default, and is
// written as Version on the next change (nothing rewrites it at the upgrade).
const (
	Version       = 2
	LegacyVersion = 1
)

// User is one SNMPv3 user of a pool: its name and the two passphrases of
// authPriv. The protocols are the level's (Layer.Auth and Layer.Priv).
type User struct {
	Name     string
	AuthPass string
	PrivPass string
}

// Complete reports whether both passphrases are set.
func (u User) Complete() bool { return u.AuthPass != "" && u.PrivPass != "" }

// Creds are the v2c community and the pool of v3 users of one level with the
// default user; empty is not set. Default names a user of this level's pool,
// and for a device also a user of its scope's pool or the default level's
// (ResolveDevice); it is "" for none.
type Creds struct {
	Community string
	Users     []User
	Default   string
	// Format is the version of the file Load read (0 for credentials that
	// were not read from a file): LegacyVersion or Version.
	Format int
}

// Empty reports whether nothing is set.
func (c Creds) Empty() bool { return c.Community == "" && len(c.Users) == 0 && c.Default == "" }

// Find is the user of the pool called name.
func (c Creds) Find(name string) (User, bool) {
	for _, u := range c.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

// Put adds the user to the pool, or replaces the one of its name (its place
// in the pool stays).
func (c *Creds) Put(u User) {
	c.Users = slices.Clone(c.Users)
	for i := range c.Users {
		if c.Users[i].Name == u.Name {
			c.Users[i] = u
			return
		}
	}
	c.Users = append(c.Users, u)
}

// Drop removes the user from the pool and says whether it was there. A
// default that names it is cleared.
func (c *Creds) Drop(name string) bool {
	for i := range c.Users {
		if c.Users[i].Name == name {
			c.Users = slices.Delete(slices.Clone(c.Users), i, i+1)
			if c.Default == name {
				c.Default = ""
			}
			return true
		}
	}
	return false
}

// Names are the users' names, in the order of the pool.
func (c Creds) Names() []string {
	out := make([]string, len(c.Users))
	for i, u := range c.Users {
		out[i] = u.Name
	}
	return out
}

func fail(lines ...string) error { return &names.Error{Msgs: lines} }

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Load reads the file at path; a missing file is no credentials.
func Load(path string) (Creds, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Creds{}, nil
	case err != nil:
		return Creds{}, fail("Cannot read " + path + ": " + errText(err))
	}
	c, err := parse(data)
	if err != nil {
		return Creds{}, fail(path + ": " + err.Error())
	}
	return c, nil
}

func parse(data []byte) (Creds, error) {
	var c Creds
	v, err := pyyaml.LoadBytes(data)
	if err != nil {
		first, _, _ := strings.Cut(err.Error(), "\n")
		return c, errors.New("not valid YAML: " + first)
	}
	if v == nil {
		return c, nil
	}
	root, ok := v.(*yamlpy.Map)
	if !ok {
		return c, errors.New("expected a mapping at the top level")
	}
	// The format first: version 1 has the key v3 and version 2 has users and
	// default, and a key of the other is as unknown as any other.
	format := 0
	if val, ok := root.Get("version"); ok {
		n, isInt := val.(int)
		if !isInt || (n != Version && n != LegacyVersion) {
			return c, errors.New("unsupported version (this tacctl reads versions " + strconv.Itoa(LegacyVersion) + " and " + strconv.Itoa(Version) + ")")
		}
		format = n
	}
	str := func(key string, val any) (string, error) {
		s, ok := val.(string)
		if !ok && val != nil {
			return "", errors.New(key + " must be text")
		}
		return s, nil
	}
	for k, val := range root.All() {
		switch {
		case k == "version":
		case k == "community":
			if c.Community, err = str(k, val); err != nil {
				return c, err
			}
		case k == "v3" && format != Version:
			u, err := parseLegacyV3(val)
			if err != nil {
				return c, err
			}
			if u.Name != "" {
				c.Users, c.Default = []User{u}, u.Name
			}
		case k == "users" && format == Version:
			if c.Users, err = parseUsers(val); err != nil {
				return c, err
			}
		case k == "default" && format == Version:
			if c.Default, err = str(k, val); err != nil {
				return c, err
			}
		default:
			return c, errors.New("unknown key '" + k + "'")
		}
	}
	c.Format = format
	return c, nil
}

// parseLegacyV3 is the v3 mapping of a version 1 file: one user. Passphrases
// with no user name belong to nobody and are not carried.
func parseLegacyV3(val any) (User, error) {
	var u User
	m, ok := val.(*yamlpy.Map)
	if !ok {
		return u, errors.New("v3 must be a mapping (user, auth_passphrase, priv_passphrase)")
	}
	for k, v := range m.All() {
		var dst *string
		switch k {
		case "user":
			dst = &u.Name
		case "auth_passphrase":
			dst = &u.AuthPass
		case "priv_passphrase":
			dst = &u.PrivPass
		default:
			return u, errors.New("unknown key 'v3." + k + "'")
		}
		s, ok := v.(string)
		if !ok && v != nil {
			return u, errors.New("v3." + k + " must be text")
		}
		*dst = s
	}
	return u, nil
}

// parseUsers is the users list of a version 2 file: a name and the two
// passphrases each, the names unique.
func parseUsers(val any) ([]User, error) {
	if val == nil {
		return nil, nil
	}
	list, ok := val.([]any)
	if !ok {
		return nil, errors.New("users must be a list (name, auth_passphrase, priv_passphrase)")
	}
	var out []User
	for i, item := range list {
		m, ok := item.(*yamlpy.Map)
		if !ok {
			return nil, errors.New("users[" + strconv.Itoa(i) + "] must be a mapping (name, auth_passphrase, priv_passphrase)")
		}
		var u User
		for k, v := range m.All() {
			var dst *string
			switch k {
			case "name":
				dst = &u.Name
			case "auth_passphrase":
				dst = &u.AuthPass
			case "priv_passphrase":
				dst = &u.PrivPass
			default:
				return nil, errors.New("unknown key 'users[" + strconv.Itoa(i) + "]." + k + "'")
			}
			s, ok := v.(string)
			if !ok && v != nil {
				return nil, errors.New("users[" + strconv.Itoa(i) + "]." + k + " must be text")
			}
			*dst = s
		}
		if u.Name == "" {
			return nil, errors.New("users[" + strconv.Itoa(i) + "] has no name")
		}
		for _, o := range out {
			if o.Name == u.Name {
				return nil, errors.New("the user '" + u.Name + "' is listed twice")
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// FitsLegacy reports whether version 1 (0.2.22 and before) can hold c: the
// community and at most one v3 user, that user being the default. A second
// user, a user that is not the default and a default that names no user of
// the file (another level's) need version 2.
func (c Creds) FitsLegacy() bool {
	switch len(c.Users) {
	case 0:
		return c.Default == ""
	case 1:
		return c.Default == c.Users[0].Name
	}
	return false
}

// Text is the file as it is written, read back with the reader it is read
// with: version 1 when it fits (FitsLegacy), else version 2. This is the one
// place that chooses the format of a file a command writes: a file that the
// older releases can read stays one they read, and only what they cannot hold
// is written in the form they refuse.
func (c Creds) Text() ([]byte, error) { return c.textWith(Header, false) }

// textWith is Text under the given header; needV2 forces version 2 (a
// device's file that counts without an snmp: entry in devices.yaml: the older
// releases ignore a version 1 file there, so it must not be one).
func (c Creds) textWith(header string, needV2 bool) ([]byte, error) {
	if c.FitsLegacy() && !needV2 {
		return c.textIn(header, LegacyVersion)
	}
	return c.textIn(header, Version)
}

// textIn writes the file in the given format: Version, or LegacyVersion
// (one v3 user: the default's), which the rollback writes for the releases
// before this one.
func (c Creds) textIn(header string, format int) ([]byte, error) {
	doc := yamlpy.NewMap("version", format)
	if c.Community != "" {
		doc.Set("community", c.Community)
	}
	if format == LegacyVersion {
		if u, ok := c.Find(c.Default); ok {
			doc.Set("v3", yamlpy.NewMap("user", u.Name, "auth_passphrase", u.AuthPass, "priv_passphrase", u.PrivPass))
		}
	} else {
		if len(c.Users) > 0 {
			list := make([]any, len(c.Users))
			for i, u := range c.Users {
				list[i] = yamlpy.NewMap("name", u.Name, "auth_passphrase", u.AuthPass, "priv_passphrase", u.PrivPass)
			}
			doc.Set("users", list)
		}
		if c.Default != "" {
			doc.Set("default", c.Default)
		}
	}
	out, err := yamlpy.EmitChecked(doc, yamlpy.StoreOptions, header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the SNMP credentials (a character YAML cannot hold?); nothing was written")
	}
	return out, nil
}

// LegacyText is the file in the format of 0.2.22 and before (version 1): the
// community and the one v3 user that is the default. The rollback writes it
// (internal/lifecycle).
func (c Creds) LegacyText(header string) ([]byte, error) { return c.textIn(header, LegacyVersion) }

// Save writes c to path (0600) in the format Text chooses; no credentials at
// all removes the file.
func Save(path string, c Creds) error { return saveWith(path, c, Header, false) }

// saveWith is Save under the given header; needV2 as in textWith.
func saveWith(path string, c Creds, header string, needV2 bool) error {
	if c.Empty() {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail("Cannot remove " + path + ": " + errText(err))
		}
		return nil
	}
	text, err := c.textWith(header, needV2)
	if err != nil {
		return err
	}
	return atomicWrite(path, text, 0o600)
}

// SaveLegacy writes c to path (0600) in version 1, the format of 0.2.22 and
// before, under the given header: the community and the one v3 user that is
// the default. The rollback writes it.
func SaveLegacy(path string, c Creds, header string) error {
	text, err := c.LegacyText(header)
	if err != nil {
		return err
	}
	return atomicWrite(path, text, 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	d := filepath.Dir(path)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return fail("Cannot create " + d + ": " + errText(err))
	}
	tf, err := os.CreateTemp(d, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fail("Cannot write " + path + ": " + errText(err))
	}
	tmp := tf.Name()
	bad := func(err error) error {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return fail("Cannot write " + path + ": " + errText(err))
	}
	if err := tf.Chmod(mode); err != nil {
		return bad(err)
	}
	if _, err := tf.Write(data); err != nil {
		return bad(err)
	}
	if err := tf.Sync(); err != nil {
		return bad(err)
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
