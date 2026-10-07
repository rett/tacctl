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
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Header starts snmp.yaml.
const Header = "# tacctl SNMP credentials (the sysName name hint of 'tacctl device add'). Secret: 0600, never printed.\n" +
	"# Edit with 'tacctl config snmp community|v3-user|clear'.\n"

// Version is the format of snmp.yaml.
const Version = 1

// Creds are the v2c community and the v3 user with its passphrases; empty
// is not set.
type Creds struct {
	Community string
	User      string
	AuthPass  string
	PrivPass  string
}

// Empty reports whether nothing is set.
func (c Creds) Empty() bool { return c == Creds{} }

// HasV3 reports whether the v3 user and both passphrases are set.
func (c Creds) HasV3() bool { return c.User != "" && c.AuthPass != "" && c.PrivPass != "" }

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
	str := func(key string, val any) (string, error) {
		s, ok := val.(string)
		if !ok && val != nil {
			return "", errors.New(key + " must be text")
		}
		return s, nil
	}
	for k, val := range root.All() {
		switch k {
		case "version":
			if n, ok := val.(int); !ok || n != Version {
				return c, errors.New("unsupported version (this tacctl reads version " + strconv.Itoa(Version) + ")")
			}
		case "community":
			if c.Community, err = str(k, val); err != nil {
				return c, err
			}
		case "v3":
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return c, errors.New("v3 must be a mapping (user, auth_passphrase, priv_passphrase)")
			}
			for k3, v3 := range m.All() {
				var dst *string
				switch k3 {
				case "user":
					dst = &c.User
				case "auth_passphrase":
					dst = &c.AuthPass
				case "priv_passphrase":
					dst = &c.PrivPass
				default:
					return c, errors.New("unknown key 'v3." + k3 + "'")
				}
				if *dst, err = str("v3."+k3, v3); err != nil {
					return c, err
				}
			}
		default:
			return c, errors.New("unknown key '" + k + "'")
		}
	}
	return c, nil
}

// Text is the file as it is written, read back with the reader it is read
// with.
func (c Creds) Text() ([]byte, error) {
	doc := yamlpy.NewMap("version", Version)
	if c.Community != "" {
		doc.Set("community", c.Community)
	}
	if c.User != "" || c.AuthPass != "" || c.PrivPass != "" {
		doc.Set("v3", yamlpy.NewMap("user", c.User, "auth_passphrase", c.AuthPass, "priv_passphrase", c.PrivPass))
	}
	out, err := yamlpy.EmitChecked(doc, yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the SNMP credentials (a character YAML cannot hold?); nothing was written")
	}
	return out, nil
}

// Save writes c to path (0600); no credentials at all removes the file.
func Save(path string, c Creds) error {
	if c.Empty() {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail("Cannot remove " + path + ": " + errText(err))
		}
		return nil
	}
	text, err := c.Text()
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
