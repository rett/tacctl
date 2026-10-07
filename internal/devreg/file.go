package devreg

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Header starts devices.yaml.
const Header = "# tacctl device registry: names for the devices and hosts that authenticate here.\n" +
	"# Edit with 'tacctl device ...'. Scope and activity are not stored; they are looked up.\n"

// LockName is the lock file beside devices.yaml.
const LockName = ".devices.lock"

// Version is the format of devices.yaml.
const Version = 1

// File is the registry: devices.yaml, version 1. An absent file is an
// empty registry.
type File struct {
	StaleDays    int
	GenericNames []string
	Devices      []*Device
	// Hosts are what tacctl records of enrolled hosts ('hosts:'), by host
	// name: the address and the pinned host keys. linux-hosts itself is
	// never written here (host enroll and sync record and pin).
	Hosts []HostPin
}

// HostPin is the record of one enrolled host: the address its enrolment
// or last sync reached, the address before that when it changed (and
// when), its pinned keys and its acknowledged notices.
type HostPin struct {
	Name string
	Keys []string
	// Address is the host's address as 'host enroll'/'host sync' saw it
	// (normalized); PrevAddress and Changed ('2006-01-02 15:04') are set
	// when a sync found another one (the address-changed notice).
	Address, PrevAddress, Changed string
	Ack                           []string
}

func (h HostPin) clone() HostPin {
	c := h
	c.Keys, c.Ack = slices.Clone(h.Keys), slices.Clone(h.Ack)
	return c
}

func (h HostPin) empty() bool { return len(h.Keys) == 0 && h.Address == "" }

// Host is the record of the enrolled host name (nil when there is none).
func (f *File) Host(name string) *HostPin {
	for i := range f.Hosts {
		if strings.EqualFold(f.Hosts[i].Name, name) {
			return &f.Hosts[i]
		}
	}
	return nil
}

// host is the record of name, created when there is none.
func (f *File) host(name string) *HostPin {
	if h := f.Host(name); h != nil {
		return h
	}
	f.Hosts = append(f.Hosts, HostPin{Name: name})
	slices.SortFunc(f.Hosts, func(a, b HostPin) int { return strings.Compare(a.Name, b.Name) })
	return f.Host(name)
}

// tidyHosts drops records that hold nothing.
func (f *File) tidyHosts() {
	f.Hosts = slices.DeleteFunc(f.Hosts, func(h HostPin) bool { return h.empty() })
}

// HostKeysOf are the keys pinned for the enrolled host name.
func (f *File) HostKeysOf(name string) []string {
	if h := f.Host(name); h != nil {
		return slices.Clone(h.Keys)
	}
	return nil
}

// SetHostKeys pins keys for the enrolled host name; no keys unpins it.
func (f *File) SetHostKeys(name string, keys []string) {
	f.host(name).Keys = slices.Clone(keys)
	f.tidyHosts()
}

// HostAddressOf is the address recorded for the enrolled host name.
func (f *File) HostAddressOf(name string) string {
	if h := f.Host(name); h != nil {
		return h.Address
	}
	return ""
}

// SetHostAddress records address (normalized by the caller) for the
// enrolled host name. A different address than the recorded one keeps the
// old one as PrevAddress with the time of the change (at) and reopens the
// address-changed notice; it reports the address it replaced ("" when
// there was none or it is the same).
func (f *File) SetHostAddress(name, address, at string) (previous string) {
	h := f.host(name)
	if h.Address != "" && h.Address != address {
		previous = h.Address
		h.PrevAddress, h.Changed = h.Address, at
		h.Ack = slices.DeleteFunc(h.Ack, func(k string) bool { return k == NoticeAddressChanged })
	}
	h.Address = address
	return previous
}

// ForgetHost drops everything recorded of the enrolled host name.
func (f *File) ForgetHost(name string) {
	f.Hosts = slices.DeleteFunc(f.Hosts, func(h HostPin) bool { return strings.EqualFold(h.Name, name) })
}

// Empty is a registry with no device.
func Empty() *File { return &File{StaleDays: DefaultStaleDays} }

// Clone is a deep copy.
func (f *File) Clone() *File {
	c := &File{StaleDays: f.StaleDays, GenericNames: slices.Clone(f.GenericNames)}
	for _, d := range f.Devices {
		dc := d.Clone()
		c.Devices = append(c.Devices, &dc)
	}
	for _, h := range f.Hosts {
		c.Hosts = append(c.Hosts, h.clone())
	}
	return c
}

// Find is the device called name, compared case-insensitively.
func (f *File) Find(name string) *Device {
	for _, d := range f.Devices {
		if strings.EqualFold(d.Name, name) {
			return d
		}
	}
	return nil
}

// FindAddress is the device registered at address (any spelling of it).
func (f *File) FindAddress(address string) *Device {
	a, err := NormalizeAddress(address)
	if err != nil {
		return nil
	}
	for _, d := range f.Devices {
		if d.Address == a {
			return d
		}
	}
	return nil
}

// Remove drops the device called name; it reports whether there was one.
func (f *File) Remove(name string) bool {
	for i, d := range f.Devices {
		if strings.EqualFold(d.Name, name) {
			f.Devices = slices.Delete(f.Devices, i, i+1)
			return true
		}
	}
	return false
}

// validate is the invariants of a registry: every device valid, names
// unique case-insensitively, addresses unique, the settings in range, the
// generic patterns compilable.
func (f *File) validate() error {
	if f.StaleDays < 1 || f.StaleDays > MaxStaleDays {
		return fail("settings.stale_days must be 1-" + strconv.Itoa(MaxStaleDays) + ".")
	}
	for _, p := range f.GenericNames {
		if _, err := regexp.Compile(p); err != nil || p == "" {
			return fail("generic_names: '" + p + "' is not a valid pattern.")
		}
	}
	names, addrs := map[string]bool{}, map[string]string{}
	for _, d := range f.Devices {
		if err := d.validate(); err != nil {
			return fail("device '" + d.Name + "': " + strings.Join(msgs(err), " "))
		}
		if lc := strings.ToLower(d.Name); names[lc] {
			return fail("device '" + d.Name + "' is registered twice (names are compared case-insensitively).")
		} else {
			names[lc] = true
		}
		if other, dup := addrs[d.Address]; dup {
			return fail(d.Address + " is registered as both '" + other + "' and '" + d.Name + "'.")
		}
		addrs[d.Address] = d.Name
	}
	hostNames := map[string]bool{}
	for _, h := range f.Hosts {
		if !reHostEntry.MatchString(h.Name) || hostNames[strings.ToLower(h.Name)] {
			return fail("hosts: invalid or repeated host name '" + h.Name + "'.")
		}
		hostNames[strings.ToLower(h.Name)] = true
		if h.empty() {
			return fail("hosts: '" + h.Name + "' has neither an address nor host_keys.")
		}
		for _, a := range []string{h.Address, h.PrevAddress} {
			if n, err := NormalizeAddress(a); a != "" && (err != nil || n != a) {
				return fail("hosts: '" + h.Name + "': invalid address '" + a + "'.")
			}
		}
		for _, k := range h.Ack {
			if !slices.Contains(HostAckableKinds, k) {
				return fail("hosts: '" + h.Name + "': ack: '" + k + "' cannot be acknowledged for an enrolled host.")
			}
		}
		for _, k := range h.Keys {
			if _, err := ParseHostKey(k); err != nil {
				return fail("hosts: '" + h.Name + "': " + strings.Join(msgs(err), " "))
			}
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

// Load reads the registry at path; a missing file is an empty registry.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Empty(), nil
	case err != nil:
		return nil, fail("Cannot read " + path + ": " + errText(err))
	}
	f, err := parse(data)
	if err != nil {
		return nil, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	return f, nil
}

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func parse(data []byte) (*File, error) {
	v, err := pyyaml.LoadBytes(data)
	if err != nil {
		return nil, fail("not valid YAML: " + firstLine(err.Error()))
	}
	f := Empty()
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
		case "settings":
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("settings must be a mapping.")
			}
			for sk, sv := range m.All() {
				n, isInt := sv.(int)
				if sk != "stale_days" || !isInt {
					return nil, fail("settings: unknown or invalid key '" + sk + "'.")
				}
				f.StaleDays = n
			}
		case "generic_names":
			l, ok := strList(val)
			if !ok {
				return nil, fail("generic_names must be a list of patterns.")
			}
			f.GenericNames = l
		case "devices":
			if val == nil {
				continue
			}
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("devices must be a mapping of name to entry.")
			}
			for name, dv := range m.All() {
				d, err := parseDevice(name, dv)
				if err != nil {
					return nil, err
				}
				f.Devices = append(f.Devices, d)
			}
		case "hosts":
			if val == nil {
				continue
			}
			m, ok := val.(*yamlpy.Map)
			if !ok {
				return nil, fail("hosts must be a mapping of host name to entry.")
			}
			for name, hv := range m.All() {
				hm, ok := hv.(*yamlpy.Map)
				if !ok {
					return nil, fail("hosts: '" + name + "' must be a mapping.")
				}
				pin := HostPin{Name: name}
				for hk, kv := range hm.All() {
					bad := fail("hosts: '" + name + "': unknown or invalid key '" + hk + "'.")
					switch hk {
					case "host_keys", "ack":
						l, ok := strList(kv)
						if !ok {
							return nil, bad
						}
						*map[string]*[]string{"host_keys": &pin.Keys, "ack": &pin.Ack}[hk] = l
					case "address", "previous_address", "address_changed":
						v, ok := kv.(string)
						if !ok {
							return nil, bad
						}
						*map[string]*string{"address": &pin.Address, "previous_address": &pin.PrevAddress, "address_changed": &pin.Changed}[hk] = v
					default:
						return nil, bad
					}
				}
				f.Hosts = append(f.Hosts, pin)
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

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func strList(v any) ([]string, bool) {
	switch x := v.(type) {
	case nil:
		return nil, true
	case []any:
		var out []string
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func parseDevice(name string, v any) (*Device, error) {
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil, fail("device '" + name + "' must be a mapping.")
	}
	d := &Device{Name: name, Vendor: VendorOther}
	bad := func(key string) error { return fail("device '" + name + "': invalid '" + key + "'.") }
	for k, val := range m.All() {
		switch k {
		case "address", "vendor", "hostname", "description":
			s, ok := val.(string)
			if !ok {
				return nil, bad(k)
			}
			*map[string]*string{"address": &d.Address, "vendor": &d.Vendor, "hostname": &d.Hostname,
				"description": &d.Description}[k] = s
		case "port":
			n, ok := val.(int)
			if !ok {
				return nil, bad(k)
			}
			d.Port = n
		case "legacy_ssh":
			b, ok := val.(bool)
			if !ok {
				return nil, bad(k)
			}
			d.LegacySSH = b
		case "host_keys", "ack":
			l, ok := strList(val)
			if !ok {
				return nil, bad(k)
			}
			if k == "ack" {
				d.Ack = l
			} else {
				d.HostKeys = l
			}
		default:
			return nil, fail("device '" + name + "': unknown key '" + k + "'.")
		}
	}
	if d.Address == "" {
		return nil, fail("device '" + name + "': the address is required.")
	}
	return d, nil
}

// doc is the file as a value for the emitter.
func (f *File) doc() *yamlpy.Map {
	devs := yamlpy.NewMap()
	for _, d := range f.Devices {
		m := yamlpy.NewMap("address", d.Address, "vendor", d.Vendor)
		if d.Hostname != "" {
			m.Set("hostname", d.Hostname)
		}
		if d.Port != 0 {
			m.Set("port", d.Port)
		}
		if d.LegacySSH {
			m.Set("legacy_ssh", true)
		}
		if d.Description != "" {
			m.Set("description", d.Description)
		}
		if len(d.HostKeys) > 0 {
			m.Set("host_keys", slices.Clone(d.HostKeys))
		}
		if len(d.Ack) > 0 {
			m.Set("ack", slices.Clone(d.Ack))
		}
		devs.Set(d.Name, m)
	}
	root := yamlpy.NewMap("version", Version, "settings", yamlpy.NewMap("stale_days", f.StaleDays))
	if len(f.GenericNames) > 0 {
		root.Set("generic_names", slices.Clone(f.GenericNames))
	}
	root.Set("devices", devs)
	if len(f.Hosts) > 0 {
		hs := yamlpy.NewMap()
		for _, h := range f.Hosts {
			m := yamlpy.NewMap()
			if h.Address != "" {
				m.Set("address", h.Address)
			}
			if h.PrevAddress != "" {
				m.Set("previous_address", h.PrevAddress)
			}
			if h.Changed != "" {
				m.Set("address_changed", h.Changed)
			}
			if len(h.Keys) > 0 {
				m.Set("host_keys", slices.Clone(h.Keys))
			}
			if len(h.Ack) > 0 {
				m.Set("ack", slices.Clone(h.Ack))
			}
			hs.Set(h.Name, m)
		}
		root.Set("hosts", hs)
	}
	return root
}

// Text is the file as it is written: the header and the YAML, checked by
// reading it back with the reader the registry is read with.
func (f *File) Text() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	out, err := yamlpy.EmitChecked(f.doc(), yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the device registry (" + firstLine(err.Error()) + "); nothing was written")
	}
	return out, nil
}

// Lock takes the registry's exclusive lock (<dir>/.devices.lock, 0600) and
// returns the function that releases it.
func Lock(path string) (unlock func(), err error) {
	d := filepath.Dir(path)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, fail("Cannot create " + d + ": " + errText(err))
	}
	lf, err := os.OpenFile(filepath.Join(d, LockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fail("Cannot open the registry lock: " + errText(err))
	}
	for {
		err = unix.Flock(int(lf.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lf.Close()
		return nil, fail("Cannot lock the device registry: " + err.Error())
	}
	return func() { _ = lf.Close() }, nil
}

// Mutate changes the registry under its lock: before runs first (a
// snapshot; an error stops the write), then the file is loaded, fn changes
// it, and the result is validated, rendered, read back and written through
// a temporary file (0600, fsync, rename). Nothing is written when fn or the
// validation fails, or when the bytes would not change. changed reports
// whether the file was replaced. knownHosts, when set, is the generated
// known_hosts (knownhosts.go): it is brought up to date under the same
// lock after every Mutate, so it always lists exactly the pinned keys.
func Mutate(path, knownHosts string, before func() error, fn func(*File) error) (changed bool, err error) {
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
	if knownHosts != "" {
		if err := WriteKnownHosts(knownHosts, f); err != nil {
			return changed, err
		}
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
