package devconf

// The per-device record store (plan D65):
//
//	<VarLib>/devices-config.json      root 0600, version 1, one record per
//	                                  device keyed by its lower-case name
//	<VarLib>/device-config/<name>.yaml  0600, the extracted sections' text of
//	                                  the last successful pull
//
// The raw configuration is never kept, and neither is a secret's value: the
// sections file holds the statements in their compared form (Normalise),
// with a secret's value elided, so nothing in it can be read back (M1).
// Both files are derived from the devices, rebuildable by a pull, and never snapshotted (backup ignores
// them as it ignores the seen cache). The pattern is the seen cache's
// (devreg/seen.go): JSON, an flock lock file beside it, an atomic write,
// paths.MkVarLib.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// RecordsVersion is the format of devices-config.json and of the sections
// files.
const RecordsVersion = 1

// LockName is the lock file beside the records file.
const LockName = ".devices-config.lock"

// SectionsHeader heads every sections file.
const SectionsHeader = "# tacctl: the managed sections of the last pull of this device, one statement per\n" +
	"# line in the form they are compared in (a secret's value is elided). Derived;\n" +
	"# 'tacctl device config pull' rebuilds it. Root only.\n"

// The Result of a pull (D65).
const (
	ResultOK              = "ok"
	ResultAuthFailed      = "auth-failed"
	ResultUnreachable     = "unreachable"
	ResultTimeout         = "timeout"
	ResultHostKeyMismatch = "host-key-mismatch"
	ResultUnsupported     = "unsupported"
	ResultParseFailed     = "parse-failed"
	ResultInterrupted     = "interrupted"
)

// SectionRecord is what a pull kept of one section: the SHA-256 of the
// device's text (Fingerprint) and the state of the last comparison.
type SectionRecord struct {
	SHA256 string `json:"sha256,omitempty"`
	State  string `json:"state,omitempty"`
}

// Applied is reserved for 0.2.5's apply: nothing writes it in 0.2.4.
type Applied struct {
	At          time.Time `json:"at,omitzero"`
	By          string    `json:"by,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Result      string    `json:"result,omitempty"`
}

// Record is one device's record.
type Record struct {
	Address string `json:"address,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	// Transport is the one the last pull used: netconf or ssh.
	Transport string `json:"transport,omitempty"`
	// Netconf is the last probe's result ("hello ok", "port closed", "no
	// hello", "not probed") and NetconfAt when it was made.
	Netconf   string    `json:"netconf,omitempty"`
	NetconfAt time.Time `json:"netconf_at,omitzero"`
	Pulled    time.Time `json:"pulled,omitzero"`
	By        string    `json:"by,omitempty"`
	// Result is one of the Result constants.
	Result     string `json:"result,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	// SecretsVisible is whether the login that pulled could see the
	// device's secrets (Extracted.SecretsVisible).
	SecretsVisible bool                     `json:"secrets_visible"`
	Sections       map[string]SectionRecord `json:"sections,omitempty"`
	Applied        *Applied                 `json:"applied,omitempty"`
}

// Records is devices-config.json.
type Records struct {
	Version int       `json:"version"`
	Updated time.Time `json:"updated,omitzero"`
	// Devices are keyed by the device's name in lower case.
	Devices map[string]*Record `json:"devices"`
}

// NewRecords is an empty set.
func NewRecords() *Records {
	return &Records{Version: RecordsVersion, Devices: map[string]*Record{}}
}

// Of is the record of a device.
func (r *Records) Of(name string) (*Record, bool) {
	if r == nil {
		return nil, false
	}
	rec, ok := r.Devices[strings.ToLower(name)]
	return rec, ok && rec != nil
}

// Put stores a device's record (a copy), replacing any.
func (r *Records) Put(name string, rec Record) {
	c := rec
	if rec.Applied != nil {
		a := *rec.Applied
		c.Applied = &a
	}
	if rec.Sections != nil {
		c.Sections = make(map[string]SectionRecord, len(rec.Sections))
		for k, v := range rec.Sections {
			c.Sections[k] = v
		}
	}
	r.Devices[strings.ToLower(name)] = &c
}

// Delete drops a device's record and reports whether there was one.
func (r *Records) Delete(name string) bool {
	k := strings.ToLower(name)
	_, ok := r.Devices[k]
	delete(r.Devices, k)
	return ok
}

// Rename moves a record to a new name. The new name must have none.
func (r *Records) Rename(oldName, newName string) error {
	o, n := strings.ToLower(oldName), strings.ToLower(newName)
	rec, ok := r.Devices[o]
	if !ok {
		return nil
	}
	if o == n {
		return nil
	}
	if _, taken := r.Devices[n]; taken {
		return fail("Cannot move the configuration record of '" + oldName + "': '" + newName + "' has one.")
	}
	r.Devices[n] = rec
	delete(r.Devices, o)
	return nil
}

// Names are the device names that have a record, sorted.
func (r *Records) Names() []string {
	out := make([]string, 0, len(r.Devices))
	for n := range r.Devices {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Store is the record store's two locations.
type Store struct {
	// Records is the path of devices-config.json.
	Records string
	// Dir is the directory of the sections files (device-config).
	Dir string
}

func fail(lines ...string) error { return &names.Error{Msgs: lines} }

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Load reads the records; an absent file is an empty set. A file that is
// not one of this tacctl is an error alongside an empty set: a pull
// rebuilds it.
func (s Store) Load() (*Records, error) {
	data, err := os.ReadFile(s.Records)
	if errors.Is(err, fs.ErrNotExist) {
		return NewRecords(), nil
	}
	if err != nil {
		return NewRecords(), fail("Cannot read " + s.Records + ": " + errText(err))
	}
	r := NewRecords()
	if err := json.Unmarshal(data, r); err != nil || r.Version != RecordsVersion {
		return NewRecords(), fail(s.Records + " is not a device configuration record file of this tacctl; 'tacctl device config pull' rebuilds it.")
	}
	if r.Devices == nil {
		r.Devices = map[string]*Record{}
	}
	for k, v := range r.Devices {
		if v == nil {
			delete(r.Devices, k)
		}
	}
	return r, nil
}

// Save writes the records (0600, through a temporary file). Updated is the
// caller's business: this package reads no clock.
func (s Store) Save(r *Records) error {
	if err := paths.MkVarLib(filepath.Dir(s.Records)); err != nil {
		return fail("Cannot create " + filepath.Dir(s.Records) + ": " + errText(err))
	}
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	return atomicWrite(s.Records, append(data, '\n'), 0o600)
}

// Lock takes the store's exclusive lock and returns its release. Writers
// hold it across Load and Save; the sections files are written under it
// too.
func (s Store) Lock() (unlock func(), err error) {
	d := filepath.Dir(s.Records)
	if err := paths.MkVarLib(d); err != nil {
		return nil, fail("Cannot create " + d + ": " + errText(err))
	}
	lf, err := os.OpenFile(filepath.Join(d, LockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fail("Cannot open the device configuration lock: " + errText(err))
	}
	for {
		err = unix.Flock(int(lf.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lf.Close()
		return nil, fail("Cannot lock the device configuration records: " + err.Error())
	}
	return func() { _ = lf.Close() }, nil
}

// sectionsPath is the sections file of a device.
func (s Store) sectionsPath(name string) (string, error) {
	n := strings.ToLower(name)
	if n == "" || n == "." || n == ".." || strings.HasPrefix(n, ".") || strings.ContainsAny(n, "/\\\x00") {
		return "", fail("'" + name + "' is not a device name.")
	}
	return filepath.Join(s.Dir, n+".yaml"), nil
}

// SaveSections writes a device's sections file (0600): one key per section,
// the statements as a literal block, in their compared form (Normalise
// elides every secret's value whatever the caller hands in). The mode of
// the directory is 0700.
func (s Store) SaveSections(name, vendor string, secs map[string]devices.Section) error {
	p, err := s.sectionsPath(name)
	if err != nil {
		return err
	}
	norm := make(map[string]devices.Section, len(secs))
	for k, v := range secs {
		n, err := Normalise(vendor, v)
		if err != nil {
			return err
		}
		norm[k] = n
	}
	secs = norm
	if err := paths.MkVarLib(filepath.Dir(s.Dir)); err != nil {
		return fail("Cannot create " + filepath.Dir(s.Dir) + ": " + errText(err))
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fail("Cannot create " + s.Dir + ": " + errText(err))
	}
	if st, err := os.Stat(s.Dir); err == nil && st.Mode().Perm() != 0o700 {
		if err := os.Chmod(s.Dir, 0o700); err != nil {
			return fail("Cannot protect " + s.Dir + ": " + errText(err))
		}
	}
	var b strings.Builder
	b.WriteString(SectionsHeader)
	b.WriteString("version: 1\n")
	keys := slices.Clone(SectionNames)
	for k := range secs {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys[len(SectionNames):])
	for _, k := range keys {
		sec, ok := secs[k]
		if !ok {
			continue
		}
		if len(sec.Lines) == 0 {
			b.WriteString(k + ": \"\"\n")
			continue
		}
		b.WriteString(k + ": |\n")
		for _, l := range sec.Lines {
			b.WriteString("  " + scrub(strings.TrimLeft(l, " ")) + "\n")
		}
	}
	return atomicWrite(p, []byte(b.String()), 0o600)
}

// Sections reads a device's sections file. An absent file is (nil, nil). A
// file that cannot be read as one is an error (a pull rewrites it). Secret
// is set for the statements the family's rules take as secrets, so the
// result can be printed with Normalise.
func (s Store) Sections(name, vendor string) (map[string]devices.Section, error) {
	p, err := s.sectionsPath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fail("Cannot read " + p + ": " + errText(err))
	}
	v, err := pyyaml.LoadBytes(data)
	root, ok := v.(*yamlpy.Map)
	if err != nil || !ok {
		return nil, fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
	}
	fam, famErr := Family(vendor)
	out := map[string]devices.Section{}
	haveVersion := false
	for k, val := range root.All() {
		if k == "version" {
			if n, ok := val.(int); !ok || n != RecordsVersion {
				return nil, fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
			}
			haveVersion = true
			continue
		}
		text, ok := val.(string)
		if !ok {
			return nil, fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
		}
		sec := devices.Section{Name: k}
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				sec.Lines = append(sec.Lines, l)
			}
		}
		if famErr == nil {
			sec = toSection(k, uniq(canonFor(fam)(sec.Lines, nil)))
		}
		out[k] = sec
	}
	if !haveVersion {
		return nil, fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
	}
	return out, nil
}

// Forget removes a device's record and sections file under the lock, and
// reports whether it had either.
func (s Store) Forget(name string) (bool, error) {
	unlock, err := s.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	r, err := s.Load()
	if err != nil {
		// A corrupt file: there is nothing to forget in it, and the
		// sections file goes all the same.
		r = NewRecords()
	}
	had := r.Delete(name)
	if had {
		if err := s.Save(r); err != nil {
			return had, err
		}
	}
	p, err := s.sectionsPath(name)
	if err != nil {
		return had, err
	}
	switch err := os.Remove(p); {
	case err == nil:
		had = true
	case !errors.Is(err, fs.ErrNotExist):
		return had, fail("Cannot remove " + p + ": " + errText(err))
	}
	return had, nil
}

// ForgetAll removes every record and sections file and returns how many
// devices had one.
func (s Store) ForgetAll() (int, error) {
	unlock, err := s.Lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	r, _ := s.Load()
	seen := map[string]bool{}
	for n := range r.Devices {
		seen[n] = true
	}
	if ents, err := os.ReadDir(s.Dir); err == nil {
		for _, e := range ents {
			if n, ok := strings.CutSuffix(e.Name(), ".yaml"); ok && !e.IsDir() {
				seen[n] = true
				if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return 0, fail("Cannot remove " + filepath.Join(s.Dir, e.Name()) + ": " + errText(err))
				}
			}
		}
	}
	r.Devices = map[string]*Record{}
	if err := s.Save(r); err != nil {
		return 0, err
	}
	return len(seen), nil
}

// Rename carries a device's record and sections file to its new name, under
// the lock (device rename). It refuses to replace a record or a sections
// file the new name already has, and returns what it cannot read.
func (s Store) Rename(oldName, newName string) error {
	from, err := s.sectionsPath(oldName)
	if err != nil {
		return err
	}
	to, err := s.sectionsPath(newName)
	if err != nil {
		return err
	}
	unlock, err := s.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.Load()
	if err != nil {
		return err
	}
	if from != to {
		if _, err := os.Stat(to); err == nil {
			if _, had := r.Of(oldName); had || fileExists(from) {
				return fail("Cannot move the configuration record of '" + oldName + "': '" + newName + "' has one.")
			}
		}
	}
	if err := r.Rename(oldName, newName); err != nil {
		return err
	}
	if err := s.Save(r); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot move " + from + ": " + errText(err))
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// atomicWrite writes data to path through a temporary file in its
// directory, with mode.
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
