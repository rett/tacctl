package devconf

// The per-device record store (plan D65):
//
//	<VarLib>/devices-config.json      root 0600, version 1, one record per
//	                                  device keyed by its lower-case name
//	<VarLib>/device-config/<name>.yaml  0600, the extracted sections' text of
//	                                  the last successful pull
//	<VarLib>/device-config/<name>.plain    0600, the plain view of that pull
//	                                  (stamped with its time)
//	<VarLib>/device-config/<name>.backout  0600, the back-out of the last plan
//	                                  that had changes (stamped with the
//	                                  pull it was computed from)
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
	// ResultDenied (0.2.7): a WTI unit's login level cannot configure the
	// unit, so its pages are not shown to it; the level is the login's, not
	// the credentials' (auth-failed).
	ResultDenied = "denied"
)

// SectionRecord is what a pull kept of one section: the SHA-256 of the
// device's text (Fingerprint), the state of the last comparison and the
// number of the device's own statements it found (SectionResult.Unmanaged).
type SectionRecord struct {
	SHA256    string `json:"sha256,omitempty"`
	State     string `json:"state,omitempty"`
	Unmanaged int    `json:"unmanaged,omitempty"`
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
	SecretsVisible bool `json:"secrets_visible"`
	// OS is the image's version line of the last pull of a Cisco device
	// ('show version | include Version', D113) and Syntax the configuration
	// syntax derived from it (SyntaxIOS12 or SyntaxModern); both are empty
	// for a Junos device and for a record made before 0.2.5 or by a pull
	// that read no version line.
	// For a WTI unit OS is the command menu's version ('8.10').
	OS       string                   `json:"os,omitempty"`
	Syntax   string                   `json:"syntax,omitempty"`
	Sections map[string]SectionRecord `json:"sections,omitempty"`
	// Unit is what the last good pull of a WTI unit saw beside its sections;
	// nil for every other vendor and for a record made before 0.2.7.
	Unit    *UnitFacts `json:"unit,omitempty"`
	Applied *Applied   `json:"applied,omitempty"`
}

// UnitFacts are the facts of a WTI unit's pull that are no section: the
// unit's own Site ID, the number of other sessions on the unit when it was
// read (no name is kept) and whether its user directory was read (the
// breakglass section is n/a when not). None of it is a secret.
type UnitFacts struct {
	SiteID        string `json:"site_id,omitempty"`
	OtherSessions int    `json:"other_sessions"`
	UsersRead     bool   `json:"users_read"`
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
	if rec.Unit != nil {
		u := *rec.Unit
		c.Unit = &u
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
	return s.writeSections(p, vendor, secs, "")
}

// plainSuffix ends the file of a device's plain view (Junos: the
// configuration without the groups' inheritance applied, D97). The name
// does not end in '.yaml', so the code that lists the sections files
// (ForgetAll) does not take it for a device.
const plainSuffix = ".plain"

// backoutSuffix ends the file of a device's stored back-out: the back-out of
// the last plan that had changes, as that plan printed it. Like the plain
// view's it does not end in '.yaml'.
const backoutSuffix = ".backout"

// stampKey is the key of a stamp in a plain view's file: the Pulled time of
// the record it belongs to.
const stampKey = "pulled"

// plainPath is the plain view's file of a device.
func (s Store) plainPath(name string) (string, error) {
	p, err := s.sectionsPath(name)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(p, ".yaml") + plainSuffix, nil
}

// SavePlain writes a device's plain view (0600, in the sections file's
// form, a secret's value elided as for any section), stamped with the time of
// the pull it belongs to (the record's Pulled). A nil map removes the file: a
// pull that read no plain view must not leave the last one behind.
func (s Store) SavePlain(name, vendor string, secs map[string]devices.Section, pulled time.Time) error {
	p, err := s.plainPath(name)
	if err != nil {
		return err
	}
	if secs == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail("Cannot remove " + p + ": " + errText(err))
		}
		return nil
	}
	return s.writeSections(p, vendor, secs, pulled.UTC().Format(time.RFC3339Nano))
}

// Plain reads a device's plain view of the pull made at pulled (the record's
// Pulled). An absent file, and one stamped with another pull, is (nil, nil):
// the record has none that belongs to it and the inheritance check is
// skipped (and said); a view of another pull would compare two pulls.
func (s Store) Plain(name, vendor string, pulled time.Time) (map[string]devices.Section, error) {
	p, err := s.plainPath(name)
	if err != nil {
		return nil, err
	}
	secs, stamp, err := s.readSections(p, vendor)
	if err != nil || secs == nil {
		return nil, err
	}
	if t, perr := time.Parse(time.RFC3339Nano, stamp); perr != nil || pulled.IsZero() || !t.Equal(pulled) {
		return nil, nil
	}
	return secs, nil
}

// writeSections writes a sections file at p, with the stamp of a plain view
// ("" for none).
func (s Store) writeSections(p, vendor string, secs map[string]devices.Section, stamp string) error {
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
	if stamp != "" {
		b.WriteString(stampKey + ": \"" + stamp + "\"\n")
	}
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
	secs, _, err := s.readSections(p, vendor)
	return secs, err
}

// readSections reads the sections file at p and the stamp it carries ("" when
// it has none).
func (s Store) readSections(p, vendor string) (map[string]devices.Section, string, error) {
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fail("Cannot read " + p + ": " + errText(err))
	}
	v, err := pyyaml.LoadBytes(data)
	root, ok := v.(*yamlpy.Map)
	if err != nil || !ok {
		return nil, "", fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
	}
	stamp := ""
	fam, famErr := Family(vendor)
	out := map[string]devices.Section{}
	haveVersion := false
	for k, val := range root.All() {
		if k == "version" {
			if n, ok := val.(int); !ok || n != RecordsVersion {
				return nil, "", fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
			}
			haveVersion = true
			continue
		}
		text, ok := val.(string)
		if !ok {
			return nil, "", fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
		}
		if k == stampKey {
			stamp = text
			continue
		}
		sec := devices.Section{Name: k}
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				sec.Lines = append(sec.Lines, l)
			}
		}
		if famErr == nil {
			sec = toSection(k, uniq(canonFor(fam)(sec.Lines, nil, nil)))
		}
		out[k] = sec
	}
	if !haveVersion {
		return nil, "", fail(p + " is not a sections file of this tacctl; 'tacctl device config pull' rebuilds it.")
	}
	return out, stamp, nil
}

// StoredBackout is the back-out of the last plan that had changes, kept
// beside the device's record: the text the plan printed (a secret's value
// elided), the Pulled time of the record it was computed from, the vendor
// (which comment leader its text uses), the address of the device it was
// computed for (a name that moved to another address is another device: the
// back-out is not its own), and the sections it covers.
type StoredBackout struct {
	Pulled time.Time
	Vendor string
	// Address is the device's address when the plan was made.
	Address string
	// Sections are the planned sections the back-out undoes, in plan order.
	Sections []string
	Text     string
}

// backoutPath is the stored back-out's file of a device.
func (s Store) backoutPath(name string) (string, error) {
	p, err := s.sectionsPath(name)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(p, ".yaml") + backoutSuffix, nil
}

// BackoutHeader heads every stored back-out.
const BackoutHeader = "# tacctl: the back-out of the last plan made for this device that had changes, as\n" +
	"# that plan printed it (a secret's value elided). Derived; 'tacctl device config\n" +
	"# plan <name> --backout' prints it. Root only.\n"

// backoutRule ends the header of a stored back-out.
const backoutRule = "---\n"

// SaveBackout writes a device's stored back-out (0600, through a temporary
// file, under the store's lock so that a forget or a rename is not undone).
func (s Store) SaveBackout(name string, b StoredBackout) error {
	p, err := s.backoutPath(name)
	if err != nil {
		return err
	}
	if b.Pulled.IsZero() || b.Address == "" {
		return fail("A back-out is stamped with the pull and the device address it was computed from.")
	}
	unlock, err := s.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fail("Cannot create " + s.Dir + ": " + errText(err))
	}
	var w strings.Builder
	w.WriteString(BackoutHeader)
	w.WriteString("version: 2\n")
	w.WriteString("pulled: " + b.Pulled.UTC().Format(time.RFC3339Nano) + "\n")
	w.WriteString("vendor: " + b.Vendor + "\n")
	w.WriteString("address: " + b.Address + "\n")
	w.WriteString("sections: " + strings.Join(b.Sections, ",") + "\n")
	w.WriteString(backoutRule)
	w.WriteString(b.Text)
	return atomicWrite(p, []byte(w.String()), 0o600)
}

// Backout reads a device's stored back-out; nil when it has none or the file
// is not one of this tacctl (the next plan with changes writes it again).
func (s Store) Backout(name string) (*StoredBackout, error) {
	p, err := s.backoutPath(name)
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
	head, text, ok := strings.Cut(string(data), "\n"+backoutRule)
	if !ok {
		return nil, nil
	}
	b := &StoredBackout{Text: text}
	version := false
	for _, l := range strings.Split(head, "\n") {
		l = strings.TrimSpace(l)
		k, v, found := strings.Cut(l, ": ")
		if !found || strings.HasPrefix(l, "#") {
			continue
		}
		switch k {
		case "version":
			version = v == "2"
		case "pulled":
			t, perr := time.Parse(time.RFC3339Nano, v)
			if perr != nil {
				return nil, nil
			}
			b.Pulled = t
		case "vendor":
			b.Vendor = v
		case "address":
			b.Address = v
		case "sections":
			for _, sec := range strings.Split(v, ",") {
				if sec = strings.TrimSpace(sec); sec != "" {
					b.Sections = append(b.Sections, sec)
				}
			}
		}
	}
	if !version || b.Pulled.IsZero() || b.Address == "" {
		return nil, nil
	}
	return b, nil
}

// RemoveBackout removes a device's stored back-out (under the lock): a plan
// that has changes and no line tacctl can type to undo them leaves none of its
// own, and an earlier plan's would be taken for it.
func (s Store) RemoveBackout(name string) error {
	p, err := s.backoutPath(name)
	if err != nil {
		return err
	}
	unlock, err := s.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot remove " + p + ": " + errText(err))
	}
	return nil
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
	for _, other := range []func(string) (string, error){s.plainPath, s.backoutPath} {
		if pp, err := other(name); err == nil {
			if err := os.Remove(pp); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return had, fail("Cannot remove " + pp + ": " + errText(err))
			}
		}
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
			if e.IsDir() {
				continue
			}
			if n, ok := strings.CutSuffix(e.Name(), ".yaml"); ok {
				seen[n] = true
				if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return 0, fail("Cannot remove " + filepath.Join(s.Dir, e.Name()) + ": " + errText(err))
				}
			}
			// a plain view and a stored back-out go with their device, and
			// are no device of their own
			if strings.HasSuffix(e.Name(), plainSuffix) || strings.HasSuffix(e.Name(), backoutSuffix) {
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
	// the plain view and the stored back-out go with it (a stale one under the
	// new name is dropped when the old name has none)
	for _, path := range []func(string) (string, error){s.plainPath, s.backoutPath} {
		pf, perr1 := path(oldName)
		pt, perr2 := path(newName)
		if perr1 != nil || perr2 != nil {
			continue
		}
		err := os.Rename(pf, pt)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			if rerr := os.Remove(pt); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				return fail("Cannot remove " + pt + ": " + errText(rerr))
			}
		default:
			return fail("Cannot move " + pf + ": " + errText(err))
		}
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
