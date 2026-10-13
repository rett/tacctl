package blocks

import (
	"slices"
	"sort"
	"strings"
)

// Manifest is the blocks in force, as tacctl.yaml names them
// (blocks.<scope>.<vendor>, or blocks_device.<device>.<vendor> with the
// device's lower case name): the scope or device, then the vendor, then the
// block names.
type Manifest map[string]map[string][]string

// Names are the block names the manifest lists for a scope (or device) and
// vendor.
func (m Manifest) Names(scope, vendor string) []string { return m[scope][vendor] }

// The kinds of a finding of Verify.
const (
	// KindUnlisted is a file the manifest does not name: it is ignored.
	KindUnlisted = "unlisted"
	// KindMissing is a manifest entry without a file.
	KindMissing = "missing"
	// KindOrphanVendor is a device's directory or manifest entry for a
	// vendor that is not the device's own (VerifyDevices): the render never
	// reads it.
	KindOrphanVendor = "orphan-vendor"
	// KindOrphanDevice is a directory or manifest entry of a device that is
	// not in the registry (VerifyDevices): nothing renders it.
	KindOrphanDevice = "orphan-device"
)

// manifestKey is the tacctl.yaml family a level's names are kept under, for
// the text of a finding.
func (l Level) manifestKey() string {
	if l.IsDevice() {
		return "blocks_device"
	}
	return "blocks"
}

// StoreFinding is one disagreement between the manifest and the files.
type StoreFinding struct {
	Kind   string
	Level  Level
	Vendor string
	Block  string
	Text   string
}

// Verify compares the manifest names of one level and vendor with the files
// of the store: a file the names lack is KindUnlisted (ignored, never in
// force), a name without a file KindMissing. A name that is not a known
// block cannot have a file and is reported missing. Findings are in block
// order, the manifest's entries first.
func (s *Store) Verify(l Level, vendor string, listed []string) ([]StoreFinding, error) {
	files, err := s.List(l, vendor)
	if err != nil {
		return nil, err
	}
	var out []StoreFinding
	seen := map[string]bool{}
	for _, n := range listed {
		if seen[n] {
			continue
		}
		seen[n] = true
		if !slices.Contains(files, n) {
			out = append(out, StoreFinding{KindMissing, l, vendor, n,
				l.String() + " " + vendor + ": the block '" + n + "' is in tacctl.yaml (" + l.manifestKey() + ") but has no file; it renders nothing"})
		}
	}
	for _, f := range files {
		if !seen[f] {
			out = append(out, StoreFinding{KindUnlisted, l, vendor, f,
				l.String() + " " + vendor + ": the file of block '" + f + "' is not in tacctl.yaml (" + l.manifestKey() + "); it is ignored"})
		}
	}
	return out, nil
}

// VerifyScopes is Verify for every scope and vendor that the manifest or the
// store has: the scopes of the manifest and the scopes with a directory, each
// with the vendors of both.
func (s *Store) VerifyScopes(m Manifest) ([]StoreFinding, error) {
	onDisk, err := s.Scopes()
	if err != nil {
		return nil, err
	}
	scopes := map[string]bool{}
	for sc := range m {
		scopes[sc] = true
	}
	for _, sc := range onDisk {
		scopes[sc] = true
	}
	var order []string
	for sc := range scopes {
		order = append(order, sc)
	}
	sort.Strings(order)
	var out []StoreFinding
	for _, sc := range order {
		l := ScopeLevel(sc)
		if l.Validate() != nil {
			continue
		}
		vendors, err := s.Vendors(l)
		if err != nil {
			return nil, err
		}
		for _, v := range Vendors {
			if _, listed := m[sc][v]; !listed && !slices.Contains(vendors, v) {
				continue
			}
			f, err := s.Verify(l, v, m[sc][v])
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
	}
	return out, nil
}

// VerifyDevices is Verify for the device level: every device and vendor the
// manifest (keyed by lower case device name) or the store has. vendorOf says
// whether a device is registered and its vendor word (blocks.Vendors, or
// another registry vendor, which has no block). Per device, in name order:
//
//   - a device that is not registered is one KindOrphanDevice finding (its
//     files and entries are never rendered);
//   - a vendor that is not the device's is one KindOrphanVendor finding (a
//     device moved to another vendor, or a hand edit: ignored);
//   - the device's own vendor is Verify's: KindMissing and KindUnlisted.
func (s *Store) VerifyDevices(m Manifest, vendorOf func(device string) (vendor string, registered bool)) ([]StoreFinding, error) {
	onDisk, err := s.Devices()
	if err != nil {
		return nil, err
	}
	devices := map[string]bool{}
	for d := range m {
		devices[strings.ToLower(d)] = true
	}
	for _, d := range onDisk {
		devices[d] = true
	}
	var order []string
	for d := range devices {
		order = append(order, d)
	}
	sort.Strings(order)
	var out []StoreFinding
	for _, d := range order {
		l := DeviceLevel(d)
		if l.Validate() != nil {
			continue
		}
		vendors, err := s.Vendors(l)
		if err != nil {
			return nil, err
		}
		own, registered := "", false
		if vendorOf != nil {
			own, registered = vendorOf(d)
		}
		if !registered {
			out = append(out, StoreFinding{KindOrphanDevice, l, "", "",
				l.String() + ": the device is not in the registry; its configuration blocks and their tacctl.yaml (blocks_device) entries are ignored"})
			continue
		}
		for _, v := range Vendors {
			names := namesOf(m, d, v)
			if len(names) == 0 && !slices.Contains(vendors, v) {
				continue
			}
			if v != own {
				out = append(out, StoreFinding{KindOrphanVendor, l, v, "",
					l.String() + " " + v + ": the device's vendor is not " + v + " (it is " + vendorWord(own) + " in the registry), so these blocks are ignored"})
				continue
			}
			f, err := s.Verify(l, v, names)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
	}
	return out, nil
}

// namesOf are the manifest's names for a device (its key in any case) and a
// vendor.
func namesOf(m Manifest, device, vendor string) []string {
	var out []string
	for k, v := range m {
		if strings.EqualFold(k, device) {
			out = append(out, v[vendor]...)
		}
	}
	return out
}

func vendorWord(v string) string {
	if v == "" {
		return "not set"
	}
	return v
}
