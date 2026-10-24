package devconf

// Staleness (D66): never, failed, differs or ok, and (D113) pull.

import "github.com/rett/tacctl/internal/devices"

// Staleness is what the configuration column and 'device config list
// --stale' say about a device.
type Staleness string

const (
	// StaleNever: no record, or a record with no pull to compare.
	StaleNever Staleness = "never"
	// StaleFailed: the last pull's result was not ok.
	StaleFailed Staleness = "failed"
	// StaleDiffers: a managed section differs from, or is missing against,
	// what tacctl renders.
	StaleDiffers Staleness = "differs"
	// StaleOK: the last pull was ok and every section agrees (or is n/a).
	StaleOK Staleness = "ok"
	// StalePull (D113): a Cisco device whose configuration syntax is
	// 'auto' and whose record has none (a record of 0.2.4, or a pull that
	// read no version line) cannot be compared: it is neither guessed
	// modern nor IOS 12.x, and one pull makes it known. The CONFIG column
	// says 'pull'; the detail is NeedsPullText. A device whose vendor
	// changed since its last pull (0.2.17 D260) is StalePull too: its
	// stored sections are of the old vendor's shape (NeedsPullVendorText).
	StalePull Staleness = "pull"
)

// NeedsPullText is the words of the StalePull state.
const NeedsPullText = "needs pull (syntax unknown)"

// NeedsPullVendorText is the words of the StalePull state of a device whose
// vendor changed since its last pull.
const NeedsPullVendorText = "needs pull (vendor changed)"

// VendorChanged reports whether the record was pulled for another vendor
// than vendor, the device's registered one: every pull and apply keeps the
// vendor it read for, and the stored sections are of that vendor's shape, so
// they are not compared in another's.
func VendorChanged(rec *Record, vendor string) bool {
	return rec != nil && !rec.Pulled.IsZero() && rec.Vendor != "" && rec.Vendor != vendor
}

// SetVendorUnlessPulled is the vendor a write that is not a good pull (a
// failed attempt, an apply's or a settle's record) leaves on the record: the
// stored sections' vendor stays, and vendor is taken only by a record with
// no good pull or no vendor yet, so VendorChanged still sees a change.
func (r *Record) SetVendorUnlessPulled(vendor string) {
	if r.Pulled.IsZero() || r.Vendor == "" {
		r.Vendor = vendor
	}
}

// NeedsSyntax reports whether the record is a good pull of a Cisco device
// that cannot be compared because its syntax is unknown (D113): the
// registry's setting is auto (or empty) and the record keeps no syntax. A
// record that is not ok, or has no sections, is never/failed already.
func NeedsSyntax(rec *Record, setting string) bool {
	if rec == nil || rec.Result != ResultOK || len(rec.Sections) == 0 {
		return false
	}
	if fam, err := Family(rec.Vendor); err != nil || fam != FamilyIOS {
		return false
	}
	return Syntax(setting, rec) == ""
}

// WithSyntax is st with D113's state laid over it: a device that is ok or
// differs but whose syntax is unknown is StalePull. matters is false where
// the syntax is of no consequence (a Cisco device in a RADIUS scope has the
// one 'radius server' syntax).
func WithSyntax(st Staleness, rec *Record, setting string, matters bool) Staleness {
	if matters && (st == StaleOK || st == StaleDiffers) && NeedsSyntax(rec, setting) {
		return StalePull
	}
	return st
}

// IsStale reports whether the device wants attention: anything but ok.
func (s Staleness) IsStale() bool { return s != StaleOK }

// Extracted rebuilds the extraction a pull recorded from its stored
// sections, for CompareAll.
func (r *Record) Extracted(secs map[string]devices.Section) Extracted {
	fam, err := Family(r.Vendor)
	if err != nil {
		fam = r.Vendor
	}
	return Extracted{Vendor: fam, Sections: secs, SecretsVisible: r.SecretsVisible}
}

// SetSections keeps the fingerprint and the comparison state of every
// section in the record, from an extraction and its comparison.
func (r *Record) SetSections(got Extracted, results []SectionResult) error {
	m := make(map[string]SectionRecord, len(results))
	for _, res := range results {
		sum, err := Fingerprint(got.Vendor, got.Sections[res.Name])
		if err != nil {
			return err
		}
		m[res.Name] = SectionRecord{SHA256: sum, State: string(res.State), Unmanaged: res.Unmanaged}
	}
	r.Sections = m
	return nil
}

// Recorded is the staleness the record alone says, from the states of the
// last comparison (what 'device list' shows: no rendering needed). A nil
// record is never.
func Recorded(rec *Record) Staleness {
	switch {
	case rec == nil || rec.Result == "":
		return StaleNever
	case rec.Result != ResultOK:
		return StaleFailed
	case len(rec.Sections) == 0:
		return StaleNever
	}
	for _, s := range rec.Sections {
		if State(s.State) == StateDiffers || State(s.State) == StateMissing {
			return StaleDiffers
		}
	}
	return StaleOK
}

// Stale is the staleness of a device against today's rendering: the stored
// sections of its last successful pull compared with expected
// (devices.Managed's result now), so a change on the tacctl side makes a
// device stale without a new pull. A record whose result is not ok is
// failed (a WTI unit's 'denied' and 'unsupported' included); a record that is
// ok but has no stored sections is never.
func Stale(rec *Record, stored map[string]devices.Section, expected []devices.Section) (Staleness, error) {
	switch {
	case rec == nil || rec.Result == "":
		return StaleNever, nil
	case rec.Result != ResultOK:
		return StaleFailed, nil
	case len(stored) == 0:
		return StaleNever, nil
	}
	results, err := CompareAll(expected, rec.Extracted(stored))
	if err != nil {
		return "", err
	}
	for _, r := range results {
		if r.State == StateDiffers || r.State == StateMissing {
			return StaleDiffers, nil
		}
	}
	return StaleOK, nil
}
