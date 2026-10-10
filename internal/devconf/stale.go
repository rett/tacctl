package devconf

// Staleness (D66): never, failed, differs or ok.

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
)

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
		m[res.Name] = SectionRecord{SHA256: sum, State: string(res.State)}
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
	case rec.Result == ResultUnsupported && rec.Vendor == "wti":
		// A vendor that is not read has nothing to be stale: only a WTI
		// unit's pull is recorded unsupported, and a record of another
		// vendor with that result is a refusal that did not read it.
		return StaleOK
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
// device stale without a new pull. A WTI unit's record, result
// 'unsupported' (a vendor that is not read), is never stale; the same result
// of another vendor is failed; a record that is ok but has no stored sections
// is never.
func Stale(rec *Record, stored map[string]devices.Section, expected []devices.Section) (Staleness, error) {
	switch {
	case rec == nil || rec.Result == "":
		return StaleNever, nil
	case rec.Result == ResultUnsupported && rec.Vendor == "wti":
		return StaleOK, nil
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
