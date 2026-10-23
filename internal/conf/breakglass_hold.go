package conf

// The break-glass hold of tacctl 0.2.5 in tacctl.yaml (docs/plans/
// 0.2.5-plan.md D121-D126): breakglass_hold.<device>.address, .since, .by and
// .reason. The record of one device the server has been told to stop
// answering: both renderers carve its address out of every scope's prefixes
// and tagged addresses (the store is never changed), so the device's local
// accounts are usable while the server is up. Nothing here has a default and
// there is no expiry: a hold ends only when it is released. No credential is
// ever recorded; the reason is free text of the operator's, kept for the
// log and the displays, never rendered into a backend file.
//
// A device name may hold dots (a fully qualified name), and a dotted path
// cannot: the key is the name with every '.' written '~', which no device
// name contains (HoldKey, HoldDevice).

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/yamlpy"
)

// HoldPrefix starts every break-glass hold key.
const HoldPrefix = "breakglass_hold."

// The leaves of a hold.
const (
	HoldKeyAddress = "address"
	HoldKeySince   = "since"
	HoldKeyBy      = "by"
	HoldKeyReason  = "reason"
)

// HoldKeys are the leaves of a hold, in the order they are written.
var HoldKeys = []string{HoldKeyAddress, HoldKeySince, HoldKeyBy, HoldKeyReason}

// MaxHoldReason is the longest reason, in characters.
const MaxHoldReason = 256

// The schema types of the hold's leaves.
const (
	// TypeHoldAddress is breakglass_hold.<device>.address: one IPv4 or IPv6
	// address in its canonical form (no prefix length).
	TypeHoldAddress = "hold_address"
	// TypeHoldSince is .since: an RFC 3339 time.
	TypeHoldSince = "hold_since"
	// TypeHoldText is .by (a user name) and .reason (free text).
	TypeHoldText = "hold_text"
)

// HoldKey is the key segment of a device's hold: its name with '.' as '~'.
func HoldKey(device string) string { return strings.ReplaceAll(device, ".", "~") }

// HoldDevice is the device name a key segment stands for.
func HoldDevice(key string) string { return strings.ReplaceAll(key, "~", ".") }

// HoldPath is the tacctl.yaml key of one leaf of a device's hold.
func HoldPath(device, leaf string) string { return HoldPrefix + HoldKey(device) + "." + leaf }

// Hold is one record.
type Hold struct {
	// Device is the registered name the hold was made under.
	Device string
	// Address is the canonical address the server stops answering.
	Address string
	// Since is the RFC 3339 time of the hold, By the user who held it and
	// Reason the why.
	Since, By, Reason string
}

// holdWildcards are the schema's entries for breakglass_hold.<device>.<leaf>.
func holdWildcards() []wildcard {
	return []wildcard{
		{HoldPrefix, Rule{Type: TypeHoldAddress, Tail: HoldKeyAddress}},
		{HoldPrefix, Rule{Type: TypeHoldSince, Tail: HoldKeySince}},
		{HoldPrefix, Rule{Type: TypeHoldText, Tail: HoldKeyBy}},
		{HoldPrefix, Rule{Type: TypeHoldText, Tail: HoldKeyReason}},
	}
}

// HoldReasonProblem is why s cannot be a reason ("" when it can): 1 to
// MaxHoldReason characters of valid UTF-8 with no control character.
func HoldReasonProblem(s string) string {
	switch {
	case strings.TrimSpace(s) == "":
		return "must not be empty"
	case !utf8.ValidString(s):
		return "must be valid UTF-8"
	case utf8.RuneCountInString(s) > MaxHoldReason:
		return fmt.Sprintf("is limited to %d characters", MaxHoldReason)
	case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "may not contain control characters"
	}
	return ""
}

// holdProblem is the break-glass hold branch of Validate: the rule's type
// says which leaf the value is.
func holdProblem(typ, path string, value any) string {
	s, ok := value.(string)
	if !ok {
		return "must be a string"
	}
	switch typ {
	case TypeHoldAddress:
		if strings.ContainsAny(s, "/% ") {
			return "must be one address, without a prefix length"
		}
		n, err := cidr.Parse(s)
		if err != nil {
			return "is not a valid IPv4 or IPv6 address"
		}
		c := n.String()
		if c = c[:strings.LastIndexByte(c, '/')]; c != s {
			return "is not in its canonical form (" + c + ")"
		}
		return ""
	case TypeHoldSince:
		if _, err := parseHoldTime(s); err != nil {
			return "must be an RFC 3339 time (2006-01-02T15:04:05Z07:00)"
		}
		return ""
	}
	if strings.HasSuffix(path, "."+HoldKeyReason) {
		return HoldReasonProblem(s)
	}
	// .by: the account that held it.
	switch {
	case s == "" || utf8.RuneCountInString(s) > 64:
		return "must be 1 to 64 characters"
	case strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r == 0x7f }):
		return "may not contain blanks or control characters"
	}
	return ""
}

// Holds reads the usable records of the merged view, ordered by device
// name: those with an address that is one IPv4 or IPv6 address. A record
// that has none (the schema accepts each leaf alone, so a hand-edited file
// can hold a partial record) or whose address is not one is left out, and
// so is carved by no renderer; HoldDefects names it for the validator.
func (c *Config) Holds() []Hold {
	v, _ := c.Value("breakglass_hold")
	return holdsOf(v)
}

// HoldRecord is one entry of breakglass_hold as the file has it.
type HoldRecord struct {
	Hold
	// Key is the mapping key it is stored under: the device's name with its
	// dots written '~' when tacctl wrote it, and whatever the person wrote
	// when the file was edited by hand (a name with a dot in it, which no
	// dotted path can reach).
	Key string
	// Usable is whether the renderers carve it and the displays list it: it
	// has an address that is one IP address.
	Usable bool
	// Defect is what is wrong with the entry ("" when nothing): it is not a
	// record, has no address, an address that is not one, or a key a dotted
	// path cannot name. A defect may leave the record usable.
	Defect string
}

// HoldDefects are the entries of the merged view that have a defect, in
// device order: what 'config validate' names, so that none stays invisible.
func (c *Config) HoldDefects() []HoldRecord {
	v, _ := c.Value("breakglass_hold")
	var out []HoldRecord
	for _, r := range holdRecordsOf(v) {
		if r.Defect != "" {
			out = append(out, r)
		}
	}
	return out
}

// HoldRecordsNamed are the entries of the merged view of a device, usable
// or not, whatever spelling their key has (names compare exactly).
func (c *Config) HoldRecordsNamed(device string) []HoldRecord {
	v, _ := c.Value("breakglass_hold")
	var out []HoldRecord
	for _, r := range holdRecordsOf(v) {
		if r.Device == device {
			out = append(out, r)
		}
	}
	return out
}

// HoldKind is the word the rendered backend files use for a hold's name:
// "host" for an enrolled host (a name in hostNames), "device" for any
// other, an orphan included. The record carries no kind: the host registry
// decides at render time.
func HoldKind(name string, hostNames map[string]bool) string {
	if hostNames[name] {
		return "host"
	}
	return "device"
}

// HoldsOf reads the records of a merged view.
func HoldsOf(view *yamlpy.Map) []Hold {
	if view == nil {
		return nil
	}
	v, _ := view.Get("breakglass_hold")
	return holdsOf(v)
}

func holdsOf(v any) []Hold {
	var out []Hold
	for _, r := range holdRecordsOf(v) {
		if r.Usable {
			out = append(out, r.Hold)
		}
	}
	return out
}

// holdRecordsOf reads every entry of a breakglass_hold mapping, ordered by
// device name.
func holdRecordsOf(v any) []HoldRecord {
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	var out []HoldRecord
	for key, e := range m.All() {
		r := HoldRecord{Key: key}
		r.Device = HoldDevice(key)
		leaves, ok := e.(*yamlpy.Map)
		if !ok {
			r.Defect = "is not a record (address, since, by and reason)"
			out = append(out, r)
			continue
		}
		str := func(k string) string {
			x, _ := leaves.Get(k)
			s, _ := x.(string)
			return s
		}
		r.Address, r.Since, r.By, r.Reason = str(HoldKeyAddress), str(HoldKeySince), str(HoldKeyBy), str(HoldKeyReason)
		switch {
		case r.Address == "":
			r.Defect = "has no address, so it silences nothing"
		case !holdAddressUsable(r.Address):
			r.Defect = "has the address '" + r.Address + "', which is not one IPv4 or IPv6 address, so it silences nothing"
		default:
			r.Usable = true
			if strings.Contains(key, ".") {
				r.Defect = "is stored under the key '" + key + "', which holds a dot (tacctl writes a device name's dots as '~': " + HoldKey(key) + ")"
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

// holdAddressUsable is whether s is one IP address (no prefix length, no
// zone): what a renderer may carve out.
func holdAddressUsable(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

// HeldAddresses are the addresses of the holds of a merged view, in device
// order: what the renderers carve out.
func HeldAddresses(view *yamlpy.Map) []string {
	var out []string
	for _, h := range HoldsOf(view) {
		if !slices.Contains(out, h.Address) {
			out = append(out, h.Address)
		}
	}
	return out
}

// SinceTime is the time of the hold (the zero time when the record's
// since does not parse).
func (h Hold) SinceTime() time.Time {
	t, _ := parseHoldTime(h.Since)
	return t
}

func parseHoldTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

// SetHold writes the four leaves of a hold in one write.
func (c *Config) SetHold(h Hold) error {
	return c.SetValues([]PathValue{
		{HoldPath(h.Device, HoldKeyAddress), h.Address},
		{HoldPath(h.Device, HoldKeySince), h.Since},
		{HoldPath(h.Device, HoldKeyBy), h.By},
		{HoldPath(h.Device, HoldKeyReason), h.Reason},
	})
}

// SetHoldIf is SetHold for a hold that is written only while check, run
// under the file's lock on the usable records the file holds at that
// moment, accepts them: the check and the write cannot be separated by
// another writer (two superusers holding one device).
func (c *Config) SetHoldIf(h Hold, check func(existing []Hold) error) error {
	return c.SetValuesIf([]PathValue{
		{HoldPath(h.Device, HoldKeyAddress), h.Address},
		{HoldPath(h.Device, HoldKeySince), h.Since},
		{HoldPath(h.Device, HoldKeyBy), h.By},
		{HoldPath(h.Device, HoldKeyReason), h.Reason},
	}, func(overrides *yamlpy.Map) error {
		v, _ := overrides.Get("breakglass_hold")
		return check(holdsOf(v))
	})
}

// HoldSkip is a hold SetHoldsIf did not write: the one asked for, and why
// the check refused it.
type HoldSkip struct {
	Hold Hold
	Err  error
}

// SetHoldsIf writes several holds in one write, each only while check, run
// under the file's lock, accepts it. check gets the usable records the file
// holds at that moment, with those of hs already accepted in this call (two
// holds of one address cannot both stand), and the hold in question; a
// non-nil error skips that hold, and the others are written. It returns what
// was written and what was skipped, each in the order of hs. Nothing is
// written when no hold is accepted. A hold that fails the schema fails the
// whole call, and nothing is written.
func (c *Config) SetHoldsIf(hs []Hold, check func(existing []Hold, h Hold) error) (written []Hold, skipped []HoldSkip, err error) {
	err = c.edit(func(overrides *yamlpy.Map) (bool, error) {
		v, _ := overrides.Get("breakglass_hold")
		existing := holdsOf(v)
		var pairs []PathValue
		written, skipped = nil, nil
		for _, h := range hs {
			if check != nil {
				if cerr := check(existing, h); cerr != nil {
					skipped = append(skipped, HoldSkip{Hold: h, Err: cerr})
					continue
				}
			}
			pairs = append(pairs,
				PathValue{HoldPath(h.Device, HoldKeyAddress), h.Address},
				PathValue{HoldPath(h.Device, HoldKeySince), h.Since},
				PathValue{HoldPath(h.Device, HoldKeyBy), h.By},
				PathValue{HoldPath(h.Device, HoldKeyReason), h.Reason})
			existing = append(existing, h)
			written = append(written, h)
		}
		if len(pairs) == 0 {
			return false, nil
		}
		for _, pv := range pairs {
			if msg := c.Schema.Validate(pv.Path, pv.Value, false); msg != "" {
				return false, &ValidationError{Path: pv.Path, Msg: msg}
			}
		}
		for _, pv := range pairs {
			setNested(overrides, pv.Path, pv.Value)
		}
		return true, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return written, skipped, nil
}

// UnsetHold removes every entry of a device (the mapping it leaves empty
// goes too), under the key each is stored under: the one tacctl writes
// (dots as '~') or a hand-written one with the dot in it. Nothing is
// written when there is none.
func (c *Config) UnsetHold(device string) error { return c.UnsetHolds([]string{device}) }

// UnsetHolds is UnsetHold for several devices, in one write.
func (c *Config) UnsetHolds(devices []string) error {
	return c.edit(func(overrides *yamlpy.Map) (bool, error) {
		v, _ := overrides.Get("breakglass_hold")
		m, ok := v.(*yamlpy.Map)
		if !ok {
			return false, nil
		}
		changed := false
		for _, key := range m.Keys() {
			if slices.Contains(devices, HoldDevice(key)) {
				m.Delete(key)
				changed = true
			}
		}
		if changed && m.Len() == 0 {
			overrides.Delete("breakglass_hold")
		}
		return changed, nil
	})
}

// HoldKeysOf lists the dotted paths under breakglass_hold in the file's own
// overrides (not the merged view): what a rollback removes.
func (c *Config) HoldKeysOf() []string {
	var out []string
	walkLeaves(c.Overrides(), "", func(p string, _ any) {
		if strings.HasPrefix(p, HoldPrefix) {
			out = append(out, p)
		}
	})
	return out
}
