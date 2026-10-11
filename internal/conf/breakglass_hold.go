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

// Holds reads the records of the merged view, ordered by device name. A
// device whose record lacks its address is left out (the schema accepts
// each leaf alone, so a hand-edited file can hold a partial record; the
// validator names it, the renderers carve nothing for it).
func (c *Config) Holds() []Hold {
	v, _ := c.Value("breakglass_hold")
	return holdsOf(v)
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
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	var out []Hold
	for key, e := range m.All() {
		leaves, ok := e.(*yamlpy.Map)
		if !ok {
			continue
		}
		str := func(k string) string {
			x, _ := leaves.Get(k)
			s, _ := x.(string)
			return s
		}
		h := Hold{Device: HoldDevice(key), Address: str(HoldKeyAddress), Since: str(HoldKeySince), By: str(HoldKeyBy), Reason: str(HoldKeyReason)}
		if h.Address == "" {
			continue
		}
		out = append(out, h)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
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

// UnsetHold removes a device's record (the key and the mappings it leaves
// empty); nothing is written when there is none.
func (c *Config) UnsetHold(device string) error {
	var paths []string
	for _, k := range HoldKeys {
		paths = append(paths, HoldPath(device, k))
	}
	return c.UnsetMany(paths)
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
