package conf

// The configuration blocks in force (0.2.7, docs/plans/0.2.7-blocks-plan.md):
// blocks.<scope>.<vendor> is the list of the blocks of that scope and vendor
// that are in force, such as [snmp, system]. The block files are
// StateDir/blocks/<scope>/<vendor>/<block> (internal/blocks); the manifest
// is here, in tacctl.yaml, so that every snapshot of a configuration change
// holds it with the rest of the settings and a restore brings both back
// together. Nothing has a default: an absent key is "no block in force", and
// a file the list does not name is ignored.
//
// A device's own blocks (StateDir/blocks/_devices/<device>/<vendor>/<block>)
// are named the same way under blocks_device.<device>.<vendor>, with the
// device's lower case name written as a break-glass hold's is: every '.' as
// '~' (HoldKey), so a fully qualified name is one key segment.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// BlocksPrefix starts every manifest key.
const BlocksPrefix = "blocks."

// BlocksDevicePrefix starts every device-level manifest key, and
// BlocksDeviceTop is the key they are under.
const (
	BlocksDevicePrefix = "blocks_device."
	BlocksDeviceTop    = "blocks_device"
)

// BlocksPath is the tacctl.yaml key of a scope's list of blocks of one
// vendor.
func BlocksPath(scope, vendor string) string { return BlocksPrefix + scope + "." + vendor }

// BlocksDeviceKey is the key segment of a device's blocks: its lower case
// name with every '.' as '~' (HoldKey), the same segment for every spelling
// of the name.
func BlocksDeviceKey(device string) string { return HoldKey(strings.ToLower(device)) }

// BlocksDevicePath is the tacctl.yaml key of a device's list of blocks of
// one vendor (blocks_device.<name with '.' as '~'>.<vendor>).
func BlocksDevicePath(device, vendor string) string {
	return BlocksDevicePrefix + BlocksDeviceKey(device) + "." + vendor
}

// BlockDevices are the devices (lower case names) that have a key under
// blocks_device, in the file's order and each once; a segment that is no
// name the store accepts is left out. It reads the merged view.
func (c *Config) BlockDevices() []string {
	var out []string
	for _, key := range c.GetKeys(BlocksDeviceTop) {
		d := HoldDevice(key)
		if blocks.ValidateDevice(d) != nil || slices.Contains(out, strings.ToLower(d)) {
			continue
		}
		out = append(out, strings.ToLower(d))
	}
	return out
}

// blockDeviceKeys are the segments of the file's own blocks_device mapping
// that stand for the device, whatever the spelling of the name there (a hand
// edit may hold an upper case name).
func blockDeviceKeys(m *yamlpy.Map, device string) []string {
	var out []string
	for _, key := range m.Keys() {
		if strings.EqualFold(HoldDevice(key), device) {
			out = append(out, key)
		}
	}
	return out
}

// UnsetBlockDevice removes every manifest entry of a device (the mapping it
// leaves empty goes too, and the file when nothing else is left). Nothing is
// written when there is none.
func (c *Config) UnsetBlockDevice(device string) error {
	return c.edit(func(overrides *yamlpy.Map) (bool, error) {
		v, _ := overrides.Get(BlocksDeviceTop)
		m, ok := v.(*yamlpy.Map)
		if !ok {
			return false, nil
		}
		keys := blockDeviceKeys(m, device)
		for _, k := range keys {
			m.Delete(k)
		}
		if len(keys) > 0 && m.Len() == 0 {
			overrides.Delete(BlocksDeviceTop)
		}
		return len(keys) > 0, nil
	})
}

// MoveBlockDevice gives a device's manifest entries a new name (a device
// renamed), in one write. Nothing is written when the device has none or
// the two names are one name in another spelling. It refuses (and writes
// nothing) when the new name already has entries: they are an earlier
// device's, and the renamed device would otherwise lose its own to them.
func (c *Config) MoveBlockDevice(old, newName string) error {
	if strings.EqualFold(old, newName) {
		return nil
	}
	return c.edit(func(overrides *yamlpy.Map) (bool, error) {
		v, _ := overrides.Get(BlocksDeviceTop)
		m, ok := v.(*yamlpy.Map)
		if !ok {
			return false, nil
		}
		from := blockDeviceKeys(m, old)
		if len(from) == 0 {
			return false, nil
		}
		if len(blockDeviceKeys(m, newName)) > 0 {
			return false, fmt.Errorf("tacctl.yaml already lists configuration blocks (%s) for a device named '%s'", BlocksDeviceTop, newName)
		}
		merged := yamlpy.NewMap()
		for _, k := range from {
			sub, _ := m.Get(k)
			if sm, ok := sub.(*yamlpy.Map); ok {
				for _, vk := range sm.Keys() {
					val, _ := sm.Get(vk)
					merged.Set(vk, val)
				}
			}
			m.Delete(k)
		}
		m.Set(BlocksDeviceKey(newName), merged)
		return true, nil
	})
}

// blockListProblem is the block_list branch of Validate for
// blocks.<scope>.<vendor> and blocks_device.<device>.<vendor>.
func blockListProblem(path string, value any) string {
	var vendor, which string
	if rest, ok := strings.CutPrefix(path, BlocksDevicePrefix); ok {
		key, v, _ := strings.Cut(rest, ".")
		vendor, which = v, "blocks_device.<device>.<vendor>"
		device := HoldDevice(key)
		if err := blocks.ValidateDevice(device); err != nil {
			return "the device in the key " + strings.ReplaceAll(err.Error(), "\n", " ")
		}
		if key != BlocksDeviceKey(device) {
			return "the device name in the key must be lower case (" + BlocksDeviceKey(device) + ")"
		}
	} else {
		rest := strings.TrimPrefix(path, BlocksPrefix)
		scope, v, _ := strings.Cut(rest, ".")
		vendor, which = v, "blocks.<scope>.<vendor>"
		if err := blocks.ValidateScope(scope); err != nil {
			return "the scope in the key " + strings.ReplaceAll(err.Error(), "\n", " ")
		}
	}
	if !slices.Contains(blocks.Vendors, vendor) {
		return "must be one of the vendors " + strings.Join(blocks.Vendors, ", ") + " (" + which + ")"
	}
	items, isList := py.List(value)
	if !isList || len(items) == 0 {
		return "must be a non-empty list of block names (" + strings.Join(blocks.KnownBlocks, ", ") + ")"
	}
	var seen []string
	for i, item := range items {
		s, isStr := item.(string)
		if !isStr {
			return fmt.Sprintf("element %d: must be a string", i)
		}
		if !slices.Contains(blocks.KnownBlocks, s) {
			return fmt.Sprintf("element %d: %s is not a block (one of: %s)", i, py.ReprString(s), strings.Join(blocks.KnownBlocks, ", "))
		}
		if slices.Contains(seen, s) {
			return fmt.Sprintf("element %d: %s is listed twice", i, py.ReprString(s))
		}
		seen = append(seen, s)
	}
	return ""
}
