package policy

// The configuration blocks in force (0.2.7): blocks.<scope>.<vendor> in
// tacctl.yaml is the list of block names of that scope and vendor whose
// files (internal/blocks) are rendered. The key is written only when a block
// is in force: a tacctl.yaml that never had one does not change.

import (
	"slices"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
)

// BlockNames are the blocks in force for a scope and vendor, as stored (a
// name that is not a known block, a hand edit 'config validate' reports, is
// skipped).
func BlockNames(c *conf.Config, scope, vendor string) []string {
	var out []string
	for _, n := range c.GetList(conf.BlocksPath(scope, vendor)) {
		if slices.Contains(blocks.KnownBlocks, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// BlockInForce reports whether the block is in force for the scope and
// vendor.
func BlockInForce(c *conf.Config, scope, vendor, block string) bool {
	return slices.Contains(BlockNames(c, scope, vendor), block)
}

// SetBlockInForce puts the block in force (on) or takes it out, keeping the
// list in the order of blocks.KnownBlocks; an empty list removes the key (and
// blocks.<scope>), so a scope without blocks leaves tacctl.yaml as it was.
func SetBlockInForce(c *conf.Config, scope, vendor, block string, on bool) error {
	cur := BlockNames(c, scope, vendor)
	switch has := slices.Contains(cur, block); {
	case on && !has:
		cur = append(cur, block)
	case !on && has:
		cur = slices.DeleteFunc(cur, func(n string) bool { return n == block })
	default:
		return nil
	}
	return WriteBlockNames(c, scope, vendor, cur)
}

// WriteBlockNames stores the scope's list of blocks in force for a vendor,
// in the order of blocks.KnownBlocks; none at all removes the key.
func WriteBlockNames(c *conf.Config, scope, vendor string, list []string) error {
	path := conf.BlocksPath(scope, vendor)
	var ordered []string
	for _, k := range blocks.KnownBlocks {
		if slices.Contains(list, k) {
			ordered = append(ordered, k)
		}
	}
	if len(ordered) == 0 {
		return c.Unset(path)
	}
	return c.SetList(path, ordered)
}

// BlockManifest is every scope's blocks in force, vendor by vendor, as
// tacctl.yaml names them (blocks.Store.VerifyScopes' input). A scope or
// vendor key that is no name the store accepts is left out.
func BlockManifest(c *conf.Config) blocks.Manifest {
	m := blocks.Manifest{}
	for _, scope := range c.GetKeys("blocks") {
		if blocks.ValidateScope(scope) != nil {
			continue
		}
		for _, v := range c.GetKeys("blocks." + scope) {
			if !slices.Contains(blocks.Vendors, v) {
				continue
			}
			if names := BlockNames(c, scope, v); len(names) > 0 {
				if m[scope] == nil {
					m[scope] = map[string][]string{}
				}
				m[scope][v] = names
			}
		}
	}
	return m
}

// The devices' own blocks (0.2.7): blocks_device.<device>.<vendor> in
// tacctl.yaml, the device's lower case name with '.' as '~', the same list
// of block names and the same rules as a scope's.

// DeviceBlockNames are the blocks in force for a device and vendor, as
// stored (an unknown name, a hand edit 'config validate' reports, is
// skipped).
func DeviceBlockNames(c *conf.Config, device, vendor string) []string {
	var out []string
	for _, n := range c.GetList(conf.BlocksDevicePath(device, vendor)) {
		if slices.Contains(blocks.KnownBlocks, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// DeviceBlockInForce reports whether the block is in force for the device
// and vendor.
func DeviceBlockInForce(c *conf.Config, device, vendor, block string) bool {
	return slices.Contains(DeviceBlockNames(c, device, vendor), block)
}

// SetDeviceBlockInForce puts the device's block in force (on) or takes it
// out, keeping the list in the order of blocks.KnownBlocks; an empty list
// removes the key (and blocks_device.<device>).
func SetDeviceBlockInForce(c *conf.Config, device, vendor, block string, on bool) error {
	cur := DeviceBlockNames(c, device, vendor)
	switch has := slices.Contains(cur, block); {
	case on && !has:
		cur = append(cur, block)
	case !on && has:
		cur = slices.DeleteFunc(cur, func(n string) bool { return n == block })
	default:
		return nil
	}
	return WriteDeviceBlockNames(c, device, vendor, cur)
}

// WriteDeviceBlockNames stores a device's list of blocks in force for a
// vendor, in the order of blocks.KnownBlocks; none at all removes the key.
func WriteDeviceBlockNames(c *conf.Config, device, vendor string, list []string) error {
	path := conf.BlocksDevicePath(device, vendor)
	var ordered []string
	for _, k := range blocks.KnownBlocks {
		if slices.Contains(list, k) {
			ordered = append(ordered, k)
		}
	}
	if len(ordered) == 0 {
		return c.Unset(path)
	}
	return c.SetList(path, ordered)
}

// DeviceBlockManifest is every device's blocks in force, vendor by vendor
// (keyed by the lower case device name), as tacctl.yaml names them
// (blocks.Store.VerifyDevices' input). A device or vendor key that is no
// name the store accepts is left out.
func DeviceBlockManifest(c *conf.Config) blocks.Manifest {
	m := blocks.Manifest{}
	for _, device := range c.BlockDevices() {
		for _, v := range blocks.Vendors {
			if names := DeviceBlockNames(c, device, v); len(names) > 0 {
				if m[device] == nil {
					m[device] = map[string][]string{}
				}
				m[device][v] = names
			}
		}
	}
	return m
}

// MoveDeviceBlocks gives a device's manifest entries its new name (a device
// renamed).
func MoveDeviceBlocks(c *conf.Config, old, newName string) error {
	return c.MoveBlockDevice(old, newName)
}

// ForgetDeviceBlocks removes a device's manifest entries (a device removed).
func ForgetDeviceBlocks(c *conf.Config, device string) error {
	return c.UnsetBlockDevice(device)
}
