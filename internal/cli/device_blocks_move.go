package cli

// A device's own configuration blocks (0.2.7) follow the device through the
// registry: the files under StateDir/blocks/_devices/<name> and the
// blocks_device.<name>.<vendor> lists of tacctl.yaml that put them in force.
// A rename moves both, a removal deletes both, and a device that would find
// the blocks of an earlier device of its name is refused before the
// registry changes (the same rules as the device's SNMP credentials file,
// device_snmp_override.go).

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/names"
)

// deviceBlockStore is the block store of this installation.
func (inv *invocation) deviceBlockStore() *blocks.Store {
	return blocks.NewStore(inv.app.Paths.BlocksDir)
}

// deviceHasBlocks reports whether the device has blocks of its own: a
// directory of files, or a manifest entry in tacctl.yaml. A name the store
// cannot hold has none.
func (inv *invocation) deviceHasBlocks(name string) bool {
	if blocks.ValidateDevice(name) != nil {
		return false
	}
	return inv.deviceBlockStore().HasDevice(name) ||
		slices.Contains(inv.app.Conf().BlockDevices(), strings.ToLower(name))
}

// deviceBlocksRemovalNote is the line a removal prints before it asks, "" when
// none of the devices has blocks.
func (inv *invocation) deviceBlocksRemovalNote(devices []string) string {
	var have []string
	for _, n := range devices {
		if inv.deviceHasBlocks(n) {
			have = append(have, n)
		}
	}
	if len(have) == 0 {
		return ""
	}
	return "The configuration blocks of " + strings.Join(have, ", ") +
		" (they may hold community strings) are removed with the device(s); the snapshot taken first holds them."
}

// blocksNewNamesFree is nil when no device that the registry change adds
// (after has it, before does not: a new device, an import, or the new name of
// a rename) finds blocks of an earlier device of its name, on disk or in
// tacctl.yaml: it would render them as its own.
func (inv *invocation) blocksNewNamesFree(before, after *devreg.File) error {
	store := inv.deviceBlockStore()
	listed := inv.app.Conf().BlockDevices()
	for _, d := range after.Devices {
		if before.Find(d.Name) != nil || blocks.ValidateDevice(d.Name) != nil {
			continue
		}
		if err := store.CheckNoDevice(d.Name); err != nil {
			return err
		}
		if slices.Contains(listed, strings.ToLower(d.Name)) {
			return &names.Error{Msgs: []string{
				"tacctl.yaml lists configuration blocks (" + conf.BlocksDeviceTop + "." + conf.BlocksDeviceKey(d.Name) + ") for a device named '" + d.Name + "'.",
				"They belong to an earlier device of that name, and the new one would use them. Remove those entries from tacctl.yaml, then run the command again.",
			}}
		}
	}
	return nil
}

// blocksDeviceCarry follows a device's rename (newName set) or removal
// (newName empty): its manifest entries and its files. What cannot be carried
// is a warning, as the SNMP credentials' is; a rename that cannot move the
// files puts the entries back, so the two never disagree about the name.
func (inv *invocation) blocksDeviceCarry(oldName, newName string) {
	if blocks.ValidateDevice(oldName) != nil || !inv.deviceHasBlocks(oldName) {
		return
	}
	a := inv.app
	c := a.Conf()
	store := inv.deviceBlockStore()
	if newName == "" {
		var problems []string
		if err := c.UnsetBlockDevice(oldName); err != nil {
			problems = append(problems, strings.Join(msgs(err), " "))
		}
		if err := store.RemoveDevice(oldName); err != nil {
			problems = append(problems, strings.Join(msgs(err), " "))
		}
		if len(problems) > 0 {
			a.Out.Warn("The configuration blocks of '" + oldName + "' were not all removed: " + strings.Join(problems, " "))
		}
		return
	}
	if blocks.ValidateDevice(newName) != nil {
		a.Out.Warn("The configuration blocks of '" + oldName + "' were not carried over: '" + newName + "' is not a name the block store holds. They are still kept under the old name and are not rendered.")
		return
	}
	if err := c.MoveBlockDevice(oldName, newName); err != nil {
		a.Out.Warn("The configuration blocks of '" + oldName + "' were not carried over to '" + newName + "': " + strings.Join(msgs(err), " ") + " They are still kept under the old name and are not rendered.")
		return
	}
	if err := store.RenameDevice(oldName, newName); err != nil {
		if back := c.MoveBlockDevice(newName, oldName); back != nil {
			a.Out.Warn("The configuration blocks of '" + oldName + "' could not be put back under their old name in tacctl.yaml: " + strings.Join(msgs(back), " "))
		}
		a.Out.Warn("The configuration blocks of '" + oldName + "' were not carried over to '" + newName + "': " + strings.Join(msgs(err), " ") + " They are still kept under the old name and are not rendered.")
	}
}
