package cli

// The configuration blocks of a scope, and of one device, as the renderers
// take them (0.2.7): the resolution of internal/policy, once per render for
// a walkthrough and once per device that has blocks of its own for a batch.

import (
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/policy"
)

// blockOverride is a block text laid in place of the file of one level
// ('block check --against' plans a device with a text that is not yet in
// force): the file in force, and the manifest, are not consulted for that
// level and block.
type blockOverride struct {
	level blocks.Level
	block string
	text  []byte
}

// forLevel is the override's text when it is for this level and block, else
// the text in hand.
func (o *blockOverride) forLevel(l blocks.Level, block string, in []byte) []byte {
	if o == nil || o.block != block || o.level.IsDevice() != l.IsDevice() {
		return in
	}
	if l.IsDevice() && !strings.EqualFold(o.level.Device, l.Device) || !l.IsDevice() && o.level.Scope != l.Scope {
		return in
	}
	return o.text
}

// blockLayer is a policy.BlockLayers as the renderers' word for it.
func blockLayer(l policy.BlockLayers) devices.BlockLayer {
	switch {
	case l.Scope && l.Device:
		return devices.LayerScopeDevice
	case l.Device:
		return devices.LayerDevice
	}
	return devices.LayerScope
}

// resolveBlocks are the blocks a device of scope and vendor is rendered
// with: the snmp and system blocks of a Junos or an IOS device; the scope's files and, for a device named, its own over them
// (a layer's file is read when the manifest names it). The zero Blocks is
// none. layers[0] is the snmp block's layers and layers[1] the system
// block's.
func (inv *invocation) resolveBlocks(vendor, scope, device string, ov *blockOverride) (devices.Blocks, [2]policy.BlockLayers, error) {
	var layers [2]policy.BlockLayers
	store, cfg := inv.deviceBlockStore(), inv.app.Conf()
	text := func(l blocks.Level, block string) ([]byte, error) {
		if ov != nil && ov.block == block && ov.forLevel(l, block, nil) != nil {
			return ov.text, nil
		}
		return policy.LayerTextFor(store, cfg, vendor, l, block)
	}
	if vendor == blocks.VendorCisco {
		return inv.resolveIOSBlocks(scope, device, text)
	}
	var sc, dv [2][]byte
	for i, block := range []string{blocks.BlockSNMP, blocks.BlockSystem} {
		var err error
		if sc[i], err = text(blocks.ScopeLevel(scope), block); err != nil {
			return devices.Blocks{}, layers, err
		}
		if device != "" {
			if dv[i], err = text(blocks.DeviceLevel(device), block); err != nil {
				return devices.Blocks{}, layers, err
			}
		}
	}
	snmp, snmpLayers, err := policy.ResolveSNMPTexts(scope, device, sc[0], dv[0])
	if err != nil {
		return devices.Blocks{}, layers, err
	}
	system, systemLayers, err := policy.ResolveSystemTexts(scope, device, sc[1], dv[1])
	if err != nil {
		return devices.Blocks{}, layers, err
	}
	layers = [2]policy.BlockLayers{snmpLayers, systemLayers}
	if snmp == nil && system == nil {
		return devices.Blocks{}, layers, nil
	}
	b := devices.Blocks{Scope: scope, SNMP: snmp, System: system,
		SNMPLayer: blockLayer(snmpLayers), SystemLayer: blockLayer(systemLayers)}
	// the layers as written, for the words of a refusal (the texts parsed
	// well: a layer with errors was refused above)
	if sc[0] != nil {
		b.ScopeSNMP, _ = blocks.Parse(string(sc[0]))
	}
	if dv[0] != nil {
		b.DeviceSNMP, _ = blocks.Parse(string(dv[0]))
	}
	if sc[1] != nil {
		b.ScopeSystem, _ = blocks.ParseSystem(string(sc[1]))
	}
	if dv[1] != nil {
		b.DeviceSystem, _ = blocks.ParseSystem(string(dv[1]))
	}
	if (snmp != nil && snmpLayers.Device) || (system != nil && systemLayers.Device) {
		b.Device = device
	}
	return b, layers, nil
}

// resolveIOSBlocks is resolveBlocks for an IOS device: the snmp and system
// blocks of the scope and, for a device named, its own over them.
func (inv *invocation) resolveIOSBlocks(scope, device string, text func(blocks.Level, string) ([]byte, error)) (devices.Blocks, [2]policy.BlockLayers, error) {
	var layers [2]policy.BlockLayers
	var sc, dv [2][]byte
	for i, block := range []string{blocks.BlockSNMP, blocks.BlockSystem} {
		var err error
		if sc[i], err = text(blocks.ScopeLevel(scope), block); err != nil {
			return devices.Blocks{}, layers, err
		}
		if device != "" {
			if dv[i], err = text(blocks.DeviceLevel(device), block); err != nil {
				return devices.Blocks{}, layers, err
			}
		}
	}
	snmp, snmpLayers, err := policy.ResolveIOSSNMPTexts(scope, device, sc[0], dv[0])
	if err != nil {
		return devices.Blocks{}, layers, err
	}
	system, systemLayers, err := policy.ResolveIOSSystemTexts(scope, device, sc[1], dv[1])
	if err != nil {
		return devices.Blocks{}, layers, err
	}
	layers = [2]policy.BlockLayers{snmpLayers, systemLayers}
	if snmp == nil && system == nil {
		return devices.Blocks{}, layers, nil
	}
	b := devices.Blocks{Scope: scope, CiscoSNMP: snmp, CiscoSystem: system,
		SNMPLayer: blockLayer(snmpLayers), SystemLayer: blockLayer(systemLayers)}
	// the layers as written, for the words of a refusal (the texts parsed
	// well: a layer with errors was refused above)
	if sc[0] != nil {
		b.ScopeCiscoSNMP, _ = blocks.ParseIOSSNMP(string(sc[0]))
	}
	if dv[0] != nil {
		b.DeviceCiscoSNMP, _ = blocks.ParseIOSSNMP(string(dv[0]))
	}
	if sc[1] != nil {
		b.ScopeCiscoSystem, _ = blocks.ParseIOSSystem(string(sc[1]))
	}
	if dv[1] != nil {
		b.DeviceCiscoSystem, _ = blocks.ParseIOSSystem(string(dv[1]))
	}
	if (snmp != nil && snmpLayers.Device) || (system != nil && systemLayers.Device) {
		b.Device = device
	}
	return b, layers, nil
}

// logBlockReads logs a restricted caller's read of the strings of the
// blocks a render carries: the block's name, never a value. The scope's
// blocks are named scope/<vendor>/<block>, a device's own
// _devices/<device>/<vendor>/<block>. logRead is secretRead for a render
// that is shown, secretUse for one that is only compared or planned.
func (inv *invocation) logBlockReads(logRead func(kind, name string), b devices.Blocks, layers [2]policy.BlockLayers, scope, device string) {
	vendor := blocks.VendorJuniper
	if b.CiscoSNMP != nil || b.CiscoSystem != nil {
		vendor = blocks.VendorCisco
	}
	secret := [2]bool{b.SNMP != nil || b.CiscoSNMP != nil,
		b.System != nil && len(b.System.NTPKeys) > 0 || b.CiscoSystem != nil && len(b.CiscoSystem.NTPKeys) > 0}
	for i, block := range []string{blocks.BlockSNMP, blocks.BlockSystem} {
		if !secret[i] {
			continue
		}
		if layers[i].Scope {
			logRead("block", scope+"/"+vendor+"/"+block)
		}
		if layers[i].Device {
			logRead("block", blocks.DevicesDir+"/"+strings.ToLower(device)+"/"+vendor+"/"+block)
		}
	}
}
