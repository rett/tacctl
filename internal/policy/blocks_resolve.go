package policy

// The snmp and system blocks a device is rendered with (0.2.7, B3, B7 and
// B8): the scope's file and the device's own, each when the manifest names
// it and its file exists, held to the grammar at its layer, resolved (the
// default layer has no file). A block with an error is never half rendered:
// the call fails and names the scope or the device and the verb that says
// what is wrong.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
)

// maxBlockFindings is how many findings of a failed block the error shows;
// 'tacctl scope block <scope> juniper check snmp' shows them all.
const maxBlockFindings = 5

// BlockLayers says which layers of the resolution hold the block that came
// out: the scope's file, the device's own, both, or neither (nothing is
// rendered).
type BlockLayers struct {
	Scope, Device bool
}

// ResolveSNMPBlock is the Junos snmp block of a scope, and of one device of
// it when device is not empty, as the renderers take it: nil when no layer
// has one in force (no manifest entry, or an entry with no file, which
// 'check' reports and which renders nothing), or an error when a layer
// cannot be rendered whole. The error names the scope or the device, holds
// no community string (the findings of internal/blocks never do) and says
// which verb to run: 'tacctl scope block <scope> juniper check snmp', or
// 'tacctl device block <device> check snmp'.
func ResolveSNMPBlock(store *blocks.Store, c *conf.Config, scope, device string) (*blocks.SNMPBlock, BlockLayers, error) {
	scopeText, deviceText, err := layerTexts(store, c, blocks.VendorJuniper, scope, device, blocks.BlockSNMP)
	if err != nil {
		return nil, BlockLayers{}, err
	}
	return ResolveSNMPTexts(scope, device, scopeText, deviceText)
}

// ResolveIOSSNMPBlock is the IOS snmp block of a scope, and of one device of
// it when device is not empty, as the renderers take it, with the same rules
// as ResolveSNMPBlock: nil when no layer has one in force, an error (naming
// the scope or the device and the verb that checks it, holding no community
// string) when a layer cannot be rendered whole.
func ResolveIOSSNMPBlock(store *blocks.Store, c *conf.Config, scope, device string) (*blocks.IOSSNMPBlock, BlockLayers, error) {
	scopeText, deviceText, err := layerTexts(store, c, blocks.VendorCisco, scope, device, blocks.BlockSNMP)
	if err != nil {
		return nil, BlockLayers{}, err
	}
	return ResolveIOSSNMPTexts(scope, device, scopeText, deviceText)
}

// ResolveIOSSNMPTexts is ResolveIOSSNMPBlock for texts already in hand: a nil
// text is a layer that has no block.
func ResolveIOSSNMPTexts(scope, device string, scopeText, deviceText []byte) (*blocks.IOSSNMPBlock, BlockLayers, error) {
	var sc, dv *blocks.IOSSNMPBlock
	var layers BlockLayers
	if scopeText != nil {
		b, findings := blocks.LintIOSSNMP(string(scopeText), blocks.LayerScope)
		if err := blockFindingsError(blocks.VendorCisco, blocks.ScopeLevel(scope), blocks.BlockSNMP, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		sc, layers.Scope = b, true
	}
	if deviceText != nil {
		b, findings := blocks.LintIOSSNMP(string(deviceText), blocks.LayerDevice)
		if err := blockFindingsError(blocks.VendorCisco, blocks.DeviceLevel(device), blocks.BlockSNMP, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		dv, layers.Device = b, true
	}
	if sc == nil && dv == nil {
		return nil, BlockLayers{}, nil
	}
	r := blocks.ResolveIOSSNMP(nil, sc, dv)
	if r.Empty() || len(blocks.IOSSNMPStatements(r)) == 0 {
		return nil, BlockLayers{}, nil
	}
	return r, layers, nil
}

// ResolveSNMPTexts is ResolveSNMPBlock for texts already in hand: a nil text
// is a layer that has no block. 'check --against' plans a device with a text
// that is not yet in force through it.
func ResolveSNMPTexts(scope, device string, scopeText, deviceText []byte) (*blocks.SNMPBlock, BlockLayers, error) {
	var sc, dv *blocks.SNMPBlock
	var layers BlockLayers
	if scopeText != nil {
		b, findings := blocks.Lint(string(scopeText), blocks.LayerScope)
		if err := blockFindingsError(blocks.VendorJuniper, blocks.ScopeLevel(scope), blocks.BlockSNMP, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		sc, layers.Scope = b, true
	}
	if deviceText != nil {
		b, findings := blocks.Lint(string(deviceText), blocks.LayerDevice)
		if err := blockFindingsError(blocks.VendorJuniper, blocks.DeviceLevel(device), blocks.BlockSNMP, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		dv, layers.Device = b, true
	}
	if sc == nil && dv == nil {
		return nil, BlockLayers{}, nil
	}
	r := blocks.Resolve(nil, sc, dv)
	if r.Empty() {
		return nil, BlockLayers{}, nil
	}
	return r, layers, nil
}

// ResolveSystemBlock is the Junos system block of a scope, and of one device
// of it when device is not empty, as the renderers take it, with the same
// rules as ResolveSNMPBlock: nil when no layer has one in force, an error
// (naming the scope or device and the verb that checks it, holding no part
// of the login message and no key) when a layer cannot be rendered whole.
// A block of delete lines only renders nothing.
func ResolveSystemBlock(store *blocks.Store, c *conf.Config, scope, device string) (*blocks.SystemBlock, BlockLayers, error) {
	scopeText, deviceText, err := layerTexts(store, c, blocks.VendorJuniper, scope, device, blocks.BlockSystem)
	if err != nil {
		return nil, BlockLayers{}, err
	}
	return ResolveSystemTexts(scope, device, scopeText, deviceText)
}

// ResolveSystemTexts is ResolveSystemBlock for texts already in hand.
func ResolveSystemTexts(scope, device string, scopeText, deviceText []byte) (*blocks.SystemBlock, BlockLayers, error) {
	var sc, dv *blocks.SystemBlock
	var layers BlockLayers
	if scopeText != nil {
		b, findings := blocks.LintSystem(string(scopeText), blocks.LayerScope)
		if err := blockFindingsError(blocks.VendorJuniper, blocks.ScopeLevel(scope), blocks.BlockSystem, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		sc, layers.Scope = b, true
	}
	if deviceText != nil {
		b, findings := blocks.LintSystem(string(deviceText), blocks.LayerDevice)
		if err := blockFindingsError(blocks.VendorJuniper, blocks.DeviceLevel(device), blocks.BlockSystem, findings); err != nil {
			return nil, BlockLayers{}, err
		}
		dv, layers.Device = b, true
	}
	if sc == nil && dv == nil {
		return nil, BlockLayers{}, nil
	}
	r := blocks.ResolveSystem(nil, sc, dv)
	if !hasSystemStatement(r) {
		return nil, BlockLayers{}, nil
	}
	return r, layers, nil
}

// hasSystemStatement reports whether the resolved block states anything to
// render (a block with delete lines only renders nothing).
func hasSystemStatement(b *blocks.SystemBlock) bool {
	return b != nil && len(blocks.SystemStatements(b)) > 0
}

// layerTexts are the texts of the scope's and the device's file of a block,
// nil for a layer that has none in force.
func layerTexts(store *blocks.Store, c *conf.Config, vendor, scope, device, block string) (scopeText, deviceText []byte, err error) {
	if scopeText, err = LayerTextFor(store, c, vendor, blocks.ScopeLevel(scope), block); err != nil {
		return nil, nil, err
	}
	if device != "" {
		if deviceText, err = LayerTextFor(store, c, vendor, blocks.DeviceLevel(device), block); err != nil {
			return nil, nil, err
		}
	}
	return scopeText, deviceText, nil
}

// LayerText is the text of one level's Junos block when it is in force and
// its file exists: nil, nil when there is none to render, an error when the
// file cannot be read. The first line of the error says it all: a batch keeps
// the first line of a refusal as the device's reason.
func LayerText(store *blocks.Store, c *conf.Config, l blocks.Level, block string) ([]byte, error) {
	return LayerTextFor(store, c, blocks.VendorJuniper, l, block)
}

// LayerTextFor is LayerText for a vendor's block (juniper or cisco).
func LayerTextFor(store *blocks.Store, c *conf.Config, vendor string, l blocks.Level, block string) ([]byte, error) {
	if store == nil || c == nil || l.Validate() != nil {
		return nil, nil
	}
	if l.IsDevice() {
		if !DeviceBlockInForce(c, l.Device, vendor, block) {
			return nil, nil
		}
	} else if !BlockInForce(c, l.Scope, vendor, block) {
		return nil, nil
	}
	text, err := store.Read(l, vendor, block)
	switch {
	case errors.Is(err, blocks.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, &names.Error{Msgs: []string{
			fmt.Sprintf("The %s block of %s cannot be read, so nothing is rendered for %s (%s). Look at it with: %s",
				block, levelWord(l), renderedFor(vendor, l), strings.Join(errLines(err), " "), CheckVerbFor(vendor, l, block)),
		}}
	}
	if text == nil {
		text = []byte{}
	}
	return text, nil
}

// CheckVerb is the command line that lints a level's Junos block.
func CheckVerb(l blocks.Level, block string) string {
	return CheckVerbFor(blocks.VendorJuniper, l, block)
}

// CheckVerbFor is the command line that lints a level's block of a vendor.
func CheckVerbFor(vendor string, l blocks.Level, block string) string {
	if l.IsDevice() {
		return "tacctl device block " + l.Device + " check " + block
	}
	return "tacctl scope block " + l.Scope + " " + vendor + " check " + block
}

// levelWord is "scope 'lab'" or "device 'sw1'".
func levelWord(l blocks.Level) string {
	if l.IsDevice() {
		return "device '" + l.Device + "'"
	}
	return "scope '" + l.Scope + "'"
}

// renderedFor is who a refusal says gets nothing.
func renderedFor(vendor string, l blocks.Level) string {
	word := "Junos"
	if vendor == blocks.VendorCisco {
		word = "IOS"
	}
	if l.IsDevice() {
		return "the device's " + word + " configuration"
	}
	return "the scope's " + word + " devices"
}

// blockFindingsError is the refusal of a block with an error finding (nil
// when it has none): a block is never rendered in part.
func blockFindingsError(vendor string, l blocks.Level, block string, findings []blocks.Finding) error {
	if !blocks.HasErrors(findings) {
		return nil
	}
	msgs := []string{fmt.Sprintf("The %s block of %s has errors, so nothing is rendered for %s (a block is never rendered in part). Fix it, then run: %s",
		block, levelWord(l), renderedFor(vendor, l), CheckVerbFor(vendor, l, block))}
	shown := 0
	for _, f := range findings {
		if f.Severity != blocks.SevError {
			continue
		}
		if shown == maxBlockFindings {
			msgs = append(msgs, "  ...")
			break
		}
		shown++
		msgs = append(msgs, "  "+f.String())
	}
	return &names.Error{Msgs: msgs}
}

// errLines are the lines of an error (a names.Error has several).
func errLines(err error) []string {
	var ne *names.Error
	if errors.As(err, &ne) {
		return ne.Lines()
	}
	return []string{err.Error()}
}
