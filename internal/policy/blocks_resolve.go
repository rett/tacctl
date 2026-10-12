package policy

// The snmp and system blocks a scope's devices are rendered with (0.2.7, B3
// and B7): the file the manifest names, held to the grammar at the scope's
// layer, resolved (device layer: none yet, B8 adds it; default layer: no file
// exists). A block with an error is never half rendered: the call fails and
// names the scope and the verb that says what is wrong.

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

// ResolveSNMPBlock is the Junos snmp block of a scope as the renderers take
// it: nil when the scope has none in force (no manifest entry, or an entry
// with no file, which 'check' reports and which renders nothing), or an
// error when the block cannot be rendered whole. The error names the scope,
// holds no community string (the findings of internal/blocks never do) and
// says to run 'tacctl scope block <scope> juniper check snmp'.
func ResolveSNMPBlock(store *blocks.Store, c *conf.Config, scope string) (*blocks.SNMPBlock, error) {
	text, err := scopeBlockText(store, c, scope, blocks.BlockSNMP)
	if text == nil || err != nil {
		return nil, err
	}
	b, findings := blocks.Lint(string(text), blocks.LayerScope)
	if err := blockFindingsError(scope, blocks.BlockSNMP, findings); err != nil {
		return nil, err
	}
	r := blocks.Resolve(nil, b, nil)
	if r.Empty() {
		return nil, nil
	}
	return r, nil
}

// ResolveSystemBlock is the Junos system block of a scope as the renderers
// take it, with the same rules as ResolveSNMPBlock: nil when none is in
// force, an error (naming the scope and 'tacctl scope block <scope> juniper
// check system', holding no part of the login message and no key) when it
// cannot be rendered whole. The default and device layers hold none yet (B8
// adds the device's), so the result is the scope's block with the delete
// lines applied.
func ResolveSystemBlock(store *blocks.Store, c *conf.Config, scope string) (*blocks.SystemBlock, error) {
	text, err := scopeBlockText(store, c, scope, blocks.BlockSystem)
	if text == nil || err != nil {
		return nil, err
	}
	b, findings := blocks.LintSystem(string(text), blocks.LayerScope)
	if err := blockFindingsError(scope, blocks.BlockSystem, findings); err != nil {
		return nil, err
	}
	r := blocks.ResolveSystem(nil, b, nil)
	if !hasSystemStatement(r) {
		return nil, nil
	}
	return r, nil
}

// hasSystemStatement reports whether the resolved block states anything to
// render (a block with delete lines only renders nothing).
func hasSystemStatement(b *blocks.SystemBlock) bool {
	return b != nil && len(blocks.SystemStatements(b)) > 0
}

// scopeBlockText is the text of the scope's Junos block when it is in force
// and its file exists: nil, nil when there is none to render, an error when
// the file cannot be read. The first line of the error says it all: a batch
// keeps the first line of a refusal as the device's reason.
func scopeBlockText(store *blocks.Store, c *conf.Config, scope, block string) ([]byte, error) {
	if store == nil || c == nil || blocks.ValidateScope(scope) != nil ||
		!BlockInForce(c, scope, blocks.VendorJuniper, block) {
		return nil, nil
	}
	check := "tacctl scope block " + scope + " juniper check " + block
	text, err := store.Read(blocks.ScopeLevel(scope), blocks.VendorJuniper, block)
	switch {
	case errors.Is(err, blocks.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, &names.Error{Msgs: []string{
			fmt.Sprintf("The %s block of scope '%s' cannot be read, so nothing is rendered for the scope's Junos devices (%s). Look at it with: %s",
				block, scope, strings.Join(errLines(err), " "), check),
		}}
	}
	return text, nil
}

// blockFindingsError is the refusal of a block with an error finding (nil
// when it has none): a block is never rendered in part.
func blockFindingsError(scope, block string, findings []blocks.Finding) error {
	if !blocks.HasErrors(findings) {
		return nil
	}
	check := "tacctl scope block " + scope + " juniper check " + block
	msgs := []string{fmt.Sprintf("The %s block of scope '%s' has errors, so nothing is rendered for the scope's Junos devices (a block is never rendered in part). Fix it, then run: %s",
		block, scope, check)}
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
