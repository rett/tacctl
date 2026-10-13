package cli

// 'adopt' of the configuration blocks (0.2.7, docs/plans/0.2.7-blocks-plan.md
// B6): a device's own statements of the hierarchy a block is for, read
// live with the caller's login and opened in the editor as the draft to
// prune (a Junos device's snmp or system hierarchy, an IOS device's
// 'snmp-server' lines and the access lists its communities name).
//
//	tacctl scope block <scope> {juniper|cisco} adopt <device> <block>
//	tacctl device block <device> adopt <block>
//
// The read is a device pull's: the same password source and cache, the same
// transport choice and timeout, the same host key handling and wording; one
// device, one login. Nothing of the device's text is stored: it exists in
// memory and in the editor's private copy, which is removed afterwards. What
// the draft holds and leaves out is internal/blocks' (AdoptSNMP,
// AdoptSystem, AdoptIOSSNMP); the flow after the editor is edit's
// (editFlow).

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// hierarchyOf is the hierarchy of the device's configuration a block is
// read from.
func hierarchyOf(block string) string {
	if block == blocks.BlockSystem {
		return "system"
	}
	return "snmp"
}

// adoptRead is what reading one hierarchy returned.
type adoptRead struct {
	raw       string
	transport string
}

// readHierarchy logs in to the device as the caller and reads one hierarchy
// of its configuration, as a pull does: the transport the settings say
// (NETCONF with the command line as the fallback under auto), the password
// from the cache or the terminal, the host key pinned. A failure is the
// reason in the words of the pull and the hint, as an error.
func (inv *invocation) readHierarchy(e devreg.Entry, user, hierarchy string) (adoptRead, error) {
	var out adoptRead
	st := inv.deviceConfigSettings()
	pw := newDevicePasswords(inv)
	defer func() {
		if d, ok := pw.(interface{ Done() }); ok {
			d.Done()
		}
	}()
	secret, err := pw.Password(inv.ctx, user)
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			return out, err
		}
		return out, errors.New("cannot log in to " + e.Name + ": " + err.Error())
	}
	password := string(secret)
	askpass.Zero(secret)

	ctx, cancel := context.WithTimeout(inv.ctx, st.timeout)
	defer cancel()
	fail := func(err error) (adoptRead, error) {
		result, reason, hint := resultOf(ctx, e.Name, err)
		var hk devssh.ErrHostKey
		if errors.As(err, &hk) {
			inv.noteHostKeys([]devreg.Entry{e}, []*pullOutcome{{Offered: hk.Offered}})
		}
		if errors.Is(err, devssh.ErrAuth) {
			pw.Rejected()
		}
		inv.app.Logger(inv.ctx, "auth.warning", "block adopt-read user="+user+" device="+e.Name+" result="+result)
		msg := "Cannot read " + e.Name + ": " + reason + "."
		if hint != "" {
			msg += " Run: " + hint
		}
		return out, errors.New(msg)
	}
	client, err := devssh.Dial(ctx, inv.deviceTarget(e, user, func() (string, error) { return password, nil }))
	if err != nil {
		return fail(err)
	}
	defer func() { _ = client.Close() }()
	pw.Accepted()

	text, transport, err := readHierarchyText(ctx, client, e.Vendor, hierarchy, st.transport)
	if err != nil {
		return fail(err)
	}
	inv.app.Logger(inv.ctx, "auth.info", "block adopt-read user="+user+" device="+e.Name+" transport="+transport+" result=ok")
	return adoptRead{raw: text, transport: transport}, nil
}

// readHierarchyText reads the hierarchy over NETCONF where the mode allows
// and the device answers, over the command line otherwise (readDeviceConfig's
// choice: 'auto' falls back, 'netconf' and 'ssh' never do).
func readHierarchyText(ctx context.Context, c *devssh.Client, vendor, hierarchy, mode string) (text, transport string, err error) {
	// NETCONF is a Junos transport: an IOS device is read over its command
	// line whatever the mode says (a pull does the same).
	if fam, _ := devconf.Family(vendor); mode != transportSSH && fam == devconf.FamilyJunos {
		ns, nerr := c.NETCONF()
		if nerr == nil {
			text, err := func() (string, error) {
				defer func() { _ = ns.Close() }()
				return devconf.ReadHierarchy(ctx, netconfRunner{ns}, vendor, hierarchy)
			}()
			if err == nil {
				return text, transportNetconf, nil
			}
			if mode == transportNetconf || ctx.Err() != nil {
				return "", "", err
			}
		} else if mode == transportNetconf || ctx.Err() != nil {
			return "", "", nerr
		}
	}
	s, err := c.CLI(vendor)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = s.Close() }()
	text, err = devconf.ReadHierarchy(ctx, s, vendor, hierarchy)
	return text, transportSSH, err
}

// adopt is 'adopt [<device>] <block> [-y]'; device is "" at the device
// level, where the device is the level's own.
func (c *blockCtx) adopt(block, device string, p Parsed) error {
	inv := c.inv
	a := inv.app
	if err := c.requireSuperuser("adopt"); err != nil {
		return err
	}
	if err := inv.terminalRequired("adopt"); err != nil {
		return err
	}
	if err := inv.editorAllowed("adopt"); err != nil {
		return err
	}
	if err := inv.confWritable(); err != nil {
		return err
	}
	cur := c.file(block)
	if cur.err != nil {
		return cur.err
	}
	// What the file in force says is the block this draft goes beneath.
	var same *blocks.SNMPBlock
	var sameSys *blocks.SystemBlock
	var sameIOS *blocks.IOSSNMPBlock
	var sameIOSSys *blocks.IOSSystemBlock
	if cur.exists {
		doc, fs, err := blocks.LintFor(c.vendor, block, string(cur.text), c.layer())
		if err != nil {
			return err
		}
		if blocks.HasErrors(fs) {
			return inv.usageErr(append([]string{"The " + block + " block of " + c.what() + " has errors, so a draft cannot be put beneath it:"},
				c.errorLines(fs)...)...)
		}
		same, _ = doc.(*blocks.SNMPBlock)
		sameSys, _ = doc.(*blocks.SystemBlock)
		sameIOS, _ = doc.(*blocks.IOSSNMPBlock)
		sameIOSSys, _ = doc.(*blocks.IOSSystemBlock)
	}
	// The layer beneath: a device's draft is the exceptions to its scope's.
	var up *blocks.SNMPBlock
	var upSys *blocks.SystemBlock
	var upIOS *blocks.IOSSNMPBlock
	var upIOSSys *blocks.IOSSystemBlock
	if c.isDevice() {
		text, err := policy.LayerTextFor(c.store(), a.Conf(), c.vendor, blocks.ScopeLevel(c.scope), block)
		if err != nil {
			return inv.usageErr(msgs(err)...)
		}
		if text != nil {
			doc, fs, err := blocks.LintFor(c.vendor, block, string(text), blocks.LayerScope)
			if err != nil {
				return err
			}
			if blocks.HasErrors(fs) {
				return inv.usageErr("The " + block + " block of scope '" + c.scope + "' has errors, so a device's draft cannot be made beneath it: tacctl scope block " +
					c.scope + " " + c.vendor + " check " + block)
			}
			up, _ = doc.(*blocks.SNMPBlock)
			upSys, _ = doc.(*blocks.SystemBlock)
			upIOS, _ = doc.(*blocks.IOSSNMPBlock)
			upIOSSys, _ = doc.(*blocks.IOSSystemBlock)
		}
	}

	// The device: one of this scope (scope level) or the level's own.
	user, err := inv.configLogin("block adopt")
	if err != nil {
		return err
	}
	name := device
	if c.isDevice() {
		name = c.dev.Name
	}
	chosen, err := inv.chooseDevices(selection{names: []string{name}}, user, true, "pull", managedOptions{})
	if err != nil {
		return err
	}
	if len(chosen.entries) != 1 {
		return inv.usageErr("Device '" + name + "' cannot be read.")
	}
	e := chosen.entries[0]
	switch {
	case e.Source != devreg.SourceDevice:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host, not a device with a configuration.")
	case e.Vendor != c.vendor:
		return inv.usageErr("'" + e.Name + "' is not " + vendorWordOf(c.vendor) + " device: the blocks of vendor " + c.vendor + " are its vendor's syntax.")
	case !c.isDevice() && e.Scope != c.level.Scope:
		return inv.usageErr("Device '" + e.Name + "' is in " + scopeWord(e.Scope) + ", not in scope '" + c.level.Scope + "': a block of this scope is not rendered for it.")
	}

	// What tacctl renders itself for it (the structured settings are not a
	// block's).
	own := blocks.AdoptOwn{}
	if block == blocks.BlockSNMP && c.vendor == blocks.VendorCisco {
		secs, err := chosen.render.Expected(e)
		if errors.Is(err, errSyntaxUnknown) {
			// the community is the same in either syntax
			secs, err = chosen.render.ExpectedAs(e, false)
		}
		if err != nil {
			return inv.usageErr("Cannot tell what tacctl renders for " + e.Name + " (" + strings.Join(msgs(err), " ") + "), so its SNMP statements cannot be told from the settings'. Nothing was changed.")
		}
		for _, s := range secs {
			if s.Name != "snmp" {
				continue
			}
			for i, l := range s.Lines {
				if s.Block != nil && s.Block[i] {
					continue
				}
				if f := strings.Fields(l); len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community" && own.Community == "" {
					own.Community = f[2]
				}
			}
		}
	} else if block == blocks.BlockSNMP {
		secs, err := chosen.render.Expected(e)
		if err != nil {
			return inv.usageErr("Cannot tell what tacctl renders for " + e.Name + " (" + strings.Join(msgs(err), " ") + "), so its SNMP statements cannot be told from the settings'. Nothing was changed.")
		}
		own.Lines = map[string]bool{}
		for _, s := range secs {
			if s.Name != "snmp" {
				continue
			}
			for i, l := range s.Lines {
				if s.Block != nil && s.Block[i] {
					continue
				}
				own.Lines[l] = true
				if f := strings.Fields(l); len(f) >= 4 && f[1] == "snmp" && f[2] == "community" && own.Community == "" {
					own.Community = f[3]
				}
			}
		}
	}

	read, err := inv.readHierarchy(e, user, hierarchyOf(block))
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			return err
		}
		return inv.usageErr(msgs(err)...)
	}
	// The read holds every community string of the device: its use is a
	// reveal's, logged whoever reads (the name, never a value).
	inv.secretRead("block-adopt", c.logName(block))

	var res blocks.AdoptResult
	switch {
	case block == blocks.BlockSNMP && c.vendor == blocks.VendorCisco:
		res = blocks.AdoptIOSSNMP(read.raw, own, sameIOS, upIOS)
	case block == blocks.BlockSNMP:
		res = blocks.AdoptSNMP(read.raw, own, same, up)
	case c.vendor == blocks.VendorCisco:
		res = blocks.AdoptIOSSystem(read.raw, sameIOSSys, upIOSSys)
	default:
		res = blocks.AdoptSystem(read.raw, sameSys, upSys)
	}
	read.raw = ""

	title := "Draft of the " + block + " block of " + c.what() + " from " + e.Name + " (read as " + user + " over " + read.transport + "; nothing of it is stored)"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	inv.echo("  " + strconv.Itoa(res.Statements) + " " + plural(res.Statements, "statement", "statements") + " in " +
		strconv.Itoa(res.Objects) + " " + plural(res.Objects, "object", "objects") + " to prune.")
	for _, n := range res.Notes {
		inv.echo("  " + n + ".")
	}
	for _, l := range res.Left {
		inv.echo("  left out: " + l + ".")
	}
	inv.echo("")
	if res.Text == "" {
		a.Out.Info("Nothing to adopt from " + e.Name + " into the " + block + " block of " + c.what() + ". Nothing was changed.")
		return nil
	}

	var head []string
	head = append(head, "adopted from "+e.Name+" at "+a.Knobs.Now().UTC().Format("2006-01-02 15:04")+" UTC (a live read; the device's text was not stored).")
	head = append(head, "Remove what this block should not own: each object left below becomes owned by tacctl once the block is in force.")
	for _, n := range res.Notes {
		head = append(head, n+".")
	}
	for _, l := range res.Left {
		head = append(head, "left out: "+l+".")
	}
	var seed strings.Builder
	if cur.exists {
		seed.WriteString(strings.TrimRight(string(cur.text), "\n") + "\n\n")
	}
	for _, h := range head {
		seed.WriteString("# " + h + "\n")
	}
	seed.WriteString(res.Text)
	return c.editFlow(block, seed.String(), cur, "adopt", "the text adopted from "+e.Name+" and edited", p.Has("-y"))
}
