package cli

// 'device config-syntax' (docs/plans/0.2.5-plan.md D113): the Cisco
// configuration syntax of a device as a fact of its own. 'auto' (the
// default) takes it from the version line the last pull read; 'ios12' and
// 'modern' say it. The comparison (pull, diff, list), the walkthrough
// (device config show, config cisco --name) and the planner all resolve it
// with syntaxOf; the ssh flag (legacy-ssh) has no part in it.

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
)

// configSyntaxText is how 'device show' and 'device config-syntax <name>'
// say a device's setting: the word, and for auto what it resolves to and
// from where (the resolution is part of the configuration state, which the
// read-only tier is not shown).
func (inv *invocation) configSyntaxText(e devreg.Entry) string {
	if e.ConfigSyntax != "" {
		return e.ConfigSyntax
	}
	if e.Vendor != "cisco" || !inv.configVisible() {
		return devreg.SyntaxAuto
	}
	rec, _ := inv.configRecords().Of(e.Name)
	r := syntaxOf(e, rec)
	if r.Syntax == "" {
		return devreg.SyntaxAuto + " (unknown until the device is pulled: tacctl device config pull " + e.Name + ")"
	}
	when := "the last pull"
	if rec != nil && !rec.Pulled.IsZero() {
		when = "the pull of " + rec.Pulled.UTC().Format("2006-01-02")
	}
	if r.Guessed {
		return fmt.Sprintf("%s (%s, guessed from \"%s\" in %s)", devreg.SyntaxAuto, r.Syntax, cleanLine(rec.OS), when)
	}
	return fmt.Sprintf("%s (%s, from %s)", devreg.SyntaxAuto, r.Syntax, when)
}

// walkthroughSyntax is the syntax a walkthrough for a registered Cisco
// device is rendered in, and the one line it says when nothing settles it
// (D113 (3)): the setting, else the last pull's, else the modern syntax.
// legacy is Request.Legacy (the IOS 12.x syntax); note is "" unless the
// walkthrough fell back for want of a pull.
func (inv *invocation) walkthroughSyntax(e devreg.Entry) (legacy bool, note string) {
	var rec *devconf.Record
	if inv.configRecords() != nil {
		rec, _ = inv.configRecords().Of(e.Name)
	}
	switch syntaxOf(e, rec).Syntax {
	case devconf.SyntaxIOS12:
		return true, ""
	case devconf.SyntaxModern:
		return false, ""
	}
	return false, "# syntax: modern (no pull yet; set 'tacctl device config-syntax " + e.Name +
		" ios12' for IOS 12.x, or pull the device once)"
}

// deviceConfigSyntax is 'device config-syntax <name> [auto|ios12|modern]':
// no word prints the setting (and what it resolves to).
func (inv *invocation) deviceConfigSyntax(args []string) error {
	p, err := inv.deviceParse("config-syntax", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	if len(p.Args) == 1 {
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		if e.Source == devreg.SourceHost {
			return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; it has no configuration syntax.")
		}
		inv.echo(inv.configSyntaxText(e))
		return nil
	}
	set, serr := devreg.ValidateConfigSyntax(p.Args[1])
	if serr != nil {
		return inv.usageErr(append(msgs(serr), "Usage: tacctl device config-syntax <name> [auto|ios12|modern]")...)
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	if set != "" && d.Vendor != "cisco" {
		return inv.usageErr("Device '" + d.Name + "' has vendor '" + d.Vendor + "'; the configuration syntax is a Cisco setting.")
	}
	name := d.Name
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find(name).ConfigSyntax = set
		return nil
	}); err != nil {
		return err
	}
	word := p.Args[1]
	if word == "" {
		word = devreg.SyntaxAuto
	}
	inv.app.Out.Info("Device '" + name + "' config-syntax " + word + ".")
	if set == "" && strings.EqualFold(d.Vendor, "cisco") {
		inv.echo("  The syntax now comes from the last pull's version line: tacctl device config pull " + name)
	}
	return nil
}
