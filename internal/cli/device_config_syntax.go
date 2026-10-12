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

// pullDate is how a message names the pull a record holds ('the pull of
// 2026-10-10'; 'the last pull' for a record with no time).
func pullDate(rec *devconf.Record) string {
	if rec != nil && !rec.Pulled.IsZero() {
		return "the pull of " + rec.Pulled.UTC().Format("2006-01-02")
	}
	return "the last pull"
}

// imageText names the image a version line stands for, for a message: the
// version number when the line has one ('IOS 12.4(15)SW'), the line itself
// (quoted) otherwise.
func imageText(os string) string {
	if v := devconf.ImageVersion(os); v != "" {
		return "IOS " + v
	}
	return "\"" + cleanLine(os) + "\""
}

// conflictText says that an explicit setting contradicts what the record's
// version line derives to (D113: the setting wins; the contradiction is
// shown, never refused). r is syntaxOf(e, rec) with Conflict set.
func conflictText(rec *devconf.Record, r devconf.SyntaxResolution) string {
	return fmt.Sprintf("%s read %s, which is %s syntax, not %s", pullDate(rec), imageText(rec.OS), r.ImageSyntax, r.Syntax)
}

// configSyntaxText is how 'device show' and 'device config-syntax <name>'
// say a device's setting: the word, and for auto what it resolves to and
// from where (the resolution is part of the configuration state, which the
// read-only tier is not shown). An explicit setting that the last pull's
// version line contradicts says so (the setting still wins).
func (inv *invocation) configSyntaxText(e devreg.Entry) string {
	if e.ConfigSyntax != "" {
		if e.Vendor == "cisco" && inv.configVisible() {
			if rec, _ := inv.configRecords().Of(e.Name); rec != nil {
				if r := syntaxOf(e, rec); r.Conflict {
					return fmt.Sprintf("%s (%s: check the setting)", e.ConfigSyntax, conflictText(rec, r))
				}
			}
		}
		return e.ConfigSyntax
	}
	if e.Vendor != "cisco" || !inv.configVisible() {
		return devreg.SyntaxAuto
	}
	rec, _ := inv.configRecords().Of(e.Name)
	r := syntaxOf(e, rec)
	if r.Syntax == "" {
		if rec != nil && strings.TrimSpace(rec.OS) != "" {
			return fmt.Sprintf("%s (unknown: %s read \"%s\", which tacctl does not map to a syntax; set one: tacctl device config-syntax %s ios12|modern)",
				devreg.SyntaxAuto, pullDate(rec), cleanLine(rec.OS), e.Name)
		}
		return devreg.SyntaxAuto + " (unknown until the device is pulled: tacctl device config pull " + e.Name + ")"
	}
	return fmt.Sprintf("%s (%s, from %s)", devreg.SyntaxAuto, r.Syntax, pullDate(rec))
}

// walkthroughSyntax is the syntax a walkthrough for a registered Cisco
// device is rendered in, and the one line it says when something about it
// needs saying (D113 (3)): the setting, else the last pull's, else the
// modern syntax. legacy is Request.Legacy (the IOS 12.x syntax); note is ""
// unless the walkthrough fell back for want of a syntax (never pulled, a
// pull that held no image line, an image tacctl does not map) or the
// explicit setting contradicts the pull (the setting wins; the note warns).
func (inv *invocation) walkthroughSyntax(e devreg.Entry) (legacy bool, note string) {
	var rec *devconf.Record
	if inv.configRecords() != nil {
		rec, _ = inv.configRecords().Of(e.Name)
	}
	r := syntaxOf(e, rec)
	switch r.Syntax {
	case devconf.SyntaxIOS12, devconf.SyntaxModern:
		legacy = r.Syntax == devconf.SyntaxIOS12
		if r.Conflict {
			note = "# warning: config-syntax of " + e.Name + " is " + r.Syntax + " but " + conflictText(rec, r) +
				"; this follows the setting (tacctl device config-syntax " + e.Name + " auto follows the pull)"
		}
		return legacy, note
	}
	pulled := rec != nil && (!rec.Pulled.IsZero() || len(rec.Sections) > 0)
	switch {
	case pulled && strings.TrimSpace(rec.OS) != "":
		return false, "# syntax: modern (" + pullDate(rec) + " read \"" + cleanLine(rec.OS) +
			"\", which tacctl does not map to a syntax; set 'tacctl device config-syntax " + e.Name + " ios12' for IOS 12.x)"
	case pulled:
		return false, "# syntax: modern (the last pull holds no image line: run device config pull " + e.Name +
			", or set 'tacctl device config-syntax " + e.Name + " ios12' for IOS 12.x)"
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
	// A setting that the last pull's image contradicts is said at once, not
	// at the next walkthrough: the setting wins, and it is the lock-out
	// direction when a 12.x image is rendered in the modern syntax.
	if set != "" && strings.EqualFold(d.Vendor, "cisco") && inv.configVisible() {
		if rec, _ := inv.configRecords().Of(name); rec != nil {
			if img, conflict := devconf.ConflictOf(set, rec.OS); conflict {
				inv.app.Out.Warn("The setting contradicts the image: " + conflictText(rec, devconf.SyntaxResolution{Syntax: set, ImageSyntax: img}) + ".")
			}
		}
	}
	if set == "" && strings.EqualFold(d.Vendor, "cisco") {
		inv.echo("  The syntax now comes from the last pull's version line: tacctl device config pull " + name)
	}
	return nil
}
