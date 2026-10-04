package tacacs

// The units on disk: install, upgrade, and the conversion of an install
// from before the listener model (_tacacs_units_install and its helpers).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

// unitsInstall is _tacacs_units_install <tree>: bring the unit files and
// drop-ins of this machine to what this release ships and what
// tacctl.yaml says. One function for a fresh install, an upgrade and the
// conversion of an install from before the listener model; idempotent,
// and it needs no store.
//
//  1. copies   everything it may touch is copied first (unitsKeep)
//  2. import   the settings of the old layout go into tacctl.yaml: the
//     hand-managed drop-in (legacyImport) and, for units older still,
//     literal -network/-address/-level flags
//  3. stage    the drop-ins are rendered from tacctl.yaml and proven
//     (unitsStage): a listener model that cannot be served stops here
//  4. files    tacquito.service, tacquito@.service, the drop-ins; then the
//     hand-managed drop-in is retired; daemon-reload
//
// The running daemon is not touched: systemd keeps the process it started
// until the caller restarts the unit. Until step 4 nothing systemd reads
// has changed; a failure in 2-4 puts every file back from the copies (and
// reloads), so the old unit keeps running under the old files. The unit
// files and drop-ins are written by rename and compared before they are
// written, so a second pass over finished work changes nothing; a reload
// that never happened is caught by asking systemd (NeedDaemonReload).
//
// It sets life.unitsState: "" nothing to do, unitsChanged, or
// unitsStopped (refused or failed, files as they were; false). After
// unitsChanged the copies stay (life.unitsKeep) until the caller has
// restarted the unit: unitsKeepDiscard when it came up, unitsRollback
// when it did not. life.unitsNotes says what it did, one line each, for
// the caller to print.
func (b *Backend) unitsInstall(ctx context.Context, tree string) bool {
	l := &b.life
	l.unitsState, l.unitsKeep, l.unitsKept, l.unitsNotes = "", "", nil, nil
	p := b.env.Paths
	src := share(tree)
	if !isRegular(src+"/"+rtacacs.UnitName) || !isRegular(src+"/"+TemplateName) {
		b.unitsStopped("the unit files are not under " + src)
		return false
	}
	if !b.overridesReadable() {
		b.unitsStopped(p.Overrides + " cannot be read")
		return false
	}

	for _, d := range []string{p.StateDir, p.TacacsUnitDir} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			b.stderrLine("mkdir: " + err.Error())
			return false
		}
	}
	// Copies an interrupted run left behind.
	for _, old := range globSorted(filepath.Join(p.StateDir, ".units.*")) {
		_ = os.RemoveAll(old)
	}
	keep, err := os.MkdirTemp(p.StateDir, ".units.")
	if err != nil {
		b.stderrLine("mktemp: " + err.Error())
		return false
	}
	kept, err := b.unitsKeep(filepath.Join(keep, "keep"))
	if err != nil {
		_ = os.RemoveAll(keep)
		b.unitsStopped("the current unit files could not be copied")
		return false
	}

	legacy := b.legacyUnits()
	why := ""
	switch {
	case !b.unitsImportOld():
		why = "its settings could not be moved into " + p.Overrides
	case !b.unitsStage(keep):
		why = "the drop-ins could not be rendered from " + p.Overrides
	}
	if why != "" {
		b.unitsRestore(kept)
		_ = os.RemoveAll(keep)
		b.unitsStopped(why)
		return false
	}

	changed := false
	for _, f := range []string{rtacacs.UnitName, TemplateName} {
		from := src + "/" + f
		dest := filepath.Join(p.TacacsUnitDir, f)
		if sameBytes(from, dest) {
			continue
		}
		switch {
		case f == rtacacs.UnitName && isRegular(dest):
			if cpFile(dest, dest+".bak") != nil {
				why = dest + " could not be backed up"
			}
			l.unitsNotes = append(l.unitsNotes, "Updated: "+f+" (previous backed up to "+dest+".bak)")
		case isRegular(dest):
			l.unitsNotes = append(l.unitsNotes, "Updated: "+f)
		default:
			l.unitsNotes = append(l.unitsNotes, "Installed: "+f)
		}
		if why == "" && installUnitFile(from, dest) == nil {
			changed = true
			continue
		}
		_ = os.Remove(dest + ".tacctl-new")
		if why == "" {
			why = dest + " could not be written"
		}
		break
	}

	if why == "" {
		commit := b.renderer().CommitUnits
		if l.commitUnits != nil {
			commit = l.commitUnits
		}
		written, err := commit(keep)
		switch {
		case err != nil:
			why = "a drop-in could not be installed"
		case len(written) > 0:
			changed = true
			l.unitsNotes = append(l.unitsNotes, "Rendered: the listener drop-in of "+strings.Join(written, ", "))
		}
	}
	if why == "" && legacy {
		if b.legacyRetire() {
			changed = true
		} else {
			why = b.overrideFile() + " could not be retired"
		}
	}
	if why != "" {
		b.unitsRestore(kept)
		_ = os.RemoveAll(keep)
		b.run(ctx, "daemon-reload")
		b.unitsStopped(why)
		return false
	}

	if changed || b.showProperty(ctx, Service, "NeedDaemonReload") == "yes" {
		b.run(ctx, "daemon-reload")
	}
	if changed {
		l.unitsState, l.unitsKeep, l.unitsKept = unitsChanged, keep, kept
	} else {
		_ = os.RemoveAll(keep)
	}
	return true
}

// installUnitFile is 'cp <from> <dest>.tacctl-new && chmod 644 ... && mv
// -f ... <dest>'.
func installUnitFile(from, dest string) error {
	tmp := dest + ".tacctl-new"
	if err := cpFile(from, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

var (
	flagNetwork = regexp.MustCompile(`-network (\S+)`)
	flagAddress = regexp.MustCompile(`-address (\S+)`)
	flagLevel   = regexp.MustCompile(`-level ([0-9]+)`)
)

// firstMatch is "grep -oP '<flag> \K<value>' | head -1".
func firstMatch(re *regexp.Regexp, text string) string {
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// unitsImportOld is _tacacs_units_import_old, step 2 of unitsInstall: the
// hand-managed drop-in's settings, then the literal flags of a unit from
// before the drop-in (today's unit takes them from the environment,
// ${TACQUITO_*}). A literal that differs from the default and that
// tacctl.yaml does not already set is kept.
func (b *Backend) unitsImportOld() bool {
	if b.legacyUnits() && !b.legacyImport() {
		return false
	}
	svc := b.serviceFile()
	if !isRegular(svc) {
		return true
	}
	data, _ := os.ReadFile(svc)
	text := string(data)
	net, addr, level := firstMatch(flagNetwork, text), firstMatch(flagAddress, text), firstMatch(flagLevel, text)
	if strings.HasPrefix(net, "$") {
		net = ""
	}
	if strings.HasPrefix(addr, "$") {
		addr = ""
	}
	c, overrides := b.env.Conf, b.env.Paths.Overrides
	if net+addr != "" && or(net, "tcp")+" "+or(addr, ":49") != "tcp :49" && !c.HasOverride("listeners.tacacs.default") {
		if err := c.SetJSON("listeners.tacacs.default",
			fmt.Sprintf(`{"network": "%s", "address": "%s"}`, or(net, "tcp"), or(addr, ":49"))); err != nil {
			b.confError(err)
			return false
		}
		b.out().InfoE("  Migrated custom -network/-address flags of tacquito.service to " + overrides)
	}
	if level != "" && level != strconv.Itoa(rtacacs.LevelDefault) && !c.HasOverride("backends.tacacs.level") {
		if err := c.Set("backends.tacacs.level", level); err != nil {
			b.confError(err)
			return false
		}
		b.out().InfoE("  Migrated the custom -level flag of tacquito.service to " + overrides)
	}
	return true
}

// unitsStopped is _tacacs_units_stopped.
func (b *Backend) unitsStopped(why string) {
	b.life.unitsState = unitsStopped
	out := b.out()
	writeString(out.Stdout, "\n")
	out.WarnE("Unit update stopped: " + why + ".")
	out.WarnE("tacquito.service, its drop-in and the running daemon were left as they are; " + b.env.Paths.Overrides + " is unchanged.")
	out.Warn("Listener, log level and metrics settings keep working from the files in place. Fix what is reported above and run 'tacctl upgrade' again.")
	writeString(out.Stdout, "\n")
}

// unitsKeepDiscard is _tacacs_units_keep_discard: the restart proved the
// new unit files, the copies go.
func (b *Backend) unitsKeepDiscard() {
	if b.life.unitsKeep != "" {
		_ = os.RemoveAll(b.life.unitsKeep)
	}
	b.life.unitsKeep, b.life.unitsKept = "", nil
}

// unitsRollback is _tacacs_units_rollback: the unit did not come up under
// the new files; the previous ones go back (unit, template, drop-ins,
// tacctl.yaml, render records) and systemd is reloaded. The caller
// restarts. False when there are no copies.
func (b *Backend) unitsRollback(ctx context.Context) bool {
	if b.life.unitsKeep == "" || b.life.unitsKept == nil {
		return false
	}
	b.unitsRestore(b.life.unitsKept)
	b.unitsKeepDiscard()
	b.run(ctx, "daemon-reload")
	return true
}
