package cli

// 'tacctl backup keep <snapshot> [--note <text>]' and 'backup unkeep
// <snapshot> [--yes]' (docs/plans/0.2.23-plan.md D302): the persist marker of
// a snapshot. Snapshots are kept in backups/, of which this release prunes
// the oldest beyond 30 and the older releases a rollback goes to do the same
// without knowing any marker, so a snapshot that matters (the one a rollback
// names as the record of what it dropped, one taken before a risky change)
// is copied to backups-kept/<id>/, where no retention reaches. The copy is
// a snapshot like any other: 'backup list' shows it, and 'backup diff',
// 'restore' and 'recover' find an id in backups/ first and then there, so
// they work on a kept copy whose original is long gone. A note says why it
// is kept; it is free text stored in the copy and never written to the audit
// log (it is not a place for secrets).
//
// The kept copies are not part of a snapshot: 'backup restore' does not touch
// backups-kept/, and 'uninstall' archives it beside backups/ when the
// backups are preserved.

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

const (
	backupKeepUsage   = "Usage: tacctl backup keep <timestamp> [--note <text>]"
	backupUnkeepUsage = "Usage: tacctl backup unkeep <timestamp> [--yes]"
	// keptNoteMax is the longest note.
	keptNoteMax = 200
)

// keepNote checks a note: valid UTF-8 text of at most keptNoteMax characters
// made of printable characters and plain spaces (no control character, no
// format character such as a zero-width space or a right-to-left override,
// no other white space).
func keepNote(note string) bool {
	if !utf8.ValidString(note) || len([]rune(note)) > keptNoteMax {
		return false
	}
	return !strings.ContainsFunc(note, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (r != ' ' && !unicode.IsPrint(r))
	})
}

// keptInfo is the record 'backup keep' writes: who, from which session and when.
func (inv *invocation) keptInfo(note string) snapshot.KeptInfo {
	w := inv.app.Audit()
	return snapshot.KeptInfo{Note: note, User: w.Actor().User, SID: w.SID(),
		At: inv.app.Knobs.Now().UTC().Format("2006-01-02T15:04:05Z")}
}

// keepSnapshot keeps snapshot id with note and says what it did.
// It returns whether the copy was made now; the copy exists after it.
func (inv *invocation) keepSnapshot(id, note string) (created bool, err error) {
	a := inv.app
	if !inv.storeMode() {
		return false, inv.usageErr("No store yet: there are no snapshots to keep. " + store.NotInitialisedMsg)
	}
	if dir, _ := inv.snapDir(id); dir == "" {
		return false, inv.usageErr("Backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
	}
	if note == "" && snapshot.KeptPath(a.Paths.KeptDir, id) != "" {
		// kept already (the original may be gone: the copy is the snapshot)
		return false, nil
	}
	a.Audit().Touch()
	_, created, err = snapshot.Keep(a.Paths.BackupDir, a.Paths.KeptDir, id, inv.keptInfo(note))
	if err != nil {
		a.Out.ErrorE("Could not keep snapshot " + id + " in " + a.Paths.KeptDir + ": " + err.Error())
		return false, inv.usageErr("Nothing was changed.")
	}
	return created, nil
}

// backupKeep is the command.
func (inv *invocation) backupKeep(args []string) error {
	a := inv.app
	p, err := Parse(backupSpecs["keep"], args)
	if err != nil {
		return inv.usageErr(backupKeepUsage)
	}
	id := p.Args[0]
	note := strings.TrimSpace(p.Value("--note"))
	if p.Has("--note") && note == "" {
		return inv.usageErr(backupKeepUsage)
	}
	if !keepNote(note) {
		return inv.usageErr("A note is at most 200 characters, with no control character. Nothing was changed.")
	}
	wasKept := snapshot.KeptPath(a.Paths.KeptDir, id) != ""
	created, err := inv.keepSnapshot(id, note)
	if err != nil {
		return err
	}
	switch {
	case created:
		inv.detail("backup keep", kvp("id", id), kvp("note", yesNo(note != "")), kvp("already", "no"))
		a.Out.Info("Snapshot " + id + " kept in " + a.Paths.KeptDir + "/" + id + " (no retention reaches it; 'tacctl backup unkeep " + id + "' removes it).")
	case wasKept && note != "":
		inv.detail("backup keep", kvp("id", id), kvp("note", "yes"), kvp("already", "yes"))
		a.Out.Info("Snapshot " + id + " is kept already; its note is replaced.")
	default:
		a.Out.Info("Snapshot " + id + " is kept already.")
	}
	return nil
}

// backupUnkeep is the command.
func (inv *invocation) backupUnkeep(args []string) error {
	a := inv.app
	p, err := Parse(backupSpecs["unkeep"], args)
	if err != nil {
		return inv.usageErr(backupUnkeepUsage)
	}
	id := p.Args[0]
	if !snapshot.ValidID(id) || snapshot.KeptPath(a.Paths.KeptDir, id) == "" {
		return inv.usageErr("Snapshot "+id+" is not kept.", "Run 'tacctl backup list' to see the kept snapshots.")
	}
	onlyCopy := true
	if d, kept := inv.snapDir(id); d != "" && !kept {
		onlyCopy = false
	}
	inv.echo("")
	if onlyCopy {
		inv.echoE(ui.Red + "No snapshot " + id + " remains in backups/: the kept copy is the only copy." + ui.NC)
	}
	if !p.Has("--yes") && !a.Prompter().Confirm("  Remove the kept copy of snapshot "+id+"? [y/N]: ") {
		a.Out.Info("Cancelled.")
		return nil
	}
	a.Audit().Touch()
	if err := snapshot.Unkeep(a.Paths.KeptDir, id); err != nil {
		a.Out.ErrorE(err.Error())
		return inv.usageErr("Nothing was changed.")
	}
	inv.detail("backup unkeep", kvp("id", id), kvp("only-copy", yesNo(onlyCopy)))
	a.Out.Info("The kept copy of snapshot " + id + " is removed.")
	return nil
}
