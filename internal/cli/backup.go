package cli

// The 'backup' family (lib/service.sh cmd_backup at 0.1.16) and its
// aliases 'config diff|restore', native since WP2.4d.
//
// With a store, a backup is a snapshot (internal/snapshot) and list, diff
// and restore work on those; old-style tacquito.yaml.<ts> copies are listed
// after them and can be diffed, and restored with --legacy (through the
// importer's check). Without a store (legacy read-only mode) nothing takes
// snapshots, and list, diff and restore work on the old-style files exactly
// as they always did: a snapshot found there (left by 'store rollback') is
// listed but refused, because restoring it would create the store without
// the import gate.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// KindBackups is the _completion-names kind of backup ids (snapshots
// newest first, then old-style backups, at most 50).
const KindBackups = "backups"

// backupSpecs are the arguments of each verb, for completion (args.go).
var backupSpecs = map[string]Spec{
	"list":    {},
	"diff":    {MaxArgs: 1, Args: []string{KindBackups}},
	"restore": {MinArgs: 1, MaxArgs: 1, Args: []string{KindBackups}, Flags: []Flag{{Names: []string{"--legacy"}}}},
}

// 'config diff' and 'config restore' are cmd_backup diff|restore.
func init() {
	registerConfigVerb("diff", backupSpecs["diff"], func(inv *invocation) *cobra.Command {
		return withRun(verb("diff [timestamp]", "Diff store.yaml and tacctl.yaml vs the last snapshot (or named one)"),
			inv.native(withPreflight, inv.backupDiff))
	})
	registerConfigVerb("restore", backupSpecs["restore"], func(inv *invocation) *cobra.Command {
		return withRun(verb("restore <timestamp> [--legacy]", "Restore a snapshot (prompts for confirmation)"),
			inv.native(withPreflight, inv.backupRestore))
	})
}

func backupCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	c := verb("backup <subcommand>", "Backup management (list, diff, restore)",
		withRun(verb("list", "Show snapshots, then old-style backups"), n(inv.backupList)),
		withRun(verb("diff [timestamp]", "Diff store.yaml and tacctl.yaml against a snapshot"), n(inv.backupDiff)),
		withRun(verb("restore <timestamp> [--legacy]", "Restore a snapshot (with confirmation)"), n(inv.backupRestore)),
	)
	// No sub-command or an unknown one: the usage, exit 1.
	c.RunE = n(func([]string) error {
		inv.write(Usage("backup", nil))
		return exit(1)
	})
	return c
}

// --- the backups on disk ------------------------------------------------------

// snapshotIDs is _backup_snapshot_ids: the snapshot ids, newest first.
func (inv *invocation) snapshotIDs() []string { return snapshot.IDs(inv.app.Paths.BackupDir) }

// legacyBackup is one old-style backup: its id (the file name without the
// leading 'tacquito.yaml.') and its path.
type legacyBackup struct{ id, path string }

// legacyBackups is _backup_legacy_entries: the regular files named
// tacquito.yaml.?* in backups/ and backups/legacy/, newest first by
// modification time (then by name, last first).
func (inv *invocation) legacyBackups() []legacyBackup {
	type entry struct {
		legacyBackup
		name  string
		mtime int64
	}
	var all []entry
	for _, dir := range []string{inv.app.Paths.BackupDir, filepath.Join(inv.app.Paths.BackupDir, "legacy")} {
		des, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range des {
			name := de.Name()
			if !de.Type().IsRegular() || !strings.HasPrefix(name, "tacquito.yaml.") || len(name) == len("tacquito.yaml.") {
				continue
			}
			fi, err := de.Info()
			if err != nil {
				continue
			}
			p := filepath.Join(dir, name)
			all = append(all, entry{legacyBackup{strings.TrimPrefix(name, "tacquito.yaml."), p}, name, fi.ModTime().UnixNano()})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].mtime != all[j].mtime {
			return all[i].mtime > all[j].mtime
		}
		return all[i].name > all[j].name
	})
	out := make([]legacyBackup, len(all))
	for i, e := range all {
		out[i] = e.legacyBackup
	}
	return out
}

// legacyIDRE is what _backup_legacy_path takes for an id: nothing that can
// name a directory.
var legacyIDRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// legacyPath is _backup_legacy_path: the old-style backup of that id
// (backups/ first, then backups/legacy/; a regular file, not a symlink).
func (inv *invocation) legacyPath(id string) (string, bool) {
	if !legacyIDRE.MatchString(id) {
		return "", false
	}
	for _, dir := range []string{inv.app.Paths.BackupDir, filepath.Join(inv.app.Paths.BackupDir, "legacy")} {
		p := filepath.Join(dir, "tacquito.yaml."+id)
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			return p, true
		}
	}
	return "", false
}

// isSnapshot is _backup_is_snapshot: id has the shape of a snapshot id
// and names a directory (not a symlink) under backups/.
func (inv *invocation) isSnapshot(id string) bool {
	if !snapshot.ValidID(id) {
		return false
	}
	st, err := os.Lstat(filepath.Join(inv.app.Paths.BackupDir, id))
	return err == nil && st.IsDir()
}

// backupNames is '_completion-names backups' (backup_names | head -50).
// 'backup list' is an operator row: the readonly tier is told no ids.
func (inv *invocation) backupNames([]string) []string {
	if inv.tierGate().Caller(inv.ctx) == tier.Readonly {
		return nil
	}
	names := inv.snapshotIDs()
	for _, e := range inv.legacyBackups() {
		names = append(names, e.id)
	}
	if len(names) > 50 {
		names = names[:50]
	}
	return names
}

func (inv *invocation) storeMode() bool { return model.Mode(inv.app.Paths.StoreFile) == "store" }

// --- list -----------------------------------------------------------------------

// backupList is _backup_list: the snapshots, then the old-style backups,
// with their sizes (du -sh).
func (inv *invocation) backupList([]string) error {
	ids, entries := inv.snapshotIDs(), inv.legacyBackups()
	inv.echo("")
	noStore := func() {
		if !inv.storeMode() {
			inv.echo("  No store yet: 'backup diff' and 'backup restore' work on old-style backups only.")
		}
	}
	if len(ids)+len(entries) == 0 {
		inv.echoE(ui.Bold + "Config Backups" + ui.NC)
		inv.echo(ui.Rule("Config Backups"))
		noStore()
		inv.echo("  No backups found.")
		inv.echo("")
		return nil
	}
	t := ui.NewTable("Config Backups", ui.Left("TIMESTAMP"), ui.Left("KIND"), ui.Left("SIZE"))
	for _, id := range ids {
		t.Add(id, "snapshot", duSH(filepath.Join(inv.app.Paths.BackupDir, id)))
	}
	for _, e := range entries {
		t.Add(e.id, "old-style", duSH(e.path))
	}
	inv.write(t.String())
	inv.echo("")
	noStore()
	inv.echo("  Old-style entries restore with 'tacctl backup restore <timestamp> --legacy'.")
	inv.echo("")
	return nil
}

// duSH is the first field of 'du -sh <path>': the disk usage of a file or
// a directory tree (allocated blocks, the directory's own included), in
// du's human-readable form; "" when it cannot be read.
func duSH(path string) string {
	if _, err := os.Lstat(path); err != nil {
		return ""
	}
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				total += st.Blocks * 512
			} else {
				total += fi.Size()
			}
		}
		return nil
	})
	return duHuman(total)
}

// duHuman is du -h's rendering of a byte count: powers of 1024, rounded
// up, one decimal below 10 (4.0K), none from 10 on (12K); 0 as "0".
func duHuman(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10)
	}
	const units = "KMGTPE"
	p, i := int64(1024), 0
	for i+1 < len(units) && n/1024 >= p {
		p *= 1024
		i++
	}
	if tenths := (n*10 + p - 1) / p; tenths < 100 {
		return strconv.FormatInt(tenths/10, 10) + "." + strconv.FormatInt(tenths%10, 10) + string(units[i])
	}
	whole := (n + p - 1) / p
	if whole >= 1024 && i+1 < len(units) {
		return "1.0" + string(units[i+1])
	}
	return strconv.FormatInt(whole, 10) + string(units[i])
}

// --- diff -------------------------------------------------------------------------

// diffU runs 'diff -u --label <la> --label <lb> --color=always a b' through
// the runner onto stdout and returns its exit status.
func (inv *invocation) diffU(la, lb, a, b string) int {
	o := inv.app.Out
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "diff",
		Args:   []string{"-u", "--label", la, "--label", lb, "--color=always", a, b},
		Stdout: o.Stdout, Stderr: o.Stderr})
	if err != nil {
		inv.stderrLine("diff: " + err.Error())
		return 2
	}
	return res.Code
}

// diffFile is _backup_diff_file: one file of a snapshot against the live
// one; a file that does not exist diffs as empty.
func (inv *invocation) diffFile(label, snap, live, id string) {
	if !cfgIsFile(snap) {
		snap = os.DevNull
	}
	if !cfgIsFile(live) {
		live = os.DevNull
	}
	if snap == os.DevNull && live == os.DevNull {
		inv.echo("  " + label + ": absent in the snapshot and now")
		return
	}
	if inv.diffU("snapshot/"+id+"/"+label, "current/"+label, snap, live) == 0 {
		inv.echo("  " + label + ": no differences")
	}
}

// diffSnapshot is _backup_diff_snapshot: the live canonical files against
// snapshot id.
func (inv *invocation) diffSnapshot(id string) {
	p := inv.app.Paths
	dir := filepath.Join(p.BackupDir, id)
	inv.echo("")
	inv.echoE(ui.Bold + "Diff: current store and tacctl.yaml vs snapshot " + id + ui.NC)
	inv.echo(ui.Rule("Diff: current store and tacctl.yaml vs snapshot " + id))
	inv.diffFile("store.yaml", filepath.Join(dir, "store.yaml"), p.StoreFile, id)
	inv.diffFile("tacctl.yaml", filepath.Join(dir, "tacctl.yaml"), p.Overrides, id)
	// The device registry joins the diff only where there is one to compare.
	if snap := filepath.Join(dir, "devices.yaml"); cfgIsFile(snap) || cfgIsFile(p.DevicesFile) {
		inv.diffFile("devices.yaml", snap, p.DevicesFile, id)
	}
	// The same for the login console's settings.
	if snap := filepath.Join(dir, "console.yaml"); cfgIsFile(snap) || cfgIsFile(p.ConsoleFile) {
		inv.diffFile("console.yaml", snap, p.ConsoleFile, id)
	}
	inv.diffHosts(dir, id)
}

// diffHosts adds the host state to the diff (D196): linux-hosts, each record
// of hosts/ (the union of both sides), staging and linux-uids, each only
// where one side has it; the registry counts when it holds a line, so a
// server without hosts diffs as before.
func (inv *invocation) diffHosts(dir, id string) {
	p := inv.app.Paths
	nonEmpty := func(path string) bool {
		st, err := os.Stat(path)
		return err == nil && st.Mode().IsRegular() && st.Size() > 0
	}
	if snap := filepath.Join(dir, snapshot.HostsName); nonEmpty(snap) || nonEmpty(p.LinuxHosts) {
		inv.diffFile(snapshot.HostsName, snap, p.LinuxHosts, id)
	}
	snapRecs := filepath.Join(dir, snapshot.HostRecordsName)
	names := slices.Concat(snapshot.HostRecordFiles(snapRecs), snapshot.HostRecordFiles(p.HostRecords))
	slices.Sort(names)
	for _, n := range slices.Compact(names) {
		inv.diffFile(snapshot.HostRecordsName+"/"+n, filepath.Join(snapRecs, n), filepath.Join(p.HostRecords, n), id)
	}
	for _, f := range [][2]string{{snapshot.StagingName, inv.stagingPath()}, {snapshot.UIDsName, p.LinuxUIDs}} {
		if snap := filepath.Join(dir, f[0]); cfgIsFile(snap) || cfgIsFile(f[1]) {
			inv.diffFile(f[0], snap, f[1], id)
		}
	}
}

// diffLegacy is _backup_diff_legacy: the live tacquito.yaml against
// old-style backup file (id).
func (inv *invocation) diffLegacy(id, file string) {
	inv.echo("")
	inv.echoE(ui.Bold + "Diff: current config vs backup " + id + ui.NC)
	inv.echo(ui.Rule("Diff: current config vs backup " + id))
	inv.diffU("backup/"+id, "current", file, inv.app.Paths.Config)
}

// backupDiff is _backup_diff: a snapshot or an old-style backup (default:
// the newest snapshot with a store, the newest old-style file without)
// against the live files. Arguments after the first are ignored.
func (inv *invocation) backupDiff(args []string) error {
	id := arg(args, 0)
	if id == "" {
		if inv.storeMode() {
			ids := inv.snapshotIDs()
			if len(ids) == 0 {
				return inv.usageErr("No snapshots found.")
			}
			id = ids[0]
		} else {
			entries := inv.legacyBackups()
			if len(entries) == 0 {
				return inv.usageErr("No backups found.")
			}
			id = entries[0].id
		}
	}
	if inv.isSnapshot(id) {
		if !inv.storeMode() {
			return inv.usageErr("Snapshot " + id + " holds the store, which is not initialised here. " + store.NotInitialisedMsg)
		}
		inv.diffSnapshot(id)
	} else if path, ok := inv.legacyPath(id); ok {
		inv.diffLegacy(id, path)
	} else {
		return inv.usageErr("Backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
	}
	inv.echo("")
	return nil
}

// --- restore ----------------------------------------------------------------------

const backupRestoreUsage = "Usage: tacctl backup restore <timestamp> [--legacy]"

// backupRestore is _backup_restore: its argument loop, then the restore of
// a snapshot, of an old-style backup (--legacy), or without a store the
// old-style copy-back.
func (inv *invocation) backupRestore(args []string) error {
	id, legacy := "", false
	for _, a := range args {
		switch {
		case a == "--legacy":
			legacy = true
		case strings.HasPrefix(a, "-"):
			return inv.usageErr("Unknown option '" + a + "'. " + backupRestoreUsage)
		default:
			if id != "" {
				return inv.usageErr("Only one timestamp may be given.")
			}
			id = a
		}
	}
	if id == "" {
		return inv.usageErr(backupRestoreUsage, "Run 'tacctl backup list' to see available backups.")
	}
	switch {
	case !inv.storeMode():
		return inv.restoreUnflipped(id)
	case legacy:
		return inv.restoreLegacy(id)
	case inv.isSnapshot(id):
		return inv.restoreSnapshot(id)
	}
	if _, ok := inv.legacyPath(id); ok {
		return inv.usageErr(id + " is an old-style backup. Restore it with: tacctl backup restore " + id + " --legacy")
	}
	return inv.usageErr("Backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
}

// confirmRestore is _backup_confirm: true only on y or Y; anything else
// says 'Cancelled.'.
func (inv *invocation) confirmRestore() bool {
	if inv.app.Prompter().Confirm("  Restore this backup? [y/N]: ") {
		return true
	}
	inv.app.Out.Info("Cancelled.")
	return false
}

// snapshotFirst is 'backup_snapshot || { error "Could not snapshot the
// current state. Nothing was changed."; return 1; }'.
func (inv *invocation) snapshotFirst() error {
	if _, err := inv.app.Snapshots().Take(); err != nil {
		inv.app.Out.Error(err.Error())
		return inv.usageErr("Could not snapshot the current state. Nothing was changed.")
	}
	return nil
}

// snapshotEnabled is _backup_snapshot_enabled: the backends the tacctl.yaml
// of snapshot directory dir enables (the default without one), or nothing
// when it cannot say.
func (inv *invocation) snapshotEnabled(dir string) []string {
	set := inv.app.Backends()
	env := &backend.Env{Conf: conf.Load(filepath.Join(dir, "tacctl.yaml"), set.IDs())}
	ids, err := backend.NewSet(set.Registry, env).Enabled()
	if err != nil {
		inv.app.Out.ErrorE(err.Error())
		return nil
	}
	return ids
}

// restoreSnapshot is _backup_restore_snapshot: everything that can be
// checked without touching a live file first (the snapshot's store and
// tacctl.yaml are valid, the backends it enables are installed), the diff
// and the confirmation, a snapshot of the current state (kept by
// retention), then the snapshot's files installed and every enabled
// backend rendered from them with force, or everything put back. The
// backends then follow the restored backends.enabled and are restarted.
func (inv *invocation) restoreSnapshot(id string) error {
	a := inv.app
	dir := filepath.Join(a.Paths.BackupDir, id)
	snapStore := filepath.Join(dir, "store.yaml")
	if !cfgIsFile(snapStore) {
		return inv.usageErr("Snapshot " + id + " has no store.yaml. Nothing was changed.")
	}
	problems, err := store.ValidateFile(snapStore)
	if err != nil {
		inv.stderrLine(store.Report(err))
	}
	for _, p := range problems {
		inv.stderrLine("tacctl store: " + p)
	}
	if err != nil || len(problems) > 0 {
		return inv.usageErr("Snapshot " + id + " cannot be restored: its store.yaml is not valid. Nothing was changed.")
	}
	if lines := a.Conf().Schema.ValidateFile(filepath.Join(dir, "tacctl.yaml")); len(lines) > 0 {
		for _, l := range lines {
			inv.stderrLine("  tacctl.yaml: " + l)
		}
		return inv.usageErr("Snapshot " + id + " cannot be restored: its tacctl.yaml is not valid. Nothing was changed.")
	}

	// The backends it enables must be on this machine: a restore cannot
	// install one. (Nothing is touched yet.)
	set := a.Backends()
	var before []string
	checkInstalled := func() error {
		var err error
		if before, err = inv.enabledOrFail(); err != nil {
			return err
		}
		for _, b := range inv.snapshotEnabled(dir) {
			if slices.Contains(before, b) {
				continue
			}
			if mod, err := set.Get(b); err != nil || !mod.Installed() {
				return inv.usageErr("Snapshot " + id + " enables backend '" + b + "', which is not installed here. Run 'tacctl backend enable " + b + "' first. Nothing was changed.")
			}
		}
		return nil
	}
	if err := checkInstalled(); err != nil {
		return err
	}

	inv.echo("")
	inv.echo("  Restoring snapshot: " + id)
	inv.diffSnapshot(id)
	// A restore is a render like any other: the break-glass holds come back
	// with a tacctl.yaml that has them and go with one that lacks them
	// (D126), so a change of the set is said before the question.
	holdNote := inv.restoreHoldNote(dir)
	if holdNote != "" {
		inv.echo("")
		inv.echoE(ui.Red + holdNote + ui.NC)
	}
	// So are the hosts: the registry, the UID ledger and the rest come back
	// with a snapshot that knows them (D192-D195).
	hostsNote := inv.restoreHostsNote(dir)
	if len(hostsNote) > 0 {
		inv.echo("")
		for _, l := range hostsNote {
			inv.echoE(ui.Red + l + ui.NC)
		}
	}
	inv.echo("")
	if !inv.confirmRestore() {
		return nil
	}

	// The whole restore is one change: ApplyForced holds the lock for the
	// render only, and the restarts and the file puts after it must not be
	// interleaved with another command's either.
	unlock, err := inv.holdApply()
	if err != nil {
		return err
	}
	// The set of enabled backends was read before the prompt: read it again
	// under the lock, for a command that finished while this one waited.
	if err := checkInstalled(); err != nil {
		unlock()
		return err
	}
	defer unlock()
	// The current state first, so the restore can be undone with another
	// one. Retention must not take the snapshot being read.
	a.Snapshots().KeepID = id
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if _, err := set.ApplyForced(inv.ctx, func() error { return inv.installSnapshot(dir) }); err != nil {
		if err == backend.ErrNotStarted {
			return err
		}
		names := set.AllArtifactNames()
		return inv.usageErr("Snapshot " + id + " was not restored: " + names + " could not be rendered from it. Store, tacctl.yaml and " + names + " are as they were.")
	}
	// The device registry comes back with the snapshot that holds one, after
	// the render that can still be rolled back; a snapshot without it (a
	// 0.2.0 one) leaves the live registry alone.
	if snapDev := filepath.Join(dir, "devices.yaml"); cfgIsFile(snapDev) {
		if err := backupPut(snapDev, a.Paths.DevicesFile, 0o600); err != nil {
			inv.stderrLine(err.Error())
			return err
		}
		// The generated known_hosts follows the restored pins.
		if err := devreg.SyncKnownHosts(a.Paths.DevicesFile, a.Paths.KnownHosts); err != nil {
			a.Out.WarnE("known_hosts was not regenerated: " + strings.Join(msgs(err), " "))
		}
	}
	// So do the console's settings: a snapshot without console.yaml leaves
	// the live file alone.
	if snapCon := filepath.Join(dir, "console.yaml"); cfgIsFile(snapCon) {
		if err := backupPut(snapCon, a.Paths.ConsoleFile, 0o600); err != nil {
			inv.stderrLine(err.Error())
			return err
		}
	}
	// And the SNMP credentials, which the settings in tacctl.yaml name.
	if err := inv.restoreSNMP(dir); err != nil {
		inv.stderrLine(err.Error())
		return err
	}
	// And the configuration blocks, which the blocks.* keys of tacctl.yaml
	// (restored with it) name.
	if err := inv.restoreBlocks(dir); err != nil {
		inv.stderrLine(err.Error())
		return err
	}
	// And the host state, last: nothing above depends on it, and the hosts
	// themselves are not touched (D194).
	if err := inv.restoreHosts(dir); err != nil {
		inv.stderrLine(err.Error())
		return err
	}
	inv.reconcileBackends(before)
	if err := set.RestartAll(inv.ctx); err != nil {
		return err
	}
	a.Out.InfoE("Restored snapshot " + id + ".")
	if holdNote != "" {
		a.Out.WarnE(holdNote)
	}
	for _, l := range hostsNote {
		a.Out.WarnE(l)
	}
	inv.echo("")
	inv.warnServerSync("Users whose tier is lower now keep their old groups")
	return nil
}

// restoreHoldNote says how the set of break-glass holds changes when the
// snapshot in dir is restored ("" when it does not): the devices held now
// and the ones held after.
func (inv *invocation) restoreHoldNote(dir string) string {
	now := inv.holds()
	after := conf.Load(filepath.Join(dir, "tacctl.yaml"), inv.app.Backends().IDs()).Holds()
	same := len(now) == len(after)
	for i := 0; same && i < len(now); i++ {
		same = now[i].Device == after[i].Device && now[i].Address == after[i].Address
	}
	if same {
		return ""
	}
	list := func(hs []conf.Hold) string {
		if len(hs) == 0 {
			return "none"
		}
		parts := make([]string, len(hs))
		for i, h := range hs {
			parts[i] = h.Device + " (" + h.Address + ")"
		}
		return strings.Join(parts, ", ")
	}
	return "Break-glass holds change: held now: " + list(now) + "; held after the restore: " + list(after) + " (tacctl breakglass list)."
}

// restoreHostsNote says what restoring the snapshot in dir does to the hosts
// (D194, D195), line by line; nothing when it changes none of it. A snapshot
// that does not know the hosts (0.2.13 and older) leaves them alone, and says
// so when there are any. One that does puts the registry back whole: the
// hosts it lacks go, the ones it has come back, and the hosts themselves are
// not touched, so the note names what to do about the drift. The UID ledger
// is put back as it was, which can forget a number a host already holds: the
// users whose number the restore drops or changes are named.
func (inv *invocation) restoreHostsNote(dir string) []string {
	p := inv.app.Paths
	live, err := hosts.LoadRegistry(p.LinuxHosts)
	if err != nil {
		return nil
	}
	if !snapshot.KnowsHosts(dir) {
		if live.Empty() {
			return nil
		}
		return []string{"This snapshot does not know the hosts (taken by 0.2.13 or older): the host registry, records, staging addresses and UID ledger stay as they are."}
	}
	snap, err := hosts.LoadRegistry(filepath.Join(dir, snapshot.HostsName))
	if err != nil {
		return nil
	}
	var back, gone, differ []string
	for _, e := range snap.Entries() {
		switch cur, ok := live.Find(e.Name); {
		case !ok:
			back = append(back, e.Name)
		case cur.Line != e.Line:
			differ = append(differ, e.Name)
		}
	}
	for _, e := range live.Entries() {
		if _, ok := snap.Find(e.Name); !ok {
			gone = append(gone, e.Name)
		}
	}
	var out []string
	if len(back)+len(gone)+len(differ) > 0 {
		var parts []string
		for _, g := range []struct {
			what  string
			names []string
		}{{"come back", back}, {"go", gone}, {"registered differently", differ}} {
			if len(g.names) > 0 {
				parts = append(parts, g.what+": "+strings.Join(g.names, ", "))
			}
		}
		out = append(out, "Enrolled hosts change (tacctl host list): "+strings.Join(parts, "; ")+".")
		out = append(out, "The hosts themselves are not touched. For a host that comes back after 'host unenroll': 'tacctl host sync <name>', 'tacctl host show <name> --check', or 'tacctl host unenroll <name>' again. For one that goes: 'tacctl host enroll' it again, or 'tacctl host unenroll <name> --force' after that.")
	}
	if l := restoreLedgerNote(hosts.UIDs{Path: p.LinuxUIDs}, hosts.UIDs{Path: filepath.Join(dir, snapshot.UIDsName)}); l != "" {
		out = append(out, l)
	}
	return out
}

// restoreLedgerNote names the users whose UID the snapshot's ledger drops or
// changes against the live one, and a change of the range it records; "" when
// the restore changes neither. A host that already holds one of these
// accounts keeps the number it has.
func restoreLedgerNote(live, snap hosts.UIDs) string {
	now, err1 := live.Numbers()
	after, err2 := snap.Numbers()
	if err1 != nil || err2 != nil {
		return ""
	}
	numbers := map[string]string{}
	for _, n := range after {
		numbers[n[0]] = n[1]
	}
	var lost []string
	for _, n := range now {
		switch uid, ok := numbers[n[0]]; {
		case !ok:
			lost = append(lost, n[0]+" ("+n[1]+", dropped)")
		case uid != n[1]:
			lost = append(lost, n[0]+" ("+n[1]+" becomes "+uid+")")
		}
	}
	slices.Sort(lost)
	text := ""
	if len(lost) > 0 {
		text = "The UID ledger (linux-uids) is put back as it was and forgets or changes the number of: " + strings.Join(lost, ", ") +
			". A host that already holds such an account keeps its number, and the next 'host sync' there may stop on a UID mismatch."
	}
	cur, _, _ := live.Recorded()
	was, _, _ := snap.Recorded()
	if cur != was {
		text += " The range the ledger is numbered for changes from " + rangeText(cur) + " to " + rangeText(was) + "."
	}
	return strings.TrimSpace(text)
}

// rangeText is a recorded range, "none" when the ledger records none.
func rangeText(r hosts.Range) string {
	if r.IsZero() {
		return "none"
	}
	return r.String()
}

// restoreHosts puts the host state of snapshot directory dir back (D192): the
// registry whole, the records made to match (a record the snapshot lacks
// goes), staging back or removed, the UID ledger back as it was. A snapshot
// that does not know the hosts (no linux-hosts in it) leaves all of it alone.
// The registry and the records go back under the registry's lock, so a
// command that writes them is not interleaved with the restore.
func (inv *invocation) restoreHosts(dir string) error {
	if !snapshot.KnowsHosts(dir) {
		return nil
	}
	p := inv.app.Paths
	reg := &hosts.Registry{Path: p.LinuxHosts}
	if err := reg.WithLock(func() error {
		snapReg := filepath.Join(dir, snapshot.HostsName)
		switch st, err := os.Stat(snapReg); {
		case err != nil:
			return err
		case st.Size() > 0 || cfgIsFile(p.LinuxHosts):
			// An empty one is written over a live one (the last host is gone
			// from the snapshot); with no live file there is nothing to empty.
			if err := backupPut(snapReg, p.LinuxHosts, 0o600); err != nil {
				return err
			}
		}
		return inv.restoreHostRecords(dir)
	}); err != nil {
		return err
	}
	for _, f := range [][2]string{{snapshot.StagingName, inv.stagingPath()}, {snapshot.UIDsName, p.LinuxUIDs}} {
		if snap := filepath.Join(dir, f[0]); cfgIsFile(snap) {
			if err := backupPut(snap, f[1], 0o600); err != nil {
				return err
			}
		} else if err := os.Remove(f[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// restoreHostRecords makes hosts/ match the snapshot's (the records 0600, the
// directory 0700): a record it lacks goes.
func (inv *invocation) restoreHostRecords(dir string) error {
	root := inv.app.Paths.HostRecords
	snapDir := filepath.Join(dir, snapshot.HostRecordsName)
	files := snapshot.HostRecordFiles(snapDir)
	if len(files) > 0 {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(root, 0o700); err != nil {
			return err
		}
	}
	for _, n := range files {
		if err := backupPut(filepath.Join(snapDir, n), filepath.Join(root, n), 0o600); err != nil {
			return err
		}
	}
	for _, n := range snapshot.HostRecordFiles(root) {
		if !slices.Contains(files, n) {
			if err := os.Remove(filepath.Join(root, n)); err != nil {
				return err
			}
		}
	}
	_ = os.Remove(root) // only when empty
	return nil
}

// restoreSNMP puts the SNMP credentials of snapshot directory dir back:
// snmp.yaml (the default), the per-scope files of snmp/ and the per-device
// files of snmp/devices/, in the modes they are kept in (0600, the
// directories 0700). A snapshot that holds a
// credentials directory makes the live one match it (a file the snapshot
// lacks goes: tacctl.yaml, restored with it, names no such scope); one that
// holds none (taken before there were any, or when there were none) leaves
// the live scope files alone. The devices' files follow the registry: a
// snapshot that holds devices.yaml makes snmp/devices/ match its own, empty
// when it has none.
func (inv *invocation) restoreSNMP(dir string) error {
	p := inv.app.Paths
	if snap := filepath.Join(dir, "snmp.yaml"); cfgIsFile(snap) {
		if err := backupPut(snap, p.SNMPFile, 0o600); err != nil {
			return err
		}
	}
	snapDir := filepath.Join(dir, "snmp")
	files, devFiles := snapshot.SNMPFiles(snapDir), snapshot.SNMPDeviceFiles(snapDir)
	// A snapshot that holds the registry says which devices have credentials
	// of their own: none when it has no snmp/devices (absent means none), so
	// a restore never leaves a device's file that the restored registry has
	// no map for. One without a registry (a 0.2.0 one) leaves the devices'
	// files alone, as it leaves the registry.
	hasRegistry := cfgIsFile(filepath.Join(dir, "devices.yaml"))
	hasCreds := len(files) > 0 || len(devFiles) > 0
	if !hasCreds && !hasRegistry {
		return nil
	}
	// The scopes' files: made to match when the snapshot holds a credentials
	// directory; a snapshot without one leaves them alone.
	if hasCreds {
		if err := os.MkdirAll(p.SNMPDir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(p.SNMPDir, 0o700); err != nil {
			return err
		}
		if err := restoreCredDir(p.SNMPDir, snapDir, files, snapshot.SNMPFiles(p.SNMPDir)); err != nil {
			return err
		}
	}
	// The devices' files (D72 of docs/plans/0.2.4-plan.md, snmp/devices/).
	devDir := filepath.Join(p.SNMPDir, snapshot.SNMPDevicesDir)
	if err := restoreCredDir(devDir, filepath.Join(snapDir, snapshot.SNMPDevicesDir), devFiles, snapshot.SNMPDeviceFiles(p.SNMPDir)); err != nil {
		return err
	}
	_ = os.Remove(devDir)    // only when empty
	_ = os.Remove(p.SNMPDir) // only when empty
	return nil
}

// restoreBlocks puts the configuration blocks of snapshot directory dir
// back (blocks/<scope>/<vendor>/<block> and blocks/_devices/<device>/
// <vendor>/<block>, the directories 0700 and the files 0600). A snapshot
// that holds a blocks directory makes the live one match it: a file it lacks
// goes (tacctl.yaml, restored with it, does not list that block), and the
// directories that leaves empty. One that holds none (taken before there
// were blocks, or when there were none) leaves the live files alone: they
// are no block in force, the restored tacctl.yaml does not name them, and
// 'tacctl scope block ... check' lists them as files that are ignored.
func (inv *invocation) restoreBlocks(dir string) error {
	root := inv.app.Paths.BlocksDir
	snapDir := filepath.Join(dir, snapshot.BlocksName)
	files := snapshot.BlockFiles(snapDir)
	if len(files) == 0 {
		return nil
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	for _, n := range files {
		rel := filepath.FromSlash(n)
		to := filepath.Join(root, rel)
		// Every directory from the root down, whatever the umask.
		cur := root
		for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
			if part == "." {
				continue
			}
			cur = filepath.Join(cur, part)
			if err := os.MkdirAll(cur, 0o700); err != nil {
				return err
			}
			if err := os.Chmod(cur, 0o700); err != nil {
				return err
			}
		}
		if err := backupPut(filepath.Join(snapDir, rel), to, 0o600); err != nil {
			return err
		}
	}
	for _, n := range snapshot.BlockFiles(root) {
		if !slices.Contains(files, n) {
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(n))); err != nil {
				return err
			}
		}
	}
	pruneEmptyDirs(root)
	return nil
}

// pruneEmptyDirs removes the directories under root that hold nothing (the
// deepest first), and root itself when it is left empty.
func pruneEmptyDirs(root string) {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i]) // only when empty
	}
}

// restoreCredDir puts the credential files of one snapshot directory back
// into liveDir (0700, the files 0600) and removes the live files the
// snapshot lacks.
func restoreCredDir(liveDir, snapDir string, files, live []string) error {
	if len(files) > 0 {
		if err := os.MkdirAll(liveDir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(liveDir, 0o700); err != nil {
			return err
		}
	}
	for _, n := range files {
		if err := backupPut(filepath.Join(snapDir, n), filepath.Join(liveDir, n), 0o600); err != nil {
			return err
		}
	}
	for _, n := range live {
		if !slices.Contains(files, n) {
			if err := os.Remove(filepath.Join(liveDir, n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// installSnapshot is _backup_install_snapshot: snapshot directory dir's
// store.yaml (0600) and tacctl.yaml (0640, tacquito's) become the live
// ones; no tacctl.yaml in it means none now.
func (inv *invocation) installSnapshot(dir string) error {
	p := inv.app.Paths
	if err := backupPut(filepath.Join(dir, "store.yaml"), p.StoreFile, 0o600); err != nil {
		inv.stderrLine(err.Error())
		return err
	}
	snapConf := filepath.Join(dir, "tacctl.yaml")
	if cfgIsFile(snapConf) {
		if err := backupPut(snapConf, p.Overrides, 0o640); err != nil {
			inv.stderrLine(err.Error())
			return err
		}
		rtacacs.ChownTacquito(p.Overrides)
	} else if err := os.Remove(p.Overrides); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// backupPut is _backup_put with a mode: src copied to <dst>.tacctl-new,
// given mode and renamed over dst, so a reader never sees half a file.
func backupPut(src, dst string, mode os.FileMode) error {
	tmp := dst + ".tacctl-new"
	err := func() error {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
		return os.Rename(tmp, dst)
	}()
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// reconcileBackends is _backup_reconcile_backends: the daemons follow the
// restored backends.enabled the way 'backend enable|disable' do: one it
// enables is enabled at boot (the restart that follows starts it), one it
// takes out is stopped and disabled. before is the enabled list before the
// restore.
func (inv *invocation) reconcileBackends(before []string) {
	a := inv.app
	set := a.Backends()
	now, err := set.Enabled()
	if err != nil {
		a.Out.ErrorE(err.Error())
		return
	}
	for _, id := range now {
		if slices.Contains(before, id) {
			continue
		}
		a.Out.InfoE("Backend '" + id + "' is enabled by this snapshot.")
		if b, err := set.Get(id); err != nil {
			a.Out.WarnE("Could not enable the service of backend '" + id + "' at boot.")
		} else if _, err := b.Service(inv.ctx, backend.ServiceEnable, ""); err != nil {
			a.Out.WarnE("Could not enable the service of backend '" + id + "' at boot.")
		}
	}
	for _, id := range before {
		if slices.Contains(now, id) {
			continue
		}
		a.Out.InfoE("Backend '" + id + "' is not enabled by this snapshot: stopping and disabling its service.")
		b, err := set.Get(id)
		if err != nil {
			continue
		}
		if _, err := b.Service(inv.ctx, backend.ServiceStop, ""); err != nil {
			a.Out.WarnE("Could not stop the service of backend '" + id + "'.")
		}
		if _, err := b.Service(inv.ctx, backend.ServiceDisable, ""); err != nil {
			a.Out.WarnE("Could not disable the service of backend '" + id + "'.")
		}
	}
}

// restoreLegacy is _backup_restore_legacy: an old-style backup goes
// through the importer's check, is shown and confirmed, then imported over
// the store (--replace) and every enabled backend rendered from it with
// force, or everything put back.
func (inv *invocation) restoreLegacy(id string) error {
	a := inv.app
	file, ok := inv.legacyPath(id)
	if !ok {
		return inv.usageErr("Old-style backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
	}
	inv.echo("")
	inv.echo("  Checking that the store can take " + file)
	if err := store.Import(a.Out, inv.importOptions(importArgs{check: true, src: file})); err != nil {
		return inv.usageErr("Old-style backup "+id+" cannot be restored: the importer's check failed (see above). Nothing was changed.",
			"To import it anyway: 'tacctl store import --replace "+file+"', then 'tacctl config render --force'.")
	}

	inv.echo("")
	inv.echo("  Restoring old-style backup: " + id)
	inv.diffLegacy(id, file)
	inv.echo("")
	if !inv.confirmRestore() {
		return nil
	}

	unlock, err := inv.holdApply()
	if err != nil {
		return err
	}
	defer unlock()
	before := inv.storeGroups()
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	set := a.Backends()
	quiet := ui.Output{Stdout: io.Discard, Stderr: a.Out.Stderr}
	if _, err := set.ApplyForced(inv.ctx, func() error {
		return store.Import(quiet, inv.importOptions(importArgs{replace: true, src: file}))
	}); err != nil {
		if err == backend.ErrNotStarted {
			return err
		}
		return inv.usageErr("Old-style backup " + id + " was not restored. Store, tacctl.yaml and " + set.AllArtifactNames() + " are as they were.")
	}
	if err := set.RestartAll(inv.ctx); err != nil {
		return err
	}
	a.Out.InfoE("Restored old-style backup " + id + ".")
	inv.echo("")
	inv.pinGroupTiers(before)
	inv.warnStaleGroupSettings()
	inv.warnServerSync("Users whose tier is lower now keep their old groups")
	return nil
}

// restoreUnflipped is _backup_restore_unflipped (lib/backends/tacacs.sh):
// no store yet, so the old-style file is copied back over tacquito.yaml as
// it always was, after an old-style backup of the file it replaces, and
// tacquito is restarted.
func (inv *invocation) restoreUnflipped(id string) error {
	a := inv.app
	file, ok := inv.legacyPath(id)
	if !ok {
		if inv.isSnapshot(id) {
			return inv.usageErr("Snapshot " + id + " holds the store, which is not initialised here. " + store.NotInitialisedMsg)
		}
		return inv.usageErr("Backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
	}
	inv.echo("")
	inv.echo("  Restoring config from: " + id)
	inv.echo("")
	inv.echoE("  " + ui.Bold + "Changes that will be applied:" + ui.NC)
	_, _ = a.Runner.Run(inv.ctx, execx.Cmd{Name: "diff", Args: []string{"--color=always", a.Paths.Config, file},
		Stdout: a.Out.Stdout, Stderr: a.Out.Stderr})
	inv.echo("")
	if !inv.confirmRestore() {
		return nil
	}

	// Back up the current config before restoring (safety net).
	if err := lifecycle.BackupConfig(a.Paths, a.Out, a.Knobs.Now()); err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err == nil {
		err = os.WriteFile(a.Paths.Config, data, 0o640)
	}
	if err != nil {
		inv.stderrLine("cp: " + err.Error())
		return exit(1)
	}
	rtacacs.ChownTacquito(a.Paths.Config)
	_ = os.Chmod(a.Paths.Config, 0o640)
	if b, err := a.Backends().Get(backend.TACACS); err == nil {
		_, _ = b.Service(inv.ctx, backend.ServiceRestart, "")
	}
	a.Out.InfoE("Config restored from backup " + id + ".")
	inv.echo("")
	return nil
}
