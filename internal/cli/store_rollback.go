package cli

// 'tacctl store rollback' (cmd_store_rollback, lib/backends/tacacs.sh at
// 0.1.16): undo the move into the store. The pre-store tacquito.yaml the
// import kept becomes the live config again, the store and the render
// records go, tacquito restarts: legacy read-only mode under this release.

import (
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

func init() { registerFamilyVerb("store", "rollback", storeRollbackCmd) }

func storeRollbackCmd(inv *invocation) *cobra.Command {
	return withRun(verb("rollback", "Undo the import: restore the pre-store tacquito.yaml"),
		inv.native(noPreflight, inv.storeRollback))
}

// storeRollback is cmd_store_rollback. Exit 0 rolled back (or cancelled at
// the prompt); 1 refused or failed, the store untouched; 2 usage.
func (inv *invocation) storeRollback(args []string) error {
	a := inv.app
	p, out := a.Paths, a.Out
	if len(args) > 0 {
		out.ErrorE("Usage: tacctl store rollback")
		return exit(2)
	}
	if !isRegularFile(p.StoreFile) {
		return inv.usageErr("There is no store at " + p.StoreFile + ": this install is already in legacy read-only mode. Nothing to roll back.")
	}
	// Legacy mode is TACACS+ only: with another backend enabled, the
	// rollback would leave it serving a store that is gone.
	ids, err := a.Backends().Enabled()
	if err != nil {
		return inv.usageErr(err.Error())
	}
	var others []string
	for _, id := range ids {
		if id != backend.TACACS {
			others = append(others, id)
		}
	}
	if len(others) > 0 {
		return inv.usageErr("Backend(s) "+strings.Join(others, ", ")+" are enabled, and legacy mode (what a rollback returns to) serves TACACS+ only.",
			"Disable them first ('tacctl backend disable <id>'). Nothing was changed.")
	}
	legacyDir := filepath.Join(p.BackupDir, "legacy")
	pre, ok := store.PreStoreLatest(legacyDir)
	if !ok {
		return inv.usageErr("No pre-store config (tacquito.yaml.pre-store.<timestamp>) under "+legacyDir+"/: there is nothing to roll back to.",
			"A fresh install starts with its store and never had a legacy tacquito.yaml. The store was left untouched.")
	}
	// Legacy mode reads everything from this file; one the loader cannot
	// read would leave tacctl without a model.
	if _, _, err := model.LegacyLoad(pre, p.PWDatesDir, filepath.Join(p.BackupDir, "disabled")); err != nil {
		inv.stderrLine(store.Report(err))
		return inv.usageErr(pre + " cannot be read as a tacquito.yaml. Nothing was changed.")
	}

	inv.echo("")
	inv.echoE(ui.Bold + "Roll back to the pre-store configuration" + ui.NC)
	inv.echo("")
	inv.echo("  This restores " + pre)
	inv.echo("  as " + p.Config + ", removes " + p.StoreFile + " and the render records,")
	inv.echo("  and restarts the service. tacctl is then in legacy read-only mode: read commands")
	inv.echo("  work, commands that change users, groups, scopes or filters are refused.")
	inv.echo("  The store is snapshotted first (see 'tacctl backup list').")
	if !matchesStore(p.StoreFile, pre) {
		inv.echo("")
		out.WarnE("The store no longer says what the pre-store file says: users, groups, scopes or filters changed since the import.")
		out.WarnE("Those changes stop being in effect. They stay in the snapshot, not in " + p.Config + ".")
	}
	inv.echo("")
	if !a.Prompter().Confirm("  Roll back? [y/N]: ") {
		out.InfoE("Cancelled.")
		return nil
	}

	if _, err := a.Snapshots().Take(); err != nil {
		return inv.usageErr(err.Error(), "Could not snapshot the store. Nothing was changed.")
	}
	env := lifecycle.NewEnv(a.BackendEnv(), a.Knobs.Rand(), a.EUID == 0)
	// A rendered config somebody edited by hand is not in the snapshot.
	if isRegularFile(p.Config) {
		if word, err := rendered.Check(p.Rendered, p.Config); err != nil || word != rendered.OK {
			r := &rtacacs.Renderer{Paths: rtacacs.PathsFrom(p), Conf: a.Conf(), Load: rtacacs.DefaultLoader,
				Now: a.Knobs.Now, Stderr: out.Stderr}
			if err := r.SaveDisplaced(p.Config); err != nil {
				return inv.usageErr("Could not keep a copy of " + p.Config + ". Nothing was changed.")
			}
		}
	}
	if err := lifecycle.StoreUnflip(env, pre); err != nil {
		inv.stderrLine(err.Error())
		return inv.usageErr("Rollback failed: " + p.Config + " could not be replaced. The store was left untouched.")
	}
	if b, err := a.Backends().Get(backend.TACACS); err == nil {
		_, _ = b.Service(inv.ctx, backend.ServiceRestart, "")
	}
	out.InfoE("Rolled back: " + p.Config + " is the pre-store file again and the store is gone (legacy read-only mode).")
	out.InfoE("To move to the store again: 'tacctl store import --check', then 'tacctl upgrade' (or 'tacctl store import' and 'tacctl config render --force').")
	inv.echo("")
	inv.warnServerSync("Users whose tier is lower now keep their old groups")
	return nil
}

// matchesStore is _tacacs_matches_store <file>: the file, read with the
// importer, holds the groups, users, scopes and filters of the store and
// nothing the store cannot represent. Every failure is "no".
func matchesStore(storeFile, path string) bool {
	st, err := store.Load(storeFile)
	if err != nil {
		return false
	}
	return rtacacs.MatchesModel(path, model.FromStore(st), rtacacs.DefaultLoader)
}
