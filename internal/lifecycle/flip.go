package lifecycle

// The move of a legacy install into the store and the way back
// (upgrade_store_flip, _store_unflip, _upgrade_flip_hint, config_service_access
// in lib/backends/tacacs.sh at 0.1.16).

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// FlipResult is what UpgradeStoreFlip did; its Code is the bash return
// status.
type FlipResult int

// The results of the store gate.
const (
	// Flipped: store written, tacquito.yaml rendered from it and recorded.
	// The caller restarts the daemon.
	Flipped FlipResult = 0
	// StorePresent: nothing to do, a store exists. It is never re-imported.
	StorePresent FlipResult = 10
	// FlipStopped: nothing was changed, the install stays in legacy
	// read-only mode, and the daemon must not be restarted on the gate's
	// account.
	FlipStopped FlipResult = 20
)

// Code is the return status of upgrade_store_flip (0, 10, 20).
func (r FlipResult) Code() int { return int(r) }

// String is the STORE_STATE word of _tacacs_upgrade_finish: flipped,
// present, stopped.
func (r FlipResult) String() string {
	switch r {
	case Flipped:
		return "flipped"
	case StorePresent:
		return "present"
	}
	return "stopped"
}

// UpgradeStoreFlip is upgrade_store_flip: move a legacy install into the
// store, if and only if that is proven not to change what the daemon does.
//
// The gate is 'tacctl store import --check' (its report printed as it
// goes): import, validate, render, equivalence with the live file, and the
// daemon loading the rendered file. Only its "proven" verdict passes; a
// failed check and a clean import whose equivalence was not proven both
// stop. So does a missing daemon binary: the check would skip the
// load-smoke and still pass, and an upgrade always has the binary it just
// built or kept. Nothing is forced and the legacy file is not rewritten to
// make it pass.
//
// After the gate, in this order: the legacy file is kept as
// backups/legacy/tacquito.yaml.pre-store.<ts> (by the import), the store
// is written, tacquito.yaml is rendered from it (--force: the first render
// over a file tacctl never rendered) and recorded, and the installed file
// is compared with the kept one once more. If the render or the comparison
// fails, StoreUnflip puts the kept file back and the store is removed
// again. Every stop prints the 'Store migration stopped' report.
//
// The daemon is not restarted here: 'upgrade finish' restarts it once, for
// everything the upgrade changed (Flipped is one of the reasons).
func UpgradeStoreFlip(ctx context.Context, env *Env) FlipResult {
	p := env.Paths
	if isRegular(p.StoreFile) {
		return StorePresent
	}
	out := env.Out
	echo(out, "")
	out.InfoE("Store migration: " + p.StoreFile + " does not exist yet.")
	if !isRegular(p.Config) {
		return flipStopped(env, "there is no "+p.Config+" to import")
	}
	bin := filepath.Join(p.Bin, "tacquito")
	if unix.Access(bin, unix.X_OK) != nil {
		return flipStopped(env, "the daemon load-smoke cannot run ("+bin+" or 'timeout' is missing), "+
			"so the rendered config cannot be proven to load")
	}

	out.InfoE("Checking that " + p.Config + " can move into the store without changing what tacquito does (the check writes nothing)...")
	if err := store.Import(out, env.importOptions(ctx, true)); err != nil {
		var st *store.ImportStatus
		if errors.As(err, &st) && st.Code == store.ImportNotProven.Code {
			return flipStopped(env, "the import is clean but its equivalence with "+p.Config+" was not proven")
		}
		return flipStopped(env, "the check above did not pass")
	}

	out.InfoE("Gate passed: writing the store and rendering " + p.Config + " from it...")
	// The report was printed by the check; errors still reach stderr.
	quiet := ui.Output{Stdout: io.Discard, Stderr: out.Stderr}
	if err := store.Import(quiet, env.importOptions(ctx, false)); err != nil {
		return flipStopped(env, "the import failed after a clean check")
	}
	pre, ok := store.PreStoreLatest(filepath.Join(p.BackupDir, "legacy"))
	if !ok {
		_ = os.Remove(p.StoreFile)
		return flipStopped(env, "the pre-store copy of "+p.Config+" is missing")
	}
	if _, err := RenderApply(ctx, env, true); err != nil {
		_ = StoreUnflip(env, pre)
		return flipStopped(env, p.Config+" could not be rendered from the store (the store was removed again)")
	}
	if eq, err := model.EquivCheckRand(env.rand())(pre, p.Config, io.Discard); err != nil || !eq {
		_ = StoreUnflip(env, pre)
		return flipStopped(env, "the rendered "+p.Config+" was not equivalent to the file it replaced "+
			"(that file is back and the store was removed again)")
	}
	if err := ConfigServiceAccess(env); err != nil {
		out.WarnE("Could not make " + p.Config + " readable by the tacquito service user (expected tacquito:tacquito, 0640); fix that before the service restarts.")
	}

	out.InfoE("Store migration complete: users, groups, scopes and filters now live in " + p.StoreFile + ".")
	out.InfoE("  " + p.Config + " is rendered from the store; change it with tacctl commands.")
	out.InfoE("  'tacctl store rollback' returns to the kept pre-store file.")
	return Flipped
}

// flipStopped is _upgrade_flip_stopped: the report of a gate that stopped.
func flipStopped(env *Env, why string) FlipResult {
	out, cfg := env.Out, env.Paths.Config
	echo(out, "")
	out.WarnE("Store migration stopped: " + why + ".")
	out.WarnE(cfg + " and the running daemon were left as they are.")
	out.WarnE("tacctl stays in legacy read-only mode: read commands work; commands that change users, groups, scopes or filters are refused.")
	out.WarnE("To proceed: 'tacctl store import --check' prints the report again. Fix what it lists in " + cfg + " and run 'tacctl upgrade' again,")
	out.WarnE("or accept the difference yourself: 'tacctl store import' (--force drops what the store cannot hold), then 'tacctl config render --force'.")
	echo(out, "")
	return FlipStopped
}

// FlipHint is _upgrade_flip_hint: what 'upgrade finish' says (on Stderr)
// when the daemon does not come back after an upgrade that flipped.
func FlipHint(out ui.Output, config string, r FlipResult) {
	if r != Flipped {
		return
	}
	out.ErrorE("This upgrade moved the configuration into the store. If the rendered " + config +
		" is the cause, 'tacctl store rollback' restores the previous file.")
}

// ConfigServiceAccess is config_service_access: as root, tacquito.yaml is
// given to tacquito:tacquito, mode 0640, so the daemon (which runs as
// 'tacquito') can read it. The renderer's own chown is best effort
// because the test suite runs unprivileged; install and upgrade run as
// root, where a failure is real. Nothing to do when not root or without
// the file.
func ConfigServiceAccess(env *Env) error {
	cfg := env.Paths.Config
	if !env.IsRoot || !isRegular(cfg) {
		return nil
	}
	uid, gid, err := tacquitoIDs()
	if err != nil {
		return err
	}
	if err := os.Chown(cfg, uid, gid); err != nil {
		return err
	}
	return os.Chmod(cfg, 0o640)
}

// StoreUnflip is _store_unflip <pre-store-file>: make pre the live
// tacquito.yaml again (through <config>.tacctl-new: 0640, tacquito's when
// possible; left alone when it already holds the same bytes) and remove
// the store and the render records. The config goes back first: if that
// fails nothing was removed. No snapshot, no restart: callers do those.
func StoreUnflip(env *Env, pre string) error {
	p := env.Paths
	if !sameBytes(pre, p.Config) {
		staged := p.Config + ".tacctl-new"
		data, err := os.ReadFile(pre)
		if err == nil {
			err = os.WriteFile(staged, data, 0o600)
		}
		if err == nil {
			err = os.Chmod(staged, 0o640)
		}
		if err != nil {
			_ = os.Remove(staged)
			return err
		}
		env.chownTacquito(staged)
		if err := os.Rename(staged, p.Config); err != nil {
			_ = os.Remove(staged)
			return err
		}
	}
	for _, f := range []string{p.StoreFile, p.Rendered} {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// echo is 'echo "<s>"' on Stdout.
func echo(out ui.Output, s string) {
	if out.Stdout != nil {
		_, _ = io.WriteString(out.Stdout, s+"\n")
	}
}
