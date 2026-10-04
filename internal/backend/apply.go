package backend

import (
	"context"
	"os"
	"path/filepath"

	"github.com/rett/tacctl/internal/store"
)

// Require is store_require: nil when the store exists; else the
// "store not initialised" line is written and ErrFailed returned.
// Mutating commands call it before they prompt.
func (s *Set) Require() error {
	if isRegular(s.Env.Paths.StoreFile) {
		return nil
	}
	s.Env.Out.Error(store.NotInitialisedMsg)
	return ErrFailed
}

// ApplyOptions are store_apply's options.
type ApplyOptions struct {
	// Gate, when not empty, are the backends to gate instead of the
	// enabled ones (--gate): for a writer that changes backends.enabled,
	// the backends that will be rendered, not those that were.
	Gate []string
	// DeferRestart are backends whose restart the caller does itself
	// (--defer-restart); they are still in Result.Changed.
	DeferRestart []string
}

// Result is what a StoreApply did.
type Result struct {
	// Changed are the backends whose artifacts the render replaced
	// (BACKENDS_CHANGED), in enabled order.
	Changed []string
	// Adopted are the backends whose gate answered GateAdopt and which
	// were therefore rendered with force (BACKENDS_ADOPT).
	Adopted []string
}

// StoreApply is store_apply, the one mutation path: every command that
// changes users, groups, scopes, filters or command rules runs its writes
// through it.
//
//  1. gate     the store must exist, and every gated backend's artifacts
//     must be replaceable; a refusal stops here, before anything is
//     written.
//  2. backup   a snapshot (Env.Snapshots; skipped when nothing changed since
//     the newest one), then private copies of store.yaml and tacctl.yaml
//     under <state>/.apply.*; a snapshot that cannot be made refuses the
//     command, before anything is written.
//  3. write    writer, with the snapshot held: the store writes it makes
//     with Env.MutateOptions() take no snapshot of their own.
//  4. render   RenderAll, forcing the backends the gate said to adopt. If it
//     fails, no artifact has changed, and store.yaml and tacctl.yaml are
//     put back as they were (and Env.Conf reloaded).
//  5. restart  only the backends whose rendered config changed, except
//     DeferRestart.
//
// It returns ErrRefused (exit 3: a rendered file was edited by hand;
// nothing changed), ErrFailed (exit 1: nothing changed, a partial write was
// rolled back) or an *Error of code 2 (an unknown id in opts.Gate), with
// every message written. A writer error is returned as it is, after the
// rollback, without being printed: the caller reports it (exit 1). The
// writer must not take the store lock around a store.Mutate of its own.
func (s *Set) StoreApply(ctx context.Context, opts ApplyOptions, writer func() error) (Result, error) {
	env := s.Env
	if err := s.Require(); err != nil {
		return Result{}, err
	}
	adopt, err := s.Gate(ctx, opts.Gate)
	if err != nil {
		return Result{}, err
	}
	if env.Snapshots != nil {
		if _, err := env.Snapshots.Take(); err != nil {
			env.Out.Error(err.Error())
			env.Out.Error("Nothing was changed: the pre-change snapshot could not be made.")
			return Result{}, ErrFailed
		}
	}

	keep, err := os.MkdirTemp(env.Paths.StateDir, ".apply.")
	if err != nil {
		env.Out.Error("Cannot create " + filepath.Join(env.Paths.StateDir, ".apply.*") + ": " + err.Error())
		return Result{}, ErrFailed
	}
	defer func() { _ = os.RemoveAll(keep) }()
	if err := copyPreserve(env.Paths.StoreFile, filepath.Join(keep, "store.yaml")); err != nil {
		env.Out.Error("Cannot copy " + env.Paths.StoreFile + ": " + err.Error())
		return Result{}, ErrFailed
	}
	if isRegular(env.Paths.Overrides) {
		if err := copyPreserve(env.Paths.Overrides, filepath.Join(keep, "tacctl.yaml")); err != nil {
			env.Out.Error("Cannot copy " + env.Paths.Overrides + ": " + err.Error())
			return Result{}, ErrFailed
		}
	}

	// The snapshot above is this command's; the writer's own store writes
	// must not add one per intermediate state.
	release := func() {}
	if env.Snapshots != nil {
		release = env.Snapshots.Hold()
	}
	werr := writer()
	release()
	s.reloadConf() // a writer may have replaced tacctl.yaml by hand
	if werr != nil {
		s.rollback(keep)
		return Result{}, werr
	}

	changed, err := s.RenderAll(ctx, RenderOptions{Force: adopt})
	if err != nil {
		// Named before the rollback: a change of backends.enabled changes
		// which backends these are.
		names := s.AllArtifactNames()
		s.rollback(keep)
		env.Out.Error("The change was not applied: " + names + " could not be rendered. Store and tacctl.yaml are as they were.")
		return Result{}, ErrFailed
	}
	s.RestartChanged(ctx, changed, opts.DeferRestart)
	return Result{Changed: changed, Adopted: adopt}, nil
}

// rollback is _store_apply_rollback: store.yaml and tacctl.yaml back from
// the copies in keep (no copy of tacctl.yaml: there was none), and the
// invocation's view of tacctl.yaml reloaded.
func (s *Set) rollback(keep string) {
	p := s.Env.Paths
	_ = os.Rename(filepath.Join(keep, "store.yaml"), p.StoreFile)
	kept := filepath.Join(keep, "tacctl.yaml")
	if isRegular(kept) {
		_ = os.Rename(kept, p.Overrides)
	} else {
		_ = os.Remove(p.Overrides)
	}
	s.reloadConf()
}

// ApplyForced is _backup_apply (lib/service.sh), the restore path: writer
// installs restored files as the live store.yaml (and tacctl.yaml), then
// every enabled backend is rendered from them with force (a restore is an
// explicit overwrite: the operator has seen the diff, and a hand-edited
// artifact is kept by its backend). There is no gate and no snapshot of
// its own: the caller takes one first (with Snapshots.KeepID set to the
// snapshot it reads). A writer or render that fails puts store.yaml and
// tacctl.yaml back from copies under <state>/.restore.*, and since the
// render changed no artifact, store, tacctl.yaml, artifacts and their
// records agree again. It returns the backends whose artifacts changed, or
// ErrFailed (the messages are the writer's and the render's).
func (s *Set) ApplyForced(ctx context.Context, writer func() error) ([]string, error) {
	env := s.Env
	keep, err := os.MkdirTemp(env.Paths.StateDir, ".restore.")
	if err != nil {
		env.Out.Error("Cannot create " + filepath.Join(env.Paths.StateDir, ".restore.*") + ": " + err.Error())
		return nil, ErrFailed
	}
	defer func() { _ = os.RemoveAll(keep) }()
	for _, f := range [][2]string{{env.Paths.StoreFile, "store.yaml"}, {env.Paths.Overrides, "tacctl.yaml"}} {
		if isRegular(f[0]) {
			if err := copyPreserve(f[0], filepath.Join(keep, f[1])); err != nil {
				env.Out.Error("Cannot copy " + f[0] + ": " + err.Error())
				return nil, ErrFailed
			}
		}
	}
	release := func() {}
	if env.Snapshots != nil {
		release = env.Snapshots.Hold()
	}
	err = writer()
	s.reloadConf() // the writer replaced tacctl.yaml (_conf_invalidate)
	var changed []string
	if err == nil {
		changed, err = s.RenderAll(ctx, RenderOptions{ForceAll: true})
	}
	release()
	if err != nil {
		s.rollbackRestore(keep)
		return nil, ErrFailed
	}
	return changed, nil
}

// rollbackRestore is _backup_apply_rollback: like rollback, except that a
// store.yaml that did not exist before is removed.
func (s *Set) rollbackRestore(keep string) {
	p := s.Env.Paths
	for _, f := range [][2]string{{"store.yaml", p.StoreFile}, {"tacctl.yaml", p.Overrides}} {
		kept := filepath.Join(keep, f[0])
		if isRegular(kept) {
			if os.Rename(kept, f[1]) != nil {
				s.Env.Out.Warn("Could not put " + f[1] + " back.")
			}
		} else {
			_ = os.Remove(f[1])
		}
	}
	s.reloadConf()
}

// reloadConf re-reads tacctl.yaml into Env.Conf (the cache invalidation
// of lib/conf.sh): the enabled list and every backend's view follow.
func (s *Set) reloadConf() {
	if s.Env.Conf != nil {
		s.Env.Conf.Reload()
	}
}
