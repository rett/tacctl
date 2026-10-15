package backend

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/store"
)

// WaitingMsg is the one line a command prints while another one holds the
// apply lock.
const WaitingMsg = "Waiting for another tacctl command that is changing the configuration..."

// errNested is a StoreApply, ApplyForced or ConfigRender started inside the
// writer of another: a change inside a change. The outer rollback would take
// the inner change with it, and the inner one would wait for a lock its own
// writer holds were the lock not reentrant.
var errNested = &Error{Code: 1, Reason: "internal: a change inside a change"}

// begin is what every transaction of this file does first: refuse a change
// inside a writer.
func (s *Set) begin() error {
	if s.Env.inWriter {
		s.Env.Out.Error("Internal error: a change was started inside the writer of another change.")
		return errNested
	}
	return nil
}

// lock takes the apply lock (Env.ApplyLock; none when it is nil) and returns
// the function that gives it back, or the error to return, its messages
// written: a wait that ctx ended is "Nothing was changed." (exit 1).
func (s *Set) lock(ctx context.Context) (func(), error) {
	out := s.Env.Out
	release, err := s.Env.ApplyLock.Acquire(ctx, func() { out.Info(WaitingMsg) })
	if err == nil {
		return release, nil
	}
	if !errors.Is(err, applylock.ErrCancelled) {
		out.Error(err.Error())
	}
	out.Error("Nothing was changed.")
	return nil, ErrFailed
}

// runWriter runs a transaction's writer with the snapshot held and
// Env.inWriter set, whatever the writer does.
func (s *Set) runWriter(writer func() error) error {
	env := s.Env
	release := func() {}
	if env.Snapshots != nil {
		release = env.Snapshots.Hold()
	}
	env.inWriter = true
	defer func() {
		env.inWriter = false
		release()
	}()
	return writer()
}

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
	// RestartFailed are the backends whose restart did not succeed, each
	// with the command the warning named: their running daemon has the
	// configuration it had before, the rendered files are the new ones.
	RestartFailed []RestartFailure
}

// StoreApply is store_apply, the one mutation path: every command that
// changes users, groups, scopes, filters or command rules runs its writes
// through it.
//
//  0. lock     the store must exist (Require), then the apply lock is taken
//     (Env.ApplyLock; reentrant): a command that is changing the
//     configuration holds it, this one waits (the one line WaitingMsg,
//     Ctrl-C ends the wait: "Nothing was changed.", exit 1). It is held
//     through the last step, the restart included, and given back on every
//     return.
//  1. gate     every gated backend's artifacts must be replaceable; a
//     refusal stops here, before anything is written.
//  2. backup   a snapshot (Env.Snapshots; skipped when nothing changed since
//     the newest one), then private copies of store.yaml and tacctl.yaml
//     under <state>/.apply.*; a snapshot that cannot be made refuses the
//     command, before anything is written.
//  3. write    writer, with the snapshot held: the store writes it makes
//     with Env.MutateOptions() take no snapshot of their own.
//  4. render   RenderAll, forcing the backends the gate said to adopt. If it
//     fails, no artifact has changed, and store.yaml and tacctl.yaml are
//     put back as they were (and Env.Conf reloaded). A file that the writer
//     left and that is not what the writer left now (a hand edit) is saved
//     as <state>/<file>.overwritten-<stamp> and named in a warning first;
//     one that is what it was before the command is not touched.
//  5. restart  only the backends whose rendered config changed, except
//     DeferRestart; one that did not restart is in Result.RestartFailed
//     (the files stay rendered, the change is not undone).
//
// It returns ErrRefused (exit 3: a rendered file was edited by hand;
// nothing changed), ErrFailed (exit 1: nothing changed, a partial write was
// rolled back) or an *Error of code 2 (an unknown id in opts.Gate), with
// every message written. A writer error is returned as it is, after the
// rollback, without being printed: the caller reports it (exit 1). The
// writer must not take the store lock around a store.Mutate of its own, and
// must not start a StoreApply, ApplyForced or ConfigRender (an internal
// error, exit 1).
func (s *Set) StoreApply(ctx context.Context, opts ApplyOptions, writer func() error) (Result, error) {
	env := s.Env
	if err := s.begin(); err != nil {
		return Result{}, err
	}
	// The store must exist before the lock does: with no state directory
	// there is nothing to lock and nothing to create.
	if err := s.Require(); err != nil {
		return Result{}, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
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
	werr := s.runWriter(writer)
	s.reloadConf() // a writer may have replaced tacctl.yaml by hand
	post := s.filesNow()
	if werr != nil {
		s.rollback(keep, post)
		return Result{}, werr
	}

	changed, err := s.RenderAll(ctx, RenderOptions{Force: adopt})
	if err != nil {
		// Named before the rollback: a change of backends.enabled changes
		// which backends these are.
		names := s.AllArtifactNames()
		s.rollback(keep, post)
		env.Out.Error("The change was not applied: " + names + " could not be rendered. Store and tacctl.yaml are as they were.")
		return Result{}, ErrFailed
	}
	// Still under the lock: a restart that ran after it was given up could
	// start a daemon on another command's half-committed render, and the
	// failure would be put on this command.
	failed := s.RestartChanged(ctx, changed, opts.DeferRestart)
	return Result{Changed: changed, Adopted: adopt, RestartFailed: failed}, nil
}

// fileState is a file's bytes at one moment (ok false: it does not exist).
type fileState struct {
	data []byte
	ok   bool
}

func readState(path string) fileState {
	data, err := os.ReadFile(path)
	return fileState{data: data, ok: err == nil}
}

func (a fileState) equal(b fileState) bool { return a.ok == b.ok && bytes.Equal(a.data, b.data) }

// filesNow is store.yaml and tacctl.yaml as they are now, in that order:
// what a writer left, for the guard of the rollbacks.
func (s *Set) filesNow() [2]fileState {
	return [2]fileState{readState(s.Env.Paths.StoreFile), readState(s.Env.Paths.Overrides)}
}

// guard is the check a rollback makes on one file before it puts the copy
// back (D157): start is the copy's bytes (absent: there was none) and post
// what the writer left. It reports whether the file is to be put back.
//
// A file that is what it was before the command is not touched (a writer
// that wrote nothing keeps its inode, mode and times). One that is not what
// the writer left can only be a hand edit, since the apply lock keeps every
// other tacctl writer out: it is saved as <state>/<name>.overwritten-<stamp>
// (0600) and the warning names that file, and then it is put back like the
// others, as the command's contract is that nothing changed.
func (s *Set) guard(name, live string, start, post fileState) (restore bool) {
	now := readState(live)
	if now.equal(start) {
		return false
	}
	if now.ok && !now.equal(post) {
		s.saveOverwritten(name, live, now.data)
	}
	return true
}

// saveOverwritten writes data as <state>/<name>.overwritten-<stamp> and warns
// with that name. A copy that cannot be written is said so, and the file is
// put back all the same.
func (s *Set) saveOverwritten(name, live string, data []byte) {
	env := s.Env
	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	base := filepath.Join(env.Paths.StateDir, name+".overwritten-"+now().Format("20060102_150405"))
	saved := ""
	for n := 0; n < 100 && saved == ""; n++ {
		path := base
		if n > 0 {
			path += "-" + strconv.Itoa(n)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			break
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr != nil || cerr != nil {
			_ = os.Remove(path)
			break
		}
		saved = path
	}
	if saved == "" {
		env.Out.Warn(live + " was changed while this command ran, and that version could not be saved; the file was put back as it was before this command.")
		return
	}
	env.Out.Warn(live + " was changed while this command ran (a hand edit); that version is saved as " + saved +
		" and the file was put back as it was before this command.")
}

// rollback is _store_apply_rollback: store.yaml and tacctl.yaml back from
// the copies in keep (no copy of tacctl.yaml: there was none), and the
// invocation's view of tacctl.yaml reloaded. post is what the writer left
// (filesNow right after it returned).
func (s *Set) rollback(keep string, post [2]fileState) {
	p := s.Env.Paths
	kept := filepath.Join(keep, "store.yaml")
	if s.guard("store.yaml", p.StoreFile, readState(kept), post[0]) {
		_ = os.Rename(kept, p.StoreFile)
	}
	kept = filepath.Join(keep, "tacctl.yaml")
	if s.guard("tacctl.yaml", p.Overrides, readState(kept), post[1]) {
		if isRegular(kept) {
			_ = os.Rename(kept, p.Overrides)
		} else {
			_ = os.Remove(p.Overrides)
		}
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
// ErrFailed (the messages are the writer's and the render's). It holds the
// apply lock like StoreApply, from before the copies to after the rollback
// or the render (its caller's restarts are the caller's: one that must not
// be interleaved holds the reentrant lock itself), and refuses to be started
// inside a writer.
func (s *Set) ApplyForced(ctx context.Context, writer func() error) ([]string, error) {
	env := s.Env
	if err := s.begin(); err != nil {
		return nil, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
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
	env.inWriter = true
	func() {
		defer func() { env.inWriter = false }()
		err = writer()
	}()
	s.reloadConf() // the writer replaced tacctl.yaml (_conf_invalidate)
	post := s.filesNow()
	var changed []string
	if err == nil {
		changed, err = s.RenderAll(ctx, RenderOptions{ForceAll: true})
	}
	release()
	if err != nil {
		s.rollbackRestore(keep, post)
		return nil, ErrFailed
	}
	return changed, nil
}

// rollbackRestore is _backup_apply_rollback: like rollback, guard included,
// except that a store.yaml that did not exist before is removed.
func (s *Set) rollbackRestore(keep string, post [2]fileState) {
	p := s.Env.Paths
	for i, f := range [][2]string{{"store.yaml", p.StoreFile}, {"tacctl.yaml", p.Overrides}} {
		kept := filepath.Join(keep, f[0])
		if !s.guard(f[0], f[1], readState(kept), post[i]) {
			continue
		}
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
