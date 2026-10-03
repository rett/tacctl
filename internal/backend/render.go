package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// The TACCTL_FAULT points of the render (they replace the bash tests'
// overrides of a module's render_stage and of rendered_record):
//
//	render-stage:<id>   that backend's stage fails, silently, before it runs
//	render-commit:<id>  that backend's commit fails after it ran (its
//	                    artifact is replaced and recorded, so the restore
//	                    has something to put back)
const (
	FaultStage  = "render-stage"
	FaultCommit = "render-commit"
)

// errOut is an Output whose every line goes to Stderr (bash's 'warn ...
// >&2' and the render's '>&2').
func errOut(o ui.Output) ui.Output { return ui.Output{Stdout: o.Stderr, Stderr: o.Stderr} }

// Gate is backends_gate, step 1 of StoreApply: every backend of ids (the
// enabled ones when ids is empty) is asked whether its artifacts may be
// replaced. A command that changes backends.enabled gates the set its
// render will cover, which is not the one its writer has not yet changed.
// It returns the backends to adopt (render with force), or ErrRefused (one
// refused: a rendered file was edited), ErrFailed, or an *Error of code 2
// for an unknown id; every message is written.
func (s *Set) Gate(ctx context.Context, ids []string) ([]string, error) {
	enabled, err := s.Enabled()
	if err != nil {
		s.Env.Out.Error(err.Error())
		return nil, ErrFailed
	}
	if len(ids) == 0 {
		ids = enabled
	}
	var adopt []string
	for _, id := range ids {
		b, err := s.Get(id)
		if err != nil {
			s.Env.Out.Error(err.Error())
			return nil, &Error{Code: 2, Reason: "unknown backend"}
		}
		switch b.RenderGate(ctx) {
		case GateOK:
		case GateAdopt:
			adopt = append(adopt, id)
		case GateRefused:
			return nil, ErrRefused
		default:
			return nil, ErrFailed
		}
	}
	return adopt, nil
}

// RenderOptions say which backends render with force: they overwrite
// artifacts that are not what tacctl rendered (each keeps a copy first).
type RenderOptions struct {
	ForceAll bool     // --force: every backend
	Force    []string // --force=<id>: these backends
}

func (o RenderOptions) forced(id string) bool { return o.ForceAll || slices.Contains(o.Force, id) }

// RenderAll is backends_render_all: render the current store into the
// artifacts of every enabled backend, all of them or none. It returns the
// ids whose artifacts changed, in enabled order. On an error no artifact
// and no render record has changed: ErrRefused (a backend refused because
// of drift) or ErrFailed. Messages are written to Stderr (the store must
// exist; the enabled list must resolve; each backend writes its own).
//
// Pass 1 stages every backend into a private directory under os.TempDir
// (it holds every candidate config, secrets included, and is removed on
// every path). Then every artifact of the enabled backends and
// rendered.json are copied aside, and pass 2 commits: if a commit fails,
// every artifact and rendered.json are put back from the copies.
func (s *Set) RenderAll(ctx context.Context, opts RenderOptions) ([]string, error) {
	out := s.Env.Out
	if !isRegular(s.Env.Paths.StoreFile) {
		out.Error(store.NotInitialisedMsg)
		return nil, ErrFailed
	}
	enabled, err := s.Enabled()
	if err != nil {
		out.Error(err.Error())
		return nil, ErrFailed
	}
	tmpd, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		out.Error("Cannot create a staging directory: " + err.Error())
		return nil, ErrFailed
	}
	defer func() { _ = os.RemoveAll(tmpd) }()

	// Pass 1: stage. Nothing outside tmpd changes.
	for _, id := range enabled {
		dir := filepath.Join(tmpd, id)
		if err := os.Mkdir(dir, 0o700); err != nil {
			out.Error("Cannot create a staging directory: " + err.Error())
			return nil, ErrFailed
		}
		if s.Env.fault(FaultStage+":"+id) != nil {
			return nil, ErrFailed
		}
		if err := s.must(id).RenderStage(ctx, dir, opts.forced(id)); err != nil {
			if errors.Is(err, ErrRefused) {
				return nil, ErrRefused
			}
			return nil, ErrFailed
		}
	}
	if ctx.Err() != nil {
		return nil, ErrFailed
	}

	// Copies to put back if a commit fails.
	kept, err := s.Keep(filepath.Join(tmpd, ".keep"), enabled)
	if err != nil {
		out.Error("Cannot copy the rendered files aside: " + err.Error())
		return nil, ErrFailed
	}

	// Pass 2: commit.
	var changed []string
	for _, id := range enabled {
		ch, err := s.must(id).RenderCommit(ctx, filepath.Join(tmpd, id))
		if err == nil {
			err = s.Env.fault(FaultCommit + ":" + id)
		}
		if err != nil {
			kept.Restore()
			return nil, ErrFailed
		}
		if ch {
			changed = append(changed, id)
		}
	}
	return changed, nil
}

// Kept is the copies _backends_keep makes: every artifact of some backends
// and rendered.json, to put back with Restore.
type Kept struct {
	dir      string
	out      ui.Output
	rendered string
	entries  []keptEntry
}

type keptEntry struct {
	path string // the artifact
	copy string // its copy; "" when it did not exist
}

// Keep is _backends_keep: copies (cp -p: content, mode, owner, times) of
// every artifact of the backends ids and of rendered.json, in the new
// directory dir. An artifact that does not exist is remembered as absent:
// Restore removes it.
func (s *Set) Keep(dir string, ids []string) (*Kept, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k := &Kept{dir: dir, out: s.Env.Out, rendered: s.Env.Paths.Rendered}
	for _, id := range ids {
		b, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		for _, path := range b.Artifacts() {
			if path == "" {
				continue
			}
			e := keptEntry{path: path}
			if isRegular(path) {
				e.copy = filepath.Join(dir, itoa(len(k.entries)+1))
				if err := copyPreserve(path, e.copy); err != nil {
					return nil, err
				}
			}
			k.entries = append(k.entries, e)
		}
	}
	if isRegular(k.rendered) {
		if err := copyPreserve(k.rendered, filepath.Join(dir, "rendered.json")); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// Restore is _backends_render_restore: every kept artifact back in place,
// then rendered.json; an artifact that did not exist is removed. A file
// that cannot be put back is warned about (on Stderr) and skipped.
func (k *Kept) Restore() {
	for _, e := range k.entries {
		k.put(e.copy, e.path)
	}
	k.put(filepath.Join(k.dir, "rendered.json"), k.rendered)
}

// put is _backends_render_put: the kept file back through a rename beside
// its target, owner and mode as they were; no kept file means the target
// did not exist.
func (k *Kept) put(kept, dst string) {
	if kept == "" || !isRegular(kept) {
		_ = os.Remove(dst)
		return
	}
	tmp := dst + ".tacctl-new"
	if err := copyPreserve(kept, tmp); err == nil {
		if err := os.Rename(tmp, dst); err == nil {
			return
		}
	}
	_ = os.Remove(tmp)
	errOut(k.out).Warn("Could not put " + dst + " back; 'tacctl config render' rewrites it from the store.")
}

// RestartChanged is backends_restart_changed: restart the backends of
// changed (what RenderAll returned), except the ids in except (a caller
// that starts one itself, 'tacctl backend enable'). A restart reports its
// own outcome and never fails.
func (s *Set) RestartChanged(ctx context.Context, changed, except []string) {
	for _, id := range changed {
		if slices.Contains(except, id) {
			continue
		}
		if b, err := s.Get(id); err == nil {
			_, _ = b.Service(ctx, ServiceRestart, "")
		}
	}
}

// RestartAll is backends_restart_all: restart every enabled backend (a
// restore or a rollback restarts whether or not the rendered bytes
// changed). The enabled list that cannot be read is an error (message
// written).
func (s *Set) RestartAll(ctx context.Context) error {
	enabled, err := s.Enabled()
	if err != nil {
		s.Env.Out.Error(err.Error())
		return ErrFailed
	}
	s.RestartChanged(ctx, enabled, nil)
	return nil
}

// ConfigRender is 'tacctl config render [--force]' after its argument
// check (cmd_config_render): render every enabled backend, then per
// backend "Rendered <artifacts>." and a restart when its artifacts
// changed, "<artifacts> is already up to date." when not, and its render
// notes. A failed render is RenderAll's error.
func (s *Set) ConfigRender(ctx context.Context, force bool) error {
	changed, err := s.RenderAll(ctx, RenderOptions{ForceAll: force})
	if err != nil {
		return err
	}
	enabled, _ := s.Enabled() // RenderAll resolved it
	for _, id := range enabled {
		b := s.must(id)
		names, _ := s.ArtifactNames(id)
		if slices.Contains(changed, id) {
			s.Env.Out.Info("Rendered " + names + ".")
			_, _ = b.Service(ctx, ServiceRestart, "")
		} else {
			s.Env.Out.Info(names + " is already up to date.")
		}
		b.RenderNotes(ctx)
	}
	return nil
}
