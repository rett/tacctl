package tacacs

import (
	"context"
	"errors"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/model"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/store"
)

// renderer is the render steps over the invocation's paths and tacctl.yaml
// view; every message goes to Stderr.
func (b *Backend) renderer() *rtacacs.Renderer {
	return &rtacacs.Renderer{
		Paths:  b.paths(),
		Conf:   b.env.Conf,
		Load:   rtacacs.DefaultLoader,
		Chown:  b.Chown,
		Now:    b.env.Now,
		Stderr: b.env.Out.Stderr,
	}
}

// RenderCheck is backend_tacacs_render_check: a trial render, nothing
// installed; with converted units the word covers the drop-ins too.
func (b *Backend) RenderCheck(context.Context) (string, error) {
	word, err := b.renderer().Check(!b.legacyUnits())
	if err != nil {
		return "", backend.ErrFailed
	}
	return word, nil
}

// RenderGate is backend_tacacs_render_gate (_tacacs_render_gate).
func (b *Backend) RenderGate(context.Context) backend.GateResult {
	switch b.renderer().Gate() {
	case rtacacs.GateOK:
		return backend.GateOK
	case rtacacs.GateAdopt:
		return backend.GateAdopt
	case rtacacs.GateRefused:
		return backend.GateRefused
	}
	return backend.GateFailed
}

// RenderStage is backend_tacacs_render_stage: tacquito.yaml, and the
// listeners' drop-ins unless the install is not converted, into dir.
func (b *Backend) RenderStage(_ context.Context, dir string, force bool) error {
	if !isRegular(b.env.Paths.StoreFile) {
		b.errOut().Error(store.NotInitialisedMsg)
		return backend.ErrFailed
	}
	err := b.renderer().Stage(dir, force, !b.legacyUnits())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rtacacs.ErrRefused):
		return backend.ErrRefused
	}
	return backend.ErrFailed
}

// RenderCommit is backend_tacacs_render_commit: tacquito.yaml, then the
// drop-ins; systemd is told about changed drop-ins (once there is a unit to
// reload). The restart that makes a process use them is the 'service
// restart' that follows a change.
func (b *Backend) RenderCommit(ctx context.Context, dir string) (bool, error) {
	r := b.renderer()
	changed, err := r.CommitConfig(dir)
	if err != nil {
		return false, backend.ErrFailed
	}
	written, err := r.CommitUnits(dir)
	if err != nil {
		return false, backend.ErrFailed
	}
	if len(written) > 0 && isRegular(b.serviceFile()) {
		stderr := b.env.Out.Stderr
		_, _ = b.env.Runner.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"daemon-reload"}, Stdout: stderr, Stderr: stderr})
	}
	return changed || len(written) > 0, nil
}

// RenderNotes is backend_tacacs_render_notes: tacquito refuses to serve a
// config without users or without scopes.
func (b *Backend) RenderNotes(context.Context) {
	p := b.env.Paths
	_, m, _, err := model.Load(model.Paths{Store: p.StoreFile, Config: p.Config, DatesDir: p.PWDatesDir,
		DisabledDir: p.BackupDir + "/disabled"})
	if err != nil || len(m.Users) == 0 || len(m.Scopes) == 0 {
		b.out().Warn("The store has no users or no scopes; tacquito refuses to serve such a config.")
	}
}
