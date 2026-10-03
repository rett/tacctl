package tacacs

// The legacy mode of the TACACS+ backend as its lifecycle phases reach it
// (lib/backends/tacacs.sh at 0.1.16: config_sync_existing is the 'upgrade
// config' phase, upgrade_store_flip the start of 'upgrade finish'). The
// steps themselves are internal/lifecycle's (legacy.go, flip.go), which
// reach this module through the backend contract and lifecycle.Smoker; this
// file gives them the module's load-smoke and chown, and gives the phases
// (WP3.3b) one call each.

import (
	"context"
	"os"

	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

var _ lifecycle.Smoker = (*Backend)(nil)

// SmokeHook is the load-smoke in the form store.ImportOptions.Smoke and
// lifecycle.Env.Smoke take (store_smoke_hook): nil passed,
// store.ErrSmokeSkipped when there is no daemon binary, ui.ErrReported
// failed (LoadSmoke said why).
func (b *Backend) SmokeHook(ctx context.Context, rendered string) error {
	switch b.LoadSmoke(ctx, rendered) {
	case SmokePassed:
		return nil
	case SmokeSkipped:
		return store.ErrSmokeSkipped
	}
	return ui.ErrReported
}

// Lifecycle is the lifecycle.Env of this backend's invocation: its
// environment, its load-smoke and chown, crypto/rand, root when the
// process runs as root.
func (b *Backend) Lifecycle() *lifecycle.Env {
	e := lifecycle.NewEnv(b.env, nil, os.Geteuid() == 0)
	e.Smoke = b.SmokeHook
	e.Chown = b.Chown
	return e
}

// ConfigSyncExisting is config_sync_existing over this backend
// (lifecycle.ConfigSyncExisting) as the 'upgrade config' phase runs it:
// the first migration that fails stops it (0.1.16 under 'set -e'). It
// returns whether tacquito.yaml changed (CONFIG_SYNC_RENDERED), which
// 'upgrade finish' needs.
func (b *Backend) ConfigSyncExisting(ctx context.Context) (bool, error) {
	return lifecycle.ConfigSyncExisting(ctx, b.Lifecycle(), lifecycle.SyncOptions{})
}

// UpgradeStoreFlip is upgrade_store_flip over this backend
// (lifecycle.UpgradeStoreFlip): the store gate at the start of 'upgrade
// finish'.
func (b *Backend) UpgradeStoreFlip(ctx context.Context) lifecycle.FlipResult {
	return lifecycle.UpgradeStoreFlip(ctx, b.Lifecycle())
}
