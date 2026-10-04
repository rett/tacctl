package tacacs

import (
	"context"
	"errors"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// SmokeHook is the load-smoke as the importer and the lifecycle steps
// take it: nil passed, ErrSmokeSkipped without the daemon, ErrReported
// failed (with the module's message).
func TestSmokeHookVerdicts(t *testing.T) {
	ctx := context.Background()
	e := newTenv(t)
	out := e.renderedFile()
	if err := e.b.SmokeHook(ctx, out); !errors.Is(err, store.ErrSmokeSkipped) {
		t.Errorf("no daemon: %v", err)
	}
	bin := e.smokeBin()
	e.run.On([]string{bin}, execx.Result{Stderr: []byte("FATAL: main.go:98: error fetching config; loader failed\n")})
	if err := e.b.SmokeHook(ctx, out); !errors.Is(err, ui.ErrReported) {
		t.Errorf("fatal: %v", err)
	}
	e.run.On([]string{bin}, execx.Result{Stderr: []byte("INFO: main.go:135: serve on 127.0.0.1:40001\n" +
		"INFO: loader.go:241: updated all providers from config source\n")})
	if err := e.b.SmokeHook(ctx, out); err != nil {
		t.Errorf("serve: %v", err)
	}
}

// The phases' entry points: the lifecycle steps over this module's
// environment, with its load-smoke.
func TestLifecycleEntryPoints(t *testing.T) {
	ctx := context.Background()
	e := newTenv(t)
	if env := e.b.Lifecycle(); env.Smoke == nil || env.Env != e.env {
		t.Error("lifecycle env")
	}
	// Nothing installed: no config, no store.
	if changed, err := e.b.ConfigSyncExisting(ctx); changed || err != nil {
		t.Error(changed, err)
	}
	if r := e.b.UpgradeStoreFlip(ctx); r != lifecycle.FlipStopped {
		t.Error(r)
	}
	e.withStore("store.minimal.yaml")
	if r := e.b.UpgradeStoreFlip(ctx); r != lifecycle.StorePresent {
		t.Error(r)
	}
	// With a store and no tacquito.yaml, the sync renders it.
	if changed, err := e.b.ConfigSyncExisting(ctx); !changed || err != nil {
		t.Errorf("%v %v\n%s", changed, err, e.stderr)
	}
}
