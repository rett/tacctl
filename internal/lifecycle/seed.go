package lifecycle

// install_seed_config (lib/lifecycle.sh at 0.1.16): the configuration an
// install starts with.

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// DefaultScopeFresh is DEFAULT_SCOPE_FRESH, the scope a fresh install
// seeds (and tacctl's shipped scope.default).
const DefaultScopeFresh = "lab"

// InstallScopePrefixes is INSTALL_SCOPE_PREFIXES: what the shipped
// tacquito.yaml template listed for the first scope (RFC 1918).
const InstallScopePrefixes = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

// SeedMode is INSTALL_CONFIG_MODE.
type SeedMode string

// The modes of InstallSeed.
const (
	// SeedFresh: store seeded and rendered; the result holds the new secret.
	SeedFresh SeedMode = "fresh"
	// SeedStore: a store was already there and was kept.
	SeedStore SeedMode = "store"
	// SeedFlipped: a legacy tacquito.yaml was already there and moved into
	// the store.
	SeedFlipped SeedMode = "flipped"
	// SeedLegacy: a legacy tacquito.yaml was already there and the gate
	// stopped (legacy read-only mode).
	SeedLegacy SeedMode = "legacy"
)

// SeedResult is what install_seed_config hands its caller
// (INSTALL_CONFIG_MODE, INSTALL_SHARED_SECRET): the secret is set only in
// SeedFresh mode and is never printed here (the install summary shows it
// once).
type SeedResult struct {
	Mode   SeedMode
	Secret string
}

// InstallSeed is install_seed_config: give the install its configuration.
// It needs the state and config directories (StateMigrate, and the
// backends' 'install account' phase).
//
// The backups directories are made first (backups and password-dates
// 0750, backups/disabled 0700; as root given to tacquito:tacquito, and a
// failure stops the install). Then:
//
//   - a store that exists is kept as it is ('upgrade config' phase of
//     every enabled backend, which re-renders: SeedStore; a phase that
//     fails is warned about and the install goes on);
//   - a legacy tacquito.yaml is kept and goes through what an upgrade does
//     to it: ConfigSyncExisting, then UpgradeStoreFlip (SeedFlipped, or
//     SeedLegacy when the gate stopped);
//   - otherwise a fresh store: the built-in groups, the scope
//     DefaultScopeFresh with InstallScopePrefixes and a generated shared
//     secret (16 random bytes, hex), the seed users disabled;
//     scope.default set to it (the shipped default, so nothing is
//     written); dead command matches healed in a tacctl.yaml adopted from
//     an earlier install; every enabled backend rendered (SeedFresh).
//
// Existing data is never replaced. The error is ui.ErrReported (printed):
// the install stops.
func InstallSeed(ctx context.Context, env *Env) (SeedResult, error) {
	p, out := env.Paths, env.Out
	disabled := filepath.Join(p.BackupDir, "disabled")
	for _, d := range []string{p.BackupDir, disabled, p.PWDatesDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			stderrLine(out, "mkdir: "+err.Error())
			return SeedResult{}, ui.ErrReported
		}
	}
	_ = os.Chmod(p.BackupDir, 0o750)
	_ = os.Chmod(p.PWDatesDir, 0o750)
	_ = os.Chmod(disabled, 0o700)
	if err := env.chownStrict(p.BackupDir, p.PWDatesDir); err != nil {
		stderrLine(out, "chown: "+err.Error())
		return SeedResult{}, ui.ErrReported
	}

	if isRegular(p.StoreFile) {
		out.InfoE("Existing store found at " + p.StoreFile + ": its users, groups and scopes are kept (no new shared secret).")
		ids, err := env.Set.Enabled()
		if err != nil {
			out.ErrorE(err.Error())
			return SeedResult{}, ui.ErrReported
		}
		// Each phase reports its own problems; a failure is named once
		// more with the way to finish the job, and stops nothing.
		for _, id := range ids {
			if b, err := env.Set.Get(id); err == nil {
				if err := b.Upgrade(ctx, backend.PhaseConfig, ""); err != nil {
					out.Warn(id + ": configuration step failed (see above); run 'tacctl upgrade' after the install")
				}
			}
		}
		return SeedResult{Mode: SeedStore}, nil
	}
	if isRegular(p.Config) {
		out.InfoE("Existing " + p.Config + " found: it is kept, not replaced by a fresh configuration.")
		// As 0.1.16 did with errexit off: a migration that fails says so,
		// the others still run, and the gate judges the file as it is.
		_, _ = ConfigSyncExisting(ctx, env, SyncOptions{ContinueOnError: true})
		if UpgradeStoreFlip(ctx, env) == Flipped {
			return SeedResult{Mode: SeedFlipped}, nil
		}
		return SeedResult{Mode: SeedLegacy}, nil
	}

	raw := make([]byte, 16)
	if _, err := io.ReadFull(env.rand(), raw); err != nil {
		out.ErrorE("Could not generate a shared secret (openssl rand failed).")
		return SeedResult{}, ui.ErrReported
	}
	secret := hex.EncodeToString(raw)
	out.InfoE("Seeding the store at " + p.StoreFile + "...")
	if err := store.SeedFresh(p.StoreFile, DefaultScopeFresh, InstallScopePrefixes, secret); err != nil {
		report(out, err)
		return SeedResult{}, ui.ErrReported
	}

	// 'tacctl user add <u> <g>' without --scopes lands new users in this
	// scope (least privilege by default). It is also tacctl's shipped
	// default, so no override is persisted.
	if err := env.Conf.Set("scope.default", DefaultScopeFresh); err != nil {
		report(out, err)
		return SeedResult{}, ui.ErrReported
	}
	out.InfoE("Default scope seeded: " + DefaultScopeFresh + " (new users land here unless --scopes given)")
	// A tacctl.yaml adopted from an earlier install may still carry
	// pre-0.1.11 dead match regexes (no-op otherwise).
	_ = MigrateDeadCommandMatches(env)

	out.InfoE("Writing configuration to " + env.Set.AllArtifactNames() + "...")
	if _, err := env.Set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		out.ErrorE("Could not render " + env.Set.AllArtifactNames() + " from the store.")
		return SeedResult{}, ui.ErrReported
	}
	out.InfoE("Built-in users seeded (disabled — set a password to activate):")
	out.InfoE("  engineer (superuser) — disabled")
	out.InfoE("  operator (operator)  — disabled")
	out.InfoE("  viewer   (readonly)  — disabled")
	out.InfoE("  root     (readonly)  — disabled (accounting sink for Junos internal daemons)")
	return SeedResult{Mode: SeedFresh, Secret: secret}, nil
}

// chownStrict is 'chown tacquito:tacquito <path>...' where a failure is
// an error (as root; unprivileged runs, the test suite's, skip it as the
// suite's chown stub does).
func (e *Env) chownStrict(paths ...string) error {
	if !e.IsRoot {
		return nil
	}
	uid, gid, err := tacquitoIDs()
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
