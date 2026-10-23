package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// services are what an App makes on first use; each exists at most once
// per invocation.
type services struct {
	conf     *conf.Config
	prompter *ui.Prompter
	snaps    *snapshot.Snapshotter
	env      *backend.Env
	set      *backend.Set
	lock     *applylock.Lock
	// audit is made once, under auditOnce: the device pulls log from their
	// pool, so the first call may come from several goroutines.
	audit     *audit.Writer
	auditOnce sync.Once
}

// nothingChanged is a wait for the apply lock that the invocation's context
// ended (Ctrl-C): the message is the operator's whole answer.
type nothingChanged struct{}

func (nothingChanged) Error() string { return "Nothing was changed." }

// SetContext gives the App the invocation's context (the one Ctrl-C cancels),
// which a wait for the apply lock watches. cli.Run sets it; an App without
// one waits on context.Background.
func (a *App) SetContext(ctx context.Context) { a.ctx = ctx }

// ApplyLock is the invocation's apply lock (internal/applylock) on
// <StateDir>/.store-apply.lock: the one lock object of the process, which
// backend.Env.ApplyLock and the tacctl.yaml writers (Conf) share, so that a
// write inside a transaction re-enters it instead of waiting for it.
func (a *App) ApplyLock() *applylock.Lock {
	if a.svc.lock == nil {
		a.svc.lock = applylock.New(a.Paths.StateDir)
	}
	return a.svc.lock
}

// confLock is conf.Config.Lock: the apply lock with the invocation's context
// and the waiting line.
func (a *App) confLock() (func(), error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := a.ApplyLock().Acquire(ctx, func() { a.Out.Info(backend.WaitingMsg) })
	if errors.Is(err, applylock.ErrCancelled) {
		return nil, nothingChanged{}
	}
	return release, err
}

// Conf is tacctl.yaml as this invocation sees it: conf.Load of the
// overrides file with the registered backends (the CLI blank-imports
// internal/backend/all, so the registry holds the shipped modules). Writes
// through it reload it, StoreApply's rollback does too, and each takes the
// apply lock (ApplyLock) around the write.
func (a *App) Conf() *conf.Config {
	if a.svc.conf == nil {
		a.svc.conf = conf.Load(a.Paths.Overrides, backend.Default().IDs())
		a.svc.conf.Lock = a.confLock
	}
	return a.svc.conf
}

// WarnConf is what sourcing lib/conf.sh does at the start of every 0.1.16
// command: one '[WARN] tacctl.yaml: could not parse ...' line on stderr
// when the overrides file cannot be used, and nothing otherwise. A native
// command calls it before anything else (the CLI's native wrapper does).
func (a *App) WarnConf() { a.Conf().WarnOnce(a.Out.Stderr) }

// Tunables are lib/conf.sh's source-time tunables (bcrypt cost, password
// and secret minimum lengths, password age), from Conf.
func (a *App) Tunables() conf.Tunables { return a.Conf().Tunables() }

// Prompter is the invocation's one prompter on stdin, shared with the
// backend modules (backend.Env.Prompter): every prompt of the run reads
// through one buffer, so none swallows the answer meant for the next.
func (a *App) Prompter() *ui.Prompter {
	if a.svc.prompter == nil {
		in := a.Stdin
		if in == nil {
			in = strings.NewReader("")
		}
		a.svc.prompter = ui.NewPrompter(in, a.Out)
	}
	return a.svc.prompter
}

// Snapshots takes the pre-change snapshots (backup_snapshot) with the
// knob clock and the TACCTL_FAULT check.
func (a *App) Snapshots() *snapshot.Snapshotter {
	if a.svc.snaps == nil {
		s := snapshot.New(a.Paths, a.Version, a.Knobs.Now, a.Out)
		s.Fault = a.Knobs.Fault
		s.LedgerLock = hosts.UIDs{Path: a.Paths.LinuxUIDs}.Lock
		a.svc.snaps = s
	}
	return a.svc.snaps
}

// BackendEnv is what the backend modules and the mutation machinery work
// with in this invocation.
func (a *App) BackendEnv() *backend.Env {
	if a.svc.env == nil {
		a.svc.env = &backend.Env{
			Paths:     a.Paths,
			Conf:      a.Conf(),
			Runner:    a.Runner,
			Out:       a.Out,
			Stdin:     a.Stdin,
			Prompter:  a.Prompter(),
			Now:       a.Knobs.Now,
			Fault:     a.Knobs.Fault,
			Snapshots: a.Snapshots(),
			ApplyLock: a.ApplyLock(),
		}
	}
	return a.svc.env
}

// Backends is the invocation's backend set (registry modules made on first
// use with BackendEnv). Every store change goes through its StoreApply.
func (a *App) Backends() *backend.Set {
	if a.svc.set == nil {
		a.svc.set = backend.NewSet(backend.Default(), a.BackendEnv())
	}
	return a.svc.set
}

// MutateOptions are the options of a store.Mutate made inside a
// StoreApply writer (the snapshot hook and the knob clock).
func (a *App) MutateOptions() store.MutateOptions { return a.BackendEnv().MutateOptions() }

// ModelPaths are the files model_load reads.
func (a *App) ModelPaths() model.Paths {
	return model.Paths{
		Store:       a.Paths.StoreFile,
		Config:      a.Paths.Config,
		DatesDir:    a.Paths.PWDatesDir,
		DisabledDir: filepath.Join(a.Paths.BackupDir, "disabled"),
	}
}

// LoadModel is model_load: the store, else the model of tacquito.yaml
// (legacy read-only mode), else *model.NoSourceError. It reads the files
// on every call, so a command that wrote sees its own change.
func (a *App) LoadModel() (*model.Model, error) {
	_, m, _, err := model.Load(a.ModelPaths())
	return m, err
}

// Preflight is preflight (lib/core.sh at 0.1.16) without the python3-bcrypt
// check (docs/plans/go-rewrite.md 3.9 item 4): a store, or a legacy
// tacquito.yaml, must exist, else the error is printed and ui.ErrReported
// returned (exit 1). With a store, no tacquito.yaml and TACACS+ enabled it
// warns (on stderr) that 'config render' writes the file again.
func (a *App) Preflight() error {
	storeOK, configOK := isFile(a.Paths.StoreFile), isFile(a.Paths.Config)
	if !storeOK && !configOK {
		a.Out.Error("Config not found: no store at " + a.Paths.StoreFile + " and no " + a.Paths.Config +
			". Is tacctl installed? (tacctl install)")
		return ui.ErrReported
	}
	if storeOK && !configOK {
		if ids, err := a.Backends().Enabled(); err == nil && slices.Contains(ids, backend.TACACS) {
			ui.Output{Stdout: a.Out.Stderr}.Warn("TACACS+ is enabled and " + a.Paths.Config +
				" is missing; 'tacctl config render' writes it again.")
		}
	}
	return nil
}

// Audit is the invocation's audit writer (internal/audit): 'logger -t
// tacctl -p <priority>' on the process's context with the cancellation
// taken off, so that no line is lost because a signal is ending the
// command, the session id (sid=) appended to every line, the actor of
// SUDO_USER and SUDO_UID, and the one warning on standard error when
// logger could not write. The session id is made on the first call, which
// the tier gate makes before it decides anything.
func (a *App) Audit() *audit.Writer {
	a.svc.auditOnce.Do(func() {
		a.svc.audit = audit.New(audit.Options{
			Runner: a.Runner,
			Ctx:    a.ctx,
			SID:    audit.NewSID(a.Knobs.Rand()),
			Actor:  audit.ActorOf(a.Env.Get("SUDO_USER"), a.Env.Get("SUDO_UID")),
			Warn:   func(msg string) { ui.Output{Stdout: a.Out.Stderr}.Warn(msg) },
		})
	})
	return a.svc.audit
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
