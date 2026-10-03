// Package radius is the RADIUS backend module: FreeRADIUS from the distro
// package serving the store over PAP (lib/backends/radius.sh at the 0.1.16
// tag, the contract functions backend_radius_*). It implements
// backend.Backend: the artifacts and their render steps, the unit and its
// drop-in, the listeners, the status and log sections, last login, secret
// constraints and device variables. The lifecycle phases (install, upgrade,
// uninstall) are WP3.3c's; phases.go holds their placeholders until then.
//
// The pure half, the renderer, is internal/render/radius. What this package
// adds around it is everything that touches the machine: the drift states of
// the live files against the render (internal/rendered), the daemon's own
// configuration check, the stage, commit and gate of a mutation, the
// systemd unit, and the reports.
//
// # Where things are written
//
// Following internal/backend: the render steps (RenderCheck, RenderGate,
// RenderStage, RenderCommit) write everything to Env.Out.Stderr; RenderNotes,
// Service and the listener setters write info and warn lines to
// Env.Out.Stdout and errors to Env.Out.Stderr; Status, Log and Accounting
// write their report to the io.Writer they are given. A failure whose
// message has been written is backend.ErrFailed (or ErrRefused for a refused
// render); an unknown status part, log sub-command or service action is
// backend.ErrUnsupported and writes nothing. ListenerOps.Show returns the
// text the command prints and writes a failure's message itself.
//
// # What a hand edit means here
//
// There is no way to adopt a hand edit of the RADIUS files into the store,
// so Describe has no ImportCmd, the gate refuses a file tacctl has no record
// of as it refuses an edited one, and 'tacctl config render --force' is the
// only way back (the file it displaces is kept under backups/legacy/).
package radius

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	rr "github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

func init() { backend.Register(backend.RADIUS, New) }

// Module is the RADIUS backend of one invocation. Make it with the factory
// (New, through backend.Set.Get) or NewModule; the exported fields are the
// seams tests and callers may replace before first use.
type Module struct {
	env    *backend.Env
	runner execx.Runner
	// L is the FreeRADIUS layout in use: the family's, with the
	// TACCTL_RADIUS_* overrides applied.
	L paths.RadiusPaths

	// Apply runs a writer through backend.Set.StoreApply (the listener
	// setters change tacctl.yaml and must render and restart as every
	// mutation does). nil: a Set over the default registry with this
	// module's Env, which is what a production invocation is.
	Apply func(ctx context.Context, opts backend.ApplyOptions, writer func() error) (backend.Result, error)
	// Sleep waits d, or until ctx ends (nil: the real clock).
	Sleep func(ctx context.Context, d time.Duration)
	// Chown gives path to root and the daemon's group, best effort as
	// 'chown root:<group> 2>/dev/null || true' (nil: the real thing). Tests
	// replace it to see what was asked for.
	Chown func(path string)
}

var _ backend.Backend = (*Module)(nil)

// New is the module's factory: the family is detected once, here
// (TACCTL_RADIUS_FAMILY decides; else the raddb directory, else the package
// manager).
func New(env *backend.Env) backend.Backend {
	r := env.Runner
	if r == nil {
		r = execx.Real{}
	}
	pe := paths.NewEnv([]string{"TACCTL_RADIUS_FAMILY=" + env.Paths.RadiusFamily})
	return NewModule(env, rr.DetectFamily(pe, nil, r))
}

// NewModule is the module for a distribution family ("debian", "rhel" or
// "" for neither, which selects the Debian layout as in bash).
func NewModule(env *backend.Env, family string) *Module {
	m := &Module{env: env, runner: env.Runner, L: rr.Layout(env.Paths, family)}
	if m.runner == nil {
		m.runner = execx.Real{}
	}
	m.Chown = m.chownRootGroup
	return m
}

// ID is "radius".
func (m *Module) ID() string { return backend.RADIUS }

// Describe is backend_radius_describe: no ImportCmd (a hand edit cannot be
// adopted).
func (m *Module) Describe() backend.Description {
	return backend.Description{
		Protocol:  "radius",
		Impl:      "freeradius",
		Units:     []string{m.L.Unit},
		User:      m.L.User,
		ConfigDir: m.L.Dir,
		LogDir:    m.L.LogDir,
	}
}

// Installed is backend_radius_installed: the daemon is on this machine and
// tacctl has set it up: its drop-in is in place (enabled), or its rendered
// config is (disabled; still tacctl's to remove on uninstall). The package
// alone is not tacctl's install.
func (m *Module) Installed() bool {
	return isExec(m.L.Bin) && (isFile(m.L.DropIn) || isFile(m.L.Conf))
}

// Artifacts is backend_radius_artifacts: the main config, the users file and
// the dictionary.
func (m *Module) Artifacts() []string { return []string{m.L.Conf, m.L.Users, m.L.Dict} }

// SecretConstraints is the interoperability advice: the shortest limit among
// the RADIUS clients a figure was found for, printable ASCII without a
// space. Advice only; the renderer refuses what it cannot write.
func (m *Module) SecretConstraints() backend.Constraints {
	return backend.Constraints{MaxLen: rr.SecretMaxLen, Charset: rr.SecretCharset}
}

// DeviceVars is backend_radius_device_vars: what a RADIUS device template
// needs from the daemon (AUTH_PORT, ACCT_PORT from the built-in listeners'
// names, SECRET of the scope when it is known). The vendor changes nothing
// here.
func (m *Module) DeviceVars(_ context.Context, _, scope string) (map[string]string, error) {
	vars := map[string]string{}
	for _, l := range m.effectiveListeners() {
		port := l.Address[strings.LastIndexByte(l.Address, ':')+1:]
		switch l.Name {
		case "auth":
			vars["AUTH_PORT"] = port
		case "acct":
			vars["ACCT_PORT"] = port
		}
	}
	if scope != "" {
		if secret, ok := m.scopeSecret(scope); ok {
			vars["SECRET"] = secret
		}
	}
	return vars, nil
}

// scopeSecret is 'model_scope <scope> secret': ok is false when there is no
// such scope (or no model at all).
func (m *Module) scopeSecret(scope string) (string, bool) {
	s, _, _, err := model.Load(m.modelPaths())
	if err != nil {
		return "", false
	}
	lines, code, err := model.Get(s, "scopes", scope, "secret")
	if err != nil || code != 0 {
		return "", false
	}
	return strings.Join(lines, "\n"), true
}

// modelPaths are what model_load reads: the store, else the legacy config.
func (m *Module) modelPaths() model.Paths {
	p := m.env.Paths
	return model.Paths{Store: p.StoreFile, Config: p.Config, DatesDir: p.PWDatesDir, DisabledDir: p.BackupDir + "/disabled"}
}

// loadStore is the store of this machine, or an error.
func (m *Module) loadStore() (*store.Store, error) { return store.Load(m.env.Paths.StoreFile) }

// --- small helpers ----------------------------------------------------------

func (m *Module) now() time.Time {
	if m.env.Now != nil {
		return m.env.Now()
	}
	return time.Now()
}

// stderr is bash's 'warn ... >&2': an Output whose every line goes to
// Stderr.
func (m *Module) stderr() ui.Output {
	return ui.Output{Stdout: m.env.Out.Stderr, Stderr: m.env.Out.Stderr}
}

// unitName is the unit without ".service" (what messages call it).
func (m *Module) unitName() string { return strings.TrimSuffix(m.L.Unit, ".service") }

// chownRootGroup is the default Chown.
func (m *Module) chownRootGroup(path string) {
	g, err := user.LookupGroup(m.L.Group)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, 0, gid)
}

func (m *Module) sleep(ctx context.Context, d time.Duration) {
	if m.Sleep != nil {
		m.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// settle is how long a restarted unit must stay up before a listener change
// counts as applied (TACCTL_SETTLE_SECONDS, default 0.5).
func (m *Module) settle() time.Duration {
	secs, err := strconv.ParseFloat(strings.TrimSpace(m.env.Paths.SettleSeconds), 64)
	if err != nil || secs < 0 {
		secs, _ = strconv.ParseFloat(paths.DefaultSettleSeconds, 64)
	}
	return time.Duration(secs * float64(time.Second))
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// isExec is bash's -x for a file: something executable that exists.
func isExec(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&0o111 != 0
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}
