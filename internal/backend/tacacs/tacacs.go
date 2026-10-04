// Package tacacs is the TACACS+ backend module of tacctl (tacquito;
// lib/backends/tacacs.sh at the 0.1.16 tag, the backend_tacacs_* contract
// functions and everything they reach that is not a lifecycle phase):
//
//   - describe, installed, artifacts (tacquito.yaml, then every listener's
//     drop-in; none while the hand-managed drop-in of an install from
//     before the listener model is still there);
//   - the render steps, over internal/render/tacacs (Renderer): check,
//     gate, stage, commit (plus 'systemctl daemon-reload' when a drop-in
//     changed), notes;
//   - the daemon load-smoke ('store import --check');
//   - service actions on tacquito.service and the listeners' instances
//     (tacquito@<name>.service), and keeping the instances in line with the
//     listeners;
//   - the listeners (listeners.tacacs in tacctl.yaml) and the two settings
//     that reach every listener (backends.tacacs.level, .metrics_address:
//     'tacctl config loglevel' and 'tacctl config metrics'), applied by
//     restarting the unit concerned and put back when it does not come up;
//   - the status parts, log and accounting commands, last login, secret
//     constraints and device variables.
//
// The lifecycle phases (install, upgrade, uninstall) are in lifecycle*.go.
//
// Messages are the 0.1.16 ones, byte for byte: info and warn lines on the
// Env's Stdout, errors on its Stderr, everything of a render step on
// Stderr. Programs run through the Env's Runner (systemctl, journalctl, ss,
// ps, tacquito); everything else is native.
package tacacs

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/backend"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	backend.Register(backend.TACACS, func(env *backend.Env) backend.Backend { return New(env) })
}

// The fixed names of the TACACS+ backend (lib/backends/tacacs.sh).
const (
	// Service is the name operators and tacctl give the service as a whole
	// in systemctl and journalctl calls (tacquito.service).
	Service = "tacquito"
	// User is the service account.
	User = "tacquito"
	// ImportCmd adopts a hand edit of tacquito.yaml into the store.
	ImportCmd = "tacctl store import --replace"
	// TemplateName is the template unit of the listeners' instances.
	TemplateName = "tacquito@.service"
)

// Backend is the TACACS+ backend of one invocation. Make it with New (or
// through the registry); the exported fields are seams for tests.
type Backend struct {
	env *backend.Env

	// Chown gives a rendered tacquito.yaml to tacquito:tacquito (nil:
	// rtacacs.ChownTacquito, best effort).
	Chown rtacacs.Chowner
	// Scrape fetches a metrics URL and returns the body, "" when nothing
	// came back ('curl -s'). Nil: an HTTP GET with a 5 second limit.
	Scrape func(ctx context.Context, url string) string
	// SmokeTime is how long the load-smoke waits for tacquito to serve
	// (TACACS_SMOKE_SECONDS; 0: 5s).
	SmokeTime time.Duration
	// Sleep waits d or until ctx is done (nil: a timer); the settle wait
	// of a settings change and the waits after a start or restart of the
	// lifecycle phases go through it.
	Sleep func(ctx context.Context, d time.Duration)

	// life is what the lifecycle phases of this invocation share
	// (lifecycle.go).
	life lifeState
}

var _ backend.Backend = (*Backend)(nil)
var _ backend.Summarizer = (*Backend)(nil)

// New is the TACACS+ backend over env. env.Conf is read on every use, never
// copied: a rollback that reloads it is seen at once.
func New(env *backend.Env) *Backend { return &Backend{env: env} }

// ID is "tacacs".
func (b *Backend) ID() string { return backend.TACACS }

// paths are the render paths of the invocation.
func (b *Backend) paths() rtacacs.Paths { return rtacacs.PathsFrom(b.env.Paths) }

// serviceFile is SERVICE_FILE, the unit of the default listener.
func (b *Backend) serviceFile() string {
	return filepath.Join(b.env.Paths.TacacsUnitDir, rtacacs.UnitName)
}

// templateFile is TEMPLATE_FILE, the template unit of the instances.
func (b *Backend) templateFile() string {
	return filepath.Join(b.env.Paths.TacacsUnitDir, TemplateName)
}

// overrideFile is OVERRIDE_FILE, the hand-managed drop-in of an install
// from before the listener model.
func (b *Backend) overrideFile() string {
	return filepath.Join(b.env.Paths.OverrideDir, rtacacs.LegacyDropInName)
}

// tacquitoBin is TACQUITO_BIN.
func (b *Backend) tacquitoBin() string { return filepath.Join(b.env.Paths.Bin, "tacquito") }

// legacyUnits is _tacacs_units_legacy: the hand-managed drop-in is still
// there, so the install is not converted.
func (b *Backend) legacyUnits() bool { return isRegular(b.overrideFile()) }

// out is the invocation's output.
func (b *Backend) out() ui.Output { return b.env.Out }

// errOut is an Output whose every line goes to Stderr (bash's '>&2').
func (b *Backend) errOut() ui.Output {
	return ui.Output{Stdout: b.env.Out.Stderr, Stderr: b.env.Out.Stderr}
}

func (b *Backend) now() time.Time {
	if b.env.Now != nil {
		return b.env.Now()
	}
	return time.Now()
}

// Describe is backend_tacacs_describe: units are every listener's unit,
// the default listener's first.
func (b *Backend) Describe() backend.Description {
	return backend.Description{
		Protocol:  backend.TACACS,
		Impl:      "tacquito",
		Units:     b.unitsAll(),
		User:      User,
		ConfigDir: b.env.Paths.Etc,
		LogDir:    b.env.Paths.Log,
		ImportCmd: ImportCmd,
	}
}

// unitsAll is _tacacs_units_all.
func (b *Backend) unitsAll() []string {
	var out []string
	for _, l := range b.listenerLines() {
		if l.Name != "" {
			out = append(out, rtacacs.Unit(l.Name))
		}
	}
	return out
}

// Installed is backend_tacacs_installed: the daemon binary is executable
// and its unit file is there.
func (b *Backend) Installed() bool {
	return executable(b.tacquitoBin()) && isRegular(b.serviceFile())
}

// Artifacts is backend_tacacs_artifacts: tacquito.yaml, then the drop-in of
// every listener. An install that is not converted has no rendered
// drop-ins.
func (b *Backend) Artifacts() []string {
	p := b.paths()
	out := []string{p.Config}
	if b.legacyUnits() {
		return out
	}
	for _, l := range b.listenerLines() {
		if l.Name != "" {
			out = append(out, rtacacs.DropIn(p, l.Name))
		}
	}
	return out
}

// SecretConstraints is backend_tacacs_secret_constraints: tacquito takes
// any key; length and strength are tacctl's own rules.
func (b *Backend) SecretConstraints() backend.Constraints { return backend.Constraints{} }

// DeviceVars is backend_tacacs_device_vars: the TACACS+ device templates
// take everything from the model and tacctl.yaml; nothing comes from the
// daemon.
func (b *Backend) DeviceVars(context.Context, string, string) (map[string]string, error) {
	return map[string]string{}, nil
}

var loginStamp = regexp.MustCompile(`[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}`)

// LastLogin is _tacacs_last_login: the newest login of the user in any
// listener's accounting log ('YYYY-MM-DD HH:MM:SS'), or "never". A login is
// the last line of a log that names the user ("User":"<name>") and carries
// cmd=login; session stops (cmd=logout, cmd=exit) do not count.
func (b *Backend) LastLogin(_ context.Context, user string) (string, error) {
	best := ""
	needle := `"User":"` + user + `"`
	for _, log := range b.acctLogs(true) {
		f, err := os.Open(log)
		if err != nil {
			continue
		}
		last := ""
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, needle) && strings.Contains(line, "cmd=login") {
				last = line
			}
		}
		_ = f.Close()
		ts := loginStamp.FindString(last)
		if ts != "" && (best == "" || ts > best) {
			best = ts
		}
	}
	if best == "" {
		return "never", nil
	}
	return strings.ReplaceAll(best, "/", "-"), nil
}

// acctLogs are ACCT_LOG (when withDefault) and every other listener's
// accounting log on disk ($LOG_DIR/accounting-*.log), in glob order.
func (b *Backend) acctLogs(withDefault bool) []string {
	var out []string
	if withDefault {
		out = append(out, b.env.Paths.AcctLog)
	}
	m, _ := filepath.Glob(filepath.Join(b.env.Paths.Log, "accounting-*.log"))
	return append(out, m...)
}

// isRegular is bash's -f (symlinks followed).
func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// executable is bash's -x.
func executable(path string) bool {
	return path != "" && unix.Access(path, unix.X_OK) == nil
}

// writeString writes s, ignoring errors as echo does.
func writeString(w io.Writer, s string) { _, _ = io.WriteString(w, s) }
