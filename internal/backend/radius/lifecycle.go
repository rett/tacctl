package radius

// The lifecycle phases of the contract (backend_radius_install, _upgrade
// and _uninstall; lib/backends/radius.sh "INSTALL, UPGRADE, UNINSTALL" at
// the 0.1.16 tag). A phase writes its own messages: info and warn lines on
// Stdout, errors on Stderr. A phase that fails returns backend.ErrFailed,
// its messages written: in bash it is an 'exit 1' inside a phase, which the
// generic commands run under errexit (install, upgrade, uninstall) or in a
// subshell whose status they report ('backend enable'). A phase the module
// has no work in, or does not know, is a no-op.
//
// What a phase leaves for the closing summary of 'tacctl upgrade'
// (UPGRADE_SUMMARY_NOTES) and of 'tacctl uninstall' (UNINSTALL_SAVED) is
// kept on the Module, which lives for one invocation: UpgradeNotes and
// UninstallSaved return it. 'upgrade finish' turns what 'upgrade config' did
// into its note, so the three upgrade phases must run on the same Module
// (backend.Set makes each module once per invocation).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// Packages are the distribution packages of the daemon (RADIUS_PKGS), the
// same names on both families.
const Packages = "freeradius freeradius-utils"

// startWait is how long the unit gets after a start or restart before it is
// asked whether it runs ('sleep 2').
const startWait = 2 * time.Second

// The upgrade's notes for the closing summary.
const (
	noteRendered = "RADIUS: config re-rendered for this release, FreeRADIUS restarted"
	noteFailed   = "RADIUS: NOT brought in line with this release (see above); 'tacctl config validate' says what stands"
)

// lifecycleState is what the phases of one invocation leave for the later
// ones and for the closing summaries.
type lifecycleState struct {
	// upgrade is RADIUS_UPGRADE_STATE: what 'upgrade config' did ("",
	// "rendered" or "failed").
	upgrade string
	notes   []string // UPGRADE_SUMMARY_NOTES added by 'upgrade finish'
	saved   []string // UNINSTALL_SAVED added by 'uninstall data'
}

const (
	upgradeRendered = "rendered"
	upgradeFailed   = "failed"
)

// UpgradeNotes are the lines 'upgrade finish' added to the closing summary
// of 'tacctl upgrade' (UPGRADE_SUMMARY_NOTES), in order; none when there is
// nothing to say.
func (m *Module) UpgradeNotes() []string { return append([]string(nil), m.lc.notes...) }

// UpgradeSummary is backend.Summarizer's view: the notes of 'upgrade
// finish' (RADIUS sets no headline and replaces no counted file).
func (m *Module) UpgradeSummary() backend.UpgradeSummary {
	return backend.UpgradeSummary{Notes: m.UpgradeNotes()}
}

// UninstallSaved are the lines 'uninstall data' added to the "Removed:"
// list of 'tacctl uninstall' (UNINSTALL_SAVED): where the logs were saved.
func (m *Module) UninstallSaved() []string { return append([]string(nil), m.lc.saved...) }

// Install runs one phase of the install (backend_radius_install): build
// (the packages), files (logrotate), account (the package's account and
// directories), start (after the first render: the unit, started and
// checked). tree is not used: nothing RADIUS installs comes from the
// checkout.
func (m *Module) Install(ctx context.Context, phase backend.Phase, _ string) error {
	switch phase {
	case backend.PhaseBuild:
		return m.installBuild(ctx)
	case backend.PhaseFiles:
		m.installFiles()
	case backend.PhaseAccount:
		return m.installAccount(ctx)
	case backend.PhaseStart:
		return m.installStart(ctx)
	}
	return nil
}

// Upgrade runs one phase of the upgrade (backend_radius_upgrade): config
// (re-render, drop-in, one restart), files (logrotate), finish (the
// summary note). None of them fails the upgrade.
func (m *Module) Upgrade(ctx context.Context, phase backend.Phase, _ string) error {
	switch phase {
	case backend.PhaseConfig:
		m.upgradeConfig(ctx)
	case backend.PhaseFiles:
		m.upgradeFiles()
	case backend.PhaseFinish:
		m.upgradeFinish()
	}
	return nil
}

// Uninstall runs one phase of the uninstall (backend_radius_uninstall):
// stop (the unit stopped and handed back), data (tacctl's files and logs;
// keepLogs archives the logs first). The package stays.
func (m *Module) Uninstall(ctx context.Context, phase backend.Phase, keepLogs bool) error {
	switch phase {
	case backend.PhaseStop:
		return m.uninstallStop(ctx)
	case backend.PhaseData:
		m.uninstallData(ctx, keepLogs)
	}
	return nil
}

// --- install ------------------------------------------------------------------

// installBuild is _radius_install_build: the packages. A FreeRADIUS that
// was here before and is active or enabled is not tacctl's to take.
func (m *Module) installBuild(ctx context.Context) error {
	out := m.env.Out
	if m.family == "" {
		out.Error("Neither a Debian/Ubuntu nor a RHEL-family system: tacctl does not know where FreeRADIUS lives here.")
		return backend.ErrFailed
	}
	if isExec(m.L.Bin) {
		if !m.unitFree(ctx) {
			return backend.ErrFailed
		}
		out.Info("FreeRADIUS is already installed (" + m.L.Bin + "); " + m.L.Unit + " is neither running nor enabled.")
		return nil
	}
	out.Info("Installing FreeRADIUS (" + Packages + ")...")
	if !m.pkgInstall(ctx) || !isExec(m.L.Bin) {
		out.Error("Could not install " + Packages + ". Install them and run this again.")
		return backend.ErrFailed
	}
	// Debian starts the package's default configuration on installation.
	m.systemctl(ctx, true, "disable", "--quiet", "--now", m.L.Unit)
	out.Info("FreeRADIUS installed; the package's own configuration in " + m.L.Dir + " is left as shipped and is not served.")
	return nil
}

// pkgInstall is _radius_pkg_install: apt on Debian, else dnf, else yum.
// It reports whether the package manager succeeded.
func (m *Module) pkgInstall(ctx context.Context) bool {
	pkgs := strings.Fields(Packages)
	have := func(name string) bool {
		_, err := m.runner.LookPath(name)
		return err == nil
	}
	switch {
	case m.family == "debian" && have("apt-get"):
		return m.aptInstall(ctx, pkgs)
	case have("dnf"):
		return m.quiet(ctx, "dnf", append([]string{"install", "-y", "-q"}, pkgs...)...) == 0
	case have("yum"):
		return m.quiet(ctx, "yum", append([]string{"install", "-y", "-q"}, pkgs...)...) == 0
	}
	return false
}

// aptInstall is _apt_install (lib/lifecycle.sh): a non-interactive
// 'apt-get install -y -qq', and when that fails (a stale package index is
// the usual cause) 'apt-get update -qq' and one more try. DEBIAN_FRONTEND
// reaches apt-get through env(1): the child inherits tacctl's environment
// otherwise unchanged.
func (m *Module) aptInstall(ctx context.Context, pkgs []string) bool {
	install := append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq"}, pkgs...)
	if m.quiet(ctx, "env", install...) == 0 {
		return true
	}
	m.quiet(ctx, "apt-get", "update", "-qq")
	return m.quiet(ctx, "env", install...) == 0
}

// quiet runs 'name args... >/dev/null': its errors reach the operator,
// its output does not. It returns the exit status (127 when it could not
// be run).
func (m *Module) quiet(ctx context.Context, name string, args ...string) int {
	res, err := m.runner.Run(ctx, execx.Cmd{Name: name, Args: args, Stderr: m.env.Out.Stderr})
	if err != nil && res.Code == 0 {
		return 127
	}
	return res.Code
}

// installFiles is _radius_install_files: the logrotate file.
func (m *Module) installFiles() {
	if err := m.LogrotateInstall(); err != nil {
		m.env.Out.Warn("Could not write " + m.L.Logrotate + ".")
	}
}

// installAccount is _radius_install_account: the package's service account,
// its directories and its main dictionary must be there.
func (m *Module) installAccount(ctx context.Context) error {
	out := m.env.Out
	if res, err := m.runner.Run(ctx, execx.Cmd{Name: "id", Args: []string{m.L.User}}); err != nil || res.Code != 0 {
		out.Error("The FreeRADIUS service account '" + m.L.User + "' does not exist; the package did not install as expected.")
		return backend.ErrFailed
	}
	if !isDir(m.L.Dir) || !isDir(m.L.LogDir) {
		out.Error(m.L.Dir + " or " + m.L.LogDir + " is missing; the package did not install as expected.")
		return backend.ErrFailed
	}
	if !readable(m.L.SystemDict) {
		out.Error("FreeRADIUS's main dictionary is not at " + m.L.SystemDict + "; the package did not install as expected.")
		return backend.ErrFailed
	}
	return nil
}

// installStart is _radius_install_start, after the first render: the unit
// enabled with tacctl's drop-in, started, and checked; each listener probed;
// then the notes of the rendered state.
func (m *Module) installStart(ctx context.Context) error {
	out := m.env.Out
	if !isFile(m.L.Conf) || !isFile(m.L.Users) || !isFile(m.L.Dict) {
		out.Error(m.L.Conf + " was not rendered.")
		return backend.ErrFailed
	}
	if _, err := m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		return backend.ErrFailed
	}
	out.Info("Starting " + m.unitName() + "...")
	m.systemctl(ctx, false, "start", m.L.Unit)
	m.sleep(ctx, startWait)
	if m.systemctl(ctx, true, "is-active", "--quiet", m.L.Unit) != 0 {
		out.Error("FreeRADIUS failed to start. Check: journalctl -u " + m.unitName() + " and " + m.L.DaemonLog)
		return backend.ErrFailed
	}
	out.Info("FreeRADIUS is running (" + m.L.Unit + ", PAP only).")
	for _, l := range m.effectiveListeners() {
		if l.Name == "" {
			continue
		}
		port := portOf(l.Address)
		if m.probe(ctx, l.Network, l.Address) != "" {
			out.Info("Listening on port " + port + "/udp (" + l.Name + ")")
		} else {
			out.Warn("Port " + port + "/udp (" + l.Name + ") not detected — check " + m.L.DaemonLog + ".")
		}
	}
	m.RenderNotes(ctx)
	return nil
}

// --- upgrade ------------------------------------------------------------------

// upgradeConfig is _radius_upgrade_config: bring the artifacts and the
// drop-in in line with this release, as one step, and restart when either
// changed. A release can change what it renders (the dictionary, and with
// it the unit's command line, came with the vendor attributes); the files
// of the release before are what tacctl rendered then, so this is a
// re-render like any other, not drift. The artifacts first, the drop-in
// only once the dictionary it names is in place, then the restart. A
// hand-edited artifact refuses the render (as it refuses every mutation)
// and leaves all of it, the running daemon included, as it was. Never
// fails the upgrade.
func (m *Module) upgradeConfig(ctx context.Context) {
	out := m.env.Out
	m.lc.upgrade = ""
	if !isFile(m.env.Paths.StoreFile) || !isFile(m.L.DropIn) || !m.Installed() {
		return
	}
	changed, err := m.renderApply(ctx)
	if err != nil {
		m.lc.upgrade = upgradeFailed
		out.Warn("The RADIUS files were not re-rendered; FreeRADIUS keeps serving the previous ones. Run 'tacctl config render' once the problem above is fixed.")
		return
	}
	dropinChanged, err := m.DropinInstall(ctx)
	if err != nil {
		out.Warn("Could not update " + m.L.DropIn + ".")
	}
	if !changed && !dropinChanged {
		return
	}
	m.lc.upgrade = upgradeRendered
	if changed {
		out.Info("RADIUS: re-rendered " + strings.Join(m.Artifacts(), ", ") + ".")
		// What an operator of a release before the vendor attributes
		// notices first: an Accept carried Cisco and Juniper attributes for
		// everyone.
		for _, n := range m.notes() {
			if n.Kind == "vendors" && noVendorScope(n.Detail) {
				out.Warn("RADIUS: no scope enables a vendor attribute, so an Access-Accept carries Service-Type only.")
				out.Warn("Enable what each scope's devices need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti (or tag addresses: tacctl scope devices).")
			}
		}
	}
	if dropinChanged {
		out.Info("RADIUS: updated " + m.L.DropIn + ".")
	}
	out.Info("Restarting " + m.unitName() + "...")
	// 'systemctl restart ... 2>/dev/null || true'
	m.resetFailed(ctx, "restart", m.L.Unit)
	_, _ = m.runner.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"restart", m.L.Unit}, Stdout: out.Stdout})
	m.sleep(ctx, startWait)
	if m.systemctl(ctx, true, "is-active", "--quiet", m.L.Unit) == 0 {
		out.Info("FreeRADIUS is running.")
		return
	}
	m.lc.upgrade = upgradeFailed
	out.Error("FreeRADIUS did not start after the re-render. Check: journalctl -u " + m.unitName() + " and " + m.L.DaemonLog)
}

// noVendorScope is the '0|*|0' test on a vendors note: no scope enables a
// vendor attribute and no address is tagged.
func noVendorScope(detail string) bool {
	return len(detail) >= 4 && strings.HasPrefix(detail, "0|") && strings.HasSuffix(detail, "|0")
}

// renderApply is _radius_render_apply: render this backend alone into a
// private directory and install the result (the upgrade's re-render; a
// command that changes the store goes through StoreApply and renders every
// backend). changed reports whether an artifact was replaced. An error
// (ErrRefused: an artifact was edited by hand; ErrFailed) replaced nothing;
// the messages are written.
func (m *Module) renderApply(ctx context.Context) (changed bool, err error) {
	tmp, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		m.env.Out.Error("Cannot create a staging directory: " + err.Error())
		return false, backend.ErrFailed
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := m.RenderStage(ctx, tmp, false); err != nil {
		return false, err
	}
	return m.RenderCommit(ctx, tmp)
}

// upgradeFiles is _radius_upgrade_files: the logrotate file as this release
// writes it, when tacctl has set the daemon up.
func (m *Module) upgradeFiles() {
	if !m.Installed() {
		return
	}
	_ = m.LogrotateInstall()
}

// upgradeFinish is _radius_upgrade_finish: one line of the closing summary.
func (m *Module) upgradeFinish() {
	switch m.lc.upgrade {
	case upgradeRendered:
		m.lc.notes = append(m.lc.notes, noteRendered)
	case upgradeFailed:
		m.lc.notes = append(m.lc.notes, noteFailed)
	}
}

// --- uninstall ----------------------------------------------------------------

// uninstallStop is _radius_uninstall_stop: tacctl's instance stopped (only
// when the unit runs it: its drop-in is there), then the unit handed back
// (disabled, the drop-in removed). A unit somebody else runs is not touched.
func (m *Module) uninstallStop(ctx context.Context) error {
	if m.systemctl(ctx, true, "is-active", "--quiet", m.L.Unit) == 0 && isFile(m.L.DropIn) {
		m.env.Out.Info("Stopping " + m.unitName() + "...")
		m.systemctl(ctx, false, "stop", m.L.Unit)
	}
	if isFile(m.L.DropIn) {
		m.systemctl(ctx, true, "disable", "--quiet", m.L.Unit)
		// The phase's status is the drop-in removal's, as the bash
		// function's is its last command's.
		return m.DropinRemove(ctx)
	}
	return nil
}

// uninstallData is _radius_uninstall_data: tacctl's files (the artifacts,
// the dictionary's directory, the logrotate file) and logs removed, the
// logs archived first under /root with keepLogs. The package and its own
// configuration stay. Nothing of tacctl's here (an uninstall that takes
// every backend because tacctl.yaml could not say which are enabled):
// nothing to do or to say.
func (m *Module) uninstallData(ctx context.Context, keepLogs bool) {
	out := m.env.Out
	logs := m.tacctlLogs()
	had := len(logs) > 0
	for _, f := range []string{m.L.Logrotate, m.L.Conf, m.L.Users, m.L.DictDir} {
		if _, err := os.Stat(f); err == nil {
			had = true
		}
	}
	if !had {
		return
	}
	for _, f := range []string{m.L.Logrotate, m.L.Conf, m.L.Users, m.L.Conf + ".tacctl-new", m.L.Users + ".tacctl-new"} {
		_ = os.Remove(f)
	}
	_ = os.RemoveAll(m.L.DictDir)
	var names []string
	for _, f := range logs {
		if isFile(f) {
			names = append(names, filepath.Base(f))
		}
	}
	if len(names) == 0 {
		out.Info("FreeRADIUS itself (" + Packages + ") is left installed, with the package's configuration in " + m.L.Dir + " as shipped.")
		return
	}
	if keepLogs {
		// paths.Paths.ArchiveDir: a fixed /root, as in 0.1.16, not the
		// invoking user's home.
		archive := m.env.Paths.ArchiveDir + "/tacctl-radius-logs-" + m.now().Format("20060102_150405") + ".tar.gz"
		// 'tar czf ... 2>/dev/null || true'
		_, _ = m.runner.Run(ctx, execx.Cmd{Name: "tar",
			Args: append([]string{"czf", archive, "-C", m.L.LogDir}, names...), Stdout: out.Stdout})
		out.Info("RADIUS logs saved to " + archive)
		m.lc.saved = append(m.lc.saved, "RADIUS logs saved to: "+archive)
	}
	out.Info("Removing tacctl's RADIUS logs from " + m.L.LogDir + "...")
	for _, n := range names {
		_ = os.Remove(filepath.Join(m.L.LogDir, n))
	}
	out.Info("FreeRADIUS itself (" + Packages + ") is left installed, with the package's configuration in " + m.L.Dir + " as shipped.")
}

// tacctlLogs is the glob "$RADIUS_LOG_DIR"/tacctl-*.log*, in glob order.
func (m *Module) tacctlLogs() []string {
	logs, _ := filepath.Glob(filepath.Join(m.L.LogDir, "tacctl-*.log*"))
	return logs
}

// readable is bash's -r: the file can be opened for reading.
func readable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
