package tacacs

// The lifecycle phases of the TACACS+ backend (lib/backends/tacacs.sh at
// the 0.1.16 tag, "BUILD, INSTALL, UPGRADE, UNINSTALL" and
// backend_tacacs_install, _upgrade, _uninstall): the steps of 'tacctl
// install', 'upgrade' and 'uninstall' that are tacquito's.
//
//	install    build    the Go toolchain (checked; the bootstrap shim
//	                    installs it), the tacquito checkout with the patch
//	                    overlay, the two binaries
//	           files    logrotate
//	           account  the service user, the config and log directories,
//	                    README.md
//	           start    (after the first render) the units, enable, start,
//	                    check
//	upgrade    preflight  source checkout and Go present
//	           build    pull, and rebuild when upstream or the overlay moved
//	                    (the previous binary kept as tacquito.bak)
//	           config   config_sync_existing
//	           files    the units and drop-ins, README.md, logrotate
//	           finish   the store gate, then one restart for everything
//	                    the daemon reads that changed, rolled back when the
//	                    daemon does not come up
//	uninstall  stop, program, data, account
//
// The phases of one upgrade share what build, config and files found
// (lifeState): the Backend of one invocation is made once per backend.Set,
// so the orchestrator must run every phase on the same Backend. What
// crosses the self-update re-exec of 'tacctl upgrade' is on disk
// (tacquito.bak) and in one environment variable (UpgradeFromEnv); see
// UpgradeHandover.
//
// Messages are 0.1.16's. A command that 0.1.16 runs under 'set -e' and
// that fails ends the phase with its exit status (a *backend.Error); the
// messages are the program's own. Programs run through the Env's Runner
// (git, go, systemctl, ss, id, useradd, userdel, tar); files are native.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
)

// The build constants of lib/backends/tacacs.sh.
const (
	// GoVersion is GO_VERSION, the toolchain tacctl installs for tacquito.
	GoVersion = paths.GoVersion
	// TacquitoRepo is TACQUITO_REPO.
	TacquitoRepo = "https://github.com/facebookincubator/tacquito.git"
	// Share is TACACS_SHARE: where a tacctl tree keeps this backend's
	// shipped files (units, logrotate), relative to its root.
	Share = "config/backends/tacacs"
	// UpgradeFromEnv carries the tacquito commit an upgrade started from
	// across its self-update re-exec (TACCTL_UPGRADE_TACQUITO_FROM).
	UpgradeFromEnv = lifecycle.UpgradeFromEnv
)

// The words of TACACS_UNITS_STATE.
const (
	unitsChanged = "changed"
	unitsStopped = "stopped"
)

// lifeState is what the lifecycle phases of one invocation share: the
// shell globals of 0.1.16 (SKIP_BUILD, CURRENT_COMMIT, NEW_COMMIT,
// TACQUITO_PREBUILT, TACACS_UNITS_*, CONFIG_SYNC_RENDERED, the summary
// lines) and the seams of the tests.
type lifeState struct {
	// skipBuild is SKIP_BUILD: "" (no build phase ran), "true" or "false"
	// (the daemon has a new binary to be restarted on).
	skipBuild     string
	currentCommit string
	newCommit     string
	// prebuilt: that binary was built by the run before the re-exec.
	prebuilt bool
	// from is TACCTL_UPGRADE_TACQUITO_FROM: inherited (SetUpgradeFrom), or
	// set by a rebuild.
	from string

	// unitsState is TACACS_UNITS_STATE ("", unitsChanged, unitsStopped);
	// after unitsChanged the copies stay in unitsKeep until the restart.
	unitsState string
	unitsKeep  string
	unitsKept  *unitsKept
	unitsNotes []string

	// configChanged is CONFIG_SYNC_RENDERED.
	configChanged bool

	report UpgradeReport
	saved  []string

	// Seams; zero is the real thing.
	goBin       string                                         // GO_BIN (paths.GoBin)
	archiveDir  string                                         // where uninstall keeps logs (/root)
	root        func() bool                                    // EUID 0 (os.Geteuid)
	commitUnits func(dir string) ([]string, error)             // _tacacs_units_commit
	flip        func(ctx context.Context) lifecycle.FlipResult // upgrade_store_flip
}

// UpgradeReport is what the upgrade phases of this backend leave for the
// closing summary of 'tacctl upgrade'.
type UpgradeReport struct {
	// Head is UPGRADE_SUMMARY_HEAD, set by finish.
	Head string
	// Notes are the UPGRADE_SUMMARY_NOTES lines finish added, in order.
	Notes []string
	// FilesNotes are the lines the files phase added (a unit update that
	// stopped); the summary shows them before Notes.
	FilesNotes []string
	// FilesUpdated is what the files phase added to SCRIPTS_UPDATED.
	FilesUpdated int
}

// SetUpgradeFrom gives the backend the value of UpgradeFromEnv this
// process was started with ("" when unset): the tacquito commit the run
// before a self-update re-exec started from. Call it before the build
// phase.
func (b *Backend) SetUpgradeFrom(commit string) { b.life.from = commit }

// UpgradeHandover is what a self-update re-exec of 'tacctl upgrade' must
// add to the environment of the new process (KEY=VALUE): UpgradeFromEnv
// once a build phase rebuilt tacquito, or inherited it; nothing otherwise.
// With tacquito.bak left beside the binary, it is how the re-executed run
// knows to restart the daemon on a binary the first run built, and what
// the summary names as the start.
func (b *Backend) UpgradeHandover() []string {
	if b.life.from == "" {
		return nil
	}
	return []string{UpgradeFromEnv + "=" + b.life.from}
}

// UpgradeReport is what the upgrade phases of this invocation left for the
// summary.
func (b *Backend) UpgradeReport() UpgradeReport {
	r := b.life.report
	r.Notes = append([]string(nil), r.Notes...)
	r.FilesNotes = append([]string(nil), r.FilesNotes...)
	return r
}

// UninstallSaved are the lines the uninstall data phase added to
// UNINSTALL_SAVED ("Accounting logs saved to: <archive>").
func (b *Backend) UninstallSaved() []string { return append([]string(nil), b.life.saved...) }

// Install is backend_tacacs_install: one phase of 'tacctl install'; tree
// is the tacctl checkout the shipped files come from.
func (b *Backend) Install(ctx context.Context, phase backend.Phase, tree string) error {
	switch phase {
	case backend.PhaseBuild:
		return b.installBuild(ctx)
	case backend.PhaseFiles:
		return b.installFiles(tree)
	case backend.PhaseAccount:
		return b.installAccount(ctx, tree)
	case backend.PhaseStart:
		return b.installStart(ctx, tree)
	}
	return nil
}

// Upgrade is backend_tacacs_upgrade: one phase of 'tacctl upgrade'.
func (b *Backend) Upgrade(ctx context.Context, phase backend.Phase, tree string) error {
	switch phase {
	case backend.PhasePreflight:
		return b.upgradePreflight(ctx)
	case backend.PhaseBuild:
		return b.upgradeBuild(ctx)
	case backend.PhaseConfig:
		// config_sync_existing; finish restarts when it changed the config.
		changed, err := b.ConfigSyncExisting(ctx)
		b.life.configChanged = changed
		return err
	case backend.PhaseFiles:
		return b.upgradeFiles(ctx, tree)
	case backend.PhaseFinish:
		return b.upgradeFinish(ctx)
	}
	return nil
}

// Uninstall is backend_tacacs_uninstall: one phase of 'tacctl uninstall';
// keepLogs is the data phase's --keep-logs.
func (b *Backend) Uninstall(ctx context.Context, phase backend.Phase, keepLogs bool) error {
	switch phase {
	case backend.PhaseStop:
		return b.uninstallStop(ctx)
	case backend.PhaseProgram:
		return b.uninstallProgram(ctx)
	case backend.PhaseData:
		return b.uninstallData(ctx, keepLogs)
	case backend.PhaseAccount:
		b.uninstallAccount(ctx)
	}
	return nil
}

// --- paths and seams ---------------------------------------------------------

// hashgenBin is HASHGEN_BIN.
func (b *Backend) hashgenBin() string { return filepath.Join(b.env.Paths.Bin, "tacquito-hashgen") }

// goBin is GO_BIN.
func (b *Backend) goBin() string {
	if b.life.goBin != "" {
		return b.life.goBin
	}
	if b.env.Paths.GoBin != "" {
		return b.env.Paths.GoBin
	}
	return paths.GoBin
}

// goProgram is the 'go' a build runs: the one on PATH, else GO_BIN (0.1.16
// appends /usr/local/go/bin to PATH first).
func (b *Backend) goProgram() string {
	if _, err := b.env.Runner.LookPath("go"); err == nil {
		return "go"
	}
	return b.goBin()
}

func (b *Backend) isRoot() bool {
	if b.life.root != nil {
		return b.life.root()
	}
	return os.Geteuid() == 0
}

// logrotateFile is /etc/logrotate.d/tacquito (TACCTL_LOGROTATE_DIR).
func (b *Backend) logrotateFile() string { return filepath.Join(b.env.Paths.LogrotateDir, "tacquito") }

// share is <tree>/config/backends/tacacs, as 0.1.16 spells it.
func share(tree string) string { return tree + "/" + Share }

// --- programs ----------------------------------------------------------------

// command runs a program in dir (""; tacctl's own). stdout nil: captured
// and returned; stderr nil: discarded. The status is 127 when the program
// could not be run.
func (b *Backend) command(ctx context.Context, dir string, stdout, stderr io.Writer, name string, args ...string) (int, string) {
	c := execx.Cmd{Name: name, Args: args, Dir: dir, Stdout: stdout, Stderr: stderr}
	if stderr == nil {
		c.Stderr = io.Discard
	}
	res, err := b.env.Runner.Run(ctx, c)
	if err != nil && res.Code == 0 {
		res.Code = 127
	}
	return res.Code, string(res.Stdout)
}

// sh is a plain command line: output passed through.
func (b *Backend) sh(ctx context.Context, dir, name string, args ...string) int {
	code, _ := b.command(ctx, dir, b.env.Out.Stdout, b.env.Out.Stderr, name, args...)
	return code
}

// shQuiet is '<cmd> 2>/dev/null'.
func (b *Backend) shQuiet(ctx context.Context, dir, name string, args ...string) int {
	code, _ := b.command(ctx, dir, b.env.Out.Stdout, nil, name, args...)
	return code
}

// shSilent is '<cmd> &>/dev/null'.
func (b *Backend) shSilent(ctx context.Context, dir, name string, args ...string) int {
	code, _ := b.command(ctx, dir, io.Discard, nil, name, args...)
	return code
}

// shOut is $(<cmd>): stdout without its trailing newlines, stderr passed
// through.
func (b *Backend) shOut(ctx context.Context, dir, name string, args ...string) (string, int) {
	code, out := b.command(ctx, dir, nil, b.env.Out.Stderr, name, args...)
	return strings.TrimRight(out, "\n"), code
}

// failed is the end of a phase at a command 0.1.16 runs under 'set -e':
// its exit status, its own messages already written.
func failed(code int, what string) error {
	if code == 0 {
		code = 1
	}
	return &backend.Error{Code: code, Reason: what}
}

// stderrLine writes a program-style message ('cp: ...') on Stderr.
func (b *Backend) stderrLine(msg string) { writeString(b.env.Out.Stderr, msg+"\n") }

// fileError is a native file operation that 0.1.16 runs as a program
// under 'set -e': the program's message, exit status 1.
func (b *Backend) fileError(prog string, err error) error {
	b.stderrLine(prog + ": " + err.Error())
	return failed(1, prog)
}

// ensureSafeDirectory is ensure_safe_directory: a system-wide git
// safe.directory entry for each path, added once.
func (b *Backend) ensureSafeDirectory(ctx context.Context, dirs ...string) {
	code, existing := b.command(ctx, "", nil, nil, "git", "config", "--system", "--get-all", "safe.directory")
	if code != 0 {
		existing = ""
	}
	have := strings.Split(existing, "\n")
	for _, d := range dirs {
		found := false
		for _, l := range have {
			if l == d {
				found = true
				break
			}
		}
		if !found {
			b.shQuiet(ctx, "", "git", "config", "--system", "--add", "safe.directory", d)
		}
	}
}

// listenCheck is _tacacs_listen_check: is the default listener's port
// open? Said after a start or a restart.
func (b *Backend) listenCheck(ctx context.Context) {
	addr := ""
	if ls := b.listenerLines(); len(ls) > 0 {
		addr = ls[0].Address
	}
	port := addr[strings.LastIndex(addr, ":")+1:]
	out, _ := b.shOut(ctx, "", "ss", "-tlnp")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, ":"+port+" ") {
			b.out().InfoE("Listening on port " + port + "/tcp")
			return
		}
	}
	b.out().WarnE("Port " + port + " not detected — check logs.")
}

// --- files -------------------------------------------------------------------

// cpFile is 'cp src dst': an existing dst keeps its mode, a new one gets
// src's mode less the umask.
func cpFile(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// sameBytes is 'cmp -s a b' (and 'diff -q'): both readable and equal.
func sameBytes(a, b string) bool {
	da, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	db, err := os.ReadFile(b)
	if err != nil {
		return false
	}
	return bytes.Equal(da, db)
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// updateIfChanged is update_if_changed <src> <dest> <label>: dest becomes
// a copy of src when it differs, reported and counted in FilesUpdated. No
// src: nothing.
func (b *Backend) updateIfChanged(src, dest, label string) error {
	if !isRegular(src) {
		return nil
	}
	if sameBytes(src, dest) {
		b.out().InfoE("  Unchanged: " + label)
		return nil
	}
	if err := cpFile(src, dest); err != nil {
		return b.fileError("cp", err)
	}
	b.out().InfoE("  Updated: " + label)
	b.life.report.FilesUpdated++
	return nil
}

// moveBack is 'mv -f <bak> <bin>' of a rollback (under 'set -e').
func (b *Backend) moveBack(bak, bin string) error {
	if err := os.Rename(bak, bin); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			b.stderrLine("mv: cannot stat '" + bak + "': No such file or directory")
			return failed(1, "mv")
		}
		return b.fileError("mv", err)
	}
	return nil
}

// chownTacquito is 'chown tacquito:tacquito <path>...' where a failure
// ends the phase. Only as root: the suite runs unprivileged (and stubs
// chown in the bash runs).
func (b *Backend) chownTacquito(dirs ...string) error {
	if !b.isRoot() {
		return nil
	}
	u, err := user.Lookup(User)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(User)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if err := os.Chown(d, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// globSorted is a glob's matches, sorted and unique ('sort -u' of the
// names is the caller's).
func globSorted(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	sort.Strings(m)
	return m
}

// UpgradeSummary is backend.Summarizer's view of UpgradeReport: the head,
// the notes of 'files' then those of 'finish', and the files 'files'
// replaced.
func (b *Backend) UpgradeSummary() backend.UpgradeSummary {
	r := b.UpgradeReport()
	return backend.UpgradeSummary{Head: r.Head, Notes: append(r.FilesNotes, r.Notes...), FilesUpdated: r.FilesUpdated}
}
