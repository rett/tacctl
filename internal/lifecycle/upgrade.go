package lifecycle

// 'tacctl upgrade' (cmd_upgrade, lib/lifecycle.sh at 0.1.16), with the Go
// self-update and the hand-over to a bash release (docs/plans/go-rewrite.md
// 5.2).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// selfUpdatePaths are the parts of the tree the binary is built from: a
// change to one of them between the commit an upgrade started from and the
// one it pulled means the installed command is out of date.
var selfUpdatePaths = []string{"cmd", "internal", "vendor", "go.mod", "go.sum", "bin", "config", "patches"}

// The one-line usages a refused argument is followed by.
const (
	installUsage   = "Usage: tacctl install [--branch <name>] [-y|--yes]"
	upgradeUsage   = "Usage: tacctl upgrade [--branch <name>]"
	uninstallUsage = "Usage: tacctl uninstall [-y|--yes]"
)

// parseLifecycleArgs reads an install, upgrade or uninstall command line:
// '--branch <name>' when branch is not nil, '-y' or '--yes' when yes is
// not nil. Anything else, or a '--branch' with no value after it, is
// refused ("Unknown argument: '<x>'" and the usage, exit 1) before
// anything is done.
func parseLifecycleArgs(h *Host, args []string, branch *string, yes *bool, usage string) error {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case branch != nil && a == "--branch" && i+1 < len(args):
			*branch = args[i+1]
			i++
		case yes != nil && (a == "-y" || a == "--yes"):
			*yes = true
		default:
			h.Out.Error("Unknown argument: '" + a + "'")
			h.Out.Error(usage)
			return backend.ErrFailed
		}
	}
	return nil
}

// Upgrade is 'tacctl upgrade [--branch <name>]' (cmd_upgrade): every
// enabled backend's preflight, the state migration, the backends' builds,
// the deploy clone brought up to date, then (when the binary is not the
// tree's) a rebuild and a re-exec of the new binary, or the hand-over to a
// bash release; otherwise the packages, the backends' config, the system
// files (each backend's, the completion, the man page, the templates) and
// each backend's finish, then the summary. Messages and order are 0.1.16's.
//
// The self-update (docs/plans/go-rewrite.md 5.2): the clone's commit is
// taken before any branch switch (START); when a pulled tree is a bash
// release (no go.mod, lib/core.sh) the installed command becomes the
// symlink to its bin/tacctl.sh again and 'bin/tacctl.sh upgrade' is
// exec'd; when the Go code changed since START, or the running binary was
// not built from HEAD, or the installed command is not a binary, the
// installed command is rebuilt from the clone (Build) and exec'd with
// 'upgrade' and ReexecEnv=1 (the loop guard: a re-executed upgrade does
// not do it again), the backends' handover (UpgradeFromEnv) in its
// environment. A build that fails prints the way back and stops; nothing
// else runs in this process after an exec.
//
// The error is the failing step's, its messages written (a
// *backend.Error: ExitCode is the status).
func Upgrade(ctx context.Context, h *Host, args []string) error {
	branch := ""
	if err := parseLifecycleArgs(h, args, &branch, nil, upgradeUsage); err != nil {
		return err
	}
	out, p := h.Out, h.Paths
	ids, err := h.enabled()
	if err != nil {
		return err
	}
	// Each backend checks that it can be upgraded at all, before anything
	// is touched.
	if err := h.upgrade(ctx, ids, backend.PhasePreflight, ""); err != nil {
		return err
	}
	h.ensureSafeDirectory(ctx, p.Deploy)
	tree := p.Tree

	h.echo("")
	h.echo(rule)
	h.echo("  tacctl Upgrade")
	h.echo(rule)
	h.echo("")

	// Move tacctl state out of /etc/tacquito (idempotent; before anything
	// reads tacctl.yaml), then read backends.enabled where it is now.
	if err := StateMigrate(StateOptionsFrom(p, out, h.Now, h.IsRoot)); err != nil {
		return backend.ErrFailed
	}
	repairVarLib(out, p.VarLib)
	h.Conf.Reload()
	if ids, err = h.enabled(); err != nil {
		return err
	}
	out.Info("Backends: " + h.backendNames(ids))

	// Pull and rebuild each backend's daemon; a run re-executed by the
	// self-update learns where the first run's build started.
	from := h.Environ.Get(UpgradeFromEnv)
	for _, id := range ids {
		if b, err := h.Set.Get(id); err == nil {
			if hv, ok := b.(Handover); ok {
				hv.SetUpgradeFrom(from)
			}
		}
	}
	if err := h.upgrade(ctx, ids, backend.PhaseBuild, ""); err != nil {
		return err
	}

	// Update the management repo.
	deploy := p.Deploy
	if isDir(filepath.Join(deploy, ".git")) {
		done, err := h.updateDeploy(ctx, ids, branch)
		if done || err != nil {
			return err
		}
	} else if !lexists(deploy) {
		out.Info("Cloning management repo...")
		if h.git(ctx, "", "clone", "--quiet", paths.ManageRepo, deploy) != 0 {
			out.Warn("Failed to clone management repo.")
		}
	}
	// Always, even when nothing was pulled: heals installs whose files
	// were left 0600 by the umask.
	NormalizeDeployPerms(deploy)

	// A newer tacctl may need packages the last one did not.
	if err := h.EnsureDependencies(ctx); err != nil {
		return err
	}
	// The entrypoint stays executable for everyone (the shim, which
	// rebuilds the binary when it is missing). 0.1.16 pointed the installed
	// command at it here; from 0.2.0 on the command is the binary.
	if isDir(deploy) {
		if err := h.chmod(filepath.Join(deploy, "bin", "tacctl.sh"), 0o755); err != nil {
			return err
		}
	}

	// A group at priv-lvl 15 gets the explicit tier 0.2.2 gave it by its band.
	h.pinGroupTiers()

	// Bring the existing config in line with this release (legacy
	// migrations of tacquito.yaml, or a re-render; RADIUS: re-render,
	// drop-in, restart): after the pull and its re-exec, so it runs once
	// and with the code being installed.
	if err := h.upgrade(ctx, ids, backend.PhaseConfig, ""); err != nil {
		return err
	}

	out.Info("Updating system files...")
	active := deploy
	if !isDir(active) {
		active = tree
	}
	updated := 0
	if err := h.upgrade(ctx, ids, backend.PhaseFiles, active); err != nil {
		return err
	}
	n, err := h.updateCompletion()
	if err != nil {
		return err
	}
	updated += n
	updated += h.updateTierSudoers(ctx)
	n, err = h.updateConsoleLink()
	if err != nil {
		return err
	}
	updated += n
	updated += h.updateConsoleDropIn(ctx)
	// Unconditional re-gzip (cheap) also heals a host where it is missing.
	if err := h.installManPage(ctx, filepath.Join(active, "man", "tacctl.1")); err != nil {
		return err
	}
	// The templates the operator has not customised are refreshed; a
	// customised one is kept, with this release's beside it.
	ts, err := h.TemplatesSync(ctx, active)
	if err != nil {
		out.Warn("Could not update every config template in " + p.Templates + "/.")
	}
	updated += ts.Updated
	for _, id := range ids {
		if s, ok := h.summarizer(id); ok {
			updated += s.UpgradeSummary().FilesUpdated
		}
	}
	out.Info(strconv.Itoa(updated) + " file(s) updated.")

	// Each backend finishes (TACACS+: the store gate, then one restart if
	// its binary, a unit or drop-in, or its config changed).
	if err := h.upgrade(ctx, ids, backend.PhaseFinish, ""); err != nil {
		return err
	}
	head, upToDate := "", ""
	var notes []string
	for _, id := range ids {
		if s, ok := h.summarizer(id); ok {
			sum := s.UpgradeSummary()
			if sum.Head != "" {
				head, upToDate = sum.Head, sum.UpToDate
			}
			notes = append(notes, sum.Notes...)
		}
	}
	// No file updated and no backend with anything to say: the headline
	// says the installation was already current.
	if updated == 0 && upToDate != "" && len(notes) == 0 {
		head = upToDate
	}
	if note := customisedNote(ts.Customised); note != "" {
		notes = append(notes, note)
	}
	if head == "" {
		head = "Upgrade Complete"
	}
	h.echo("")
	h.echo(rule)
	h.echo("  " + head)
	h.echo("  Managed scripts: " + strconv.Itoa(updated) + " updated")
	for _, n := range notes {
		h.echo("  " + n)
	}
	h.echo(rule)
	h.echo("")
	h.presetNotice()
	h.rootMembersNotice(ctx)
	return nil
}

// summarizer is the backend id as a backend.Summarizer.
func (h *Host) summarizer(id string) (backend.Summarizer, bool) {
	b, err := h.Set.Get(id)
	if err != nil {
		return nil, false
	}
	s, ok := b.(backend.Summarizer)
	return s, ok
}

// handover is what every backend of ids carries across a re-exec.
func (h *Host) handover(ids []string) []string {
	var env []string
	for _, id := range ids {
		if b, err := h.Set.Get(id); err == nil {
			if hv, ok := b.(Handover); ok {
				env = append(env, hv.UpgradeHandover()...)
			}
		}
	}
	return env
}

// updateDeploy brings the deploy clone up to date (0.1.16's "Update
// management repo" block) and then hands over to a bash release or
// rebuilds and re-executes tacctl when it must. done: this process has
// nothing more to do (it exec'd; in tests, whose runner does not replace
// the process, the exec was recorded).
func (h *Host) updateDeploy(ctx context.Context, ids []string, branch string) (done bool, err error) {
	out, p := h.Out, h.Paths
	deploy := p.Deploy
	out.Info("Pulling latest management scripts...")
	// Discard local tracked-file edits so the pull can fast-forward.
	if h.git(ctx, deploy, "checkout", "--", ".") != 0 {
		out.Error("Failed to discard local modifications in " + deploy + ".")
		out.Error("Run 'sudo git -C " + deploy + " status' to investigate.")
		return true, backend.ErrFailed
	}
	// tacctl-managed untracked backup files that 'checkout -- .' leaves.
	for _, pat := range []string{"bin/tacctl.sh.*-bak", "config/templates/*.template.*-bak"} {
		m, _ := filepath.Glob(filepath.Join(deploy, pat))
		for _, f := range m {
			_ = os.Remove(f)
		}
	}
	// The code this run was started from: a branch switch and a pull both
	// count against it (0.1.16 item (g)).
	start, code := h.gitOut(ctx, deploy, "rev-parse", "HEAD")
	if code != 0 {
		start = ""
	}
	fetchFailed := func() (bool, error) {
		out.Error("git fetch failed. Check network / credentials.")
		return true, backend.ErrFailed
	}
	// Where the clone was before a branch switch: its branch, or the
	// commit when detached. A refused hand-over to a bash release goes back
	// there.
	origin, code := h.gitOut(ctx, deploy, "symbolic-ref", "-q", "--short", "HEAD")
	if code != 0 || origin == "" {
		origin = start
	}
	if branch != "" {
		// --tags --force so force-pushed tags update locally.
		if h.git(ctx, deploy, "fetch", "--tags", "--force") != 0 {
			return fetchFailed()
		}
		if h.gitQuiet(ctx, deploy, "checkout", branch) != 0 &&
			h.gitQuiet(ctx, deploy, "checkout", "-b", branch, "origin/"+branch) != 0 {
			out.Error("Could not switch " + deploy + " to branch '" + branch + "' (does it exist on the remote?).")
			return true, backend.ErrFailed
		}
		out.Info("Switched to branch '" + branch + "'.")
	}
	if h.git(ctx, deploy, "fetch", "--tags", "--force") != 0 {
		return fetchFailed()
	}
	local, _ := h.gitOut(ctx, deploy, "rev-parse", "HEAD")
	remote, code := h.gitOut(ctx, deploy, "rev-parse", "@{u}")
	if code != 0 {
		remote = ""
	}
	short := func() string { s, _ := h.gitOut(ctx, deploy, "rev-parse", "--short", "HEAD"); return s }
	switch {
	case remote != "" && local != remote:
		// --ff-only refuses any merge; its complaints are shown.
		if h.git(ctx, deploy, "pull", "--ff-only") != 0 {
			out.Error("git pull failed. Common causes:")
			out.Error("  - local commits on " + deploy + " diverging from origin")
			out.Error("  - untracked files that would be overwritten")
			out.Error("Run 'sudo git -C " + deploy + " status' to investigate.")
			return true, backend.ErrFailed
		}
		out.Info("Management scripts updated: " + short())
	case local != start:
		out.Info("Management scripts updated: " + short())
	default:
		out.Info("Management scripts already up to date.")
	}

	// A bash release (0.1.x): it takes over from here.
	if !exists(filepath.Join(deploy, "go.mod")) && exists(filepath.Join(deploy, "lib", "core.sh")) {
		if err := h.ensureBashReleaseDeps(ctx, branch, origin); err != nil {
			return true, err
		}
		return true, h.handOverToBash(ids)
	}
	if h.Environ.Get(ReexecEnv) == "1" {
		return false, nil
	}
	head, _ := h.gitOut(ctx, deploy, "rev-parse", "HEAD")
	changed := false
	if start != "" {
		changed = h.gitQuiet(ctx, deploy, append([]string{"diff", "--quiet", start, "HEAD", "--"}, selfUpdatePaths...)...) != 0
	}
	st, err := os.Lstat(p.Command)
	binary := err == nil && st.Mode().IsRegular()
	if !changed && h.Commit == head && head != "" && binary {
		return false, nil
	}
	return true, h.selfUpdate(ctx, ids, start)
}

// selfUpdate replaces the installed command with the deploy clone's binary
// (Build: the verified release binary, or one built from the clone) and
// re-executes 'upgrade' with it.
func (h *Host) selfUpdate(ctx context.Context, ids []string, start string) error {
	out, p := h.Out, h.Paths
	if err := h.Build(ctx, p.Deploy, p.Command); err != nil {
		return h.buildFailed(err, start)
	}
	out.Info("tacctl updated — restarting upgrade with new version...")
	// No --branch: the clone is on that branch now, so the new process
	// finds nothing more to pull.
	env := withEnv(h.Environ.Environ(), append([]string{ReexecEnv + "=1"}, h.handover(ids)...))
	if err := h.Runner.Exec(p.Command, []string{p.Command, "upgrade"}, env); err != nil {
		out.Error("Cannot run " + p.Command + ": " + err.Error())
		return &backend.Error{Code: 126, Reason: "exec"}
	}
	return nil
}

// ensureBashReleaseDeps makes sure the packages a bash release needs to
// start at all are installed before the host is handed over to it
// (docs/plans/go-rewrite.md 3.9 item 32): a bash release runs python3 with
// yaml and bcrypt from its first line, before its own upgrade could install
// them, and a server installed with 0.2.0 has none of them. Checked and
// installed as EnsureDependencies does (dpkg-query, apt-get). When they
// cannot be installed nothing is handed over: the installed command is
// left as it is, and after a --branch switch the clone goes back to
// origin (the branch, or the commit, it was on).
func (h *Host) ensureBashReleaseDeps(ctx context.Context, branch, origin string) error {
	out := h.Out
	if !h.has("apt-get") || !h.has("dpkg-query") {
		out.Warn("Not a Debian/Ubuntu system; the bash release needs: " + strings.Join(BashReleaseDeps, " "))
		return nil
	}
	var missing []string
	for _, p := range BashReleaseDeps {
		if !h.pkgInstalled(ctx, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		out.Info("Packages the bash release needs: all present.")
		return nil
	}
	out.Info("Installing packages the bash release needs: " + strings.Join(missing, " "))
	if h.aptInstall(ctx, missing) {
		return nil
	}
	deploy := h.Paths.Deploy
	again := "sudo tacctl upgrade"
	if branch != "" {
		again += " --branch " + branch
	}
	out.Error("Could not install: " + strings.Join(missing, " ") + ". The bash release cannot run without them; not handing over.")
	if branch != "" && origin != "" && h.gitQuiet(ctx, deploy, "checkout", "-q", origin) == 0 {
		out.Error(deploy + " is back on '" + origin + "'; " + h.Paths.Command + " is unchanged.")
	} else {
		head, _ := h.gitOut(ctx, deploy, "rev-parse", "--short", "HEAD")
		out.Error(deploy + " is at " + head + " (the bash release); " + h.Paths.Command + " is unchanged and still works.")
	}
	out.Error("Install them, then run the upgrade again:")
	out.Error("  sudo apt-get install -y " + strings.Join(BashReleaseDeps, " ") + " && " + again)
	return h.failed("")
}

// handOverToBash gives the host back to a bash release of tacctl: the
// installed command becomes the symlink to its entrypoint again (replaced
// in one rename), and its 'upgrade' runs in this process's place, with the
// backends' handover in the environment (0.1.16 reads UpgradeFromEnv too).
func (h *Host) handOverToBash(ids []string) error {
	out, p := h.Out, h.Paths
	entry := filepath.Join(p.Deploy, "bin", "tacctl.sh")
	out.Info("Target branch is a bash release of tacctl; handing over.")
	if err := h.chmod(entry, 0o755); err != nil {
		return err
	}
	tmp := p.Command + ".tacctl-link"
	_ = os.Remove(tmp)
	if err := os.Symlink(entry, tmp); err != nil {
		return h.failed("ln: failed to create symbolic link '" + p.Command + "': " + errno(err))
	}
	if err := os.Rename(tmp, p.Command); err != nil {
		_ = os.Remove(tmp)
		return h.failed("ln: failed to create symbolic link '" + p.Command + "': " + errno(err))
	}
	env := withEnv(h.Environ.Environ(), h.handover(ids), ReexecEnv)
	if err := h.Runner.Exec(entry, []string{entry, "upgrade"}, env); err != nil {
		out.Error("Cannot run " + entry + ": " + err.Error())
		return &backend.Error{Code: 126, Reason: "exec"}
	}
	return nil
}

// updateCompletion writes the completion this binary generates when the
// installed one differs: "Updated: bash completion", else "Unchanged:".
func (h *Host) updateCompletion() (int, error) {
	if h.Completion == nil {
		return 0, nil
	}
	script, err := h.Completion()
	if err != nil {
		return 0, err
	}
	if cur, err := os.ReadFile(h.Paths.Completion); err == nil && bytes.Equal(cur, script) {
		h.Out.Info("  Unchanged: bash completion")
		return 0, nil
	}
	if err := h.writeFile(h.Paths.Completion, script, 0o644); err != nil {
		return 0, err
	}
	h.Out.Info("  Updated: bash completion")
	return 1, nil
}

// updateTierSudoers refreshes the tiers sudoers drop-in an administrator
// installed ('config sudoers tiers install') when this release's rules
// differ from it, so tier users can run the verbs this release opens to
// them: "Updated: tiers sudoers", else "Unchanged:". The file is never
// created here, and it is rewritten only through tier.InstallSudoers
// (visudo -cf, then install); a refused or failed rewrite leaves the old
// file and warns, and the upgrade carries on.
func (h *Host) updateTierSudoers(ctx context.Context) int {
	file := h.Paths.TierSudoersFile
	cur, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	body := tier.Sudoers()
	if string(cur) == body {
		h.Out.Info("  Unchanged: tiers sudoers")
		return 0
	}
	if err := tier.InstallSudoers(ctx, h.Runner, h.Out.Stdout, h.Out.Stderr, body, file); err != nil {
		why := "install failed"
		if errors.Is(err, tier.ErrVisudo) {
			why = "visudo validation failed"
		}
		h.Out.Warn("  Not updated: tiers sudoers (" + why + "; " + file + " is unchanged)")
		return 0
	}
	h.Out.Info("  Updated: tiers sudoers")
	return 1
}
