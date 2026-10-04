package cli

// 'tacctl backend enable|disable <id> [-y]' (cmd_backend_enable and
// cmd_backend_disable, lib/backend.sh at 0.1.16). Both are one transaction
// on the files tacctl owns (backends.enabled in tacctl.yaml, the store,
// every rendered artifact and rendered.json): they complete or leave all of
// them as they were. What cannot be undone is software: an install that
// enable ran stays installed, and disable leaves the package and every
// rendered file in place.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerFamilyVerb("backend", "enable", backendEnableCmd)
	registerFamilyVerb("backend", "disable", backendDisableCmd)
}

func backendEnableCmd(inv *invocation) *cobra.Command {
	return withRun(verb("enable", "Install the backend if needed, enable it, render its config, start it"),
		inv.native(withPreflight, func(args []string) error { return inv.switcher().enable(args) }))
}

func backendDisableCmd(inv *invocation) *cobra.Command {
	return withRun(verb("disable", "Stop and disable it, take it out of backends.enabled (confirms)"),
		inv.native(withPreflight, func(args []string) error { return inv.switcher().disable(args) }))
}

// startWait is how long a backend gets between its start and the question
// whether it runs (BACKEND_START_WAIT).
const startWait = 2 * time.Second

// switcher runs enable and disable on a backend set; the CLI makes it from
// the invocation, tests from a set of stand-ins.
type switcher struct {
	ctx    context.Context
	set    *backend.Set
	out    ui.Output
	prompt *ui.Prompter
	// tree is the checkout the install phases take shipped files from
	// (PROJECT_DIR).
	tree string
	// wait sleeps for d, or until the command is cancelled.
	wait func(d time.Duration)
}

func (inv *invocation) switcher() *switcher {
	a := inv.app
	return &switcher{ctx: inv.ctx, set: a.Backends(), out: a.Out, prompt: a.Prompter(), tree: a.Paths.Tree, wait: inv.pause}
}

func (s *switcher) echo(line string) { _, _ = io.WriteString(s.out.Stdout, line+"\n") }

// fail prints the lines as errors (echo -e, as bash's error does) and
// returns exit status 1.
func (s *switcher) fail(msgs ...string) error {
	for _, m := range msgs {
		s.out.ErrorE(m)
	}
	return exit(1)
}

// parse is the argument loop of both commands: -y|--yes, one id; any other
// dash-word is an unknown option, a second id a usage error (exit 1).
func (s *switcher) parse(args []string, usage string) (id string, yes bool, err error) {
	for _, a := range args {
		switch {
		case a == "-y" || a == "--yes":
			yes = true
		case strings.HasPrefix(a, "-"):
			return "", false, s.fail("Unknown option '" + a + "'. " + usage)
		case id != "":
			return "", false, s.fail(usage)
		default:
			id = a
		}
	}
	ids := s.set.IDs()
	switch {
	case id == "":
		return "", false, s.fail("Missing backend id (known: " + strings.Join(ids, " ") + ").")
	case !slices.Contains(ids, id):
		return "", false, s.fail("Unknown backend '" + id + "' (known: " + strings.Join(ids, " ") + ").")
	}
	return id, yes, nil
}

// enabled is '_backends_load || return 1'.
func (s *switcher) enabled() ([]string, error) {
	ids, err := s.set.Enabled()
	if err != nil {
		return nil, s.fail(err.Error())
	}
	return ids, nil
}

// confirm is _backend_confirm: true only on y or Y (or with -y); anything
// else, an empty stdin included, is a no, said as such (the callers then
// exit 0: declining is not a failure).
func (s *switcher) confirm(prompt string, yes bool) bool {
	if yes {
		return true
	}
	if s.prompt.Confirm("  " + prompt + " [y/N]: ") {
		return true
	}
	s.out.Info("Cancelled. Nothing was changed.")
	return false
}

// runPhases is _backend_run_phases: the phases in order, the first failure
// reported with its exit status and false returned.
func (s *switcher) runPhases(b backend.Backend, phases ...backend.Phase) bool {
	for _, p := range phases {
		err := b.Install(s.ctx, p, s.tree)
		if err == nil {
			continue
		}
		var code int
		if backend.Reported(err) {
			code = backend.ExitCode(err)
		} else {
			code = exitCode(err, s.out)
		}
		s.out.Error("Backend '" + b.ID() + "': install step '" + string(p) + "' failed (exit " + strconv.Itoa(code) + ").")
		return false
	}
	return true
}

// writeEnabled is _backend_enabled_write: backends.enabled becomes ids.
func (s *switcher) writeEnabled(ids []string) func() error {
	return func() error { return s.set.Env.Conf.SetList("backends.enabled", ids) }
}

// applyError is the status of a failed StoreApply, its writer's error
// printed when nothing has printed it yet.
func (s *switcher) applyError(err error) int {
	if backend.Reported(err) {
		return backend.ExitCode(err)
	}
	return exitCode(err, s.out)
}

// enable is cmd_backend_enable:
//
//  1. refuse unless the backend exists, is not enabled, and the store
//     exists;
//  2. not installed: confirm (-y skips), then its install phases build,
//     files, account. Failure: nothing but its software is touched;
//  3. StoreApply gating every backend of the new set (the new one
//     included), adding the id to backends.enabled and rendering every
//     backend, all or none; the new one's restart is deferred to step 4.
//     Failure: StoreApply put everything back; the backend is installed
//     but not enabled;
//  4. bring it up: the install phase 'start' for a backend installed in
//     step 2; otherwise 'service enable', then a restart if its render
//     changed anything or a start if not. Then it must report 'active'.
//     Failure at either: tacctl.yaml, every artifact and rendered.json are
//     put back from copies taken before step 3, the service is stopped and
//     disabled, and the backends the render had restarted are restarted
//     again. The store was not changed by any of it.
//
// Whatever fails exits 1 (3 when a gate refused: a rendered file was edited
// by hand), saying what state it left.
func (s *switcher) enable(args []string) error {
	id, yes, err := s.parse(args, "Usage: tacctl backend enable <id> [-y]")
	if err != nil {
		return err
	}
	enabled, err := s.enabled()
	if err != nil {
		return err
	}
	if slices.Contains(enabled, id) {
		s.out.Info("Backend '" + id + "' is already enabled.")
		return nil
	}
	if err := s.set.Require(); err != nil {
		return err
	}
	b, err := s.set.Get(id)
	if err != nil {
		return err
	}

	fresh := !b.Installed()
	if fresh {
		impl := b.Describe().Impl
		if impl == "" {
			impl = "its daemon"
		}
		s.echo("")
		s.echo("  Backend '" + id + "' is not installed. Enabling it installs " + impl)
		s.echo("  (packages, a service account, its service unit), then renders its config and starts it.")
		if !s.confirm("Install and enable '"+id+"'?", yes) {
			return nil
		}
		if !s.runPhases(b, backend.PhaseBuild, backend.PhaseFiles, backend.PhaseAccount) {
			return s.fail("Backend '" + id + "' was not enabled. tacctl.yaml, the store and every rendered file are as they were; what the install did stays on this machine.")
		}
	}

	newEnabled := append(slices.Clone(enabled), id)
	keptNote := ""
	if fresh {
		keptNote = "; the install stays on this machine"
	}
	p := s.set.Env.Paths
	keep, err := os.MkdirTemp(p.StateDir, ".enable.")
	if err != nil {
		return s.fail("Cannot create " + filepath.Join(p.StateDir, ".enable.*") + ": " + err.Error())
	}
	defer func() { _ = os.RemoveAll(keep) }()
	kept, err := s.set.Keep(filepath.Join(keep, "artifacts"), newEnabled)
	if err != nil {
		return s.fail("Could not copy the rendered files before the change. Nothing was changed.")
	}
	keptConf := filepath.Join(keep, "tacctl.yaml")
	if isRegularFile(p.Overrides) {
		if err := copyKeep(p.Overrides, keptConf); err != nil {
			return s.fail("Cannot copy " + p.Overrides + ": " + err.Error())
		}
	}

	res, err := s.set.StoreApply(s.ctx, backend.ApplyOptions{Gate: newEnabled, DeferRestart: []string{id}}, s.writeEnabled(newEnabled))
	if err != nil {
		code := s.applyError(err)
		s.out.ErrorE("Backend '" + id + "' was not enabled. tacctl.yaml, the store and every rendered file are as they were" + keptNote + ".")
		return exit(code)
	}

	up := true
	state := ""
	if fresh {
		up = s.runPhases(b, backend.PhaseStart)
	} else if _, err := b.Service(s.ctx, backend.ServiceEnable, ""); err != nil {
		up = false
	} else {
		action := backend.ServiceStart
		if slices.Contains(res.Changed, id) {
			action = backend.ServiceRestart
		}
		if _, err := b.Service(s.ctx, action, ""); err != nil {
			up = false
		}
	}
	if up {
		s.wait(startWait)
		state, _ = b.Service(s.ctx, backend.ServiceIsActive, "")
		up = state == "active"
	}
	if !up {
		s.out.WarnE("Backend '" + id + "' did not come up (service " + or(state, "unknown") + "); undoing the change.")
		s.undo(b, keptConf, kept, res.Changed)
		return s.fail("Backend '" + id + "' was not enabled. tacctl.yaml and every rendered file are back as they were, the service is stopped and disabled" + keptNote + ".")
	}
	s.out.InfoE("Backend '" + id + "' is enabled and running.")
	s.echo("")
	return nil
}

// undo is _backend_enable_undo: put tacctl.yaml, every artifact and
// rendered.json back from the copies after the backend did not come up, and
// stop what was started. The other backends were restarted by the render
// this undoes, so the ones it changed are restarted again onto what they
// had.
func (s *switcher) undo(b backend.Backend, keptConf string, kept *backend.Kept, changed []string) {
	_, _ = b.Service(s.ctx, backend.ServiceStop, "")
	_, _ = b.Service(s.ctx, backend.ServiceDisable, "")
	overrides := s.set.Env.Paths.Overrides
	if isRegularFile(keptConf) {
		if err := copyKeep(keptConf, overrides); err != nil {
			s.out.Warn("Could not put " + overrides + " back.")
		}
	} else {
		_ = os.Remove(overrides)
	}
	if s.set.Env.Conf != nil {
		s.set.Env.Conf.Reload()
	}
	kept.Restore()
	for _, other := range changed {
		if other == b.ID() {
			continue
		}
		if ob, err := s.set.Get(other); err == nil {
			_, _ = ob.Service(s.ctx, backend.ServiceRestart, "")
		}
	}
}

// disable is cmd_backend_disable. Refused: the last enabled backend (with
// none enabled tacctl would render and serve nothing), and tacacs while
// there is no store (an install still in legacy mode: tacquito.yaml is the
// only source of truth and tacquito the one thing serving it).
//
//  1. confirm (-y skips);
//  2. store mode: StoreApply gates the backends that stay, takes the id out
//     of backends.enabled and renders the rest. Failure: everything as it
//     was, the service untouched. Legacy mode (a backend other than
//     tacacs): tacctl.yaml is rewritten alone, from a copy kept for the
//     failure case;
//  3. 'service stop', then 'service disable'. A failure here is reported
//     (exit 1): the backend is out of backends.enabled and its service
//     still runs, and the message names what to run.
//
// Its rendered files, their records, the snapshots and the package stay.
func (s *switcher) disable(args []string) error {
	id, yes, err := s.parse(args, "Usage: tacctl backend disable <id> [-y]")
	if err != nil {
		return err
	}
	enabled, err := s.enabled()
	if err != nil {
		return err
	}
	if !slices.Contains(enabled, id) {
		s.out.Info("Backend '" + id + "' is not enabled. Nothing to do.")
		return nil
	}
	var remaining []string
	for _, e := range enabled {
		if e != id {
			remaining = append(remaining, e)
		}
	}
	if len(remaining) == 0 {
		return s.fail("Backend '"+id+"' is the only enabled backend. With none enabled nothing would serve the store.",
			"Enable another first ('tacctl backend enable <id>'), or remove tacctl's daemons with 'tacctl uninstall'.")
	}
	p := s.set.Env.Paths
	legacy := !isRegularFile(p.StoreFile)
	if legacy && id == backend.TACACS {
		return s.fail("Backend 'tacacs' cannot be disabled while there is no store: "+p.Config+" is still the source of truth and tacquito the only thing serving it.",
			store.NotInitialisedMsg)
	}
	b, err := s.set.Get(id)
	if err != nil {
		return err
	}

	s.echo("")
	s.echo("  This takes backend '" + id + "' out of backends.enabled and stops and disables its service.")
	s.echo("  Clients of that protocol can no longer authenticate. Its package and rendered files stay on this machine;")
	s.echo("  'tacctl backend enable " + id + "' brings it back.")
	if !s.confirm("Disable '"+id+"'?", yes) {
		return nil
	}

	code := 0
	if legacy {
		code = s.disableLegacy(remaining)
	} else if _, err := s.set.StoreApply(s.ctx, backend.ApplyOptions{Gate: remaining}, s.writeEnabled(remaining)); err != nil {
		code = s.applyError(err)
	}
	if code != 0 {
		s.out.ErrorE("Backend '" + id + "' was not disabled. tacctl.yaml, the store and every rendered file are as they were.")
		return exit(code)
	}

	ok := true
	if _, err := b.Service(s.ctx, backend.ServiceStop, ""); err != nil {
		ok = false
	}
	if _, err := b.Service(s.ctx, backend.ServiceDisable, ""); err != nil {
		ok = false
	}
	if !ok {
		units := strings.Join(b.Describe().Units, " ")
		if units == "" {
			units = "<unit>"
		}
		return s.fail("Backend '" + id + "' is out of backends.enabled, but its service could not be stopped or disabled. Run: systemctl stop " + units + " ; systemctl disable " + units)
	}
	names := strings.Join(b.Artifacts(), ", ")
	if names == "" {
		names = "its rendered files"
	}
	s.out.InfoE("Backend '" + id + "' is disabled: removed from backends.enabled, service stopped and disabled.")
	s.out.InfoE("Left in place: its package and " + names + " (not rendered any more).")
	s.echo("")
	return nil
}

// disableLegacy is disable's legacy-mode write: tacctl.yaml alone, put
// back from a copy (<state>/.disable.*) when the write fails. It returns
// the exit status (0 or 1), the failure printed.
func (s *switcher) disableLegacy(remaining []string) int {
	p := s.set.Env.Paths
	f, err := os.CreateTemp(p.StateDir, ".disable.")
	if err != nil {
		s.out.Error("Cannot create " + filepath.Join(p.StateDir, ".disable.*") + ": " + err.Error())
		return 1
	}
	keep := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(keep) }()
	// 'cp -p tacctl.yaml keep 2>/dev/null || : > keep'
	if copyKeep(p.Overrides, keep) != nil {
		_ = os.WriteFile(keep, nil, 0o600)
	}
	if err := s.writeEnabled(remaining)(); err != nil {
		exitCode(err, s.out)
		_ = copyKeep(keep, p.Overrides)
		s.set.Env.Conf.Reload()
		return 1
	}
	return 0
}

// copyKeep is 'cp -p src dst': the content, the mode, the times and (best
// effort, as cp does unprivileged) the owner. An existing dst is rewritten
// in place.
func copyKeep(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = out.Chown(int(sys.Uid), int(sys.Gid))
	}
	if err := out.Chmod(st.Mode().Perm()); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}
