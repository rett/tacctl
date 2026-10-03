package tacacs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/pyyaml"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Changing a listener, the log level or the metrics address does not go
// through StoreApply: it renders no tacquito.yaml, so it needs no store and
// works on an install still in legacy mode, as these commands always did;
// and it proves the change by restarting the unit and puts everything back
// when the unit does not come up, which StoreApply does not do. It
// snapshots first when there is a store.

// prompt is the invocation's prompter on the Env's Stdin (one for the
// module, so that no read swallows the input of the next).
func (b *Backend) prompt() *ui.Prompter {
	if b.prompter == nil {
		in := b.env.Stdin
		if in == nil {
			in = strings.NewReader("")
		}
		b.prompter = ui.NewPrompter(in, b.env.Out)
	}
	return b.prompter
}

// confError writes a tacctl.yaml write error as lib/conf.sh does: a file
// that does not parse as two [ERROR] lines, a value the schema refuses as a
// plain line on stderr, anything else as one [ERROR] line.
func (b *Backend) confError(err error) {
	var pe *conf.ParseError
	var ve *conf.ValidationError
	switch {
	case errors.As(err, &pe):
		b.out().ErrorLines(pe)
	case errors.As(err, &ve):
		writeString(b.env.Out.Stderr, ve.Error()+"\n")
	default:
		b.out().Error(err.Error())
	}
}

// overridesReadable is _tacacs_overrides_readable: tacctl.yaml must parse
// before a setting is written into it.
func (b *Backend) overridesReadable() bool {
	path := b.env.Paths.Overrides
	if !isRegular(path) {
		return true
	}
	if data, err := os.ReadFile(path); err == nil {
		if v, err := pyyaml.Load(data, path); err == nil {
			if _, isMap := v.(*yamlpy.Map); v == nil || isMap {
				return true
			}
		}
	}
	b.out().Error(path + " is not valid YAML ('tacctl config validate' shows where); fix it first.")
	return false
}

// unitsFiles is _tacacs_units_files: every file a settings change can
// touch.
func (b *Backend) unitsFiles() []string {
	p := b.env.Paths
	out := []string{p.Overrides, p.Rendered, b.serviceFile(), b.templateFile(), b.overrideFile(),
		rtacacs.DropIn(b.paths(), "default")}
	return append(out, b.instanceDropIns()...)
}

// instanceDropIns are the instances' rendered drop-ins on disk, in glob
// order.
func (b *Backend) instanceDropIns() []string {
	m, _ := filepath.Glob(filepath.Join(b.env.Paths.TacacsUnitDir, "tacquito@*.service.d", rtacacs.DropInName))
	var out []string
	for _, f := range m {
		if isRegular(f) {
			out = append(out, f)
		}
	}
	return out
}

// unitsKept is what _tacacs_units_keep copied: path n of paths is kept as
// <dir>/<n> (no such copy: the file did not exist).
type unitsKept struct {
	dir   string
	paths []string
}

// unitsKeep is _tacacs_units_keep.
func (b *Backend) unitsKeep(dir string) (*unitsKept, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k := &unitsKept{dir: dir}
	for _, path := range b.unitsFiles() {
		k.paths = append(k.paths, path)
		if isRegular(path) {
			if err := copyPreserve(path, filepath.Join(dir, strconv.Itoa(len(k.paths)))); err != nil {
				return nil, err
			}
		}
	}
	return k, nil
}

// unitsRestore is _tacacs_units_restore: every kept file back, drop-ins of
// instances that did not exist then removed, tacctl.yaml re-read. Never
// fails: it warns per file.
func (b *Backend) unitsRestore(k *unitsKept) {
	for i, path := range k.paths {
		kept := filepath.Join(k.dir, strconv.Itoa(i+1))
		if isRegular(kept) {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
		}
		b.put(kept, path)
	}
	for _, f := range b.instanceDropIns() {
		if !slices.Contains(k.paths, f) {
			_ = os.Remove(f)
			_ = unix.Rmdir(filepath.Dir(f))
		}
	}
	_ = unix.Rmdir(b.env.Paths.OverrideDir)
	b.env.Conf.Reload()
}

// put is _backends_render_put: the kept file back through a rename beside
// its target, owner, mode and times as they were; no kept file means the
// target did not exist.
func (b *Backend) put(kept, dst string) {
	if !isRegular(kept) {
		_ = os.Remove(dst)
		return
	}
	tmp := dst + ".tacctl-new"
	if err := copyPreserve(kept, tmp); err == nil {
		if err := os.Rename(tmp, dst); err == nil {
			return
		}
	}
	_ = os.Remove(tmp)
	b.errOut().Warn("Could not put " + dst + " back; 'tacctl config render' rewrites it from the store.")
}

// legacyImport is _tacacs_legacy_import: what the hand-managed drop-in
// says goes into tacctl.yaml; a key it sets is set, a key it does not set
// goes back to the default (the file is the truth for as long as it
// exists). The file itself stays; legacyRetire removes it once the rendered
// drop-in is in place.
func (b *Backend) legacyImport() bool {
	values, err := LegacyDropInValues(b.overrideFile())
	if err != nil {
		writeString(b.env.Out.Stderr, rendered.Report(err)+"\n")
		return false
	}
	c := b.env.Conf
	net, addr := values["TACQUITO_NETWORK"], values["TACQUITO_ADDRESS"]
	steps := []func() error{
		func() error {
			if net+addr != "" {
				return c.SetJSON("listeners.tacacs.default",
					fmt.Sprintf(`{"network": "%s", "address": "%s"}`, or(net, "tcp"), or(addr, ":49")))
			}
			return c.Unset("listeners.tacacs.default")
		},
		setOrUnset(c, "backends.tacacs.level", values["TACQUITO_LEVEL"]),
		setOrUnset(c, "backends.tacacs.metrics_address", values["TACQUITO_METRICS_ADDRESS"]),
	}
	for _, step := range steps {
		if err := step(); err != nil {
			b.confError(err)
			return false
		}
	}
	return true
}

func setOrUnset(c *conf.Config, path, value string) func() error {
	return func() error {
		if value != "" {
			return c.Set(path, value)
		}
		return c.Unset(path)
	}
}

// legacyRetire is _tacacs_legacy_retire: remove the hand-managed drop-in,
// keeping a copy under backups/legacy/, once the drop-in rendered from its
// imported values is installed.
func (b *Backend) legacyRetire() bool {
	if !b.legacyUnits() {
		return true
	}
	src := b.overrideFile()
	dir := filepath.Join(b.env.Paths.BackupDir, "legacy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.out().Error(err.Error())
		return false
	}
	_ = os.Chmod(dir, 0o700)
	dest := dir + "/" + filepath.Base(src) + "." + rtacacs.DriftStamp(b.now())
	data, err := os.ReadFile(src)
	if err == nil {
		err = os.WriteFile(dest, data, 0o600)
	}
	if err == nil {
		err = os.Chmod(dest, 0o600)
	}
	if err == nil {
		err = removeIfExists(src)
	}
	if err == nil {
		err = removeIfExists(src + ".bak")
	}
	if err != nil {
		b.out().Error(err.Error())
		return false
	}
	b.out().Info("Listener, log level and metrics settings moved from " + src + " into " +
		b.env.Paths.Overrides + " (the old drop-in is kept as " + dest + ").")
	return true
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// unitsStage is _tacacs_units_stage: every listener's drop-in rendered into
// <dir>/units, without a store.
func (b *Backend) unitsStage(dir string) bool {
	c := b.env.Conf
	err := rtacacs.CheckOverrides(c.Path)
	if err == nil {
		_, err = rtacacs.StageUnits(c.Merged(), filepath.Join(dir, rtacacs.UnitsDir), b.paths())
	}
	if err != nil {
		writeString(b.env.Out.Stderr, rendered.Report(err)+"\n")
		return false
	}
	return true
}

// settingsApply is _tacacs_settings_apply <target> <writer>: run writer (a
// tacctl.yaml write to listeners.tacacs or backends.tacacs; it returns the
// write's error unprinted) and make the units follow: render the drop-ins,
// reload systemd, restart what the change concerns and check that it
// stayed up. target "all" (or "default") is a change that concerns every
// listener (restarting tacquito.service restarts all); a listener name
// restarts, starts (new) or stops (removed) only that listener's instance.
// An install that is not converted is converted first. On failure
// tacctl.yaml, the drop-ins and the units are as they were, the messages
// are written and ErrFailed returned.
func (b *Backend) settingsApply(ctx context.Context, target string, writer func() error) error {
	out := b.out()
	if !b.overridesReadable() {
		return backend.ErrFailed
	}
	stateDir := b.env.Paths.StateDir
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		out.Error("Cannot create " + stateDir + ": " + err.Error())
		return backend.ErrFailed
	}
	keep, err := os.MkdirTemp(stateDir, ".units.")
	if err != nil {
		out.Error("Cannot create " + filepath.Join(stateDir, ".units.*") + ": " + err.Error())
		return backend.ErrFailed
	}
	defer func() { _ = os.RemoveAll(keep) }()
	kept, err := b.unitsKeep(filepath.Join(keep, "keep"))
	if err != nil {
		out.Error("Cannot copy the unit settings aside: " + err.Error())
		return backend.ErrFailed
	}
	if s := b.env.Snapshots; s != nil {
		if _, err := s.Take(); err != nil {
			out.Error(err.Error())
			out.Error("Nothing was changed: the pre-change snapshot could not be made.")
			return backend.ErrFailed
		}
	}

	ok := !b.legacyUnits() || b.legacyImport()
	if ok {
		if err := writer(); err != nil {
			b.confError(err)
			ok = false
		}
	}
	if !ok || !b.unitsStage(keep) {
		b.unitsRestore(kept)
		out.Error("Nothing was changed.")
		return backend.ErrFailed
	}
	if _, err := b.renderer().CommitUnits(keep); err != nil || !b.legacyRetire() {
		b.unitsRestore(kept)
		b.run(ctx, "daemon-reload")
		out.Error("The change could not be installed. Settings and drop-ins are as they were.")
		return backend.ErrFailed
	}
	b.run(ctx, "daemon-reload")

	var unit string
	if target == "all" || target == "default" {
		unit = Service
		// A restart that fails is judged (and undone) by the check below.
		b.run(ctx, "restart", unit)
		b.instancesSync(ctx)
	} else {
		unit = rtacacs.Unit(target)
		if !isRegular(rtacacs.DropIn(b.paths(), target)) {
			// The listener was removed: nothing to prove.
			b.quiet(ctx, "disable", "--quiet", "--now", unit)
			return nil
		}
		b.quiet(ctx, "enable", "--quiet", unit)
		b.run(ctx, "restart", unit)
	}

	if b.unitSettled(ctx, unit) {
		return nil
	}
	out.Error(strings.TrimSuffix(unit, ".service") + " failed to start. Restoring previous override.")
	b.unitsRestore(kept)
	b.run(ctx, "daemon-reload")
	if unit == Service || isRegular(rtacacs.DropIn(b.paths(), target)) {
		b.run(ctx, "restart", unit)
	} else {
		b.quiet(ctx, "disable", "--quiet", "--now", unit)
	}
	return backend.ErrFailed
}

// The log levels of 'tacctl config loglevel'.
var (
	levelNames = map[string]string{"10": "error", "20": "info", "30": "debug"}
	levelNums  = map[string]int{"debug": 30, "info": 20, "error": 10}
)

// LogLevel is 'tacctl config loglevel [debug|info|error]'
// (cmd_config_loglevel): without a level the current one and the usage;
// with one, backends.tacacs.level is set (the default is not written down)
// and every listener restarted.
func (b *Backend) LogLevel(ctx context.Context, level string) error {
	out := b.out()
	cur, _ := b.setting("level")
	if level == "" {
		name := levelNames[cur]
		if name == "" {
			name = "unknown"
		}
		writeString(out.Stdout, "\n  Current log level: "+name+" ("+cur+")\n\n  Usage: tacctl config loglevel <debug|info|error>\n\n")
		return nil
	}
	num, ok := levelNums[level]
	if !ok {
		out.Error("Invalid level: " + level + ". Use: debug, info, or error")
		return backend.ErrFailed
	}
	n := strconv.Itoa(num)
	if cur == n {
		out.Info("Already at " + level + " (" + n + ").")
		return nil
	}
	if err := b.settingsApply(ctx, "all", func() error { return b.env.Conf.Set("backends.tacacs.level", n) }); err != nil {
		return err
	}
	out.Info("Log level changed to " + level + " (" + n + "). Service restarted.")
	writeString(out.Stdout, "\n")
	return nil
}

// loopback reports whether a metrics address is loopback-only, as the
// metrics report words it.
func loopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "[::1]") || strings.HasPrefix(addr, "localhost:")
}

// scrapeURL is the URL of the exporter at a metrics address.
func scrapeURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr + "/metrics"
	}
	return "http://" + addr + "/metrics"
}

// Metrics is 'tacctl config metrics [show|enable|disable|address
// <host:port>|reset]' (cmd_config_metrics): the default listener's
// Prometheus exporter. 'disable' binds it to 127.0.0.1:0, a loopback port
// no scraper can know: tacquito's -export-promhttp=false would tear down
// the whole daemon.
func (b *Backend) Metrics(ctx context.Context, sub, arg string) error {
	out := b.out()
	w := out.Stdout
	def, sink := rtacacs.MetricsDefault, rtacacs.MetricsSink
	cur, override := b.setting("metrics_address")
	src := "default"
	if override {
		src = "override"
	}
	state, color := "enabled (externally reachable)", ui.Yellow
	switch {
	case cur == sink:
		state, color = "disabled", ui.Red
	case loopback(cur):
		state, color = "enabled (loopback-only)", ui.Green
	}
	apply := func(writer func() error) error { return b.settingsApply(ctx, "all", writer) }
	unset := func() error { return b.env.Conf.Unset("backends.tacacs.metrics_address") }

	switch sub {
	case "", "show", "-h", "--help", "help":
		var s strings.Builder
		s.WriteString("\n" + ui.Bold + "Prometheus metrics exporter" + ui.NC + "\n")
		s.WriteString("--------------------------------------------\n")
		s.WriteString("  State:    " + color + state + ui.NC + "\n")
		s.WriteString(ui.Echo("  Address:  " + cur + "  (" + src + ")"))
		if state != "disabled" {
			s.WriteString("\n  Scrape URL: " + scrapeURL(cur) + "\n")
		}
		s.WriteString("\nUsage:\n")
		s.WriteString("  tacctl config metrics                      Show current state\n")
		s.WriteString("  tacctl config metrics enable               Revert to default (" + def + ")\n")
		s.WriteString("  tacctl config metrics disable              Sink to " + sink + " (no scraper can reach)\n")
		s.WriteString("  tacctl config metrics address <host:port>  Explicit bind (e.g. 10.1.0.1:8080 for external)\n")
		s.WriteString("  tacctl config metrics reset                Clear override (revert to unit default)\n\n")
		if state == "disabled" {
			s.WriteString("  Note: tacquito still runs the exporter goroutine, bound to an\n")
			s.WriteString("        ephemeral loopback port unknown to any scraper. This is the\n")
			s.WriteString("        closest we can get without patching tacquito upstream.\n\n")
		}
		writeString(w, s.String())
		return nil
	case "enable":
		if state != "disabled" && !override {
			out.Info("Already enabled on default (" + def + ").")
			return nil
		}
		if err := apply(unset); err != nil {
			return err
		}
		out.Info("Metrics exporter enabled on " + def + "/metrics.")
	case "disable":
		if state == "disabled" {
			out.Info("Already disabled (sunk to " + sink + ").")
			return nil
		}
		if err := apply(func() error { return b.env.Conf.Set("backends.tacacs.metrics_address", sink) }); err != nil {
			return err
		}
		out.Info("Metrics exporter sunk to " + sink + " — no scraper can reach it.")
		out.Warn("Note: the exporter goroutine still runs; bind-to-loopback-0 is the")
		out.Warn("closest 'off' state tacquito supports without an upstream patch.")
	case "address":
		if arg == "" {
			out.Error("Usage: tacctl config metrics address <host:port>")
			out.Error("Examples:  127.0.0.1:8080  (loopback only — default)")
			out.Error("           :8080           (all interfaces — external scrapers can reach)")
			out.Error("           10.1.0.1:9090   (specific mgmt IP + custom port)")
			return backend.ErrFailed
		}
		if !strings.Contains(arg, ":") {
			out.Error("Address must include a port (e.g. '127.0.0.1:8080' or ':8080').")
			return backend.ErrFailed
		}
		// The default address is not written down (the write prunes it).
		if err := apply(func() error { return b.env.Conf.Set("backends.tacacs.metrics_address", arg) }); err != nil {
			return err
		}
		out.Info("Metrics listen address set to " + arg + ". Service restarted.")
		if !strings.HasPrefix(arg, "127.") && !strings.HasPrefix(arg, "[::1]") && arg != sink {
			out.Warn("Exporter is now externally reachable. Ensure downstream scrapers")
			out.Warn("have appropriate network-level access controls.")
		}
	case "reset":
		if err := apply(unset); err != nil {
			return err
		}
		out.Info("Metrics override cleared. Using unit default (" + def + ").")
	default:
		out.Error("Unknown subcommand: '" + sub + "'")
		out.Error("Run 'tacctl config metrics' with no arguments for usage.")
		return backend.ErrFailed
	}
	writeString(w, "\n")
	return nil
}

// copyPreserve is 'cp -p src dst': the content, then the owner (best
// effort), the mode and the access and modification times.
func copyPreserve(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	o, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, in); err != nil {
		_ = o.Close()
		return err
	}
	atime := st.ModTime()
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = o.Chown(int(sys.Uid), int(sys.Gid))
		atime = time.Unix(sys.Atim.Sec, sys.Atim.Nsec)
	}
	if err := o.Chmod(st.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		_ = o.Close()
		return err
	}
	if err := o.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, atime, st.ModTime())
}
