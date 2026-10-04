package radius

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	rr "github.com/rett/tacctl/internal/render/radius"
)

// systemctl runs 'systemctl args...'. Its output goes to the invocation's
// output (bash lets it through), or nowhere when quiet ('2>/dev/null'; the
// commands that are only asked for their answer). It returns the exit
// status, 127 or 126 when systemctl could not be run.
func (m *Module) systemctl(ctx context.Context, quiet bool, args ...string) int {
	c := execx.Cmd{Name: "systemctl", Args: args}
	if !quiet {
		c.Stdout, c.Stderr = m.env.Out.Stdout, m.env.Out.Stderr
	}
	res, err := m.runner.Run(ctx, c)
	if err != nil && res.Code == 0 {
		return 1
	}
	return res.Code
}

// systemctlOut is 'systemctl args... 2>/dev/null': its standard output
// (without the final newline) and exit status.
func (m *Module) systemctlOut(ctx context.Context, args ...string) (string, int) {
	res, err := m.runner.Run(ctx, execx.Cmd{Name: "systemctl", Args: args})
	code := res.Code
	if err != nil && code == 0 {
		code = 1
	}
	return strings.TrimRight(string(res.Stdout), "\n"), code
}

// DropinText is _radius_dropin_text: the drop-in that makes the package's
// unit run tacctl's instance, with tacctl's dictionary ('-D'), per family.
func (m *Module) DropinText() string { return rr.DropinText(m.L) }

// DropinInstall is _radius_dropin_install: write the drop-in when it is
// missing or not what this release writes, then 'systemctl daemon-reload'.
// changed says whether it was written (RADIUS_DROPIN_CHANGED); an error is a
// failure to write it, or a daemon-reload that failed (as the return status
// of the bash function is that of its last command).
func (m *Module) DropinInstall(ctx context.Context) (changed bool, err error) {
	want := m.DropinText()
	if have, err := os.ReadFile(m.L.DropIn); err == nil && isFile(m.L.DropIn) &&
		strings.TrimRight(string(have), "\n") == strings.TrimRight(want, "\n") {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(m.L.DropIn), 0o755); err != nil {
		return false, err
	}
	next := m.L.DropIn + ".tacctl-new"
	if err := os.WriteFile(next, []byte(strings.TrimRight(want, "\n")+"\n"), 0o600); err != nil {
		return false, err
	}
	if err := os.Chmod(next, 0o644); err != nil {
		_ = os.Remove(next)
		return false, err
	}
	if err := os.Rename(next, m.L.DropIn); err != nil {
		_ = os.Remove(next)
		return false, err
	}
	if m.systemctl(ctx, false, "daemon-reload") != 0 {
		return true, backend.ErrFailed
	}
	return true, nil
}

// DropinRemove is _radius_dropin_remove: remove the drop-in (and its
// directory when that leaves it empty), then 'systemctl daemon-reload'.
// Nothing when there is none.
func (m *Module) DropinRemove(ctx context.Context) error {
	if !isFile(m.L.DropIn) {
		return nil
	}
	_ = os.Remove(m.L.DropIn)
	_ = os.Remove(filepath.Dir(m.L.DropIn)) // rmdir: only when empty
	if m.systemctl(ctx, false, "daemon-reload") != 0 {
		return backend.ErrFailed
	}
	return nil
}

// LogrotateText is _radius_logrotate_text: the logrotate file for the three
// logs tacctl's instance writes.
func (m *Module) LogrotateText() string {
	var b strings.Builder
	b.WriteString("# Installed by tacctl: the logs of its FreeRADIUS instance.\n")
	b.WriteString(m.L.DaemonLog + " " + m.L.AuthLog + " " + m.L.AcctLog + " {\n")
	for _, l := range []string{"weekly", "rotate 12", "missingok", "notifempty", "compress", "delaycompress", "copytruncate"} {
		b.WriteString("\t" + l + "\n")
	}
	b.WriteString("\tsu " + m.L.User + " " + m.L.Group + "\n}\n")
	return b.String()
}

// LogrotateInstall is _radius_logrotate_install: write the logrotate file
// (0644) when logrotate's directory exists.
func (m *Module) LogrotateInstall() error {
	if !isDir(filepath.Dir(m.L.Logrotate)) {
		return nil
	}
	if err := os.WriteFile(m.L.Logrotate, []byte(m.LogrotateText()), 0o600); err != nil {
		return err
	}
	return os.Chmod(m.L.Logrotate, 0o644)
}

// unitRestart is _radius_unit_restart: restart the unit on what the
// artifacts now are. A drop-in from a release before the dictionary starts
// the daemon without '-D'; the configuration a render of this release writes
// does not load that way, so the drop-in is brought in line first (only once
// the dictionary it names is there, and only while the backend runs tacctl's
// instance). It reports whether the restart succeeded.
func (m *Module) unitRestart(ctx context.Context) bool {
	if isFile(m.L.DropIn) && isFile(m.L.Dict) {
		if _, err := m.DropinInstall(ctx); err != nil {
			m.env.Out.Warn("Could not update " + m.L.DropIn + ".")
		}
	}
	return m.systemctl(ctx, true, "restart", m.L.Unit) == 0
}

// unitFree is _radius_unit_free: is the package's unit free for tacctl to
// run its instance under? Not when it is running or enabled without tacctl's
// drop-in: that is somebody's RADIUS server. False comes with what to do
// about it, written.
func (m *Module) unitFree(ctx context.Context) bool {
	if isFile(m.L.DropIn) {
		return true
	}
	why := ""
	switch {
	case m.systemctl(ctx, true, "is-active", "--quiet", m.L.Unit) == 0:
		why = "running"
	case m.systemctl(ctx, true, "is-enabled", "--quiet", m.L.Unit) == 0:
		why = "enabled at boot"
	}
	if why == "" {
		return true
	}
	out := m.env.Out
	out.Error("FreeRADIUS is already installed on this machine and " + m.L.Unit + " is " + why + ": somebody's RADIUS server.")
	out.Error("tacctl runs its own configuration under that unit (the files in " + m.L.Dir + " stay as they are, but are no longer served).")
	out.Error("If it is not in use, hand the unit over and run this again:  systemctl disable --now " + m.L.Unit)
	return false
}

// Service is backend_radius_service. One daemon serves every listener, so
// the listener argument changes nothing. 'reload' restarts: FreeRADIUS reads
// its clients only at start. A restart reports its own outcome and never
// fails. stop does nothing without the drop-in: the unit is then not running
// tacctl's instance, and whatever it does is not tacctl's to stop.
// is-active returns systemctl's word and an error when it is not "active";
// since and pid return systemd's values.
func (m *Module) Service(ctx context.Context, action backend.ServiceAction, _ string) (string, error) {
	out := m.env.Out
	switch action {
	case backend.ServiceRestart, backend.ServiceReload:
		if m.unitRestart(ctx) {
			out.Info("Service restarted (" + m.unitName() + ").")
		} else {
			out.Warn("Service restart failed — run: sudo systemctl restart " + m.unitName())
		}
		return "", nil
	case backend.ServiceStart:
		return "", failed(m.systemctl(ctx, false, "start", m.L.Unit))
	case backend.ServiceStop:
		if !isFile(m.L.DropIn) {
			return "", nil
		}
		return "", failed(m.systemctl(ctx, false, "stop", m.L.Unit))
	case backend.ServiceEnable:
		if !m.unitFree(ctx) {
			return "", backend.ErrFailed
		}
		if _, err := m.DropinInstall(ctx); err != nil {
			out.Error("Could not write " + m.L.DropIn + ".")
			return "", backend.ErrFailed
		}
		return "", failed(m.systemctl(ctx, false, "enable", "--quiet", m.L.Unit))
	case backend.ServiceDisable:
		if !isFile(m.L.DropIn) {
			return "", nil
		}
		rc := m.systemctl(ctx, false, "disable", "--quiet", m.L.Unit)
		if err := m.DropinRemove(ctx); err != nil || rc != 0 {
			return "", backend.ErrFailed
		}
		return "", nil
	case backend.ServiceIsActive:
		word, code := m.systemctlOut(ctx, "is-active", m.L.Unit)
		return word, failed(code)
	case backend.ServiceSince:
		v, _ := m.systemctlOut(ctx, "show", m.L.Unit, "--property=ActiveEnterTimestamp")
		return cutField2(v), nil
	case backend.ServicePID:
		v, _ := m.systemctlOut(ctx, "show", m.L.Unit, "--property=MainPID")
		return cutField2(v), nil
	}
	return "", backend.ErrUnsupported
}

// failed maps a systemctl status to the error of a verb that reports it.
func failed(code int) error {
	if code != 0 {
		return backend.ErrFailed
	}
	return nil
}

// cutField2 is "| cut -d= -f2": the second '='-separated field, or the line
// itself when it has no '='. Several lines are cut one by one.
func cutField2(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if f := strings.Split(line, "="); len(f) > 1 {
			line = f[1]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
