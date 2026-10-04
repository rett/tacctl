package radius

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	rr "github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/rendered"
)

// statusFile is what RenderStage leaves in its directory for RenderCommit:
// '<conf state> <users state> <dictionary state>'.
const statusFile = "status"

// report writes what the 0.1.16 render program prints for err: one
// "tacctl render: <message>" line on stderr.
func (m *Module) report(err error) {
	var re *rr.Error
	text := rendered.Report(err)
	if errors.As(err, &re) {
		text = rr.Report(err)
	}
	_, _ = fmt.Fprintln(m.env.Out.Stderr, text)
}

// artifactNames is the artifacts as one phrase for a message
// (_radius_artifact_names).
func (m *Module) artifactNames() string {
	return m.L.Conf + ", " + m.L.Users + " or " + m.L.Dict
}

// renderLive is _radius_render_live: render the current store into
// <dir>/conf, <dir>/users and <dir>/dictionary (mode 0600) and say how each
// live artifact stands against its render, in the words of the contract's
// render_check, in the order conf, users, dictionary. An error is the
// render program's (m.report prints it).
func (m *Module) renderLive(dir string) ([3]string, error) {
	var states [3]string
	s, err := m.loadStore()
	if err != nil {
		return states, err
	}
	merged, err := rr.ConfView(m.env.Conf)
	if err != nil {
		return states, err
	}
	out, err := rr.RenderStore(s, merged, rr.ParamsFor(m.L))
	if err != nil {
		return states, err
	}
	if err := out.WriteDir(dir); err != nil {
		return states, err
	}
	for i, f := range []struct{ text, live string }{
		{out.Conf, m.L.Conf}, {out.Users, m.L.Users}, {out.Dictionary, m.L.Dict},
	} {
		st, err := rendered.LiveStatus(m.env.Paths.Rendered, f.live, []byte(f.text))
		if err != nil {
			return states, err
		}
		states[i] = st
	}
	return states, nil
}

// DaemonCheck is _radius_daemon_check: have the daemon itself read
// <dir>/conf, <dir>/users and <dir>/dictionary ('radiusd -C'). checked is
// false when there is no daemon on this machine to ask (the check is
// skipped, err nil); err is non-nil when the daemon rejects the files or the
// check cannot be run, with the messages written.
//
// The check drops to the service account before it reads the users file, so
// the files are copied into a scratch directory beside the live ones (0750
// root:<daemon group>; a staging directory under /tmp is closed to that
// account), the daemon is pointed at it with -d and at the copy of the
// dictionary with -D. The live files are not touched and the scratch
// directory is removed before this returns.
func (m *Module) DaemonCheck(ctx context.Context, dir string) (checked bool, err error) {
	out := m.env.Out
	if !isExec(m.L.Bin) || !isDir(m.L.Dir) {
		return false, nil
	}
	// tacctl's dictionary includes the package's; without that one the
	// daemon knows no attribute at all, and says so in a way that names
	// neither.
	f, err := os.Open(m.L.SystemDict)
	if err != nil {
		out.Error("FreeRADIUS's main dictionary is not at " + m.L.SystemDict + "; tacctl's dictionary (" + m.L.Dict + ") includes it.")
		out.Error("The freeradius package is incomplete or keeps its dictionaries somewhere tacctl does not know. Nothing was changed.")
		return true, backend.ErrFailed
	}
	_ = f.Close()
	chk, err := os.MkdirTemp(m.L.Dir, ".tacctl-check.")
	if err != nil {
		out.Error("Cannot create a scratch directory in " + m.L.Dir + ": " + err.Error())
		return true, backend.ErrFailed
	}
	defer func() { _ = os.RemoveAll(chk) }()
	dictD := filepath.Join(chk, "dictionary.d")
	if err := os.Mkdir(dictD, 0o750); err != nil {
		out.Error("Cannot create a scratch directory in " + m.L.Dir + ": " + err.Error())
		return true, backend.ErrFailed
	}
	for _, f := range [][2]string{
		{"conf", filepath.Join(chk, paths.RadiusName+".conf")},
		{"users", filepath.Join(chk, paths.RadiusName+".users")},
		{"dictionary", filepath.Join(dictD, "dictionary")},
	} {
		if err := copyFile(filepath.Join(dir, f[0]), f[1], 0o640); err != nil {
			out.Error("Cannot copy the rendered files for the check: " + err.Error())
			return true, backend.ErrFailed
		}
	}
	for _, p := range []string{chk, dictD,
		filepath.Join(chk, paths.RadiusName+".conf"), filepath.Join(chk, paths.RadiusName+".users"), filepath.Join(dictD, "dictionary")} {
		m.Chown(p)
	}
	_ = os.Chmod(chk, 0o750)
	_ = os.Chmod(dictD, 0o750)

	res, runErr := m.runner.Run(ctx, execx.Cmd{
		Name: m.L.Bin,
		Args: []string{"-C", "-lstdout", "-d", chk, "-D", dictD, "-n", paths.RadiusName},
	})
	if runErr == nil && res.Code == 0 {
		return true, nil
	}
	out.Error("FreeRADIUS rejects the rendered configuration ('" + filepath.Base(m.L.Bin) + " -C'):")
	// The scratch paths are the live files' as far as the operator is
	// concerned.
	text := string(res.Stdout) + string(res.Stderr)
	if runErr != nil && len(text) == 0 {
		text = runErr.Error() + "\n"
	}
	var errLines []string
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			l = strings.ReplaceAll(l, dictD, m.L.DictDir)
			l = strings.ReplaceAll(l, chk, m.L.Dir)
			errLines = append(errLines, l)
		}
	}
	if len(errLines) > 5 {
		errLines = errLines[len(errLines)-5:]
	}
	for _, l := range errLines {
		_, _ = fmt.Fprintln(m.env.Out.Stderr, l)
	}
	return true, backend.ErrFailed
}

// RenderCheck is backend_radius_render_check: a trial render of the current
// store, proved by the daemon when there is one, nothing installed; the
// state furthest from the render among the three files.
func (m *Module) RenderCheck(ctx context.Context) (string, error) {
	tmp, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		m.env.Out.Error("Cannot create a staging directory: " + err.Error())
		return "", backend.ErrFailed
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	states, err := m.renderLive(tmp)
	if err != nil {
		m.report(err)
		return "", backend.ErrFailed
	}
	if _, err := m.DaemonCheck(ctx, tmp); err != nil {
		return "", backend.ErrFailed
	}
	word, _ := rr.Worst(states[:]...)
	return word, nil
}

// RenderGate is _radius_render_gate, the gate of StoreApply's step 1. Hand
// edits cannot be adopted, so a file tacctl has no record of is refused like
// an edited one; the answer is never "adopt".
func (m *Module) RenderGate(context.Context) backend.GateResult {
	out := m.env.Out
	for _, f := range m.Artifacts() {
		word, err := rendered.Check(m.env.Paths.Rendered, f)
		if err != nil {
			out.Error("Cannot read " + m.env.Paths.Rendered + "; refusing to overwrite " + f + ".")
			return backend.GateFailed
		}
		switch word {
		case rendered.OK, rendered.Missing:
			continue
		case rendered.Drift:
			out.Error(f + " was edited since tacctl rendered it; this command would discard those edits.")
		default:
			out.Error(f + " was not rendered by tacctl; this command would replace it.")
		}
		out.Error("Nothing was changed. There is no way to adopt an edit of the RADIUS files into the store; to discard it: 'tacctl config render --force'. Then run this command again.")
		return backend.GateRefused
	}
	return backend.GateOK
}

// RenderStage is _radius_render_stage: render, prove, and decide whether the
// live artifacts may be replaced. It leaves <dir>/conf, <dir>/users,
// <dir>/dictionary and <dir>/status. An artifact that is missing is simply
// written: that is the state of an install from before the dictionary
// existed. Drift (or a file tacctl never rendered) without force is
// backend.ErrRefused.
func (m *Module) RenderStage(ctx context.Context, dir string, force bool) error {
	out := m.env.Out
	states, err := m.renderLive(dir)
	if err != nil {
		m.report(err)
		return backend.ErrFailed
	}
	worst, ok := rr.Worst(states[:]...)
	if !ok {
		return backend.ErrFailed
	}
	switch worst {
	case rendered.Current, rendered.Same, rendered.OK, rendered.Missing:
	case rendered.Drift, rendered.Unrecorded:
		if !force {
			if worst == rendered.Drift {
				out.Error(m.artifactNames() + " was edited since tacctl rendered it; rendering would discard those edits.")
			} else {
				out.Error(m.artifactNames() + " was not rendered by tacctl; rendering would replace it.")
			}
			out.Error("There is no way to adopt an edit of the RADIUS files into the store. To discard it: 'tacctl config render --force' (the current files are saved under " + m.env.Paths.BackupDir + "/legacy/ first).")
			return backend.ErrRefused
		}
	default:
		out.Error("Cannot read " + m.env.Paths.Rendered + "; refusing to overwrite " + m.L.Conf + ".")
		return backend.ErrFailed
	}
	if _, err := m.DaemonCheck(ctx, dir); err != nil {
		return backend.ErrFailed
	}
	text := strings.Join(states[:], " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, statusFile), []byte(text), 0o600); err != nil {
		out.Error("Cannot write " + filepath.Join(dir, statusFile) + ": " + err.Error())
		return backend.ErrFailed
	}
	return nil
}

// RenderCommit is _radius_render_commit: install what RenderStage left. The
// dictionary first (the other two need its attributes), then the users file:
// until the config that carries the new render id is in place too, the
// daemon would match nobody rather than a mix of two renders.
func (m *Module) RenderCommit(_ context.Context, dir string) (bool, error) {
	out := m.env.Out
	data, err := os.ReadFile(filepath.Join(dir, statusFile))
	if err != nil {
		out.Error("Cannot read " + filepath.Join(dir, statusFile) + ": " + err.Error())
		return false, backend.ErrFailed
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		out.Error("Cannot read " + filepath.Join(dir, statusFile) + ": it does not hold three states.")
		return false, backend.ErrFailed
	}
	if err := os.MkdirAll(m.L.Dir, 0o755); err != nil {
		out.Error("Cannot create " + m.L.Dir + ": " + err.Error())
		return false, backend.ErrFailed
	}
	changed := false
	for _, a := range []struct{ name, live, state string }{
		{"dictionary", m.L.Dict, f[2]}, {"users", m.L.Users, f[1]}, {"conf", m.L.Conf, f[0]},
	} {
		ch, err := m.installFile(filepath.Join(dir, a.name), a.live, a.state)
		if err != nil {
			return false, backend.ErrFailed
		}
		changed = changed || ch
	}
	return changed, nil
}

// installFile is _radius_install_file: one artifact of a commit. changed is
// true when the live file was replaced.
func (m *Module) installFile(staged, live, state string) (changed bool, err error) {
	out := m.env.Out
	switch state {
	case rendered.Current:
		return false, nil
	case rendered.Same:
		return false, m.record(live)
	case rendered.Drift, rendered.Unrecorded:
		if err := m.saveDisplaced(live); err != nil {
			out.Error("Cannot save " + live + " under " + filepath.Join(m.env.Paths.BackupDir, "legacy") + ": " + err.Error())
			return false, err
		}
	}
	// Same directory as the target, so the final step is a rename.
	next := live + ".tacctl-new"
	if dir := filepath.Dir(live); !isDir(dir) {
		// The dictionary's directory, on its first render.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			out.Error("Cannot create " + dir + ": " + err.Error())
			return false, err
		}
		_ = os.Chmod(dir, 0o750)
		m.Chown(dir)
	}
	if err := copyFile(staged, next, 0o640); err != nil {
		_ = os.Remove(next)
		out.Error("Cannot write " + next + ": " + err.Error())
		return false, err
	}
	m.Chown(next)
	if err := os.Rename(next, live); err != nil {
		_ = os.Remove(next)
		out.Error("Cannot replace " + live + ": " + err.Error())
		return false, err
	}
	if err := m.record(live); err != nil {
		return false, err
	}
	return true, nil
}

// record is 'rendered_record <live>', its message on stderr.
func (m *Module) record(live string) error {
	if err := rendered.Record(m.env.Paths.Rendered, live); err != nil {
		m.report(err)
		return err
	}
	return nil
}

// saveDisplaced is _radius_save_displaced: copy a file that is about to be
// overwritten into backups/legacy/ (0700, the copy 0600) and say so.
func (m *Module) saveDisplaced(src string) error {
	dir := filepath.Join(m.env.Paths.BackupDir, "legacy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	now := m.now()
	dest := filepath.Join(dir, fmt.Sprintf("%s.drift.%s_%03d", filepath.Base(src),
		now.Format("20060102_150405"), now.Nanosecond()/1_000_000))
	if err := copyFile(src, dest, 0o600); err != nil {
		return err
	}
	m.stderr().Warn("Previous " + src + " saved to " + dest)
	return nil
}

// copyFile is 'cp src dst; chmod mode dst'.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(mode); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
