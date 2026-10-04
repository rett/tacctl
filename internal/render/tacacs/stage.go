package tacacs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// Paths are the files the render steps read and write.
type Paths struct {
	Config      string // CONFIG: the live tacquito.yaml
	StoreFile   string // STORE_FILE
	Rendered    string // RENDERED_FILE: rendered.json
	BackupDir   string // BACKUP_DIR: displaced copies go to its legacy/
	LogDir      string // LOG_DIR
	AcctLog     string // ACCT_LOG: the default listener's accounting log
	OverrideDir string // OVERRIDE_DIR: tacquito.service's drop-in directory
	UnitDir     string // TACACS_UNIT_DIR: unit files and the instances' drop-in directories
}

// PathsFrom takes the render paths from the resolved TACCTL_* paths.
func PathsFrom(p paths.Paths) Paths {
	return Paths{
		Config:      p.Config,
		StoreFile:   p.StoreFile,
		Rendered:    p.Rendered,
		BackupDir:   p.BackupDir,
		LogDir:      p.Log,
		AcctLog:     p.AcctLog,
		OverrideDir: p.OverrideDir,
		UnitDir:     p.TacacsUnitDir,
	}
}

// The errors of the render steps. Their messages have been written to the
// Renderer's Stderr already; the caller only maps them to an exit status.
var (
	// ErrRefused: replacing the live file would discard something and
	// --force was not given (exit 3).
	ErrRefused = errors.New("tacacs render: refused")
	// ErrFailed: the step failed (exit 1).
	ErrFailed = errors.New("tacacs render: failed")
)

// GateResult is the render gate's verdict (_tacacs_render_gate).
type GateResult int

// The verdicts, with the bash function's return status as Code.
const (
	GateOK      GateResult = iota // go ahead (0)
	GateAdopt                     // go ahead and adopt the never-rendered file: render with --force (10)
	GateRefused                   // refused, messages written (3)
	GateFailed                    // failed, messages written (1)
)

// Code is the bash return status of the verdict.
func (g GateResult) Code() int {
	switch g {
	case GateOK:
		return 0
	case GateAdopt:
		return 10
	case GateRefused:
		return 3
	}
	return 1
}

// Staged file names inside a stage directory.
const (
	StagedConfig = "tacquito.yaml"
	StatusName   = "status"
	UnitsDir     = "units"
)

// Renderer runs the render steps of the TACACS+ backend over Paths: what
// lib/backends/tacacs.sh does in _tacacs_render_stage/_commit,
// _tacacs_units_commit, _tacacs_render_gate and the render check.
type Renderer struct {
	Paths Paths
	// Conf is tacctl.yaml: its merged view is rendered, and its file
	// (Conf.Path) must parse (CheckOverrides).
	Conf *conf.Config
	// Load is the legacy loader every render is read back with.
	Load LegacyLoader
	// Chown gives a written file to tacquito:tacquito (ChownTacquito when
	// nil).
	Chown Chowner
	// Now is the clock of the displaced copies' names (time.Now when nil).
	Now func() time.Time
	// Stderr receives every message.
	Stderr io.Writer
}

func (r *Renderer) out() ui.Output {
	w := r.Stderr
	if w == nil {
		w = io.Discard
	}
	// info and warn are redirected to stderr by the bash callers (>&2).
	return ui.Output{Stdout: w, Stderr: w}
}

func (r *Renderer) report(err error) {
	w := r.Stderr
	if w == nil {
		w = io.Discard
	}
	_, _ = io.WriteString(w, rendered.Report(err)+"\n")
}

func (r *Renderer) chown() Chowner {
	if r.Chown != nil {
		return r.Chown
	}
	return ChownTacquito
}

func (r *Renderer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// ChownTacquito is 'chown tacquito:tacquito <path>' with every failure
// ignored (no such account, not permitted).
func ChownTacquito(path string) {
	u, err := user.Lookup("tacquito")
	if err != nil {
		return
	}
	g, err := user.LookupGroup("tacquito")
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(g.Gid)
	if err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
}

// RenderLive is the render-live program of 0.1.16: render the store into
// out (RenderToFile, with the read-back), and with unitsDir set also stage
// every listener's drop-in there (StageUnits); return the word of the live
// tacquito.yaml against the render (rendered.LiveStatus). Errors are not
// written; rendered.Report words them.
func (r *Renderer) RenderLive(out, unitsDir string) (string, error) {
	st, err := store.Load(r.Paths.StoreFile)
	if err != nil {
		return "", err
	}
	if r.Conf == nil {
		return "", &rendered.Error{Msg: "internal: no tacctl.yaml view to render with"}
	}
	if err := CheckOverrides(r.Conf.Path); err != nil {
		return "", err
	}
	view := r.Conf.Merged()
	text, err := RenderToFile(st, view, out, r.Load, r.chown())
	if err != nil {
		return "", err
	}
	if unitsDir != "" {
		if _, err := StageUnits(view, unitsDir, r.Paths); err != nil {
			return "", err
		}
	}
	return rendered.LiveStatus(r.Paths.Rendered, r.Paths.Config, text)
}

// Stage is _tacacs_render_stage: render the store into
// <dir>/tacquito.yaml, note in <dir>/status how the live config stands
// against it, and refuse (ErrRefused) when replacing it would discard
// something and force is not set. With units the listeners' drop-ins are
// staged in <dir>/units by the same run (they never refuse). Touches
// nothing outside dir.
func (r *Renderer) Stage(dir string, force, units bool) error {
	unitsDir := ""
	if units {
		unitsDir = filepath.Join(dir, UnitsDir)
	}
	status, err := r.RenderLive(filepath.Join(dir, StagedConfig), unitsDir)
	if err != nil {
		r.report(err)
		return ErrFailed
	}
	o := r.out()
	cfg := r.Paths.Config
	switch status {
	case rendered.Current, rendered.Same, rendered.OK, rendered.Missing:
	case rendered.Drift, rendered.Unrecorded:
		if !force {
			if status == rendered.Drift {
				o.Error(cfg + " was edited since tacctl rendered it; rendering would discard those edits.")
			} else {
				o.Error(cfg + " was not rendered by tacctl; rendering would replace it.")
			}
			o.Error("To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'.")
			o.Error("To discard it: 'tacctl config render --force' alone. Either way the current file is saved under " +
				r.Paths.BackupDir + "/legacy/ first.")
			return ErrRefused
		}
	default:
		o.Error("Cannot read " + r.Paths.Rendered + "; refusing to overwrite " + cfg + ".")
		return ErrFailed
	}
	if err := os.WriteFile(filepath.Join(dir, StatusName), []byte(status+"\n"), 0o666); err != nil {
		r.report(err)
		return ErrFailed
	}
	return nil
}

// install copies src to dst through dst+".tacctl-new" (mode, then the
// optional chown, then a rename), as the bash commits do with cp, chmod
// and mv -f.
func install(src, dst string, mode os.FileMode, chown Chowner) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	staged := dst + ".tacctl-new"
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(staged, mode); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if chown != nil {
		chown(staged)
	}
	if err := os.Rename(staged, dst); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return nil
}

// CommitConfig is _tacacs_render_commit: install the tacquito.yaml Stage
// left in dir. It reports whether the live file was replaced (CHANGED);
// a file already as rendered is only recorded when it was not.
func (r *Renderer) CommitConfig(dir string) (changed bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, StatusName))
	if err != nil {
		r.report(err)
		return false, ErrFailed
	}
	cfg := r.Paths.Config
	switch strings.TrimRight(string(data), "\n") {
	case rendered.Current:
		return false, nil
	case rendered.Same:
		if err := rendered.Record(r.Paths.Rendered, cfg); err != nil {
			r.report(err)
			return false, ErrFailed
		}
		return false, nil
	case rendered.Drift, rendered.Unrecorded:
		if err := r.SaveDisplaced(cfg); err != nil {
			return false, err
		}
	}
	if err := install(filepath.Join(dir, StagedConfig), cfg, 0o640, r.chown()); err != nil {
		r.report(err)
		return false, ErrFailed
	}
	if err := rendered.Record(r.Paths.Rendered, cfg); err != nil {
		r.report(err)
		return false, ErrFailed
	}
	return true, nil
}

// instanceDropIns are the rendered drop-ins of instances on disk
// ($TACACS_UNIT_DIR/tacquito@*.service.d/tacctl.conf, regular files), in
// glob order, with their listener names.
func (r *Renderer) instanceDropIns() ([][2]string, error) {
	matches, err := filepath.Glob(filepath.Join(r.Paths.UnitDir, "tacquito@*.service.d", DropInName))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var out [][2]string
	for _, f := range matches {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			continue
		}
		inst := strings.TrimSuffix(f, ".service.d/"+DropInName)
		inst = inst[strings.LastIndex(inst, "/tacquito@")+len("/tacquito@"):]
		out = append(out, [2]string{inst, f})
	}
	return out, nil
}

// CommitUnits is _tacacs_units_commit: install the drop-ins Stage left in
// <dir>/units and remove those of listeners that are gone (file, empty
// directory and record). It returns the unit of every drop-in it wrote or
// removed (none: all were current). Files only: reloading systemd and
// restarting are the caller's.
func (r *Renderer) CommitUnits(dir string) ([]string, error) {
	udir := filepath.Join(dir, UnitsDir)
	if st, err := os.Stat(filepath.Join(udir, IndexName)); err != nil || !st.Mode().IsRegular() {
		return nil, nil
	}
	index, err := ReadIndex(udir)
	if err != nil {
		r.report(err)
		return nil, ErrFailed
	}
	var written, names []string
	for _, e := range index {
		names = append(names, e.Listener)
		switch e.Status {
		case rendered.Current:
			continue
		case rendered.Same:
			if err := rendered.Record(r.Paths.Rendered, e.Live); err != nil {
				r.report(err)
				return written, ErrFailed
			}
			continue
		case rendered.Unreadable:
			r.out().Error("Cannot read " + r.Paths.Rendered + "; refusing to overwrite " + e.Live + ".")
			return written, ErrFailed
		case rendered.Drift, rendered.Unrecorded:
			if err := r.SaveDisplaced(e.Live); err != nil {
				return written, err
			}
		}
		d := filepath.Dir(e.Live)
		if err := os.MkdirAll(d, 0o755); err != nil {
			r.report(err)
			return written, ErrFailed
		}
		_ = os.Chmod(d, 0o755)
		if err := install(filepath.Join(udir, e.Listener+".conf"), e.Live, 0o644, nil); err != nil {
			r.report(err)
			return written, ErrFailed
		}
		if err := rendered.Record(r.Paths.Rendered, e.Live); err != nil {
			r.report(err)
			return written, ErrFailed
		}
		written = append(written, Unit(e.Listener))
	}
	stale, err := r.instanceDropIns()
	if err != nil {
		r.report(err)
		return written, ErrFailed
	}
	for _, s := range stale {
		inst, f := s[0], s[1]
		if containsString(names, inst) {
			continue
		}
		if err := os.Remove(f); err != nil {
			r.report(err)
			return written, ErrFailed
		}
		_ = os.Remove(filepath.Dir(f)) // rmdir: only when empty
		if err := rendered.Forget(r.Paths.Rendered, f); err != nil {
			r.report(err)
			return written, ErrFailed
		}
		written = append(written, Unit(inst))
	}
	return written, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// PreStoreLatest is store_pre_store_latest: the newest copy the import
// kept of the pre-store config (backups/legacy/tacquito.yaml.pre-store.*,
// regular files, not symlinks), by name.
func PreStoreLatest(backupDir string) (string, bool) {
	matches, _ := filepath.Glob(filepath.Join(backupDir, "legacy", "tacquito.yaml.pre-store.*"))
	newest := ""
	for _, f := range matches {
		st, err := os.Lstat(f)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if newest == "" || f > newest {
			newest = f
		}
	}
	return newest, newest != ""
}

func sameContent(a, b string) bool {
	da, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	db, err := os.ReadFile(b)
	return err == nil && bytes.Equal(da, db)
}

// DriftStamp is 'date +%Y%m%d_%H%M%S_%3N' of t (local time).
func DriftStamp(t time.Time) string {
	return t.Format("20060102_150405") + fmt.Sprintf("_%03d", t.Nanosecond()/1e6)
}

// SaveDisplaced is _tacacs_save_displaced: copy a file that is about to be
// overwritten to backups/legacy/<name>.drift.<stamp> (0600; the directory
// 0700) and warn where it went. A file the import already kept as the
// pre-store config is not copied twice.
func (r *Renderer) SaveDisplaced(src string) error {
	o := r.out()
	if dest, ok := PreStoreLatest(r.Paths.BackupDir); ok && sameContent(src, dest) {
		o.Info("Previous " + src + " is already kept as " + dest)
		return nil
	}
	dir := r.Paths.BackupDir + "/legacy"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.report(err)
		return ErrFailed
	}
	_ = os.Chmod(dir, 0o700)
	dest := dir + "/" + filepath.Base(src) + ".drift." + DriftStamp(r.now())
	data, err := os.ReadFile(src)
	if err == nil {
		err = os.WriteFile(dest, data, 0o600)
	}
	if err == nil {
		err = os.Chmod(dest, 0o600)
	}
	if err != nil {
		r.report(err)
		return ErrFailed
	}
	o.Warn("Previous " + src + " saved to " + dest)
	return nil
}

// Gate is _tacacs_render_gate, step 1 of store_apply: may a command that
// re-renders go ahead? The live config as tacctl rendered it, or none, is
// GateOK; a file tacctl never rendered that already says what the store
// says is GateAdopt; a hand-edited or foreign file is GateRefused, and
// unreadable records GateFailed (messages written).
func (r *Renderer) Gate() GateResult {
	o := r.out()
	cfg := r.Paths.Config
	word, err := rendered.Check(r.Paths.Rendered, cfg)
	if err != nil {
		r.report(err)
		o.Error("Cannot read " + r.Paths.Rendered + "; refusing to overwrite " + cfg + ".")
		return GateFailed
	}
	switch word {
	case rendered.OK, rendered.Missing:
		return GateOK
	case rendered.Drift:
		o.Error(cfg + " was edited since tacctl rendered it; this command would discard those edits.")
	case rendered.Unrecorded:
		if r.matchesStore(cfg) {
			return GateAdopt
		}
		o.Error(cfg + " was not rendered by tacctl and does not say what the store says; this command would replace it.")
	}
	o.Error("Nothing was changed. To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'.")
	o.Error("To discard it: 'tacctl config render --force' alone. Then run this command again.")
	return GateRefused
}

// matchesStore is _tacacs_matches_store: the file, read with the importer,
// holds what the current store holds. Every failure is "no".
func (r *Renderer) matchesStore(path string) bool {
	st, err := store.Load(r.Paths.StoreFile)
	if err != nil {
		return false
	}
	return MatchesModel(path, model.FromStore(st), r.Load)
}

// Check is tacacs_render_check (units false) and the units form of
// backend_tacacs_render_check (units true): a trial render of the store
// in a temp dir, nothing installed, and the one word for the live config
// against it; with units the artifact furthest from the render decides
// (rendered.Furthest). A store or listener model that cannot be rendered
// is ErrFailed (message written).
func (r *Renderer) Check(units bool) (string, error) {
	tmp, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		r.report(err)
		return "", ErrFailed
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	unitsDir := ""
	if units {
		unitsDir = filepath.Join(tmp, UnitsDir)
	}
	status, err := r.RenderLive(filepath.Join(tmp, StagedConfig), unitsDir)
	if err != nil {
		r.report(err)
		return "", ErrFailed
	}
	if !units {
		return status, nil
	}
	states := []string{status}
	index, err := ReadIndex(unitsDir)
	if err != nil {
		r.report(err)
		return "", ErrFailed
	}
	for _, e := range index {
		if e.Status != "" {
			states = append(states, e.Status)
		}
	}
	word, ok := rendered.Furthest(states)
	if !ok {
		return "", ErrFailed
	}
	return word, nil
}
