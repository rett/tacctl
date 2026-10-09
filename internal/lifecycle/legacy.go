package lifecycle

// The legacy mode of the TACACS+ configuration (lib/backends/tacacs.sh at
// 0.1.16, "Legacy mode" and "The daemon's config"): an install from before
// the store keeps a tacquito.yaml that is its own source of truth, and
// every upgrade runs the in-place migrations of that file before the store
// gate (flip.go) judges it. With a store they are no-ops and the config is
// re-rendered instead.
//
// The migrations edit tacquito.yaml with regular expressions, as 0.1.16's
// Python did: the patterns below are those of the Python, with its Unicode
// classes spelled out (Go's \w and \s are ASCII), and the file is read with
// Python's universal newlines (\r\n and \r are \n).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/py"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Env is what the configuration steps of install and upgrade work with:
// the invocation's backend environment (paths, tacctl.yaml, output, clock,
// snapshots, the backend set) and what the TACACS+ legacy mode needs on
// top. Make it with NewEnv.
type Env struct {
	*backend.Env
	// Rand keys the equivalence check's fingerprints and makes the shared
	// secret of a fresh install (nil: crypto/rand).
	Rand io.Reader
	// IsRoot: run as root (bash: EUID 0). Ownership changes that 0.1.16
	// requires as root (install's backups directories, the flipped
	// tacquito.yaml) are made only then.
	IsRoot bool
	// Smoke is the daemon load-smoke of a rendered tacquito.yaml: nil
	// passed, store.ErrSmokeSkipped skipped (no daemon binary), any other
	// error failed (the smoke printed why). nil: always skipped.
	Smoke func(ctx context.Context, rendered string) error
	// Chown gives a rendered tacquito.yaml to tacquito:tacquito (nil:
	// rtacacs.ChownTacquito, best effort).
	Chown rtacacs.Chowner

	// Seams for tests; nil is the real step.
	// ImportRender is store_render_hook (the import check's render).
	ImportRender func(s *store.Store) ([]byte, error)
	// RenderApply is tacacs_render_apply.
	RenderApply func(ctx context.Context, force bool) (bool, error)
}

// Smoker is a backend with a daemon load-smoke in the form Env.Smoke
// takes (the TACACS+ module).
type Smoker interface {
	SmokeHook(ctx context.Context, rendered string) error
}

// NewEnv is the Env over be: Smoke is the TACACS+ module's load-smoke when
// be.Set has a module that is a Smoker (be.Set is made over the default
// registry when be has none yet). rnd may be nil (crypto/rand).
func NewEnv(be *backend.Env, rnd io.Reader, isRoot bool) *Env {
	e := &Env{Env: be, Rand: rnd, IsRoot: isRoot}
	if be != nil && be.Set == nil {
		backend.NewSet(backend.Default(), be) // fills be.Set
	}
	if be != nil && be.Set != nil {
		if b, err := be.Set.Get(backend.TACACS); err == nil {
			if s, ok := b.(Smoker); ok {
				e.Smoke = s.SmokeHook
			}
		}
	}
	return e
}

func (e *Env) rand() io.Reader {
	if e.Rand != nil {
		return e.Rand
	}
	return rand.Reader
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) smoke(ctx context.Context, rendered string) error {
	if e.Smoke == nil {
		return store.ErrSmokeSkipped
	}
	return e.Smoke(ctx, rendered)
}

// renderer is the TACACS+ render steps over the Env (messages on Stderr).
func (e *Env) renderer() *rtacacs.Renderer {
	return &rtacacs.Renderer{
		Paths:  rtacacs.PathsFrom(e.Paths),
		Conf:   e.Conf,
		Load:   rtacacs.DefaultLoader,
		Chown:  e.Chown,
		Now:    e.Now,
		Stderr: e.Out.Stderr,
	}
}

func (e *Env) chownTacquito(path string) {
	if e.Chown != nil {
		e.Chown(path)
		return
	}
	rtacacs.ChownTacquito(path)
}

// importOptions are store_import's (with --check when check) over the
// Env: the TACACS+ render with the live tacctl.yaml, the equivalence
// check, the load-smoke.
func (e *Env) importOptions(ctx context.Context, check bool) store.ImportOptions {
	p := e.Paths
	var snap func() error
	if e.Snapshots != nil {
		snap = e.Snapshots.Hook
	}
	return store.ImportOptions{
		Check:       check,
		StorePath:   p.StoreFile,
		ConfigPath:  p.Config,
		DatesDir:    p.PWDatesDir,
		DisabledDir: filepath.Join(p.BackupDir, "disabled"),
		LegacyDir:   filepath.Join(p.BackupDir, "legacy"),
		Snapshot:    snap,
		Render:      e.importRender,
		Equiv:       model.EquivCheckRand(e.rand()),
		Smoke:       func(rendered string) error { return e.smoke(ctx, rendered) },
		Now:         e.Now,
	}
}

// importRender is store_render_hook: the imported store rendered as
// tacquito.yaml with the live tacctl.yaml's command rules, read back
// before it counts. A failure is printed here ('tacctl render: ...').
func (e *Env) importRender(s *store.Store) ([]byte, error) {
	if e.ImportRender != nil {
		return e.ImportRender(s)
	}
	fail := func(err error) ([]byte, error) {
		stderrLine(e.Out, rendered.Report(err))
		return nil, ui.ErrReported
	}
	if err := rtacacs.CheckOverrides(e.Conf.Path); err != nil {
		return fail(err)
	}
	dir, err := os.MkdirTemp("", "tacctl-render.")
	if err != nil {
		return fail(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	text, err := rtacacs.RenderToFile(s, e.Conf.Merged(), filepath.Join(dir, "tacquito.yaml"), rtacacs.DefaultLoader, nil)
	if err != nil {
		return fail(err)
	}
	return text, nil
}

// report prints err as 0.1.16's helpers did (nothing for ui.ErrReported).
func report(out ui.Output, err error) {
	var (
		pe *conf.ParseError
		ve *conf.ValidationError
		ee *store.ExistsError
	)
	switch {
	case err == nil, errors.Is(err, ui.ErrReported):
	case errors.As(err, &pe):
		out.ErrorLines(pe)
	case errors.As(err, &ve):
		stderrLine(out, ve.Error())
	case errors.As(err, &ee):
		out.ErrorE(ee.Error())
	case store.Reportable(err):
		stderrLine(out, store.Report(err))
	default:
		out.ErrorE(err.Error())
	}
}

// --- backup_config -------------------------------------------------------------

// BackupConfig is backup_config, the legacy-mode backup: tacquito.yaml
// copied to <backups>/tacquito.yaml.<YYYYmmdd_HHMMSS_mmm> (0640,
// tacquito's), then the newest snapshot.Retention of those files kept (by
// modification time, ties by name). A failure is printed (as mkdir or cp
// would) and returned as ui.ErrReported. With a store, snapshots are the
// backup; this is for an install without one.
func BackupConfig(p paths.Paths, out ui.Output, now time.Time) error {
	dir := p.BackupDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		stderrLine(out, "mkdir: "+err.Error())
		return ui.ErrReported
	}
	_ = os.Chmod(dir, 0o750)
	rtacacs.ChownTacquito(dir)
	dst := filepath.Join(dir, "tacquito.yaml."+rtacacs.DriftStamp(now))
	data, err := os.ReadFile(p.Config)
	if err == nil {
		err = os.WriteFile(dst, data, 0o640)
	}
	if err != nil {
		stderrLine(out, "cp: "+err.Error())
		return ui.ErrReported
	}
	_ = os.Chmod(dst, 0o640)
	rtacacs.ChownTacquito(dst)
	out.InfoE("Config backed up to " + dst)

	// Prune: every tacquito.yaml.* entry of backups/ counts, newest first
	// by modification time (ls -1t: ties by name), the oldest beyond the
	// retention go.
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type entry struct {
		name  string
		mtime int64
	}
	var all []entry
	for _, de := range des {
		if !strings.HasPrefix(de.Name(), "tacquito.yaml.") {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, de.Name()))
		if err != nil {
			continue
		}
		all = append(all, entry{de.Name(), fi.ModTime().UnixNano()})
	}
	if len(all) <= snapshot.Retention {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].mtime != all[j].mtime {
			return all[i].mtime > all[j].mtime
		}
		return all[i].name < all[j].name
	})
	for _, e := range all[snapshot.Retention:] {
		_ = os.Remove(filepath.Join(dir, e.name))
	}
	return nil
}

// --- the Python of the migrations ------------------------------------------------

// Python's \w, \s and \S for str patterns (Unicode).
const (
	pyW  = `[\p{L}\p{N}_]`
	pyS  = `[\t\n\v\f\r \x1c-\x1f\x85\p{Z}]`
	pyNS = `[^\t\n\v\f\r \x1c-\x1f\x85\p{Z}]`
)

var (
	// conf_migrate_command_rules: a group's block, its commands: section,
	// one rule, one quoted match.
	reGroupBlock = regexp.MustCompile(`(?m)^(` + pyW + `+): &(` + pyW + `+)\n(?:[ \t].*\n)+`)
	reCommands   = regexp.MustCompile(`(?m)^  commands:\n((?:    -.*\n(?:      .*\n)*)+)`)
	reRule       = regexp.MustCompile(`    - name:` + pyS + `*(?P<name>"[^"]*"|` + pyNS + `+)` + pyS + `*\n` +
		`(?:      match:` + pyS + `*\[(?P<match>.*)\]` + pyS + `*\n)?` +
		`      action:` + pyS + `*\*action_(?P<action>permit|deny)` + pyS + `*\n`)

	// conf_migrate_exec_service_name.
	reExecCount   = regexp.MustCompile(`(?m)^exec_` + pyW + `+: &exec_` + pyW + `+\n  name: exec$`)
	reExecReplace = regexp.MustCompile(`(?m)^(exec_` + pyW + `+: &exec_` + pyW + `+\n  name: )exec$`)

	// regenerate_tacquito_commands: a group whose anchor and name agree.
	reTacquitoGroup = regexp.MustCompile(`(?m)^(` + pyW + `+): &(` + pyW + `+)\n  name: (` + pyW + `+)\n`)
	reBlankRuns     = regexp.MustCompile(`\n{3,}`)
)

// readPy is open(path).read() in Python's text mode: universal newlines.
// A file that is not valid UTF-8 is an error (Python's would raise).
func readPy(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", errors.New(path + ": not valid UTF-8")
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n"), nil
}

// writePy is the migrations' write: a temporary file in the file's
// directory, 0640, renamed over it.
func writePy(path, text string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o640)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// mapGet is d.get(k) of a mapping (nil for anything else).
func mapGet(v any, k string) (any, bool) {
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil, false
	}
	return m.Get(k)
}

// --- conf_migrate_command_rules ------------------------------------------------

// MigrateCommandRules is conf_migrate_command_rules: on an install without
// a store, every group's commands: block of tacquito.yaml whose rules
// (match regexes that can never fire dropped) differ from the current
// commands.<group> view is written to tacctl.yaml as that group's
// override, and announced. Nothing happens with a store, without a
// readable tacquito.yaml, or when every block already matches. Idempotent.
// A write that fails is printed and returned.
func MigrateCommandRules(env *Env) error { return migrateCommandRules(env, false) }

// migrateCommandRules is MigrateCommandRules; with cont a write that fails
// is printed and the loop goes on, the group's line still announced (what
// 0.1.16 did with errexit off), and the first error is returned at the end.
func migrateCommandRules(env *Env, cont bool) error {
	p := env.Paths
	if isRegular(p.StoreFile) {
		return nil
	}
	cfg, err := readPy(p.Config)
	if err != nil {
		return nil
	}
	cur, _ := env.Conf.Merged().Get("commands")
	type change struct {
		group string
		rules []any
	}
	var todo []change
	for _, gm := range reGroupBlock.FindAllStringSubmatchIndex(cfg, -1) {
		group, anchor := cfg[gm[2]:gm[3]], cfg[gm[4]:gm[5]]
		if group != anchor {
			continue
		}
		block := cfg[gm[0]:gm[1]]
		cm := reCommands.FindStringSubmatch(block)
		if cm == nil {
			continue
		}
		var rules []any
		unreadable := ""
		for _, rm := range reRule.FindAllStringSubmatch(cm[1], -1) {
			name := strings.Trim(py.Strip(rm[1]), `"`)
			var matches []any
			if ms := py.Strip(rm[2]); ms != "" {
				// The flow list is read by the YAML loader: a regex written
				// with an escaped quote, a \uNNNN escape or a ']' in it is
				// what the renderer wrote, not what a scrape of quotes sees.
				list, ok := parseMatchList(ms)
				if !ok {
					unreadable = name
					break
				}
				for _, q := range list {
					m := rtacacs.UnwrapMatch(q)
					if names.CommandMatchIsDead(name, m) {
						continue
					}
					matches = append(matches, m)
				}
			}
			r := yamlpy.NewMap()
			r.Set("name", name)
			r.Set("action", rm[3])
			if len(matches) > 0 {
				r.Set("match", matches)
			}
			rules = append(rules, r)
		}
		if unreadable != "" {
			// A rule with no match permits (or denies) every argument: a
			// group whose list cannot be read is not migrated at all.
			env.Out.Warn("The match list of rule '" + unreadable + "' of group '" + group + "' in " + p.Config + " could not be read; its command rules were not migrated.")
			continue
		}
		if len(rules) == 0 {
			continue
		}
		if have, _ := mapGet(cur, group); have != nil && py.Equal(have, rules) {
			continue
		}
		// What an earlier tacctl shipped is not an override (0.2.3 changed
		// the shipped rules of operator and readonly).
		if policy.IsPreviousDefault(group, rules) {
			continue
		}
		todo = append(todo, change{group, rules})
	}
	var failed error
	for _, c := range todo {
		if err := env.Conf.SetValue("commands."+c.group, c.rules); err != nil {
			report(env.Out, err)
			if !cont {
				return ui.ErrReported
			}
			failed = ui.ErrReported
		}
		env.Out.InfoE("Migrated tacquito.yaml commands: block for group '" + c.group + "' → commands." + c.group)
	}
	return failed
}

// --- conf_migrate_dead_command_matches ------------------------------------------

// MigrateDeadCommandMatches is conf_migrate_dead_command_matches
// (policy.HealDeadMatches) with its messages: a commands.<group> override
// loses the match regexes that repeat the command word, and is dropped
// when what is left is the shipped default. A write that fails is printed
// and returned.
func MigrateDeadCommandMatches(env *Env) error {
	healed, err := policy.HealDeadMatches(env.Conf)
	for _, h := range healed {
		env.Out.InfoE(h.Message())
	}
	if err != nil {
		report(env.Out, err)
		return ui.ErrReported
	}
	return nil
}

// --- conf_migrate_exec_service_name ----------------------------------------------

// MigrateExecServiceName is conf_migrate_exec_service_name: on an install
// without a store, the Cisco exec services of tacquito.yaml that are still
// named 'exec' (devices ask for service=shell) are renamed 'shell' in
// place, after a BackupConfig of the file as it was. Junos services and
// group bodies are not touched. Silent when there is nothing to do. A
// failure is printed and returned.
func MigrateExecServiceName(env *Env) error { return migrateExecServiceName(env, false) }

// migrateExecServiceName is MigrateExecServiceName; with cont a backup
// that fails is printed and the rewrite still runs (what 0.1.16 did with
// errexit off), its error returned at the end.
func migrateExecServiceName(env *Env, cont bool) error {
	p := env.Paths
	if isRegular(p.StoreFile) {
		return nil
	}
	cfg, err := readPy(p.Config)
	if err != nil {
		return nil
	}
	n := len(reExecCount.FindAllStringIndex(cfg, -1))
	if n == 0 {
		return nil
	}
	backupErr := BackupConfig(p, env.Out, env.now())
	if backupErr != nil && !cont {
		return backupErr
	}
	if err := writePy(p.Config, reExecReplace.ReplaceAllString(cfg, "${1}shell")); err != nil {
		stderrLine(env.Out, err.Error())
		return ui.ErrReported
	}
	env.chownTacquito(p.Config)
	env.Out.InfoE("Migrated tacquito.yaml service name(s) exec → shell for " + strconv.Itoa(n) + " group(s)")
	return backupErr
}

// --- regenerate_tacquito_commands -----------------------------------------------

// RegenerateCommands is regenerate_tacquito_commands [<group>]: bring the
// per-group commands: blocks of tacquito.yaml in line with tacctl.yaml.
// With a store tacquito.yaml is an artifact: it is re-rendered
// (RenderApply), and a render that fails or is refused is reported with a
// warning, never an error. Without one (an install whose import has not
// happened) each group's commands: block is spliced in place: only group
// when given, else every group that has rules in tacctl.yaml or a block in
// the file. Idempotent; the file is written only when it changes.
func RegenerateCommands(ctx context.Context, env *Env, group string) error {
	p := env.Paths
	if isRegular(p.StoreFile) {
		if _, err := RenderApply(ctx, env, false); err != nil {
			env.Out.WarnE("tacquito.yaml was not re-rendered; run 'tacctl config render' once the problem above is fixed.")
		}
		return nil
	}
	if !isRegular(p.Config) {
		return nil
	}
	cfg, err := readPy(p.Config)
	if err != nil {
		stderrLine(env.Out, err.Error())
		return ui.ErrReported
	}
	cmdsV, _ := env.Conf.Merged().Get("commands")
	cmds, _ := cmdsV.(*yamlpy.Map)

	var groups []string
	if group != "" {
		groups = []string{group}
	} else {
		set := map[string]bool{}
		if cmds != nil {
			for _, k := range cmds.Keys() {
				set[k] = true
			}
		}
		for _, m := range reTacquitoGroup.FindAllStringSubmatch(cfg, -1) {
			if m[1] == m[2] && m[1] == m[3] {
				set[m[1]] = true
			}
		}
		for g := range set {
			groups = append(groups, g)
		}
		sort.Strings(groups)
	}

	out := cfg
	for _, g := range groups {
		var rules []any
		if cmds != nil {
			if v, ok := cmds.Get(g); ok && truthy(v) {
				rules, _ = py.List(v)
			}
		}
		out = spliceGroup(out, g, renderBlock(rules))
	}
	out = reBlankRuns.ReplaceAllString(out, "\n\n")
	if out == cfg {
		return nil
	}
	if err := writePy(p.Config, out); err != nil {
		stderrLine(env.Out, err.Error())
		return ui.ErrReported
	}
	env.chownTacquito(p.Config)
	return nil
}

// parseMatchList is the text between the brackets of a rendered 'match: [...]'
// flow list as its strings, read by the YAML loader (the double-quoted
// scalars rtacacs.YQ writes, escapes and all). false when it is not a list
// of strings.
func parseMatchList(inner string) ([]string, bool) {
	v, err := yamlpy.Decode([]byte("[" + inner + "]"))
	if err != nil {
		return nil, false
	}
	list, ok := py.List(v)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		str, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, str)
	}
	return out, true
}

// renderBlock is render_block: a tacquito-shaped '  commands:' block for
// a rule list ("" for none).
func renderBlock(rules []any) string {
	if len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("  commands:\n")
	for _, r := range rules {
		name, action := "", "permit"
		if v, ok := mapGet(r, "name"); ok {
			name = py.Str(v)
		}
		if v, ok := mapGet(r, "action"); ok {
			action = py.Str(v)
		}
		var match []any
		if v, ok := mapGet(r, "match"); ok && truthy(v) {
			match, _ = py.List(v)
		}
		b.WriteString(`    - name: "` + name + "\"\n")
		if len(match) > 0 {
			q := make([]string, len(match))
			for i, m := range match {
				q[i] = rtacacs.YQ(rtacacs.WrapMatch(py.Str(m)))
			}
			b.WriteString("      match: [" + strings.Join(q, ", ") + "]\n")
		}
		b.WriteString("      action: *action_" + action + "\n")
	}
	return b.String()
}

// spliceGroup is splice_group: replace (or insert, or delete) the
// commands: section of group, the block from '<group>: &<group>' to its
// '  accounter:' line. A group that is absent, or shaped otherwise, is left
// alone.
func spliceGroup(cfg, group, block string) string {
	hdr := regexp.QuoteMeta(group) + `: &` + regexp.QuoteMeta(group)
	re, err := regexp.Compile(`(?m)(^` + hdr + `\n(?:[ \t].*\n)*?)` +
		`(^  commands:\n(?:    -.*\n(?:      .*\n)*)+)?` +
		`(^  accounter:.*\n)`)
	if err != nil {
		return cfg
	}
	m := re.FindStringSubmatchIndex(cfg)
	if m == nil {
		return cfg
	}
	pre, accounter := cfg[m[2]:m[3]], cfg[m[6]:m[7]]
	return cfg[:m[0]] + pre + block + accounter + cfg[m[1]:]
}

// --- tacacs_render_apply ---------------------------------------------------------

// RenderApply is tacacs_render_apply [--force]: render the store into
// tacquito.yaml (only; the listeners' drop-ins are the contract's render)
// through a private staging directory and install it when it changed. It
// reports whether the live file was replaced. Without a store it fails
// ('store not initialised'); a file that is not what tacctl rendered is
// refused unless force (backend.ErrRefused), and every other failure is
// backend.ErrFailed. Messages go to Stderr.
func RenderApply(ctx context.Context, env *Env, force bool) (bool, error) {
	if env.RenderApply != nil {
		return env.RenderApply(ctx, force)
	}
	if !isRegular(env.Paths.StoreFile) {
		env.Out.ErrorE(store.NotInitialisedMsg)
		return false, backend.ErrFailed
	}
	tmp, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		stderrLine(env.Out, "mktemp: "+err.Error())
		return false, backend.ErrFailed
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	r := env.renderer()
	if err := r.Stage(tmp, force, false); err != nil {
		if errors.Is(err, rtacacs.ErrRefused) {
			return false, backend.ErrRefused
		}
		return false, backend.ErrFailed
	}
	changed, err := r.CommitConfig(tmp)
	if err != nil {
		return false, backend.ErrFailed
	}
	return changed, nil
}

// --- config_sync_existing --------------------------------------------------------

// SyncOptions are how ConfigSyncExisting treats a failed migration.
type SyncOptions struct {
	// ContinueOnError: print it and go on (install); false stops at the
	// first one (upgrade).
	ContinueOnError bool
}

// ConfigSyncExisting is config_sync_existing, the TACACS+ backend's
// 'upgrade config' phase (also run by an install over an existing
// tacquito.yaml): bring an existing install's config in line with this
// release. It returns whether the rendered tacquito.yaml changed
// (CONFIG_SYNC_RENDERED), which is one of the reasons 'upgrade finish'
// restarts tacquito.
//
// Without a store: the in-place migrations every upgrade has run, ahead of
// the store gate, which judges the file as they leave it
// (MigrateCommandRules, MigrateDeadCommandMatches, MigrateExecServiceName,
// RegenerateCommands); changed means tacquito.yaml's bytes differ from
// before the first of them.
//
// With a store: the migrations are no-ops and the config is re-rendered.
// A tacquito.yaml tacctl never rendered (an upgrade interrupted between
// writing the store and rendering, or a manual 'store import') is replaced
// only when what the store renders is proven equivalent to it and the
// daemon loads it; otherwise it is left for the operator with three
// warnings. A render that fails or is refused is a warning.
//
// The error is a migration's failure (printed). How the sync goes on
// after one is opts.ContinueOnError: upgrade (0.1.16 under 'set -e') stops
// at the first failure; install (0.1.16 with errexit off, since
// install_seed_config runs under '|| exit 1') prints it and runs the
// remaining migrations and the rest of the sync, and the first error is
// returned at the end with the 'changed' of the whole run.
func ConfigSyncExisting(ctx context.Context, env *Env, opts SyncOptions) (bool, error) {
	p := env.Paths
	before := ""
	if !isRegular(p.StoreFile) {
		before = fileSum(p.Config)
	}
	cont := opts.ContinueOnError
	var failed error
	step := func(err error) bool {
		if err == nil {
			return true
		}
		if failed == nil {
			failed = err
		}
		return cont
	}
	if !step(migrateCommandRules(env, cont)) ||
		!step(MigrateDeadCommandMatches(env)) ||
		!step(migrateExecServiceName(env, cont)) {
		return false, failed
	}
	if !isRegular(p.StoreFile) {
		if !step(RegenerateCommands(ctx, env, "")) {
			return false, failed
		}
		return fileSum(p.Config) != before, failed
	}

	force := false
	if word, err := rendered.Check(p.Rendered, p.Config); err == nil && word == rendered.Unrecorded {
		if !renderIsProven(ctx, env) {
			env.Out.WarnE(p.Config + " was not rendered by tacctl, and what the store renders is not proven equivalent to it; it was left as it is.")
			env.Out.WarnE("To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'.")
			env.Out.WarnE("To replace it with the store's content: 'tacctl config render --force'.")
			return false, failed
		}
		env.Out.InfoE(p.Config + " is equivalent to what the store renders; replacing it with the rendered file.")
		force = true
	}
	changed, err := RenderApply(ctx, env, force)
	if err != nil {
		env.Out.WarnE("tacquito.yaml was not re-rendered; run 'tacctl config render' once the problem above is fixed.")
		return false, failed
	}
	return changed, failed
}

// renderIsProven is _config_render_is_proven: what the store renders is
// equivalent to the live tacquito.yaml and the daemon loads it. As at the
// gate, a load-smoke that cannot run is not a pass.
func renderIsProven(ctx context.Context, env *Env) bool {
	tmp, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		return false
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	out := filepath.Join(tmp, "tacquito.yaml")
	if _, err := env.renderer().RenderLive(out, ""); err != nil {
		stderrLine(env.Out, rendered.Report(err))
		return false
	}
	eq, err := model.EquivCheckRand(env.rand())(env.Paths.Config, out, io.Discard)
	if err != nil || !eq {
		return false
	}
	return env.smoke(ctx, out) == nil
}

// fileSum is 'sha256sum <file>' ("" when it cannot be read).
func fileSum(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// tacquitoIDs are the uid and gid of the tacquito account.
func tacquitoIDs() (int, int, error) {
	u, err := user.Lookup("tacquito")
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup("tacquito")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// truthy is Python's bool() of a tacctl.yaml value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case *yamlpy.Map:
		return x.Len() > 0
	}
	if b := py.BigInt(v); b != nil {
		return b.Sign() != 0
	}
	if l, ok := py.List(v); ok {
		return len(l) > 0
	}
	return true
}
