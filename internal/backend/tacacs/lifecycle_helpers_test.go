package tacacs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// The test kit of the lifecycle phases: the bats stubs of
// tests/integration/{units_convert,upgrade_restart}.bats as fake-runner
// rules.

// repoRoot is the checkout these tests run in (TACCTL_SRC): the tree the
// shipped unit files come from.
func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// newLifeTenv is newTenv with the directories the lifecycle phases reach
// outside the state tree: the tacquito checkout (TACQUITO_SRC), the patch
// directory (empty: no patches), logrotate, the Go toolchain (GO_BIN, an
// executable file) and the uninstall archive directory.
// ltenv is a tenv with the lifecycle's directories (dir).
type ltenv struct {
	*tenv
	dir string
}

func newLifeTenv(t *testing.T, extraEnv ...string) *ltenv {
	t.Helper()
	w := t.TempDir()
	for _, d := range []string{"tacquito-src/cmds/server/config/authenticators/bcrypt/generator", "patches", "logrotate", "root", "gobin"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := newTenv(t, append([]string{
		"TACQUITO_SRC=" + filepath.Join(w, "tacquito-src"),
		"TACCTL_PATCH_DIR=" + filepath.Join(w, "patches"),
		"TACCTL_LOGROTATE_DIR=" + filepath.Join(w, "logrotate"),
	}, extraEnv...)...)
	goBin := filepath.Join(w, "gobin", "go")
	writeFile(t, goBin, "#!/bin/sh\n")
	if err := os.Chmod(goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	le := &ltenv{tenv: e, dir: w}
	le.freshLife()
	return le
}

// freshLife is a new process: the lifecycle state of the last run is gone,
// the seams stay.
func (e *ltenv) freshLife() {
	e.b.life = lifeState{
		goBin:      filepath.Join(e.dir, "gobin", "go"),
		archiveDir: filepath.Join(e.dir, "root"),
		root:       func() bool { return false },
	}
}

func (e *tenv) src() string { return e.p.TacquitoSrc }

// out is everything written, stdout then stderr (bats 'run' merges them;
// the order across the two does not matter to these tests).
func (e *tenv) out() string { return e.stdout.String() + e.stderr.String() }

// --- systemd ---------------------------------------------------------------

// fakeSystemd is the systemctl stub of upgrade_restart.bats: it keeps
// which units are active and enabled. failStart: the next start or
// restart of the unit does not stay up (exit 0, inactive). failRestart:
// the next N starts fail with exit status 1.
type fakeSystemd struct {
	mu          sync.Mutex
	active      map[string]bool
	enabled     map[string]bool
	failStart   map[string]bool
	failRestart map[string]int
	needReload  bool
}

func (e *tenv) systemd() *fakeSystemd {
	s := &fakeSystemd{active: map[string]bool{}, enabled: map[string]bool{}, failStart: map[string]bool{}, failRestart: map[string]int{}}
	e.run.Func(func(c execx.Cmd) bool { return c.Name == "systemctl" }, s.answer)
	return s
}

func (s *fakeSystemd) answer(c execx.Cmd) (execx.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(c.Args) == 0 {
		return execx.Result{}, nil
	}
	verb := c.Args[0]
	now := false
	var units []string
	for _, a := range c.Args[1:] {
		switch {
		case a == "--now":
			now = true
		case strings.HasPrefix(a, "-"):
		default:
			units = append(units, strings.TrimSuffix(a, ".service"))
		}
	}
	u := ""
	if len(units) > 0 {
		u = units[0]
	}
	out := func(text string, code int) (execx.Result, error) {
		return execx.Result{Stdout: []byte(text), Code: code}, nil
	}
	switch verb {
	case "is-active":
		if s.active[u] {
			return out("active\n", 0)
		}
		return out("inactive\n", 3)
	case "is-enabled":
		if s.enabled[u] {
			return out("enabled\n", 0)
		}
		return out("disabled\n", 1)
	case "start", "restart":
		if s.failStart[u] {
			delete(s.failStart, u)
			delete(s.active, u)
			return out("", 0)
		}
		if s.failRestart[u] > 0 {
			s.failRestart[u]--
			delete(s.active, u)
			return out("", 1)
		}
		s.active[u] = true
	case "stop":
		delete(s.active, u)
	case "enable":
		s.enabled[u] = true
		if now {
			s.active[u] = true
		}
	case "disable":
		delete(s.enabled, u)
		if now {
			delete(s.active, u)
		}
	case "show":
		switch {
		case strings.Contains(strings.Join(c.Args, " "), "NeedDaemonReload"):
			if s.needReload {
				return out("NeedDaemonReload=yes\n", 0)
			}
			return out("NeedDaemonReload=no\n", 0)
		case strings.Contains(strings.Join(c.Args, " "), "MainPID"):
			if s.active[u] {
				return out("MainPID=4242\n", 0)
			}
			return out("MainPID=0\n", 0)
		}
		return out("ActiveEnterTimestamp=Fri 2026-10-02 10:00:00 UTC\n", 0)
	}
	return out("", 0)
}

// serviceCalls is service_calls: every systemctl call that starts, stops,
// restarts or reloads a unit.
func (e *tenv) serviceCalls() []string {
	rx := regexp.MustCompile(`^systemctl (restart|start|stop|reload|try-restart|reload-or-restart|condrestart|kill)( |$)|^systemctl .*--now`)
	var out []string
	for _, a := range e.run.Argvs() {
		if rx.MatchString(a) {
			out = append(out, a)
		}
	}
	return out
}

// --- the tacquito checkout and go --------------------------------------------

// fakeTacquito is the git and go stubs of upgrade_restart.bats: the
// checkout's HEAD is local, its upstream remote; a build writes "built at
// <local>" as the binary.
type fakeTacquito struct {
	mu            sync.Mutex
	local, remote string
}

func (e *tenv) tacquitoRepo(commit string) *fakeTacquito {
	f := &fakeTacquito{local: commit, remote: commit}
	src := e.src()
	inSrc := func(c execx.Cmd) bool {
		if c.Name != "git" {
			return false
		}
		if len(c.Args) > 1 && c.Args[0] == "-C" {
			return strings.HasPrefix(c.Args[1]+"/", src+"/")
		}
		return strings.HasPrefix(c.Dir+"/", src+"/")
	}
	e.run.Func(inSrc, func(c execx.Cmd) (execx.Result, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		res := func(s string) (execx.Result, error) { return execx.Result{Stdout: []byte(s)}, nil }
		switch a := strings.Join(c.Args, " "); {
		case a == "rev-parse --short HEAD":
			return res(f.local[:7] + "\n")
		case a == "rev-parse HEAD":
			return res(f.local + "\n")
		case a == "rev-parse @{u}":
			return res(f.remote + "\n")
		case a == "pull --quiet":
			f.local = f.remote
		case strings.HasPrefix(a, "log --oneline "):
			return res(f.remote[:7] + " upstream change\n")
		}
		return res("")
	})
	e.run.Func(func(c execx.Cmd) bool { return c.Name == "go" && len(c.Args) > 2 && c.Args[0] == "build" },
		func(c execx.Cmd) (execx.Result, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if err := os.WriteFile(c.Args[2], []byte("built at "+f.local+"\n"), 0o755); err != nil {
				return execx.Result{Code: 1}, nil
			}
			return execx.Result{}, os.Chmod(c.Args[2], 0o755)
		})
	return f
}

func (f *fakeTacquito) setRemote(commit string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote = commit
}

const (
	commit1 = "1111111111111111111111111111111111111111"
	commit2 = "2222222222222222222222222222222222222222"
)

// --- trees -------------------------------------------------------------------

// copyTree copies a directory recursively (cp -r).
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// deployTree is the management repo of upgrade_restart.bats: this
// checkout's shipped files (the TACACS+ ones and README.md).
func (e *ltenv) deployTree() string {
	e.t.Helper()
	root := repoRoot(e.t)
	d := filepath.Join(e.dir, "deploy")
	copyTree(e.t, filepath.Join(root, Share), filepath.Join(d, Share))
	data, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		e.t.Fatal(err)
	}
	writeFile(e.t, filepath.Join(d, "README.md"), string(data))
	return d
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// listing is 'ls -la --time-style=full-iso' of directories: name, mode,
// size and modification time of every entry.
func listing(t *testing.T, dirs ...string) string {
	t.Helper()
	var b strings.Builder
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			b.WriteString(d + " absent\n")
			continue
		}
		for _, en := range entries {
			info, err := en.Info()
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(d + "/" + en.Name() + " " + info.Mode().String() + " " + strconv.FormatInt(info.Size(), 10) + " " +
				info.ModTime().String() + "\n")
		}
	}
	return b.String()
}

// findAll is 'find <dir> -mindepth 1', sorted.
func findAll(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// upgrade runs the TACACS+ phases of one 'tacctl upgrade' in the order
// cmd_upgrade runs them, stopping at the first error.
func (e *tenv) upgrade(tree string) error {
	ctx := context.Background()
	for _, ph := range backend.UpgradePhases {
		t := ""
		if ph == backend.PhaseFiles {
			t = tree
		}
		if err := e.b.Upgrade(ctx, ph, t); err != nil {
			return err
		}
	}
	return nil
}
