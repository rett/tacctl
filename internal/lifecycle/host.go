package lifecycle

// What install, upgrade and uninstall share: the Host they run on, the
// backend phases, programs, and the file steps 0.1.16 runs under 'set -e'.

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// The environment variables of the self-update re-exec.
const (
	// ReexecEnv is set (=1) in the environment of an upgrade that a
	// self-update re-executed: it does not build and re-execute again,
	// whatever the remote did meanwhile (the loop guard).
	ReexecEnv = "TACCTL_UPGRADE_REEXEC"
	// UpgradeFromEnv carries the tacquito commit an upgrade started from
	// across its re-exec (TACCTL_UPGRADE_TACQUITO_FROM, 0.1.16's name, so a
	// bash release handed over to reads it too). The TACACS+ module sets
	// and reads it (Handover).
	UpgradeFromEnv = "TACCTL_UPGRADE_TACQUITO_FROM"
)

// Host is one run of install, upgrade or uninstall: the invocation's
// environment (paths, tacctl.yaml, the runner, the output, the prompter,
// the backend set) and what the commands need from the process. Every
// phase of the command runs on the backends of Env.Set (Set.Get makes each
// once), so what one phase leaves for a later one, and for the summary, is
// there.
type Host struct {
	*Env
	// Environ is the process environment: handed to a re-exec, and read
	// for UpgradeFromEnv and ReexecEnv.
	Environ paths.Env
	// Commit is the commit the running binary was built from ("" or
	// "unknown": not known, so never current).
	Commit string
}

// Handover is a backend that carries something across the self-update
// re-exec of 'tacctl upgrade' in the environment (the TACACS+ module: the
// tacquito commit the first run started from, UpgradeFromEnv).
type Handover interface {
	// SetUpgradeFrom gives the backend UpgradeFromEnv's value as this
	// process got it ("" when unset), before the build phase.
	SetUpgradeFrom(commit string)
	// UpgradeHandover is what the re-executed process must find in its
	// environment (KEY=VALUE).
	UpgradeHandover() []string
}

// enabled is _backends_load: the enabled backends, or the error printed
// and ErrFailed.
func (h *Host) enabled() ([]string, error) {
	ids, err := h.Set.Enabled()
	if err != nil {
		h.Out.Error(err.Error())
		return nil, backend.ErrFailed
	}
	return ids, nil
}

// backendNames is upgrade_backend_names: "tacacs (tacquito), radius
// (freeradius)".
func (h *Host) backendNames(ids []string) string {
	var parts []string
	for _, id := range ids {
		s := id
		if b, err := h.Set.Get(id); err == nil {
			if impl := b.Describe().Impl; impl != "" {
				s += " (" + impl + ")"
			}
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// phase is backends_run <verb> <phase> [tree]: the phase on every backend
// of ids, in order. The first that fails ends the command with its error
// (its messages written), as a failing phase ends 0.1.16's command under
// errexit.
func (h *Host) phase(ids []string, run func(backend.Backend) error) error {
	for _, id := range ids {
		b, err := h.Set.Get(id)
		if err != nil {
			return err
		}
		if err := run(b); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) install(ctx context.Context, ids []string, p backend.Phase, tree string) error {
	return h.phase(ids, func(b backend.Backend) error { return b.Install(ctx, p, tree) })
}

func (h *Host) upgrade(ctx context.Context, ids []string, p backend.Phase, tree string) error {
	return h.phase(ids, func(b backend.Backend) error { return b.Upgrade(ctx, p, tree) })
}

// --- programs --------------------------------------------------------------

// cmd runs a program. stdout and stderr nil: discarded (captured into the
// Result's Stdout when keep is set). The status is 127 when it could not
// be started.
func (h *Host) cmd(ctx context.Context, c execx.Cmd) execx.Result {
	res, err := h.Runner.Run(ctx, c)
	if err != nil && res.Code == 0 {
		res.Code = 127
	}
	return res
}

// git runs git in dir as 'cd <dir>; git <args>' with stdout and stderr
// passed through.
func (h *Host) git(ctx context.Context, dir string, args ...string) int {
	return h.cmd(ctx, execx.Cmd{Name: "git", Args: args, Dir: dir, Stdout: h.Out.Stdout, Stderr: h.Out.Stderr}).Code
}

// gitQuiet is 'git <args> &>/dev/null'.
func (h *Host) gitQuiet(ctx context.Context, dir string, args ...string) int {
	return h.cmd(ctx, execx.Cmd{Name: "git", Args: args, Dir: dir, Stdout: io.Discard, Stderr: io.Discard}).Code
}

// gitQuietErr is 'git <args> 2>/dev/null'.
func (h *Host) gitQuietErr(ctx context.Context, dir string, args ...string) int {
	return h.cmd(ctx, execx.Cmd{Name: "git", Args: args, Dir: dir, Stdout: h.Out.Stdout, Stderr: io.Discard}).Code
}

// gitOut is '$(git <args> 2>/dev/null)': stdout without its trailing
// newlines.
func (h *Host) gitOut(ctx context.Context, dir string, args ...string) (string, int) {
	res := h.cmd(ctx, execx.Cmd{Name: "git", Args: args, Dir: dir, Stderr: io.Discard})
	return strings.TrimRight(string(res.Stdout), "\n"), res.Code
}

// has is 'command -v <name>'.
func (h *Host) has(name string) bool {
	_, err := h.Runner.LookPath(name)
	return err == nil
}

// ensureSafeDirectory is ensure_safe_directory: a system-wide git
// safe.directory entry for each path (in /etc/gitconfig), added once, so
// that an unprivileged operator can read the root-owned clone.
func (h *Host) ensureSafeDirectory(ctx context.Context, dirs ...string) {
	existing, code := h.gitOut(ctx, "", "config", "--system", "--get-all", "safe.directory")
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
			h.cmd(ctx, execx.Cmd{Name: "git", Args: []string{"config", "--system", "--add", "safe.directory", d},
				Stdout: h.Out.Stdout, Stderr: io.Discard})
		}
	}
}

// --- files -----------------------------------------------------------------

// NormalizeDeployPerms is normalize_deploy_perms, 'chmod -R a+rX <dir>':
// read for everyone on every file and directory, and search (x) on
// directories and on files that are executable for someone. tacctl runs
// with umask 077, so git leaves the clone's files 0600; this lets
// non-root users read README.md and the templates. Symbolic links are not
// followed; errors are ignored; no directory, nothing.
func NormalizeDeployPerms(dir string) {
	if !isDir(dir) {
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return nil // chmod -R goes on past what it cannot read
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode().Perm() | 0o444
		if d.IsDir() || info.Mode().Perm()&0o111 != 0 {
			mode |= 0o111
		}
		if mode != info.Mode().Perm() {
			_ = os.Chmod(p, mode|(info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)))
		}
		return nil
	})
}

// errno is the strerror text of a file error, as coreutils print it.
func errno(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	s := err.Error()
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// failed is a step 0.1.16 runs under 'set -e' that failed: msg (the
// program's own complaint, "" for none) on stderr, exit status 1.
func (h *Host) failed(msg string) error {
	if msg != "" {
		stderrLine(h.Out, msg)
	}
	return backend.ErrFailed
}

// chmod is 'chmod <mode> <path>' under 'set -e'.
func (h *Host) chmod(path string, mode fs.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return h.failed("chmod: cannot access '" + path + "': " + errno(err))
	}
	return nil
}

// cp is 'cp <src> <dst>' under 'set -e': an existing dst keeps its mode, a
// new one gets src's less the umask.
func (h *Host) cp(src, dst string) error {
	if err := copyFile(src, dst); err != nil {
		return h.failed("cp: cannot create regular file '" + dst + "': " + errno(err))
	}
	return nil
}

// copyFile is cp's copy: the bytes of src into dst (created with src's
// mode, under the umask, when it is new).
func copyFile(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeKeepMode(dst, data, st.Mode().Perm())
}

// writeKeepMode writes data to path as a redirection or cp does: an
// existing file keeps its mode, a new one is created with mode (less the
// umask).
func writeKeepMode(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// rmF is 'rm -f <path>...' under 'set -e'.
func (h *Host) rmF(paths ...string) error {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			if st, serr := os.Lstat(p); serr == nil && st.IsDir() {
				return h.failed("rm: cannot remove '" + p + "': Is a directory")
			}
			return h.failed("rm: cannot remove '" + p + "': " + errno(err))
		}
	}
	return nil
}

// rmRF is 'rm -rf <path>...' under 'set -e'.
func (h *Host) rmRF(paths ...string) error {
	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			return h.failed("rm: cannot remove '" + p + "': " + errno(err))
		}
	}
	return nil
}

// echo is 'echo "<s>"'; echoE is 'echo -e "<s>"'.
func (h *Host) echo(s string)  { _, _ = io.WriteString(h.Out.Stdout, s+"\n") }
func (h *Host) echoE(s string) { _, _ = io.WriteString(h.Out.Stdout, ui.Echo(s)) }

// rule is the banner rule of install, upgrade and uninstall.
const rule = "============================================"

// confirm is 'read -rp "<prompt>" a || true; [[ $a == y || $a == Y ]]'.
func (h *Host) confirm(prompt string) bool { return h.Prompt().Confirm(prompt) }

// withEnv is environ with each KEY=VALUE of add set (replacing an earlier
// value of the same key) and each key of drop removed.
func withEnv(environ []string, add []string, drop ...string) []string {
	keys := map[string]bool{}
	for _, kv := range add {
		k, _, _ := strings.Cut(kv, "=")
		keys[k] = true
	}
	for _, k := range drop {
		keys[k] = true
	}
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if !keys[k] {
			out = append(out, kv)
		}
	}
	return append(out, add...)
}
