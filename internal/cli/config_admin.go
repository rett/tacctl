package cli

// 'config sudoers [tiers]' (lib/dispatch.sh), 'config branch'
// (lib/lifecycle.sh cmd_config_branch) and 'config render --dry-run' (new,
// docs/plans/go-rewrite.md 3.9 item 8).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// cfgIsFile is bash's '[[ -f <path> ]]': a regular file, symlinks followed.
func cfgIsFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// cfgIsDir is '[[ -d <path> ]]'.
func cfgIsDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// cfgErrno is the strerror text of an os error, as coreutils print it.
func cfgErrno(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	s := err.Error()
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// --- sudoers ------------------------------------------------------------------

var reSudoersGroup = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

// configSudoers is cmd_config_sudoers: show (the default) / install [group]
// / remove of the NOPASSWD drop-in, or 'tiers ...'.
func (inv *invocation) configSudoers(args []string) error {
	a := inv.app
	sub := arg(args, 0)
	if sub == "tiers" {
		return inv.configSudoersTiers(args[1:])
	}
	// "${2:-adm}", and "%adm" is "adm".
	group := arg(args, 1)
	if group == "" {
		group = "adm"
	}
	group = strings.TrimPrefix(group, "%")
	file := a.Paths.SudoersFile

	switch sub {
	case "", "show":
		inv.echo("")
		if cfgIsFile(file) {
			inv.echo("  Status: installed at " + file)
			inv.echo("")
			inv.echo("  Contents:")
			if err := inv.indentFile(file); err != nil {
				return err
			}
		} else {
			inv.echo("  Status: not installed")
		}
		inv.write(`
  Usage: tacctl config sudoers <show|install|remove> [group]
  Examples:
    tacctl config sudoers install          # grant to group 'adm'
    tacctl config sudoers install wheel    # grant to group 'wheel'
    tacctl config sudoers remove
    tacctl config sudoers tiers [show|install|remove]   # RO/OP/SU rules for tacctl users with local accounts

`)
		return nil
	case "install":
	case "remove":
		return inv.removeFile(file)
	default:
		return inv.usageErr("Invalid subcommand: '" + sub + "'. Use: show, install, or remove")
	}

	if !reSudoersGroup.MatchString(group) {
		return inv.usageErr("Invalid group name: '" + group + "'")
	}
	// Confirm: this grants the group passwordless root via tacctl.
	inv.echo("")
	a.Out.WarnE("This grants members of group '%" + group + "' passwordless sudo on")
	a.Out.Warn("/usr/local/bin/tacctl, which can modify system config and restart")
	a.Out.Warn("services. Effectively passwordless root for that group.")
	inv.echo("")
	if !a.Prompter().ConfirmPrefix("  Install " + file + " for group '%" + group + "'? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	body := "# Managed by tacctl. Grants passwordless sudo on " + tier.Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		"%" + group + " ALL=(ALL) NOPASSWD: " + tier.Binary + "\n"
	if err := inv.installSudoers(body, file); err != nil {
		return err
	}
	a.Out.InfoE("Installed " + file + " for group '%" + group + "'.")
	inv.echo("")
	return nil
}

// configSudoersTiers is cmd_config_sudoers_tiers: show (the default) /
// install / remove of the per-tier rules (tier.Sudoers, emit_tier_sudoers).
func (inv *invocation) configSudoersTiers(args []string) error {
	a := inv.app
	file := a.Paths.TierSudoersFile
	sub := arg(args, 0)
	if sub == "" {
		sub = "show"
	}
	switch sub {
	case "show":
		inv.echo("")
		installed := cfgIsFile(file)
		if installed {
			inv.echo("  Status: installed at " + file)
		} else {
			inv.echo("  Status: not installed. 'tacctl config sudoers tiers install' would write:")
		}
		inv.echo("")
		if installed {
			if err := inv.indentFile(file); err != nil {
				return err
			}
		} else {
			inv.write(indentLines(tier.Sudoers()))
		}
		inv.echo("")
		return nil
	case "install":
		if err := inv.installSudoers(tier.Sudoers(), file); err != nil {
			return err
		}
		a.Out.Info("Installed " + file + ".")
		a.Out.Info("Tiers apply to members of " + tier.ReadonlyGroup + ", " + tier.OperatorGroup + " and " + tier.SuperuserGroup + ".")
		inv.echo("")
		return nil
	case "remove":
		return inv.removeFile(file)
	}
	return inv.usageErr("Invalid subcommand: '" + sub + "'. Use: tiers show, tiers install, or tiers remove")
}

// removeFile is the 'remove' of both drop-ins.
func (inv *invocation) removeFile(file string) error {
	a := inv.app
	if !cfgIsFile(file) {
		a.Out.Info("Not installed. Nothing to remove.")
		return nil
	}
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		inv.stderrLine("rm: cannot remove '" + file + "': " + cfgErrno(err))
		return exit(1)
	}
	a.Out.Info("Removed " + file + ".")
	return nil
}

// installSudoers writes body to a temp file, has 'visudo -cf' check it and
// installs it as dst with 'install -m 0440 -o root -g root' (both external,
// as in 0.1.16: the suite stubs them). A failed check is reported and
// exit 1; a failed install exits with its status (bash's errexit), after
// its own message.
func (inv *invocation) installSudoers(body, dst string) error {
	a := inv.app
	f, err := os.CreateTemp("", "tmp.")
	if err != nil {
		inv.stderrLine("mktemp: failed to create file via template '" + filepath.Join(os.TempDir(), "tmp.XXXXXXXXXX") + "': " + cfgErrno(err))
		return exit(1)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.WriteString(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	res, _ := a.Runner.Run(inv.ctx, execx.Cmd{Name: "visudo", Args: []string{"-cf", tmp}, Stderr: a.Out.Stderr})
	if res.Code != 0 {
		a.Out.Error("visudo validation failed. Not installed.")
		return exit(1)
	}
	res, _ = a.Runner.Run(inv.ctx, execx.Cmd{Name: "install", Args: []string{"-m", "0440", "-o", "root", "-g", "root", tmp, dst},
		Stdout: a.Out.Stdout, Stderr: a.Out.Stderr})
	if res.Code != 0 {
		return exit(res.Code)
	}
	return nil
}

// indentLines is "sed 's/^/    /'" of text.
func indentLines(text string) string {
	if text == "" {
		return ""
	}
	var b strings.Builder
	for _, l := range strings.SplitAfter(text, "\n") {
		if l != "" {
			b.WriteString("    " + l)
		}
	}
	return b.String()
}

// indentFile is "sed 's/^/    /' <file>"; a file that cannot be read is
// sed's complaint and its exit status 2 (errexit).
func (inv *invocation) indentFile(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		inv.stderrLine("sed: can't read " + file + ": " + cfgErrno(err))
		return exit(2)
	}
	inv.write(indentLines(string(data)))
	return nil
}

// --- branch -------------------------------------------------------------------

// configBranch is cmd_config_branch on the deploy clone: DEPLOY_DIR
// (/opt/tacctl) as in 0.1.16, or the tree TACCTL_TREE names (the tests'
// scratch clone). Unlike paths.Tree it does not fall back to the checkout a
// dev binary was built in: switching discards local edits, and 0.1.16 never
// touched any clone but the deploy one. With no name it shows the current
// branch and the remote ones; with a name it switches the clone to it
// (fetch, discard local edits, checkout, pull, read access for all).
func (inv *invocation) configBranch(args []string) error {
	a := inv.app
	dir := paths.DeployDir
	if t := a.Env.Get("TACCTL_TREE"); t != "" {
		dir = t
	}
	want := arg(args, 0)
	if !cfgIsDir(filepath.Join(dir, ".git")) {
		a.Out.ErrorE("Deploy directory not found at " + dir + ".")
		return exit(1)
	}
	// git -C <dir> ...: stdout is captured or passed on (pass), stderr
	// dropped (2>/dev/null) unless noted.
	git := func(pass bool, args ...string) execx.Result {
		c := execx.Cmd{Name: "git", Args: append([]string{"-C", dir}, args...)}
		if pass {
			c.Stdout = a.Out.Stdout
		}
		res, _ := a.Runner.Run(inv.ctx, c)
		return res
	}
	current := strings.TrimRight(string(git(false, "branch", "--show-current").Stdout), "\n")

	if want == "" {
		inv.echo("")
		inv.echoE("  " + ui.Bold + "Current branch:" + ui.NC + " " + current)
		inv.echo("")
		inv.echo("  Available remote branches:")
		git(true, "fetch", "--quiet")
		// branch -r | grep -v HEAD | sed 's|origin/||' | while IFS= read -r b
		out := string(git(false, "branch", "-r").Stdout)
		// grep ends every line it prints with a newline, so a last line
		// without one is read too.
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if out == "" {
			lines = nil
		}
		for _, l := range lines {
			if strings.Contains(l, "HEAD") {
				continue
			}
			b, err := shellquote.XargsEcho(strings.Replace(l, "origin/", "", 1))
			if err != nil {
				inv.stderrLine("xargs: " + err.Error())
				return exit(1)
			}
			if b == current {
				inv.echoE("    " + ui.Green + "* " + b + ui.NC)
			} else {
				inv.echo("      " + b)
			}
		}
		inv.echo("")
		return nil
	}

	if want == current {
		a.Out.InfoE("Already on branch '" + want + "'.")
		return nil
	}
	git(true, "fetch", "--quiet")
	if git(false, "rev-parse", "--verify", "origin/"+want).Code != 0 {
		a.Out.ErrorE("Branch '" + want + "' does not exist on remote.")
		return exit(1)
	}
	git(true, "checkout", "--", ".")
	if git(false, "checkout", want).Code != 0 {
		// 'checkout <b> &>/dev/null || checkout -b <b> origin/<b> &>/dev/null'
		// under errexit: when both fail the command ends there, silently.
		if res := git(false, "checkout", "-b", want, "origin/"+want); res.Code != 0 {
			return exit(res.Code)
		}
	}
	git(true, "pull", "--quiet")
	cfgReadableTree(dir)
	script := filepath.Join(dir, "bin", "tacctl.sh")
	if err := os.Chmod(script, 0o755); err != nil {
		inv.stderrLine("chmod: cannot access '" + script + "': " + cfgErrno(err))
		return exit(1)
	}
	a.Out.InfoE("Switched to branch '" + want + "'.")
	a.Out.Info("Run 'tacctl upgrade' to apply any changes.")
	inv.echo("")
	return nil
}

// cfgReadableTree is normalize_deploy_perms, 'chmod -R a+rX <dir>': read
// for everyone on every file and directory, and search (x) for everyone on
// directories and on files that are executable for someone. Symbolic links
// are not followed; errors are ignored.
func cfgReadableTree(dir string) {
	if !cfgIsDir(dir) {
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return nil // chmod -R goes on past what it cannot read
		}
		info, err := d.Info()
		if err != nil {
			return nil // as above
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

// --- render --dry-run -----------------------------------------------------------

// configRenderDryRun is 'config render --dry-run --out <dir> [--force]':
// every enabled backend renders the store into a private staging
// directory, exactly as 'config render' stages it (the daemon's own config
// check included), and the artifacts are copied under <dir> at their live
// paths (<dir>/etc/tacquito/tacquito.yaml, ...). Nothing live is written:
// no artifact, no render record, no copy of a hand-edited file, no
// restart. <dir> must be new or empty, so nothing in it can lead back to
// a live path; it and everything in it are private to root (0700/0600),
// since the artifacts hold secrets and hashes. A hand-edited artifact
// does not stop a dry run (--force is accepted and changes nothing).
func (inv *invocation) configRenderDryRun(args []string) error {
	a := inv.app
	const usage = "Usage: tacctl config render --dry-run --out <dir>"
	p, err := Parse(Spec{MaxArgs: 0, Flags: []Flag{
		{Names: []string{"--dry-run"}}, {Names: []string{"--force"}}, {Names: []string{"--out"}, Value: true},
	}}, args)
	if err != nil || p.Value("--out") == "" {
		return inv.usageErr(usage)
	}
	out, err := filepath.Abs(p.Value("--out"))
	if err != nil {
		return err
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return inv.usageErr("'" + out + "' is not empty: a dry run writes into a new or empty directory.")
	} else if err != nil && !os.IsNotExist(err) {
		return inv.usageErr("Cannot use '" + out + "': " + cfgErrno(err))
	}

	set := a.Backends()
	if !cfgIsFile(a.Paths.StoreFile) {
		a.Out.Error(store.NotInitialisedMsg)
		return exit(1)
	}
	enabled, err := set.Enabled()
	if err != nil {
		a.Out.ErrorE(err.Error())
		return exit(1)
	}
	tmpd, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		a.Out.Error("Cannot create a staging directory: " + err.Error())
		return exit(1)
	}
	defer func() { _ = os.RemoveAll(tmpd) }()
	type staged struct {
		id    string
		files [][2]string // {staged file, live path}
	}
	var all []staged
	for _, id := range enabled {
		dir := filepath.Join(tmpd, id)
		if err := os.Mkdir(dir, 0o700); err != nil {
			a.Out.Error("Cannot create a staging directory: " + err.Error())
			return exit(1)
		}
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		if err := b.RenderStage(inv.ctx, dir, true); err != nil {
			return backend.ErrFailed
		}
		files, err := stagedArtifacts(id, dir, b.Artifacts())
		if err != nil {
			return err
		}
		all = append(all, staged{id, files})
	}
	if inv.ctx.Err() != nil {
		return backend.ErrFailed
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return inv.usageErr("Cannot create '" + out + "': " + cfgErrno(err))
	}
	for _, s := range all {
		var written []string
		for _, f := range s.files {
			dst := filepath.Join(out, f[1])
			if err := cfgCopyPrivate(f[0], dst); err != nil {
				a.Out.Error("Cannot write " + dst + ": " + cfgErrno(err))
				return exit(1)
			}
			written = append(written, dst)
		}
		a.Out.Info(s.id + ": " + strings.Join(written, ", "))
	}
	a.Out.Info("Dry run: rendered into " + out + "; no live file, render record or service was touched.")
	return nil
}

// stagedArtifacts pairs the files a backend's RenderStage left in dir with
// the live paths they would be installed at (what its RenderCommit
// installs): TACACS+ stages tacquito.yaml and units/<listener>.conf (the
// units index says where each goes); RADIUS stages conf, users and
// dictionary (its artifacts, in that order). A backend this does not know
// has every regular file of its staging directory copied under its id.
func stagedArtifacts(id, dir string, artifacts []string) ([][2]string, error) {
	var out [][2]string
	switch id {
	case backend.TACACS:
		if len(artifacts) > 0 {
			out = append(out, [2]string{filepath.Join(dir, rtacacs.StagedConfig), artifacts[0]})
		}
		udir := filepath.Join(dir, rtacacs.UnitsDir)
		index, err := rtacacs.ReadIndex(udir)
		if err != nil {
			return nil, err
		}
		for _, u := range index {
			out = append(out, [2]string{filepath.Join(udir, u.Listener+".conf"), u.Live})
		}
		return out, nil
	case backend.RADIUS:
		for i, name := range []string{"conf", "users", "dictionary"} {
			if i < len(artifacts) {
				out = append(out, [2]string{filepath.Join(dir, name), artifacts[i]})
			}
		}
		return out, nil
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, [2]string{p, filepath.Join("/", id, rel)})
		}
		return nil
	})
	return out, err
}

// cfgCopyPrivate copies src to dst (0600), creating dst's directories
// (0700).
func cfgCopyPrivate(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}
