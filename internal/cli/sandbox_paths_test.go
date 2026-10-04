package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend/radius"
	"github.com/rett/tacctl/internal/paths"
)

// sandboxPathEnv is every TACCTL_* path variable pointed under dir, for the
// tests that run lifecycle phases or 'backend enable|disable': none of the
// paths they can write may stay at its host default (hostDefaults).
func sandboxPathEnv(dir string) []string {
	j := func(p ...string) string { return filepath.Join(append([]string{dir}, p...)...) }
	return []string{
		"TACCTL_ETC=" + j("etc"), "TACCTL_STATE_DIR=" + j("state"), "TACCTL_LOG=" + j("log"), "TACCTL_BIN=" + j("bin"),
		"TACCTL_CONFIG=" + j("etc", "tacquito.yaml"),
		"TACCTL_SUDOERS_FILE=" + j("sudoers.d", "tacctl"), "TACCTL_TIER_SUDOERS_FILE=" + j("sudoers.d", "tacctl-tiers"),
		"TACCTL_SYSTEMD_DIR=" + j("systemd"), "TACCTL_OVERRIDE_DIR=" + j("systemd", "tacquito.service.d"),
		"TACCTL_LOGROTATE_DIR=" + j("logrotate.d"), "TACQUITO_SRC=" + j("tacquito-src"), "TACCTL_LINUX_DIR=" + j("linux"),
		"TACCTL_TREE=" + j("tree"),
		"TACCTL_RADIUS_DIR=" + j("raddb"), "TACCTL_RADIUS_LOG=" + j("radius-log"),
		"TACCTL_RADIUS_BIN=" + j("radius-bin", "radiusd"), "TACCTL_RADIUS_DICT=" + j("radius-share", "dictionary"),
	}
}

// sandboxArchive points 'uninstall data --keep-logs' (/root) under dir for
// the test.
func sandboxArchive(t *testing.T, dir string) {
	old := radius.LogArchiveDir
	radius.LogArchiveDir = filepath.Join(dir, "root")
	t.Cleanup(func() { radius.LogArchiveDir = old })
}

// hostDefaults names every path a lifecycle phase, a render or 'backend
// enable|disable' can write (or remove) that does not resolve under root,
// for both RADIUS layouts. PIDFile and LibDir are only written into the
// rendered config, never touched.
func hostDefaults(p paths.Paths, root string) []string {
	root = filepath.Clean(root) + string(filepath.Separator)
	check := map[string]string{
		"Etc": p.Etc, "StateDir": p.StateDir, "Log": p.Log, "Bin": p.Bin, "Config": p.Config,
		"BackupDir": p.BackupDir, "Overrides": p.Overrides, "StoreFile": p.StoreFile, "Rendered": p.Rendered,
		"LinuxUIDs": p.LinuxUIDs, "LinuxHosts": p.LinuxHosts, "Templates": p.Templates,
		"SudoersFile": p.SudoersFile, "TierSudoersFile": p.TierSudoersFile,
		"OverrideDir": p.OverrideDir, "TacacsUnitDir": p.TacacsUnitDir, "SystemdDir": p.SystemdDir,
		"LogrotateDir": p.LogrotateDir, "TacquitoSrc": p.TacquitoSrc, "LinuxDir": p.LinuxDir,
		"Tree": p.Tree, "PatchDir": p.PatchDir, "radius.LogArchiveDir": radius.LogArchiveDir,
	}
	for _, fam := range []string{"debian", "rhel"} {
		l := p.Radius(fam)
		for name, path := range map[string]string{
			"Dir": l.Dir, "Bin": l.Bin, "LogDir": l.LogDir, "SystemDict": l.SystemDict, "Conf": l.Conf,
			"Users": l.Users, "DictDir": l.DictDir, "Dict": l.Dict, "DaemonLog": l.DaemonLog,
			"AuthLog": l.AuthLog, "AcctLog": l.AcctLog, "DropIn": l.DropIn, "Logrotate": l.Logrotate,
		} {
			check[fam+" "+name] = path
		}
	}
	var bad []string
	for name, path := range check {
		if !strings.HasPrefix(filepath.Clean(path)+string(filepath.Separator), root) {
			bad = append(bad, name+"="+path)
		}
	}
	return bad
}

// The environments of the tests that run lifecycle phases or 'backend
// enable|disable' (radiusSandbox, newSwEnv) leave no path at a host
// default; and the guard does see one.
func TestLifecycleTestsAreSandboxed(t *testing.T) {
	sb := radiusSandbox(t, "debian")
	if bad := hostDefaults(paths.Resolve(paths.NewEnv(sb.env), "/opt/x/dist/tacctl", nil), sb.dir); len(bad) != 0 {
		t.Errorf("radiusSandbox: %v", bad)
	}
	e := newSwEnv(t)
	if bad := hostDefaults(e.p, e.w); len(bad) != 0 {
		t.Errorf("newSwEnv: %v", bad)
	}
	if bad := hostDefaults(paths.Resolve(paths.NewEnv(nil), "", nil), t.TempDir()); len(bad) < 10 {
		t.Errorf("the guard missed host defaults: %v", bad)
	}
}
