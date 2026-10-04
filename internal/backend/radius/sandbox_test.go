package radius_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/paths"
)

// hostDefaults names every path a lifecycle phase, a render or 'backend
// enable|disable' can write (or remove) that does not resolve under root:
// a test environment that leaves one at its host default could change the
// machine the tests run on. PIDFile and LibDir are only written into the
// rendered config, never touched.
func hostDefaults(p paths.Paths, l paths.RadiusPaths, root string) []string {
	root = filepath.Clean(root) + string(filepath.Separator)
	var bad []string
	for name, path := range map[string]string{
		"Etc": p.Etc, "StateDir": p.StateDir, "Log": p.Log, "Bin": p.Bin, "Config": p.Config,
		"BackupDir": p.BackupDir, "Overrides": p.Overrides, "StoreFile": p.StoreFile, "Rendered": p.Rendered,
		"LinuxUIDs": p.LinuxUIDs, "LinuxHosts": p.LinuxHosts, "Templates": p.Templates,
		"SudoersFile": p.SudoersFile, "TierSudoersFile": p.TierSudoersFile,
		"OverrideDir": p.OverrideDir, "TacacsUnitDir": p.TacacsUnitDir, "SystemdDir": p.SystemdDir,
		"LogrotateDir": p.LogrotateDir, "TacquitoSrc": p.TacquitoSrc, "LinuxDir": p.LinuxDir,
		"Tree": p.Tree, "PatchDir": p.PatchDir,
		"radius Dir": l.Dir, "radius Bin": l.Bin, "radius LogDir": l.LogDir, "radius SystemDict": l.SystemDict,
		"radius Conf": l.Conf, "radius Users": l.Users, "radius DictDir": l.DictDir, "radius Dict": l.Dict,
		"radius DaemonLog": l.DaemonLog, "radius AuthLog": l.AuthLog, "radius AcctLog": l.AcctLog,
		"radius DropIn": l.DropIn, "radius Logrotate": l.Logrotate,
		"ArchiveDir": p.ArchiveDir,
	} {
		if !strings.HasPrefix(filepath.Clean(path)+string(filepath.Separator), root) {
			bad = append(bad, name+"="+path)
		}
	}
	return bad
}

// The harness keeps every path a phase can write inside the test's temp
// dir, on both families (newEnv fails otherwise; this says so by name).
func TestHarnessIsSandboxed(t *testing.T) {
	for _, opts := range [][]option{nil, {rhel}} {
		r := newEnv(t, opts...)
		if bad := hostDefaults(r.p, r.m.L, r.w); len(bad) != 0 {
			t.Errorf("host defaults: %v", bad)
		}
	}
	// And the guard sees a host default.
	if bad := hostDefaults(paths.Resolve(paths.NewEnv(nil), "", nil), paths.Paths{}.Radius("debian"), t.TempDir()); len(bad) < 10 {
		t.Errorf("the guard missed host defaults: %v", bad)
	}
}
