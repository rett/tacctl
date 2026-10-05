package paths

import (
	"reflect"
	"testing"
)

func TestEnv(t *testing.T) {
	e := NewEnv([]string{"A=1", "B=", "NOEQ", "A=2", "C=x=y"})
	if v, ok := e.Lookup("A"); !ok || v != "2" {
		t.Errorf("Lookup(A) = %q, %v; want 2, true (last wins)", v, ok)
	}
	if v, ok := e.Lookup("B"); !ok || v != "" {
		t.Errorf("Lookup(B) = %q, %v; want empty, true", v, ok)
	}
	if _, ok := e.Lookup("NOEQ"); ok {
		t.Error("Lookup(NOEQ) is set; an entry without '=' has no value")
	}
	if got := e.Get("C"); got != "x=y" {
		t.Errorf("Get(C) = %q, want x=y", got)
	}
	if got := e.Get("missing"); got != "" {
		t.Errorf("Get(missing) = %q", got)
	}
	if got := e.Or("B", "def"); got != "def" {
		t.Errorf("Or(B) = %q; an empty value takes the default like ${B:-def}", got)
	}
	if got := e.Or("A", "def"); got != "2" {
		t.Errorf("Or(A) = %q", got)
	}
	want := []string{"A=1", "B=", "NOEQ", "A=2", "C=x=y"}
	got := e.Environ()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Environ() = %q, want %q", got, want)
	}
	got[0] = "changed"
	if e.Environ()[0] != "A=1" {
		t.Error("Environ() returned the internal slice")
	}
	var zero Env
	if zero.Get("A") != "" || len(zero.Environ()) != 0 {
		t.Error("zero Env is not empty")
	}
}

func none(string) bool { return false }

func TestResolveDefaults(t *testing.T) {
	p := Resolve(NewEnv(nil), "/usr/local/bin/tacctl", none)
	want := map[string]string{
		"Etc":             "/etc/tacquito",
		"StateDir":        "/etc/tacctl",
		"Log":             "/var/log/tacquito",
		"Bin":             "/usr/local/bin",
		"Config":          "/etc/tacquito/tacquito.yaml",
		"BackupDir":       "/etc/tacctl/backups",
		"PWDatesDir":      "/etc/tacctl/backups/password-dates",
		"AcctLog":         "/var/log/tacquito/accounting.log",
		"Overrides":       "/etc/tacctl/tacctl.yaml",
		"StoreFile":       "/etc/tacctl/store.yaml",
		"Rendered":        "/etc/tacctl/rendered.json",
		"LinuxUIDs":       "/etc/tacctl/linux-uids",
		"LinuxHosts":      "/etc/tacctl/linux-hosts",
		"Templates":       "/etc/tacctl/templates",
		"SudoersFile":     "/etc/sudoers.d/tacctl",
		"TierSudoersFile": "/etc/sudoers.d/tacctl-tiers",
		"OverrideDir":     "/etc/systemd/system/tacquito.service.d",
		"TacacsUnitDir":   "/etc/systemd/system",
		"SystemdDir":      "/etc/systemd/system",
		"LogrotateDir":    "/etc/logrotate.d",
		"SettleSeconds":   "0.5",
		"TacquitoSrc":     "/opt/tacquito-src",
		"LinuxDir":        "/var/lib/tacctl/linux",
		"LoginDefs":       "/etc/login.defs",
		"Tree":            "/opt/tacctl",
		"PatchDir":        "/opt/tacctl/patches",
	}
	checkFields(t, p, want)
	if p.SkipSudo {
		t.Error("SkipSudo set without TACCTL_SKIP_SUDO")
	}
}

func TestResolveOverrides(t *testing.T) {
	env := NewEnv([]string{
		"TACCTL_ETC=/t/etc", "TACCTL_STATE_DIR=/t/state", "TACCTL_LOG=/t/log", "TACCTL_BIN=/t/bin",
		"TACCTL_SUDOERS_FILE=/t/sudoers", "TACCTL_TIER_SUDOERS_FILE=/t/tiers",
		"TACCTL_OVERRIDE_DIR=/t/dropin", "TACCTL_LOGROTATE_DIR=/t/lr", "TACCTL_SETTLE_SECONDS=0",
		"TACQUITO_SRC=/t/src", "TACCTL_LINUX_DIR=/t/linux", "TACCTL_TREE=/t/tree", "TACCTL_LOGIN_DEFS=/t/login.defs",
		"TACCTL_PATCH_DIR=/t/patches", "TACCTL_SKIP_SUDO=1",
	})
	p := Resolve(env, "", none)
	checkFields(t, p, map[string]string{
		"Etc":             "/t/etc",
		"Config":          "/t/etc/tacquito.yaml", // follows TACCTL_ETC
		"StateDir":        "/t/state",
		"StoreFile":       "/t/state/store.yaml",
		"Overrides":       "/t/state/tacctl.yaml",
		"AcctLog":         "/t/log/accounting.log",
		"Bin":             "/t/bin",
		"SudoersFile":     "/t/sudoers",
		"TierSudoersFile": "/t/tiers",
		"OverrideDir":     "/t/dropin",
		"TacacsUnitDir":   "/t", // the drop-in dir's parent when TACCTL_SYSTEMD_DIR is unset
		"SystemdDir":      "/etc/systemd/system",
		"LogrotateDir":    "/t/lr",
		"SettleSeconds":   "0",
		"TacquitoSrc":     "/t/src",
		"LinuxDir":        "/t/linux",
		"LoginDefs":       "/t/login.defs",
		"Tree":            "/t/tree",
		"PatchDir":        "/t/patches",
	})
	if !p.SkipSudo {
		t.Error("SkipSudo not set by TACCTL_SKIP_SUDO=1")
	}

	p = Resolve(NewEnv([]string{"TACCTL_CONFIG=/x/t.yaml", "TACCTL_SYSTEMD_DIR=/sd", "TACCTL_SKIP_SUDO=yes"}), "", none)
	checkFields(t, p, map[string]string{"Config": "/x/t.yaml", "TacacsUnitDir": "/sd", "SystemdDir": "/sd"})
	if p.SkipSudo {
		t.Error("SkipSudo set by a value other than 1")
	}
	// An empty variable is unset, as ${VAR:-default} and ${VAR:=default} treat it.
	p = Resolve(NewEnv([]string{"TACCTL_STATE_DIR="}), "", none)
	if p.StateDir != "/etc/tacctl" {
		t.Errorf("empty TACCTL_STATE_DIR: StateDir = %q", p.StateDir)
	}
}

func TestTree(t *testing.T) {
	has := func(want string) func(string) bool { return func(p string) bool { return p == want } }
	if got := Tree(NewEnv(nil), "/home/u/src/tacctl/dist/tacctl", has("/home/u/src/tacctl/go.mod")); got != "/home/u/src/tacctl" {
		t.Errorf("dev checkout: Tree = %q", got)
	}
	if got := Tree(NewEnv(nil), "/usr/local/bin/tacctl", has("/home/u/src/tacctl/go.mod")); got != DeployDir {
		t.Errorf("installed binary: Tree = %q", got)
	}
	if got := Tree(NewEnv([]string{"TACCTL_TREE=/x"}), "/home/u/src/tacctl/dist/tacctl", has("/home/u/src/tacctl/go.mod")); got != "/x" {
		t.Errorf("TACCTL_TREE: Tree = %q", got)
	}
	if got := Tree(NewEnv(nil), "", nil); got != DeployDir {
		t.Errorf("no executable: Tree = %q", got)
	}
	// The real filesystem: this package's directory has no go.mod two levels up.
	if got := Tree(NewEnv(nil), "/nonexistent/dir/tacctl", nil); got != DeployDir {
		t.Errorf("stat fallback: Tree = %q", got)
	}
}

func TestRadius(t *testing.T) {
	p := Resolve(NewEnv(nil), "", none)
	deb := p.Radius("debian")
	checkFields(t, deb, map[string]string{
		"Family":     "debian",
		"Dir":        "/etc/freeradius/3.0",
		"Unit":       "freeradius.service",
		"User":       "freerad",
		"Group":      "freerad",
		"Bin":        "/usr/sbin/freeradius",
		"LogDir":     "/var/log/freeradius",
		"PIDFile":    "/run/freeradius/freeradius.pid",
		"LibDir":     "/usr/lib/freeradius",
		"SystemDict": "/usr/share/freeradius/dictionary",
		"Conf":       "/etc/freeradius/3.0/tacctl-radius.conf",
		"Users":      "/etc/freeradius/3.0/tacctl-radius.users",
		"DictDir":    "/etc/freeradius/3.0/tacctl-radius-dictionary",
		"Dict":       "/etc/freeradius/3.0/tacctl-radius-dictionary/dictionary",
		"DaemonLog":  "/var/log/freeradius/tacctl-radius.log",
		"AuthLog":    "/var/log/freeradius/tacctl-auth.log",
		"AcctLog":    "/var/log/freeradius/tacctl-accounting.log",
		"DropIn":     "/etc/systemd/system/freeradius.service.d/tacctl.conf",
		"Logrotate":  "/etc/logrotate.d/tacctl-radius",
	})
	if got := p.Radius("").Family; got != "debian" {
		t.Errorf("undetected family lays out as %q, want debian", got)
	}
	checkFields(t, p.Radius("rhel"), map[string]string{
		"Family":  "rhel",
		"Dir":     "/etc/raddb",
		"Unit":    "radiusd.service",
		"User":    "radiusd",
		"Bin":     "/usr/sbin/radiusd",
		"LogDir":  "/var/log/radius",
		"PIDFile": "/run/radiusd/radiusd.pid",
		"LibDir":  "/usr/lib64/freeradius",
		"DropIn":  "/etc/systemd/system/radiusd.service.d/tacctl.conf",
	})

	p = Resolve(NewEnv([]string{
		"TACCTL_RADIUS_DIR=/t/raddb", "TACCTL_RADIUS_BIN=/t/radiusd", "TACCTL_RADIUS_LOG=/t/rlog",
		"TACCTL_RADIUS_DICT=/t/dict", "TACCTL_RADIUS_FAMILY=rhel", "TACCTL_SYSTEMD_DIR=/t/sd",
		"TACCTL_LOGROTATE_DIR=/t/lr",
	}), "", none)
	if p.RadiusFamily != "rhel" {
		t.Errorf("RadiusFamily = %q", p.RadiusFamily)
	}
	for _, fam := range []string{"debian", "rhel"} {
		checkFields(t, p.Radius(fam), map[string]string{
			"Dir":        "/t/raddb",
			"Bin":        "/t/radiusd",
			"LogDir":     "/t/rlog",
			"SystemDict": "/t/dict",
			"Conf":       "/t/raddb/tacctl-radius.conf",
			"AuthLog":    "/t/rlog/tacctl-auth.log",
			"Logrotate":  "/t/lr/tacctl-radius",
		})
	}
	if got := p.Radius("debian").DropIn; got != "/t/sd/freeradius.service.d/tacctl.conf" {
		t.Errorf("DropIn = %q", got)
	}
}

// checkFields compares the named string fields of a struct with want.
func checkFields(t *testing.T, v any, want map[string]string) {
	t.Helper()
	rv := reflect.ValueOf(v)
	for name, w := range want {
		f := rv.FieldByName(name)
		if !f.IsValid() {
			t.Errorf("no field %s", name)
			continue
		}
		if got := f.String(); got != w {
			t.Errorf("%s = %q, want %q", name, got, w)
		}
	}
}

// tacctl's own host locations: the 0.1.16 literals, and Reroot moving them (not the TACCTL_* ones) under a root.
func TestHostLocationsAndReroot(t *testing.T) {
	p := Resolve(NewEnv(nil), "", func(string) bool { return false })
	want := map[string]string{
		"Deploy": "/opt/tacctl", "Command": "/usr/local/bin/tacctl", "GoBin": "/usr/local/go/bin/go",
		"Completion": "/etc/bash_completion.d/tacctl", "ManPage": "/usr/share/man/man1/tacctl.1.gz", "ArchiveDir": "/root",
	}
	got := func(p Paths) map[string]string {
		return map[string]string{"Deploy": p.Deploy, "Command": p.Command, "GoBin": p.GoBin,
			"Completion": p.Completion, "ManPage": p.ManPage, "ArchiveDir": p.ArchiveDir}
	}
	for k, v := range got(p) {
		if want[k] != v {
			t.Errorf("%s = %q, want %q", k, v, want[k])
		}
	}
	if p.Reroot("") != p {
		t.Error("Reroot(\"\") changed something")
	}
	r := p.Reroot("/sb")
	for k, v := range got(r) {
		if v != "/sb"+want[k] {
			t.Errorf("rerooted %s = %q", k, v)
		}
	}
	if r.Etc != p.Etc || r.StateDir != p.StateDir || r.Bin != p.Bin {
		t.Error("Reroot moved a TACCTL_* location")
	}
	// The deploy clone is /opt/tacctl whatever tree the binary runs from
	// (bash's DEPLOY_DIR is not read from the environment).
	if q := Resolve(NewEnv([]string{"TACCTL_TREE=/scratch/clone"}), "", nil); q.Deploy != "/opt/tacctl" {
		t.Errorf("Deploy with TACCTL_TREE: %q", q.Deploy)
	}
}

// The device registry's and the console's paths (0.2.1): under StateDir
// except the seen cache, which follows TACCTL_VAR_LIB.
func TestDeviceAndConsolePaths(t *testing.T) {
	p := Resolve(NewEnv(nil), "", func(string) bool { return false })
	want := map[string]string{
		p.DevicesFile: "/etc/tacctl/devices.yaml", p.KnownHosts: "/var/lib/tacctl/ssh/known_hosts",
		p.ConsoleFile: "/etc/tacctl/console.yaml", p.ConsoleDir: "/etc/tacctl/console",
		p.VarLib: "/var/lib/tacctl", p.SeenCache: "/var/lib/tacctl/devices-seen.json",
	}
	for got, w := range want {
		if got != w {
			t.Errorf("default %q, want %q", got, w)
		}
	}
	p = Resolve(NewEnv([]string{"TACCTL_STATE_DIR=/s", "TACCTL_VAR_LIB=/v"}), "", func(string) bool { return false })
	for got, w := range map[string]string{
		p.DevicesFile: "/s/devices.yaml", p.KnownHosts: "/v/ssh/known_hosts", p.ConsoleFile: "/s/console.yaml",
		p.ConsoleDir: "/s/console", p.VarLib: "/v", p.SeenCache: "/v/devices-seen.json",
	} {
		if got != w {
			t.Errorf("overridden %q, want %q", got, w)
		}
	}
}
