package paths

import (
	"os"
	"path/filepath"
)

// Production locations that no variable overrides.
const (
	// DeployDir is the clone install and upgrade manage (DEPLOY_DIR).
	DeployDir = "/opt/tacctl"
	// DefaultBashImpl is the bash entrypoint of the installed tree, which the
	// Go front door delegates to during the rewrite when TACCTL_BASH_IMPL is
	// not set.
	DefaultBashImpl = DeployDir + "/bin/tacctl.sh"
	// GoBin is the toolchain tacctl installs for tacquito (GO_BIN).
	GoBin = "/usr/local/go/bin/go"
	// DefaultSettleSeconds is how long a restarted unit must stay up before a
	// settings change counts as applied (TACACS_SETTLE_SECONDS,
	// RADIUS_SETTLE_SECONDS), as the bash text "0.5".
	DefaultSettleSeconds = "0.5"
)

// Paths is every location tacctl reads or writes, after the TACCTL_*
// overrides. Field comments name the bash variable each one mirrors.
type Paths struct {
	Etc        string // TACCTL_ETC (CONFIG_DIR): the TACACS+ daemon's directory
	StateDir   string // TACCTL_STATE_DIR: tacctl-owned state
	Log        string // TACCTL_LOG (LOG_DIR): tacquito's log directory
	Bin        string // TACCTL_BIN: where tacquito and tacquito-hashgen live
	Config     string // TACCTL_CONFIG (CONFIG): tacquito.yaml
	BackupDir  string // BACKUP_DIR
	PWDatesDir string // PASSWORD_DATES_DIR
	AcctLog    string // ACCT_LOG
	Overrides  string // TACCTL_OVERRIDES_FILE: tacctl.yaml
	StoreFile  string // STORE_FILE
	Rendered   string // RENDERED_FILE: rendered.json
	LinuxUIDs  string // LINUX_UID_FILE
	LinuxHosts string // LINUX_HOSTS_FILE: the enrolled-host registry
	Templates  string // TEMPLATE_DIR_LOCAL: operator template overrides

	SudoersFile     string // TACCTL_SUDOERS_FILE (SUDOERS_FILE)
	TierSudoersFile string // TACCTL_TIER_SUDOERS_FILE (TIER_SUDOERS_FILE)

	OverrideDir   string // TACCTL_OVERRIDE_DIR (OVERRIDE_DIR): tacquito.service's drop-in directory
	TacacsUnitDir string // TACACS_UNIT_DIR: TACCTL_SYSTEMD_DIR, else the parent of OverrideDir
	SystemdDir    string // ${TACCTL_SYSTEMD_DIR:-/etc/systemd/system}, as the RADIUS module uses it
	LogrotateDir  string // ${TACCTL_LOGROTATE_DIR:-/etc/logrotate.d}
	SettleSeconds string // TACCTL_SETTLE_SECONDS, as text

	TacquitoSrc string // TACQUITO_SRC: the tacquito source checkout
	LinuxDir    string // TACCTL_LINUX_DIR (LINUX_DIR)

	// Tree is the source/deploy tree this binary treats as its checkout
	// (bash: PROJECT_DIR, the parent of the script's own directory).
	Tree string
	// PatchDir holds the tacquito patches: TACCTL_PATCH_DIR, else Tree/patches.
	PatchDir string
	// BashImpl is the bash entrypoint delegated to during the rewrite:
	// TACCTL_BASH_IMPL, else DefaultBashImpl.
	BashImpl string

	// RADIUS overrides as given; the family decides the defaults (Radius).
	RadiusFamily string // TACCTL_RADIUS_FAMILY
	radiusDir    string // TACCTL_RADIUS_DIR
	radiusBin    string // TACCTL_RADIUS_BIN
	radiusLog    string // TACCTL_RADIUS_LOG
	radiusDict   string // TACCTL_RADIUS_DICT

	// SkipSudo is TACCTL_SKIP_SUDO=1: no sudo re-exec (tests only).
	SkipSudo bool
}

// Resolve computes Paths from env. exe is the running executable (for the
// tree rule); exists reports whether a path exists (os.Stat when nil).
func Resolve(env Env, exe string, exists func(string) bool) Paths {
	if exists == nil {
		exists = statExists
	}
	var p Paths
	p.Etc = env.Or("TACCTL_ETC", "/etc/tacquito")
	p.StateDir = env.Or("TACCTL_STATE_DIR", "/etc/tacctl")
	p.Log = env.Or("TACCTL_LOG", "/var/log/tacquito")
	p.Bin = env.Or("TACCTL_BIN", "/usr/local/bin")
	p.Config = env.Or("TACCTL_CONFIG", p.Etc+"/tacquito.yaml")
	p.BackupDir = p.StateDir + "/backups"
	p.PWDatesDir = p.StateDir + "/backups/password-dates"
	p.AcctLog = p.Log + "/accounting.log"
	p.Overrides = p.StateDir + "/tacctl.yaml"
	p.StoreFile = p.StateDir + "/store.yaml"
	p.Rendered = p.StateDir + "/rendered.json"
	p.LinuxUIDs = p.StateDir + "/linux-uids"
	p.LinuxHosts = p.StateDir + "/linux-hosts"
	p.Templates = p.StateDir + "/templates"

	p.SudoersFile = env.Or("TACCTL_SUDOERS_FILE", "/etc/sudoers.d/tacctl")
	p.TierSudoersFile = env.Or("TACCTL_TIER_SUDOERS_FILE", "/etc/sudoers.d/tacctl-tiers")

	p.OverrideDir = env.Or("TACCTL_OVERRIDE_DIR", "/etc/systemd/system/tacquito.service.d")
	p.TacacsUnitDir = env.Or("TACCTL_SYSTEMD_DIR", filepath.Dir(p.OverrideDir))
	p.SystemdDir = env.Or("TACCTL_SYSTEMD_DIR", "/etc/systemd/system")
	p.LogrotateDir = env.Or("TACCTL_LOGROTATE_DIR", "/etc/logrotate.d")
	p.SettleSeconds = env.Or("TACCTL_SETTLE_SECONDS", DefaultSettleSeconds)

	p.TacquitoSrc = env.Or("TACQUITO_SRC", "/opt/tacquito-src")
	p.LinuxDir = env.Or("TACCTL_LINUX_DIR", "/var/lib/tacctl/linux")

	p.Tree = Tree(env, exe, exists)
	p.PatchDir = env.Or("TACCTL_PATCH_DIR", p.Tree+"/patches")
	p.BashImpl = env.Or("TACCTL_BASH_IMPL", DefaultBashImpl)

	p.RadiusFamily = env.Get("TACCTL_RADIUS_FAMILY")
	p.radiusDir = env.Get("TACCTL_RADIUS_DIR")
	p.radiusBin = env.Get("TACCTL_RADIUS_BIN")
	p.radiusLog = env.Get("TACCTL_RADIUS_LOG")
	p.radiusDict = env.Get("TACCTL_RADIUS_DICT")

	p.SkipSudo = env.Get("TACCTL_SKIP_SUDO") == "1"
	return p
}

// Tree is the checkout the binary treats as its own: TACCTL_TREE when set;
// else the parent of the executable's directory when that holds go.mod (a
// dev checkout running dist/tacctl); else DeployDir.
func Tree(env Env, exe string, exists func(string) bool) string {
	if t := env.Get("TACCTL_TREE"); t != "" {
		return t
	}
	if exists == nil {
		exists = statExists
	}
	if exe != "" {
		parent := filepath.Dir(filepath.Dir(exe))
		if exists(filepath.Join(parent, "go.mod")) {
			return parent
		}
	}
	return DeployDir
}

// RadiusPaths is the FreeRADIUS layout of one distribution family
// (lib/backends/radius.sh, "Layout").
type RadiusPaths struct {
	Family     string // debian | rhel
	Dir        string // RADIUS_DIR (raddb)
	Unit       string // RADIUS_UNIT
	User       string // RADIUS_USER
	Group      string // RADIUS_GROUP
	Bin        string // RADIUS_BIN
	LogDir     string // RADIUS_LOG_DIR
	PIDFile    string // RADIUS_PID_FILE
	LibDir     string // RADIUS_LIB_DIR
	SystemDict string // RADIUS_SYSTEM_DICT
	Conf       string // RADIUS_CONF
	Users      string // RADIUS_USERS
	DictDir    string // RADIUS_DICT_DIR
	Dict       string // RADIUS_DICT
	DaemonLog  string // RADIUS_DAEMON_LOG
	AuthLog    string // RADIUS_AUTH_LOG
	AcctLog    string // RADIUS_ACCT_LOG
	DropIn     string // RADIUS_DROPIN
	Logrotate  string // RADIUS_LOGROTATE
}

// RadiusName is the name the daemon runs under ('-n'; RADIUS_NAME).
const RadiusName = "tacctl-radius"

// Radius returns the RADIUS layout for family ("rhel"; anything else is the
// Debian layout, as in bash), with the TACCTL_RADIUS_* overrides applied.
// Detecting the family is the RADIUS module's job.
func (p Paths) Radius(family string) RadiusPaths {
	r := RadiusPaths{Family: "debian"}
	or := func(v, def string) string {
		if v != "" {
			return v
		}
		return def
	}
	if family == "rhel" {
		r.Family = "rhel"
		r.Dir = or(p.radiusDir, "/etc/raddb")
		r.Unit, r.User, r.Group = "radiusd.service", "radiusd", "radiusd"
		r.Bin = or(p.radiusBin, "/usr/sbin/radiusd")
		r.LogDir = or(p.radiusLog, "/var/log/radius")
		r.PIDFile = "/run/radiusd/radiusd.pid"
		r.LibDir = "/usr/lib64/freeradius"
	} else {
		r.Dir = or(p.radiusDir, "/etc/freeradius/3.0")
		r.Unit, r.User, r.Group = "freeradius.service", "freerad", "freerad"
		r.Bin = or(p.radiusBin, "/usr/sbin/freeradius")
		r.LogDir = or(p.radiusLog, "/var/log/freeradius")
		r.PIDFile = "/run/freeradius/freeradius.pid"
		r.LibDir = "/usr/lib/freeradius"
	}
	r.SystemDict = or(p.radiusDict, "/usr/share/freeradius/dictionary")
	r.Conf = r.Dir + "/" + RadiusName + ".conf"
	r.Users = r.Dir + "/" + RadiusName + ".users"
	r.DictDir = r.Dir + "/" + RadiusName + "-dictionary"
	r.Dict = r.DictDir + "/dictionary"
	r.DaemonLog = r.LogDir + "/tacctl-radius.log"
	r.AuthLog = r.LogDir + "/tacctl-auth.log"
	r.AcctLog = r.LogDir + "/tacctl-accounting.log"
	r.DropIn = p.SystemdDir + "/" + r.Unit + ".d/tacctl.conf"
	r.Logrotate = p.LogrotateDir + "/tacctl-radius"
	return r
}

func statExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
