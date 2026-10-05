package paths

import (
	"os"
	"path/filepath"
)

// Production locations that no variable overrides.
const (
	// DeployDir is the clone install and upgrade manage (DEPLOY_DIR).
	DeployDir = "/opt/tacctl"
	// GoBin is the toolchain tacctl installs for tacquito (GO_BIN).
	GoBin = "/usr/local/go/bin/go"
	// GoVersion is GO_VERSION, the toolchain tacctl installs (the bootstrap
	// shim's GO_VERSION; go.mod's go line).
	GoVersion = "1.26.2"
	// Command is the installed tacctl command: the binary from 0.2.0 on,
	// a symlink to the bash entrypoint before.
	Command = "/usr/local/bin/tacctl"
	// ConsoleCommand is the login console: a symlink to Command.
	ConsoleCommand = "/usr/local/bin/tacctl-console"
	// Completion is the installed bash completion.
	Completion = "/etc/bash_completion.d/tacctl"
	// ManPage is the installed man page.
	ManPage = "/usr/share/man/man1/tacctl.1.gz"
	// ArchiveDir is where uninstall keeps what it was asked to preserve
	// (a fixed /root, as in 0.1.16).
	ArchiveDir = "/root"
	// ManageRepo is the repository install clones (MANAGE_REPO).
	ManageRepo = "https://github.com/rett/tacctl.git"
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

	// The device registry and the console (0.2.1, 0.2.2); every one is under
	// StateDir (/etc/tacctl, 0700) except the seen cache and the generated
	// known_hosts, which are under VarLib: users' own ssh reads known_hosts.
	DevicesFile string // StateDir/devices.yaml: the device registry
	KnownHosts  string // VarLib/ssh/known_hosts: the generated host-key file (dir 0755, file 0644)
	ConsoleFile string // StateDir/console.yaml: the login console's settings
	SSHDDropIn  string // TACCTL_SSHD_DROPIN: sshd's drop-in for the console group
	ShellsFile  string // TACCTL_SHELLS_FILE: /etc/shells
	VarLib      string // TACCTL_VAR_LIB: tacctl's variable data (/var/lib/tacctl, 0711)
	SeenCache   string // VarLib/devices-seen.json: what the logs showed of each device

	SudoersFile     string // TACCTL_SUDOERS_FILE (SUDOERS_FILE)
	TierSudoersFile string // TACCTL_TIER_SUDOERS_FILE (TIER_SUDOERS_FILE)

	OverrideDir   string // TACCTL_OVERRIDE_DIR (OVERRIDE_DIR): tacquito.service's drop-in directory
	TacacsUnitDir string // TACACS_UNIT_DIR: TACCTL_SYSTEMD_DIR, else the parent of OverrideDir
	SystemdDir    string // ${TACCTL_SYSTEMD_DIR:-/etc/systemd/system}, as the RADIUS module uses it
	LogrotateDir  string // ${TACCTL_LOGROTATE_DIR:-/etc/logrotate.d}
	SettleSeconds string // TACCTL_SETTLE_SECONDS, as text

	TacquitoSrc string // TACQUITO_SRC: the tacquito source checkout
	LinuxDir    string // TACCTL_LINUX_DIR (LINUX_DIR)
	LoginDefs   string // TACCTL_LOGIN_DEFS: this server's login.defs, read (never written) for 'host enroll --local'

	// Tree is the source/deploy tree this binary treats as its checkout
	// (bash: PROJECT_DIR, the parent of the script's own directory).
	Tree string
	// PatchDir holds the tacquito patches: TACCTL_PATCH_DIR, else Tree/patches.
	PatchDir string

	// tacctl's own fixed host locations, which 0.1.16 hard-codes (no
	// variable overrides them; Reroot moves them for tests).
	//
	Deploy         string // DEPLOY_DIR, the clone install and upgrade manage (/opt/tacctl)
	Command        string // the installed command (/usr/local/bin/tacctl)
	ConsoleCommand string // the login console, a symlink to Command (/usr/local/bin/tacctl-console)
	GoBin          string // GO_BIN (/usr/local/go/bin/go)
	Completion     string // /etc/bash_completion.d/tacctl
	ManPage        string // /usr/share/man/man1/tacctl.1.gz
	ArchiveDir     string // where uninstall archives what it keeps (/root)

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
	p.DevicesFile = p.StateDir + "/devices.yaml"
	p.ConsoleFile = p.StateDir + "/console.yaml"
	p.SSHDDropIn = env.Or("TACCTL_SSHD_DROPIN", "/etc/ssh/sshd_config.d/tacctl-console.conf")
	p.ShellsFile = env.Or("TACCTL_SHELLS_FILE", "/etc/shells")
	p.VarLib = env.Or("TACCTL_VAR_LIB", "/var/lib/tacctl")
	p.SeenCache = p.VarLib + "/devices-seen.json"
	p.KnownHosts = p.VarLib + "/ssh/known_hosts"

	p.SudoersFile = env.Or("TACCTL_SUDOERS_FILE", "/etc/sudoers.d/tacctl")
	p.TierSudoersFile = env.Or("TACCTL_TIER_SUDOERS_FILE", "/etc/sudoers.d/tacctl-tiers")

	p.OverrideDir = env.Or("TACCTL_OVERRIDE_DIR", "/etc/systemd/system/tacquito.service.d")
	p.TacacsUnitDir = env.Or("TACCTL_SYSTEMD_DIR", filepath.Dir(p.OverrideDir))
	p.SystemdDir = env.Or("TACCTL_SYSTEMD_DIR", "/etc/systemd/system")
	p.LogrotateDir = env.Or("TACCTL_LOGROTATE_DIR", "/etc/logrotate.d")
	p.SettleSeconds = env.Or("TACCTL_SETTLE_SECONDS", DefaultSettleSeconds)

	p.TacquitoSrc = env.Or("TACQUITO_SRC", "/opt/tacquito-src")
	p.LinuxDir = env.Or("TACCTL_LINUX_DIR", "/var/lib/tacctl/linux")
	p.LoginDefs = env.Or("TACCTL_LOGIN_DEFS", "/etc/login.defs")

	p.Tree = Tree(env, exe, exists)
	p.PatchDir = env.Or("TACCTL_PATCH_DIR", p.Tree+"/patches")

	p.Deploy, p.Command, p.GoBin, p.Completion, p.ManPage, p.ArchiveDir = DeployDir, Command, GoBin, Completion, ManPage, ArchiveDir
	p.ConsoleCommand = ConsoleCommand

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

// Reroot moves tacctl's fixed host locations (Deploy, Command, ConsoleCommand,
// GoBin, Completion, ManPage, ArchiveDir) under root,
// keeping their paths below it: /usr/local/bin/tacctl becomes
// <root>/usr/local/bin/tacctl. It is for tests (the -tags testknobs knob
// TACCTL_TEST_ROOT, and Go tests), so that install, upgrade and uninstall
// can run without reaching the machine's own; root "" changes nothing.
func (p Paths) Reroot(root string) Paths {
	if root == "" {
		return p
	}
	under := func(path string) string { return filepath.Join(root, path) }
	p.Deploy, p.Command, p.GoBin, p.Completion = under(p.Deploy), under(p.Command), under(p.GoBin), under(p.Completion)
	p.ManPage, p.ArchiveDir, p.ConsoleCommand = under(p.ManPage), under(p.ArchiveDir), under(p.ConsoleCommand)
	return p
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

// VarLibMode is VarLib's mode: every user may pass through it (their ssh
// reads VarLib/ssh/known_hosts) but only root may list it.
const VarLibMode os.FileMode = 0o711

// MkVarLib creates dir (VarLib) with VarLibMode, or brings the mode of an
// existing directory to it: wherever tacctl creates or writes under
// /var/lib/tacctl.
func MkVarLib(dir string) error {
	if err := os.MkdirAll(dir, VarLibMode); err != nil {
		return err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st.Mode().Perm() != VarLibMode {
		return os.Chmod(dir, VarLibMode)
	}
	return nil
}
