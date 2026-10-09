// Package tier is the caller-tier gate of lib/dispatch.sh (0.1.16):
// caller_tier, tier_permits, enforce_tier, and emit_tier_sudoers, the
// sudoers drop-in that grants the same commands. tacctl always runs as
// root, so the tier of the person behind sudo is enforced here as well as
// in that drop-in: sudoers argument globs are loose, this gate is not.
//
// Only callers in the local group tac-users are tier-managed (the accounts
// tacctl provisions for its users); everyone else who reaches tacctl (root,
// a local admin with sudo) is unrestricted. A managed caller's tier comes
// from the model and tacctl.yaml (the tier set on the user's group, else
// its priv-lvl), never from local group membership.
//
// The gate and the sudoers rules are one table (Rules): Permits reads it,
// Sudoers prints it, so the two cannot disagree. A new read-only verb is
// one row.
package tier

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// The local groups of the tiers (TIER_USERS_GROUP, TIER_GROUP_*).
const (
	UsersGroup     = "tac-users"
	ReadonlyGroup  = "tac-readonly"
	OperatorGroup  = "tac-operator"
	EngineerGroup  = "tac-engineer"
	SuperuserGroup = "tac-superuser"
)

// Tier is a caller's tier.
type Tier string

// The tiers. None is a tier-managed caller with no usable tacctl user
// (unknown or disabled), denied everything.
const (
	Unrestricted Tier = "unrestricted"
	Superuser    Tier = "superuser"
	Engineer     Tier = "engineer"
	Operator     Tier = "operator"
	Readonly     Tier = "readonly"
	None         Tier = "none"
)

// Managed are the tiers of tacctl users, lowest first: the tiers a group
// may be given (conf.Tiers) and the order of the tier table's rows.
var Managed = []Tier{Readonly, Operator, Engineer, Superuser}

// Rank is a managed tier's place in Managed, lowest first (-1: not one).
func Rank(t Tier) int { return rank(t) }

// rank is a managed tier's place in Managed (-1: not one).
func rank(t Tier) int {
	for i, m := range Managed {
		if m == t {
			return i
		}
	}
	return -1
}

// InvalidSetting is what policy.GroupTier answers for a tier setting that is
// there but cannot be one (not a non-empty string, or a tier that is not a
// mapping). It is not a managed tier, so ForGroup makes it readonly.
const InvalidSetting = "invalid"

// ForGroup is the tier of a user whose group has the tier setting set
// (policy.GroupTier: "" when none is set) and the priv-lvl privlvl: the
// setting, when it names a managed tier, else the priv-lvl band
// (ForPrivLvl). A setting that is not a managed tier (a hand-edited file;
// the validated writers refuse it) is readonly, never the band: it must not
// leave a group at priv-lvl 15 a superuser. A user with no usable priv-lvl
// (unknown, disabled, a group without one) is none whatever the setting
// says. The setting is what makes an engineer: the bands give readonly,
// operator or superuser only, so a group at priv-lvl 15 on the devices can
// be engineers in tacctl (docs/plans/0.2.2-plan.md D18).
func ForGroup(setting, privlvl string) Tier {
	t := ForPrivLvl(privlvl)
	if t == None || setting == "" {
		return t
	}
	if s := Tier(setting); rank(s) >= 0 {
		return s
	}
	return Readonly
}

// ForPrivLvl is tier_for_privlvl: 15 and up superuser, 7 and up operator,
// any other number readonly; anything that is not a number is none.
func ForPrivLvl(privlvl string) Tier {
	if !reDigits.MatchString(privlvl) {
		return None
	}
	n, err := strconv.Atoi(privlvl)
	switch {
	case err != nil || n >= 15: // too many digits for an int: bash's >= 15 holds too
		return Superuser
	case n >= 7:
		return Operator
	}
	return Readonly
}

var (
	reDigits = regexp.MustCompile(`^[0-9]+$`)
	reCaller = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// Rule is one row of the tier table: what a lower tier may run.
type Rule struct {
	// Tier is the lowest tier the row is for: Readonly rows are open to
	// operators and engineers too, Operator rows to engineers.
	Tier Tier
	// Cmd and Sub are the first two words of the command line; AnySub
	// opens every Sub (Sub is then empty).
	Cmd, Sub string
	AnySub   bool
	// Sudoers are the argument patterns the sudoers drop-in grants for the
	// row, after the binary (nil: the row is the gate's only — 'hash' runs
	// without sudo, '--version' and '-v' were never granted).
	Sudoers []string
	// Wrap ends the drop-in's line after the row's patterns.
	Wrap bool
}

// Rules is the tier table (tier_permits and emit_tier_sudoers). Anything
// that prints a shared secret or a password hash (scope secret, backup diff,
// config dump, store show) is superuser-only, and so is everything that
// changes anything, but for the Engineer rows (0.2.2, D18; 0.2.3, D45, D47
// and D53): the device registry (add, remove, rename, address, hostname,
// vendor, port, description, location, legacy-ssh, hostkey, and import from
// standard input only), the scope's devices, vendor tags and staging
// addresses ('scope devices', 'scope staging' to list), the device
// configurations 'config cisco|juniper|wti' and 'device config show' of their
// own scopes (which print the scope's secret), the Linux hosts of their scopes to read ('host list',
// 'host show'), and the secret, settings and SNMP settings of a scope of
// their own to read ('scope secret', 'scope show', 'scope snmp'). The gate
// lets an engineer run those verbs; the verbs themselves keep the engineer
// to the devices, hosts and secrets of their own scopes (callerScopes) and
// refuse what would change anything global: 'scope secret' other than
// 'show', 'scope staging' other than 'list', every setter, clear and test of
// 'scope snmp', and 'device import' of a file. Users, groups, scopes, the
// secrets' changes, backends, backups, upgrades, rollbacks and the
// deployment on Linux hosts (enroll, sync, move, target, provisioner,
// unenroll, default-method) stay the superuser's. The order is the drop-in's.
var Rules = []Rule{
	{Tier: Readonly, Cmd: "", AnySub: true, Sudoers: []string{`""`}},
	{Tier: Readonly, Cmd: "passwd", AnySub: true, Sudoers: []string{"passwd"}},
	{Tier: Readonly, Cmd: "status", AnySub: true, Sudoers: []string{"status"}},
	{Tier: Readonly, Cmd: "version", AnySub: true, Sudoers: []string{"version"}, Wrap: true},
	{Tier: Readonly, Cmd: "help", Sudoers: []string{"help"}},
	{Tier: Readonly, Cmd: "-h", Sudoers: []string{"-h"}},
	{Tier: Readonly, Cmd: "--help", Sudoers: []string{"--help"}, Wrap: true},
	{Tier: Readonly, Cmd: "user", Sub: "list", Sudoers: []string{"user list"}},
	{Tier: Readonly, Cmd: "user", Sub: "show", Sudoers: []string{"user show *"}},
	{Tier: Readonly, Cmd: "group", Sub: "list", Sudoers: []string{"group list"}},
	{Tier: Readonly, Cmd: "group", Sub: "show", Sudoers: []string{"group show *"}},
	{Tier: Readonly, Cmd: "scope", Sub: "list", Sudoers: []string{"scope list"}, Wrap: true},
	{Tier: Readonly, Cmd: "backend", Sub: "list", Sudoers: []string{"backend list"}},
	{Tier: Readonly, Cmd: "backend", Sub: "status", Sudoers: []string{"backend status", "backend status *"}, Wrap: true},
	// 'ssh <name>' and the device registry's reads (0.2.1): the root side
	// filters them to the caller's own scopes (docs/plans/operator-console.md 8).
	{Tier: Readonly, Cmd: "ssh", AnySub: true, Sudoers: []string{"ssh *"}},
	{Tier: Readonly, Cmd: "device", Sub: "list", Sudoers: []string{"device list", "device list *"}},
	{Tier: Readonly, Cmd: "device", Sub: "show", Sudoers: []string{"device show *"}},
	{Tier: Readonly, Cmd: "device", Sub: "notices", Sudoers: []string{"device notices", "device notices *"}},
	{Tier: Readonly, Cmd: "device", Sub: "ssh", Sudoers: []string{"device ssh *"}},
	{Tier: Readonly, Cmd: "device", Sub: "ssh-config", Sudoers: []string{"device ssh-config"}, Wrap: true},
	{Tier: Readonly, Cmd: "_completion-names", AnySub: true, Sudoers: []string{"_completion-names *"}},
	// The login console asks for its settings once per session (console.go).
	{Tier: Readonly, Cmd: "_console-policy", AnySub: true, Sudoers: []string{"_console-policy"}},
	{Tier: Readonly, Cmd: "--version", AnySub: true},
	{Tier: Readonly, Cmd: "-v", AnySub: true},
	{Tier: Readonly, Cmd: "hash", AnySub: true},

	{Tier: Operator, Cmd: "log", Sub: "tail", Sudoers: []string{"log tail", "log tail *"}},
	{Tier: Operator, Cmd: "log", Sub: "search", Sudoers: []string{"log search *"}, Wrap: true},
	{Tier: Operator, Cmd: "log", Sub: "failures", Sudoers: []string{"log failures"}},
	{Tier: Operator, Cmd: "log", Sub: "accounting", Sudoers: []string{"log accounting", "log accounting *"}, Wrap: true},
	{Tier: Operator, Cmd: "config", Sub: "validate", Sudoers: []string{"config validate"}},
	{Tier: Operator, Cmd: "backup", Sub: "list", Sudoers: []string{"backup list"}, Wrap: true},
	{Tier: Operator, Cmd: "device", Sub: "check", Sudoers: []string{"device check *"}},
	{Tier: Operator, Cmd: "device", Sub: "scan", Sudoers: []string{"device scan", "device scan *"}},
	{Tier: Operator, Cmd: "device", Sub: "discover", Sudoers: []string{"device discover", "device discover *"}},
	{Tier: Operator, Cmd: "device", Sub: "export", Sudoers: []string{"device export", "device export *"}, Wrap: true},
	{Tier: Operator, Cmd: "console", Sub: "show", Sudoers: []string{"console show"}},
	{Tier: Operator, Cmd: "console", Sub: "check", Sudoers: []string{"console check"}},

	{Tier: Engineer, Cmd: "device", Sub: "add", Sudoers: []string{"device add *"}},
	{Tier: Engineer, Cmd: "device", Sub: "remove", Sudoers: []string{"device remove *"}},
	{Tier: Engineer, Cmd: "device", Sub: "rename", Sudoers: []string{"device rename *"}, Wrap: true},
	{Tier: Engineer, Cmd: "device", Sub: "address", Sudoers: []string{"device address *"}},
	{Tier: Engineer, Cmd: "device", Sub: "hostname", Sudoers: []string{"device hostname *"}},
	{Tier: Engineer, Cmd: "device", Sub: "vendor", Sudoers: []string{"device vendor *"}},
	{Tier: Engineer, Cmd: "device", Sub: "port", Sudoers: []string{"device port *"}, Wrap: true},
	{Tier: Engineer, Cmd: "device", Sub: "description", Sudoers: []string{"device description *"}},
	{Tier: Engineer, Cmd: "device", Sub: "location", Sudoers: []string{"device location *"}},
	{Tier: Engineer, Cmd: "device", Sub: "legacy-ssh", Sudoers: []string{"device legacy-ssh *"}},
	{Tier: Engineer, Cmd: "device", Sub: "hostkey", Sudoers: []string{"device hostkey *"}},
	// An engineer imports from standard input only: sudoers matches the
	// first argument, so 'device import /etc/shadow' never reaches tacctl.
	{Tier: Engineer, Cmd: "device", Sub: "import", Sudoers: []string{"device import -", "device import - *"}, Wrap: true},
	{Tier: Engineer, Cmd: "scope", Sub: "devices", Sudoers: []string{"scope devices *"}, Wrap: true},
	// 'device config show <name>' prints a device's walkthrough, secret and
	// all: the engineer's own scopes' devices (the verb sees to that).
	{Tier: Engineer, Cmd: "device", Sub: "config", Sudoers: []string{"device config", "device config show *"}},
	{Tier: Engineer, Cmd: "config", Sub: "cisco", Sudoers: []string{"config cisco", "config cisco *"}},
	{Tier: Engineer, Cmd: "config", Sub: "juniper", Sudoers: []string{"config juniper", "config juniper *"}},
	{Tier: Engineer, Cmd: "config", Sub: "wti", Sudoers: []string{"config wti", "config wti *"}, Wrap: true},
	// Engineers read the Linux hosts of their scopes and change nothing on
	// them: enrolling, syncing and the rest of host deployment are the
	// superuser's.
	{Tier: Engineer, Cmd: "host", Sub: "list", Sudoers: []string{"host list"}},
	{Tier: Engineer, Cmd: "host", Sub: "show", Sudoers: []string{"host show *"}, Wrap: true},
	{Tier: Engineer, Cmd: "scope", Sub: "staging", Sudoers: []string{"scope staging", "scope staging list"}},
	{Tier: Engineer, Cmd: "scope", Sub: "secret", Sudoers: []string{"scope secret *"}},
	// The scope's SNMP settings: an engineer reads their own scopes' ('show
	// [--reveal]', D45); the verb refuses every setter, clear and test.
	{Tier: Engineer, Cmd: "scope", Sub: "snmp", Sudoers: []string{"scope snmp *"}},
	{Tier: Engineer, Cmd: "scope", Sub: "show", Sudoers: []string{"scope show *"}},
}

// Permits is tier_permits: whether tier may run 'tacctl cmd sub'.
// Unrestricted and superuser may run anything, none nothing; readonly the
// Readonly rows, operator the Readonly and Operator rows, engineer all
// three kinds. 'help', '-h' and '--help' with nothing after them are
// Readonly rows: the usage is no secret.
func Permits(t Tier, cmd, sub string) bool {
	switch t {
	case Unrestricted, Superuser:
		return true
	case Readonly, Operator, Engineer:
	default:
		return false
	}
	for _, r := range Rules {
		if !Covers(t, r) {
			continue
		}
		if r.Cmd == cmd && (r.AnySub || r.Sub == sub) {
			return true
		}
	}
	return false
}

// Covers reports whether row r is open to tier t (a lower tier's rows are
// open to the tiers above it).
func Covers(t Tier, r Rule) bool {
	return rank(t) >= rank(r.Tier) && rank(r.Tier) >= 0
}

// Binary is the command path the drop-in names (the installed tacctl).
const Binary = "/usr/local/bin/tacctl"

// EnvKeep is the sudoers line both drop-ins carry: 'tacctl host' runs ssh
// as the invoking user (a superuser enrols and syncs hosts; 'tacctl ssh' of
// every tier opens a session with the caller's own keys) and needs their
// agent socket, which sudo's env_reset would drop. env_keep lets that one
// variable through (from the caller's environment, or as
// 'SSH_AUTH_SOCK=...' on the sudo command line) and nothing else; the rules
// carry no SETENV tag, which would let a caller set any variable, SUDO_USER
// among them, and so pose as someone else to the tier gate. The second
// name is the login console's marker (TACCTL_CONSOLE=<session>, a command-
// line assignment on each of its lines); it is only ever read by tacctl, to
// tighten what it does, never to widen it. The third is the X11 display
// sshd's forwarding sets ('tacctl ssh -X' hands it to the ssh it runs as
// the caller; tacctl checks its shape first).
const EnvKeep = "Defaults!" + Binary + " env_keep += \"SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY\"\n"

// Sudoers is emit_tier_sudoers: the per-tier drop-in, byte for byte.
func Sudoers() string {
	var b strings.Builder
	b.WriteString("# Managed by tacctl. Per-tier access for tacctl users with local accounts.\n")
	b.WriteString("# Remove with: tacctl config sudoers tiers remove\n")
	for _, a := range []struct {
		name string
		tier Tier
	}{{"TACCTL_RO", Readonly}, {"TACCTL_OP", Operator}, {"TACCTL_EN", Engineer}} {
		var lines [][]string
		var cur []string
		for _, r := range Rules {
			if r.Tier != a.tier || len(r.Sudoers) == 0 {
				continue
			}
			for _, p := range r.Sudoers {
				cur = append(cur, Binary+" "+p)
			}
			if r.Wrap {
				lines, cur = append(lines, cur), nil
			}
		}
		if len(cur) > 0 {
			lines = append(lines, cur)
		}
		for i, l := range lines {
			if i == 0 {
				b.WriteString("Cmnd_Alias " + a.name + " = ")
			} else {
				b.WriteString("    ")
			}
			b.WriteString(strings.Join(l, ", "))
			if i < len(lines)-1 {
				b.WriteString(", \\")
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(EnvKeep)
	b.WriteString("%" + SuperuserGroup + " ALL=(ALL:ALL) ALL\n")
	b.WriteString("%" + SuperuserGroup + " ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP, TACCTL_EN\n")
	// Engineers get tacctl's own verbs and nothing else on this server: no
	// '(ALL:ALL) ALL' line, here or in the host drop-in the client script
	// writes (it leaves tac-engineer out on the tacctl server, TAC_LOCAL=1).
	b.WriteString("%" + EngineerGroup + " ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP, TACCTL_EN\n")
	b.WriteString("%" + OperatorGroup + " ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP\n")
	b.WriteString("%" + ReadonlyGroup + " ALL=(root) NOPASSWD: TACCTL_RO\n")
	return b.String()
}

// Gate is enforce_tier for one invocation.
type Gate struct {
	Runner execx.Runner
	Out    ui.Output
	// SudoUser is SUDO_USER: the person behind sudo ("" or "root": none).
	SudoUser string
	// SudoUID is SUDO_UID: when set, SudoUser must name its account
	// (VerifyCaller), or the caller is denied everything.
	SudoUID string
	// PrivLvl is model_user_privlvl: the priv-lvl of the user's group, ""
	// when the user is unknown or disabled or the model cannot be read. It
	// is asked only for a managed caller.
	PrivLvl func(user string) string
	// GroupTier is the tier set on the user's group (policy.GroupTier; ""
	// when none is set, or nil: the priv-lvl band decides). It is asked
	// only for a managed caller with a priv-lvl.
	GroupTier func(user string) string
	// ConfProblem is why tacctl.yaml cannot be read ("" when it can; nil:
	// never). The tier settings in it are then unknown, so no managed
	// caller is trusted above the operator tier, which still allows 'config
	// validate' and 'console check' to diagnose it. Root and the
	// unrestricted caller are not affected.
	ConfProblem func() string
	// AmbiguousGroup is the name of the user's group when that group is a
	// group other than the built-in superuser at priv-lvl 15 or more with no
	// tier setting in
	// tacctl.yaml ("" otherwise, or nil: never): its tier cannot be told
	// from a superuser group that lost its setting, so its members are held
	// at the operator tier (asked only for a managed caller above it).
	// Members of the built-in superuser group, and everyone else, are not
	// affected: a superuser keeps the tier verbs that repair the setting.
	AmbiguousGroup func(user string) string
	// ConfPath is the path of tacctl.yaml, for the denial.
	ConfPath string
}

// ErrDenied is Enforce's refusal; its message has been written (exit 1).
var ErrDenied = errors.New("tier: command denied")

// ErrCallerMismatch is VerifyCaller's refusal: SUDO_USER does not name the
// account of SUDO_UID.
var ErrCallerMismatch = errors.New("SUDO_USER does not name the account of SUDO_UID")

// VerifyCaller checks that user (SUDO_USER) is the account of uid
// (SUDO_UID). sudo sets both from the invoking user; the sudoers rules
// tacctl writes let no caller set either, but a rule elsewhere with SETENV
// (or one that matches ALL) would let a caller name somebody else in
// SUDO_USER, and tacctl acts on SUDO_USER: the tier gate, the user 'tacctl
// ssh' and 'host' run ssh as. Forging the pair takes both variables, so the
// passwd entry of SUDO_UID ('getent passwd <uid>', NSS included) must name
// SUDO_USER. No uid (tacctl run as root outside sudo) is not checked; a uid
// that is not a number, or whose account cannot be looked up, is refused.
func VerifyCaller(ctx context.Context, r execx.Runner, user, uid string) error {
	if uid == "" {
		return nil
	}
	if !reDigits.MatchString(uid) {
		return ErrCallerMismatch
	}
	res, err := r.Run(ctx, execx.Cmd{Name: "getent", Args: []string{"passwd", uid}})
	if err != nil || res.Code != 0 {
		return ErrCallerMismatch
	}
	line, _, _ := strings.Cut(string(res.Stdout), "\n")
	f := strings.Split(line, ":")
	if len(f) < 3 || f[2] != uid || f[0] != user {
		return ErrCallerMismatch
	}
	return nil
}

// Caller is caller_tier. A SUDO_USER that VerifyCaller refuses is None.
func (g Gate) Caller(ctx context.Context) Tier {
	if g.verify(ctx) != nil {
		return None
	}
	t, _, _ := g.capped(ctx)
	return t
}

// EngineerBound reports whether the caller is an engineer whatever the cap
// of an unreadable tacctl.yaml makes of its tier: the tier without the cap
// is engineer, or the account is a member of tac-engineer (a sync put it
// there). The console keeps its system shell and forwarding closed to such
// a caller (D18); the cap lowers what the gate permits, never what an
// engineer's login can do.
func (g Gate) EngineerBound(ctx context.Context) bool {
	if g.verify(ctx) != nil {
		return false
	}
	if _, uncapped, _ := g.capped(ctx); uncapped == Engineer {
		return true
	}
	caller := g.SudoUser
	if caller == "" || caller == "root" {
		return false
	}
	res, err := g.Runner.Run(ctx, execx.Cmd{Name: "id", Args: []string{"-nG", "--", caller}})
	if err != nil || res.Code != 0 {
		return false
	}
	return slices.Contains(strings.Fields(string(res.Stdout)), EngineerGroup)
}

func (g Gate) verify(ctx context.Context) error {
	return VerifyCaller(ctx, g.Runner, g.SudoUser, g.SudoUID)
}

// Why a caller is capped at the operator tier (capped's third result).
const (
	capNone      = ""
	capConf      = "conf-problem"
	capAmbiguous = "group-ambiguous"
)

// capped is the caller's tier with the cap applied (an unreadable
// tacctl.yaml caps every managed caller; a group whose tier setting is
// lost caps its members), the tier it would have without the cap, and why
// it was capped.
func (g Gate) capped(ctx context.Context) (t, uncapped Tier, why string) {
	t = g.caller(ctx)
	if rank(t) > rank(Operator) {
		if g.ConfProblem != nil && g.ConfProblem() != "" {
			return Operator, t, capConf
		}
		if g.AmbiguousGroup != nil && g.AmbiguousGroup(g.SudoUser) != "" {
			return Operator, t, capAmbiguous
		}
	}
	return t, t, capNone
}

func (g Gate) caller(ctx context.Context) Tier {
	caller := g.SudoUser
	if caller == "" || caller == "root" {
		return Unrestricted
	}
	// 'id -nG -- <caller>': a failure is "not a member", as in bash.
	res, err := g.Runner.Run(ctx, execx.Cmd{Name: "id", Args: []string{"-nG", "--", caller}})
	if err != nil || res.Code != 0 {
		return Unrestricted
	}
	member := false
	for _, grp := range strings.Fields(string(res.Stdout)) {
		member = member || grp == UsersGroup
	}
	if !member {
		return Unrestricted
	}
	if !reCaller.MatchString(caller) {
		return None
	}
	lvl := ""
	if g.PrivLvl != nil {
		lvl = g.PrivLvl(caller)
	}
	set := ""
	if g.GroupTier != nil && ForPrivLvl(lvl) != None {
		set = g.GroupTier(caller)
	}
	return ForGroup(set, lvl)
}

// Enforce is enforce_tier <cmd> <sub>: nil when the caller's tier permits
// the command; otherwise the denial is logged ('logger -t tacctl -p
// auth.warning'), printed, and ErrDenied returned.
//
// A SUDO_USER that VerifyCaller refuses is denied every command, logged
// with the uid ('tier DENY user=<SUDO_USER> uid=<SUDO_UID>
// reason=sudo-user-mismatch').
func (g Gate) Enforce(ctx context.Context, cmd, sub string) error {
	user := g.SudoUser
	if user == "" {
		user = "root"
	}
	if g.verify(ctx) != nil {
		_, _ = g.Runner.Run(ctx, execx.Cmd{Name: "logger", Args: []string{"-t", "tacctl", "-p", "auth.warning",
			"tier DENY user=" + user + " uid=" + g.SudoUID + " reason=sudo-user-mismatch cmd=" + cmd + " " + sub}})
		g.Out.ErrorE("SUDO_USER '" + g.SudoUser + "' is not the account of SUDO_UID " + g.SudoUID + ", so tacctl access is denied.")
		return ErrDenied
	}
	t, uncapped, why := g.capped(ctx)
	if Permits(t, cmd, sub) {
		return nil
	}
	// The cap is the reason only when the tier without it would have run
	// the command.
	byCap := t != uncapped && Permits(uncapped, cmd, sub)
	reason := ""
	if byCap {
		reason = " reason=" + why
	}
	_, _ = g.Runner.Run(ctx, execx.Cmd{Name: "logger", Args: []string{"-t", "tacctl", "-p", "auth.warning",
		"tier DENY user=" + user + " tier=" + string(t) + reason + " cmd=" + cmd + " " + sub}})
	if byCap && why == capAmbiguous {
		grp := g.AmbiguousGroup(g.SudoUser)
		g.Out.ErrorE("'tacctl " + cmd + " " + sub + "' is not permitted: your group '" + grp + "' is at priv-lvl 15 or more and has no tier setting in " +
			g.ConfPath + " (it was lost), so its members are held at the operator tier. A superuser who is not a member sets it: tacctl group edit " +
			grp + " tier <tier>.")
	} else if byCap {
		g.Out.ErrorE("'tacctl " + cmd + " " + sub + "' is not permitted: " + g.ConfPath + " cannot be read (" + g.ConfProblem() +
			"), so no tacctl user is trusted above the operator tier until it is fixed (tacctl config validate).")
	} else if t == None {
		g.Out.ErrorE("'" + g.SudoUser + "' has no active tacctl user, so tacctl access is denied.")
	} else {
		g.Out.ErrorE("'tacctl " + cmd + " " + sub + "' is not permitted for the " + string(t) + " tier.")
	}
	return ErrDenied
}
