// Package tier is the caller-tier gate of lib/dispatch.sh (0.1.16):
// caller_tier, tier_permits, enforce_tier, and emit_tier_sudoers, the
// sudoers drop-in that grants the same commands. tacctl always runs as
// root, so the tier of the person behind sudo is enforced here as well as
// in that drop-in: sudoers argument globs are loose, this gate is not.
//
// Only callers in the local group tac-users are tier-managed (the accounts
// tacctl provisions for its users); everyone else who reaches tacctl (root,
// a local admin with sudo) is unrestricted. A managed caller's tier comes
// from the model (the user's group's priv-lvl), never from local group
// membership.
//
// The gate and the sudoers rules are one table (Rules): Permits reads it,
// Sudoers prints it, so the two cannot disagree. A new read-only verb is
// one row.
package tier

import (
	"context"
	"errors"
	"regexp"
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
	SuperuserGroup = "tac-superuser"
)

// Tier is a caller's tier.
type Tier string

// The tiers. None is a tier-managed caller with no usable tacctl user
// (unknown or disabled), denied everything.
const (
	Unrestricted Tier = "unrestricted"
	Superuser    Tier = "superuser"
	Operator     Tier = "operator"
	Readonly     Tier = "readonly"
	None         Tier = "none"
)

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
	// operators too.
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
// that prints a shared secret or a password hash (config
// cisco|juniper|wti, scope secret, backup diff, config dump, store show) is
// superuser-only, as is scope show (it gives the secret's length) and
// everything that changes anything. The order is the drop-in's.
var Rules = []Rule{
	{Tier: Readonly, Cmd: "", AnySub: true, Sudoers: []string{`""`}},
	{Tier: Readonly, Cmd: "passwd", AnySub: true, Sudoers: []string{"passwd"}},
	{Tier: Readonly, Cmd: "status", AnySub: true, Sudoers: []string{"status"}},
	{Tier: Readonly, Cmd: "version", AnySub: true, Sudoers: []string{"version"}, Wrap: true},
	{Tier: Readonly, Cmd: "user", Sub: "list", Sudoers: []string{"user list"}},
	{Tier: Readonly, Cmd: "user", Sub: "show", Sudoers: []string{"user show *"}},
	{Tier: Readonly, Cmd: "group", Sub: "list", Sudoers: []string{"group list"}},
	{Tier: Readonly, Cmd: "scope", Sub: "list", Sudoers: []string{"scope list"}, Wrap: true},
	{Tier: Readonly, Cmd: "backend", Sub: "list", Sudoers: []string{"backend list"}},
	{Tier: Readonly, Cmd: "backend", Sub: "status", Sudoers: []string{"backend status", "backend status *"}, Wrap: true},
	{Tier: Readonly, Cmd: "_completion-names", AnySub: true, Sudoers: []string{"_completion-names *"}},
	{Tier: Readonly, Cmd: "--version", AnySub: true},
	{Tier: Readonly, Cmd: "-v", AnySub: true},
	{Tier: Readonly, Cmd: "hash", AnySub: true},

	{Tier: Operator, Cmd: "log", Sub: "tail", Sudoers: []string{"log tail", "log tail *"}},
	{Tier: Operator, Cmd: "log", Sub: "search", Sudoers: []string{"log search *"}, Wrap: true},
	{Tier: Operator, Cmd: "log", Sub: "failures", Sudoers: []string{"log failures"}},
	{Tier: Operator, Cmd: "log", Sub: "accounting", Sudoers: []string{"log accounting", "log accounting *"}, Wrap: true},
	{Tier: Operator, Cmd: "config", Sub: "validate", Sudoers: []string{"config validate"}},
	{Tier: Operator, Cmd: "backup", Sub: "list", Sudoers: []string{"backup list"}},
}

// Permits is tier_permits: whether tier may run 'tacctl cmd sub'.
// Unrestricted and superuser may run anything, none nothing; readonly the
// Readonly rows, operator both kinds. ('help' is in no row: a tier user
// running 'tacctl help' is denied before the usage, as in 0.1.16.)
func Permits(t Tier, cmd, sub string) bool {
	switch t {
	case Unrestricted, Superuser:
		return true
	case Readonly, Operator:
	default:
		return false
	}
	for _, r := range Rules {
		if r.Tier == Operator && t != Operator {
			continue
		}
		if r.Cmd == cmd && (r.AnySub || r.Sub == sub) {
			return true
		}
	}
	return false
}

// Binary is the command path the drop-in names (the installed tacctl).
const Binary = "/usr/local/bin/tacctl"

// Sudoers is emit_tier_sudoers: the per-tier drop-in, byte for byte.
func Sudoers() string {
	var b strings.Builder
	b.WriteString("# Managed by tacctl. Per-tier access for tacctl users with local accounts.\n")
	b.WriteString("# Remove with: tacctl config sudoers tiers remove\n")
	for _, a := range []struct {
		name string
		tier Tier
	}{{"TACCTL_RO", Readonly}, {"TACCTL_OP", Operator}} {
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
	b.WriteString("%" + SuperuserGroup + " ALL=(ALL:ALL) ALL\n")
	b.WriteString("%" + SuperuserGroup + " ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP\n")
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
	// PrivLvl is model_user_privlvl: the priv-lvl of the user's group, ""
	// when the user is unknown or disabled or the model cannot be read. It
	// is asked only for a managed caller.
	PrivLvl func(user string) string
}

// ErrDenied is Enforce's refusal; its message has been written (exit 1).
var ErrDenied = errors.New("tier: command denied")

// Caller is caller_tier.
func (g Gate) Caller(ctx context.Context) Tier {
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
	return ForPrivLvl(lvl)
}

// Enforce is enforce_tier <cmd> <sub>: nil when the caller's tier permits
// the command; otherwise the denial is logged ('logger -t tacctl -p
// auth.warning'), printed, and ErrDenied returned.
func (g Gate) Enforce(ctx context.Context, cmd, sub string) error {
	t := g.Caller(ctx)
	if Permits(t, cmd, sub) {
		return nil
	}
	user := g.SudoUser
	if user == "" {
		user = "root"
	}
	_, _ = g.Runner.Run(ctx, execx.Cmd{Name: "logger", Args: []string{"-t", "tacctl", "-p", "auth.warning",
		"tier DENY user=" + user + " tier=" + string(t) + " cmd=" + cmd + " " + sub}})
	if t == None {
		g.Out.ErrorE("'" + g.SudoUser + "' has no active tacctl user, so tacctl access is denied.")
	} else {
		g.Out.ErrorE("'tacctl " + cmd + " " + sub + "' is not permitted for the " + string(t) + " tier.")
	}
	return ErrDenied
}
