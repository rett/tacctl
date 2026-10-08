package cli

// The 'config' family (lib/dispatch.sh cmd_config at 0.1.16). Native since
// WP2.4c: show, validate, render (and the new 'render --dry-run --out',
// docs/plans/go-rewrite.md 3.9 item 8), dump, defaults, get, get-list,
// loglevel, listen, metrics, sudoers [tiers], password-age, bcrypt-cost,
// password-min-length, secret-min-length and branch (config_report.go:
// show and validate; config_admin.go: sudoers, branch, render --dry-run).
//
// Registered from other files with registerConfigVerb (below), which
// replaces the declared word of the same name: diff and restore
// (backup.go), allow, deny and mgmt-acl (config_policy_register.go),
// cisco, juniper and wti (devices.go), linux (linux.go). Every config verb
// is native; the family node, its usage and its preflight rule stay here.

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
)

// KindListeners is the _completion-names kind of listener names
// ('_completion-names listeners [<backend>]').
const KindListeners = "listeners"

// configVerbs are the native 'config' verbs that other files of this
// package register (registerConfigVerb), by name.
var configVerbs = map[string]func(inv *invocation) *cobra.Command{}

// registerConfigVerb makes 'config <name>' native with the command mk
// builds, in place of the declared word of that name (or as a new verb),
// and spec its arguments for completion (configSpecs). Call it from an
// init function of the file that implements the verb; mk gives the command
// (and its sub-commands) RunEs made with inv.native (withPreflight:
// bin/tacctl.sh runs preflight before every 'config' verb but render).
func registerConfigVerb(name string, spec Spec, mk func(inv *invocation) *cobra.Command) {
	configVerbs[name] = mk
	configSpecs[name] = spec
}

// configSpecs are the arguments of the native verbs, for completion
// (args.go). The verbs parse their own arguments the way cmd_config's
// helpers do (extra arguments are mostly ignored); these say what can be
// completed.
var configSpecs = map[string]Spec{
	"show":     {MaxArgs: -1},
	"validate": {MaxArgs: -1},
	"render": {MaxArgs: 0, Flags: []Flag{
		{Names: []string{"--force"}}, {Names: []string{"--dry-run"}}, {Names: []string{"--out"}, Value: true, Kind: KindFile}}},
	"dump":     {MaxArgs: -1},
	"defaults": {MaxArgs: -1},
	"get":      {MinArgs: 1, MaxArgs: 2, Args: []string{configPaths}},
	"get-list": {MinArgs: 1, MaxArgs: 1, Args: []string{configPaths}},
	"loglevel": {MaxArgs: 1, Args: []string{"debug|info|error"}},
	"listen": {MaxArgs: 2, Args: []string{"show|reset|tcp|tcp6|udp|udp6", ""}, Flags: []Flag{
		{Names: []string{"--backend"}, Value: true, Kind: "backends"},
		{Names: []string{"--listener"}, Value: true, Kind: KindListeners}}},
	"metrics":             {MaxArgs: 2, Args: []string{"show|enable|disable|address|reset", ""}},
	"sudoers":             {MaxArgs: 2, Args: []string{"show|install|remove|tiers", ""}},
	"password-age":        {MaxArgs: 1},
	"bcrypt-cost":         {MaxArgs: 1, Args: []string{"10|11|12|13|14"}},
	"password-min-length": {MaxArgs: 1},
	"secret-min-length":   {MaxArgs: 1},
	"branch":              {MaxArgs: 1},
}

func configCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	// sub is a sub-command word of a native verb: it runs the verb with
	// itself in front of the rest, as the verb's own case statement sees it.
	sub := func(name, short string, run func([]string) error, subs ...*cobra.Command) *cobra.Command {
		c := verb(name, short, subs...)
		c.RunE = n(func(args []string) error { return run(append([]string{name}, args...)) })
		return c
	}
	filter := func(name, short string) *cobra.Command {
		return verb(name, short,
			verb("list", "Show the list"),
			verb("add", "Add one or more CIDRs"),
			verb("remove", "Remove one or more CIDRs"),
			verb("clear", "Wipe all (confirms)"),
		)
	}
	metrics := inv.configMetrics
	tiers := func(args []string) error { return inv.configSudoers(append([]string{"tiers"}, args...)) }
	c := verb("config <subcommand>", "Configuration (show, render, cisco, juniper, wti, validate, ...)",
		withRun(verb("show", "Show current configuration"), n(inv.configShow)),
		withRun(verb("dump", "Show tacctl defaults + overrides + merged view"), n(inv.configDump)),
		withRun(verb("defaults", "Print canonical tacctl defaults (shipped)"), n(func([]string) error {
			inv.write(conf.DefaultsText)
			return nil
		})),
		withRun(verb("get <path> [fallback]", "Read a dotted-path value from the merged config"), n(inv.configGet)),
		withRun(verb("get-list <path>", "Read a list value (one item per line)"), n(inv.configGetList)),
		withRun(verb("validate", "Validate config syntax and structure"), n(inv.configValidate)),
		// 'config render' rebuilds the artifacts from the store: with a
		// store it runs no preflight, which would warn that the file it is
		// about to write is missing (bin/tacctl.sh).
		withRun(verb("render [--force] | --dry-run --out <dir>", "Regenerate every enabled backend's config from the store"),
			inv.native(noPreflight, func(args []string) error {
				if !cfgIsFile(inv.app.Paths.StoreFile) {
					if err := inv.app.Preflight(); err != nil {
						return err
					}
				}
				return inv.configRender(args)
			})),
		verb("diff", "Diff store.yaml and tacctl.yaml vs the last snapshot (or named one)"),
		verb("restore", "Restore a snapshot (prompts for confirmation)"),
		withRun(verb("loglevel [debug|info|error]", "Show or change log level"), n(inv.configLoglevel)),
		withRun(verb("listen [--backend <id>] [--listener <name>] [show|reset|<network> <address>]",
			"Show, change, or reset a listen address"), n(inv.configListen)),
		withRun(verb("metrics [show|enable|disable|address <host:port>|reset]", "Prometheus exporter control",
			sub("show", "Show the exporter's state", metrics),
			sub("enable", "Enable the exporter", metrics),
			sub("disable", "Disable the exporter", metrics),
			sub("address", "Set the exporter's address", metrics),
			sub("reset", "Reset the exporter's address", metrics),
		), n(metrics)),
		withRun(verb("sudoers [show|install [group]|remove|tiers ...]", "Manage NOPASSWD sudoers drop-in for tacctl",
			sub("show", "Show the drop-in", inv.configSudoers),
			sub("install", "Install the drop-in (confirms)", inv.configSudoers),
			sub("remove", "Remove the drop-in", inv.configSudoers),
			sub("tiers", "Manage per-tier (RO/OP/SU) sudoers rules", func(args []string) error { return inv.configSudoers(args) },
				sub("show", "Show the tier rules", tiers),
				sub("install", "Install the tier rules", tiers),
				sub("remove", "Remove the tier rules", tiers),
			),
		), n(inv.configSudoers)),
		withRun(verb("password-age [days]", "Show or set password age warning threshold"), n(inv.configPasswordAge)),
		withRun(verb("bcrypt-cost [10-14]", "Show or set bcrypt cost factor (default 12)"), n(inv.configBcryptCost)),
		withRun(verb("password-min-length [8-64]", "Show or set minimum interactive password length (default 12)"),
			n(inv.configPasswordMinLength)),
		withRun(verb("secret-min-length [16-128]", "Show or set minimum shared-secret length (default 16)"),
			n(inv.configSecretMinLength)),
		filter("allow", "Manage connection allow list"),
		filter("deny", "Manage connection deny list"),
		verb("mgmt-acl", "Manage Cisco VTY-ACL + Juniper lo0-filter permits",
			verb("list", "Show current permits"),
			verb("add", "Add one or more CIDRs"),
			verb("remove", "Remove one or more CIDRs"),
			verb("clear", "Wipe all permits (confirms)"),
			verb("cisco-name", "Show or set the Cisco ACL name"),
			verb("juniper-name", "Show or set the Juniper filter name"),
		),
		verb("cisco", "Show working Cisco device configuration for a scope"),
		verb("juniper", "Show working Juniper device configuration for a scope"),
		verb("wti", "Show step-by-step WTI console-server setup for a scope"),
		verb("linux", "TACACS+ or RADIUS login for Linux hosts (install/removal scripts)",
			verb("build", "Fetch and prepare the pinned pam_tacplus source"),
			verb("script", "Write the install script for hosts in a scope"),
			verb("remove-script", "Write the removal script"),
			verb("uid", "Show or change the UID a user gets on every host"),
			verb("uid-range", "Show or change the UID range of all hosts (default 80000-89999)"),
			verb("engineer-sudo", "Show or limit what engineers may run through sudo on enrolled hosts"),
			verb("builds", "Show or drop the modules 'host enroll' built in containers"),
		),
		withRun(verb("branch [name]", "Show or change the tacctl repo branch"), n(inv.configBranch)),
	)
	// The verbs other files register replace the declared words.
	names := make([]string, 0, len(configVerbs))
	for name := range configVerbs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if old := child(c, name); old != nil {
			c.RemoveCommand(old)
		}
		c.AddCommand(configVerbs[name](inv))
	}
	// No sub-command, or one cmd_config does not have: the usage, exit 1,
	// with no error line.
	c.RunE = n(func([]string) error {
		inv.write(configUsage())
		return exit(1)
	})
	return c
}

// configUsage is cmd_config's usage block.
func configUsage() string { return Usage("config", nil) }

// --- dump, get, get-list ----------------------------------------------------

func (inv *invocation) configDump([]string) error { return inv.app.Conf().Dump(inv.app.Out.Stdout) }

// configGet is 'conf_get "$@"' after the path check: the value (or the
// fallback) and a newline, nothing for a list or a mapping.
func (inv *invocation) configGet(args []string) error {
	if arg(args, 0) == "" {
		return inv.usageErr("Usage: tacctl config get <dotted.path> [fallback]")
	}
	if text, printed := inv.app.Conf().Get(args[0], arg(args, 1)); printed {
		inv.write(text + "\n")
	}
	return nil
}

// configGetList is 'conf_get_list "$@"': one item per line.
func (inv *invocation) configGetList(args []string) error {
	if arg(args, 0) == "" {
		return inv.usageErr("Usage: tacctl config get-list <dotted.path>")
	}
	for _, item := range inv.app.Conf().GetList(args[0]) {
		inv.write(item + "\n")
	}
	return nil
}

// --- the four tunables (lib/conf.sh cmd_config_password_age ...) -----------

// configTunable shows a tunable (show: the lines between the blank lines)
// when no value is given, else sets path to it and says so (done, through
// 'info', whose echo -e interprets the value's escapes).
func (inv *invocation) configTunable(args []string, path string, show []string, done string) error {
	v := arg(args, 0)
	if v == "" {
		inv.echo("")
		for _, l := range show {
			inv.echo(l)
		}
		inv.echo("")
		return nil
	}
	if err := inv.app.Conf().Set(path, v); err != nil {
		return err
	}
	inv.app.Out.InfoE(strings.ReplaceAll(done, "%v", v))
	inv.echo("")
	return nil
}

func (inv *invocation) configPasswordAge(args []string) error {
	t := inv.app.Tunables()
	return inv.configTunable(args, "password.max_age_days", []string{
		"  Password age warning threshold: " + strconv.Itoa(t.PasswordMaxAgeDays) + " days",
		"",
		"  Usage: tacctl config password-age <days>",
	}, "Password age warning threshold set to %v days.")
}

func (inv *invocation) configBcryptCost(args []string) error {
	t := inv.app.Tunables()
	return inv.configTunable(args, "bcrypt.cost", []string{
		"  Bcrypt cost factor: " + strconv.Itoa(t.BcryptCost),
		"  (New hashes only — existing hashes keep their minted cost.)",
		"",
		"  Usage: tacctl config bcrypt-cost <10-14>",
		"  Typical wall-clock on a modern CPU: 10≈100ms, 12≈300ms, 14≈1.2s",
	}, "Bcrypt cost set to %v. Applies to new/changed passwords.")
}

func (inv *invocation) configPasswordMinLength(args []string) error {
	t := inv.app.Tunables()
	return inv.configTunable(args, "password.min_length", []string{
		"  Password minimum length: " + strconv.Itoa(t.PasswordMinLength),
		"  (Enforced on interactively-entered passwords; auto-generated bypass.)",
		"",
		"  Usage: tacctl config password-min-length <8-64>",
		"  Guidance: NIST 800-63 floor is 8; OWASP 2025 recommends ≥12.",
	}, "Password minimum length set to %v. Applies to new/changed passwords.")
}

func (inv *invocation) configSecretMinLength(args []string) error {
	t := inv.app.Tunables()
	return inv.configTunable(args, "secret.min_length", []string{
		"  Shared-secret minimum length: " + strconv.Itoa(t.SecretMinLength),
		"  (Enforced on user-supplied secrets; auto-generated bypass.)",
		"",
		"  Usage: tacctl config secret-min-length <16-128>",
		"  Guidance: Cisco TACACS+ best practice is ≥16.",
	}, "Shared-secret minimum length set to %v. Applies to new secrets.")
}

// --- loglevel and metrics (the TACACS+ backend's settings) ------------------

// tacacsSettings is what the TACACS+ module offers for 'config loglevel'
// and 'config metrics' (internal/backend/tacacs).
type tacacsSettings interface {
	LogLevel(ctx context.Context, level string) error
	Metrics(ctx context.Context, sub, arg string) error
}

// tacacsBackend is the TACACS+ module, for its settings commands.
func (inv *invocation) tacacsBackend() (tacacsSettings, error) {
	b, err := inv.app.Backends().Get(backend.TACACS)
	if err != nil {
		return nil, err
	}
	s, ok := b.(tacacsSettings)
	if !ok {
		return nil, &backend.UnknownError{ID: backend.TACACS}
	}
	return s, nil
}

// configLoglevel is cmd_config_loglevel. An unknown level is refused here,
// through 'error' (echo -e), before the module is asked.
func (inv *invocation) configLoglevel(args []string) error {
	level := arg(args, 0)
	switch level {
	case "", "debug", "info", "error":
	default:
		return inv.usageErr("Invalid level: " + level + ". Use: debug, info, or error")
	}
	b, err := inv.tacacsBackend()
	if err != nil {
		return err
	}
	return b.LogLevel(inv.ctx, level)
}

// configMetrics is cmd_config_metrics. An unknown subcommand is refused
// here, through 'error' (echo -e), before the module is asked.
func (inv *invocation) configMetrics(args []string) error {
	sub := arg(args, 0)
	switch sub {
	case "", "show", "-h", "--help", "help", "enable", "disable", "address", "reset":
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl config metrics' with no arguments for usage.")
	}
	b, err := inv.tacacsBackend()
	if err != nil {
		return err
	}
	return b.Metrics(inv.ctx, sub, arg(args, 1))
}

// --- listen (lib/backend.sh cmd_config_listen) ------------------------------

var reListenerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// configListen is cmd_config_listen: [--backend <id>] [--listener <name>]
// [show|reset|<network> <address>], the TACACS+ default listener without
// flags. Any other word, a dash-word included, is a positional.
func (inv *invocation) configListen(args []string) error {
	a := inv.app
	id, listener := backend.TACACS, "default"
	var rest []string
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == "--backend" || w == "--listener":
			if arg(args, i+1) == "" {
				return inv.usageErr(w + " needs a value. Usage: tacctl config listen [--backend <id>] [--listener <name>] <show|<network> <address>|reset>")
			}
			if w == "--backend" {
				id = args[i+1]
			} else {
				listener = args[i+1]
			}
			i++
		case strings.HasPrefix(w, "--backend="):
			id = strings.TrimPrefix(w, "--backend=")
		case strings.HasPrefix(w, "--listener="):
			listener = strings.TrimPrefix(w, "--listener=")
		default:
			rest = append(rest, w)
		}
	}
	set := a.Backends()
	if !slices.Contains(set.IDs(), id) {
		return inv.usageErr("Unknown backend '" + id + "' (known: " + strings.Join(set.IDs(), " ") + ").")
	}
	if !reListenerName.MatchString(listener) {
		return inv.usageErr("Invalid listener name '" + listener + "': a lowercase letter, then up to 31 of [a-z0-9_-].")
	}
	b, err := set.Get(id)
	if err != nil {
		return err
	}
	ops := b.Listeners()
	switch sub := arg(rest, 0); sub {
	case "", "show":
		shown, err := ops.Show(inv.ctx, listener)
		if err != nil {
			return err
		}
		inv.echo("")
		inv.echo(strings.TrimRight(shown, "\n"))
		inv.echo("")
		if id != backend.TACACS {
			// Another backend's networks and listener names are its own.
			inv.echo("  Usage: tacctl config listen --backend " + id + " --listener <name> <network> <address>")
			inv.echo("         tacctl config listen --backend " + id + " --listener <name> reset")
			inv.echo("")
			return nil
		}
		inv.write(`  Usage: tacctl config listen <show|tcp|tcp6|reset> [address]
  Examples:
    tacctl config listen tcp :49
    tacctl config listen tcp 10.1.0.1:49
    tacctl config listen tcp6 [::]:49
    tacctl config listen reset       # drop override, use template default

`)
		return nil
	case "reset":
		return ops.Reset(inv.ctx, listener)
	default:
		// A network and an address; the backend says which networks it has.
		return ops.Set(inv.ctx, listener, sub, arg(rest, 1))
	}
}

// listenerNames is '_completion-names listeners [<backend>]'
// (_completion_listeners): the listener names of the backends named
// (blank-separated; every registered one when none is), sorted, each once.
// Best effort: an unknown backend or one whose listeners cannot be read
// adds nothing.
func (inv *invocation) listenerNames(args []string) []string {
	set := inv.app.Backends()
	ids := strings.Fields(arg(args, 0))
	if len(ids) == 0 {
		ids = set.IDs()
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		b, err := set.Get(id)
		if err != nil {
			continue
		}
		ls, err := b.Listeners().List()
		if err != nil {
			continue
		}
		for _, l := range ls {
			if l.Name != "" && !seen[l.Name] {
				seen[l.Name] = true
				out = append(out, l.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// --- render -------------------------------------------------------------------

// configRender is cmd_config_render: 'render' or 'render --force', and
// nothing else; '--dry-run' (anywhere) is the new preview
// (configRenderDryRun).
func (inv *invocation) configRender(args []string) error {
	if slices.Contains(args, "--dry-run") {
		return inv.configRenderDryRun(args)
	}
	force := false
	switch arg(args, 0) {
	case "":
	case "--force":
		force = true
	default:
		return inv.usageErr("Usage: tacctl config render [--force]")
	}
	if len(args) > 1 {
		return inv.usageErr("Usage: tacctl config render [--force]")
	}
	return inv.app.Backends().ConfigRender(inv.ctx, force)
}
