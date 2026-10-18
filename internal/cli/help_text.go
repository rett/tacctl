// Code generated from the 0.1.16 bash usage text by a one-off script; the
// text is maintained by hand from here on, and help_test.go holds it to
// testdata/usage (written by tests/tools/usage-goldens.sh from the 0.1.16
// tag). DO NOT reformat: every byte is part of the CLI contract.

package cli

// usageBlocks are the usage texts of the bash implementation (0.1.16), as
// printed to stdout, verbatim. <b> and </b> stand for the bold and reset
// escapes, <o> and </o> for cyan and reset (an option name or a
// placeholder; the markers only wrap text that is there, so the plain bytes
// are the 0.1.16 ones); {{name}} is a value the command fills in (Usage).
var usageBlocks = map[string]string{
	// lib/dispatch.sh usage
	"top": `
<b>tacctl</b> ({{version}}) — Pluggable network-device AAA management
Copyright (c) 2026 Everett C. Haimes III · MIT License · https://github.com/rett/tacctl

Usage: tacctl <command> [arguments]

Commands:
  <b>install</b> [<o>--branch <name></o>] [<o>-y</o>|<o>--yes</o>]  Install tacctl and the TACACS+ backend (tacquito) from scratch
      <o>--branch <name></o>                   The tacctl repo branch to install or upgrade from (default: the current one)
      <o>-y</o>, <o>--yes</o>                         Answer yes to the confirmations
  <b>upgrade</b> [<o>--branch <name></o>]             Pull latest source, rebuild, update scripts and every enabled backend
  <b>uninstall</b> [<o>-y</o>|<o>--yes</o>]                  Remove tacctl, its backends' services and all associated files
  <b>rollback</b> <o><version></o> [options]          Prepare the state for the release before this one (0.2.9) or for 0.2.3: a dry run unless <o>--apply</o>
      <o>--apply</o>                           Take a snapshot, then convert the files the target cannot read (tacctl.yaml, sudoers; for 0.2.3 also console.yaml, devices.yaml)
      <o>--yes</o>                             Acknowledge the warnings that <o>--apply</o> refuses to go on without
      <o>--hosts</o>                           Accepted; the hosts need nothing for this target (no host is synced)
  <b>status</b>                                Show service health, stats, and recent errors (per backend)
  <b>passwd</b>                                Change your own password (asks for the current one)
  <b>user</b> <o><subcommand></o>                     User management (list, add, remove, passwd, scope, ...)
  <b>group</b> <o><subcommand></o>                    Group management (list, add, edit, remove)
  <b>scope</b> <o><subcommand></o>                    Scope management (named CIDR + shared-secret bundles)
  <b>host</b> <o><subcommand></o>                     Linux hosts: enroll, sync, unenroll TACACS+ or RADIUS login over SSH
  <b>device</b> <o><subcommand></o>                   Device registry: list, add, scan, discover, check, host keys (ssh-config)
  <b>breakglass</b> <o><subcommand></o>               Break-glass hold: make the server stop answering one device or host (hold, release, list)
  <b>ssh</b> <o><name|address></o> [<o>-p <port></o>]        Open an ssh session to a registered device or enrolled host, as you
      <o>-p <port></o>                         Connect to this port instead of the registered one
  <b>shell</b> [<o>--idle <min></o>] [<o>-c <line></o>]      An interactive tacctl prompt with history and completion
      <o>--idle <min></o>                      End the session after this many idle minutes at the prompt
      <o>-c <line></o>                         Run one line and exit
      <o>--no-history</o>                      Keep no history file for this session
      <o>--space-completion</o> on|off         A typed space completes a fixed word and never doubles (default on)
      <o>--password-cache</o>                  Keep your network password in this shell's memory (when your tier's policy allows)
  <b>console</b> <o><subcommand></o>                  Login console: tiers, per-user overrides, settings (show, tiers, user, ...)
  <b>backend</b> <o><subcommand></o>                  Auth backends: list, status, enable <o><id></o>, disable <o><id></o>
  <b>store</b> <o><subcommand></o>                    The canonical store: show, import, rollback
  <b>config</b> <o><subcommand></o>                   Configuration (show, render, cisco, juniper, wti, validate, ...)
  <b>log</b> <o><subcommand></o>                      Log viewer (tail, search, failures, accounting; <o>--backend <id></o>)
  <b>backup</b> <o><subcommand></o>                   Backup management (list, diff, restore)
  <b>hash</b> <o><subcommand></o>                     Bcrypt helper (generate, commands — runs as invoking user, no sudo)
  <b>completion</b> bash|zsh|fish              Print the shell completion script
  <b>version</b> [<o>--long</o>]                      Print tacctl version (<o>--long</o>: commit, build date, Go version)
      <o>--long</o>                            Also the commit, build date, Go version and whether test knobs are on

Run any command without arguments for detailed help, e.g.:
  tacctl user
  tacctl config
  tacctl backend

Examples:
  tacctl install
  tacctl upgrade
  tacctl user add jsmith superuser
  tacctl user scope jsmith add prod
  tacctl scope add prod --prefixes 10.10.0.0/16 --secret generate
  tacctl config cisco --scope prod

Documentation: man tacctl, /opt/tacctl/docs/ · Project: https://github.com/rett/tacctl

`,
	// lib/users.sh cmd_user
	"user": `
<b>User Commands</b>

Usage: tacctl user <subcommand> [arguments]

Subcommands:
  <b>list</b>                                        List all users (name, group, status, pw age, scopes)
  <b>show</b> <o><username></o>                             Show user details incl. scope membership
  <b>add</b> <o><username></o> <o><group></o>                      Add a new user; lands in default scope
  <b>add</b> <o><username></o> <o><group></o> <o>--scopes <s></o>[,s...]  Grant specific scopes at creation
  <b>add</b> <o><username></o> <o><group></o> <o>--hash <hash></o>        Add with pre-generated bcrypt hash
  <b>remove</b> <o><username></o>                           Remove a user
  <b>passwd</b> <o><username></o>                           Change a user's password
  <b>passwd</b> <o><username></o> <o>--hash <hash></o>             Change with pre-generated bcrypt hash
  <b>disable</b> <o><username></o>                          Disable a user (preserves hash)
  <b>enable</b> <o><username></o>                           Re-enable a disabled user
  <b>rename</b> <o><old></o> <o><new></o>                          Rename a user
  <b>move</b> <o><user></o> <o><group></o>                         Move user to a different group
  <b>verify</b> <o><username></o>                           Verify password and show user details
  <b>scope</b> <o><user></o> list|add|remove|replace        Manage which scopes the user can auth from
  <b>scope</b> <o><user></o> remove <o>--all</o>                   Remove every scope from the user

Examples:
  tacctl user list
  tacctl user add jsmith superuser
  tacctl user add jsmith superuser --scopes prod,lab
  tacctl user scope jsmith add prod
  tacctl user verify jsmith

`,
	// lib/groups.sh cmd_group
	"group": `
<b>Group Commands</b>

Usage: tacctl group <subcommand> [arguments]

Subcommands:
  <b>list</b>                                                List all groups
  <b>show</b> <o><name></o>                                         Every setting and where it comes from, Junos patterns too
  <b>add</b> <o><name></o> <o><priv-lvl></o> <o><juniper-class></o>               Add a new group
      <o>--tier <tier></o>                                   (add) Its tacctl tier instead of the priv-lvl's (at 15: superuser if omitted)
      <o>--wti-level <level></o>                             (add) Its WTI level instead of the priv-lvl's
  <b>edit</b> <o><name></o> priv-lvl <o><0-15></o>                         Change Cisco privilege level
  <b>edit</b> <o><name></o> juniper-class <o><CLASS></o>                   Change Juniper class name
  <b>edit</b> <o><name></o> wti-level auto|<o><level></o>                  WTI access level (viewonly, user, superuser, administrator)
  <b>edit</b> <o><name></o> tier auto|<o><tier></o>                        tacctl tier (readonly, operator, engineer, superuser)
  <b>remove</b> <o><name></o>                                       Remove a custom group
  <b>commands</b> list|default|add|remove|reset|seed <o><group></o> ...  Per-group authorized commands
  <b>privilege</b> list|add|remove|reset|seed <o><group></o> ...         Per-group Cisco priv-exec mappings
  <b>junos</b> <o><group></o> list|clear|deny-commands|deny-configuration ...  Per-group Junos deny rules
  <b>preset</b> roles                                        Starting values for viewer, operator, engineer, superuser (confirms)
      <o>--dry-run</o>                                       (preset, reset) Show what would change; write nothing
      <o>--force</o>                                         (preset) Replace values that differ from the preset's
  <b>reset</b> <o><name></o>                                        Put readonly, operator, superuser or engineer back to its canonical state (diff, confirms; superuser only)
      <o>--preset</o>                                        (reset) The role preset's values instead of the shipped ones
      <o>--only <sections></o>                               (reset) Only settings, commands, privileges or junos (comma list)
      <o>--yes</o>                                           (reset) Do not ask

'auto' (the default) takes the WTI level and the tier from the priv-lvl:
below 7 readonly, 7-14 operator, 15 superuser. A group at priv-lvl 15 other
than the built-in superuser always carries its tier: 'add' and 'edit priv-lvl'
record superuser when none is set, and so does 'edit tier auto' there. Lowering
a group below 15 takes a superuser setting away again (the recorded one and one
chosen with --tier superuser look alike): set the tier again when a superuser
group below 15 is wanted.

Examples:
  tacctl group list
  tacctl group add helpdesk 5 HELPDESK-CLASS
  tacctl group edit operator priv-lvl 10
  tacctl group edit operator juniper-class NEW-CLASS
  tacctl group edit engineer tier engineer
  tacctl group show engineer
  tacctl group preset roles --dry-run
  tacctl group reset operator --dry-run
  tacctl group remove helpdesk
  tacctl group commands default operator deny
  tacctl group commands add operator show --action permit
  tacctl group privilege list operator
  tacctl group privilege add operator 'show running-config'

`,
	// lib/groups.sh cmd_group_commands_usage
	"group-commands": `
<b>tacctl group commands</b> — per-group authorized commands

Usage:
  <b>tacctl group commands list</b> <o><group></o>                              Show rules + default action
  <b>tacctl group commands default</b> <o><group></o> <o><permit|deny></o>             Set default action (catchall)
  <b>tacctl group commands add</b> <o><group></o> <o><name></o> [<o>--match <regex></o>]...   Add a rule
                                            [<o>--action</o> permit|deny]
                                            [<o>--before <name></o>|<o>--first</o>]
      <o>--match <regex></o>                                             (add, remove) A regex the command's arguments must match (repeatable; remove: the rule's, in order)
      <o>--action</o> permit|deny                                        (add, remove) What the rule does (add: default permit)
      <o>--before <name></o>                                             (add) Put the rule before the first rule named <o><name></o> (default: before the catchall)
      <o>--first</o>                                                     (add) Put the rule first
  <b>tacctl group commands remove</b> <o><group></o> <o><name></o> [<o>--all</o>]             Drop a rule
                                            [<o>--match <regex></o>]... [<o>--action</o> permit|deny]
      <o>--all</o>                                                       (remove) Drop every rule named <o><name></o>
  <b>tacctl group commands reset</b> <o><group></o> [<o>--dry-run</o>] [<o>--yes</o>]         Revert the rules to the shipped defaults (diff, confirms; superuser only)
      <o>--dry-run</o>                                                   (reset) Show the difference; write nothing
      <o>--yes</o>                                                       (reset) Do not ask
  <b>tacctl group commands seed</b> [<o><group></o>] [<o>--force</o>]                  Re-apply the shipped rules (recovery tool)
      <o>--force</o>                                                     (seed) Overwrite a group that already has rules

<name> is compared literally to the TACACS+ cmd= word. --match
regexes are tested against the command's ARGUMENTS only (the
cmd-arg values after the word: 'running-config' for 'show
running-config'), never the full line -- so '^show .*$' can
never match and is rejected. Omit --match to cover any args.
A --match must match the whole arguments string, joined by
spaces, without <cr> (it is rendered as ^(?:regex)$):
'^crypto' matches 'show crypto' only; write '^crypto( .*)?$'
to cover 'show crypto pki certificates' too. An empty or
invalid regex is refused; 'add' warns about a prefix form
without '( .*)?' and about a rule no command can reach.

'reset' puts the group's rules back to the shipped defaults, as
'group reset <group> --only commands' does; it has no --preset (the
preset's rules come with 'group reset <group> --preset'). A group
with no shipped rules has none afterwards.

Rules are tried in order ('#' in 'list'): a rule without
--match decides, one whose regexes all miss falls through.
'add' puts a rule before the catchall, before the first rule
of the --before name, or first (--first). 'remove' refuses
when several rules share the name: pick one with --match
(all of the rule's regexes, in order) and --action, or pass
--all.

Rules live under commands.<group> in {{overrides}};
tacquito.yaml's per-group commands: block is a regenerated
artifact (do not hand-edit). RADIUS does not enforce them
(no per-command authorization). Built-ins ship with defaults:
   superuser: permit *   |   operator: show/ping/traceroute/
                              terminal + deny *   |   readonly:
                              show/ping/traceroute + deny *

Cisco devices ask tacquito per command (live enforcement) when
'aaa authorization commands <level>' is in the device config —
tacctl auto-emits these lines in 'tacctl config cisco'. Junos
devices do not use these rules: the server sends them the
group's own deny sets ('tacctl group junos').

`,
	// lib/groups.sh cmd_group_privilege_usage
	"group-privilege": `
<b>tacctl group privilege</b> — per-group Cisco priv-exec command mappings

Usage:
  <b>tacctl group privilege list</b> <o><group></o>                              Show mappings (explicit or default)
  <b>tacctl group privilege add</b> <o><group></o>    '<o><cmd></o>'[,'<o><cmd></o>'...]       Move one or more commands to the priv-lvl
  <b>tacctl group privilege remove</b> <o><group></o> '<o><cmd></o>'[,'<o><cmd></o>'...]       Remove mapping(s)
  <b>tacctl group privilege reset</b> <o><group></o> [<o>--dry-run</o>] [<o>--yes</o>]         Reset the mappings to the shipped default (diff, confirms; superuser only)
      <o>--dry-run</o>                                                    (reset) Show the difference; write nothing
      <o>--yes</o>                                                        (reset) Do not ask
  <b>tacctl group privilege seed</b> [<o><group></o>] [<o>--force</o>]                  Populate built-ins with safe defaults
      <o>--force</o>                                                      (seed) Overwrite a group that already has mappings

Each '<cmd>' may start with a mode: 'exec:' (the default when
there is none), 'exec all:', 'configure:' or 'configure all:',
e.g. 'configure: router bgp','exec all: show ip'.

'reset' puts the group's mappings back to the shipped default, which
the plain 'group reset' takes too; it has no --preset (the preset's
values come with 'group reset <group> --preset'). A group with no
shipped list has none afterwards.

Drives the 'privilege <mode> [all] level <lvl> <cmd>' lines emitted
by 'tacctl config cisco'. Pure device-side; tacquito does not read
these. When no explicit mappings exist for a group, a conservative
default set is used (only commands moved DOWN from priv 15).

`,
	// 0.2.2 (docs/plans/0.2.2-plan.md §5.1)
	"group-junos": `
<b>tacctl group junos</b> — per-group Junos rules the server sends at login

Usage:
  <b>tacctl group junos</b> <o><group></o> list                                    Show both sets and their sizes
  <b>tacctl group junos</b> <o><group></o> deny-commands list                      Show the set
  <b>tacctl group junos</b> <o><group></o> deny-commands add '<o><regex></o>'             Add a pattern
  <b>tacctl group junos</b> <o><group></o> deny-commands remove '<o><regex></o>'          Remove a pattern (exact text)
  <b>tacctl group junos</b> <o><group></o> deny-commands clear                     Drop the set (confirms)
  <b>tacctl group junos</b> <o><group></o> deny-configuration list|add|remove|clear
  <b>tacctl group junos</b> <o><group></o> clear                                   Drop both sets (confirms)

Each pattern is a POSIX extended regular expression Junos tests against
the whole command line (deny-commands) or the configuration path
(deny-configuration). The set is sent as one value, the patterns joined
with '|'; a set may not exceed 241 bytes (deny-commands) or 236
(deny-configuration), the TACACS+ argument limit. deny-commands does not
cover 'show configuration <path>': put paths in deny-configuration, which
also hides them from reading. The class on the device keeps only its
permission bits ('tacctl config juniper').

Sets live under junos.<group> in {{overrides}}; tacquito.yaml's
junos-exec service and the RADIUS policy are regenerated from them.

`,
	// lib/scopes.sh cmd_scope_usage
	"scope": `
<b>tacctl scope</b> — named (CIDR-prefixes, shared-secret) bundles

Usage:
  <b>tacctl scope list</b>                                        One row per scope (aggregated prefix list)
  <b>tacctl scope routing</b>                                     One row per (scope, prefix) — first-match order
  <b>tacctl scope show</b> <o><name></o>                                 Detailed view
  <b>tacctl scope add</b> <o><name></o> <o>--prefixes <cidrs></o>               Create a new scope
                       [<o>--secret <value></o>|<o>--secret</o> generate]
                       [<o>--protocols <protocol></o>[,<o><protocol></o>...]]
                       [<o>--vendor-attrs <vendor></o>[,<o><vendor></o>...]]
                       [<o>--default</o>]
      <o>--prefixes <cidrs></o>                                   (add) The scope's CIDRs, comma-separated
      <o>--secret <value></o>|generate                            (add) The shared secret, or a generated one
      <o>--protocols <csv></o>                                    (add) Limit it to tacacs, radius (default: all)
      <o>--vendor-attrs <csv></o>                                 (add) RADIUS vendor attributes to send (cisco, juniper, wti)
      <o>--default</o>                                            (add) Make it the default scope
  <b>tacctl scope remove</b> <o><name></o> [<o>--force</o>]                     Delete a scope (confirms)
      <o>--force</o>                                              (remove) Also take it out of the users that have it
  <b>tacctl scope rename</b> <o><old></o> <o><new></o>                          Rename (updates user references)
  <b>tacctl scope default</b> [<o><name></o>]                            Show or set the default scope
  <b>tacctl scope lookup</b> <o><ip|cidr></o>                            Show which scope owns an address

  <b>tacctl scope prefixes</b> <o><scope></o> list|add|remove|move       Manage a scope's CIDR list
  <b>tacctl scope staging</b> [list | remove <o><address></o>]           Bench addresses of devices provisioned off-site (<o>--staging</o>), until seen in place
  <b>tacctl scope secret</b>   <o><scope></o> show|set|generate          Manage a scope's shared secret
  <b>tacctl scope protocols</b> <o><scope></o> list|set <o><csv></o>|clear      Limit a scope to some protocols (tacacs, radius); default: all
  <b>tacctl scope vendor-attrs</b> <o><scope></o> [enable|disable <o><csv></o>] RADIUS: vendor privilege attributes sent to the scope's devices (cisco, juniper, wti); default: not sent
  <b>tacctl scope devices</b> <o><scope></o> [set <o><ip|cidr></o> <o><vendor></o>|unset <o><ip|cidr></o>]  RADIUS: tag an address of the scope with its vendor (it gets that vendor's attribute only)
  <b>tacctl scope aaa-order</b> <o><scope></o> [tacacs-first|local-first] AAA method-list order in this scope's rendered device configs (default tacacs-first)
  <b>tacctl scope exec-timeout</b> <o><scope></o> [minutes]              Per-scope idle-session timeout in rendered device configs (0..60 min; default 60; 0 = never expire)
  <b>tacctl scope tacacs-group</b> <o><scope></o> [name]                 Per-scope Cisco aaa-group-server label (default TACACS-GROUP)
  <b>tacctl scope radius-group</b> <o><scope></o> [name]                 Per-scope Cisco aaa-group-server label for RADIUS (default RADIUS-GROUP)
  <b>tacctl scope auth-method</b> <o><scope></o> [tacacs|radius|clear]   Protocol this scope's device configs and host enrollments use when the command names none
  <b>tacctl scope mgmt-acl</b> <o><scope></o> list|add|remove|clear      Per-scope permit list (fallback: global mgmt_acl.permits)
  <b>tacctl scope mgmt-acl</b> <o><scope></o> cisco-name|juniper-name [name]  Per-scope ACL / filter name (defaults VTY-ACL / MGMT-ACL)
  <b>tacctl scope breakglass</b> <o><scope></o> list|add <o><name></o>|remove <o><name></o>  Per-scope break-glass local users in the device walkthroughs (names and roles only; no credential is stored): the accounts 'tacctl breakglass hold' makes usable
      <o>--role <role></o>                                        (add) admin (default), operator or readonly
  <b>tacctl scope snmp</b> <o><scope></o> show|version|community|v3-user|clients|contact|port|timeout|clear|test
                                                           SNMP of a scope: credentials, allowed clients, contact (default beneath: tacctl config snmp)
  <b>tacctl scope netconf</b> <o><scope></o> [show|enable|disable|leave]
                                                           NETCONF service of the scope's Junos devices (default leave: nothing is planned or compared; a device's own setting wins)
      <o>--connection-limit <n>|none</o>                          (enable) The connection limit of the service, 1 to 250; none removes it
      <o>--rate-limit <n>|none</o>                                (enable) The rate limit of the service, 1 to 250; none removes it
  <b>tacctl scope block</b> <o><scope></o> {juniper|cisco} list|show|check|set|remove|edit|adopt [<o><block></o>]
                                                           Configuration blocks of a scope (Junos snmp and system, IOS snmp): community strings, trap groups and hosts, access lists, login message, domain, time zone, name servers, NTP

{{current}}

`,
	// lib/scopes.sh cmd_scope_prefixes_dispatch
	"scope-prefixes": `
<b>tacctl scope prefixes {{scope}}</b> — CIDR prefix list for scope '{{scope}}'

Usage:
  <b>tacctl scope prefixes</b> {{scope}} list                         Show entries
  <b>tacctl scope prefixes</b> {{scope}} add    <o><cidr></o>[,<o><cidr></o>...]    Add one or more
  <b>tacctl scope prefixes</b> {{scope}} remove <o><cidr></o>[,<o><cidr></o>...]    Remove one or more
  <b>tacctl scope prefixes</b> {{scope}} remove <o>--all</o> [<o>--force</o>]       Remove all, which removes the scope (confirms; <o>--force</o> also strips it from users)
  <b>tacctl scope prefixes</b> {{scope}} move <o><cidr></o>[,<o><cidr></o>...] <o><scope></o>
                                                            Move them to another scope in one change; names the hosts that then belong elsewhere
      <o>--all</o>                                                 (remove) Every prefix
      <o>--force</o>                                               (remove <o>--all</o>) Also take the scope out of the users that have it

{{current}}

`,
	// lib/scopes.sh cmd_scope_secret_dispatch
	"scope-secret": `
<b>tacctl scope secret {{scope}}</b> — shared secret for scope '{{scope}}'

Usage:
  <b>tacctl scope secret</b> {{scope}} show                Print raw value + length/posture
  <b>tacctl scope secret</b> {{scope}} set <o><value></o>         Set to <o><value></o> (validated)
  <b>tacctl scope secret</b> {{scope}} generate            Auto-generate + apply

{{current}}

`,
	// lib/scopes.sh cmd_scope_mgmt_acl
	"scope-mgmt-acl": `
<b>tacctl scope mgmt-acl {{scope}}</b> — per-scope Cisco VTY-ACL + Juniper lo0-filter + WTI IP Tables

Usage:
  <b>tacctl scope mgmt-acl</b> {{scope}} list                          Show effective permits for this scope
  <b>tacctl scope mgmt-acl</b> {{scope}} add    <o><entry></o>[,<o><entry></o>...]   Add one or more entries to the per-scope list
  <b>tacctl scope mgmt-acl</b> {{scope}} remove <o><entry></o>[,<o><entry></o>...]   Remove entries (a bare <o><cidr></o> removes every entry of that CIDR)
  <b>tacctl scope mgmt-acl</b> {{scope}} clear                         Wipe the per-scope list (confirms; render falls back to global)
  <b>tacctl scope mgmt-acl</b> {{scope}} cisco-name   [label]          Per-scope Cisco VTY-ACL name
  <b>tacctl scope mgmt-acl</b> {{scope}} juniper-name [label]          Per-scope Junos filter name

An <entry> is a <cidr>, or a <cidr> with the services it permits:
  <cidr>[:<service>[,<service>...]]    e.g. 172.16.100.0/23:tcp/22,udp/161,udp/162
  <service> is tcp/<ports>, udp/<ports> or icmp; <ports> is N, N-M or *.
  A <cidr> alone permits every protocol and port from it (the WTI IP Tables list renders that; a
  Cisco VTY-ACL and a Junos filter list a source only when its entry permits tcp/22).

{{current}}

`,
	// lib/dispatch.sh cmd_config
	"config": `
<b>Config Commands</b>

Usage: tacctl config <subcommand> [value]

Subcommands:
  <b>show</b>                                 Show current configuration
  <b>dump</b>                                 Show tacctl defaults + overrides + merged view
  <b>defaults</b>                             Print canonical tacctl defaults (shipped)
  <b>get</b> <o><path></o> [fallback]                Read a dotted-path value from the merged config
  <b>get-list</b> <o><path></o>                      Read a list value (one item per line)
  <b>validate</b>                             Validate config syntax and structure
  <b>render</b> [<o>--force</o>]                     Regenerate every enabled backend's config from the store (<o>--force</o> overwrites hand edits)
      <o>--force</o>                          Overwrite a generated file that was edited by hand
  <b>render</b> <o>--dry-run</o> <o>--out <dir></o>         Render into a new, empty directory at the live paths; nothing live is written
  <b>diff</b> [timestamp]                     Diff store.yaml and tacctl.yaml vs the last snapshot (or named one)
  <b>restore</b> <o><timestamp></o> [<o>--legacy</o>]       Restore a snapshot (prompts for confirmation); <o>--legacy</o> for an old-style backup
      <o>--legacy</o>                         The timestamp names an old-style backup (backups/legacy)
  <b>loglevel</b> [debug|info|error]          Show or change log level
  <b>listen</b> [show|tcp|tcp6|reset] [addr]  Show, change, or reset a listen address (default: tacacs, listener 'default')
      <o>--listener <name></o>                ...of another listener (its own tacquito@<name> unit; reset removes it)
      <o>--backend <id></o>                   ...of another backend (see 'tacctl backend list'); radius: <o>--listener</o> auth|acct <o><udp|udp6></o> <o><addr></o>
  <b>metrics</b> <show|enable|disable|address <o><host:port></o>|reset>  Prometheus exporter control
  <b>sudoers</b> [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
  <b>sudoers</b> tiers [show|install|remove]  Manage per-tier (RO/OP/SU) sudoers rules for tacctl users with local accounts
  <b>password-age</b> [days]                  Show or set password age warning threshold
  <b>bcrypt-cost</b> [10-14]                  Show or set bcrypt cost factor (default 12)
  <b>password-min-length</b> [8-64]           Show or set minimum interactive password length (default 12)
  <b>secret-min-length</b> [16-128]           Show or set minimum shared-secret length (default 16)
  <b>allow</b> list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)
  <b>deny</b> list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)
  <b>mgmt-acl</b> list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter + WTI IP Tables permits
  <b>mgmt-acl</b> cisco-name [name]           Show or set the emitted Cisco ACL name (default VTY-ACL)
  <b>mgmt-acl</b> juniper-name [name]         Show or set the emitted Juniper filter name (default MGMT-ACL)
  <b>cisco</b> source-interface [<o><scope></o> [<o><interface></o>|none]]  Show or set the interface a scope's Cisco devices source their server requests from (the full name IOS prints: Loopback0, GigabitEthernet0/0)
  <b>cisco</b>   [<o>--scope <name></o>] [<o>--legacy</o>] [<o>--protocol</o> tacacs|radius]  Show working Cisco device configuration for a scope (<o>--legacy</o> = IOS 12.x syntax; <o>--protocol</o> radius = RADIUS backend, default tacacs)
  <b>juniper</b> [<o>--scope <name></o>] [<o>--protocol</o> tacacs|radius]             Show working Juniper device configuration for a scope
  <b>wti</b>     [<o>--scope <name></o>] [<o>--protocol</o> tacacs|radius]             Show step-by-step WTI console-server (v8.x serial menu) setup for a scope (RADIUS: not verified on a unit)
      <o>--scope <name></o>                   (cisco, juniper, wti) The scope whose server address and secret go in (default: the default scope)
      <o>--protocol</o> tacacs|radius         (cisco, juniper, wti) The backend the device uses (default: the scope's auth-method, else its only protocol, else tacacs)
      <o>--legacy</o>                         (cisco) The IOS 12.x syntax, whatever the <o>--name</o> device's config-syntax says
      <o>--staging <bench-ip></o>             (cisco, juniper, wti, with <o>--scope</o>) Provisioned off-site: the bench address joins the scope as a
                                       /32 (its secret and users) until the device is seen in place (tacctl scope staging)
      <o>--name <device></o>                  (cisco, juniper, wti) A registered device of the scope: its location, description and sysName fill the SNMP step;
                                       with --staging it is also the device whose move ends the staging (default: the one at the bench address)
      <o>--server <address|name></o>          (cisco, juniper, wti) The address the devices are told to authenticate against, for devices behind a
                                       translating firewall (a name must resolve to an IPv4 address); not stored
      <o>--source <address></o>               (cisco, juniper, wti) The address tacctl itself reaches the devices from: the first SNMP client (default: the
                                       address of the route to the Internet); not stored
      <o>--snmp-location <text></o>           (cisco, juniper, wti) The SNMP location for this paste; not stored (a device's own: tacctl device location)
  <b>linux</b>   build|script|remove-script|uid|builds  TACACS+ or RADIUS login for Linux hosts (install/removal scripts)
  <b>snmp</b>    show|community|v3-user|port|timeout|clear|test  SNMP for the name hint of 'device add' (sysName)
  <b>devices</b> [show|max-concurrency|transport|timeout|confirm-timeout|apply-confirm-timeout|apply-pause|apply-transport] [value]  How 'device config pull' reads the devices (default 8 at once, auto, 90 s), the confirm timeout of 'plan' (5 min) and how 'device config apply' runs (confirm 10 min, pause 60 s, transport cli)
  <b>branch</b> [name]                        Show or change the tacctl repo branch

Examples:
  tacctl config show
  tacctl config validate
  tacctl config loglevel debug
  tacctl config listen tcp6 [::]:49
  tacctl config sudoers install adm
  tacctl config cisco --scope prod
  tacctl config cisco --scope prod --legacy   # legacy IOS 12.x syntax
  tacctl config cisco --scope prod --protocol radius
  tacctl config cisco source-interface prod Loopback0
  tacctl config wti --scope prod
  tacctl config wti --scope prod --protocol radius

`,
	// lib/scopes.sh cmd_config_prefix_filter (allow and deny)
	"config-filter": `
<b>tacctl config {{label}}</b> — connection IP ACL ({{label}} list)

Usage:
  <b>tacctl config</b> {{label}} list                          Show current {{label}} list
  <b>tacctl config</b> {{label}} add    <o><cidr></o>[,<o><cidr></o>...]     Add one or more CIDRs
  <b>tacctl config</b> {{label}} remove <o><cidr></o>[,<o><cidr></o>...]     Remove one or more CIDRs
  <b>tacctl config</b> {{label}} clear                         Wipe all (confirms)

{{current}}
Note: 'deny' takes precedence over 'allow'. Both empty = all connections accepted.

`,
	// lib/render_devices.sh cmd_config_mgmt_acl
	"config-mgmt-acl": `
<b>tacctl config mgmt-acl</b> — shared Cisco VTY-ACL + Juniper lo0-filter + WTI IP Tables permits

Usage:
  <b>tacctl config mgmt-acl list</b>                          Show current permits
  <b>tacctl config mgmt-acl add</b>    <o><entry></o>[,<o><entry></o>...]   Add one or more entries
  <b>tacctl config mgmt-acl remove</b> <o><entry></o>[,<o><entry></o>...]   Remove entries (a bare <o><cidr></o> removes every entry of that CIDR)
  <b>tacctl config mgmt-acl clear</b>                         Wipe all permits (confirms)
  <b>tacctl config mgmt-acl cisco-name</b> [name]             Show or set the Cisco ACL name (default VTY-ACL)
  <b>tacctl config mgmt-acl juniper-name</b> [name]           Show or set the Juniper filter name (default MGMT-ACL)

An <entry> is a <cidr>, or a <cidr> with the services it permits:
  <cidr>[:<service>[,<service>...]]    e.g. 172.16.100.0/23:tcp/22,udp/161,udp/162
  <service> is tcp/<ports>, udp/<ports> or icmp; <ports> is N, N-M or *.
  A <cidr> alone permits every protocol and port from it (the WTI IP Tables list renders that; a
  Cisco VTY-ACL and a Junos filter list a source only when its entry permits tcp/22).

Storage: tacctl.yaml (mgmt_acl.permits + mgmt_acl.names).
{{current}}

`,
	// lib/linux_hosts.sh cmd_config_linux
	"config-linux": `
<b>Linux host TACACS+ or RADIUS login</b>

Usage: tacctl config linux <subcommand>

  build                                   Fetch and prepare the pinned pam_tacplus source (once, and after upgrades)
  script [--scope <name>] [--server <address>] [--method tacplus|radius] [--output <file>]
                                          Write the install script for hosts in a scope (contains the secret)
      --scope <name>                      (script) The scope whose users and secret it carries (default: the default scope)
      --server <address>                  (script) The address hosts use for this server (default: detected)
      --method tacplus|radius             (script) pam_tacplus, or the host's pam_radius_auth (default: host default-method)
      --output, -o <file>                 Where the script goes (default: tacctl-linux-<scope>.sh, remove-script: tacctl-linux-remove.sh)
  remove-script [--output <file>]         Write the removal script (no secrets; accounts are left in place)
  uid [<username> [<uid>]]                Show or change the UID a user gets on every host
  uid-range [<min>-<max>]                 Show or change the UID range of all hosts (default 80000-89999)
  engineer-sudo [all|<cmd>[,<cmd>...]]    Show or limit what engineers may run through sudo on enrolled hosts (default all)
  builds [list|clear]                     Show or drop the modules 'host enroll' built in containers

Scripts written here give every account /bin/bash. The login console of this
server's own tacctl users comes with 'host enroll --local' and 'host sync'.

`,
	// lib/linux_hosts.sh cmd_host_usage
	"host": `
<b>Host Commands</b> (TACACS+ or RADIUS login for Linux hosts)

Usage: tacctl host <subcommand> [arguments]

  list [--json]                        Show enrolled hosts, with the address recorded for each
  show <name> [--all] [--json]         One enrolled host in full: connection, scope, address, host keys, sightings,
                                       notices, accounts, last sync and host facts
      --all                            (show) The acknowledged notices too
      --json                           (list and show) Print JSON (show: every field, and --check's findings under 'check')
      --check                          (show) Log in read-only and compare the host with what tacctl would make it:
                                       one line per difference with the command that fixes it; exit 1 when there is one (superuser only)
  enroll <[user@]host> [options]       Install TACACS+ or RADIUS login on a host over SSH and register it
  enroll --local [options]             Same, for this machine (its tacctl users get the login console)
      --method tacplus|radius          pam_tacplus against the TACACS+ backend, or the host's pam_radius_auth
                                       package against the RADIUS backend (default: the host's current
                                       method, else the scope's auth-method, else its only protocol,
                                       else 'host default-method').
                                       Re-enroll with the other to switch
      --scope <name>                   The host's scope (default: its registered one, else the scope covering its address)
      --server <address>               Address the host should use for this server (default: detected)
      --name <name>                    Registry name (default: short hostname; not a tacctl word; names are not case-sensitive)
      --port <n>, --identity <file>    SSH port and key
      --build-on-host                  (tacplus) Compile pam_tacplus on the host instead of in a container here
      --yes                            (enroll and move) Move a registered host to another scope even when that deletes accounts
      --staging                        (enroll, with --scope) Provisioned off-site: the host's bench address joins the scope as a
                                       /32 (its secret and users) until the host is seen in place (tacctl scope staging)
  sync <name> | --all                  Push account adds, deletions and tier changes
      --all                            Every enrolled host
      --allow-uid-mismatch             (enroll and sync) accept a UID conflict on the host instead of stopping
      --remove-home                    (enroll and sync) delete removed users' home directories without asking
                                       (on a terminal each one is asked; without one they are kept)
  move <name> [<scope>] | --all        Move an enrolled host to another scope (default: the one answering its address);
                                       --all: every host another scope answers. Asks before deleting accounts
  target <name> [<[user@]host>]        Show, or change and test, how tacctl reaches an enrolled host over ssh
      --port <n>, --identity <file>    SSH port and key; tested first, and the host's ssh keys must match the pin
      --no-identity                    No key file (ssh's default keys and the agent)
  provisioner <name> rotate <user>     Switch the account tacctl logs in to the host with: create the new one, prove
                                       it in a new connection (ssh trusts the host's pinned keys only), then change the
                                       registry. One rotation of a host at a time
      --key <file>                     (provisioner) Key login: NOPASSWD sudo and the public key only (sudoers line
                                       written last); a missing file is made by ssh-keygen, as you
      --password                       (provisioner) Password login: typed into the host's own passwd on this terminal;
                                       tacctl never sees it; refused for a host with no pinned ssh keys
      --remove-old                     (provisioner) Last, over the new account, remove the old one; its home is moved
                                       out of reach unless --remove-home. Needs a registry target with an explicit user@
      --dry-run                        (provisioner) Print the plan and test the current login; change nothing
  rename <old> <new>                   Give an enrolled host another name: registry line, pinned keys, record, staging
                                       addresses and break-glass hold follow; nothing is sent to the host. When the host
                                       is the only user of scope linux-<old>, asks whether to rename that scope too
      --yes                            (rename) Replace what an earlier host of the new name left, and rename the scope
  forget <name>                        Drop the host's registration from this server (registry line, pinned keys,
                                       record, staging addresses) and run nothing on the host; also what a registry
                                       line no longer has. Refused for a held host
      --yes                            (forget) Forget the host without asking
  unenroll <name> [--force]            Remove the login method from the host (accounts and homes are kept)
      --force                          Forget the host even when the removal there failed
  default-method [tacplus|radius]      Show or set the method for hosts enrolled without --method
                                       (a scope's own choice comes first: tacctl scope auth-method)

ssh runs as the user who invoked sudo; the remote login must be root or able to sudo.

`,
	// lib/backend.sh _backend_usage
	"backend": `
<b>Backend Commands</b>

Usage: tacctl backend <subcommand> [arguments]

Subcommands:
  <b>list</b>                    Every backend: protocol, implementation, installed, enabled, service
  <b>status</b> [<o><id></o>]           Service and listener state of every backend (or one)
  <b>enable</b> <o><id></o> [<o>-y</o>]        Install the backend if needed, enable it, render its config, start it
  <b>disable</b> <o><id></o> [<o>-y</o>]       Stop and disable it, take it out of backends.enabled (confirms);
                          its package and rendered files stay
      <o>-y</o>, <o>--yes</o>           Answer yes to the confirmation

Backends: {{backends}}

`,
	// lib/store.sh cmd_store_usage
	"store": `
<b>tacctl store</b> — canonical store (users, groups, scopes, filters)

  show [--json]                          Print the model (YAML by default).
                                         Includes shared secrets and password hashes.
      --json                             Print JSON instead
  import [--check|--force] [--replace] [<file>]
                                         Import a legacy tacquito.yaml (default: the live one).
      --check                            write nothing; report what an import would do
      --force                            drop content the store cannot represent (each item is listed)
      --replace                          overwrite an existing store
  rollback                               Undo the import: restore the pre-store tacquito.yaml, remove
                                         the store, restart (back to legacy read-only mode).

`,
	// lib/service.sh cmd_log
	"log": `
<b>Log Commands</b>

Usage: tacctl log <subcommand> [--backend <id>] [arguments]

Subcommands:
  <b>tail</b> [<o>-f</o>] [n]         Show the last N log entries (default 20; TACACS+: journal, RADIUS: auth and daemon log)
      <o>-f</o>, <o>--follow</o>      (tail) Then print new entries as they arrive, until Ctrl-C
  <b>search</b> <o><term></o>         Search the logs for a username or keyword
  <b>failures</b>              Show auth failures from the last 24 hours
  <b>accounting</b> [n]        Show last N accounting log entries
  <b>clear</b> [<o>--force</o>|<o>-y</o>]    Purge each backend's logs: journal or auth log, accounting log (confirms)
      <o>--backend <id></o>    Only that backend's log (every subcommand)
      <o>--force</o>, <o>-y</o>       (clear) Purge without asking

With more than one backend enabled each subcommand shows every backend's log in a
section of its own; --backend <id> shows only that backend's.

`,
	// lib/service.sh cmd_backup
	"backup": `
<b>Backup Commands</b>

Usage: tacctl backup <subcommand> [arguments]

Subcommands:
  <b>list</b>                           Show snapshots, then old-style backups
  <b>diff</b> [timestamp]               Diff store.yaml and tacctl.yaml against a snapshot (default: most recent)
  <b>restore</b> <o><timestamp></o> [<o>--legacy</o>] Restore a snapshot (with confirmation); <o>--legacy</o> for an old-style backup
      <o>--legacy</o>                   The timestamp names an old-style backup (backups/legacy)

`,
	// lib/users.sh cmd_hash_usage
	"hash": `
<b>tacctl hash</b> — bcrypt hash helper (non-root)

Usage:
  <b>tacctl hash generate</b>                Prompt for a password and print its bcrypt hash
  <b>tacctl hash commands</b>                Show OS-specific one-liners for offline generation

Use 'generate' when you can shell in to this server.
Use 'commands' to hand an operator a command they can run on their own machine,
so the plaintext password never leaves their laptop.

Either output plugs into:
  tacctl user add <username> <group> --hash '<hash>'
  tacctl user passwd <username> --hash '<hash>'

Both accept either form — hex ('24326224...') or raw ('$2b$12$...').

`,
}
