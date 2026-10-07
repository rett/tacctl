// Code generated from the 0.1.16 bash usage text by a one-off script; the
// text is maintained by hand from here on, and help_test.go holds it to
// testdata/usage (written by tests/tools/usage-goldens.sh from the 0.1.16
// tag). DO NOT reformat: every byte is part of the CLI contract.

package cli

// usageBlocks are the usage texts of the bash implementation (0.1.16), as
// printed to stdout, verbatim. <b> and </b> stand for the bold and reset
// escapes; {{name}} is a value the command fills in (Usage).
var usageBlocks = map[string]string{
	// lib/dispatch.sh usage
	"top": `
<b>tacctl</b> ({{version}}) — TACACS+ (tacquito) and RADIUS (FreeRADIUS) from one store

Usage: tacctl <command> [arguments]

Commands:
  install [--branch <name>] [-y|--yes]  Install tacctl and the TACACS+ backend (tacquito) from scratch
      --branch <name>                   The tacctl repo branch to install or upgrade from (default: the current one)
      -y, --yes                         Answer yes to the confirmations
  upgrade [--branch <name>]             Pull latest source, rebuild, update scripts and every enabled backend
  uninstall [-y|--yes]                  Remove tacctl, its backends' services and all associated files
  status                                Show service health, stats, and recent errors (per backend)
  passwd                                Change your own password (asks for the current one)
  user <subcommand>                     User management (list, add, remove, passwd, scope, ...)
  group <subcommand>                    Group management (list, add, edit, remove)
  scope <subcommand>                    Scope management (named CIDR + shared-secret bundles)
  host <subcommand>                     Linux hosts: enroll, sync, unenroll TACACS+ or RADIUS login over SSH
  device <subcommand>                   Device registry: list, add, scan, discover, check, host keys (ssh-config)
  ssh <name|address> [-p <port>]        Open an ssh session to a registered device or enrolled host, as you
      -p <port>                         Connect to this port instead of the registered one
  shell [--idle <min>] [-c <line>]      An interactive tacctl prompt with history and completion
      --idle <min>                      End the session after this many idle minutes at the prompt
      -c <line>                         Run one line and exit
      --no-history                      Keep no history file for this session
  console <subcommand>                  Login console: tiers, per-user overrides, settings (show, tiers, user, ...)
  backend <subcommand>                  Auth backends: list, status, enable <id>, disable <id>
  store <subcommand>                    The canonical store: show, import, rollback
  config <subcommand>                   Configuration (show, render, cisco, juniper, wti, validate, ...)
  log <subcommand>                      Log viewer (tail, search, failures, accounting; --backend <id>)
  backup <subcommand>                   Backup management (list, diff, restore)
  hash <subcommand>                     Bcrypt helper (generate, commands — runs as invoking user, no sudo)
  completion bash|zsh|fish              Print the shell completion script
  version [--long]                      Print tacctl version (--long: commit, build date, Go version)
      --long                            Also the commit, build date, Go version and whether test knobs are on

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

`,
	// lib/users.sh cmd_user
	"user": `
<b>User Commands</b>

Usage: tacctl user <subcommand> [arguments]

Subcommands:
  list                                        List all users (name, group, status, pw age, scopes)
  show <username>                             Show user details incl. scope membership
  add <username> <group>                      Add a new user; lands in default scope
  add <username> <group> --scopes <s>[,s...]  Grant specific scopes at creation
  add <username> <group> --hash <hash>        Add with pre-generated bcrypt hash
  remove <username>                           Remove a user
  passwd <username>                           Change a user's password
  passwd <username> --hash <hash>             Change with pre-generated bcrypt hash
  disable <username>                          Disable a user (preserves hash)
  enable <username>                           Re-enable a disabled user
  rename <old> <new>                          Rename a user
  move <user> <group>                         Move user to a different group
  verify <username>                           Verify password and show user details
  scope <user> list|add|remove|replace        Manage which scopes the user can auth from
  scope <user> remove --all                   Remove every scope from the user

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
  list                                                List all groups
  show <name>                                         Every setting and where it comes from
  add <name> <priv-lvl> <juniper-class>               Add a new group
      --tier <tier>                                   (add) Its tacctl tier instead of the priv-lvl's
      --wti-level <level>                             (add) Its WTI level instead of the priv-lvl's
  edit <name> priv-lvl <0-15>                         Change Cisco privilege level
  edit <name> juniper-class <CLASS>                   Change Juniper class name
  edit <name> wti-level auto|<level>                  WTI access level (viewonly, user, superuser, administrator)
  edit <name> tier auto|<tier>                        tacctl tier (readonly, operator, engineer, superuser)
  remove <name>                                       Remove a custom group
  commands list|default|add|remove|clear|seed <group> ...  Per-group authorized commands
  privilege list|add|remove|clear|seed <group> ...         Per-group Cisco priv-exec mappings
  junos <group> list|clear|deny-commands|deny-configuration ...  Per-group Junos deny rules
  preset roles                                        Starting values for viewer, operator, engineer, superuser (confirms)
      --dry-run                                       (preset) Show what would change; write nothing
      --force                                         (preset) Replace values that differ from the preset's
      --mgmt-filter <name>                            (preset) Deny engineers that Junos firewall filter too

'auto' (the default) takes the WTI level and the tier from the priv-lvl:
below 7 readonly, 7-14 operator, 15 superuser.

Examples:
  tacctl group list
  tacctl group add helpdesk 5 HELPDESK-CLASS
  tacctl group edit operator priv-lvl 10
  tacctl group edit operator juniper-class NEW-CLASS
  tacctl group edit engineer tier engineer
  tacctl group show engineer
  tacctl group preset roles --dry-run
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
  tacctl group commands list <group>                              Show rules + default action
  tacctl group commands default <group> <permit|deny>             Set default action (catchall)
  tacctl group commands add <group> <name> [--match <regex>]...   Add a rule
                                            [--action permit|deny]
                                            [--before <name>|--first]
      --match <regex>                                             (add, remove) A regex the command's arguments must match (repeatable; remove: the rule's, in order)
      --action permit|deny                                        (add, remove) What the rule does (add: default permit)
      --before <name>                                             (add) Put the rule before the first rule named <name> (default: before the catchall)
      --first                                                     (add) Put the rule first
  tacctl group commands remove <group> <name> [--all]             Drop a rule
                                            [--match <regex>]... [--action permit|deny]
      --all                                                       (remove) Drop every rule named <name>
  tacctl group commands clear <group>                             Drop overrides — revert to shipped defaults (confirms)
  tacctl group commands seed [<group>] [--force]                  Re-apply legacy seed set (recovery tool)
      --force                                                     (seed) Overwrite a group that already has rules

<name> is compared literally to the TACACS+ cmd= word. --match
regexes are tested against the command's ARGUMENTS only (the
cmd-arg values after the word: 'running-config' for 'show
running-config'), never the full line -- so '^show .*$' can
never match and is rejected. Omit --match to cover any args.
A --match is anchored at both ends and tested against the
arguments joined by spaces, without <cr>: '^crypto' matches
'show crypto' only; write '^crypto( .*)?' to cover 'show
crypto pki certificates' too.

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
  tacctl group privilege list <group>                              Show mappings (explicit or default)
  tacctl group privilege add <group>    '<cmd>'[,'<cmd>'...]       Move one or more commands to the priv-lvl
  tacctl group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove mapping(s)
  tacctl group privilege clear <group>                             Wipe explicit mappings (revert to defaults)
  tacctl group privilege seed [<group>] [--force]                  Populate built-ins with safe defaults
      --force                                                      (seed) Overwrite a group that already has mappings

Each '<cmd>' may start with a mode: 'exec:' (the default when
there is none), 'exec all:', 'configure:' or 'configure all:',
e.g. 'configure: router bgp','exec all: show ip'.

Drives the 'privilege <mode> [all] level <lvl> <cmd>' lines emitted
by 'tacctl config cisco'. Pure device-side; tacquito does not read
these. When no explicit mappings exist for a group, a conservative
default set is used (only commands moved DOWN from priv 15).

`,
	// 0.2.2 (docs/plans/0.2.2-plan.md §5.1)
	"group-junos": `
<b>tacctl group junos</b> — per-group Junos rules the server sends at login

Usage:
  tacctl group junos <group> list                                    Show both sets and their sizes
  tacctl group junos <group> deny-commands list                      Show the set
  tacctl group junos <group> deny-commands add '<regex>'             Add a pattern
  tacctl group junos <group> deny-commands remove '<regex>'          Remove a pattern (exact text)
  tacctl group junos <group> deny-commands clear                     Drop the set (confirms)
  tacctl group junos <group> deny-configuration list|add|remove|clear
  tacctl group junos <group> clear                                   Drop both sets (confirms)

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
  tacctl scope list                                        One row per scope (aggregated prefix list)
  tacctl scope routing                                     One row per (scope, prefix) — first-match order
  tacctl scope show <name>                                 Detailed view
  tacctl scope add <name> --prefixes <cidrs>               Create a new scope
                       [--secret <value>|--secret generate]
                       [--protocols <protocol>[,<protocol>...]]
                       [--vendor-attrs <vendor>[,<vendor>...]]
                       [--default]
      --prefixes <cidrs>                                   (add) The scope's CIDRs, comma-separated
      --secret <value>|generate                            (add) The shared secret, or a generated one
      --protocols <csv>                                    (add) Limit it to tacacs, radius (default: all)
      --vendor-attrs <csv>                                 (add) RADIUS vendor attributes to send (cisco, juniper, wti)
      --default                                            (add) Make it the default scope
  tacctl scope remove <name> [--force]                     Delete a scope (confirms)
      --force                                              (remove) Also take it out of the users that have it
  tacctl scope rename <old> <new>                          Rename (updates user references)
  tacctl scope default [<name>]                            Show or set the default scope
  tacctl scope lookup <ip|cidr>                            Show which scope owns an address

  tacctl scope prefixes <scope> list|add|remove|move       Manage a scope's CIDR list
  tacctl scope staging [list | remove <address>]           Bench addresses of devices provisioned off-site (--staging), until seen in place
  tacctl scope secret   <scope> show|set|generate          Manage a scope's shared secret
  tacctl scope protocols <scope> list|set <csv>|clear      Limit a scope to some protocols (tacacs, radius); default: all
  tacctl scope vendor-attrs <scope> [enable|disable <csv>] RADIUS: vendor privilege attributes sent to the scope's devices (cisco, juniper, wti); default: not sent
  tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]  RADIUS: tag an address of the scope with its vendor (it gets that vendor's attribute only)
  tacctl scope aaa-order <scope> [tacacs-first|local-first] AAA method-list order in this scope's rendered device configs (default tacacs-first)
  tacctl scope exec-timeout <scope> [minutes]              Per-scope idle-session timeout in rendered device configs (0..60 min; default 60; 0 = never expire)
  tacctl scope tacacs-group <scope> [name]                 Per-scope Cisco aaa-group-server label (default TACACS-GROUP)
  tacctl scope radius-group <scope> [name]                 Per-scope Cisco aaa-group-server label for RADIUS (default RADIUS-GROUP)
  tacctl scope auth-method <scope> [tacacs|radius|clear]   Protocol this scope's device configs and host enrollments use when the command names none
  tacctl scope mgmt-acl <scope> list|add|remove|clear      Per-scope permit list (fallback: global mgmt_acl.permits)
  tacctl scope mgmt-acl <scope> cisco-name|juniper-name [name]  Per-scope ACL / filter name (defaults VTY-ACL / MGMT-ACL)

{{current}}

`,
	// lib/scopes.sh cmd_scope_prefixes_dispatch
	"scope-prefixes": `
<b>tacctl scope prefixes {{scope}}</b> — CIDR prefix list for scope '{{scope}}'

Usage:
  tacctl scope prefixes {{scope}} list                         Show entries
  tacctl scope prefixes {{scope}} add    <cidr>[,<cidr>...]    Add one or more
  tacctl scope prefixes {{scope}} remove <cidr>[,<cidr>...]    Remove one or more
  tacctl scope prefixes {{scope}} remove --all [--force]       Remove all, which removes the scope (confirms; --force also strips it from users)
  tacctl scope prefixes {{scope}} move <cidr>[,<cidr>...] <scope>
                                                            Move them to another scope in one change; names the hosts that then belong elsewhere
      --all                                                 (remove) Every prefix
      --force                                               (remove --all) Also take the scope out of the users that have it

{{current}}

`,
	// lib/scopes.sh cmd_scope_secret_dispatch
	"scope-secret": `
<b>tacctl scope secret {{scope}}</b> — shared secret for scope '{{scope}}'

Usage:
  tacctl scope secret {{scope}} show                Print raw value + length/posture
  tacctl scope secret {{scope}} set <value>         Set to <value> (validated)
  tacctl scope secret {{scope}} generate            Auto-generate + apply

{{current}}

`,
	// lib/scopes.sh cmd_scope_mgmt_acl
	"scope-mgmt-acl": `
<b>tacctl scope mgmt-acl {{scope}}</b> — per-scope Cisco VTY-ACL + Juniper lo0-filter

Usage:
  tacctl scope mgmt-acl {{scope}} list                          Show effective permits for this scope
  tacctl scope mgmt-acl {{scope}} add    <cidr>[,<cidr>...]     Add one or more CIDRs to the per-scope list
  tacctl scope mgmt-acl {{scope}} remove <cidr>[,<cidr>...]     Remove one or more CIDRs from the per-scope list
  tacctl scope mgmt-acl {{scope}} clear                         Wipe the per-scope list (confirms; render falls back to global)
  tacctl scope mgmt-acl {{scope}} cisco-name   [label]          Per-scope Cisco VTY-ACL name
  tacctl scope mgmt-acl {{scope}} juniper-name [label]          Per-scope Junos filter name

{{current}}

`,
	// lib/dispatch.sh cmd_config
	"config": `
<b>Config Commands</b>

Usage: tacctl config <subcommand> [value]

Subcommands:
  show                                 Show current configuration
  dump                                 Show tacctl defaults + overrides + merged view
  defaults                             Print canonical tacctl defaults (shipped)
  get <path> [fallback]                Read a dotted-path value from the merged config
  get-list <path>                      Read a list value (one item per line)
  validate                             Validate config syntax and structure
  render [--force]                     Regenerate every enabled backend's config from the store (--force overwrites hand edits)
      --force                          Overwrite a generated file that was edited by hand
  render --dry-run --out <dir>         Render into a new, empty directory at the live paths; nothing live is written
  diff [timestamp]                     Diff store.yaml and tacctl.yaml vs the last snapshot (or named one)
  restore <timestamp> [--legacy]       Restore a snapshot (prompts for confirmation); --legacy for an old-style backup
      --legacy                         The timestamp names an old-style backup (backups/legacy)
  loglevel [debug|info|error]          Show or change log level
  listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset a listen address (default: tacacs, listener 'default')
      --listener <name>                ...of another listener (its own tacquito@<name> unit; reset removes it)
      --backend <id>                   ...of another backend (see 'tacctl backend list'); radius: --listener auth|acct <udp|udp6> <addr>
  metrics <show|enable|disable|address <host:port>|reset>  Prometheus exporter control
  sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
  sudoers tiers [show|install|remove]  Manage per-tier (RO/OP/SU) sudoers rules for tacctl users with local accounts
  password-age [days]                  Show or set password age warning threshold
  bcrypt-cost [10-14]                  Show or set bcrypt cost factor (default 12)
  password-min-length [8-64]           Show or set minimum interactive password length (default 12)
  secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)
  allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)
  deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)
  mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits
  mgmt-acl cisco-name [name]           Show or set the emitted Cisco ACL name (default VTY-ACL)
  mgmt-acl juniper-name [name]         Show or set the emitted Juniper filter name (default MGMT-ACL)
  cisco   [--scope <name>] [--legacy] [--protocol tacacs|radius]  Show working Cisco device configuration for a scope (--legacy = IOS 12.x syntax; --protocol radius = RADIUS backend, default tacacs)
  juniper [--scope <name>] [--protocol tacacs|radius]             Show working Juniper device configuration for a scope
  wti     [--scope <name>] [--protocol tacacs|radius]             Show step-by-step WTI console-server (v8.x serial menu) setup for a scope (RADIUS: not verified on a unit)
      --scope <name>                   (cisco, juniper, wti) The scope whose server address and secret go in (default: the default scope)
      --protocol tacacs|radius         (cisco, juniper, wti) The backend the device uses (default: the scope's auth-method, else its only protocol, else tacacs)
      --legacy                         (cisco) IOS 12.x syntax
      --staging <bench-ip>             (cisco, juniper, wti, with --scope) Provisioned off-site: the bench address joins the scope as a
                                       /32 (its secret and users) until the device is seen in place (tacctl scope staging)
      --name <device>                  (with --staging) The registered device whose move ends the staging (default: the one at the bench address)
  linux   build|script|remove-script|uid|builds  TACACS+ or RADIUS login for Linux hosts (install/removal scripts)
  branch [name]                        Show or change the tacctl repo branch

Examples:
  tacctl config show
  tacctl config validate
  tacctl config loglevel debug
  tacctl config listen tcp6 [::]:49
  tacctl config sudoers install adm
  tacctl config cisco --scope prod
  tacctl config cisco --scope prod --legacy   # legacy IOS 12.x syntax
  tacctl config cisco --scope prod --protocol radius
  tacctl config wti --scope prod
  tacctl config wti --scope prod --protocol radius

`,
	// lib/scopes.sh cmd_config_prefix_filter (allow and deny)
	"config-filter": `
<b>tacctl config {{label}}</b> — connection IP ACL ({{label}} list)

Usage:
  tacctl config {{label}} list                          Show current {{label}} list
  tacctl config {{label}} add    <cidr>[,<cidr>...]     Add one or more CIDRs
  tacctl config {{label}} remove <cidr>[,<cidr>...]     Remove one or more CIDRs
  tacctl config {{label}} clear                         Wipe all (confirms)

{{current}}
Note: 'deny' takes precedence over 'allow'. Both empty = all connections accepted.

`,
	// lib/render_devices.sh cmd_config_mgmt_acl
	"config-mgmt-acl": `
<b>tacctl config mgmt-acl</b> — shared Cisco VTY-ACL + Juniper lo0-filter permits

Usage:
  tacctl config mgmt-acl list                          Show current permits
  tacctl config mgmt-acl add    <cidr>[,<cidr>...]     Add one or more CIDRs
  tacctl config mgmt-acl remove <cidr>[,<cidr>...]     Remove one or more CIDRs
  tacctl config mgmt-acl clear                         Wipe all permits (confirms)
  tacctl config mgmt-acl cisco-name [name]             Show or set the Cisco ACL name (default VTY-ACL)
  tacctl config mgmt-acl juniper-name [name]           Show or set the Juniper filter name (default MGMT-ACL)

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
  builds [list|clear]                     Show or drop the modules 'host enroll' built in containers

Scripts written here give every account /bin/bash. The login console of this
server's own tacctl users comes with 'host enroll --local' and 'host sync'.

`,
	// lib/linux_hosts.sh cmd_host_usage
	"host": `
<b>Host Commands</b> (TACACS+ or RADIUS login for Linux hosts)

Usage: tacctl host <subcommand> [arguments]

  list                                 Show enrolled hosts
  show <name> [--all] [--json]         One enrolled host in full: connection, scope, address, host keys, sightings,
                                       notices, accounts, last sync and host facts
      --all                            (show) The acknowledged notices too
      --json                           (show) Print JSON: every field, and --check's findings under 'check'
      --check                          (show) Log in read-only and compare the host with what tacctl would make it:
                                       one line per difference with the command that fixes it; exit 1 when there is one
  enroll <[user@]host> [options]       Install TACACS+ or RADIUS login on a host over SSH and register it
  enroll --local [options]             Same, for this machine (its tacctl users get the login console)
      --method tacplus|radius          pam_tacplus against the TACACS+ backend, or the host's pam_radius_auth
                                       package against the RADIUS backend (default: the host's current
                                       method, else the scope's auth-method, else its only protocol,
                                       else 'host default-method').
                                       Re-enroll with the other to switch
      --scope <name>                   The host's scope (default: its registered one, else the scope covering its address)
      --server <address>               Address the host should use for this server (default: detected)
      --name <name>                    Registry name (default: short hostname)
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
  list                    Every backend: protocol, implementation, installed, enabled, service
  status [<id>]           Service and listener state of every backend (or one)
  enable <id> [-y]        Install the backend if needed, enable it, render its config, start it
  disable <id> [-y]       Stop and disable it, take it out of backends.enabled (confirms);
                          its package and rendered files stay
      -y, --yes           Answer yes to the confirmation

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
  tail [-f] [n]         Show the last N log entries (default 20; TACACS+: journal, RADIUS: auth and daemon log)
      -f, --follow      (tail) Then print new entries as they arrive, until Ctrl-C
  search <term>         Search the logs for a username or keyword
  failures              Show auth failures from the last 24 hours
  accounting [n]        Show last N accounting log entries
  clear [--force|-y]    Purge each backend's logs: journal or auth log, accounting log (confirms)
      --backend <id>    Only that backend's log (every subcommand)
      --force, -y       (clear) Purge without asking

With more than one backend enabled each subcommand shows every backend's log in a
section of its own; --backend <id> shows only that backend's.

`,
	// lib/service.sh cmd_backup
	"backup": `
<b>Backup Commands</b>

Usage: tacctl backup <subcommand> [arguments]

Subcommands:
  list                           Show snapshots, then old-style backups
  diff [timestamp]               Diff store.yaml and tacctl.yaml against a snapshot (default: most recent)
  restore <timestamp> [--legacy] Restore a snapshot (with confirmation); --legacy for an old-style backup
      --legacy                   The timestamp names an old-style backup (backups/legacy)

`,
	// lib/users.sh cmd_hash_usage
	"hash": `
<b>tacctl hash</b> — bcrypt hash helper (non-root)

Usage:
  tacctl hash generate                Prompt for a password and print its bcrypt hash
  tacctl hash commands                Show OS-specific one-liners for offline generation

Use 'generate' when you can shell in to this server.
Use 'commands' to hand an operator a command they can run on their own machine,
so the plaintext password never leaves their laptop.

Either output plugs into:
  tacctl user add <username> <group> --hash '<hash>'
  tacctl user passwd <username> --hash '<hash>'

Both accept either form — hex ('24326224...') or raw ('$2b$12$...').

`,
}
