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
  shell [--idle <min>] [-c <line>]      An interactive tacctl prompt with history and completion
  backend <subcommand>                  Auth backends: list, status, enable <id>, disable <id>
  store <subcommand>                    The canonical store: show, import, rollback
  config <subcommand>                   Configuration (show, render, cisco, juniper, wti, validate, ...)
  log <subcommand>                      Log viewer (tail, search, failures, accounting; --backend <id>)
  backup <subcommand>                   Backup management (list, diff, restore)
  hash <subcommand>                     Bcrypt helper (generate, commands — runs as invoking user, no sudo)
  completion bash|zsh|fish              Print the shell completion script
  version [--long]                      Print tacctl version (--long: commit, build date, Go version)

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
  add <name> <priv-lvl> <juniper-class>               Add a new group
  edit <name> priv-lvl <0-15>                         Change Cisco privilege level
  edit <name> juniper-class <CLASS>                   Change Juniper class name
  remove <name>                                       Remove a custom group
  commands list|default|add|remove|clear|seed <group> ...  Per-group authorized commands
  privilege list|add|remove|clear|seed <group> ...         Per-group Cisco priv-exec mappings

Examples:
  tacctl group list
  tacctl group add helpdesk 5 HELPDESK-CLASS
  tacctl group edit operator priv-lvl 10
  tacctl group edit operator juniper-class NEW-CLASS
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
  tacctl group commands remove <group> <name>                     Drop a rule
  tacctl group commands clear <group>                             Drop overrides — revert to shipped defaults (confirms)
  tacctl group commands seed [<group>] [--force]                  Re-apply legacy seed set (recovery tool)

<name> is compared literally to the TACACS+ cmd= word. --match
regexes are tested against the command's ARGUMENTS only (the
cmd-arg values after the word: 'running-config' for 'show
running-config'), never the full line -- so '^show .*$' can
never match and is rejected. Omit --match to cover any args.

Rules live under commands.<group> in {{overrides}};
tacquito.yaml's per-group commands: block is a regenerated
artifact (do not hand-edit). RADIUS does not enforce them
(no per-command authorization). Built-ins ship with defaults:
   superuser: permit *   |   operator: show/ping/traceroute/
                              terminal + deny *   |   readonly:
                              show/ping/traceroute + deny *

Cisco devices ask tacquito per command (live enforcement) when
'aaa authorization commands <level>' is in the device config —
tacctl auto-emits these lines in 'tacctl config cisco'. Juniper
enforcement is LOCAL via class allow/deny-commands, rendered
from the same tacctl-authored rules by 'tacctl config juniper'.

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

Drives 'privilege exec level <lvl> <cmd>' lines emitted by
'tacctl config cisco'. Pure device-side; tacquito does not read
these. When no explicit mappings exist for a group, a conservative
default set is used (only commands moved DOWN from priv 15).

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
  tacctl scope remove <name> [--force]                     Delete a scope (confirms)
  tacctl scope rename <old> <new>                          Rename (updates user references)
  tacctl scope default [<name>]                            Show or set the default scope
  tacctl scope lookup <ip|cidr>                            Show which scope owns an address

  tacctl scope prefixes <scope> list|add|remove            Manage a scope's CIDR list
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
  render --dry-run --out <dir>         Render into a new, empty directory at the live paths; nothing live is written
  diff [timestamp]                     Diff store.yaml and tacctl.yaml vs the last snapshot (or named one)
  restore <timestamp> [--legacy]       Restore a snapshot (prompts for confirmation); --legacy for an old-style backup
  loglevel [debug|info|error]          Show or change log level
  listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset a listen address (default: tacacs, listener 'default')
         [--listener <name>]           ...of another listener (its own tacquito@<name> unit; reset removes it)
         [--backend <id>]              ...of another backend (see 'tacctl backend list'); radius: --listener auth|acct <udp|udp6> <addr>
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
  remove-script [--output <file>]         Write the removal script (no secrets; accounts are left in place)
  uid [<username> [<uid>]]                Show or change the UID/GID a user gets on every host
  builds [list|clear]                     Show or drop the modules 'host enroll' built in containers

`,
	// lib/linux_hosts.sh cmd_host_usage
	"host": `
<b>Host Commands</b> (TACACS+ or RADIUS login for Linux hosts)

Usage: tacctl host <subcommand> [arguments]

  list                                 Show enrolled hosts
  enroll <[user@]host> [options]       Install TACACS+ or RADIUS login on a host over SSH and register it
  enroll --local [options]             Same, for this machine
      --method tacplus|radius          pam_tacplus against the TACACS+ backend, or the host's pam_radius_auth
                                       package against the RADIUS backend (default: the host's current
                                       method, else the scope's auth-method, else its only protocol,
                                       else 'host default-method').
                                       Re-enroll with the other to switch
      --scope <name>                   Use an existing scope (default: create linux-<name> for the host's /32)
      --server <address>               Address the host should use for this server (default: detected)
      --name <name>                    Registry name (default: short hostname)
      --port <n>, --identity <file>    SSH port and key
      --build-on-host                  (tacplus) Compile pam_tacplus on the host instead of in a container here
  sync <name> | --all                  Push account adds, deletions and tier changes
      --allow-uid-mismatch             (enroll and sync) accept a UID/GID conflict on the host instead of stopping
      --remove-home                    (enroll and sync) delete removed users' home directories without asking
                                       (on a terminal each one is asked; without one they are kept)
  target <name> [<[user@]host>]        Show, or change and test, how tacctl reaches an enrolled host over ssh
      --port <n>, --identity <file>    SSH port and key; tested first, and the host's ssh keys must match the pin
      --no-identity                    No key file (ssh's default keys and the agent)
  unenroll <name> [--force]            Remove the login method from the host (accounts and homes are kept)
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

Backends: {{backends}}

`,
	// lib/store.sh cmd_store_usage
	"store": `
<b>tacctl store</b> — canonical store (users, groups, scopes, filters)

  show [--json]                          Print the model (YAML by default).
                                         Includes shared secrets and password hashes.
  import [--check|--force] [--replace] [<file>]
                                         Import a legacy tacquito.yaml (default: the live one).
      --check     write nothing; report what an import would do
      --force     drop content the store cannot represent (each item is listed)
      --replace   overwrite an existing store
  rollback                               Undo the import: restore the pre-store tacquito.yaml, remove
                                         the store, restart (back to legacy read-only mode).

`,
	// lib/service.sh cmd_log
	"log": `
<b>Log Commands</b>

Usage: tacctl log <subcommand> [--backend <id>] [arguments]

Subcommands:
  tail [n]              Show the last N log entries (default 20; TACACS+: journal, RADIUS: auth and daemon log)
  search <term>         Search the logs for a username or keyword
  failures              Show auth failures from the last 24 hours
  accounting [n]        Show last N accounting log entries
  clear [--force|-y]    Purge each backend's logs: journal or auth log, accounting log (confirms)

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
