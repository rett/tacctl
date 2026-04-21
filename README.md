# tacctl

Management toolkit for [tacquito](https://github.com/facebookincubator/tacquito), a TACACS+ server (RFC 8907) by Facebook Incubator. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices.

## Quick Start

```bash
# Install on a new server
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl && tacctl install'

# Or upgrade an existing server (pulls latest from GitHub)
tacctl upgrade

# After install, add your first user (lands in the default 'lab' scope)
tacctl user add jsmith superuser

# Create a production scope and grant jsmith access to it
tacctl scopes add prod --prefixes 10.10.0.0/16 --secret generate
tacctl user scopes jsmith add prod

# Manage users
tacctl user list

# Show device configs with your server's IP and scope-specific secret pre-filled
tacctl config cisco                   # default scope
tacctl config cisco --scope prod      # specific scope
tacctl config juniper --scope prod
```

## Project Structure

```
tacctl/
  bin/
    tacctl.sh               # CLI (symlinked to /usr/local/bin/tacctl)
  config/
    tacquito.yaml           # Template TACACS+ config (used by installer)
    tacquito.service        # Systemd unit file
    tacquito.logrotate      # Log rotation config (daily, 90-day retention)
    templates/
      cisco.template        # Default Cisco device config template
      juniper.template      # Default Juniper device config template
  README.md
  LICENSE
```

## System Files

| File | Purpose |
|------|---------|
| `/etc/tacquito/tacquito.yaml` | Server configuration |
| `/etc/systemd/system/tacquito.service` | Systemd unit file |
| `/etc/systemd/system/tacquito.service.d/tacctl-overrides.conf` | Systemd drop-in for `-network`/`-address`/`-level` overrides (preserved across upgrades) |
| `/etc/sudoers.d/tacctl` | Optional NOPASSWD rule (installed via `tacctl config sudoers install`) |
| `/var/log/tacquito/accounting.log` | Accounting records |
| `/etc/tacquito/backups/` | Config backups and password dates |
| `/usr/local/bin/tacquito` | Server binary |
| `/usr/local/bin/tacctl` | Symlink to management CLI |
| `/usr/local/bin/tacquito-hashgen` | Password hash generator |
| `/etc/tacquito/templates/` | Custom device config templates (override defaults) |
| `/etc/tacquito/password-max-age` | Password age warning threshold (days) |
| `/etc/tacquito/default-scope` | Name of the default scope (used when `user add` / `config cisco` / `config juniper` are called without `--scopes` / `--scope`) |
| `/opt/tacctl/` | Git clone of this repo (used by upgrade) |
| `/opt/tacquito-src/` | Tacquito server source code |

## Important Notes

- **IPv4 by default:** The service listens on IPv4 only (`-network tcp`). Switching to `tcp6` enables dual-stack, so IPv6 clients connect with mapped addresses (e.g., `::ffff:10.1.0.1`) that do not match IPv4 prefix rules — effectively bypassing prefix-based access control. Use `tacctl config listen tcp6 [::]:49` only if you also add IPv6 prefix rules; the command prompts for confirmation first.
- **Shared secrets:** Use hex-only secrets (`openssl rand -hex 16`) to avoid quoting issues on devices.
- **Juniper template users are required:** Every `local-user-name` value (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each Juniper device. Without this, TACACS+ auth succeeds but Junos rejects the login.
- **Config edits:** The `tacctl` tool handles service restarts automatically. Manual edits with `sed -i` require a manual restart.

## Security Best Practices

### Bind to a specific interface
The default listener is `-address :49` (all interfaces). Change it to your management IP:
```
tacctl config listen tcp 10.1.0.1:49
```
The setting lives in a systemd drop-in (`/etc/systemd/system/tacquito.service.d/tacctl-overrides.conf`) so it survives `tacctl upgrade`. Use `tacctl config listen show` to inspect, or `tacctl config listen reset` to revert to the template default.

### Scopes (environment isolation)
A **scope** is a named bundle of `(client CIDR prefixes, shared secret)`. Each user carries a list of scope names; authentication succeeds only when the scope the client IP falls inside is in the user's scope list. Scopes let you run multiple environments (prod, lab, edge) off a single tacquito instance with distinct secrets and tight device-class boundaries.

Fresh installs ship with a single scope named **`lab`** (least-privilege default). An operator who runs `tacctl user add alice operator` without thinking about scopes gets a user that can only authenticate on lab devices — production access must be granted explicitly.

**Overlapping prefixes across scopes are supported.** A narrow lab subnet can live inside a broader production scope's address space; tacctl emits one `secrets:` entry per (scope, prefix) pair, globally sorted by specificity, so tacquito's first-match provider walk routes each client IP to the narrowest scope that contains it. The one-CIDR-per-scope invariant is still enforced: no two scopes can claim the same exact prefix.

Example multi-environment setup (broader prod with narrower lab and sandbox carved out):
```
tacctl scopes add prod_dc_east  --prefixes 10.10.0.0/16      --secret generate
tacctl scopes add prod_dc_west  --prefixes 10.20.0.0/16      --secret generate
tacctl scopes add corp_campus   --prefixes 172.20.0.0/16     --secret generate
tacctl scopes add lab_east      --prefixes 10.10.99.0/24     --secret generate   # carved from prod_dc_east
tacctl scopes add sandbox       --prefixes 10.10.200.0/23    --secret generate   # carved from prod_dc_east

tacctl scopes default prod_dc_east                  # optional: new users land in prod by default
tacctl user add alice superuser --scopes prod_dc_east,prod_dc_west
tacctl user add dev1 superuser  --scopes sandbox,lab_east    # no prod access

tacctl scopes lookup 10.10.99.7                     # -> lab_east (shadowed by prod_dc_east, lab)
tacctl scopes lookup 10.10.1.5                      # -> prod_dc_east (shadowed by lab)
```

Emit per-scope device configs:
```
tacctl config cisco --scope prod_dc_east            # prod's secret + header mentions sibling scopes
tacctl config juniper --scope lab_east
```

Scope management commands:
```
tacctl scopes list                              # name, prefix list, user count, default marker
tacctl scopes show <name>                       # full detail + raw secret + users + default-ness
tacctl scopes add <name> --prefixes <cidrs>     # --secret <v> | --secret generate | --default
tacctl scopes remove <name> [--force]           # refuses if users reference it; --force strips them
tacctl scopes rename <old> <new>                # rewrites every matching entry + user refs + default marker
tacctl scopes default [<name>]                  # show / set the default
tacctl scopes lookup <ip|cidr>                  # trace which scope owns an address (+ shadow overlaps)
tacctl scopes prefixes <name> list|add|remove|clear [--force]
tacctl scopes secret <name>   show|set <v>|generate
tacctl user scopes <user>     list|add|remove|set|clear
```

Removed: `tacctl config prefixes` and `tacctl config secret`. Both are now scope-owned. Old invocations print an explicit redirect to the new `scopes prefixes <name>` / `scopes secret <name>` forms.

### Configure connection filters
Use allow/deny lists for additional IP-level filtering:
```
tacctl config allow add 10.1.0.0/24
tacctl config deny add 10.99.0.0/24
```
Deny takes precedence over allow.

### Cisco priv-exec mappings
Cisco IOS gates command **availability** by privilege level (`privilege exec level X <cmd>`) independently of TACACS+ command authorization. Both gates must say yes for a command to run. Manage the mappings per group:
```
tacctl group privilege seed                  # built-in defaults (only verified move-DOWNs)
tacctl group privilege list operator         # show current mappings + source (explicit / default)
tacctl group privilege add operator 'show ip route'
tacctl group privilege remove operator 'show running-config'
```
Defaults move only verified priv-15 commands DOWN to lower groups (e.g. `show running-config` → priv 7 for `operator`); they never move commands UP from a lower default level (which would silently restrict them from `readonly` users). Mappings live in `/etc/tacquito/cisco-privileges.conf` and survive `tacctl upgrade`.

### Per-command authorization
Restrict which commands a group can run, enforced live by Cisco IOS via TACACS+. Quickest path is to seed the built-in groups with sensible defaults:
```
tacctl group commands seed                # all three built-ins
tacctl group commands seed operator       # just operator (refuses to overwrite without --force)
tacctl group commands list operator
```
Defaults: `readonly` permits show / ping / traceroute / terminal / navigation / `enable` and denies the rest; `operator` adds `clear test monitor` on top with default deny; `superuser` gets an unrestricted `*` catchall.

Or build rules manually:
```
tacctl group commands default operator deny
tacctl group commands add operator show --action permit
tacctl group commands add operator ping --action permit
```
The trailing `*` catchall encodes the default action. Once any group has rules, `tacctl config cisco` emits `aaa authorization commands 1/7/15 default group TACACS-GROUP local` so IOS asks tacquito per command. Juniper enforcement is local via class `allow-commands`/`deny-commands` regex — `tacctl config juniper` emits the equivalent `set system login class …` lines, but you must push them to each device.

When you add the first rule to a group, tacctl auto-seeds a `* permit` catchall onto sibling groups at the same Cisco priv-lvl so their users aren't accidentally locked out.

### Management ACL (Cisco VTY-ACL + Juniper lo0 filter)
Restrict which source subnets can reach the device management plane. Build the permit list once on the tacquito server:
```
tacctl config mgmt-acl add 10.1.0.0/16
tacctl config mgmt-acl add 192.168.5.0/24
tacctl config mgmt-acl list
```
`tacctl config cisco` then emits a populated `VTY-ACL` applied to `line vty 0 15` via `access-class VTY-ACL in`. `tacctl config juniper` emits a commented `set firewall family inet filter MGMT-SSH-ACL` block (including a trailing `default-accept` term to keep BGP/OSPF/IS-IS traffic to the RE working) — review and uncomment per device. The list lives at `/etc/tacquito/mgmt-acl.conf` and survives `tacctl upgrade`.

Rename the emitted ACL / filter names to match your site conventions:
```
tacctl config mgmt-acl cisco-name MGMT-ACCESS
tacctl config mgmt-acl juniper-name MGMT-SSH-FILTER
```
Overrides live at `/etc/tacquito/mgmt-acl-names.conf` and also survive `tacctl upgrade`.

### Prometheus metrics exporter
Tacquito ships a Prometheus HTTP exporter for auth-rate and error counters. By default it binds to **loopback only** (`127.0.0.1:8080`) — local scrapers on the box work out of the box, external scrapers are opt-in. Manage via:
```
tacctl config metrics                         # show current state + scrape URL
tacctl config metrics address 10.1.0.1:8080   # expose to external scrapers on a specific mgmt IP
tacctl config metrics disable                 # sink to 127.0.0.1:0 (unreachable ephemeral port)
tacctl config metrics enable                  # revert to loopback:8080 default
```
`disable` does not use tacquito's own `-export-promhttp=false` flag — upstream's handler unconditionally cancels the server context when the exporter goroutine returns, which would tear down the whole daemon. Binding to a loopback ephemeral port gives the same operator-visible result (no scraper can reach it) without requiring a tacquito patch.

### Log retention
Accounting logs are rotated daily and retained for 90 days (see `/etc/logrotate.d/tacquito`). Adjust the `rotate` value if your compliance requirements differ.

### Password age
The default password age warning is 90 days. Adjust with:
```
tacctl config password-age <days>
```

### Passwordless sudo for operators (opt-in)
By default, `tacctl` requires `sudo` authentication. To let a group run it without a password prompt, install a sudoers drop-in:
```
tacctl config sudoers install adm     # or: wheel, ops, etc.
```
This writes `/etc/sudoers.d/tacctl` (validated with `visudo -cf`) granting `%adm ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl`. Because `tacctl` can modify system config and restart services, this is effectively passwordless root for members of that group — the command prompts for confirmation before installing. Remove with `tacctl config sudoers remove`.

## Self-Service Password Generation

Users can generate their own bcrypt hash and provide it to an admin. The admin never sees the plaintext password.

Admins can print these same client-side commands on demand with:
```bash
tacctl hash commands
```

**On the server (if available):**
```bash
tacctl hash generate
```

**Linux / macOS:**
```bash
python3 -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (Python):**
```powershell
python -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (PowerShell, no Python):**
```powershell
Install-Module -Name BcryptNet -Scope CurrentUser
[BCrypt.Net.BCrypt]::HashPassword((Read-Host -AsSecureString "Password" | ConvertFrom-SecureString -AsPlainText))
```

**Admin adds with pre-generated hash:**
```bash
tacctl user add jsmith superuser --hash '$2b$12$...'
```

**Admin rotates an existing user's password with a pre-generated hash:**
```bash
tacctl user passwd jsmith --hash '$2b$12$...'
```

---

## CLI Reference

> For a single-page reference, run `man tacctl` after install.

### Command Conventions

These patterns apply uniformly across every subcommand family:

- **No arguments** — dispatcher commands (`user`, `group`, `config`, `scopes`, `log`, `backup`, `hash`, and nested dispatchers like `scopes prefixes` / `scopes secret` / `user scopes` / `group privilege`) print their own usage and exit without side effects. Scalar getter/setters (`config loglevel`, `config listen`, `config metrics`, `config password-age`, `config bcrypt-cost`, `config password-min-length`, `config secret-min-length`, `config branch`, `scopes default`) print the current value when called with no arguments.
- **Multi-item input** — every `add` / `remove` that takes a CIDR, a scope name, or a Cisco exec command accepts either a single value or a comma-separated list (`a,b,c`). Every input is validated first; a bad entry aborts the entire operation without writing anything.
- **CIDR semantics** — every CIDR-list subcommand (`scopes prefixes`, `config allow`, `config deny`, `config mgmt-acl`) canonicalizes input before storage: `10.1.5.5/24` becomes `10.1.5.0/24`, `2001:DB8::/32` becomes `2001:db8::/32`. Exact duplicates (after canonicalization) are rejected as no-ops on `add`. Overlapping CIDRs of different prefix lengths coexist (`10.0.0.0/8` and `10.99.0.0/16` can both be present). Stored order is by broadcast-address ascending (IPv4 before IPv6): disjoint ranges sort by their end address, and an overlapping subnet falls immediately above its containing supernet (the subnet's range ends before the supernet's). This groups related CIDRs together and gives tacquito's provider selector the "most-specific first among overlaps" ordering it needs so a narrower scope wins a first-match lookup over a broader scope that contains it.
- **Scope prefix invariants** — every CIDR belongs to **exactly one** scope after canonicalization. Adding a prefix already claimed by a different scope is rejected with a message naming the owner; you must `tacctl scopes prefixes <owner> remove <cidr>` before re-adding it elsewhere. Overlapping prefixes *across* scopes are allowed and routed correctly (e.g. `10.5.0.0/16` in `staging` coexists with `10.0.0.0/8` in `lab`). To make cross-scope first-match honor specificity, tacctl emits one `secrets:` entry per (scope, prefix) pair — a scope with N prefixes becomes N entries sharing the same `name:` and `secret.key`. Entries are re-sorted globally by prefix specificity (v4 before v6, smaller broadcast first) after every mutation, so tacquito's slice-ordered walk picks the narrowest scope. The CLI continues to show the logical one-bundle-per-scope view; do not hand-edit the `secrets:` block, and `tacctl config validate` flags any same-name key divergence.
- **`clear`** — `clear` subcommands always prompt with `[y/N]` and print a warning describing the resulting posture (e.g. "no clients can connect" or "fails open").
- **Service restart** — changes that mutate `/etc/tacquito/tacquito.yaml` restart the tacquito service automatically. Changes to tacctl-internal files (`mgmt-acl.conf`, `cisco-privileges.conf`, `mgmt-acl-names.conf`, `password-min-length`, etc.) do not — tacquito never reads them.
- **Flags** — long-form flags (`--hash`, `--scopes`, `--scope`, `--prefixes`, `--secret`, `--default`, `--match`, `--action`, `--force`, `--branch`) take a single argument. Required positional args come before flags.

### Top-Level Commands

```
tacctl install [--branch name]  # Install tacquito server from scratch
tacctl upgrade [--branch name]  # Pull latest source, rebuild, update scripts
tacctl uninstall                # Remove tacquito and all associated files
tacctl status                   # Service health, stats, errors, password age warnings
tacctl user <subcommand>        # User management (incl. per-user scope membership)
tacctl group <subcommand>       # Group management
tacctl scopes <subcommand>      # Scope management (CIDR+secret bundles)
tacctl config <subcommand>      # Configuration
tacctl log <subcommand>         # Log viewer
tacctl backup <subcommand>      # Backup management
tacctl hash                     # Show usage
tacctl hash generate            # Prompt + print a bcrypt hash
tacctl hash commands            # Print OS-specific client-side recipes
tacctl version                  # Print tacctl version
```

Run any command without arguments for detailed help.

### User Commands — `tacctl user`

```
user list                                         List all users (name, group, status, pw age, scopes)
user show <name>                                  Show user details incl. scope membership (no password prompt)
user add <name> <group>                           Add a new user; lands in default scope
user add <name> <group> --scopes <name>[,name...] Grant specific scopes at creation
user add <name> <group> --hash <hash>             Add user with pre-generated bcrypt hash
user remove <name>                                Remove a user (with confirmation)
user passwd <name>                                Change password (with confirmation)
user passwd <name> --hash <hash>                  Change password with pre-generated bcrypt hash
user disable <name>                               Disable (preserves hash for re-enable)
user enable <name>                                Re-enable a disabled user
user rename <old> <new>                           Rename a user
user move <name> <group>                          Move user to a different group (keeps password)
user verify <name>                                Show user details and verify password
user scopes <name>                                List the user's scopes (orphan refs flagged red)
user scopes <name> add <s>[,s...]                 Grant one or more scopes
user scopes <name> remove <s>[,s...]              Revoke one or more scopes
user scopes <name> set <s>[,s...]                 Replace the full scope list
user scopes <name> clear                          Wipe all scopes (with confirmation)
```

### Group Commands — `tacctl group`

```
group list                                                List all groups with Cisco priv-lvl, Juniper class, user count
group add <name> <priv-lvl> <class>                       Add a custom group
group edit <name> priv-lvl <0-15>                         Change Cisco privilege level
group edit <name> juniper-class <CLASS>                   Change Juniper class name
group remove <name>                                       Remove a custom group (built-ins protected)
group commands list <group>                               Show per-command rules + default action
group commands default <group> <permit|deny>              Set default action (catchall)
group commands add <group> <name> [--match <regex>]...    Add a command rule
                                  [--action permit|deny]
group commands remove <group> <name>                      Drop a rule
group commands clear <group>                              Wipe rules for a group
group commands seed [<group>] [--force]                   Populate built-ins with sensible defaults
group privilege list <group>                              Show Cisco priv-exec mappings
group privilege add <group> '<cmd>'[,'<cmd>'...]          Move one or more commands to the group's priv-lvl
group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove one or more mappings
group privilege clear <group>                             Wipe explicit mappings (revert to defaults)
group privilege seed [<group>] [--force]                  Populate built-ins with safe priv-exec defaults
```

**Default Groups:**

| Group | Cisco priv-lvl | Juniper class | Use Case |
|-------|---------------|---------------|----------|
| `readonly` | 1 | RO-CLASS | Monitoring, read-only |
| `operator` | 7 | OP-CLASS | Operational (show, ping, traceroute) |
| `superuser` | 15 | RW-CLASS | Full administrative access |

### Config Commands — `tacctl config`

```
config show                                 Show current configuration summary incl. per-scope breakdown
config cisco [--scope <name>]               Generate working Cisco device config for a scope (default if omitted)
config juniper [--scope <name>]             Generate working Juniper device config for a scope (default if omitted)
config validate                             Validate config syntax + scope integrity (orphan refs, default-scope marker)
config diff [timestamp]                     Diff current config vs a backup
config loglevel [debug|info|error]          Show or change log level
config listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset TCP listen address
config metrics <show|enable|disable|address <host:port>|reset>   Prometheus exporter control. Default: loopback-only 127.0.0.1:8080. `disable` sinks to 127.0.0.1:0 (unreachable ephemeral port) since tacquito's own disable flag would crash the server.
config sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
config password-age [days]                  Show or set password age warning threshold (default 90)
config bcrypt-cost [10-14]                  Show or set bcrypt cost factor for new hashes (default 12)
config password-min-length [8-64]           Show or set minimum interactive password length (default 12)
config secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)
config allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)
config deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)
config mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits (add/remove accept comma-lists)
config mgmt-acl cisco-name [name]           Show or set the emitted Cisco ACL name (default VTY-ACL)
config mgmt-acl juniper-name [name]         Show or set the emitted Juniper filter name (default MGMT-SSH-ACL)
config branch [name]                        Show or change the tacctl repo branch
```

Removed in this release: `config secret` and `config prefixes`. Use `tacctl scopes secret <name>` / `tacctl scopes prefixes <name>` instead — see **Scope Commands** below.

### Scope Commands — `tacctl scopes`

```
scopes list                                              List every (scope, prefix) pair in tacquito first-match order (numbered by slice position)
scopes show <name>                                       Full detail: prefixes, users, raw secret + posture, default-ness
scopes add <name> --prefixes <cidrs>                     Create a new scope
           [--secret <value>|--secret generate] [--default]
scopes remove <name> [--force]                           Delete. Refuses if users reference it unless --force
scopes rename <old> <new>                                Rewrites secrets[].name + every user's scopes[] + default marker
scopes default [<name>]                                  Show / set the default scope (tacctl-managed marker file)
scopes lookup <ip|cidr>                                  Resolve an IP/CIDR to the owning scope (+ shadowed overlaps)
scopes prefixes <name> list|add|remove|clear [--force]   Per-scope CIDR list (add/remove accept comma-lists; clear refuses if users reference unless --force)
scopes secret   <name> show|set <value>|generate         Per-scope shared secret (show prints the raw value + length/posture)
```

**Connection filters:** `deny` takes precedence over `allow`. Both empty = all connections accepted.

### Log Commands — `tacctl log`

```
log tail [n]              Show last N journal entries (default 20)
log search <term>         Search logs for a username or keyword (last 7 days)
log failures              Show auth failures from the last 24 hours
log accounting [n]        Show last N accounting log entries
```

### Backup Commands — `tacctl backup`

```
backup list               Show available config backups with timestamps
backup diff [timestamp]   Diff current config vs a backup (default: most recent)
backup restore <ts>       Restore a config backup (with confirmation)
```

Config backups are created automatically before every change. Last 30 backups are retained.

---

## Network Device Configuration

Use `tacctl config cisco` or `tacctl config juniper` to generate
copy-pasteable configs with your server's IP and shared secret pre-filled.

### Cisco IOS / IOS-XE

The generated config includes AAA setup, TACACS+ server definition, and operator
privilege level command mappings. All groups and their privilege levels are included
dynamically.

**Key points:**
- `local` fallback ensures access if TACACS+ is unreachable
- Custom privilege levels (2-14) require `privilege exec level` command mappings
- Use `config cisco` to regenerate after adding groups

### Juniper Junos

The generated config includes template user creation, TACACS+ server setup, and
verification commands. All groups and their Juniper classes are included dynamically.

**Key points:**
- Template users MUST exist before TACACS+ logins will work
- If a login fails silently after successful TACACS+ auth, the template user is missing
- Use `config juniper` to regenerate after adding groups

### Custom Templates

The generated Cisco and Juniper configs are rendered from template files using `${VAR}` placeholders (processed by `envsubst`). You can customize the output by editing the templates.

**Template locations** (checked in order):
1. `/etc/tacquito/templates/` — per-host overrides (takes precedence)
2. `config/templates/` in the repo — version-controlled defaults

**Template files:**
- `cisco.template` — Cisco IOS/IOS-XE device config
- `juniper.template` — Juniper Junos device config

**Available variables:**

| Variable | Used in | Description |
|----------|---------|-------------|
| `${SERVER_IP}` | Both | Auto-detected server IP address |
| `${SECRET}` | Both | Shared TACACS+ secret |
| `${PRIVILEGE_COMMANDS}` | Cisco | Pre-rendered privilege level command mappings |
| `${TEMPLATE_USERS}` | Juniper | Pre-rendered `set system login user` lines |
| `${TACPLUS_CONFIG}` | Juniper | Pre-rendered TACACS+ server setup commands |
| `${VERIFY_COMMANDS}` | Juniper | Pre-rendered `show configuration` commands |
| `${GROUP_SUMMARY}` | Both | Human-readable group mapping table |

**To customize:** copy the default template to the override location and edit it:
```bash
sudo cp /opt/tacctl/config/templates/cisco.template /etc/tacquito/templates/cisco.template
sudo vi /etc/tacquito/templates/cisco.template
```

**To reset to defaults:** remove the override file:
```bash
sudo rm /etc/tacquito/templates/cisco.template
```

---

## Upgrading

```bash
tacctl upgrade

# Switch to a specific branch during upgrade
tacctl upgrade --branch develop
```

The upgrade command:
1. Pulls latest tacquito server source and rebuilds the binary (if changed)
2. Pulls latest management scripts from `rett/tacctl` on GitHub
3. Updates system config files (service unit, logrotate, README) if changed
4. Restarts the service only if something changed
5. Re-executes itself if tacctl was updated during the pull

Use `--branch` to switch to a different branch (e.g., `develop` for pre-release features). You can also switch branches without upgrading: `tacctl config branch <name>`.

`/usr/local/bin/tacctl` is symlinked to `/opt/tacctl/bin/tacctl.sh`, so git pulls update it instantly.

---

## Troubleshooting

### Common Issues

**`bad secret detected for ip [x.x.x.x]`**
- Shared secret mismatch between server and device
- Identify which scope the client falls into: `tacctl scopes list` / `tacctl scopes show <name>`
- Regenerate that scope's key: `tacctl scopes secret <name> generate`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `tacctl user verify <username>`
- Reset: `tacctl user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `tacctl config juniper`

**No connection attempts reaching the server**
- Verify port 49 reachable: `telnet <server_ip> 49` from the device
- Check service is running: `tacctl status`
- Check listener network/address: `tacctl config listen show`

**Config change not taking effect**
- Manual edits to `tacquito.yaml` still require: `sudo systemctl restart tacquito` (tacquito hot-reloads only when written via the tool)
- Check for parse errors: `tacctl config validate`

### Useful Commands

```bash
tacctl status          # Health check with auth stats
tacctl log failures    # Recent auth failures
tacctl config validate # Check config syntax
tacctl config diff     # What changed since last backup
```

---

## License

MIT License. See [LICENSE](LICENSE).
