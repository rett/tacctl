# tacctl

Management toolkit for [tacquito](https://github.com/facebookincubator/tacquito), a TACACS+ server (RFC 8907) by Facebook Incubator. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices, plus WTI console servers.

## Quick Start

```bash
# Install on a new server
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl && tacctl install'

# Or upgrade an existing server (pulls latest from GitHub)
tacctl upgrade

# Fresh installs seed four built-ins: engineer/superuser, operator/operator,
# viewer/readonly (all disabled — set a password to activate), plus
# root/readonly as a permanent accounting-only sink (Junos internal daemons
# emit accounting packets as root; tacctl user passwd root is rejected).
tacctl user passwd engineer

# Or add your own (lands in the default 'lab' scope)
tacctl user add jsmith superuser

# Create a production scope and grant jsmith access to it
tacctl scope add prod --prefixes 10.10.0.0/16 --secret generate
tacctl user scope jsmith add prod

# Manage users
tacctl user list

# Show device configs with your server's IP and scope-specific secret pre-filled
tacctl config cisco                   # default scope
tacctl config cisco --scope prod      # specific scope
tacctl config cisco --scope prod --legacy   # legacy IOS 12.x syntax (pre-15.0 devices)
tacctl config juniper --scope prod
tacctl config wti --scope prod        # WTI console server: serial-menu walkthrough
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
      wti.template          # Default WTI console-server setup walkthrough
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
| `/etc/tacquito/tacctl.yaml` | Operator overrides — only keys you've changed. Absent keys inherit from the canonical defaults embedded in `bin/tacctl.sh`. Inspect with `tacctl config dump`; list canonical defaults with `tacctl config defaults`. |
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
tacctl scope add prod_dc_east  --prefixes 10.10.0.0/16      --secret generate
tacctl scope add prod_dc_west  --prefixes 10.20.0.0/16      --secret generate
tacctl scope add corp_campus   --prefixes 172.20.0.0/16     --secret generate
tacctl scope add lab_east      --prefixes 10.10.99.0/24     --secret generate   # carved from prod_dc_east
tacctl scope add sandbox       --prefixes 10.10.200.0/23    --secret generate   # carved from prod_dc_east

tacctl scope default prod_dc_east                  # optional: new users land in prod by default
tacctl user add alice superuser --scopes prod_dc_east,prod_dc_west
tacctl user add dev1 superuser  --scopes sandbox,lab_east    # no prod access

tacctl scope lookup 10.10.99.7                     # -> lab_east (shadowed by prod_dc_east, lab)
tacctl scope lookup 10.10.1.5                      # -> prod_dc_east (shadowed by lab)
```

Emit per-scope device configs:
```
tacctl config cisco --scope prod_dc_east            # prod's secret + header mentions sibling scopes
tacctl config juniper --scope lab_east
```

Scope management commands:
```
tacctl scope list                              # name, prefix list, user count, default marker
tacctl scope show <name>                       # full detail + raw secret + users + default-ness
tacctl scope add <name> --prefixes <cidrs>     # --secret <v> | --secret generate | --default
tacctl scope remove <name> [--force]           # refuses if users reference it; --force strips them
tacctl scope rename <old> <new>                # rewrites every matching entry + user refs + default marker
tacctl scope default [<name>]                  # show / set the default
tacctl scope lookup <ip|cidr>                  # trace which scope owns an address (+ shadow overlaps)
tacctl scope prefixes <name> list|add|remove|clear [--force]
tacctl scope secret <name>   show|set <v>|generate
tacctl user scope <user>     list|add|remove|set|clear
```

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
Defaults move only verified priv-15 commands DOWN to lower groups (e.g. `show running-config` → priv 7 for `operator`); they never move commands UP from a lower default level (which would silently restrict them from `readonly` users). Mappings live under `privileges.<group>` in `/etc/tacquito/tacctl.yaml` and survive `tacctl upgrade`.

### Per-command authorization
Restrict which commands a group can run, enforced live by Cisco IOS via TACACS+ and mirrored into Junos class `allow-commands`/`deny-commands` by `tacctl config juniper`. Tacctl ships sensible defaults embedded in the script — no seed step needed for fresh installs:

- `superuser`: unrestricted `*` catch-all (permit).
- `operator`: permits `show`, `ping`, `traceroute`, `terminal`; default **deny** catch-all.
- `readonly`: permits `show`, `ping`, `traceroute`; default **deny** catch-all (`terminal` omitted — `terminal monitor` can leak debug across sessions).

View the shipped defaults with `tacctl config defaults`; inspect a single group with `tacctl group commands list <group>`. Rules live under `commands.<group>` in `/etc/tacquito/tacctl.yaml`; tacquito.yaml's per-group `commands:` block is regenerated from that source on every mutation.

The `tacctl group commands seed` command is retained as a recovery tool — it re-applies the legacy seed rule set (with `enable`, `clear`, `monitor`, etc.) and should only be needed if you've customized and want to start over. On a fresh install, the shipped defaults above are already in effect.

Or build rules manually:
```
tacctl group commands default operator deny
tacctl group commands add operator show --action permit
tacctl group commands add operator ping --action permit
tacctl group commands add operator clear --match 'counters.*' --action permit
```
A rule's `name` is compared literally to the TACACS+ `cmd=` word. `--match` regexes are tested by tacquito against the command's **arguments only** — the space-joined `cmd-arg` values after the word, so `show running-config` is tested as `running-config`, never as the full line. A regex that repeats the command word (`^show .*$`) can never match and is rejected by `tacctl group commands add`; omit `--match` to cover any arguments. (tacctl ≤ 0.1.10 shipped defaults with that dead shape, which denied every `show` to operator/readonly users; `tacctl upgrade` heals any override still carrying it.)
The trailing `*` catchall encodes the default action. Once any group has rules, `tacctl config cisco` emits `aaa authorization commands 1/7/15 default group TACACS-GROUP local` so IOS asks tacquito per command. Juniper enforcement is local via class `allow-commands`/`deny-commands` regex — `tacctl config juniper` emits the equivalent `set system login class …` lines, but you must push them to each device.

When you add the first rule to a group, tacctl auto-seeds a `* permit` catchall onto sibling groups at the same Cisco priv-lvl so their users aren't accidentally locked out.

### Management ACL (Cisco VTY-ACL + Juniper lo0 filter)
Restrict which source subnets can reach the device management plane. Build the permit list once on the tacquito server:
```
tacctl config mgmt-acl add 10.1.0.0/16
tacctl config mgmt-acl add 192.168.5.0/24
tacctl config mgmt-acl list
```
`tacctl config cisco` then emits a populated `VTY-ACL` applied to `line vty 0 15` via `access-class VTY-ACL in`. `tacctl config juniper` emits a commented `set firewall family inet filter MGMT-ACL` block (including a trailing `default-accept` term to keep BGP/OSPF/IS-IS traffic to the RE working) — review and uncomment per device. The list lives under `mgmt_acl.permits` in `/etc/tacquito/tacctl.yaml` and survives `tacctl upgrade`.

Rename the emitted ACL / filter names to match your site conventions:
```
tacctl config mgmt-acl cisco-name MGMT-ACCESS
tacctl config mgmt-acl juniper-name MGMT-SSH-FILTER
```
Overrides live under `mgmt_acl.names.{cisco,juniper}` in `/etc/tacquito/tacctl.yaml` and also survive `tacctl upgrade`.

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

### TACACS+ login for Linux hosts
Linux hosts log in against tacquito through `pam_tacplus`. No current distribution packages a usable build and upstream is archived, so tacctl pins v1.7.0 (verified by commit hash) and builds it on each host.
```
tacctl config linux build                                  # once, on the server: prepare the source tarball
tacctl config linux script --scope prod -o enroll.sh       # install script for hosts in a scope
tacctl config linux remove-script -o unenroll.sh           # removal script (no secrets)
```
Copy the install script to the host and run it as root from a session you keep open. It:
- builds and installs `pam_tacplus` before creating any account (`gcc`, `make` and `libpam0g-dev` are installed with apt if missing; a host that already has the module from the same source is not rebuilt);
- creates a local account for each user in the scope, with a locked password and a UID that is the same on every host, in `tac-users` plus `tac-readonly`, `tac-operator` or `tac-superuser`;
- sends `sshd`, `sudo` and console `login` to TACACS+ for members of `tac-users` only (the shared `common-*` files and every other local account are untouched);
- grants `%tac-superuser` full sudo, authenticated with the TACACS+ password.

A reject from the server is final. If the server is unreachable, login falls through to the local password, which only pre-existing (adopted) accounts have. The script refuses to run unless a local administrator with a usable password exists outside the TACACS+ user list, and restores the PAM files if any step fails. Re-run it with `--accounts-only` after adding, removing or moving users.

The install script contains the scope's shared secret, and so do the root-only `/etc/pam.d/tacctl-*` files it writes: use a dedicated scope per host or host group, and keep TACACS+ traffic on a management network or tunnel (no Linux PAM client supports TACACS+ over TLS). `passwd` does not work for TACACS+ users; they change passwords with `tacctl passwd` on the server.

The removal script undoes the PAM edits and deletes the secret, module and sudoers drop-in. Accounts, home directories and the `tac-*` groups stay; it lists any account left with neither a local password nor an SSH key.

#### Enrolling hosts over SSH
`tacctl host` does the copy-and-run for you and keeps a registry of enrolled hosts:
```
tacctl host enroll admin@web1.example.net     # creates scope linux-web1 (the host's /32, own secret), installs, registers
tacctl host enroll --local                    # this machine
tacctl user scope jsmith add linux-web1       # give a user a login on that host...
tacctl host sync web1                         # ...and push the account (or: tacctl host sync --all)
tacctl host list
tacctl host unenroll web1                     # remove TACACS+ login; accounts and home directories stay
```
`ssh` runs as the user who invoked `sudo`, with their keys; the remote login must be root or able to `sudo` (a password prompt works when run from a terminal). `--scope` enrolls into an existing scope instead of creating one, `--server` overrides the detected server address, and `--port` / `--identity` are passed to ssh. Account changes are not pushed automatically: run `host sync` after `user add`, `remove`, `move` or `scope` changes. Until then a removed user is already refused at password login by the server, but an SSH key on the host keeps working.

#### Consistent UIDs and GIDs
Each user gets one number, used as both UID and primary GID on every host this server enrolls. It is assigned the first time the user is sent to a host (from 20000 up, never reused) and stored in `/etc/tacquito/linux-uids`.
```
tacctl config linux uid                  # list assignments
tacctl config linux uid jsmith           # print one
tacctl config linux uid jsmith 20500     # change it
```
If the number is already taken on a host, by a user or by a group, the install or sync **stops before changing anything** and lists the options:
1. free the number on the host by renumbering whatever holds it (`usermod -u` / `groupmod -g`, then `chown` its files);
2. assign the tacctl user a number that is free everywhere (`tacctl config linux uid <user> <uid>`) and re-run;
3. accept a different number on that host only: `tacctl host enroll|sync ... --allow-uid-mismatch`.

Accounts that existed before enrollment are adopted with the UID they already have; every sync reports the difference and how to fix it. Changing an assignment does not renumber accounts already created on hosts. Two tacctl servers assign independently, so copy `linux-uids` between them if their hosts must agree.

#### Accounts that already exist on a host
If a host already has a local account with the same name as a TACACS+ user, the install or sync stops before changing anything: a matching name does not prove it is the same person. The message lists the options: confirm it with `--adopt <name>[,<name>...]` on `tacctl host enroll` or `sync`, rename the tacctl user or keep it off that host, or remove the local account.

An adopted account keeps its UID, local password, files and groups; tacctl only adds it to `tac-users` and its tier group. Two consequences are reported when they apply:
- at adoption, if the account is in a privileged local group (`sudo`, `wheel`, `adm`, `docker`, ...), since those rights hold whatever the TACACS+ tier is;
- when the user is later removed from the scope or disabled, since an adopted account is **not** locked or expired (accounts tacctl created are): it goes back to being a plain local account, and the sync says whether its local password or an SSH key still works and how to block it (`usermod -L -e 1 <name>`).

### Tiered access for TACACS+ users (opt-in)
TACACS+ users who have a local account on the server can be given tacctl access that follows their group:
```
tacctl config sudoers tiers show      # print the rules
tacctl config sudoers tiers install   # write /etc/sudoers.d/tacctl-tiers
```
| Local group | Tier (priv-lvl) | tacctl access |
|---|---|---|
| `tac-readonly` | read-only (below 7) | `passwd`, `status`, `version`, `user list`, `user show`, `group list`, `scope list` |
| `tac-operator` | operator (7-14) | read-only set plus `log tail/search/failures/accounting`, `config validate`, `backup list` |
| `tac-superuser` | superuser (15) | everything, plus full `sudo` |

Lower-tier rules are `NOPASSWD`. Anything that prints a shared secret or a password hash (`config cisco|juniper|wti`, `scope show`, `scope secret`, `backup diff`, `config dump`) stays superuser-only. tacctl also checks the tier itself on every run, taking it from the user's group in `tacquito.yaml` rather than from local group membership, and logs denials to syslog. Callers who are not in the local group `tac-users` (root, local admins) are not restricted.

`tacctl passwd` (no arguments) lets any tier change their own password: it acts only on the user who invoked sudo and asks for the current password first.

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

- **No arguments** — dispatcher commands (`user`, `group`, `config`, `scope`, `log`, `backup`, `hash`, and nested dispatchers like `scope prefixes` / `scope secret` / `scope aaa-order` / `scope exec-timeout` / `scope tacacs-group` / `scope mgmt-acl` / `user scope` / `group privilege`) print their own usage and exit without side effects. Scalar getter/setters (`config loglevel`, `config listen`, `config metrics`, `config password-age`, `config bcrypt-cost`, `config password-min-length`, `config secret-min-length`, `config branch`, `scope default`) print the current value when called with no arguments.
- **Multi-item input** — every `add` / `remove` that takes a CIDR, a scope name, or a Cisco exec command accepts either a single value or a comma-separated list (`a,b,c`). Every input is validated first; a bad entry aborts the entire operation without writing anything.
- **CIDR semantics** — every CIDR-list subcommand (`scope prefixes`, `config allow`, `config deny`, `config mgmt-acl`) canonicalizes input before storage: `10.1.5.5/24` becomes `10.1.5.0/24`, `2001:DB8::/32` becomes `2001:db8::/32`. Exact duplicates (after canonicalization) are rejected as no-ops on `add`. Overlapping CIDRs of different prefix lengths coexist (`10.0.0.0/8` and `10.99.0.0/16` can both be present). Stored order is by broadcast-address ascending (IPv4 before IPv6): disjoint ranges sort by their end address, and an overlapping subnet falls immediately above its containing supernet (the subnet's range ends before the supernet's). This groups related CIDRs together and gives tacquito's provider selector the "most-specific first among overlaps" ordering it needs so a narrower scope wins a first-match lookup over a broader scope that contains it.
- **Scope prefix invariants** — every CIDR belongs to **exactly one** scope after canonicalization. Adding a prefix already claimed by a different scope is rejected with a message naming the owner; you must `tacctl scope prefixes <owner> remove <cidr>` before re-adding it elsewhere. Overlapping prefixes *across* scopes are allowed and routed correctly (e.g. `10.5.0.0/16` in `staging` coexists with `10.0.0.0/8` in `lab`). To make cross-scope first-match honor specificity, tacctl emits one `secrets:` entry per (scope, prefix) pair — a scope with N prefixes becomes N entries sharing the same `name:` and `secret.key`. Entries are re-sorted globally by prefix specificity (v4 before v6, smaller broadcast first) after every mutation, so tacquito's slice-ordered walk picks the narrowest scope. The CLI continues to show the logical one-bundle-per-scope view; do not hand-edit the `secrets:` block, and `tacctl config validate` flags any same-name key divergence.
- **`clear`** — `clear` subcommands always prompt with `[y/N]` and print a warning describing the resulting posture (e.g. "no clients can connect" or "fails open").
- **Service restart** — changes that mutate `/etc/tacquito/tacquito.yaml` restart the tacquito service automatically. Changes to `/etc/tacquito/tacctl.yaml` (mgmt-acl permits + names, bcrypt cost, password age, privileges, etc.) do not — tacquito never reads that file.
- **Flags** — long-form flags (`--hash`, `--scopes`, `--scope`, `--prefixes`, `--secret`, `--default`, `--match`, `--action`, `--force`, `--branch`) take a single argument. Required positional args come before flags.

### Top-Level Commands

```
tacctl install [--branch name]  # Install tacquito server from scratch
tacctl upgrade [--branch name]  # Pull latest source, rebuild, update scripts
tacctl uninstall                # Remove tacquito and all associated files
tacctl status                   # Service health, stats, errors, password age warnings
tacctl user <subcommand>        # User management (incl. per-user scope membership)
tacctl group <subcommand>       # Group management
tacctl scope <subcommand>      # Scope management (CIDR+secret bundles)
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
user add <name> <group>                           Add a new user; lands in default scope. Reserved names `root` and `tacquito` are rejected (they collide with OS accounts tacquito resolves locally).
user add <name> <group> --scopes <name>[,name...] Grant specific scopes at creation
user add <name> <group> --hash <hash>             Add user with pre-generated bcrypt hash
user remove <name>                                Remove a user (with confirmation)
user passwd <name>                                Change password (with confirmation)
passwd                                            Change your own password (asks for the current one; all tiers)
user passwd <name> --hash <hash>                  Change password with pre-generated bcrypt hash
user disable <name>                               Disable (preserves hash for re-enable)
user enable <name>                                Re-enable a disabled user
user rename <old> <new>                           Rename a user
user move <name> <group>                          Move user to a different group (keeps password)
user verify <name>                                Show user details and verify password
user scope <name>                                 List the user's scopes (orphan refs flagged red)
user scope <name> add <s>[,s...]                  Grant one or more scopes
user scope <name> remove <s>[,s...]               Revoke one or more scopes
user scope <name> set <s>[,s...]                  Replace the full scope list
user scope <name> clear                           Wipe all scopes (with confirmation)
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

| Group | Cisco priv-lvl | Juniper class | WTI access level | Use Case |
|-------|---------------|---------------|------------------|----------|
| `readonly` | 1 | RO-CLASS | ViewOnly | Monitoring, read-only |
| `operator` | 7 | OP-CLASS | User | Operational (show, ping, traceroute) |
| `superuser` | 15 | RW-CLASS | Administrator | Full administrative access |

The WTI column is derived from the Cisco priv-lvl (WTI bands: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator); a group at priv-lvl 10-14 is the only way to land in the SuperUser band.

### Config Commands — `tacctl config`

```
config show                                 Show current configuration summary incl. per-scope breakdown
config dump                                 Show tacctl defaults + overrides + merged view
config defaults                             Print canonical tacctl defaults (shipped, embedded in bin/tacctl.sh)
config get <path> [fallback]                Read a dotted-path value from the merged config
config get-list <path>                      Read a list value (one item per line)
config cisco [--scope <name>] [--legacy]    Generate working Cisco device config for a scope (default if omitted). --legacy emits IOS 12.x syntax (tacacs-server host / aaa group server ... / server <ip>) for devices predating the IOS 15.0 'tacacs server' block
config juniper [--scope <name>]             Generate working Juniper device config for a scope (default if omitted)
config wti [--scope <name>]                 Print the step-by-step serial-menu procedure for a WTI console server (firmware v8.x) with the scope's server IP, secret, and group→access-level mapping filled in
config validate                             Validate YAML syntax + server-config structure (orphan scope refs, scope.default pointing at a nonexistent scope, reserved usernames, missing accounter:) + schema-walk tacctl.yaml (including commands.<group> / privileges.<group> / mgmt_acl.*)
config diff [timestamp]                     Diff current config vs a backup
config loglevel [debug|info|error]          Show or change log level
config listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset TCP listen address
config metrics <show|enable|disable|address <host:port>|reset>   Prometheus exporter control. Default: loopback-only 127.0.0.1:8080. `disable` sinks to 127.0.0.1:0 (unreachable ephemeral port) since tacquito's own disable flag would crash the server.
host list                                   Show enrolled Linux hosts
host enroll <[user@]host>|--local [opts]    Install TACACS+ login on a host over SSH and register it
host sync <name>|--all                      Push account adds, removals and tier changes
host unenroll <name> [--force]              Remove TACACS+ login from a host (accounts are kept)
config linux uid [<user> [<uid>]]           Show or change the UID/GID a user gets on every host
config linux build|script|remove-script     TACACS+ login for Linux hosts (pam_tacplus install/removal scripts)
config sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
config sudoers tiers [show|install|remove]  Manage per-tier (RO/OP/SU) sudoers rules for TACACS+ users
config password-age [days]                  Show or set password age warning threshold (default 90)
config bcrypt-cost [10-14]                  Show or set bcrypt cost factor for new hashes (default 12)
config password-min-length [8-64]           Show or set minimum interactive password length (default 12)
config secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)
config allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)
config deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)
config mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits (add/remove accept comma-lists)
config mgmt-acl cisco-name [name]           Show or set the emitted Cisco ACL name (default VTY-ACL)
config mgmt-acl juniper-name [name]         Show or set the emitted Juniper filter name (default MGMT-ACL)
config branch [name]                        Show or change the tacctl repo branch
```

#### Configuration tunables — `tacctl.yaml`

tacctl ships canonical tunable defaults embedded in `bin/tacctl.sh` (dumped on demand via `tacctl config defaults`). Operator overrides live in a single file: `/etc/tacquito/tacctl.yaml`. Only list keys you want to change; missing keys inherit from the defaults. Setting a key back to the default value removes it (revert-to-default) and an empty overrides file is pruned.

Schema (what `tacctl config defaults` prints):

```yaml
password:
  max_age_days: 90           # warning threshold in `tacctl status`  (int, >= 1)
  min_length: 12             # floor for interactively-typed passwords  (int, 8..64)

secret:
  min_length: 16             # floor for operator-typed shared secrets  (int, 16..128)

bcrypt:
  cost: 12                   # applies only to new hashes  (int, 10..14)

scope:
  default: lab               # matches the fresh-install seed scope; override via `tacctl scope default`

mgmt_acl:
  names:
    cisco: VTY-ACL           # ACL name emitted by `tacctl config cisco`  (letter-start, [A-Za-z0-9_-], 1..63)
    juniper: MGMT-ACL    # filter name emitted by `tacctl config juniper`  (same rules)
  permits: []                # list of CIDRs; each element validated

privileges:                  # per-group Cisco priv-exec lowering (move commands DOWN from priv 15)
  operator:
    - show running-config
    - show startup-config
    - show tech-support
    - show archive
    - show access-list
    - show ip route

commands:                    # per-group command-authz rules. Rendered for both Cisco
                             # (tacquito enforces) and Juniper (class allow/deny-commands)
                             # from this single tacctl-authored source. Ordered
                             # superuser → operator → readonly.
  superuser:
    - { name: "*", action: permit }
  operator:
    - { name: show,       action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: terminal,   action: permit }
    - { name: "*",        action: deny }
  readonly:
    - { name: show,       action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: "*",        action: deny }
```

Merge semantics:
- Maps deep-merge (overriding `password.max_age_days` keeps the default `password.min_length`).
- Lists replace wholesale (an override list does not concatenate with the default list).
- Scalars replace.

**Write-time validation.** Every `tacctl config <setter>` invocation (and direct `conf_set` / `conf_set_list` calls) check the value against a schema table defined next to the defaults. Out-of-range numbers, bad ACL names, malformed CIDRs, invalid Cisco command strings, and typo'd keys are rejected with a clear error before anything is written. `tacctl config validate` runs the same schema over `tacctl.yaml` to catch hand-edits.

**Read path caching.** Every read merges defaults + overrides and walks the dotted path, but the merged view is cached per script invocation (`_TACCTL_CFG_CACHE`). Commands that touch many tunables (`config cisco`, `status`, `config show`) load the merged YAML once and then answer from memory. Writes invalidate the cache.

View effective posture with `tacctl config dump`; read individual values with `tacctl config get <path>` / `tacctl config get-list <path>`.

### Scope Commands — `tacctl scope`

```
scope list                                               One row per scope (deduplicated; prefixes joined)
scope routing                                            One row per (scope, prefix) — tacquito first-match order
scope show <name>                                        Full detail: prefixes, users, raw secret + posture, default-ness
scope add <name> --prefixes <cidrs>                      Create a new scope
          [--secret <value>|--secret generate] [--default]
scope remove <name> [--force]                            Delete. Refuses if users reference it unless --force
scope rename <old> <new>                                 Rewrites secrets[].name + every user's scopes[] + default marker
scope default [<name>]                                   Show / set the default scope (tacctl-managed marker file)
scope lookup <ip|cidr>                                   Resolve an IP/CIDR to the owning scope (+ shadowed overlaps)
scope prefixes <name> list|add|remove|clear [--force]    Per-scope CIDR list (add/remove accept comma-lists; clear refuses if users reference unless --force)
scope secret   <name> show|set <value>|generate          Per-scope shared secret (show prints the raw value + length/posture)
scope aaa-order <name> [tacacs-first|local-first]        Order of TACACS+ vs local in this scope's generated Cisco / Junos AAA lines. Default `tacacs-first` keeps TACACS+ authoritative (local only kicks in on server outage). Set `local-first` when a break-glass local account must authenticate while tacquito is still reachable — any local name that collides with a TACACS+ user wins locally, so scope local accounts to emergency credentials only.
scope exec-timeout <name> [minutes]                      Per-scope idle-session timeout for this scope's generated device configs. Cisco renders `exec-timeout <n> 0` on `line con 0` / `line vty 0 15`; Junos renders `set system login idle-timeout <n>`. Range 0..60 (Junos's max); `0` disables idle expiry on both vendors. Default 60.
scope tacacs-group <name> [label]                        Per-scope Cisco `aaa group server tacacs+ <LABEL>` name. Rendered into every AAA group + method-list line for that scope. Must conform to Cisco ACL naming rules (letter-start, letters/digits/_/-). Default `TACACS-GROUP`. Junos has no equivalent.
scope mgmt-acl <name> list|add|remove|clear [cidrs]      Per-scope permit list. Mirrors the global `tacctl config mgmt-acl list|add|remove|clear`. Falls back to the global `mgmt_acl.permits` when this scope's list is empty, so per-scope use is reserved for scopes that genuinely need different permits than the house default. `clear` unsets the per-scope override (renders fall back to global).
scope mgmt-acl <name> cisco-name|juniper-name [label]    Per-scope mgmt-acl / filter name. Mirrors the global `tacctl config mgmt-acl cisco-name|juniper-name`. Cisco renders `ip access-list standard <LABEL>` + `access-class <LABEL> in`; Junos renders `set firewall family inet filter <LABEL>` + lo0 filter apply. Fallback chain: per-scope override → global (`tacctl config mgmt-acl …`) → shipped default (`VTY-ACL` / `MGMT-ACL`).
```

**Connection filters:** `deny` takes precedence over `allow`. Both empty = all connections accepted.

### Log Commands — `tacctl log`

```
log tail [n]              Show last N journal entries (default 20)
log search <term>         Search logs for a username or keyword (last 7 days)
log failures              Show auth failures from the last 24 hours
log accounting [n]        Show last N accounting log entries
log clear [--force]       Purge tacquito journal + truncate accounting log (prompts)
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
copy-pasteable configs with your server's IP and shared secret pre-filled,
or `tacctl config wti` for a menu-by-menu walkthrough of a WTI console server.

### Cisco IOS / IOS-XE

The generated config includes AAA setup, TACACS+ server definition, and operator
privilege level command mappings. All groups and their privilege levels are included
dynamically.

**Key points:**
- `local` fallback ensures access if TACACS+ is unreachable
- Custom privilege levels (2-14) require `privilege exec level` command mappings
- Use `config cisco` to regenerate after adding groups
- By default the output uses the modern IOS 15.0+ `tacacs server <name>` block. For older devices
  (e.g. IOS 12.4), add `--legacy` to emit the global `tacacs-server host` / `aaa group server ... / server <ip>`
  syntax instead. Only the server-definition block changes; the AAA, privilege, and line config are identical.

### Juniper Junos

The generated config includes template user creation, TACACS+ server setup, and
verification commands. All groups and their Juniper classes are included dynamically.

**Key points:**
- Template users MUST exist before TACACS+ logins will work
- If a login fails silently after successful TACACS+ auth, the template user is missing
- Use `config juniper` to regenerate after adding groups

### WTI Console Servers (DSM/CPM/REM/TSM/RSM, firmware v8.x)

WTI units are configured through numbered text menus on the serial SetUp port, so
`tacctl config wti` prints a walkthrough instead of a pasteable config: `/N` → the
**TACACS** entry (item 28 on recent firmware) → one value per menu item, then `[Esc]`
until "Saving Configuration". No WTI-specific service is added to `tacquito.yaml` — the
unit requests exec authorization and reads the standard `priv-lvl` attribute from the same
`shell` service Cisco uses. WTI maps priv-lvl bands to its four access levels:

| priv-lvl | WTI access level | Shipped group |
|----------|------------------|---------------|
| 0-4 | ViewOnly (only the ports/services granted under Default TACACS User Access; factory: none) | `readonly` (1) |
| 5-9 | User (only the ports/services granted under Default TACACS User Access; factory: none) | `operator` (7) |
| 10-14 | SuperUser (all ports/plugs; no configuration menus) | *(add a group at 10-14)* |
| 15 | Administrator | `superuser` (15) |

**Key points:**
- WTI authenticates with **PAP**; tacquito's bcrypt authenticator handles PAP, nothing to change server-side
- **Account Management Module = Enabled** is the authorization request that carries `priv-lvl`; **Session Management Module = Enabled** is accounting (the unit's client uses PAM terminology). Accounting needs tacquito built with `patches/0002` (empty `server_msg` on accounting success): given upstream's `success, logging started` message, the unit drops the SSH session right after login. `tacctl install` / `tacctl upgrade` apply the patch overlay
- **Service Name** is set to `shell` so the unit's request matches tacquito's configured service directly. The factory default `wti` also works, but only through the default-service-permit patch in `patches/` (an unmatched service is answered with the group's `shell` priv-lvl)
- **Fallback Local** follows the scope's `aaa-order`: `tacacs-first` → `On (Transport Failure)`, `local-first` → `On (All Failures)`. Keep a local Administrator account on the unit as break-glass
- **Default User Access must be `On`** (Access Level `ViewOnly` as the least-privilege floor; the returned `priv-lvl` still sets the effective level). SSH logins go through the unit's OpenSSH, which has to resolve the account locally: with it `Off`, a TACACS-only user is invalid to sshd, which forwards a junk password (`\b\n\r\177INCORRECT…`), so tacquito logs `failed to validate the user` on every attempt no matter what was typed
- If the unit's **IP Tables** (`/N`) end in `DROP`, they must accept `-i lo` and `-m conntrack --ctstate ESTABLISHED,RELATED` before the final DROP. Otherwise the unit's TACACS+ SYN leaves but tacquito's SYN-ACK is dropped: every login waits out the Fallback Timer, and tacquito logs nothing (only SYNs in tcpdump, half-open sockets in `ss`). The unit's Ping Test passes regardless — it is ICMP only
- Test the first login with `ssh -o PreferredAuthentications=password <user>@<wti>`. If a plain `ssh` is closed without a password prompt while the password method works, the unit's Invalid Access Lockout is armed from earlier failures — `/UL` clears it
- Port and service access for User/ViewOnly-level logins is defined only under Default TACACS User Access → Configure Port Access / Service Access (factory: Administrator and SuperUser get all ports, User and ViewOnly get none). A same-named local account on the unit overrides the server-assigned level, so keep the two directories disjoint
- The output warns when the scope secret contains whitespace/punctuation or exceeds 32 characters, or when a scope member's username exceeds WTI's 32-character limit — regenerate a hex-only key with `tacctl scope secret <name> set $(openssl rand -hex 16)`
- Verify with `tacctl config loglevel debug` + `tacctl log tail`: `accepting user [x] using a bcrypt password` (PAP), then `client args [service=shell ...]`, then `authorized user [x] ... [priv-lvl=N]`; accounting (start at login, stop after `/X`) lands in `tacctl log accounting`. On the unit, TACACS Parameters → `12. Debug: On` echoes every exchange on the serial session — turn it back `Off` when done

### Custom Templates

The generated Cisco, Juniper, and WTI output is rendered from template files using `${VAR}` placeholders (processed by `envsubst`). You can customize the output by editing the templates.

**Template locations** (checked in order):
1. `/etc/tacquito/templates/` — per-host overrides (takes precedence)
2. `config/templates/` in the repo — version-controlled defaults

**Template files:**
- `cisco.template` — Cisco IOS/IOS-XE device config
- `juniper.template` — Juniper Junos device config
- `wti.template` — WTI console-server serial-menu walkthrough

**Available variables:**

| Variable | Used in | Description |
|----------|---------|-------------|
| `${SERVER_IP}` | All | Auto-detected server IP address |
| `${SECRET}` | All | Shared TACACS+ secret |
| `${PRIVILEGE_COMMANDS}` | Cisco | Pre-rendered privilege level command mappings |
| `${TEMPLATE_USERS}` | Juniper | Pre-rendered `set system login user` lines |
| `${TACPLUS_CONFIG}` | Juniper | Pre-rendered TACACS+ server setup commands |
| `${VERIFY_COMMANDS}` | Juniper | Pre-rendered `show configuration` commands |
| `${GROUP_SUMMARY}` | All | Human-readable group mapping table |
| `${SCOPE}` | WTI | Name of the scope being rendered |
| `${FALLBACK_LOCAL}` | WTI | `On (Transport Failure)` or `On (All Failures)`, from the scope's `aaa-order` |
| `${SERVICE_NAME}` | WTI | Authorization service name the unit should send (`shell`) |

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
- Identify which scope the client falls into: `tacctl scope list` / `tacctl scope show <name>`
- Regenerate that scope's key: `tacctl scope secret <name> generate`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `tacctl user verify <username>`
- Reset: `tacctl user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `tacctl config juniper`

**WTI login refused, or lands at the wrong access level**
- `tacctl config loglevel debug`, retry, then `tacctl log tail 50`: the `client args [...]` line shows the service name the unit sent. If it is not `shell`, set TACACS Parameters → Service Name to `shell` (or confirm the default-service-permit patch is applied: `tacctl status`)
- No authorization request at all → Account Management Module is Disabled on the unit
- `failed to validate the user [x] using a bcrypt password` on every attempt although `tacctl user verify` accepts the password → Default User Access is `Off` on the unit (its sshd sends a junk password for users it cannot resolve); set it `On` / Access Level `ViewOnly`
- Nothing in the tacquito log while the unit waits the Fallback Timer, SYNs visible in tcpdump → the unit's IP Tables drop tacquito's replies; add the `ESTABLISHED,RELATED` accept rule before the final DROP
- Login succeeds, then the session drops (`Broken pipe`) with an accounting start but no stop → tacquito lacks `patches/0002`; run `tacctl upgrade`, or disable the unit's Session Management Module until it is rebuilt
- Level is right but no ports are reachable → User/ViewOnly-level accounts only get the ports granted under Default TACACS User Access → Configure Port Access (factory: none)
- Level is wrong for one user only → a same-named local account on the unit overrides the server-assigned level
- `bad secret detected` in `tacctl log failures` → Secret Word was mistyped or truncated on the unit; `unknown authenticate start packet type` → the unit did not send PAP with TACACS+ minor version 1 (open an issue)
- Set TACACS Parameters → `12. Debug: On` on the unit to see the exchange from its side

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
