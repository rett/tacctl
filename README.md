# tacctl

Management toolkit for [tacquito](https://github.com/facebookincubator/tacquito), a TACACS+ server (RFC 8907) by Facebook Incubator. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices.

## Quick Start

```bash
# Install on a new server
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl && tacctl install'

# Or upgrade an existing server (pulls latest from GitHub)
tacctl upgrade

# After install, add your first user
tacctl user add jsmith superuser

# Manage users
tacctl user list

# Show device configs with your server's IP and secret pre-filled
tacctl config cisco
tacctl config juniper
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

### Restrict allowed prefixes
The default config allows all RFC 1918 space. After install, restrict to your actual management subnets:
```
tacctl config prefixes 10.1.0.0/24,172.16.5.0/24
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

### Top-Level Commands

```
tacctl install [--branch name]  # Install tacquito server from scratch
tacctl upgrade [--branch name]  # Pull latest source, rebuild, update scripts
tacctl uninstall                # Remove tacquito and all associated files
tacctl status                   # Service health, stats, errors, password age warnings
tacctl user <subcommand>        # User management
tacctl group <subcommand>       # Group management
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
user list                              List all users (name, group, status, password age)
user show <name>                       Show user details (read-only; no password prompt)
user add <name> <group>                Add a new user (password prompted with confirmation)
user add <name> <group> --hash <hash>  Add user with pre-generated bcrypt hash
user remove <name>                     Remove a user (with confirmation)
user passwd <name>                     Change password (with confirmation)
user passwd <name> --hash <hash>       Change password with pre-generated bcrypt hash
user disable <name>                    Disable (preserves hash for re-enable)
user enable <name>                     Re-enable a disabled user
user rename <old> <new>                Rename a user
user move <name> <group>               Move user to a different group (keeps password)
user verify <name>                     Show user details and verify password
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
group privilege add <group> '<command>'                   Move a command to the group's priv-lvl
group privilege remove <group> '<command>'                Remove a mapping
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
config show                                 Show current configuration summary
config cisco                                Generate working Cisco device config
config juniper                              Generate working Juniper device config
config validate                             Validate config syntax and structure
config diff [timestamp]                     Diff current config vs a backup
config secret [value]                       Change shared secret
config loglevel [debug|info|error]          Show or change log level
config listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset TCP listen address
config sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
config password-age [days]                  Show or set password age warning threshold (default 90)
config bcrypt-cost [10-14]                  Show or set bcrypt cost factor for new hashes (default 12)
config password-min-length [8-64]           Show or set minimum interactive password length (default 12)
config secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)
config prefixes list|add|remove|clear       Manage secret-provider client prefixes
config prefixes [cidr,...]                  (legacy) replace the entire prefixes block
config allow list|add|remove                Manage connection allow list (IP ACL)
config deny list|add|remove                 Manage connection deny list (IP ACL)
config mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits
config branch [name]                        Show or change the tacctl repo branch
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
- Regenerate with hex-only: `tacctl config secret`
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
