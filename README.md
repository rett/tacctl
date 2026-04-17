# tacctl

Management toolkit for [tacquito](https://github.com/facebookincubator/tacquito), a TACACS+ server (RFC 8907) by Facebook Incubator. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices.

## Quick Start

```bash
# Install on a new server
sudo ./bin/tacquito-install.sh

# Or upgrade an existing server (pulls latest from GitHub)
sudo tacquito-upgrade

# Manage users
sudo tacctl user list
sudo tacctl user add jsmith superuser

# Show device configs with your server's IP and secret pre-filled
sudo tacctl config cisco
sudo tacctl config juniper
```

## Project Structure

```
tacctl/
  bin/
    tacquito-install.sh     # Automated installer (Go, build, configure, start)
    tacctl.sh               # Management CLI (symlinked to /usr/local/bin/tacctl)
    tacquito-uninstall.sh   # Uninstaller (removes server, scripts, config, and data)
    tacquito-upgrade.sh     # Upgrade script (symlinked to /usr/local/bin/tacquito-upgrade)
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
| `/var/log/tacquito/accounting.log` | Accounting records |
| `/etc/tacquito/backups/` | Config backups and password dates |
| `/usr/local/bin/tacquito` | Server binary |
| `/usr/local/bin/tacctl` | Symlink to management CLI |
| `/usr/local/bin/tacquito-upgrade` | Symlink to upgrade script |
| `/usr/local/bin/tacquito-hashgen` | Password hash generator |
| `/etc/tacquito/templates/` | Custom device config templates (override defaults) |
| `/opt/tacctl/` | Git clone of this repo (used by upgrade) |
| `/opt/tacquito-src/` | Tacquito server source code |

## Important Notes

- **IPv4 only:** The service runs with `-network tcp`. The default `tcp6` (dual-stack) breaks IPv4 prefix matching.
- **Shared secrets:** Use hex-only secrets (`openssl rand -hex 16`) to avoid quoting issues on devices.
- **Juniper template users are required:** Every `local-user-name` value (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each Juniper device. Without this, TACACS+ auth succeeds but Junos rejects the login.
- **Config edits:** The `tacctl` tool handles service restarts automatically. Manual edits with `sed -i` require a manual restart.

---

## CLI Reference

### Top-Level Commands

```
sudo tacctl status              # Service health, stats, errors, password age warnings
sudo tacctl user <subcommand>   # User management
sudo tacctl group <subcommand>  # Group management
sudo tacctl config <subcommand> # Configuration
sudo tacctl log <subcommand>    # Log viewer
sudo tacctl backup <subcommand> # Backup management
```

Run any command without arguments for detailed help.

### User Commands — `tacctl user`

```
user list                    List all users (name, group, status, password age)
user add <name> <group>      Add a new user (password prompted with confirmation)
user remove <name>           Remove a user (with confirmation)
user passwd <name>           Change password (with confirmation)
user disable <name>          Disable (preserves hash for re-enable)
user enable <name>           Re-enable a disabled user
user rename <old> <new>      Rename a user
user move <name> <group>     Move user to a different group (keeps password)
user verify <name>           Show user details and verify password
```

### Group Commands — `tacctl group`

```
group list                               List all groups with Cisco priv-lvl, Juniper class, user count
group add <name> <priv-lvl> <class>      Add a custom group
group edit <name> priv-lvl <0-15>        Change Cisco privilege level
group edit <name> juniper-class <CLASS>  Change Juniper class name
group remove <name>                      Remove a custom group (built-ins protected)
```

**Default Groups:**

| Group | Cisco priv-lvl | Juniper class | Use Case |
|-------|---------------|---------------|----------|
| `readonly` | 1 | RO-CLASS | Monitoring, read-only |
| `operator` | 7 | OP-CLASS | Operational (show, ping, traceroute) |
| `superuser` | 15 | RW-CLASS | Full administrative access |

### Config Commands — `tacctl config`

```
config show                          Show current configuration summary
config cisco                         Generate working Cisco device config
config juniper                       Generate working Juniper device config
config validate                      Validate config syntax and structure
config diff [timestamp]              Diff current config vs a backup
config secret [value]                Change shared secret
config loglevel [debug|info|error]   Show or change log level
config password-age [days]           Show or set password age warning threshold (default 90)
config juniper-ro [class]            Change Juniper read-only class name
config juniper-rw [class]            Change Juniper super-user class name
config prefixes [cidr,...]           Change allowed device subnets
config allow list|add|remove         Manage connection allow list (IP ACL)
config deny list|add|remove          Manage connection deny list (IP ACL)
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
sudo tacquito-upgrade
```

The upgrade script:
1. Pulls latest tacquito server source and rebuilds the binary (if changed)
2. Pulls latest management scripts from `rett/tacctl` on GitHub
3. Updates system config files (service unit, logrotate, README) if changed
4. Restarts the service only if something changed
5. Re-executes itself if the upgrade script was updated during the pull

Management scripts (`tacctl`, `tacquito-upgrade`) are symlinked from
`/usr/local/bin/` to `/opt/tacctl/bin/`, so git pulls update them instantly.

---

## Troubleshooting

### Common Issues

**`bad secret detected for ip [x.x.x.x]`**
- Shared secret mismatch between server and device
- Regenerate with hex-only: `sudo tacctl config secret`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `sudo tacctl user verify <username>`
- Reset: `sudo tacctl user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `sudo tacctl config juniper`

**No connection attempts reaching the server**
- Verify port 49 reachable: `telnet <server_ip> 49` from the device
- Check service is running: `sudo tacctl status`
- Check IPv4 mode: ensure `-network tcp` is in the systemd unit

**Config change not taking effect**
- Manual edits with `sed -i` require: `sudo systemctl restart tacquito`
- Check for parse errors: `sudo tacctl config validate`

### Useful Commands

```bash
sudo tacctl status          # Health check with auth stats
sudo tacctl log failures    # Recent auth failures
sudo tacctl config validate # Check config syntax
sudo tacctl config diff     # What changed since last backup
```

---

## License

MIT License. See [LICENSE](LICENSE).
