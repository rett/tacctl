# tacquito-manage

Management toolkit for [tacquito](https://github.com/facebookincubator/tacquito), a TACACS+ server (RFC 8907) by Facebook Incubator. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices.

## Quick Start

```bash
# Install on a new server
sudo ./bin/tacquito-install.sh

# Or upgrade an existing server (pulls latest from GitHub)
sudo tacquito-upgrade

# Manage users
sudo tacquito-manage user list
sudo tacquito-manage user add jsmith superuser

# Show device configs with your server's IP and secret pre-filled
sudo tacquito-manage config cisco
sudo tacquito-manage config juniper
```

## Project Structure

```
tacquito-manage/
  bin/
    tacquito-install.sh     # Automated installer (Go, build, configure, start)
    tacquito-manage.sh      # Management CLI (symlinked to /usr/local/bin/tacquito-manage)
    tacquito-upgrade.sh     # Upgrade script (symlinked to /usr/local/bin/tacquito-upgrade)
  config/
    tacquito.yaml           # Template TACACS+ config (used by installer)
    tacquito.service        # Systemd unit file
    tacquito.logrotate      # Log rotation config (daily, 90-day retention)
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
| `/usr/local/bin/tacquito-manage` | Symlink to management CLI |
| `/usr/local/bin/tacquito-upgrade` | Symlink to upgrade script |
| `/usr/local/bin/tacquito-hashgen` | Password hash generator |
| `/opt/tacquito-manage/` | Git clone of this repo (used by upgrade) |
| `/opt/tacquito-src/` | Tacquito server source code |

## Important Notes

- **IPv4 only:** The service runs with `-network tcp`. The default `tcp6` (dual-stack) breaks IPv4 prefix matching.
- **Shared secrets:** Use hex-only secrets (`openssl rand -hex 16`) to avoid quoting issues on devices.
- **Juniper template users are required:** Every `local-user-name` value (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each Juniper device. Without this, TACACS+ auth succeeds but Junos rejects the login.
- **Config edits:** The `tacquito-manage` tool handles service restarts automatically. Manual edits with `sed -i` require a manual restart.

---

## CLI Reference

### Top-Level Commands

```
sudo tacquito-manage status              # Service health, stats, errors, password age warnings
sudo tacquito-manage user <subcommand>   # User management
sudo tacquito-manage group <subcommand>  # Group management
sudo tacquito-manage config <subcommand> # Configuration
sudo tacquito-manage log <subcommand>    # Log viewer
sudo tacquito-manage backup <subcommand> # Backup management
```

Run any command without arguments for detailed help.

### User Commands — `tacquito-manage user`

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

### Group Commands — `tacquito-manage group`

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

### Config Commands — `tacquito-manage config`

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

### Log Commands — `tacquito-manage log`

```
log tail [n]              Show last N journal entries (default 20)
log search <term>         Search logs for a username or keyword (last 7 days)
log failures              Show auth failures from the last 24 hours
log accounting [n]        Show last N accounting log entries
```

### Backup Commands — `tacquito-manage backup`

```
backup list               Show available config backups with timestamps
backup diff [timestamp]   Diff current config vs a backup (default: most recent)
backup restore <ts>       Restore a config backup (with confirmation)
```

Config backups are created automatically before every change. Last 30 backups are retained.

---

## Network Device Configuration

Use `tacquito-manage config cisco` or `tacquito-manage config juniper` to generate
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

---

## Upgrading

```bash
sudo tacquito-upgrade
```

The upgrade script:
1. Pulls latest tacquito server source and rebuilds the binary (if changed)
2. Pulls latest management scripts from `rett/tacquito-manage` on GitHub
3. Updates system config files (service unit, logrotate, README) if changed
4. Restarts the service only if something changed
5. Re-executes itself if the upgrade script was updated during the pull

Management scripts (`tacquito-manage`, `tacquito-upgrade`) are symlinked from
`/usr/local/bin/` to `/opt/tacquito-manage/bin/`, so git pulls update them instantly.

---

## Troubleshooting

### Common Issues

**`bad secret detected for ip [x.x.x.x]`**
- Shared secret mismatch between server and device
- Regenerate with hex-only: `sudo tacquito-manage config secret`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `sudo tacquito-manage user verify <username>`
- Reset: `sudo tacquito-manage user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `sudo tacquito-manage config juniper`

**No connection attempts reaching the server**
- Verify port 49 reachable: `telnet <server_ip> 49` from the device
- Check service is running: `sudo tacquito-manage status`
- Check IPv4 mode: ensure `-network tcp` is in the systemd unit

**Config change not taking effect**
- Manual edits with `sed -i` require: `sudo systemctl restart tacquito`
- Check for parse errors: `sudo tacquito-manage config validate`

### Useful Commands

```bash
sudo tacquito-manage status          # Health check with auth stats
sudo tacquito-manage log failures    # Recent auth failures
sudo tacquito-manage config validate # Check config syntax
sudo tacquito-manage config diff     # What changed since last backup
```

---

## License

MIT License. See [LICENSE](LICENSE).
