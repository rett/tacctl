# Tacquito TACACS+ Server — Usage & Administration Guide

## Overview

Tacquito is a TACACS+ server (RFC 8907) by Facebook Incubator, built in Go. This deployment
is configured for local user authentication against Cisco IOS/IOS-XE and Juniper devices.

- **Config file:** `/etc/tacquito/tacquito.yaml`
- **Service:** `tacquito.service` (systemd)
- **Listen port:** 49/tcp IPv4 only (`-network tcp`)
- **Accounting log:** `/var/log/tacquito/accounting.log`
- **Prometheus metrics:** `http://localhost:8080/metrics`
- **Source code:** `/opt/tacquito-src`
- **Management tool:** `sudo tacquito-manage` (user & config management)

### Important Notes

- **IPv4 only:** The service runs with `-network tcp` (IPv4 only). The default `tcp6`
  (dual-stack) causes IPv4 devices to appear as `::ffff:x.x.x.x`, which breaks prefix
  matching against IPv4 CIDRs.
- **Shared secrets:** Always use hex-only secrets (`openssl rand -hex 16`) to avoid
  quoting issues with `/`, `+`, `=` characters on network devices.
- **Config edits with sed:** `sed -i` replaces the file inode, which breaks fsnotify
  hot-reload. After editing with `sed -i`, restart the service: `sudo systemctl restart tacquito`.
  The `tacquito-manage` tool handles this automatically.
- **Juniper template users are required:** Every `local-user-name` value returned by
  tacquito (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each
  Juniper device. Without this, TACACS+ authentication succeeds but Junos rejects the login.

---

## Service Management

```bash
# Check status
sudo systemctl status tacquito

# Start / stop / restart
sudo systemctl start tacquito
sudo systemctl stop tacquito
sudo systemctl restart tacquito

# View logs (live)
sudo journalctl -u tacquito -f

# View recent logs
sudo journalctl -u tacquito --no-pager -n 100

# Enable debug logging (edit service, change -level 20 to -level 30)
sudo systemctl edit tacquito --full
# Then restart:
sudo systemctl restart tacquito
```

---

## User Management

### How Users Work

Each user in `tacquito.yaml` has:
- **name** — the login username
- **scopes** — which device groups the user can authenticate to
- **groups** — determines authorization (readonly, operator, or superuser)
- **authenticator** — bcrypt password hash (unique per user)
- **accounter** — where to log accounting records

Users inherit services from their group:
- `readonly` group → Cisco priv-lvl 1 + Juniper RO-CLASS (read-only)
- `operator` group → Cisco priv-lvl 7 + Juniper OP-CLASS (operator)
- `superuser` group → Cisco priv-lvl 15 + Juniper RW-CLASS (super-user)

### Generate a Password Hash

Use Python (simplest method):

```bash
python3 -c "
import bcrypt, binascii
pw = input('Enter password: ').encode()
h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=10))
print('Hex hash:', binascii.hexlify(h).decode())
"
```

Or use the built-in tool (requires terminal — interactive only):

```bash
/usr/local/bin/tacquito-hashgen -mode bcrypt
```

To verify an existing password against a hash:

```bash
/usr/local/bin/tacquito-hashgen -mode verify-bcrypt
```

### Add a New Read-Only User

1. Generate a bcrypt hex hash (see above).
2. Edit `/etc/tacquito/tacquito.yaml`.
3. Add a new authenticator anchor and user entry:

```yaml
# Add near the other bcrypt_* entries:
bcrypt_newuser: &bcrypt_newuser
  type: *authenticator_type_bcrypt
  options:
    hash: <PASTE_HEX_HASH_HERE>

# Add under the users: section:
  - name: newuser
    scopes: ["network_devices"]
    groups: [*readonly]
    authenticator: *bcrypt_newuser
    accounter: *file_accounter
```

4. Save the file. If you edited with a text editor, tacquito hot-reloads automatically.
   If you used `sed -i`, restart the service: `sudo systemctl restart tacquito`.
   Or use `sudo tacquito-manage add <username> <group>` to handle this automatically.

### Add a User to a Different Group

Same as above, but change the group reference. Available groups: `readonly`, `operator`, `superuser`.

```yaml
# Operator example:
  - name: newops
    scopes: ["network_devices"]
    groups: [*operator]
    authenticator: *bcrypt_newops
    accounter: *file_accounter

# Super-user example:
  - name: newadmin
    scopes: ["network_devices"]
    groups: [*superuser]
    authenticator: *bcrypt_newadmin
    accounter: *file_accounter
```

### Change a User's Password

1. Generate a new bcrypt hex hash.
2. Replace the `hash:` value in the user's `bcrypt_*` anchor.
3. Save. Hot-reload applies the change immediately.

### Remove a User

1. Delete the user's entry from the `users:` section.
2. Delete the user's `bcrypt_*` authenticator anchor.
3. Save.

### Disable a User Temporarily

Replace the user's hash with an invalid value (e.g., `0000`). The bcrypt comparison
will always fail, effectively locking the account. Restore the original hash to re-enable.

---

## Group Management

### Existing Groups

| Group | Cisco (priv-lvl) | Juniper (local-user-name) | Use Case |
|-------|-------------------|--------------------------|----------|
| `readonly` | 1 | RO-CLASS | Monitoring, read-only access |
| `operator` | 7 | OP-CLASS | Operational access (clear, debug, show run, ping) |
| `superuser` | 15 | RW-CLASS | Full administrative access |

### Create a New Group

To create a custom group, you need three things: a Cisco exec service (priv-lvl), a
Juniper junos-exec service (local-user-name), and the group definition that ties them
together.

Example: a "helpdesk" group with Cisco priv-lvl 5 and Juniper class HELPDESK-CLASS:

```yaml
# Define services
exec_helpdesk: &exec_helpdesk
  name: exec
  set_values:
    - name: priv-lvl
      values: [5]

junos_exec_helpdesk: &junos_exec_helpdesk
  name: junos-exec
  set_values:
    - name: local-user-name
      values: ["HELPDESK-CLASS"]

# Define the group (add in the # --- Groups --- section)
helpdesk: &helpdesk
  name: helpdesk
  services:
    - *exec_helpdesk
    - *junos_exec_helpdesk
  authenticator: *bcrypt_sw  # placeholder, overridden per-user
  accounter: *file_accounter
```

Then assign users to it with `groups: [*helpdesk]`.

**Juniper requirement:** Create a matching template user on each Juniper device:
```
set system login user HELPDESK-CLASS class read-only
commit
```

**Cisco note:** Custom privilege levels (2-14) require explicit command mappings on the
device. Without those, priv-lvl 1 and 15 are the only meaningful levels on Cisco.

---

## Scope & Device Management

### How Scopes Work

Scopes tie users to device groups. The `secrets:` section defines scopes with:
- **name** — scope identifier (referenced by users' `scopes:` list)
- **secret.key** — shared secret (PSK) for this device group
- **prefixes** — CIDR blocks of allowed device source IPs

### Current Scope

```yaml
secrets:
  - name: network_devices
    secret:
      # Use hex-only secrets to avoid quoting issues on devices
      key: "c940d4555cfaa4fa605f723d92f08d82"
    options:
      prefixes: |
        [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16"
        ]
```

**Prefix format:** Use standard IPv4 CIDR notation. The service runs in IPv4-only mode
(`-network tcp`), so IPv6-mapped addresses (`::ffff:...`) are not needed.

### Restrict to Specific Subnets

Replace the broad RFC1918 ranges with your actual management subnets:

```yaml
      prefixes: |
        [
          "10.1.100.0/24",
          "10.2.200.0/24"
        ]
```

### Multiple Scopes (Different Secrets per Site)

You can create separate scopes with different shared secrets for different locations:

```yaml
secrets:
  - name: site_a
    secret:
      group: tacquito
      key: "secret-for-site-a"
    handler:
      type: *handler_type_start
    type: *provider_type_prefix
    options:
      prefixes: |
        ["10.1.0.0/16"]

  - name: site_b
    secret:
      group: tacquito
      key: "secret-for-site-b"
    handler:
      type: *handler_type_start
    type: *provider_type_prefix
    options:
      prefixes: |
        ["10.2.0.0/16"]
```

Then assign users to one or both scopes:

```yaml
  - name: engineering
    scopes: ["site_a", "site_b"]
    groups: [*superuser]
    authenticator: *bcrypt_engineering
    accounter: *file_accounter
```

---

## Shared Secret Management

### Change the Shared Secret

1. Edit `/etc/tacquito/tacquito.yaml`, update `secret.key` in the `secrets:` section.
2. Save (hot-reloads).
3. Update every network device that uses this server with the new secret.

### Generate a New Secret

```bash
# Use hex-only to avoid special character issues on network devices
openssl rand -hex 16
```

Or use the management tool:
```bash
sudo tacquito-manage config secret
```

---

## Network Device Configuration

### Cisco IOS / IOS-XE

```
aaa new-model
!
tacacs server TACACS
  address ipv4 <TACQUITO_SERVER_IP>
  key <SHARED_SECRET>
  single-connection
!
aaa group server tacacs+ TACACS-GROUP
  server name TACACS
!
aaa authentication login default group TACACS-GROUP local
aaa authorization exec default group TACACS-GROUP local if-authenticated
aaa accounting exec default start-stop group TACACS-GROUP
aaa accounting commands 15 default start-stop group TACACS-GROUP
!
! Operator privilege level 7 — map operational commands
privilege exec level 7 clear counters
privilege exec level 7 clear ip bgp
privilege exec level 7 clear ip ospf
privilege exec level 7 clear ip route
privilege exec level 7 clear logging
privilege exec level 7 clear arp-cache
privilege exec level 7 debug
privilege exec level 7 undebug all
privilege exec level 7 show running-config
privilege exec level 7 show startup-config
privilege exec level 7 ping
privilege exec level 7 traceroute
privilege exec level 7 terminal monitor
privilege exec level 7 terminal no monitor
!
line vty 0 15
  login authentication default
```

**Important:**
- The `local` fallback ensures console access if TACACS+ is unreachable.
- Operator users (priv-lvl 7) can run the mapped commands without `enable`.
- Adjust the `privilege exec level 7` list to match your operational needs.
- Use `sudo tacquito-manage config cisco` to generate this config with your
  server's IP and shared secret pre-filled.

### Juniper Junos

**Step 1 — Create template users (REQUIRED).** These MUST exist before TACACS+ logins
will work. Tacquito returns a `local-user-name` value during authorization (e.g.,
`RO-CLASS`, `OP-CLASS`, or `RW-CLASS`). Junos maps the authenticated user to the matching
local template user's login class. If the template user does not exist, authentication
succeeds at the TACACS+ server but Junos rejects the login silently.

```
set system login user RO-CLASS class read-only
set system login user OP-CLASS class operator
set system login user RW-CLASS class super-user
```

If you create custom groups with additional `local-user-name` values, you must also
create matching template users on every Juniper device.

**Step 2 — Configure TACACS+:**

```
set system authentication-order [tacplus password]
set system tacplus-server <TACQUITO_SERVER_IP> secret <SHARED_SECRET>
set system tacplus-server <TACQUITO_SERVER_IP> single-connection
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus
commit
```

**Troubleshooting Juniper logins:**
- If `show log messages | match tacplus` shows authentication success but login fails,
  the template user is missing.
- Verify template users exist: `show configuration system login user RO-CLASS`,
  `show configuration system login user OP-CLASS`, and `show configuration system login user RW-CLASS`.
- Test connectivity: `telnet <TACQUITO_SERVER_IP> 49` should connect immediately.

---

## Monitoring & Troubleshooting

### Log Levels

| Level | Flag Value | Description |
|-------|-----------|-------------|
| Error | 10 | Errors only |
| Info  | 20 | Normal operation (default) |
| Debug | 30 | Verbose — use during troubleshooting |

Change in the systemd unit (`-level` flag) and restart, or edit the ExecStart line.

### Check Service Health

```bash
# Is it running?
sudo systemctl status tacquito

# Is it listening?
ss -tlnp | grep :49

# Recent logs
sudo journalctl -u tacquito --no-pager -n 50

# Accounting log
sudo cat /var/log/tacquito/accounting.log

# Prometheus metrics
curl -s http://localhost:8080/metrics
```

### Common Issues

**Service won't start — port 49 in use:**
```bash
ss -tlnp | grep :49
# Kill the conflicting process or change the port
```

**`bad secret detected for ip [x.x.x.x]` in logs:**
- The shared secret on the device does not match the server's `secret.key` value.
- Secrets with `/`, `+`, or `=` characters can cause quoting issues on devices.
  Regenerate with hex-only: `openssl rand -hex 16` or `sudo tacquito-manage config secret`.
- On Juniper, delete and re-set the secret to ensure no hidden characters:
  ```
  delete system tacplus-server <IP>
  set system tacplus-server <IP> secret <HEX_SECRET>
  commit
  ```

**`failed to validate the user [x] using a bcrypt password` in logs:**
- The shared secret is correct (packets are decrypted) but the password doesn't match.
- Verify the password: `sudo tacquito-manage verify <username>`
- If hashes were corrupted by bulk sed/Python edits, regenerate:
  `sudo tacquito-manage passwd <username>`

**TACACS+ auth succeeds but Juniper login fails:**
- The template user for the `local-user-name` value doesn't exist on the device.
- Check all three: `show configuration system login user RO-CLASS`,
  `show configuration system login user OP-CLASS`,
  `show configuration system login user RW-CLASS`
- Fix — create any that are missing:
  ```
  set system login user RO-CLASS class read-only
  set system login user OP-CLASS class operator
  set system login user RW-CLASS class super-user
  commit
  ```
- This is the most common Juniper issue — every `local-user-name` value must have
  a matching local template user on the device.

**No connection attempts reaching the server (0 packets on tcpdump):**
- Verify the device can reach port 49: `telnet <server_ip> 49` from the device.
- Check that tacquito is running in IPv4 mode (`-network tcp` in the systemd unit).
  The default `tcp6` causes prefix matching failures with IPv4 devices.
- Verify the device source IP is within the configured `prefixes` CIDRs.

**Config change not taking effect:**
- If you edited with `sed -i`: restart the service (`sudo systemctl restart tacquito`).
  `sed -i` replaces the file inode, which breaks fsnotify hot-reload.
- If you edited with a text editor (nano, vim): check journalctl for parse errors —
  invalid YAML is rejected silently and the previous config stays active.
- Verify YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('/etc/tacquito/tacquito.yaml'))"`

**Juniper login fails but Cisco works (or vice versa):**
- Juniper: Ensure template users (RO-CLASS, OP-CLASS, RW-CLASS) exist on the device
- Cisco: Ensure `aaa authorization exec` is configured

---

## File Locations

| File | Purpose |
|------|---------|
| `/etc/tacquito/tacquito.yaml` | Server configuration (hot-reloads) |
| `/etc/systemd/system/tacquito.service` | Systemd unit file |
| `/var/log/tacquito/accounting.log` | TACACS+ accounting records |
| `/usr/local/bin/tacquito` | Server binary |
| `/usr/local/bin/tacquito-manage` | User & config management tool |
| `/usr/local/bin/tacquito-upgrade` | Pull latest source & rebuild |
| `/usr/local/bin/tacquito-hashgen` | Password hash generator |
| `/etc/tacquito/backups/` | Config backups (created by tacquito-manage) |
| `/opt/tacquito-src/` | Source code (for rebuilding) |
| `/usr/local/go/` | Go toolchain |

---

## Rebuilding from Source

If you need to update tacquito:

```bash
cd /opt/tacquito-src
sudo git pull
cd cmds/server
sudo -E /usr/local/go/bin/go build -o /usr/local/bin/tacquito .
sudo systemctl restart tacquito
```

---

## Management Tool — `tacquito-manage`

The `tacquito-manage` command handles user and config management. All changes are
backed up automatically before applying.

### User Commands

```bash
sudo tacquito-manage list                        # List all users
sudo tacquito-manage add <user> <group>          # Add user (readonly|operator|superuser)
sudo tacquito-manage remove <user>               # Remove user
sudo tacquito-manage passwd <user>               # Change password
sudo tacquito-manage disable <user>              # Disable (preserves hash)
sudo tacquito-manage enable <user>               # Re-enable disabled user
sudo tacquito-manage verify <user>               # Test password against hash
```

### Config Commands

```bash
sudo tacquito-manage config show                 # Show current config
sudo tacquito-manage config cisco                # Show working Cisco device config
sudo tacquito-manage config juniper              # Show working Juniper device config
sudo tacquito-manage config secret [value]       # Change shared secret
sudo tacquito-manage config juniper-ro [class]   # Change Juniper RO class name
sudo tacquito-manage config juniper-rw [class]   # Change Juniper RW class name
sudo tacquito-manage config prefixes [cidr,...]  # Change allowed subnets
```

---

## Quick Reference — Adding a User Checklist

**With the management tool (recommended):**
1. `sudo tacquito-manage add jsmith superuser`
2. Enter or auto-generate a password
3. On Juniper devices: ensure the template user exists (`RO-CLASS` for readonly,
   `OP-CLASS` for operator, `RW-CLASS` for superuser)
4. Test login from a network device

**Manually:**
1. Generate password: `openssl rand -base64 18`
2. Generate bcrypt hex hash (Python one-liner above)
3. Edit `/etc/tacquito/tacquito.yaml`:
   - Add `bcrypt_<username>` anchor with the hex hash
   - Add user entry with name, scopes, groups, authenticator, accounter
4. Restart service: `sudo systemctl restart tacquito`
5. On Juniper devices: ensure the template user exists
6. Test login from a network device
