# System Files

[Documentation](../README.md) › [Server](README.md)

**tacctl**

| File | Purpose |
|------|---------|
| `/etc/tacctl/` | State directory (0700 root) |
| `/etc/tacctl/store.yaml` | Users, groups, scopes, filters (0600) |
| `/etc/tacctl/tacctl.yaml` | Operator overrides — only keys you've changed. Absent keys inherit from the canonical defaults built into tacctl. Inspect with `tacctl config dump`; list canonical defaults with `tacctl config defaults`. |
| `/etc/tacctl/rendered.json` | Checksums of the generated files (drift detection) |
| `/etc/tacctl/backups/` | Snapshots (`<timestamp>/`), `legacy/` (old-style backups, pre-store config, displaced files), `password-dates/` (read by the importer) |
| `/etc/tacctl/templates/` | Device config templates: a copy of each shipped one, which you may customize (a file here overrides the built-in one); `.shipped.sha256` is the manifest of what tacctl wrote there, `<name>.template.new` is a new release's version beside a template you customized (see [Custom Templates](../devices/templates.md#custom-templates)) |
| `/etc/tacctl/devices.yaml` | The device registry (`tacctl device`): names, addresses and settings of the network devices; 0600 root, absent means none. Snapshots include it |
| `/etc/tacctl/snmp.yaml` | The SNMP community, or the v3 user and passphrases, that `device add` and `device check` read a device's sysName with (`tacctl config snmp`); 0600 root, never printed, absent means none |
| `/etc/tacctl/snmp/devices/<name>.yaml` | One device's own SNMP community, or v3 user and passphrases (`tacctl device snmp <name>`), over its scope's and the default's; the lowercased device name, 0600 in a 0700 directory, never printed but by `show --reveal`, absent means the device has none of its own. A device's rename moves it, its removal deletes it; snapshots hold it and a restore brings it back |
| `/etc/tacctl/snmp/<scope>.yaml` | One scope's SNMP community, or v3 user and passphrases (`tacctl scope snmp <scope>`), read in place of `snmp.yaml` for the devices of that scope; 0600 in a 0700 directory, never printed but by `show --reveal`, absent means the scope has none of its own. A scope's rename moves it, its removal deletes it |
| `/etc/tacctl/blocks/<scope>/<vendor>/<block>` | One configuration block of a scope: vendor syntax (`<vendor>` is `juniper` or `cisco`, `<block>` is `snmp` or `system`) that tacctl owns beside the structured settings; 0600 in 0700 directories, never printed but by `--reveal` (it holds community strings). In force only while `blocks.<scope>.<vendor>` in `tacctl.yaml` names it. Written by `tacctl scope block <scope> <vendor> set`. A scope's rename moves it, its removal deletes it; snapshots hold it and a restore brings it back |
| `/etc/tacctl/blocks/_devices/<device>/<vendor>/<block>` | One configuration block of a device, over its scope's block of the same object; the lowercased device name. In force while `blocks_device.<device>.<vendor>` names it (the device's dots written `~`). Written by `tacctl device block <name> set`. A device's rename moves it and its removal deletes it; a new device, or a rename onto a name whose blocks are on disk, is refused |
| `/etc/tacctl/console.yaml` | The login console's settings (`tacctl console`): per-tier switches, per-user overrides, idle timeout, system shell; 0600 root, absent means the defaults (the console on for every tier). Snapshots include it |
| `/etc/tacctl/linux-hosts`, `/etc/tacctl/linux-uids` | Enrolled Linux hosts; the UID each user gets on every host |
| `/var/lib/tacctl/` | tacctl's variable data; 0711 (every user may pass through, only root may list it) |
| `/var/lib/tacctl/ssh/known_hosts` | Generated from the pinned host keys in `devices.yaml` on every registry write; 0644 root in a 0755 directory, so every user's ssh reads it (`/etc/tacctl` is root's alone). Do not edit |
| `/var/lib/tacctl/wti-plain-acl-noted` | Marker that `tacctl upgrade` named, once, the scopes whose plain management ACL entries now permit every protocol and port on WTI units (a fresh install writes it at once); `tacctl uninstall` removes it |
| `/var/lib/tacctl/tier-pinned` | Marker that `tacctl upgrade` recorded the tier of every group at priv-lvl 15 (once; a fresh install writes it at once). Outside `tacctl.yaml`, which is what gets lost; `tacctl uninstall` removes it |
| `/var/lib/tacctl/devices-seen.json` | The seen cache of `tacctl device scan`: what the logs showed of each device address, where each backend's next scan resumes, the last host-key re-scans; 0600 root, derived, not snapshotted; `tacctl uninstall` removes it |
| `/var/lib/tacctl/devices-config.json` | The record of each device's last configuration pull (`tacctl device config pull`): when, by whom, over which transport, the NETCONF probe, the result and the state of each section (the release, model and serial number the device reported; for a WTI unit also its command menu's version, its Site ID and how many other sessions it had; for an IOS device the file system of its archive path, for the plan's restore point); 0600 root, derived (a pull rebuilds it), never snapshotted. `device rename` carries a record along, `device remove` and `device config forget` delete it, and so does `tacctl uninstall` |
| `/var/lib/tacctl/device-config/<name>.yaml` | The managed sections of the device's last successful pull, one literal block per section, secret values elided (0600 in a 0700 directory; derived, never snapshotted; `tacctl uninstall` removes it) |
| `/var/lib/tacctl/device-config/<name>.plain` | A Junos device's plain view of the last successful pull (`show configuration \| display set`, without the groups' inheritance applied), in the same form and under the same rules: what `device config plan` compares with the inheritance view to tell a statement of the device's own from one a group supplies; it is stamped with the time of its pull and read for that pull only (a device that answered none has no file) |
| `/var/lib/tacctl/device-config/<name>.backout` | The back-out of the last plan that had changes, as that plan printed it (a secret's value never in it), stamped with the pull it was computed from: what `device config plan <name> --backout` prints once a later pull has replaced the picture. `0600`; `device config forget` and `device rename` carry it |
| `/var/lib/tacctl/device-apply/` | What `device config apply` keeps: `shapes.json` (0600; each shape's statements with every secret elided and who confirmed it) and `locks/<name>.lock` (one lock per device). Root only; not snapshotted; no raw device output and no password |
| `/var/lib/tacctl/linux/` | pam_tacplus source tarball and container-built modules |
| `/etc/sudoers.d/tacctl`, `/etc/sudoers.d/tacctl-tiers` | Optional sudoers rules (`tacctl config sudoers install`, `… tiers install`) |
| `/usr/local/bin/tacctl` | The tacctl binary, built on the server from `/opt/tacctl` by `install` and `upgrade` |
| `/usr/local/bin/tacctl-console` | The login console: a symlink to the binary, made by `install` and refreshed by `upgrade` (see [Login console](../security/login-console.md#login-console)) |
| `/etc/ssh/sshd_config.d/tacctl-console.conf` | sshd's drop-in for the members of `tac-console` (the console users): the console forced, no forwarding (X11 and TCP ports for the tiers of `console forwarding tiers`, superusers by default), no key logins. Written by `host sync` of this server or `tacctl console install`, checked with `sshd -t`, refreshed by `upgrade`; do not edit |
| `/etc/ssh/sshd_config.d/00-tacctl-engineer.conf` | sshd's drop-in for the members of `tac-engineer` (the engineer tier): no forwarding, no tunnel (agent forwarding follows `console agent-forwarding`), whatever their shell. Its name sorts before `tacctl-console.conf` on purpose: sshd reads the drop-ins in name order and the first value of a keyword wins across `Match` blocks, so an engineer who is also in a group the console lets forward (a stale `tac-superuser`) stays locked down; `upgrade` and `console install` rename the earlier `tacctl-engineer.conf`. Written at every `host sync` or `host enroll --local` of this server and by `tacctl console install`, whether or not the console is installed; checked with `sshd -t`, refreshed by `upgrade`, left by `console remove`, removed by `uninstall`; do not edit |
| `/etc/shells` | Gets the line `/usr/local/bin/tacctl-console` while any account may have the console; `console remove` and `uninstall` take it out again |
| `/opt/tacctl/` | Git clone of this repo: what the binary is built from, and what `upgrade` pulls. Holds the shipped templates, units, patches and man page |
| `/opt/tacctl/bin/tacctl.sh` | Bootstrap: installs Go if needed, builds the binary when it is missing or out of date, runs it |
| `/etc/bash_completion.d/tacctl`, `/usr/share/man/man1/tacctl.1.gz` | Completion (bash, generated by `tacctl completion bash`), man page |
| `/usr/local/go/` | The Go toolchain tacctl builds with (installed once, never replaced by an older one); `/usr/local/go/bin/go` is the compiler tacctl runs |
| `/root/tacquito-backups-<time>.tar.gz`, `/root/tacquito-logs-<time>.tar.gz`, `/root/tacctl-radius-logs-<time>.tar.gz` | What `uninstall` leaves when asked to keep the configuration, the TACACS+ accounting logs and the RADIUS logs |

**TACACS+ (tacquito)**

| File | Purpose |
|------|---------|
| `/etc/tacquito/tacquito.yaml` | Server configuration, generated from the store (0640 `tacquito:tacquito`) |
| `/etc/systemd/system/tacquito.service` | Systemd unit file (the default listener) |
| `/etc/systemd/system/tacquito@.service` | Template unit: one instance `tacquito@<name>` per further listener |
| `/etc/systemd/system/tacquito.service.d/tacctl.conf` | Drop-in with the listen address, log level, metrics address and accounting log, rendered from `tacctl.yaml`; do not edit (own unit settings go in another `.conf` file there). Instances have `tacquito@<name>.service.d/tacctl.conf` |
| `/var/log/tacquito/accounting.log` | Accounting records (`accounting-<name>.log` per further listener) |
| `/etc/logrotate.d/tacquito` | Log rotation |
| `/usr/local/bin/tacquito`, `/usr/local/bin/tacquito-hashgen` | Server binary, password hash generator |
| `/opt/tacquito-src/` | Tacquito server source code |

In `/etc/tacquito/`, the old locations of `tacctl.yaml`, `linux-hosts`, `linux-uids`, `backups/` and `templates/` lead into `/etc/tacctl/`.

**RADIUS (FreeRADIUS)**, where enabled. `<raddb>` is `/etc/freeradius/3.0` on Debian/Ubuntu and `/etc/raddb` on the RHEL family; the unit is `freeradius.service` or `radiusd.service`, the logs are in `/var/log/freeradius` or `/var/log/radius`.

| File | Purpose |
|------|---------|
| `<raddb>/tacctl-radius.conf` | tacctl's complete FreeRADIUS configuration: listeners, one client per scope prefix, policy (generated, 0640 `root:<daemon group>`) |
| `<raddb>/tacctl-radius.users` | One entry per (user, scope) with the bcrypt hash (generated, same mode) |
| `<raddb>/tacctl-radius-dictionary/dictionary` | The package's dictionary plus the WTI vendor and tacctl's internal attributes (generated) |
| `/etc/systemd/system/freeradius.service.d/tacctl.conf` (`radiusd.service.d` on the RHEL family) | Drop-in that starts the distribution's unit as `-n tacctl-radius -D <dictionary dir>`; present exactly while the backend is enabled |
| `/usr/sbin/freeradius`, `/usr/lib/freeradius/`, `/usr/share/freeradius/dictionary`, `/run/freeradius/freeradius.pid` | What the package provides and the configuration names: the daemon, its module directory, the main dictionary the generated one includes, the pid file. On the RHEL family `/usr/sbin/radiusd`, `/usr/lib64/freeradius/`, the same dictionary and `/run/radiusd/radiusd.pid`. Read, never edited |
| `/etc/logrotate.d/tacctl-radius` | Log rotation |
| `<logs>/tacctl-auth.log` | One line per Access-Accept and Access-Reject (read by `status`, `log`, `user show`) |
| `<logs>/tacctl-accounting.log`, `<logs>/tacctl-radius.log` | Accounting detail records; the daemon's log |

No file the FreeRADIUS package installed is edited, moved or unlinked.

## Important Notes

- **IPv4 by default:** TACACS+ listens on IPv4 only (`tcp`), RADIUS on `udp`. Switching a listener to `tcp6`/`udp6` enables dual-stack, so IPv4 clients connect with mapped addresses (e.g., `::ffff:10.1.0.1`) that do not match IPv4 prefix rules — effectively bypassing prefix-based access control. Use `tacctl config listen tcp6 [::]:49` only if you also add IPv6 prefix rules; the command prompts for confirmation first.
- **Shared secrets:** Use hex-only secrets (`openssl rand -hex 16`) to avoid quoting issues on devices. A scope's secret is shared by TACACS+ and RADIUS.
- **Juniper template users are required:** Every `local-user-name` value (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each Juniper device. Without this, authentication succeeds but Junos rejects the login.
- **Config edits:** Generated files are overwritten by tacctl and a hand edit blocks every change until it is resolved (see [Drift](store-and-configs.md#the-store-and-generated-configs)). Use tacctl commands; `tacctl` handles service restarts.
