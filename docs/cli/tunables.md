# Configuration tunables — `tacctl.yaml`

[Documentation](../README.md) › [CLI reference](README.md)

tacctl ships canonical tunable defaults, built into the binary (printed by `tacctl config defaults`). Operator overrides live in one file, `/etc/tacctl/tacctl.yaml`. List only the keys you want to change; missing keys inherit from the defaults. Setting a key back to the default value removes it (revert-to-default) and an empty overrides file is pruned.

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
  default: lab               # matches the fresh-install seed scope; override via `tacctl scope
                             default`

host:
  default_method: tacplus    # how `tacctl host enroll` sets up a new Linux host: tacplus | radius

mgmt_acl:
  names:
    cisco: VTY-ACL           # ACL name emitted by `tacctl config cisco`  (letter-start,
                             [A-Za-z0-9_-], 1..63)
    juniper: MGMT-ACL        # filter name emitted by `tacctl config juniper`  (same rules)
  permits: []                # list of CIDRs; each element validated

privileges:                  # per-group Cisco priv-exec lowering (move commands DOWN from priv 15)
  readonly:
    - show running-config
  operator:
    - undebug all

commands:                    # per-group command-authz rules. Rendered for both Cisco # (tacquito
                             enforces) and Juniper (class allow/deny-commands) # from this single
                             tacctl-authored source. Ordered # superuser → operator → readonly. Not
                             enforced over RADIUS.
  superuser:
    - { name: "*", action: permit }
  operator:
    - { name: show,          action: permit }
    - { name: ping,          action: permit }
    - { name: traceroute, action: permit }
    - { name: terminal,      action: permit }
    - { name: "*",           action: deny }
  readonly:
    - { name: show,          action: permit }
    - { name: ping,          action: permit }
    - { name: traceroute, action: permit }
    - { name: "*",           action: deny }
```

Keys without a shipped default (`backends.*`, `listeners.*`, `snmp.*`, `device.config.*` and the per-scope keys) are written only by their commands. With `snmp.version` unset there is no SNMP lookup; `snmp.timeout` is in seconds. The SNMP credentials are never in `tacctl.yaml`. `snmp_scope.<scope>.*` is written only when set; its `clients` is a list of at most 32 canonical IPv4 CIDRs, never `0.0.0.0/0`, none twice.

**Every key of `tacctl.yaml`**, with its value, its default and the command that sets it (`man tacctl`, CONFIGURATION KEYS, has the full text; a name in angle brackets stands for a group, a scope, a backend or a listener, and the keys of a family exist once for each):

| Key | Value (default) | Set with |
|---|---|---|
| `audit.strict` | `true` or `false` (`false`) | `config audit-strict` |
| `backends.enabled` | non-empty list of `tacacs`, `radius` (`[tacacs]`) | `backend enable`, `backend disable` |
| `backends.tacacs.level` | 0 to 100 (20) | `config loglevel` |
| `backends.tacacs.metrics_address` | host:port (127.0.0.1:8080) | `server metrics address` |
| `bcrypt.cost` | 10 to 14 (12) | `config bcrypt-cost` |
| `host.default_method` | `tacplus` or `radius` (`tacplus`) | `host default-method` |
| `server.addresses` | list of one IP address, the address devices and hosts reach this server at, not a host name, loopback, link-local, multicast, broadcast or IPv4-mapped (a list that holds one address for now) | `server addresses` |
| `linux.engineer_sudo` | list of absolute command paths (unset: every command) | `config linux engineer-sudo` |
| `linux.uid_min`, `linux.uid_max` | 1000 to 4294967293 (80000, 89999) | `config linux uid-range` |
| `mgmt_acl.names.cisco`, `mgmt_acl.names.juniper` | name of 1 to 63 characters (`VTY-ACL`, `MGMT-ACL`) | `config mgmt-acl cisco-name`, `juniper-name` |
| `mgmt_acl.permits` | list of CIDRs, each with optional services after a colon (`tcp/22`, `udp/161-162`, `tcp/*`, `icmp`, comma separated; `[]`) | `config mgmt-acl add`, `remove` |
| `blocks.<scope>.<vendor>` | non-empty list of block names (`snmp`, `system`) | `scope block` |
| `blocks_device.<device>.<vendor>` | the same, the device's dots written `~` | `device block` |
| `password.max_age_days`, `password.min_length` | 1 or more (90); 8 to 64 (12) | `config password-age`, `password-min-length` |
| `secret.min_length` | 16 to 128 (16) | `config secret-min-length` |
| `scope.default` | scope name or null (`lab`) | `scope default` |
| `snmp.version`, `snmp.port`, `snmp.timeout`, `snmp.v3.auth`, `snmp.v3.priv` | `v2c`/`v3` (unset); 1 to 65535 (161); 1 to 10 (2); `sha`/`sha256`; `aes128` | `config snmp` |
| `device.config.max_concurrency`, `device.config.transport`, `device.config.timeout`, `device.config.confirm_timeout` | 1 to 64 (8); `auto`, `netconf` or `ssh` (`auto`); 10 to 600 seconds (90); 1 to 60 minutes (5) | `config devices` |
| `device.apply.confirm_timeout`, `device.apply.pause` | 3 to 60 minutes (10); 0 to 3600 seconds (60) | `config devices apply-confirm-timeout`, `apply-pause` |
| `device.apply.transport` | `cli`, `auto` or `netconf` (cli) | `config devices apply-transport` |
| `privileges.<group>` | list of Cisco priv-exec commands (the shipped list of a built-in group) | `group privilege` |
| `commands.<group>` | ordered `{name, action, match}` rules ending in the `*` catch-all (shipped) | `group commands` |
| `aaa.order.<scope>` | `tacacs-first` or `local-first` (`tacacs-first`) | `scope aaa-order` |
| `exec_timeout.<scope>` | 0 to 60 minutes (60; 0 never) | `scope exec-timeout` |
| `tacacs_group.<scope>`, `radius_group.<scope>` | label (`TACACS-GROUP`, `RADIUS-GROUP`) | `scope tacacs-group`, `radius-group` |
| `cisco.source_interface.<scope>` | interface name as IOS prints it, such as `Loopback0` or `GigabitEthernet0/0/1` (not an abbreviation; unset: no line is rendered or compared) | `config cisco source-interface` |
| `scope_auth_method.<scope>` | `tacacs` or `radius` (unset) | `scope auth-method` |
| `scope_mgmt_acl.names.cisco.<scope>`, `scope_mgmt_acl.names.juniper.<scope>`, `scope_mgmt_acl.permits.<scope>` | the scope's own ACL name, filter name and permitted entries (CIDRs, each with optional services), in place of `mgmt_acl.*` | `scope mgmt-acl` |
| `scope_mgmt_acl.mode.<scope>` | `strict`: the scope's Junos filter is deny by default; unset is `ssh-only` | `scope mgmt-acl <scope> mode` |
| `listeners.<backend>.<name>` | network, address, role, metrics_address (`tacacs.default` tcp :49, `radius.auth` udp :1812, `radius.acct` udp :1813) | `server listen` |
| `junos.<group>.deny_commands`, `junos.<group>.deny_configuration` | list of POSIX extended regular expressions (unset) | `group junos` |
| `wti_level.<group>` | `viewonly`, `user`, `superuser` or `administrator` (unset: the priv-lvl band) | `group add`, `group edit` |
| `tier.<group>` | `readonly`, `operator`, `engineer` or `superuser` (unset: the priv-lvl band) | `group add`, `group edit` |
| `breakglass_scope.<scope>.users` | list of `name:role` (role `admin`, `operator` or `readonly`), at most 16; names and roles only | `scope breakglass` |
| `breakglass_hold.<device>.address`, `.since`, `.by`, `.reason` | the record of a [break-glass hold](../devices/break-glass.md#holding-break-glass): the address the server does not answer, when and by whom, and why (1 to 256 characters; never rendered into a backend file); no expiry. A device name's dots are written `~` in the key | `breakglass hold`, `breakglass release` |
| `emergency.lockdown.<scope>.groups`, `.since`, `.by`, `.reason` | the record of an [emergency lockdown](emergency.md): the groups whose logins the scope refuses (a list of group names), when and by whom, and why (1 to 256 characters; never rendered into a backend file); no expiry | `emergency lockdown` |
| `snmp_scope.<scope>.version`, `snmp_scope.<scope>.port`, `snmp_scope.<scope>.timeout`, `snmp_scope.<scope>.v3.auth`, `snmp_scope.<scope>.v3.priv`, `snmp_scope.<scope>.contact`, `snmp_scope.<scope>.clients` | the scope's own SNMP settings, in place of `snmp.*`; `contact` up to 120 characters; `clients` at most 32 IPv4 CIDRs | `scope snmp` |
| `netconf_scope.<scope>.state`, `netconf_scope.<scope>.connection_limit`, `netconf_scope.<scope>.rate_limit` | the scope's NETCONF service setting: `state` is `enable` or `disable` (no key is `leave`, the default); the limits 1 to 250, with `enable` only | `scope netconf` |

`audit.strict` is set with `tacctl config audit-strict on` (`audit:` with
`strict: true` under it) and `off` (the key removed); with no argument the
command shows the value and where it comes from. A hand-edited value that is
not `true` or `false` is a validation error and reads as off. With `true`, a
command that changes state is refused (status 1, `The audit line cannot be
written (logger: <reason>) and audit.strict is set; nothing was changed.`)
when its `cmd start` line cannot be written, and a command that shows a
secret is refused (`...; nothing was shown.`) when its `secret-read` line
cannot be written; other reads run. `config audit-strict` itself is never
refused, so `off` works while `logger` is down. See [Audit
log](../security/audit.md).

Merge semantics:
- Maps deep-merge (overriding `password.max_age_days` keeps the default `password.min_length`).
- Lists replace wholesale (an override list does not concatenate with the default list).
- Scalars replace.

**Write-time validation.** Every `tacctl config <setter>` checks the value against the schema and rejects out-of-range numbers, bad ACL names, malformed CIDRs, invalid Cisco command strings, colliding or malformed listeners and typo'd keys with an error before anything is written. `tacctl config validate` runs the same schema over `tacctl.yaml` to catch hand-edits.

**A `tacctl.yaml` that does not parse** is never written into: every setter refuses with `tacctl.yaml: could not parse <path>: line L, column C: <problem>` and exits non-zero, leaving the file untouched. Commands that only read carry on with the defaults and say so once, on stderr. Fix the file; `tacctl config validate` reports the same line. A change to users, groups or scopes is refused as well, since every backend's config is rendered from the file.

**Read path caching.** The merged view of defaults and overrides is cached for the duration of one command: commands that read many tunables (`config cisco`, `status`, `config show`) load it once. Writes invalidate the cache.

View effective posture with `tacctl config dump`; read individual values with `tacctl config get <path>` / `tacctl config get-list <path>`.
