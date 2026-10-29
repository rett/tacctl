# Custom templates

[Documentation](../README.md) › [Network devices](README.md)

The generated Cisco, Juniper, and WTI output is rendered from template files using `${VAR}` placeholders (processed by `envsubst`). You can customize the output by editing the templates.

**Template locations** (checked in order):
1. `/etc/tacctl/templates/` — per-host overrides (takes precedence)
2. `config/templates/` in the repo — version-controlled defaults

**Template files:**
- `cisco.template`, `cisco-legacy.template` — Cisco IOS/IOS-XE device config (`--legacy`: IOS 12.x)
- `juniper.template` — Juniper Junos device config
- `wti.template` — WTI console-server serial-menu walkthrough
- `cisco-radius.template`, `juniper-radius.template`, `wti-radius.template` — the same for `--protocol radius`

**Available variables:**

| Variable | Used in | Description |
|----------|---------|-------------|
| `${SERVER_IP}` | All | Auto-detected server IP address |
| `${SECRET}` | All | Shared secret of the scope |
| `${AUTH_PORT}`, `${ACCT_PORT}` | Cisco, WTI RADIUS | UDP ports of the RADIUS `auth` and `acct` listeners |
| `${TACACS_PORT_LINE}`, `${TACACS_HOST_PORT}` | Cisco TACACS+ | The TACACS+ port of a listener that is not on 49: `  port <n>` (the leaf of `tacacs server`) and ` port <n>` (the word of the legacy `tacacs-server host` line, after `single-connection`); empty for 49 |
| `${TACACS_PORT}` | WTI TACACS+ | The TACACS+ listener's port (49 by default) |
| `${RADIUS_GROUP}` | Cisco RADIUS | `aaa group server radius` label (`scope radius-group`, default `RADIUS-GROUP`) |
| `${AUTHN_METHODS}`, `${AUTHZ_EXEC_METHODS}`, `${EXEC_TIMEOUT}`, `${VTY_ACL_BLOCK}`, `${VTY_ACCESS_CLASS}` | Cisco | Method lists (from `aaa-order`), idle timeout and the management-ACL blocks |
| `${RADIUS_CONFIG}` | Juniper RADIUS | Pre-rendered RADIUS server, authentication-order and accounting commands |
| `${PRIVILEGE_COMMANDS}` | Cisco | Pre-rendered privilege level command mappings |
| `${AUTHZ_COMMANDS_BLOCK}` | Cisco TACACS+ | Per-level `aaa authorization commands` lines, `config-commands` and the commented `console` line |
| `${ACCT_COMMANDS_BLOCK}` | Cisco TACACS+ | One `aaa accounting commands <level>` line per privilege level in use (a template copied before 0.2.2 has the 1/7/15 lines written out) |
| `${CLASS_COMMAND_RULES}` | Juniper | Step 3: what the server sends per class (comments only) |
| `${TEMPLATE_USERS}` | Juniper | Pre-rendered `set system login user` lines |
| `${TACPLUS_CONFIG}` | Juniper | Pre-rendered TACACS+ server setup commands |
| `${VERIFY_COMMANDS}` | Juniper | Pre-rendered `show configuration` commands |
| `${SNMP_BLOCK}` | All | The SNMP step (see [SNMP and NETCONF in the walkthroughs](walkthroughs.md#snmp-and-netconf-in-the-walkthroughs)); a template copied before 0.2.3 has no such step, and the `Unfilled` line is left out with it |
| `${NETCONF_BLOCK}` | Cisco, Juniper | The commented NETCONF step |
| `${GROUP_SUMMARY}` | All | Human-readable group mapping table |
| `${SCOPE}` | WTI | Name of the scope being rendered |
| `${FALLBACK_LOCAL}` | WTI | `On (Transport Failure)` or `On (All Failures)`, from the scope's `aaa-order` |
| `${SERVICE_NAME}` | WTI | Authorization service name the unit should send (`wti`) |
| `${BREAKGLASS_BLOCK}` | All | The scope's break-glass local accounts with a placeholder for the credential, or the notice that it has none (see [Break-glass local users](break-glass.md#break-glass-local-users)); a template copied before 0.2.3 lacks the step |

A template you changed before 0.2.22 does not have `${TACACS_PORT_LINE}`, `${TACACS_HOST_PORT}` or `${TACACS_PORT}` (an unchanged one is replaced on upgrade, see below): its Cisco output names no TACACS+ port, and its WTI output says 49, whatever the listener is. The upgrade leaves it and writes the new default beside it as `<name>.template.new`; add the variables from there.

**To customize:** edit the copy in the override location (install puts one there; if it is missing, copy the default first):
```bash
sudo cp /opt/tacctl/config/templates/cisco.template /etc/tacctl/templates/cisco.template
sudo vi /etc/tacctl/templates/cisco.template
```

**On upgrade:** a template in `/etc/tacctl/templates/` that you have not changed is replaced by the new release's. tacctl records what it wrote there in `/etc/tacctl/templates/.shipped.sha256` (`sha256sum` format; `cd /etc/tacctl/templates && sha256sum -c .shipped.sha256` lists which are still as shipped). A template you changed is left as it is: the new release's version is written beside it as `<name>.template.new`, and the upgrade warns, naming both files. A `.new` file is never used for rendering. Compare and merge what you want, or take the new version as it is:
```bash
sudo diff /etc/tacctl/templates/cisco.template /etc/tacctl/templates/cisco.template.new
sudo mv /etc/tacctl/templates/cisco.template.new /etc/tacctl/templates/cisco.template
```
Until you do, each upgrade warns again and refreshes the `.new` file. A template with no record there counts as unchanged when it is byte for byte a version tacctl shipped (according to the git history in `/opt/tacctl`).

**To reset to defaults:** remove the override file (and its `.new`, if any). The repo's default is used, and the next upgrade puts a fresh copy of it back:
```bash
sudo rm /etc/tacctl/templates/cisco.template
```
