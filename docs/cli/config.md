# Config Commands — `tacctl config`

[Documentation](../README.md) › [CLI reference](README.md)

```
config show

    Show current configuration summary incl. per-scope breakdown and each backend's listeners

config dump

    Show tacctl defaults + overrides + merged view

config defaults

    Print canonical tacctl defaults (built into tacctl)

config get <path> [fallback]

    Read a dotted-path value from the merged config. Tab completes every key of the configuration
    and the start of each family of keys that takes a name (`tier.`, `snmp_scope.`), then the groups
    or scopes of the store

config get-list <path>

    Read a list value (one item per line)

config cisco [--scope <name>] [--legacy] [--protocol tacacs|radius] [--name <device>]
             [--server <address|name>] [--source <address>] [--snmp-location <text>]

    Generate working Cisco device config for a scope (default if omitted). --legacy emits IOS 12.x
    syntax (tacacs-server host / aaa group server ... / server <ip>) for devices that use the older
    'tacacs-server host' form. --protocol radius (default: the scope's `auth-method`, else the one
    protocol its `protocols` filter names, else tacacs) renders the RADIUS configuration instead
    (devices/radius.md)

config cisco source-interface [<scope> [<interface>|none]]

    Show or set the interface the Cisco devices of a scope take the source address of their TACACS+
    and RADIUS requests from (`ip tacacs source-interface`, `ip radius source-interface`); `none`
    unsets it. Setting it is the superuser's, an engineer reads their own scopes'

config juniper [--scope <name>] [--protocol tacacs|radius] [--name <device>]
               [--server <address|name>] [--source <address>] [--snmp-location <text>]

    Generate working Juniper device config for a scope (default if omitted); --protocol radius as
    for cisco

config wti [--scope <name>] [--protocol tacacs|radius] [--name <device>] [--server <address|name>]
           [--source <address>] [--snmp-location <text>]

    Print the step-by-step serial-menu procedure for a WTI console server (firmware v8.x) with the
    scope's server IP, secret, and group→access-level mapping filled in; --protocol as for cisco
    (the RADIUS walkthrough is not verified on a unit)

config render [--force]

    Regenerate every enabled backend's config from the store and tacctl.yaml, all or none, and
    restart the ones that changed (needs the store; refuses to overwrite a hand-edited file unless
    --force, which first saves it under backups/legacy/)

config render --dry-run --out <dir>

    Render every enabled backend into a new, empty directory at the live paths; nothing live is
    written, no restart

config validate [--json | --fix-names [-y]]

    Validate the store, tacctl.yaml (schema walk, incl. commands.<group> / privileges.<group> /
    mgmt_acl.* / listeners) and the server-config structure (orphan scope refs, scope.default
    pointing at a nonexistent scope, reserved usernames, missing accounter:), then each enabled
    backend: rendered config up to date, drift; RADIUS scopes that send no vendor attribute. An
    empty privileges.<group> list on a built-in group that ships one (it hides the shipped list;
    `group privilege reset <group>` removes it) is a warning, and so is a key that names a group or
    scope the store does not have (`privileges.<group>`, `commands.<group>`, `snmp_scope.<scope>`,
    `exec_timeout.<scope>` and the other per-scope keys; a group or scope added later under that
    name would take it over), one `Orphan settings:` line per key, and so are the files of a device
    or scope that is not registered (a pull's records, SNMP credentials), an `Orphan files:` line
    each, and so is a private copy of the configuration that a killed command left in the state
    directory (`.apply.*`, `.restore.*`,
    `.enable.*`, `.units.*`, `.disable.*`, older than ten minutes, with no command holding the
    apply lock). Under `Linux hosts:` it also warns of two hosts whose names are equal ignoring
    case, a host named like a device, two hosts with the same recorded address and ssh port, and
    a pin, record or staging entry with no registry line (each names its fix: `host forget`,
    `host rename`; see cli/host.md). A device, host, user or scope whose name has upper case (the
    names of new ones are lower case) gets a `Names:` warning that names the rename which fixes it
    (`tacctl user rename Alice alice`; for a user it adds that devices match the typed login name
    exactly, so the rename changes what the person types); the superuser's view only. Exits 1 on
    errors. The verb takes no argument: a word other than its options is refused (`Unknown
    argument`) and no report is printed. `--json` prints the findings as one JSON object and
    nothing else on standard output (the schema is below); the exit status is the same.
    `--fix-names` follows the report with the offer to rename each such name to its lower-case
    spelling (below); the superuser's

config diff [timestamp]

    Alias of `backup diff`

config restore <timestamp> [--legacy|--keep-uids]

    Alias of `backup restore`

config loglevel [debug|info|error]

    Show or change the TACACS+ log level

config listen [--backend <id>] [--listener <name>] [show|tcp|tcp6|udp|udp6|reset] [addr]

    Show, change, or reset a listen address (default: the TACACS+ listener 'default'; see
    server/backends.md, "Listeners")

config metrics <show|enable|disable|address <host:port>|reset>

    Prometheus exporter control (TACACS+). Default: loopback-only 127.0.0.1:8080. `disable` sinks to
    127.0.0.1:0 (unreachable ephemeral port) since tacquito's own disable flag would crash the
    server.

config linux build|script|remove-script|uid|uid-range|engineer-sudo|builds

    Login for Linux hosts (cli/host.md)

config linux script [--scope <name>] [--server <address>] [--method tacplus|radius]
                    [--output <file>]

    Write the install script for hosts in a scope (contains the secret)

config linux remove-script [--output <file>]

    Write the removal script (no secrets; removes either method)

config linux uid [<user> [<uid>]]

    Show or change the UID a user gets on every host

config linux uid-range [<min>-<max>]

    Show or change the UID range of all hosts (default 80000-89999)

config linux engineer-sudo [all|<cmd>[,<cmd>...]]

    Show or limit what engineers may run through sudo on enrolled hosts (default all; warns for a
    shell, interpreter, editor, su, sudo, find or env)

config linux builds [list|clear]

    Show or drop the pam_tacplus modules 'host enroll' built in containers

config snmp show [--reveal]

    The default SNMP settings of the name hint and the walkthroughs, and whether the credentials are
    set; --reveal prints them (administrators)

config snmp community [--stdin]

    Set the v2c community (asked twice, not echoed; --stdin: one line); the version becomes v2c

config snmp v3-user <user> [--auth sha|sha256] [--priv aes128] [--stdin]

    Set the v3 user and its authentication and privacy passphrases (authPriv); the version becomes
    v3

config snmp port [<n>] | timeout [<seconds>]

    Show or set the agents' UDP port (default 161) and the wait for an answer (1-10, default 2; one
    retry)

config snmp clear

    Remove the credentials and unset the version: no lookups

config snmp test <address|device>

    Read one device's sysName, or say why there is none (timeout, unknownUserName, wrongDigest,
    ...); a registered device is read with its own settings, else its scope's, else the default's

config devices [show]

    How `device config pull`, `diff --pull` and `plan --pull` read the devices, the confirm timeout
    of `plan` and the confirm timeout and pause of `device config apply`: the settings and where
    each stands (administrators)

config devices max-concurrency [<n>]

    Show or set the most devices read at once, 1-64 (default 8; `--concurrency` can lower it per
    run, never raise it)

config devices transport [auto|netconf|ssh]

    Show or set the default transport (default auto)

config devices timeout [<seconds>]

    Show or set the time one device may take, connect included, 10-600 (default 90)

config devices confirm-timeout [<minutes>]

    Show or set the minutes of the `commit confirmed` that ends a Junos plan, 1-60 (default 5)

config devices apply-confirm-timeout [<minutes>]

    Show or set the minutes of the `commit confirmed` of `device config apply`, 3-60 (default 10)

config devices apply-pause [<seconds>]

    Show or set the seconds `device config apply` waits between the devices of a batch after the
    canary, 0-3600 (default 60; 0 none)

config devices apply-transport [cli|auto|netconf]

    Show or set how `device config apply` reaches a Junos device: the command line only (cli, the
    default), NETCONF where the device answers and can confirm, else the command line (auto), or
    NETCONF only (netconf); `--transport` of one run replaces it

config sudoers [show|install|remove] [grp]

    Manage NOPASSWD sudoers drop-in for tacctl

config sudoers tiers [show|install|remove]

    Manage per-tier (RO/OP/SU) sudoers rules for tacctl users with local accounts

config password-age [days]

    Show or set password age warning threshold (default 90)

config bcrypt-cost [10-14]

    Show or set bcrypt cost factor for new hashes (default 12)

config password-min-length [8-64]

    Show or set minimum interactive password length (default 12)

config secret-min-length [16-128]

    Show or set minimum shared-secret length (default 16)

config allow list|add|remove|clear

    Manage connection allow list (IP ACL; add/remove accept comma-lists)

config deny list|add|remove|clear

    Manage connection deny list (IP ACL; add/remove accept comma-lists)

config mgmt-acl list|add|remove|clear

    Manage Cisco VTY-ACL + Juniper lo0-filter + WTI IP Tables permits (add/remove accept comma-lists
    of entries: `<cidr>` or `<cidr>:tcp/22,udp/161,icmp`; `remove <cidr>` removes every entry of
    that CIDR)

config mgmt-acl cisco-name [name]

    Show or set the emitted Cisco ACL name (default VTY-ACL)

config mgmt-acl juniper-name [name]

    Show or set the emitted Juniper filter name (default MGMT-ACL)

config branch [name]

    Show or change the tacctl repo branch
```

## `config validate --fix-names`

`config validate --fix-names [-y]` prints the usual report, then offers
every `Names:` finding whose lower-case spelling is free, one at a time:
devices first, then hosts, users and scopes, each kind in alphabetical
order.

```
Rename device 'Core-SW1' to 'core-sw1'? [y/N]:
```

Only `y` or `Y` renames; anything else, and a closed standard input, is a
no. A piped `y` works as for every other question, and no terminal is
required. `-y` (`--yes`) answers yes to every question.

On yes the verb that renames that kind of name runs as when typed
(`device rename`, `host rename`, `user rename`, `scope rename`) and prints
what it prints. Each rename takes its own snapshot, so each has its own undo
point, and carries what its verb carries (a host's pins, record, staging and
hold and the offer of its own `linux-<name>` scope; a user's UID line; a
scope's keys, hosts and staging). `-y` is passed on to `host rename` only
when it was given here: without it the verb asks its own questions (a
leftover under the new name, the scope) after this one. The findings are
read again after each rename, so a scope that a host rename carried is not
offered twice.

A name whose lower-case spelling is another name's (`Alice` beside `alice`,
two hosts equal ignoring case, a device and a host that are one name) is not
offered. One line says so:

```
'Alice' is not offered: 'alice' is taken; pick a name: tacctl user rename Alice <new>
```

For two hosts equal ignoring case the line adds `, or tacctl host forget
<name> drops the stray registration`. A rename its verb refuses (a name
taken since the report, a scope whose new name already has SNMP
credentials) prints the verb's refusal and does not stop the rest.

A host renamed whose own scope is then refused (`Host renamed. Scope
'linux-Web1' was NOT renamed: ...`) counts as renamed, not failed: the host
keeps the scope, which the same refusal would meet again if it were offered.
One line gives the command instead of the question, and the scope counts
under `not offered`:

```
'linux-Web1' is not offered: its rename was refused with the host's (<reason>);
retry: tacctl scope rename linux-Web1 linux-web1
```

The scope is left out of that run only; the next `--fix-names` offers it
again.

The run ends with a count, and, when a user was renamed and hosts are
enrolled, with the `tacctl host sync --all` that renames their accounts:

```
Names: renamed 3, declined 1, not offered 1, failed 0.
```

The exit status is 1 when the report had errors, a rename failed or a name
was not offered, so that a script with `-y` learns that names remain; a
decline does not fail the run. `--fix-names` renames, so it is the
superuser's: an operator or an engineer is refused. It needs the store and
does not go with `--json`.

## `config validate --json`

`config validate --json` runs the same checks and prints the result as one
JSON object on standard output, and nothing else there. What the report
writes around itself (the complaint of a store that cannot be read, a
backend's own message) goes to standard error. The exit status is the text
report's: 1 when `errors` is not 0, otherwise 0 (warnings alone exit 0); the
object is printed either way. The verb is the operator's, with or without
`--json`.

```
{
  "valid": false,
  "errors": 1,
  "warnings": 2,
  "mode": "store",
  "counts": {"users": 12, "groups": 3, "scopes": 4},
  "backends": ["tacacs", "radius"],
  "findings": [
    {"section": "scope_default", "level": "error", "fix": "",
     "text": "Default scope override points at 'x' which is not a defined scope"},
    {"section": "linux_hosts", "level": "warning",
     "text": "the hosts 'Web1', 'web1' are one name ignoring case and share one record ...",
     "fix": "tacctl host forget <name> drops the stray registration; ...",
     "hosts": ["Web1", "web1"]},
    {"section": "rendered", "level": "warning", "backend": "tacacs",
     "text": "tacquito.yaml was not rendered by tacctl yet ...",
     "fix": "tacctl config render --force"}
  ]
}
```

| Field | Meaning |
|---|---|
| `valid` | `true` when `errors` is 0 |
| `errors`, `warnings` | how many findings have each level |
| `mode` | `store`, or `legacy` when there is no store yet (read-only mode) |
| `counts` | the users, groups and scopes the model defines; `null` when it cannot be read |
| `backends` | the enabled backends; `[]` when the list cannot be read |
| `findings` | what the text report lists as a problem, in its order; `[]` when there is none |

A finding has:

| Field | Meaning |
|---|---|
| `section` | the label of the text report as a fixed token (below) |
| `level` | `error` (counts toward the exit status) or `warning` |
| `text` | what is wrong, as the text report words it, without the command that puts it right |
| `fix` | that command, when the finding carries one apart from its text; else `""`. For a drifted file it is the advice the text report prints under the `DRIFT:` line |
| `backend` | the backend a rendered-config, drift or vendor-attribute finding belongs to; absent otherwise |
| `hosts` | the registered hosts a `linux_hosts` or `names` finding names; absent otherwise |

The sections are `store`, `yaml` (without a store: `tacquito.yaml` does not
parse), `overrides` (`tacctl.yaml`), `command_rules`, `structure` (users,
groups and scopes), `scope_default`, `linux_hosts`, `names`, `breakglass`,
`breakglass_hold`, `config_blocks`, `operator_policy`, `group_settings`,
`orphan_settings`, `orphan_files`, `leftovers`, `backends` (the enabled list
cannot be read), `rendered`, `drift` and `vendor_attrs`. A line of the text
report that says all is well (`valid`, `up to date`, `no overrides`) has no
finding.

The level is the one that counts. A finding the text report colours red but
does not count (a break-glass hold with no registered device, or a hold
record the `tacctl.yaml` check already reports) is a `warning` here, so
`valid` and the exit status agree with `errors`. The text report counts the
files of one backend that drifted as a single error; the object counts each
file. A caller who sees only some scopes (an engineer) gets no `linux_hosts`,
`names` or hold-defect findings, as in the text report.

Each setting changed also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `config <setting> from= to=` for the tunables, `config allow|deny|mgmt-acl op= value=`, `config sudoers op= file=`, `config render backends=`, `config linux uid user= uid=`, `snmp set kind=` for `config snmp`, and `secret-export scope= file=` when `config linux script` writes a file that holds a scope's secret ([Audit log](../security/audit.md#detail-lines)).
