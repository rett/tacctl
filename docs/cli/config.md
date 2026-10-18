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

config validate

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
    case, a host named like a device, two hosts with the same recorded address, and a pin, record
    or staging entry with no registry line (each names its fix: `host forget`, `host rename`; see
    cli/host.md). Exits 1 on errors

config diff [timestamp]

    Alias of `backup diff`

config restore <timestamp> [--legacy]

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
