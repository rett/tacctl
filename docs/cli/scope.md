# Scope Commands — `tacctl scope`

[Documentation](../README.md) › [CLI reference](README.md)

```
scope list

    One row per scope (deduplicated; prefixes joined)

scope routing

    One row per (scope, prefix) — first-match order

scope show <name>

    Full detail: prefixes, users, secret length + posture (the value: `scope secret <name> show`),
    default-ness, protocols, auth-method, vendor attributes, tagged addresses

scope add <name> --prefixes <cidrs>

    Create a new scope; the name is lower case (`Names are lower case: use 'lab'.`): a letter, then
    up to 31 lower-case letters, digits, `_` or `-`

    [--secret <value>|--secret generate] [--protocols <csv>] [--vendor-attrs <csv>] [--default]

scope remove <name> [--force]

    Delete. Refuses if users reference it unless --force

scope rename <old> <new>

    Rewrites every user's scopes[], the default marker and every per-scope setting; the enrolled
    hosts and staging addresses that name the scope follow. host rename offers this for a host's
    own linux-<name> scope. The new name is lower case; `scope rename Lab lab` fixes a name from
    before

scope default [<name>]

    Show / set the default scope

scope lookup <ip|cidr>

    Resolve an IP/CIDR to the owning scope (+ shadowed overlaps, + its vendor tag)

scope prefixes <name> list|add|remove <cidrs>

    Per-scope CIDR list (add/remove accept comma-lists; the last prefix cannot be removed this way)

scope prefixes <name> remove --all [--force]

    Remove every prefix, which removes the scope (confirms; refuses if users reference it unless
    --force, which strips it from them)

scope secret

    <name> show|set [<value>|--stdin]|generate  Per-scope shared secret (show prints the raw value +
    length/posture)

scope protocols <name> [list]
scope protocols <name> set <protocol>[,<protocol>...]
scope protocols <name> clear

    Limit the scope to some protocols (tacacs, radius). A filter: empty (`clear`) means every
    enabled backend serves it

scope vendor-attrs <name> [show]
scope vendor-attrs <name> enable|disable <vendor>[,<vendor>...]

    RADIUS: the vendors (cisco, juniper, wti) whose privilege attribute an Access-Accept carries for
    the scope's devices. Opt-in: a new scope sends none ("not sent"); its verbs are enable and
    disable. Stored in store.yaml, so a change re-renders and restarts the RADIUS backend. TACACS+
    is not affected. See server/radius.md, "What an Access-Accept carries"

scope devices <name> [list]
scope devices <name> set <ip|cidr> <vendor>
scope devices <name> unset <ip|cidr>

    RADIUS: tag an address (a bare IP is a /32) of the scope with its vendor: it gets that vendor's
    attribute and no other, whatever the scope enables. The address must be one `scope lookup`
    answers with this scope. `scope prefixes remove` refuses to leave a tag outside the scope's
    prefixes; tags go with the scope on rename and remove. Shown by `scope show` and `scope lookup`

scope aaa-order <name> [tacacs-first|local-first]

    Order of the server vs local in this scope's generated Cisco / Junos AAA lines (TACACS+ and
    RADIUS). Default `tacacs-first` keeps the server authoritative (local only kicks in on server
    outage). Set `local-first` when a break-glass local account must authenticate while the server
    is still reachable — any local name that collides with a server user wins locally, so scope
    local accounts to emergency credentials only.

scope exec-timeout <name> [<minutes>]

    Per-scope idle-session timeout for this scope's generated device configs. Cisco renders
    `exec-timeout <n> 0` on `line con 0` / `line vty 0 15`; Junos renders `set system login
    idle-timeout <n>` (on each login class for a registered device whose recorded release is before
    16.1, which has no such statement). Range 0..60 (Junos's max); `0` disables idle expiry on both
    vendors. Default 60.

scope tacacs-group <name> [<label>]

    Per-scope Cisco `aaa group server tacacs+ <LABEL>` name. Rendered into every AAA group +
    method-list line for that scope. Must conform to Cisco ACL naming rules (letter-start,
    letters/digits/_/-). Default `TACACS-GROUP`. Junos has no equivalent.

scope radius-group <name> [<label>]

    The RADIUS twin of `tacacs-group`: the Cisco `aaa group server radius <LABEL>` name rendered by
    `config cisco --protocol radius`. Same naming rules. Default `RADIUS-GROUP`.

scope auth-method <name> [tacacs|radius|clear]

    The protocol this scope uses when a command names none: `config cisco|juniper|wti` without
    `--protocol`, and `host enroll` (a host not registered yet) / `config linux script` without
    `--method` (`tacacs` is host method `tacplus`, which is accepted here too). The order:
    `--protocol` / `--method`; a registered host's own method; this setting; the one protocol the
    scope's `protocols` filter names, when it names exactly one; the global default (device configs:
    TACACS+; hosts: `host default-method`). `clear` removes the setting (`default` is accepted for
    it). Refused when the scope's `protocols` filter leaves the protocol out, and `scope protocols
    <name> set` refuses a list without it. `config cisco --legacy` on a scope that resolves to
    RADIUS needs `--protocol tacacs`. Shown by `scope show`.

scope mgmt-acl <name> list|add|remove|clear [<entry>[,<entry>...]]

    Per-scope permit list; an entry is a `<cidr>` or a `<cidr>:tcp/22,udp/161,icmp` (a plain CIDR
    permits every protocol and port; `remove <cidr>` removes every entry of that CIDR). Mirrors the
    global `tacctl config mgmt-acl list|add|remove|clear`. Falls back to the global
    `mgmt_acl.permits` when this scope's list is empty, so set per-scope permits only where a scope
    needs different ones. `clear` unsets the per-scope override (renders fall back to global).

scope snmp <name> show [--reveal]

    The scope's effective SNMP version, port, timeout, protocols, credentials (set or not;
    `--reveal` prints them, an engineer's own scopes only, logged), contact and allowed clients,
    each with where it comes from: `(scope)`, `(default)` or `(built-in)`, the order of resolution
    (a device's own setting first), and which of the scope's devices have settings of their own
    (`device snmp`). See devices/walkthroughs.md, "SNMP and NETCONF in the walkthroughs"

scope snmp <name> version [v2c|v3]

    Show or set the scope's SNMP version

scope snmp <name> community [--stdin]

    Set the scope's v2c community (asked twice, not echoed); the scope's version becomes v2c

scope snmp <name> v3-user <user> [--auth sha|sha256] [--priv aes128] [--stdin]

    Set the scope's v3 user and passphrases (authPriv); the scope's version becomes v3

scope snmp <name> clients list|add|remove [<cidr>[,<cidr>...]]

    The ranges allowed to query the scope's devices: IPv4, kept in the order given, at most 32,
    never `0.0.0.0/0` (an overlap is a note)

scope snmp <name> contact [<text>|--clear]

    Show, set or remove the scope's SNMP contact (120 characters, no control characters, no `?`)

scope snmp <name> port [<n>]
scope snmp <name> timeout [<seconds>]

    Show or set the scope's agent port and wait (the default's apply until set)

scope snmp <name> clear

    Remove the scope's own SNMP settings, credentials, clients and contact: the default applies
    again

scope snmp <name> test <address|device>

    Read one device's sysName with the scope's settings

scope netconf <name> [show|enable|disable|leave] [--connection-limit <n>|none]
              [--rate-limit <n>|none]

    Superuser. The NETCONF service of the scope's Junos devices: `enable` renders and plans `set
    system services netconf ssh` (with `--connection-limit` and `--rate-limit`, 1 to 250, each
    `none` to remove it; a limit's statement enables the service by itself, so with a limit the
    statement is the limit's), `disable` plans `delete system services netconf` (and drops the
    limits), `leave` (the default, and what removes the scope's setting) plans and compares nothing
    of it; a device's own setting (`device netconf`) wins. The limits bound the service's own port
    (830); tacctl reaches NETCONF through the SSH subsystem, which they do not bound on Junos 25.4.
    `show` prints the setting. Stored as `netconf_scope.<name>.*`, only when set

scope block <name> cisco|juniper list

    The scope's configuration blocks: each block's state (in force, no file, or a file `tacctl.yaml`
    does not name), size and what it states (communities, trap groups, statements), and the
    findings. Nothing secret. An engineer: their own scopes

scope block <name> cisco|juniper show <block> [--reveal]

    The block as it is in force, elided: `<secret:N>` for a community string, `<group:N>` for a trap
    group's name, `<secret>` for an NTP key, `<message: N lines, M characters>` for the login
    message; comments are never shown. `--reveal` prints the file as stored (every reveal is logged,
    the superuser's too: `secret-read kind=block name=<scope>/<vendor>/<block>`; an engineer: their
    own scopes only)

scope block <name> cisco|juniper check <block> [--file <path>|-] [--against <device>]

    Lint the file in force, a file or standard input: every finding with its line, the objects that
    become owned, the statements that carry a secret (a count), the diff against the file in force
    (elided), and a block community that is the scope's own community (refused). `--against` plans a
    device of the scope with the text in force and prints the statements of the block's section,
    from its last pull (nothing is written, no device is reached). Exit 1 on an error

scope block <name> cisco|juniper set <block> (--file <path>|-) [-y]

    Superuser. Check the text, show the objects and the diff, ask, take a snapshot, write the file
    (0600, atomically) and name it in `tacctl.yaml`. A block read from standard input needs `-y`
    unless standard input is a terminal; a text that states nothing is refused (use `remove`);
    nothing is restarted

scope block <name> cisco|juniper remove <block> [-y]

    Superuser. Take the block out of force and delete its file (asks, takes a snapshot first).
    Nothing is deleted from a device: what the block set is no longer rendered, and the next compare
    lists those statements as the device's own

scope block <name> cisco|juniper edit <block> [-y]

    Superuser, at a terminal. Open the block in your editor (`VISUAL`, else `EDITOR`, else `editor`,
    else `vi`), run as you, never as root, on a private 0600 copy in a 0700 directory under
    `/var/tmp` that is removed afterwards; then check, show the diff, ask (`-y` answers) and install
    as `set` does. A new block opens as its grammar in `#` lines. A text that fails the check is
    offered back with the errors at the top as `# tacctl:` lines. Opening a block in force (or, on a
    device, the scope's objects as comments) is logged before the editor starts: `secret-read
    kind=block`

scope block <name> cisco|juniper adopt <device> <block> [-y]

    Superuser, at a terminal. Read the device's own statements of the block's hierarchy with your
    login (the password as `device config pull` asks it; nothing is stored) and open them in your
    editor as the draft to prune: minus what tacctl renders itself, the device's identity (`snmp
    name`, `engine-id`; on IOS the contact, location and engine id) and a string the login sees
    masked or as ciphertext (each named as a `# left out:` line, never a value); an existing block
    is opened first, whole. On IOS it reads `show running-config | include ^snmp-server` and, for
    each access list a community names, `show running-config | section ip access-list standard
    <NAME>`. Logged `secret-read kind=block-adopt`

scope mgmt-acl <name> cisco-name|juniper-name [<label>]

    Per-scope mgmt-acl / filter name. Mirrors the global `tacctl config mgmt-acl
    cisco-name|juniper-name`. Cisco renders `ip access-list standard <LABEL>` + `access-class
    <LABEL> in`; Junos renders `set firewall family inet filter <LABEL>` + lo0 filter apply.
    Fallback chain: per-scope override → global (`tacctl config mgmt-acl …`) → shipped default
    (`VTY-ACL` / `MGMT-ACL`).

scope breakglass <name> [list]
scope breakglass <name> add <user> [--role admin|operator|readonly]
scope breakglass <name> remove <user>

    Per-scope break-glass local users of the device walkthroughs: names and roles (`admin` by
    default, `operator`, `readonly`) only. No password or hash is ever stored
    (devices/break-glass.md, "Break-glass local users"). They are the accounts a `breakglass hold`
    makes usable (devices/break-glass.md, "Holding break-glass"). Superuser only. Shown by `scope
    show`.
```

**A secret kept off the command line.** `scope secret <name> set` with no
value asks for the secret twice at a terminal, without echo, and
`scope secret <name> set --stdin` reads one line from standard input (a
script; typed without echo when standard input is a terminal). The line is
taken as it is, less its line end, and a secret with a control character is
refused from every source. The length and character-class checks apply to the
value read. The
value given on the command line (`set <value>`) works as well, but sudo's log
records the whole command line and `ps` shows it while the command runs; use
the quiet forms where that matters. The same holds for `tacctl shell`, which
runs every line through sudo.

**Connection filters:** `deny` takes precedence over `allow`. Both empty = all connections accepted.

**Settings stored under a scope's name** in `tacctl.yaml` (`aaa.order`, `exec_timeout`, `tacacs_group`, `radius_group`, `scope_auth_method`, `scope_mgmt_acl.names.cisco|juniper`, `scope_mgmt_acl.permits`, `breakglass_scope.<scope>.users`, `snmp_scope.<scope>.*`, `netconf_scope.<scope>.*`, and the scope's credentials file `snmp/<scope>.yaml`) follow the scope on `scope rename` and are removed with it by `scope remove` (and `scope prefixes remove --all`), so a new scope of the same name starts from the defaults. Its `protocols`, `vendor-attrs` and `devices` are part of its entry in `store.yaml` and do the same.

**After a change to what the devices are rendered from** (`prefixes`, `secret`, `mgmt-acl`, `snmp`, `netconf`, `block`, and the protocol, AAA order, timeout and group settings), the verb says, in one line, when at least one device of the scope has a stored pull that `device config plan` would now change: `tacctl device config apply --scope <name> --check` (`device config plan --scope <name>` for a caller who is not a superuser). It reads the stored pulls only: no login, no network.

Each change also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `scope add`, `scope remove`, `scope rename`, `scope default`, `scope prefixes op= scope= cidr=`, `scope protocols|vendor-attrs|auth-method|aaa-order|exec-timeout|tacacs-group|radius-group|netconf scope= from= to=`, `scope mgmt-acl`, `scope secret set scope= source=`, `snmp set kind= scope=` and the lines of `config allow|deny` and `config mgmt-acl`, never a secret or a community; a shown secret is `secret-read kind= name=` for every caller ([Audit log](../security/audit.md#detail-lines)).
