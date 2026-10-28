# Emergency Commands — `tacctl emergency`

[Documentation](../README.md) › [CLI reference](README.md)

```
emergency lockdown <scope> enable [<group>[,<group>...]] [--tier <tier>]
                                  [--reason <text>] [--dry-run]
emergency lockdown --all-scopes enable [<group>[,<group>...]] [--tier <tier>]
                                       [--reason <text>] [--dry-run]

    Refuses the logins of the groups on every device and Linux host the scope answers. With no
    group, every group that is not a superuser's; with a list, those groups; with --tier, the
    groups of that tier (readonly, operator or engineer). It adds to what is locked already. The
    users of those groups are taken out of the scope when the backends render, so the server
    answers every login and every further command authorization with a refusal (TACACS+ FAIL,
    RADIUS Reject), never with silence. Shows who loses access and who keeps it, then asks for the
    scope's name typed back at a terminal (the word "all" for --all-scopes, which includes this
    server's own logins); --dry-run prints the list and changes nothing. --reason (1 to 256
    characters) is kept with the record and in the log. The scope of this server's own login (the
    name `tacctl`, which no command names: `emergency lockdown tacctl ...` is refused as reserved)
    is locked by --all-scopes only; its lines say `this server's own login`, and `--all-scopes
    disable` lifts it. Superuser only

emergency lockdown <scope> disable [<group>[,<group>...]]
emergency lockdown --all-scopes disable [<group>[,<group>...]]

    Lifts the lockdown for the groups named, or all of it. The rendered files come back byte for
    byte. Superuser only

emergency lockdown status [<scope>] [--json]
emergency lockdown <scope>

    The lockdowns that stand: scope, groups, since when, how long, by whom, why, the users locked
    out and the superusers who keep access, and the ways a device's local accounts stay usable.
    Superuser only, like the rest of the verb; the top-level `status` and `config validate` show
    the lockdowns to an engineer, for their own scopes
```

```
tacctl emergency lockdown site-a enable --reason "credential leak"
tacctl emergency lockdown site-a enable ops,readonly
tacctl emergency lockdown site-a disable
tacctl emergency lockdown status
```

A user of a superuser group (its tier is superuser, and it is not a group at
priv-lvl 15 with no tier setting) is never locked: naming such a group, or
`--tier superuser`, is refused. There is no timer; a lockdown stands until
`disable`. `store.yaml` is never changed, and the record is
`emergency.lockdown.<scope>.groups|since|by|reason` in `tacctl.yaml`.

**What stays open.** A device's own local accounts are not tacctl users and
are not locked; they stay out of the way only because of the device's method
list. Not closed: a Cisco console line, the Junos root account on the console,
a scope that lists local accounts first (`scope aaa-order local-first`), local
ssh keys, sessions that are already open (Junos devices, WTI units and Linux
hosts keep a session until it logs in again or runs sudo) and a device that
cannot reach this server. `status` names these, and `enable` warns in red on
a local-first scope. A [break-glass hold](breakglass.md) on a device of the
scope makes the device fall back to its local accounts, and `status` names it.

**The message.** While a lockdown stands, every command that names the scope,
a device or host in it, or that is about no one scope (`status`, `config
validate`, `scope list`, `device list`, `host list`) writes one red line on
standard error, once per command: `EMERGENCY LOCKDOWN on scope 'site-a' since
<time> by <user> (<duration>): logins of groups <groups> are refused;
superusers keep access. Reason: <text>`. Standard output and the exit status
are unchanged. An engineer sees the lockdowns of their own scopes.
`status`, `config validate` and `emergency lockdown status` list the
lockdowns too (`--json` has the locked users and the exempt superusers).

A scope's rename moves its record and its removal drops it; `group remove`
takes the group out of every lockdown, and `group edit <group> tier superuser`
(or a priv-lvl edit that makes the group a superuser's) is refused while the
group is locked, since a superuser group is never locked. A rollback to a
release before 0.2.19 is refused while a lockdown stands (`tacctl rollback`). `config validate` warns while a
lockdown stands and reports a record that names a scope or group that no
longer exists, a group that is a superuser's now, or no group. The log has
`emergency lockdown enable|disable scope= groups= ...`.
