# Emergency Commands — `tacctl emergency`

[Documentation](../README.md) › [CLI reference](README.md)

```
emergency lockdown <scope> enable [<group>[,<group>...]] [--tier <tier>]
                                  [--reason <text>] [--dry-run] [--yes]
emergency lockdown --all-scopes enable [<group>[,<group>...]] [--tier <tier>]
                                       [--reason <text>] [--dry-run] [--yes]

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
    disable` lifts it. Then it offers the sync of the scope's enrolled hosts (below): --yes
    answers yes without the question. Superuser only

emergency lockdown <scope> disable [<group>[,<group>...]] [--yes]
emergency lockdown --all-scopes disable [<group>[,<group>...]] [--yes]

    Lifts the lockdown for the groups named, or all of it. The rendered files come back byte for
    byte. When the last group is lifted, every enrolled host of the scope is offered the sync that
    removes sshd's lockdown drop-in (below). Superuser only

emergency lockdown status [<scope>] [--json]
emergency lockdown <scope>

    The lockdowns that stand: scope, groups, since when, how long, by whom, why, the users locked
    out and the superusers who keep access, the enrolled hosts with those the sshd lockdown has
    not reached yet and the command that completes it, and the ways a device's local accounts
    stay usable. A lockdown lifted on the devices whose hosts still hold the drop-in is listed
    after them. `--json` has `locked_users`, `exempt`, `hosts`, `pending_hosts` and `lifted` (a
    lifted lockdown that waits for hosts is listed too, with no groups and `"lifted": true`: a
    consumer must read that field to tell it from a standing one). Superuser
    only, like the rest of the verb; the top-level `status` and `config validate` show the
    lockdowns to an engineer, for their own scopes
```

```
tacctl emergency lockdown site-a enable --reason "credential leak"
tacctl emergency lockdown site-a enable ops,readonly
tacctl emergency lockdown site-a disable --yes
tacctl emergency lockdown status
```

A user of a superuser group (its tier is superuser, and it is not a group at
priv-lvl 15 with no tier setting) is never locked: naming such a group, or
`--tier superuser`, is refused. There is no timer; a lockdown stands until
`disable`. `store.yaml` is never changed, and the record is
`emergency.lockdown.<scope>.groups|since|by|reason|pending` in `tacctl.yaml`.

**The enrolled hosts.** A device is closed by the render; a Linux host is
closed by one sshd drop-in that `host sync` writes (see [Emergency lockdown on
a host](../hosts/README.md#emergency-lockdown-on-a-host)): no key login and no
forwarding for an account that is not a superuser's, and `enable` ends the live
sessions of those accounts (`loginctl terminate-user`, else their processes;
`disable` ends nothing; root, the superusers, the provisioning login and the
account the script runs from are never touched). A host knows the tier groups,
not the store's, so on the hosts a lockdown locks every account that is not a
superuser's. `enable` says so, in red and naming them, when the groups it locks
leave out users of the scope, before it asks for the scope's name.

After the change on the devices, `enable` and `disable` name the enrolled
hosts of the scope with the command (`tacctl host sync web1 web2`) and, on a
terminal, ask `Sync these hosts now? [y/N]`. Only `--yes` answers for you; with
no terminal nothing runs and the notice is all. A host that is unreachable,
held (it is skipped and said) or refused stays on the record's `pending` list:
`status` shows it with the command, `config validate` warns of it, and the next
`host sync` of that host completes the change and takes it off the list. The
host that waits for the start of a lockdown gets the end of the live sessions at
that sync too; a host synced later, or enrolled while the lockdown stands, only
gets the drop-in. At `enable` every host of the scope is on the list, read when
the record is written (after the name is typed). At a full `disable` every
enrolled host of the scope is on it, the ones that were waiting for the start
too: a listed host may hold the file (a run that failed after the script wrote
it), and a sync of a host without the file removes nothing. A lockdown lifted
while hosts are on the list stays as a lifted record with no group and those
hosts, and goes with its last host; `emergency lockdown <scope> disable` offers
them again. A host comes off the list when a sync or an enrolment of it
succeeds, but only if its script was written for what the record still says: a
sync that started before a `disable` does not clear the host the `disable` just
listed. A host that is forgotten or renamed leaves or follows the list (`host
forget` says that a host the lockdown had reached keeps the file, and so does a
host on the list of a lifted record); `host move` into a scope that is locked
down gives the host the step that ends the sessions of its accounts, and out of
one drops its name from that scope's list. The exit status of `enable` and
`disable` is 0 when hosts are left on the list: the lockdown on the devices is in
force, and the warning names the hosts and the command.

A host provisioned through a tacctl account that is not a superuser's is
refused by the sync (the lockdown would close its own key and the way to the
host): `enable` names such a host before it asks for the scope's name, and the
host stays on the list until it is enrolled through a local account. `host show
--check` compares the drop-in with the scope's state, and tells a host a sync cannot
lock down the real reason (no sshd, which is a note; an `sshd_config` without the
Include; a provisioner that is a tacctl non-superuser), not a sync.

A restored snapshot cannot say what the hosts hold, so a restore that ends a
lockdown (a snapshot taken before it) writes a lifted record that lists every
enrolled host of the scope, and one that brings a lockdown back or changes its
groups lists every host as waiting; the report names them and the command.

**What stays open.** A device's own local accounts are not tacctl users and
are not locked; they stay out of the way only because of the device's method
list. Not closed: a Cisco console line, the Junos root account on the console,
a scope that lists local accounts first (`scope aaa-order local-first`), local
keys on a device, sessions that are already open (Junos devices and WTI
units keep a session until it logs in again or runs sudo) and a device that
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
release before 0.2.19 is refused while a lockdown stands, and every rollback
is while a lockdown has enrolled hosts or a lifted one waits for a host
(`tacctl rollback`; older releases cannot lift the drop-in). `config validate` warns while a
lockdown stands and reports a record that names a scope or group that no
longer exists, a group that is a superuser's now, or no group, and while a
host waits for the drop-in. The log has `emergency lockdown enable|disable
scope= groups= ... hosts=<count>` and, for the host step, `emergency lockdown
hosts action= scopes= hosts= synced= pending=` (host names, never an account).
