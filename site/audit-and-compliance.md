---
title: "Audit and Compliance"
description: "Audit trail, evidence and periodic reviews"
permalink: "/audit-and-compliance/"
parent: "Tasks"
nav_order: 6
doctype: how-to
---

# Audit and Compliance

*Audit trail, evidence and periodic reviews · Checked against tacctl 0.2.27*

[Printable PDF](../pdf/tacctl-audit-and-compliance.pdf){: .pdf-link }

How to answer "who did what, when, and why" from tacctl's audit trail, and
how to run the periodic reviews that auditors ask for. Written for
superusers, security teams and compliance staff.

> **Example names used on this page**
> Users: `alice` (superuser), `bob` (engineer), `carol` (read-only),
> `dave` · Scope: `site-a` · Device: `sw1`

---

## 1. Where the audit trail lives

tacctl writes every audit line to **syslog**, facility `auth`:

| Tag | Source |
|---|---|
| `tacctl` | Every tacctl command that changes state, and every refusal |
| `tacctl-console` | Login console sessions (start, end, refused commands, and each file transfer: `console sftp ...`) |

tacctl keeps no log of its own. On a journald system:

```bash
journalctl -t tacctl -t tacctl-console                 # everything
journalctl -t tacctl --since "2026-10-01" --until "2026-11-01"
```

> **Ship the log off the server.** For example, `systemd-journal-upload` to
> a central collector, somewhere an operator who runs tacctl cannot rewrite
> it. That is what turns it into an audit trail.

Separately, `tacctl log …` shows the **authentication service's** logs (who
logged in to which device, and accounting of commands run on devices):

```bash
tacctl log search dave           # logins by a user (TACACS+: last 7 days)
tacctl log failures              # failures in the last 24 hours
tacctl log accounting 100        # device command accounting
```

From 0.2.24 these take filters and `--json`, which makes the evidence
repeatable:

```bash
tacctl log accounting --since 2026-11-01 --until 2026-11-02 --user alice --device sw1
tacctl log accounting --type change --since -24h --json | jq .
tacctl log failures --since yesterday --json
```

- Accounting records name the device that sent them (`"Device":"sw1"`, the
  registered name when the caller may see it, else the address).
- `--type change` is the records that carry a Junos change-log entry;
  `command` is any other command; `login` the start and stop of a session.
- `--json` is one object per line; the time is UTC. The filters are described
  in [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.4.

---

## 2. Reading an audit line

Each command that changes something writes a **start** line, a **detail**
line (what changed) and an **end** line, all sharing one `sid`:

```
cmd start v=1 user=alice uid=1001 origin=sudo tier=superuser tty=pts/3 console=-
    cmd="user add" args="dave ops --hash <redacted>" sid=k3x9a0bq
user add name=dave group=ops scopes=core,lab by=alice sid=k3x9a0bq
cmd end v=1 user=alice cmd="user add" result=ok status=0 duration=0.312s
    snapshot=20261021_093015_412 sid=k3x9a0bq
```

(Each is one line in the log. The examples are wrapped here.)

| Field | Meaning |
|---|---|
| `user`, `uid`, `origin` | Who ran it. `origin=root` (no login identity) only for a root shell or script. |
| `tier` | The tier the person was held to |
| `tty`, `console` | Terminal and console session (`-` = none) |
| `cmd`, `args` | What was run. Secrets and hashes show as `<redacted>`. |
| `result`, `status` | `ok`, `failed`, `denied`, `interrupted` or `aborted`, and the exit code |
| `snapshot` | The snapshot taken **before** the change. `tacctl backup diff <id>` shows it. |
| `sid` | Ties all the lines of one command together |

Commands that only read (lists, shows, checks) write no lines. Every
refusal is logged at `auth.warning`:

```
tier DENY user=carol tier=readonly cmd=user remove sid=...
cmd DENY v=1 user=bob ... tier=engineer cmd="scope secret"
    args="site-a set <redacted>" reason=superuser sid=...
```

`reason=superuser` means the verb belongs to superusers. `reason=scope`
means the target is outside the caller's scopes.

---

## 3. Search recipes

```bash
J="journalctl -t tacctl -t tacctl-console --no-pager"

$J | grep 'cmd end'                              # every change made through tacctl
$J | grep 'cmd end' | grep -v 'result=ok'        # changes that failed or were refused
$J | grep 'DENY'                                 # every refusal (tier, verb, console)
$J | grep 'sid=k3x9a0bq'                         # all lines of one command
$J | grep -E '^.*user (add|remove|disable|enable|move|rename|scope)'   # account changes
$J | grep 'user passwd'                          # password resets (never the password)
$J | grep 'user password-change'                 # password changes required or lifted (state=)
$J | grep 'password-change DENY'                 # commands refused until the password is changed
$J | grep 'secret-read'                          # every time a secret was shown, and by whom
$J | grep 'scope secret set'                     # secret rotations
$J | grep -E 'emergency lockdown|breakglass'     # lockdowns and holds, with reasons
$J | grep 'breakglass hold' | grep 'firewall=failed'   # holds whose firewall did not load
$J | grep -E 'backup (keep|unkeep|recover)'      # snapshots kept, dropped or recovered
$J | grep 'user email'                           # email changes (op=set|clear, never the address)
$J | grep -E 'device (clone|replace)'            # a device copied at a bench address, then moved in
$J | grep 'device config apply'                  # device changes: review, approval, apply
$J | grep 'device reports access'                # a superuser's reach into other users' reports
$J | grep -E 'device reports (generate|rename|remove|prune) '   # a user's own reports
$J | grep -E 'config reports|user reports-limit' # changes of the limits of the stored reports
$J | grep 'scope mgmt-acl scope=.* op=mode'      # Junos filter mode changes (value=strict|ssh-only)
$J | grep -E 'server (addresses|listen|metrics|name)'   # changes of this server's settings
$J | grep 'group edit'                           # privilege or tier changes to groups
$J | grep 'backup restore'                       # rollbacks
$J | grep 'console start'                        # console logins (user=, from=)
$J | grep 'console sftp'                         # file transfers through the console
$J | grep 'console sftp DENY'                    # transfer requests the console refused (reason=)
$J | grep 'console set' | grep file-transfer     # who may transfer files, quota and rate changes
```

The changes of this server's settings each write a detail line beside the
`cmd` pair: `server name` and `server metrics` carry `from=` and `to=`,
`server listen` adds `backend=` and `listener=`, and `server addresses` carries
`op=add` or `op=replace` and `address=`. The timing scale is recorded in the
same way: `scope timeout-scale` writes `scope=`, `from=` and `to=`,
`device timeout-scale` a `device set` line (`name`, `field=timeout-scale`,
`from`, `to`), and `config devices timeout-scale` a `config devices` line with
`key`, `from` and `to`.

**Reports.** A superuser who reads or changes another user's device reports
(`device reports list --user` or `--all-users`, and `show`, `export`,
`rename`, `remove` and `prune` of `<user>/<report>`, `--user` or
`--all-users`) writes one line **before** anything is listed, shown or
changed, at `auth.notice`, and never a content:

```
device reports access verb=show owner=bob report=inventory-20261106 by=alice sid=k3x9a0bq
device reports access verb=prune owner=bob report=* by=alice sid=k3x9a0bq
```

`verb` is `list`, `show`, `export`, `rename`, `remove`, `prune` or
`prune-dry-run`; `list --all-users` has `owner=*`, and a `prune` of other
users' reports writes a line with `report=*` for each other user whose
directory it reads, also when nothing in it is old enough, and never a report
name or a count (since 0.2.27; the line carried `count=` before). All the
lines of a run are written before the first directory is read. With
`audit.strict` on, an access whose line cannot be written is refused, and so
is a whole `prune --all-users` when one line cannot. A
user's own reports write a detail line only when something changes:
`device reports generate type= name= format= rows=`, `rename name= new=`,
`remove name=` and `prune older-than= removed=`; the `format=` of a `generate`
can be `pdf`. `config reports` writes
`key=max_size|max_count from= to=` and `user reports-limit` writes `name=
key=max-size|max-count op=set|clear` and `value=` for a set
([Superuser Daily Operations](superuser-daily-operations.md) §4.11).

**File transfer through the console.** A transfer (the sftp subsystem, new in
0.2.28) has lines of its own under the tag `tacctl-console`, with the session
id and the user. The session opens with `console start ... mode=sftp` and
`console sftp start ... tier= from= home="<path>" quota=<size>|unlimited
rate=<size>|off`. Each upload, download and change is one line
(`console sftp upload|download|delete|rename|mkdir|setstat ... tier=
path="<path>"`, with `to="<path>"` for a rename, `bytes=` for an upload and a
download and `error="<text>"` for a request that failed), and each request
the console refused is `console sftp DENY ... tier= path="<path>" reason=` at
`auth.warning`. The session ends with `console sftp end ... up=<bytes>
down=<bytes> ops=<n> refused=<n>` and `console end ... reason=sftp`.

```
console sftp upload sid=k3x9a0bq user=bob tier=operator path="/notes.txt" bytes=431
console sftp DENY sid=k3x9a0bq user=bob tier=operator path="/big.iso" reason=quota
```

- The reasons of a refusal are `.ssh` (the folder is out of reach),
  `outside-the-home`, `symlink`, `link` (a file with more than one name was
  asked to be opened, written or have its mode or times set), `quota`,
  `unsupported`, `bad-path` and `too-many-open-files` (the 257th handle of a
  session).
- A refusal of any kind is logged, a refused `readlink` and `realpath`
  included. A successful `stat`, listing, `readlink` or `realpath` is not.
- A path is logged as a double-quoted string in which a control character, a
  quote, a backslash and a byte that is not UTF-8 are escapes, cut at 200
  bytes: no file name can end a line or forge a field.
- A transfer the console would not start is `console DENY ...
  reason=file-transfer|password-change|policy|home|stream subsystem=sftp`.
  `reason=file-transfer` is an account that does not have file transfer:
  that user sees only `Connection closed` from the client, so this line is
  where to look.
- A superuser's change of who may transfer, or of a quota or rate, is a
  `console set` line with `key=file-transfer` at `auth.notice`; its `item` is
  the tier, `user:<name>`, `quota:<tier>`, `quota-user:<name>`,
  `rate:<tier>` or `rate-user:<name>`.
- If `logger` cannot write a line during a transfer, the transfer goes on
  unaudited and the warning `The audit line was not written` appears on the
  client's standard error.

A command string the console does not run (`scp -O`, a program, a shell) is
`console DENY ... reason=command first=<word>`, as before.

> A `cmd start` with no matching `cmd end` means the command did not finish
> (killed, crash, power loss). The snapshot named on its lines holds the
> state from before it. `tacctl config validate` shows the state now.

---

## 4. Evidence by control

| Auditor asks for | Evidence |
|---|---|
| List of users and their access | `tacctl user list`, `tacctl group list`, `tacctl scope list` |
| Who has administrative rights | `tacctl user list` filtered to superuser groups; `tacctl group show superuser` |
| Joiner/mover/leaver changes in the period | `grep 'cmd end'` plus `user add\|remove\|move\|scope\|disable` detail lines |
| Password resets | `grep 'user passwd'` (`source=prompt\|hash\|generated`); `grep 'user password-change'` (`state=required\|cleared`) |
| Password age policy is enforced | `tacctl config password-age`; the warnings in `tacctl status` |
| Privileged access to secrets | `grep 'secret-read'` (kind, name, by) |
| Emergency access use | `grep -E 'breakglass\|emergency lockdown'`, with reason, duration and person |
| Device configuration changes | `grep 'device config apply'` (`mode=attended` = names typed back) |
| Commands run on devices | `tacctl log accounting` |
| Who looked at another user's device reports | `grep 'device reports access'` (verb, owner, report, by); never the content |
| Failed/denied attempts | `tacctl log failures`; `grep DENY` |
| Changes can be rolled back | `tacctl backup list`; the `snapshot=` on each `cmd end` ([Backups and Undo](backups-and-undo.md)) |

---

## 5. Monthly review checklist

1. `tacctl user list`: every account has a current owner. Remove leavers.
2. `tacctl group list`: superuser and engineer membership is justified.
3. `tacctl status`: no password-age warnings beyond policy.
4. `tacctl emergency lockdown status` and `tacctl breakglass list`: nothing
   left in place.
5. `tacctl config validate`: no warnings left unanswered (for example,
   scopes without break-glass local users).
6. `$J | grep 'secret-read'`: every secret view is explained.
7. `$J | grep DENY`: look for repeated refusals of one person (probing).
8. `$J | grep 'device reports access'`: every look at another user's device
   reports is explained.
9. `tacctl device config list --differs`: devices drifting from the
   standard.
10. `tacctl host check --all`: Linux hosts match.
11. Save the outputs with the date as review evidence.

---

## 6. What is never logged

Passwords, hashes and shared secrets never appear in any line. Values passed
with `--hash`, `--secret`, `scope secret … set` and similar options are
replaced with `<redacted>`. So are a user's email address (`--email` of
`user add`, the address of `user email`: the detail line says only
`op=set` or `op=clear`) and the `--note` of `backup keep`. The audit lines of
`device reports` say who, whose and which report, never what a report holds,
and no report holds a secret, a hash or a community string.

Free text **is** logged as typed: `--reason` for lockdowns and holds, and
arguments after `--` on `ssh`. **Never put secrets in a reason.**

Values typed on a command line also land in **sudo's own log**. Use the
prompting forms (`user passwd`, `scope secret <s> set`, `--hash -`,
`--stdin`) so values never reach the command line.

---

*See also:* [Access Lifecycle](access-lifecycle.md) ·
[Incident Response Runbooks](incident-response-runbooks.md) ·
[Audit log (repo)](https://github.com/rett/tacctl/blob/master/docs/security/audit.md) ·
`man tacctl` (AUDIT LOG)
