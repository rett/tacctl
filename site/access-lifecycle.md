---
title: "Access Lifecycle"
description: "Joiners, movers and leavers"
permalink: "/access-lifecycle/"
parent: "Tasks"
nav_order: 2
doctype: how-to
---

# Access Lifecycle

*Joiners, movers and leavers · Checked against tacctl 0.2.20*

[Printable PDF](../pdf/tacctl-access-lifecycle.pdf){: .pdf-link }

How a superuser manages a person's access from their first day to their
last: accounts, roles, scopes, passwords, Linux hosts, and periodic reviews.
Each section is a short procedure you can follow as written.

> **Example names used on this page**
> Users: `alice` (new NOC operator), `bob` (engineer), `carol` ·
> Scopes: `lab`, `site-a`, `site-b`

---

## 1. The access model in brief

A person's **group** decides *what* they can do (device privilege and
tacctl tier), their **scopes** decide *where* they can log in, and their
**status** decides *whether* they can log in at all. [Concepts](concepts.md)
§1–2 has the full model and the group table.

> An **empty scope list means no access anywhere**. It never means
> everywhere. The `engineer` group exists only after
> `tacctl group preset roles`; check with `tacctl group list`.

---

## 2. Joiner: a new person

```bash
tacctl user add alice operator --scopes site-a,site-b    # 1. create; prompts for the first password
tacctl host sync --all                                   # 2. accounts on the enrolled Linux hosts,
                                                         #    the tacctl server included
tacctl user show alice                                   # 3. confirm (Password change line)
```

Give alice the first password your usual way. She must change it at her
first login to the tacctl server ([Getting Started](getting-started.md)
§2.1): until then no device accepts her, and the other hosts keep her
account expired. Her account on the server exists only after the sync of
step 2, so run it before she logs in. The requirement and what to check
are in §5.1.

Names are lower case: letters, digits, `_` and `-`, and a period between
two parts (`alice.smith`; never first, last or twice in a row). `root` and
`tacquito` are reserved. A name with a period is no Linux account name:
`host sync` skips that user with a warning, so they log in at devices only,
and `tacctl rollback` is refused while such a name exists.

**Password without you seeing it.** The person creates a bcrypt hash on
their own machine (`tacctl hash commands` prints the recipes for Linux,
macOS and Windows) and sends you only the hash:

```bash
tacctl user add alice operator --scopes site-a --hash -    # paste the hash on standard input
```

Reading from `-` keeps the hash out of sudo's log and out of `ps`. A new
user must change the password whichever way it was set;
`--no-change-required` skips that, for example for a password only the
person knows.

**Service accounts** (backup and NCM tools): use `readonly`, give them only
the scopes they poll, and record the owner in your inventory. Create them
with `--no-change-required`: a tool cannot change its password at the tacctl
server, and no device would accept it until it did.

---

## 3. Mover: a change of role or territory

| Change | Command | Notes |
|---|---|---|
| Promotion or demotion | `tacctl user move alice engineer` | Password kept. Run `host sync --all` so the host tier follows. |
| New site | `tacctl user scope alice add site-b` | Comma lists accepted |
| Leaving a site | `tacctl user scope alice remove site-b` | |
| Reorganization | `tacctl user scope alice replace site-a,lab` | Replaces the whole list |
| Name change | `tacctl user rename alice alice2` | Devices need the **new** name at login. The UID is kept, and hosts rename the account at the next sync. |

After any of these, push the change to Linux hosts:

```bash
tacctl host sync --all
```

> **After a rename,** sync **all** hosts before you give the old name to a
> new person. Otherwise a host's UID check will refuse the sync.

A name may also clash with a scope's break-glass local account. tacctl
refuses that and names the command that resolves it.

---

## 4. Leaver: offboarding

### 4.1 Planned departure

```bash
tacctl user disable carol      # day 1: logins refused everywhere; password hash kept
tacctl host sync --all         # Linux accounts expired; files kept
```

Then, when HR/retention allows:

```bash
tacctl user remove carol       # confirms
tacctl host sync --all         # Linux accounts deleted; asks per home directory
```

When a user is removed, `host sync` asks about each home directory at a
terminal. `--remove-home` deletes the homes without asking. Without a
terminal they are kept and moved to `.tacctl-removed` under `/home`, a
directory only root can open. The UID stays reserved on the server.

### 4.2 Urgent removal (termination, suspected misuse)

Disable at once, sync, and check what the person did. The full procedure is
**R1** in the [Incident Response Runbooks](incident-response-runbooks.md).

> Disable stops **new** logins. A session that is already open keeps
> running until it logs in again or runs `sudo` (Junos, WTI, Linux). Ask
> the device owners to clear it.

---

## 5. Passwords

```bash
tacctl user passwd alice                        # reset (prompted twice); alice must change it
tacctl user passwd alice --no-change-required   # reset without requiring a change
tacctl passwd                                   # anyone: change their own (asks the current one)
tacctl user verify alice                        # show details and check a typed password
tacctl config password-age                      # show the password-age policy (days)
tacctl config password-min-length
tacctl hash generate                            # prompts for a password and prints its bcrypt hash
```

`tacctl status` warns about passwords that are getting old. Every reset
logs `user passwd name=… source=prompt|hash|generated` in the audit log,
and never the password itself.

### 5.1 A required password change

A user who must change the password can log in to the tacctl server only,
and there the console asks for the change before anything else runs
([Getting Started](getting-started.md) §2.1). `user add` and your reset with
`user passwd` require it by default. To require it, or lift it, on demand:

```bash
tacctl user require-password-change alice       # require it (on is the default)
tacctl user require-password-change alice off   # lift it
tacctl user require-password-change --all       # every user (superusers are skipped)
tacctl host sync --all                          # the other hosts expire the accounts
```

What the requirement does, until the user changes the password:

- Every device refuses the user, as it refuses an unknown user.
- Every enrolled Linux host but the tacctl server expires the account at its
  next `host sync` (password and ssh key both fail; files kept). The sync
  after the change opens it again.
- On the server, every command but `passwd`, `version` and `help` is
  refused with exit status 1, in the console and on the command line.
- The user's own `tacctl passwd` lifts it, and so do
  `user passwd --no-change-required` and `require-password-change off`.

A superuser is never held to it: the tier of the user's group decides each
time. The requirement is set only for a user who can log in to the server to
make the change (the server enrolled with `host enroll --local`, the user in
its scope, enabled, with no period in the name); otherwise the command says
why and sets nothing. `require-password-change --all` ends with
`Flagged N, skipped M, already required K.`

Who is waiting: `user list` marks the date with `(change required)`,
`user show` has a `Password change` line, and `status` counts the users.
Two marks need you:

| Mark | Meaning | What to do |
|---|---|---|
| `flagged, cannot log in to change it` | The user has no login on the server (`user show` gives the reason) | Restore the login, or `tacctl user require-password-change <name> off` |
| `flagged, devices in a scope shared with the server still accept the password` | The server shares its scope with devices, which keep accepting the old password | Give the server a scope of its own: `scope add`, then `host enroll --local --scope <name>` |

A change that would leave a flagged user with no login on the server (taking
the server's scope away, for example) is refused with nothing changed, and
names `tacctl user require-password-change <name> off`.

> **Before you require it of everyone,** check
> `tacctl console forwarding tiers`. A user of a listed tier can still
> forward ports through the server with the old password until it is
> changed. The default lists only superusers, who are never held.

---

## 6. Periodic access review (monthly or quarterly)

1. **Export the facts:**

```bash
tacctl user list                 # name, group, status, password age, scopes
tacctl group list                # groups and user counts
tacctl scope list                # scopes
```

2. **Check each item:**
   - Every user maps to a current person or an owned service account.
   - `disabled` users older than your retention period → `user remove`.
   - Superusers are as few as possible.
   - Scopes per user are no more than the role needs.
   - Password ages are within policy (`status` warnings).
   - `user scope <name>` shows no orphan scopes (they are flagged in red).
3. **Fix**, then run `tacctl host sync --all` and
   `tacctl config validate`.
4. **Record evidence:** the audit lines of the changes (see
   [Audit and Compliance](audit-and-compliance.md)).

---

## 7. Quick reference

| Task | Command |
|---|---|
| New user (prompts for the first password) | `tacctl user add <n> <group> --scopes <s,…>` |
| Reset a password | `tacctl user passwd <n>` |
| Require / lift a password change | `tacctl user require-password-change <n> [on\|off]` |
| Add/remove scope | `tacctl user scope <n> add\|remove <s>` |
| Replace scopes | `tacctl user scope <n> replace <s,…>` |
| Change role | `tacctl user move <n> <group>` |
| Rename | `tacctl user rename <old> <new>` |
| Suspend / restore | `tacctl user disable\|enable <n>` |
| Delete | `tacctl user remove <n>` |
| Push to hosts | `tacctl host sync --all` |
| Review | `tacctl user list` |

---

*See also:* [Concepts](concepts.md) · [Linux Host Operations](linux-host-operations.md) ·
[Incident Response Runbooks](incident-response-runbooks.md) ·
[Audit and Compliance](audit-and-compliance.md) · `man tacctl`
