---
title: "Access Lifecycle"
description: "Joiners, movers and leavers"
permalink: "/access-lifecycle/"
parent: "Tasks"
nav_order: 2
doctype: how-to
---

# Access Lifecycle

*Joiners, movers and leavers · Checked against tacctl 0.2.19*

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
tacctl user add alice operator --scopes site-a,site-b    # 1. create in the right group and scopes
tacctl user passwd alice                                 # 2. set the first password (prompted)
tacctl host sync --all                                   # 3. accounts on the enrolled Linux hosts
tacctl user show alice                                   # 4. confirm
```

Names are lower case: letters, digits, `_` and `-`. `root` and `tacquito`
are reserved.

**Password without you seeing it.** The person creates a bcrypt hash on
their own machine (`tacctl hash commands` prints the recipes for Linux,
macOS and Windows) and sends you only the hash:

```bash
tacctl user add alice operator --scopes site-a --hash -    # paste the hash on standard input
```

Reading from `-` keeps the hash out of sudo's log and out of `ps`.

**Service accounts** (backup and NCM tools): use `readonly`, give them only
the scopes they poll, and record the owner in your inventory.

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
terminal they are kept and moved to `/home/.tacctl-removed/`. The UID stays
reserved on the server.

### 4.2 Urgent removal (termination, suspected misuse)

Disable at once, sync, and check what the person did. The full procedure is
**R1** in the [Incident Response Runbooks](incident-response-runbooks.md).

> Disable stops **new** logins. A session that is already open keeps
> running until it logs in again or runs `sudo` (Junos, WTI, Linux). Ask
> the device owners to clear it.

---

## 5. Passwords

```bash
tacctl user passwd alice         # reset (prompted twice)
tacctl passwd                    # anyone: change their own (asks for the current one)
tacctl user verify alice         # show details and check a typed password
tacctl config password-age       # show the password-age policy (days)
tacctl config password-min-length
tacctl hash generate             # prompts for a password and prints its bcrypt hash
```

`tacctl status` warns about passwords that are getting old. Every reset
logs `user passwd name=… source=prompt|hash|generated` in the audit log,
and never the password itself.

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
| New user | `tacctl user add <n> <group> --scopes <s,…>` |
| First password | `tacctl user passwd <n>` |
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
