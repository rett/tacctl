---
title: "Backups and Undo"
description: "Snapshots, comparing them, and restoring tacctl's configuration"
permalink: "/backups-and-undo/"
parent: "Tasks"
nav_order: 5
doctype: how-to
---

# Backups and Undo

*Snapshots, comparing them, and restoring tacctl's configuration · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-backups-and-undo.pdf){: .pdf-link }

Every tacctl change takes a snapshot of the configuration first. This page
explains what a snapshot holds, how to see what changed, when to restore and
when to fix forward, and what to check after a restore. Restoring is a
**superuser** task.

> **Example names used on this page**
> Scope: `site-a` · User: `alice` · Hosts: `web1`, `db1` · Ticket `CHG-1182`

---

## 1. What a snapshot is

| Question | Answer |
|---|---|
| When is one taken? | Automatically, before every change that would alter tacctl's configuration. Nothing is added when nothing would change. |
| What does it hold? | The store (users, groups, scopes) and `tacctl.yaml` (settings, including break-glass holds), plus the Linux host registry, host records and UID ledger |
| How many are kept? | The newest 30 |
| What does it **not** do? | Touch any device or host. A restore changes tacctl's records only. |

> **Snapshots contain shared secrets and password hashes.** That is why
> `backup diff` and `backup restore` are superuser-only, and why each diff
> writes a `secret-read` audit line.

---

## 2. See what changed

```bash
tacctl backup list                  # snapshots, newest first (operator tier and up)
tacctl backup diff                  # what changed since the most recent snapshot
tacctl backup diff <timestamp>      # ... since a specific one
```

To find the snapshot taken just before a given change, read the audit
trail: each change's `cmd end` line names it as `snapshot=<id>`
([Audit and Compliance](audit-and-compliance.md) §2).

```bash
journalctl -t tacctl --no-pager | grep 'cmd end' | grep 'user scope'
```

---

## 3. Restore or fix forward?

A restore puts back **everything** the snapshot holds, so it also undoes
every change made after it.

| Situation | Better choice |
|---|---|
| One wrong command, nothing changed since | Either. A targeted fix (`tacctl user scope alice remove site-b`) is often clearer in the audit trail. |
| Several related changes went wrong together | Restore the snapshot from before the first one |
| Others have made changes since the mistake | Fix forward with targeted commands, or you undo their work too |
| The configuration is broken and you don't know why | `tacctl config validate` first, then restore if needed |

---

## 4. Restore

**1. Preview.**

```bash
tacctl backup list
tacctl backup diff <timestamp>      # what the restore would put back
```

**2. Restore.** It asks for confirmation.

```bash
tacctl backup restore <timestamp>
```

What happens:

- tacctl first snapshots the **current** state, so a restore can itself be
  undone with another restore.
- Both configuration files come back, every enabled backend is re-rendered
  and the backends restart.
- Nothing changes if the snapshot is invalid or the render fails.
- Break-glass holds come and go with the snapshot, and the restore names
  them when they change. The restore also shows any emergency lockdown that
  stands.
- Host files come back too. Before the question and after the restore, a
  note names the hosts that come back, go, or are registered differently,
  and every user whose UID would be dropped or changed.

**3. Check.**

```bash
tacctl status                       # backends running?
tacctl config validate              # no new problems?
tacctl emergency lockdown status    # lockdowns as you expect?
tacctl breakglass list              # holds as you expect?
tacctl host check --all             # do the hosts still match?
```

> **No device or host is touched by a restore.** If the restore changed
> users or scopes, run `tacctl host sync --all` so the Linux hosts follow.
> If it changed a scope's secret, the devices need the matching key again.

### 4.1 Keeping the hosts' UIDs

If the hosts have synced since the snapshot was taken, keep the live UID
ledger, which is the one the hosts agree with:

```bash
tacctl backup restore <timestamp> --keep-uids
```

Users, groups, scopes and devices come back from the snapshot; restored
users keep the UIDs they have now.

---

## 5. Quick reference

| Task | Command | Who |
|---|---|---|
| List snapshots | `tacctl backup list` | Operator |
| What changed since the latest | `tacctl backup diff` | Superuser |
| What changed since one | `tacctl backup diff <ts>` | Superuser |
| Restore | `tacctl backup restore <ts>` | Superuser |
| Restore, keep host UIDs | `tacctl backup restore <ts> --keep-uids` | Superuser |
| Find the snapshot before a change | `journalctl -t tacctl \| grep 'cmd end'` | Superuser |

---

*See also:* [Incident Response Runbooks](incident-response-runbooks.md) R8 ·
[Audit and Compliance](audit-and-compliance.md) ·
[Maintenance commands (repo)](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) ·
`man tacctl`
