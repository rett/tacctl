---
title: "Linux Host Operations"
description: "Keeping enrolled Linux hosts in step"
permalink: "/linux-host-operations/"
parent: "Tasks"
nav_order: 3
doctype: how-to
---

# Linux Host Operations

*Keeping enrolled Linux hosts in step · Checked against tacctl 0.2.20*

[Printable PDF](../pdf/tacctl-linux-host-operations.pdf){: .pdf-link }

How a superuser runs the Linux servers enrolled in tacctl day to day:
keeping accounts in step, checking hosts, moving and retiring them, and
recovering when logins break. Enrolled hosts authenticate logins and `sudo`
against tacctl, over TACACS+ (`pam_tacplus`) or RADIUS (`pam_radius_auth`).

Host operations are **superuser only**. Engineers can list and show the
hosts of their own scopes.

> **Example names used on this page**
> Hosts: `web1`, `db1`, `db2` · Scopes: `site-a`, `lab` · Users: `alice`,
> `carol`

---

## 1. See your hosts

```bash
tacctl host list                 # target, ADDRESS, scope, server, METHOD, users (+ STATE when held)
tacctl host list --json
tacctl host show web1            # connection, scope, pinned keys, sightings,
                                 # the accounts the next sync makes
tacctl host check web1           # read-only: does the host match what tacctl would make it?
tacctl host check --all
```

`host check` logs in, changes nothing, and lists each difference with the
command that fixes it. It exits 1 if a host differs or could not be
checked. If `host list` ends with *N finding(s)*, run
`tacctl config validate`.

---

## 2. Keep accounts in step: `host sync`

User changes reach hosts only when you sync. **Sync after every user add,
remove, disable, enable, rename, move or scope change.**

```bash
tacctl host sync web1                  # one host
tacctl host sync db1 db2               # several, in the order typed
tacctl host sync --all                 # every enrolled host
tacctl host sync --all --remove-home   # also delete removed users' homes without asking
```

What a sync does:

| User state | Effect on the host |
|---|---|
| New in the host's scope | Account created (with a UID consistent across hosts). A user name with a period is skipped with a warning: it is no Linux account name. |
| Disabled | Account expired: no login, ssh keys included. Files kept. |
| Must change the password | As disabled, on every host but the tacctl server, until the user changes it there; the next sync opens it again. `host show` counts it with the disabled accounts. |
| Re-enabled | Restored |
| Removed, or out of the scope | Account deleted. The home is deleted only if you agree (asked at a terminal, or `--remove-home`). Otherwise it is moved to `/home/.tacctl-removed/`. |
| Renamed | Account renamed by UID. The home stays where it is. |
| Group/tier changed | Tier on the host updated |

A failing host doesn't stop the others. The exit status is 1 if any host
failed. A held host (break-glass) is skipped by `--all` and refused when
named.

> **Local accounts are never touched.** tacctl manages only the accounts it
> created. If a local account has the same name as a tacctl user, that user
> gets no account on the host and you see a warning
> (`web1: synced (4 users; 1 refused: carl)`). Resolve it by renaming one
> of the two.

---

## 3. Enroll a host

```bash
tacctl host enroll admin@web1.example.net --scope site-a
tacctl host enroll admin@10.30.0.15 --name web2 --method radius
tacctl host enroll admin@10.30.0.16 --name db3 --port 2222 --identity ~/.ssh/deploy_ed25519
```

- `--method tacplus|radius`: if you leave it out, the scope's or the
  server's default is used (`tacctl host default-method`).
- `--name`: the registry name. The default is the short hostname, in lower
  case.
- Enrolling pins the host's ssh keys and registers the host.

If the host's `/etc/login.defs` `UID_MIN`–`UID_MAX` overlaps tacctl's UID
range, enroll and sync warn you. Keep local UIDs clear of that range.

---

## 4. Move, rename, retire

```bash
tacctl host move web1 lab        # another scope (asks before deleting accounts)
tacctl host move --all           # every host whose address another scope now answers
tacctl host rename web1 web2         # registry only; offers to rename its own linux-<name> scope
tacctl host unenroll web1        # remove the PAM setup and secret from the host, then deregister
tacctl host unenroll web1 --force    # deregister even if the host can't be cleaned
tacctl host forget web1          # drop only this server's record; nothing sent to the host
```

| Goal | Use |
|---|---|
| Decommission a reachable host | `unenroll`. Local accounts and homes stay on the host. |
| Remove a wrong or duplicate registration | `forget` |
| Host re-addressed or moved to a new segment | `host move` (or `--all` after changing scope prefixes) |

---

## 5. Rotating the provisioning account

tacctl logs in to each host with a provisioning account. To switch it:

```bash
tacctl host provisioner web1 rotate tacprov --key ~/.ssh/tacprov_ed25519 --dry-run
tacctl host provisioner web1 rotate tacprov --key ~/.ssh/tacprov_ed25519 --remove-old
```

The new account is created over the current login and proven in a fresh
connection (`sudo id -u` must return 0) before the registry changes.

---

## 6. Recovery: logins or sudo broken on a host

```bash
tacctl breakglass hold web1 --reason "INC-4821 sudo broken"     # type 'web1' to confirm
```

While held, the server stops answering that host's address. The host's
local administrator and console work. tacctl users can't log in or `sudo`
there.

```bash
# ... fix the host with the local admin ...
tacctl breakglass release web1
tacctl host check web1
```

While a host is held, `host sync`, `show --check`, `enroll`, `move`,
`unenroll` and `forget` refuse it. `tacctl ssh` warns you and connects.
Holds never expire; [Break Glass](break-glass.md) covers holds in full, and
[Incident Response Runbooks](incident-response-runbooks.md) R5 is the incident
form of this procedure.

---

## 7. Troubleshooting

| Symptom | Check / fix |
|---|---|
| User has no account on one host | A local account with the same name exists there (see the sync summary). Rename one. |
| Sync stops on a UID conflict | A local account uses a UID from tacctl's range. Fix the host. Use `--allow-uid-mismatch` only if you understand the result. |
| `'alice': not renamed … processes run as UID …` | The user is logged in. The rename is retried at the next sync. |
| Host shows a drift warning in `host list` | Its scope no longer answers its address. Run `tacctl host move <name>`. |
| `the UID ledger … is locked` | Another command is running. Try again shortly. |
| `host check` differences | Run the fix command printed beside each one, usually `host sync <name>` |

---

## 8. Quick reference

| Task | Command |
|---|---|
| List / detail | `tacctl host list` / `host show <n>` |
| Compliance check | `tacctl host check --all` |
| Push accounts | `tacctl host sync --all` |
| Enroll | `tacctl host enroll <user>@<host> --scope <s>` |
| Move scope | `tacctl host move <n> <scope>` |
| Rename | `tacctl host rename <old> <new>` |
| Retire | `tacctl host unenroll <n>` |
| Drop bad record | `tacctl host forget <n>` |
| Emergency access | `tacctl breakglass hold <n> --reason "…"` |

---

*See also:* [Access Lifecycle](access-lifecycle.md) · [Break Glass](break-glass.md) ·
[Troubleshooting](troubleshooting.md) §7 ·
[Linux hosts (repo)](https://github.com/rett/tacctl/blob/master/docs/hosts/README.md) ·
`man tacctl`
