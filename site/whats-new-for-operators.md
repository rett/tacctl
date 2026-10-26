---
title: "What's New for Operators"
description: "The changes in each tacctl release that people on shift will notice"
permalink: "/whats-new-for-operators/"
parent: "Reference"
nav_order: 4
---

# What's New for Operators

*The changes in each tacctl release that people on shift will notice · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-whats-new-for-operators.pdf){: .pdf-link }

Release notes describe every change in depth. This page lists only what
changes day-to-day work: renamed commands, new commands and changed
behavior. Each release links to its full notes. The newest release comes
first.

> **Scripts break on renames.** tacctl does not keep aliases for renamed
> commands. Check your scripts against every release you skip.

---

## 1. tacctl 0.2.19

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.19.md)

| Change | What it means on shift | Page |
|---|---|---|
| **Emergency lockdown** (`tacctl emergency lockdown`) | Superusers can refuse the logins of chosen groups on a scope at once. A red notice appears on every command that names a locked scope. | [Emergency Lockdown](emergency-lockdown.md) |
| **Engineers work their own scopes** | Engineers can enroll, collect, onboard, sync and apply for the devices of their own scopes | [Engineer Guide](engineer-guide-device-changes.md) |
| `tacctl device support-bundle` | Collects a scrubbed, read-only bundle of what a developer needs from one device | [Device commands (repo)](https://github.com/rett/tacctl/blob/master/docs/cli/device.md) |
| Wider `system` blocks | Junos and IOS `system` blocks now cover syslog, login banners, login retry and password policy, ssh settings and timestamps; plans can remove a service a scope requires to be off | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| Host names may contain dots | `tacctl host rename web1 web1.example.net` works | [Linux Host Operations](linux-host-operations.md) |
| Unknown commands answered first | A mistyped command is answered before `sudo` asks for a password | — |

## 2. tacctl 0.2.18

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.18.md)

**Renamed commands, no aliases.** The old names are now unknown commands:

| Up to 0.2.17 | From 0.2.18 |
|---|---|
| `device config-syntax <name> [auto\|ios12\|modern]` | `device ios-syntax <name> [auto\|ios12\|modern]` |
| `device add --config-syntax <syntax>` | `device add --ios-syntax <syntax>` |
| `device notices [<name>] [--all]` | `device notice list [<name>] [--all]` |
| `device ssh-config` | `device client-config` |

Also: Tab now completes these names with a space, `?` describes every
command and flag from its own usage, and a mistyped command suggests what
you may have meant (`tacctl enroll` suggests `device enroll` and
`host enroll`). Every tier can run `device notice list` and
`device client-config`.

## 3. tacctl 0.2.17

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.17.md)

| Change | What it means on shift | Page |
|---|---|---|
| **`tacctl device enroll`** | One attended command from a new address to its plan: key, vendor, registration, pull, plan | [Engineer Guide](engineer-guide-device-changes.md) §2.2 |
| **Apply review asks per device** | Approve each Junos device by typing its name. Typing a count no longer works; scripts use `--confirmed -y`. | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| **Host keys accepted one device at a time** | `enroll`, `collect` and `onboard` show the one key they will pin; you accept it by typing the name back | [Connecting to Devices](connecting-to-devices.md) §6 |
| **Audit session id** | Every audit line ends in `sid=<id>`, so one `grep` finds a whole command. Log filters that anchor the end of a line (`$`) need updating. | [Audit and Compliance](audit-and-compliance.md) §2 |
| `cmd start` / `cmd end` lines | Every change writes a start and an end line, with the result and the snapshot taken | [Audit and Compliance](audit-and-compliance.md) |
| Vendor read by SNMP | `device add` and `device check` say which vendor the device reports; `device vendor <name> --from-device` sets it | [Engineer Guide](engineer-guide-device-changes.md) §2.4 |
| New selectors | `device config pull`, `diff`, `plan` and `apply` take `--differs`, `--name` and `--ip`; `apply --pull` reads fresh first | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |

---

## 4. Older releases

Releases 0.2.0 to 0.2.16 are listed on the
[releases page](https://github.com/rett/tacctl/releases), and every change is
numbered in
[`CHANGELOG.md`](https://github.com/rett/tacctl/blob/master/CHANGELOG.md).

---

*See also:* [About These Docs](about-these-docs.md) (which release each page was
checked against) · `tacctl version`
