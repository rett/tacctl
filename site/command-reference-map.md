---
title: "Command Reference Map"
description: "From each tacctl command family to its reference page and the task page that uses it"
permalink: "/command-reference-map/"
parent: "Reference"
nav_order: 1
doctype: reference
---

# Command Reference Map

*From each tacctl command family to its reference page and the task page that uses it · Checked against tacctl 0.2.28*

[Printable PDF](../pdf/tacctl-command-reference-map.pdf){: .pdf-link }

This documentation explains *how to do things*. The flag-by-flag reference for every
command lives in the repository's
[CLI reference](https://github.com/rett/tacctl/blob/master/docs/cli/README.md)
and in `man tacctl` on the server. This table maps each command family to
both.

> In the console or `tacctl shell`, `?` and `help <command>` show the usage
> of any command. A command family with no arguments prints its usage too.

---

## 1. Command families

| Command family | What it covers | Reference (repo) | Task pages |
|---|---|---|---|
| `tacctl status`, `passwd`, `ssh`, `version`, `hash` | Top-level commands | [Conventions and top-level commands](https://github.com/rett/tacctl/blob/master/docs/cli/conventions.md) | [Getting Started](getting-started.md), [Connecting to Devices](connecting-to-devices.md) |
| `tacctl shell`, `completion`, `man` | The interactive shell, completion, the bash help key, the manual page, password cache | [Shell, completion and manual page](https://github.com/rett/tacctl/blob/master/docs/cli/shell.md) | [Getting Started](getting-started.md) |
| `tacctl console` | The login console and its settings: system shell, file transfer (SFTP, with a quota and a rate; superuser only), password cache, colour, list length | [Console commands](https://github.com/rett/tacctl/blob/master/docs/cli/console.md) | [Getting Started](getting-started.md) §1.4, [Superuser Daily Operations](superuser-daily-operations.md) §10 |
| `tacctl user` | Users, passwords, scope membership, email addresses, the limits of a user's stored reports (`user reports-limit`) | [User commands](https://github.com/rett/tacctl/blob/master/docs/cli/user.md) | [Access Lifecycle](access-lifecycle.md) §2, [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| `tacctl group` | Groups, privilege levels, tiers, Junos classes | [Group commands](https://github.com/rett/tacctl/blob/master/docs/cli/group.md) | [Concepts](concepts.md) |
| `tacctl scope` | Prefixes, shared secrets, break-glass accounts, per-scope settings (SNMP among them), the timing scale of a scope | [Scope commands](https://github.com/rett/tacctl/blob/master/docs/cli/scope.md) | [Superuser Daily Operations](superuser-daily-operations.md) §4.9, §8, [Break Glass](break-glass.md) |
| `tacctl device` | Registry, clone and replace, notices, host keys, timing scale, SNMP settings and users, check and scan (with `--sources`), pull, diff, plan, apply (with `--timing`), enroll, onboard | [Device commands](https://github.com/rett/tacctl/blob/master/docs/cli/device.md) | [Engineer Guide: Device Changes](engineer-guide-device-changes.md) §2.5, §3.1, [Connecting to Devices](connecting-to-devices.md) §7, [Superuser Daily Operations](superuser-daily-operations.md) §4.10 |
| `tacctl device reports` | Saved, dated reports of the registered devices (inventory, members, software, config) as text, CSV, JSON or PDF, in the user's home: generate, list, show, export, rename, remove, prune; a superuser's audited reach into other users' reports | [Device reports](https://github.com/rett/tacctl/blob/master/docs/devices/reports.md), [Device commands](https://github.com/rett/tacctl/blob/master/docs/cli/device.md) | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6, [Engineer Guide: Device Changes](engineer-guide-device-changes.md) §3.2, [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| `tacctl host` | Linux hosts: enroll, sync, check, move, unenroll | [Host commands](https://github.com/rett/tacctl/blob/master/docs/cli/host.md) | [Linux Host Operations](linux-host-operations.md) |
| `tacctl breakglass` | Holding and releasing devices and hosts (the firewall for held addresses is `tacctl config breakglass-firewall`) | [Break-glass commands](https://github.com/rett/tacctl/blob/master/docs/cli/breakglass.md) | [Break Glass](break-glass.md) |
| `tacctl emergency` | Emergency lockdown, devices and enrolled hosts | [Emergency commands](https://github.com/rett/tacctl/blob/master/docs/cli/emergency.md) | [Emergency Lockdown](emergency-lockdown.md) |
| `tacctl log` | Authentication logs, failures, accounting, with filters by time, user, device and kind, and `--json` | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.4, [Superuser Daily Operations](superuser-daily-operations.md) §9, [Audit and Compliance](audit-and-compliance.md) §1, [Troubleshooting](troubleshooting.md) |
| `tacctl backup` | Snapshots, diff, restore (also of a snapshot that holds a user with a period), keep, unkeep, recover | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | [Backups and Undo](backups-and-undo.md) §4.4 |
| `tacctl upgrade`, `rollback` | Updating tacctl, which renames users whose name has a period; preparing the state for an earlier release (`rollback 0.2.27` is the release before); the upgrade offers the PDF tools of the device reports, once | [Upgrading](https://github.com/rett/tacctl/blob/master/docs/install/upgrading.md) | [Access Lifecycle](access-lifecycle.md) §2, [Backups and Undo](backups-and-undo.md) §5 |
| `tacctl backend`, `store` | Backends and the store | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | Out of scope for this documentation |
| `tacctl config` | Settings (including the server's timing scale, `config devices timeout-scale`, the SNMP defaults of `config snmp`, the break-glass firewall and the limits of the stored reports, `config reports`) and the device configuration walkthroughs | [Config commands](https://github.com/rett/tacctl/blob/master/docs/cli/config.md), [tacctl.yaml settings](https://github.com/rett/tacctl/blob/master/docs/cli/tunables.md) | [Vendor Notes](vendor-notes.md), [Superuser Daily Operations](superuser-daily-operations.md) §4.9, §4.10, [Break Glass](break-glass.md) §2.1 |
| `tacctl server` | This server's own settings: an overview, its console name, the address devices and hosts reach it at, listeners, the metrics exporter | [Server commands](https://github.com/rett/tacctl/blob/master/docs/cli/server.md) | [Superuser Daily Operations](superuser-daily-operations.md) §11 |
| Exit codes, environment | — | [Exit status and environment](https://github.com/rett/tacctl/blob/master/docs/cli/exit-status.md) | [Exit Codes](exit-codes.md) |

---

## 2. Out of scope for this documentation

Installation, upgrades, backends, the store and server files are covered
only in the repository ([Backups and Undo](backups-and-undo.md) §5
summarises going back to an earlier release):

| Topic | Reference (repo) |
|---|---|
| Install, upgrade, roll back | [Installation and upgrades](https://github.com/rett/tacctl/blob/master/docs/install/README.md) |
| Backends, store, RADIUS, metrics | [Server](https://github.com/rett/tacctl/blob/master/docs/server/README.md) |
| Scopes, tiers, command authorization, audit log in depth | [Security](https://github.com/rett/tacctl/blob/master/docs/security/README.md) |

---

*See also:* [Quick Reference](quick-reference.md) · [Glossary](glossary.md) ·
`man tacctl`
