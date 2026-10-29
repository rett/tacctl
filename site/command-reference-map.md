---
title: "Command Reference Map"
description: "From each tacctl command family to its reference page and the task page that uses it"
permalink: "/command-reference-map/"
parent: "Reference"
nav_order: 1
doctype: reference
---

# Command Reference Map

*From each tacctl command family to its reference page and the task page that uses it · Checked against tacctl 0.2.22*

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
| `tacctl console` | The login console and its settings: system shell, password cache, colour, list length | [Console commands](https://github.com/rett/tacctl/blob/master/docs/cli/console.md) | [Getting Started](getting-started.md), [Superuser Daily Operations](superuser-daily-operations.md) §10 |
| `tacctl user` | Users, passwords, scope membership | [User commands](https://github.com/rett/tacctl/blob/master/docs/cli/user.md) | [Access Lifecycle](access-lifecycle.md) |
| `tacctl group` | Groups, privilege levels, tiers, Junos classes | [Group commands](https://github.com/rett/tacctl/blob/master/docs/cli/group.md) | [Concepts](concepts.md) |
| `tacctl scope` | Prefixes, shared secrets, break-glass accounts, per-scope settings | [Scope commands](https://github.com/rett/tacctl/blob/master/docs/cli/scope.md) | [Superuser Daily Operations](superuser-daily-operations.md) §8, [Break Glass](break-glass.md) |
| `tacctl device` | Registry, notices, host keys, pull, diff, plan, apply, enroll, onboard | [Device commands](https://github.com/rett/tacctl/blob/master/docs/cli/device.md) | [Engineer Guide: Device Changes](engineer-guide-device-changes.md), [Connecting to Devices](connecting-to-devices.md) |
| `tacctl host` | Linux hosts: enroll, sync, check, move, unenroll | [Host commands](https://github.com/rett/tacctl/blob/master/docs/cli/host.md) | [Linux Host Operations](linux-host-operations.md) |
| `tacctl breakglass` | Holding and releasing devices and hosts | [Break-glass commands](https://github.com/rett/tacctl/blob/master/docs/cli/breakglass.md) | [Break Glass](break-glass.md) |
| `tacctl emergency` | Emergency lockdown | [Emergency commands](https://github.com/rett/tacctl/blob/master/docs/cli/emergency.md) | [Emergency Lockdown](emergency-lockdown.md) |
| `tacctl log` | Authentication logs, failures, accounting | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | [Superuser Daily Operations](superuser-daily-operations.md) §9, [Troubleshooting](troubleshooting.md) |
| `tacctl backup` | Snapshots, diff, restore | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | [Backups and Undo](backups-and-undo.md) |
| `tacctl backend`, `store` | Backends and the store | [Maintenance commands](https://github.com/rett/tacctl/blob/master/docs/cli/maintenance.md) | Out of scope for this documentation |
| `tacctl config` | Settings and the device configuration walkthroughs | [Config commands](https://github.com/rett/tacctl/blob/master/docs/cli/config.md), [tacctl.yaml settings](https://github.com/rett/tacctl/blob/master/docs/cli/tunables.md) | [Vendor Notes](vendor-notes.md) |
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
