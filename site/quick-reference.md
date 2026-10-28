---
title: "Quick Reference"
description: "The most common tacctl commands on one card"
permalink: "/quick-reference/"
parent: "Start here"
nav_order: 3
doctype: reference
---

# Quick Reference

*The most common tacctl commands on one card · Checked against tacctl 0.2.20*

[Printable PDF](../pdf/tacctl-quick-reference.pdf){: .pdf-link }

The most common tacctl commands on one card. The **Tier** column gives the
lowest tier that can run each one: R read-only · O operator · E engineer
(own scopes) · S superuser. Run any command family with no arguments for its
usage. In the console and `tacctl shell`, `?` shows help.

---

## 1. Everyday

| Task | Command | Tier |
|---|---|---|
| Interactive prompt | `tacctl shell` (`--password-cache`) | R |
| Change own password | `tacctl passwd` | R |
| Server health | `tacctl status` | R |
| Find problems | `tacctl config validate` | O |
| Help | `tacctl <command> --help` · `tacctl man [<topic>]` | R |
| Password cache (your own choice) | `console password-cache on\|off` (console word) | O |

## 2. Devices

| Task | Command | Tier |
|---|---|---|
| List / filter | `tacctl device list [--scope s] [--vendor v] [--stale]` | R |
| Detail | `tacctl device show <n>` | R |
| Connect | `tacctl ssh <n> [-- <cmd>]` | R |
| Notices | `tacctl device notice list` | R |
| Health check | `tacctl device check <n>` | O |
| Unregistered | `tacctl device discover [--snmp]` | O |
| Register | `tacctl device add <n> <ip> --vendor cisco\|juniper\|wti [--pull]` | E |
| Enroll discovered | `tacctl device enroll --discovered` | E |
| Edit field | `tacctl device address\|description\|location <n> <value>` | E |
| Rename / remove | `tacctl device rename <old> <new>` · `device remove <n>` | E |
| Re-pin key | `tacctl device hostkey <n> set SHA256:<fp>` | E |
| Drift state | `tacctl device config list [--differs]` | O |
| Read config | `tacctl device config pull <n>\|--scope s` | E |
| Diff / plan | `tacctl device config diff <n>` · `device config plan <n>` | E |
| Junos apply | `tacctl device config apply <n> [--check]` | E |
| Back-out | `tacctl device config plan <n> --backout` | E |

## 3. Users

| Task | Command | Tier |
|---|---|---|
| List / detail | `tacctl user list` · `user show <n>` | R |
| Add | `tacctl user add <n> <group> --scopes <s,…>` | S |
| Password reset | `tacctl user passwd <n>` | S |
| Require / lift a password change | `tacctl user require-password-change <n> [on\|off]` | S |
| Scopes | `tacctl user scope <n> add\|remove\|replace <s,…>` | S |
| Change group | `tacctl user move <n> <group>` | S |
| Suspend / restore | `tacctl user disable\|enable <n>` | S |
| Remove | `tacctl user remove <n>` | S |

## 4. Linux hosts

| Task | Command | Tier |
|---|---|---|
| List / detail | `tacctl host list` · `host show <n>` | E |
| Check | `tacctl host check --all` | S |
| Push accounts | `tacctl host sync --all` | S |
| Enroll | `tacctl host enroll <user>@<host> --scope <s>` | S |
| Move / retire | `tacctl host move <n> <s>` · `host unenroll <n>` | S |

## 5. Scopes

| Task | Command | Tier |
|---|---|---|
| List | `tacctl scope list` | R |
| First-match order | `tacctl scope routing` | S |
| Who owns an IP | `tacctl scope lookup <ip>` | S |
| Prefixes | `tacctl scope prefixes <s> add\|remove <cidr>` | S |
| Rotate secret | `tacctl scope secret <s> generate` | S |
| Break-glass accounts | `tacctl scope breakglass <s> add <user>` | S |
| Junos filter mode: show | `tacctl scope mgmt-acl <s> mode` | E |
| Junos filter mode: set | `tacctl scope mgmt-acl <s> mode ssh-only\|strict` | S |

## 6. Emergencies

| Task | Command | Tier |
|---|---|---|
| Preview lockdown | `tacctl emergency lockdown <s> enable --dry-run` | S |
| Lock down | `tacctl emergency lockdown <s> enable [groups] --reason "…"` | S |
| Status | `tacctl emergency lockdown status` | S |
| Lift | `tacctl emergency lockdown <s> disable` | S |
| Hold device/host | `tacctl breakglass hold <n> --reason "…"` | S |
| Release | `tacctl breakglass release <n>` | S |
| List holds | `tacctl breakglass list` | E |

## 7. Logs and recovery

| Task | Command | Tier |
|---|---|---|
| Live | `tacctl log tail -f` | O |
| Search | `tacctl log search <term>` | O |
| Failures (24 h) | `tacctl log failures` | O |
| Accounting | `tacctl log accounting [n]` | O |
| Snapshots | `tacctl backup list` | O |
| Diff / restore | `tacctl backup diff [ts]` · `backup restore <ts>` | S |
| Audit trail | `journalctl -t tacctl -t tacctl-console` | — |

## 8. Exit codes

`0` ok · `1` refused/failed · `2` wrong arguments or a change is needed
(`--exit-code`) · `3` refused to overwrite a hand edit · `130` interrupted.
Details: [Exit Codes](exit-codes.md).

---

*See also:* [Getting Started](getting-started.md) ·
[Command Reference Map](command-reference-map.md) · [Glossary](glossary.md) ·
`man tacctl`
