---
title: "Home"
description: "The tacctl operations documentation: where to start, by role and by situation"
nav_order: 1
permalink: "/"
doctype: reference
---

# Home

*The tacctl operations documentation: where to start, by role and by situation · Checked against tacctl 0.2.20*

[Printable PDF](pdf/tacctl-home.pdf){: .pdf-link }

tacctl keeps the users, groups and scopes of your network-device logins in
one place and serves them over TACACS+ (and RADIUS, where enabled) to Cisco
IOS/IOS-XE, Juniper Junos, WTI console servers and Linux hosts. This
documentation covers **using** tacctl during a shift: connecting to devices,
managing access, changing device AAA configuration, and handling incidents.

Installation, upgrades and server internals are in the
[repository documentation](https://github.com/rett/tacctl/blob/master/docs/README.md).
Every command and setting is in `man tacctl` on the server.

---

## 1. Where to start

| You are… | Start with | Then |
|---|---|---|
| New to tacctl | [Getting Started](getting-started.md) | [Concepts](concepts.md), [Quick Reference](quick-reference.md) |
| NOC, help desk, tier 1–2 (read-only or operator tier) | [Operator Field Guide](operator-field-guide.md) | [Day-to-Day Device Operations](day-to-day-device-operations.md) |
| Engineer | [Engineer Guide: Device Changes](engineer-guide-device-changes.md) | [Vendor Notes](vendor-notes.md) |
| Superuser | [Superuser Daily Operations](superuser-daily-operations.md) | [Access Lifecycle](access-lifecycle.md), [Linux Host Operations](linux-host-operations.md) |
| Security or compliance | [Audit and Compliance](audit-and-compliance.md) | [Incident Response Runbooks](incident-response-runbooks.md) |

## 2. Something is happening now

| Situation | Go to |
|---|---|
| A user can't log in, a device won't connect, a pull fails | [Troubleshooting](troubleshooting.md) |
| `tacctl ssh` refuses or warns about a host key | [Connecting to Devices](connecting-to-devices.md) |
| Credentials leaked, account compromised, secret exposed | [Incident Response Runbooks](incident-response-runbooks.md) |
| A group must be locked out of a scope **now** | [Emergency Lockdown](emergency-lockdown.md) |
| A device or host is locked out after a bad change | [Break Glass](break-glass.md) |
| A tacctl change made things worse | [Backups and Undo](backups-and-undo.md) |

## 3. All pages

| Section | Pages |
|---|---|
| Start here | [Getting Started](getting-started.md) · [Concepts](concepts.md) · [Quick Reference](quick-reference.md) |
| Guides by role | [Operator Field Guide](operator-field-guide.md) · [Day-to-Day Device Operations](day-to-day-device-operations.md) · [Engineer Guide: Device Changes](engineer-guide-device-changes.md) · [Superuser Daily Operations](superuser-daily-operations.md) |
| Tasks | [Connecting to Devices](connecting-to-devices.md) · [Access Lifecycle](access-lifecycle.md) · [Linux Host Operations](linux-host-operations.md) · [Vendor Notes](vendor-notes.md) · [Backups and Undo](backups-and-undo.md) · [Audit and Compliance](audit-and-compliance.md) |
| Emergencies and problems | [Troubleshooting](troubleshooting.md) · [Incident Response Runbooks](incident-response-runbooks.md) · [Emergency Lockdown](emergency-lockdown.md) · [Break Glass](break-glass.md) |
| Reference | [Command Reference Map](command-reference-map.md) · [Exit Codes](exit-codes.md) · [Glossary](glossary.md) · [What's New for Operators](whats-new-for-operators.md) |
| About | [About These Docs](about-these-docs.md) |

---

*See also:* [About These Docs](about-these-docs.md) for the example names, the
release each page was checked against, and how to report a mistake.
