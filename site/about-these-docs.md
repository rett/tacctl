---
title: "About These Docs"
description: "What this documentation covers, how it relates to the repository docs, and the conventions it follows"
permalink: "/about-these-docs/"
nav_order: 7
doctype: explanation
---

# About These Docs

*What this documentation covers, how it relates to the repository docs, and the conventions it follows · Checked against tacctl 0.2.21*

[Printable PDF](../pdf/tacctl-about-these-docs.pdf){: .pdf-link }

This documentation is the **operations** layer of tacctl: how to do things
during a shift. It is written for network engineers, operators and support
staff.

---

## 1. What is here, and what is not

| Here (this documentation) | In the repository docs |
|---|---|
| Task guides by role: operators, engineers, superusers | Installation, upgrades and rolling back |
| Procedures: connecting, access lifecycle, device changes, hosts, undo | Backends, the store, generated files, RADIUS and metrics |
| Emergencies: troubleshooting, runbooks, lockdown, break-glass | Every command and flag, every `tacctl.yaml` setting |
| Concepts, a glossary, exit codes, operator release notes | Design plans and development notes |

The [repository documentation](https://github.com/rett/tacctl/blob/master/docs/README.md)
and `man tacctl` are updated in the same change as the code, so they are the
reference. When this documentation and the reference disagree, **the
reference wins**: please report the difference.

---

## 2. Which release a page describes

Every page says, under its title, which tacctl release it was checked
against (for example *Checked against tacctl 0.2.21*). The footer shows
the release for the documentation as a whole. Run `tacctl version` on your
server to see which release you have.
[What's New for Operators](whats-new-for-operators.md) lists what changed
between releases.

---

## 3. Conventions

| Convention | Meaning |
|---|---|
| `tacctl …` commands | The full form, for a normal shell. In the login console or `tacctl shell`, leave out `tacctl`. |
| Console-first pages | [Day-to-Day Device Operations](day-to-day-device-operations.md) shows commands without the prefix, as typed at the console |
| **Tier** or **Who** column | The lowest tier that can run a command: R read-only, O operator, E engineer (own scopes), S superuser |
| `--dry-run`, `--check` first | Every risky command is shown with its preview first |
| `--reason "<ticket>"` | Lockdowns and holds always carry a ticket number |
| Numbered sections | Cite a section as *Page §4.2* |
| Yellow callouts | Warnings and gotchas |

### 3.1 Example names

All examples use made-up names from the
[examples table](https://github.com/rett/tacctl/blob/master/docs/development/README.md#examples)
of the tacctl repository, so no example points to a real network. Names
the table does not list are invented in the same style.

| Kind | Names |
|---|---|
| Server | `tacacs.example.net` (its console prompt is `tacacs>`) |
| Scopes | `lab`, `site-a`, `site-b` |
| Cisco devices | `sw1`, `sw2`, `sw3`, `sw7` (legacy IOS 12.4) |
| Junos devices | `rtr1`, `rtr2`, `jsw1` (blank switch, onboarded) |
| WTI | `pdu1` |
| Linux hosts | `web1`, `db1`, `db2` |
| Users | `alice`, `bob`, `carol`, `dave`; each name keeps one role on a page |
| Addresses | `10.10.0.0/16` (`site-a`), `10.10.0.1` (`sw1`), `10.10.0.2` (`rtr1`), `10.10.0.50` (`pdu1`) |
| Tickets | `INC-4821`, `CHG-1182` |

---

## 4. Reporting a mistake

If a page is wrong or out of date, use **Report a problem with this page**
at the foot of the page: it opens a GitHub issue with the page already
named. Or open an issue on the
[tacctl repository](https://github.com/rett/tacctl/issues) naming the page,
the section and the tacctl release you run.

---

## 5. Printable PDFs

Every page links its PDF under the title. All of them:

| Page | PDF |
|---|---|
| [Home](index.md) | [tacctl-home.pdf](../pdf/tacctl-home.pdf) |
| [Getting Started](getting-started.md) | [tacctl-getting-started.pdf](../pdf/tacctl-getting-started.pdf) |
| [Concepts](concepts.md) | [tacctl-concepts.pdf](../pdf/tacctl-concepts.pdf) |
| [Quick Reference](quick-reference.md) | [tacctl-quick-reference.pdf](../pdf/tacctl-quick-reference.pdf) |
| [Operator Field Guide](operator-field-guide.md) | [tacctl-operator-field-guide.pdf](../pdf/tacctl-operator-field-guide.pdf) |
| [Day-to-Day Device Operations](day-to-day-device-operations.md) | [tacctl-day-to-day-device-operations.pdf](../pdf/tacctl-day-to-day-device-operations.pdf) |
| [Engineer Guide: Device Changes](engineer-guide-device-changes.md) | [tacctl-engineer-guide-device-changes.pdf](../pdf/tacctl-engineer-guide-device-changes.pdf) |
| [Superuser Daily Operations](superuser-daily-operations.md) | [tacctl-superuser-daily-operations.pdf](../pdf/tacctl-superuser-daily-operations.pdf) |
| [Connecting to Devices](connecting-to-devices.md) | [tacctl-connecting-to-devices.pdf](../pdf/tacctl-connecting-to-devices.pdf) |
| [Access Lifecycle](access-lifecycle.md) | [tacctl-access-lifecycle.pdf](../pdf/tacctl-access-lifecycle.pdf) |
| [Linux Host Operations](linux-host-operations.md) | [tacctl-linux-host-operations.pdf](../pdf/tacctl-linux-host-operations.pdf) |
| [Vendor Notes](vendor-notes.md) | [tacctl-vendor-notes.pdf](../pdf/tacctl-vendor-notes.pdf) |
| [Backups and Undo](backups-and-undo.md) | [tacctl-backups-and-undo.pdf](../pdf/tacctl-backups-and-undo.pdf) |
| [Audit and Compliance](audit-and-compliance.md) | [tacctl-audit-and-compliance.pdf](../pdf/tacctl-audit-and-compliance.pdf) |
| [Troubleshooting](troubleshooting.md) | [tacctl-troubleshooting.pdf](../pdf/tacctl-troubleshooting.pdf) |
| [Incident Response Runbooks](incident-response-runbooks.md) | [tacctl-incident-response-runbooks.pdf](../pdf/tacctl-incident-response-runbooks.pdf) |
| [Emergency Lockdown](emergency-lockdown.md) | [tacctl-emergency-lockdown.pdf](../pdf/tacctl-emergency-lockdown.pdf) |
| [Break Glass](break-glass.md) | [tacctl-break-glass.pdf](../pdf/tacctl-break-glass.pdf) |
| [Command Reference Map](command-reference-map.md) | [tacctl-command-reference-map.pdf](../pdf/tacctl-command-reference-map.pdf) |
| [Exit Codes](exit-codes.md) | [tacctl-exit-codes.pdf](../pdf/tacctl-exit-codes.pdf) |
| [Glossary](glossary.md) | [tacctl-glossary.pdf](../pdf/tacctl-glossary.pdf) |
| [What's New for Operators](whats-new-for-operators.md) | [tacctl-whats-new-for-operators.pdf](../pdf/tacctl-whats-new-for-operators.pdf) |
| [About These Docs](about-these-docs.md) | [tacctl-about-these-docs.pdf](../pdf/tacctl-about-these-docs.pdf) |

---

*See also:* [Home](index.md) · [Command Reference Map](command-reference-map.md) ·
[Glossary](glossary.md)
