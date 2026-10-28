---
title: "Glossary"
description: "The words tacctl and this documentation use, in one list"
permalink: "/glossary/"
parent: "Reference"
nav_order: 3
doctype: explanation
---

# Glossary

*The words tacctl and this documentation use, in one list · Checked against tacctl 0.2.20*

[Printable PDF](../pdf/tacctl-glossary.pdf){: .pdf-link }

Terms are in alphabetical order. Each entry points to the page that
explains it in full.

---

| Term | Meaning | More |
|---|---|---|
| **Accounting** | The server's record of commands run on devices. `tacctl log accounting` shows it. | [Audit and Compliance](audit-and-compliance.md) |
| **Apply** | Junos only: tacctl commits a plan under `commit confirmed`, proves it with a fresh login as you, then confirms. | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| **Audit line** | A syslog line (tags `tacctl`, `tacctl-console`) that tacctl writes for every change and refusal: who, what, result, snapshot. | [Audit and Compliance](audit-and-compliance.md) |
| **Back-out** | The lines that undo a plan's paste. `tacctl device config plan <name> --backout` prints them. | [Engineer Guide](engineer-guide-device-changes.md) §7 |
| **Break-glass account** | A local emergency account on a device, recorded per scope with `tacctl scope breakglass`; on Junos it may be `root`. tacctl never stores its password. | [Break Glass](break-glass.md) §1 |
| **Break-glass hold** | The server stops answering one device or host on purpose, so its local accounts work. Never expires. | [Break Glass](break-glass.md) |
| **Canary** | During a Junos apply, the first device of each new shape goes alone before the others. | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| **Client config** | An ssh configuration file (`tacctl device client-config`) that gives plain `ssh` and `scp` the registry's pinned host keys. | [Connecting to Devices](connecting-to-devices.md) §3 |
| **Configured / unconfigured** | A registered device is configured when a scope's prefixes cover its address. Only configured devices authenticate users. | [Concepts](concepts.md) §4 |
| **Console (login console)** | The login shell of every tacctl user on the tacctl server: tacctl commands and ssh to devices, nothing else. | [Getting Started](getting-started.md) §1 |
| **Converge** | `device config plan --converge`: after the first paste is verified, also remove statements outside the standard (old servers and similar). | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Diff** | What differs between a device's last pull and what tacctl renders, section by section. | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| **Drift** | Two uses: a device whose configuration differs from the standard (`device config list --differs`), and a rendered server file edited by hand (`DRIFT`, exit status 3). | [Exit Codes](exit-codes.md) |
| **Emergency lockdown** | The server refuses the logins of chosen groups on a scope. Superusers keep access. Never expires. | [Emergency Lockdown](emergency-lockdown.md) |
| **Enroll (device)** | `tacctl device enroll`: one attended run from a new address to its plan: key, vendor, registration, pull, plan. | [Engineer Guide](engineer-guide-device-changes.md) §2.2 |
| **Enroll (host)** | `tacctl host enroll`: install TACACS+ or RADIUS login on a Linux host and register it. | [Linux Host Operations](linux-host-operations.md) §3 |
| **Extras** | Statements in a managed section that tacctl does not render. Reported, left alone until `--converge`. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Group** | Decides *what* a user can do: device privilege and tacctl tier. | [Concepts](concepts.md) §2 |
| **Host key / pin** | The device's ssh host key. tacctl pins it at registration, and ssh accepts only the pinned key. | [Connecting to Devices](connecting-to-devices.md) §5 |
| **Host sync** | `tacctl host sync`: push user changes to enrolled Linux hosts. Nothing reaches a host without it. | [Linux Host Operations](linux-host-operations.md) §2 |
| **Legacy ssh** | A device setting for old IOS that offers only SHA-1 key exchange, CBC ciphers and `ssh-rsa`. Separate from the configuration syntax. | [Vendor Notes](vendor-notes.md) §2.4 |
| **Managed sections** | The parts of a device's configuration tacctl compares: `aaa`, `roles`, `mgmt-acl`, `snmp`, `netconf`, `breakglass`, and in some scopes `system`. | [Concepts](concepts.md) §6 |
| **Notice** | A flag on a device or host that needs attention, with the command that fixes it. `tacctl device notice list`. | [Concepts](concepts.md) §5 |
| **Onboard** | `tacctl device onboard`: bring a blank Junos device in through one of its local accounts. | [Engineer Guide](engineer-guide-device-changes.md) §2.3 |
| **Password cache** | Keeps your network password in locked memory for the session. A superuser allows it per tier; each user turns it on with `console password-cache on`. | [Getting Started](getting-started.md) §1.3 |
| **`PENDING`** | A Junos apply whose state could not be read after the commit. Type nothing on the device until the time shown (the device's own clock) passes. | [Vendor Notes](vendor-notes.md) §3.2 |
| **Plan** | The exact fix for a device: report, the region between `PASTE FROM HERE` and `PASTE TO HERE`, checks and back-out. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Pull** | Log in to a device as you and read its managed sections. Read only. | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| **Required password change** | A user must change the password before logging in to anything but the tacctl server. Set by `user add` and a superuser's `user passwd` by default; never binds a superuser. | [Access Lifecycle](access-lifecycle.md) §5.1 |
| **Reason** | Free text given with `--reason` on lockdowns and holds. Logged as typed: never put a secret in it. | [Audit and Compliance](audit-and-compliance.md) §6 |
| **Registry** | The list of devices (and hosts) by name, with address, vendor and pinned keys. | [Concepts](concepts.md) §4 |
| **Restore point** | Cisco: a copy of the configuration on flash, added before a plan's region with `--restore-point=flash:`. | [Vendor Notes](vendor-notes.md) §2.5 |
| **Scope** | Client address prefixes plus a shared secret. Decides *where* a user can log in. | [Concepts](concepts.md) §3 |
| **Secret (shared secret)** | The TACACS+ or RADIUS key between a scope's devices and the server. Every print writes a `secret-read` audit line. | [Concepts](concepts.md) §3 |
| **Severity** | A plan's rating of each problem: `ACCESS`, `MONITORING` or `COSMETIC`. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Shape** | A set of devices that need the same change. A Junos apply groups its review by shape. | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| **`sid`** | The session id that ends every audit line of one command run, so `grep sid=<id>` finds them all. | [Audit and Compliance](audit-and-compliance.md) §2 |
| **Snapshot** | A copy of tacctl's configuration taken before every change. `tacctl backup list`. | [Backups and Undo](backups-and-undo.md) |
| **Status (user)** | Enabled or disabled: decides *whether* a user can log in. | [Access Lifecycle](access-lifecycle.md) |
| **Template user** | Junos: the local account a TACACS+ user logs in through. Must exist before TACACS+ logins work. | [Vendor Notes](vendor-notes.md) §3.1 |
| **System shell** | A user's own shell on the tacctl server, started with the console word `system-shell`. Superusers always; read-only and operator users when a superuser opens it; engineers never. | [Superuser Daily Operations](superuser-daily-operations.md) §10.1 |
| **Tier** | The level of tacctl access a group gives: read-only < operator < engineer < superuser. | [Concepts](concepts.md) §2 |

---

*See also:* [Concepts](concepts.md) · [Command Reference Map](command-reference-map.md) ·
`man tacctl`
