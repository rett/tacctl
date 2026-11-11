---
title: "Glossary"
description: "The words tacctl and this documentation use, in one list"
permalink: "/glossary/"
parent: "Reference"
nav_order: 3
doctype: explanation
---

# Glossary

*The words tacctl and this documentation use, in one list · Checked against tacctl 0.2.30*

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
| **Bench address** | The address a cloned device has before it replaces the original (`tacctl device clone --staging`). `device rename --replace` ends it. | [Engineer Guide](engineer-guide-device-changes.md) §2.5 |
| **Break-glass account** | A local emergency account on a device, recorded per scope with `tacctl scope breakglass`; on Junos it may be `root`. tacctl never stores its password. | [Break Glass](break-glass.md) §1 |
| **Break-glass firewall** | The nftables table `inet tacctl` that refuses the TCP connections of held addresses to the server, so a device that falls back only when the server is unreachable does fall back. Set with `tacctl config breakglass-firewall reject\|drop\|off`. | [Break Glass](break-glass.md) §2.1 |
| **Break-glass hold** | The server stops answering one device or host on purpose, so its local accounts work. Never expires. | [Break Glass](break-glass.md) |
| **Canary** | In one Junos apply run, the first device of each shape goes alone; the rest of its shape start only when it applied. If it fails, they are skipped (`skipped: canary <name> failed`) and, at the default `--max-failures` of 1, the run stops. It is about the order of a run, not about what was proved earlier (see Confirmed shape). | [Engineer Guide](engineer-guide-device-changes.md) §5.3 |
| **Chassis members** | The units of a Junos virtual chassis or a Cisco stack, recorded by a good `device config pull` (id, role, model, serial number, release, status, priority). `device show` prints them; the `members` report has a row for each (a read-only user sees none). | [Vendor Notes](vendor-notes.md) §2.5, §3.3 |
| **Client config** | An ssh configuration file (`tacctl device client-config`) that gives plain `ssh` and `scp` the registry's pinned host keys. | [Connecting to Devices](connecting-to-devices.md) §3 |
| **Clone (device)** | `tacctl device clone`: register a copy of a device at a bench address, then move it into place with `device rename --replace`. | [Engineer Guide](engineer-guide-device-changes.md) §2.5 |
| **Configured / unconfigured** | A registered device is configured when a scope's prefixes cover its address. Only configured devices authenticate users. | [Concepts](concepts.md) §4 |
| **Confirmed shape** | A shape that an earlier apply has proved on one device (committed, a fresh login as you worked, what landed is what the check showed). `apply --confirmed` applies only confirmed shapes; a shape nobody has proved is `new`. See also Seeded shape. | [Engineer Guide](engineer-guide-device-changes.md) §5.3 |
| **Console (login console)** | The login shell of every tacctl user on the tacctl server: tacctl commands and ssh to devices, and SFTP for the accounts that have file transfer; nothing else. | [Getting Started](getting-started.md) §1 |
| **Converge** | `device config plan --converge`: after the first paste is verified, also remove statements outside the standard (old servers and similar). | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Diff** | What differs between a device's last pull and what tacctl renders, section by section. | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| **Drift** | Two uses: a device whose configuration differs from the standard (`device config list --differs`), and a rendered server file edited by hand (`DRIFT`, exit status 3). | [Exit Codes](exit-codes.md) |
| **Emergency lockdown** | The server refuses the logins of chosen groups on a scope. Superusers keep access. Never expires. | [Emergency Lockdown](emergency-lockdown.md) |
| **Enroll (device)** | `tacctl device enroll`: one attended run from a new address to its plan: key, vendor, registration, pull, plan. | [Engineer Guide](engineer-guide-device-changes.md) §2.2 |
| **Enroll (host)** | `tacctl host enroll`: install TACACS+ or RADIUS login on a Linux host and register it. | [Linux Host Operations](linux-host-operations.md) §3 |
| **Extras** | Statements in a managed section that tacctl does not render. Reported, left alone until `--converge`. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **File transfer (console)** | SFTP served by the login console, for `sftp` and the `scp` of OpenSSH 9 or later, rooted in the user's home, with a quota and an optional rate. Off for every tier but the superuser tier until a superuser runs `tacctl console file-transfer`. | [Getting Started](getting-started.md) §1.4, [Superuser Daily Operations](superuser-daily-operations.md) §10.3 |
| **Group** | Decides *what* a user can do: device privilege and tacctl tier. | [Concepts](concepts.md) §2 |
| **Host key / pin** | The device's ssh host key. tacctl pins it at registration, and ssh accepts only the pinned key. | [Connecting to Devices](connecting-to-devices.md) §5 |
| **Host sync** | `tacctl host sync`: push user changes to enrolled Linux hosts. Nothing reaches a host without it. | [Linux Host Operations](linux-host-operations.md) §2 |
| **Kept snapshot** | A snapshot copied by `tacctl backup keep` to a place no retention reaches. A rollback keeps the one that holds what it dropped. | [Backups and Undo](backups-and-undo.md) §4.2 |
| **Legacy ssh** | A device setting for old IOS that offers only SHA-1 key exchange, CBC ciphers and `ssh-rsa`. Separate from the configuration syntax. | [Vendor Notes](vendor-notes.md) §2.4 |
| **Managed sections** | The parts of a device's configuration tacctl compares: `aaa`, `roles`, `mgmt-acl`, `snmp`, `netconf`, `breakglass`, and in some scopes `system`. | [Concepts](concepts.md) §6 |
| **Managed server login** | The login of every user to the tacctl server and its console: the reserved scope `tacctl`, this server's registry entry, the PAM client and sshd's drop-in. `install` and `upgrade` set it up; `host enroll --local` rebuilds or repairs it. | [Superuser Daily Operations](superuser-daily-operations.md) §11.1 |
| **Notice** | A flag on a device or host that needs attention, with the command that fixes it. `tacctl device notice list`. | [Concepts](concepts.md) §5 |
| **Onboard** | `tacctl device onboard`: bring a blank Junos device in through one of its local accounts. | [Engineer Guide](engineer-guide-device-changes.md) §2.3 |
| **Password cache** | Keeps your network password in locked memory for the session. A superuser allows it per tier; each user turns it on with `console password-cache on`. With it on, `ssh` asks for the password the first time and keeps it. | [Getting Started](getting-started.md) §1.3 |
| **Pending host** | An enrolled host the sshd lockdown drop-in has not reached (or not yet removed from): unreachable, held or refused. `emergency lockdown status` lists it; `host sync` completes it. | [Emergency Lockdown](emergency-lockdown.md) §3.1 |
| **`PENDING`** | A Junos apply whose state could not be read after the commit. Type nothing on the device until the time shown (the device's own clock) passes. | [Vendor Notes](vendor-notes.md) §3.2 |
| **Plan** | The exact fix for a device: report, the region between `PASTE FROM HERE` and `PASTE TO HERE`, checks and back-out. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Pool (SNMPv3 users)** | The SNMPv3 users of a level (the server, a scope or a device), with one default user. A device reads with its own default, else its scope's, else the server's. | [Superuser Daily Operations](superuser-daily-operations.md) §4.10 |
| **Pull** | Log in to a device as you and read its managed sections. Read only. | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| **Reason** | Free text given with `--reason` on lockdowns and holds. Logged as typed: never put a secret in it. | [Audit and Compliance](audit-and-compliance.md) §6 |
| **Recover** | `tacctl backup recover`: put back only the email addresses or SNMPv3 users that a rollback dropped, from a snapshot, without restoring anything else. | [Backups and Undo](backups-and-undo.md) §4.3 |
| **Registry** | The list of devices (and hosts) by name, with address, vendor and pinned keys. | [Concepts](concepts.md) §4 |
| **Report (device report)** | A saved, dated document about the devices of your scopes, made from what tacctl stores and kept as a file in your home (`~/reports/devices/`): `tacctl device reports generate`. As text, CSV, JSON or PDF (`--format pdf` needs `weasyprint`). A superuser reaches other users' reports, and every access is audited; the size and the number of a user's reports are limited. | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6, [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| **Required password change** | A user must change the password before logging in to anything but the tacctl server. Set by `user add` and a superuser's `user passwd` by default; never binds a superuser. | [Access Lifecycle](access-lifecycle.md) §5.1 |
| **Restore point** | Cisco: a copy of the configuration on flash, added before a plan's region with `--restore-point=flash:`. | [Vendor Notes](vendor-notes.md) §2.5 |
| **Scope** | Client address prefixes plus a shared secret. Decides *where* a user can log in. | [Concepts](concepts.md) §3 |
| **Secret (shared secret)** | The TACACS+ or RADIUS key between a scope's devices and the server. Every print writes a `secret-read` audit line. | [Concepts](concepts.md) §3 |
| **Seeded shape** | A shape a superuser filed as confirmed on their word, for a device that was applied and verified by hand: `tacctl device config shapes seed <name>`. It allows what a confirmed shape allows and is logged. | [Engineer Guide](engineer-guide-device-changes.md) §5.3 |
| **Server address** | The address devices and hosts reach this server at: the setting `server.addresses`, shown and changed by `tacctl server addresses`. It is the default of `--server`. | [Superuser Daily Operations](superuser-daily-operations.md) §11.2 |
| **Severity** | A plan's rating of each problem: `ACCESS`, `MONITORING` or `COSMETIC`. | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **Shape** | The same change on several devices: a 12-hex id of the statements `plan` would type, with secrets removed and per-device values (location, contact, host name) masked. Devices that need the same change share a shape; the review shows it once per shape. It is `new`, `confirmed` or `seeded`. | [Engineer Guide](engineer-guide-device-changes.md) §5.2 |
| **`sid`** | The session id that ends every audit line of one command run, so `grep sid=<id>` finds them all. | [Audit and Compliance](audit-and-compliance.md) §2 |
| **Snapshot** | A copy of tacctl's configuration taken before every change. `tacctl backup list`. | [Backups and Undo](backups-and-undo.md) |
| **Status (user)** | Enabled or disabled: decides *whether* a user can log in. | [Access Lifecycle](access-lifecycle.md) |
| **System shell** | A user's own shell on the tacctl server, started with the console word `system-shell`. Superusers always; read-only and operator users when a superuser opens it; engineers never. | [Superuser Daily Operations](superuser-daily-operations.md) §10.1 |
| **Template user** | Junos: the local account a TACACS+ user logs in through. Must exist before TACACS+ logins work. | [Vendor Notes](vendor-notes.md) §3.1 |
| **Tier** | The level of tacctl access a group gives: read-only < operator < engineer < superuser. | [Concepts](concepts.md) §2 |
| **Timing scale** | A whole number from 1 to 10 that multiplies the network timings tacctl uses to reach a device, for a slow or distant one. Set for a device, a scope or the server; 1 changes nothing. | [Connecting to Devices](connecting-to-devices.md) §7 |

---

*See also:* [Concepts](concepts.md) · [Command Reference Map](command-reference-map.md) ·
`man tacctl`
