---
title: "Vendor Notes"
description: "What differs between Cisco, Junos and WTI for operations staff"
permalink: "/vendor-notes/"
parent: "Tasks"
nav_order: 4
---

# Vendor Notes

*What differs between Cisco, Junos and WTI for operations staff · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-vendor-notes.pdf){: .pdf-link }

tacctl serves the same users to every vendor, but each vendor takes its
configuration, its privileges and its emergencies differently. This page
puts those differences side by side. The step-by-step procedures stay in
[Engineer Guide: Device Changes](engineer-guide-device-changes.md); this page
links to them.

> **Example names used on this page**
> Scope: `site-a` · Devices: `sw1` (Cisco IOS-XE), `sw7` (IOS
> 12.4), `rtr1` (Junos), `pdu1` (WTI)

---

## 1. At a glance

| | Cisco IOS / IOS-XE | Juniper Junos | WTI console servers |
|---|---|---|---|
| How a fix lands | You paste the plan's region | tacctl applies it (`device config apply`) | You type a menu checklist |
| Safety net | Second session; optional restore point; back-out region | `commit confirmed`, proven by a fresh login as you, rolled back if the proof fails | None: values take effect at once, no rollback |
| Groups map to | priv-lvl 1 / 7 / 15 | Classes `RO-CLASS`, `OP-CLASS`, `EN-CLASS`, `RW-CLASS` | ViewOnly / User / SuperUser / Administrator |
| `enable` | Local enable secret only | — | — |
| Host key on the console | `show ip ssh` | `file show /etc/ssh/ssh_host_ed25519_key.pub` | — |
| Break-glass login | Local account after the server timeout; console list is local | Local `system login user`; `root` on the console is always local | Only if *Fallback Local* is `On` |
| Steps | Engineer Guide §5.2 | Engineer Guide §5.1 | Engineer Guide §5.3 |

Junos is the only vendor tacctl writes to. For Cisco and WTI it reads,
compares and plans; a person makes the change.

---

## 2. Cisco IOS / IOS-XE

### 2.1 The standard block

Every Cisco device gets the same lines in the same order, so a pull can say
exactly what differs. The walkthrough and plans have:

- **Step 0**, a commented checklist (hostname, ssh settings, the local
  enable secret and similar). It is never compared.
- **Step 1**, the AAA standard, in an order that keeps the session you paste
  from alive.
- **The check, then Step 2**, command authorization.

### 2.2 Command authorization is held back on purpose

Until the device is proven to use the scope's server, plans leave out
`aaa authorization commands` and `config-commands`. Once a commands list
names the server, any user the server doesn't know (including the local
user your paste session runs as) is denied every command. Paste Step 1,
prove the path, **pull again**, and the next plan adds Step 2.

### 2.3 `enable` and the console

- `enable` always uses the **local** enable secret. Users land at their
  level directly (superuser 15, operator 7), so nobody needs `enable` day
  to day.
- The console line has its own login list, `CONSOLE`, which is local only.
  A local account can always log in there; with the server up it lands at
  privilege 1, and `enable` with the local enable secret takes it to 15.

### 2.4 ssh algorithms and configuration syntax are separate

| Setting | What it is | Command |
|---|---|---|
| `legacy-ssh` | The device offers only SHA-1 key exchange, CBC ciphers and `ssh-rsa` | `tacctl device legacy-ssh sw7 enable` |
| `ios-syntax` | Which Cisco syntax is compared: `modern` (IOS 15.2+, 16.x, 17.x, IOS-XE) or `ios12` (IOS 12.x) | `tacctl device ios-syntax sw7 ios12` |

With `auto` (the default), the version line of the last pull decides the
syntax. A device whose version line isn't mapped shows
`needs pull (syntax unknown)`: set `ios12` or `modern`, then pull again.
A new IOS 15.6 router may need `--legacy-ssh` and still speak `modern`.

### 2.5 Other Cisco points

- **Source interface.** A device may send AAA from another interface than
  its registered address. `tacctl config cisco source-interface <scope>`
  shows or pins it; the source address must be inside the scope's prefixes.
- **Restore point.** `tacctl device config plan sw1 --restore-point=flash:`
  adds a block to paste first; `configure replace` with that file backs out.
- **Vendor detection** by SNMP does not name IOS 12.x devices (or ASA and
  IOS XR). Register them with `--vendor cisco`.

---

## 3. Juniper Junos

### 3.1 Template users

Junos logs a TACACS+ user in through a local **template user** of the
group's class. **Template users must exist before TACACS+ logins work.**
If a login fails right after the server accepted it, the template user is
missing: create the template users from the walkthrough
(`tacctl config juniper`, or `tacctl device config show rtr1`).

### 3.2 Applying: `commit confirmed` and the proof

`tacctl device config apply` commits under `commit confirmed` (10 minutes
by default for an apply), logs in again **as you** through the device's own
login path, checks what landed, and only then confirms. If the proof fails,
the change rolls back by itself.

A pasted Junos plan region also ends in `commit confirmed` (5 minutes by
default); you type `commit` yourself after the check.

> **`PENDING until <time>`** means tacctl could not read the device after
> the commit. **Type nothing on that device until the time passes.** Any
> `commit` would confirm the change. The next apply or `--check` settles
> the record.

### 3.3 Other Junos points

| Situation | What to do |
|---|---|
| Apply `failed: other editors or staged changes` | Someone has uncommitted configuration on the device. Coordinate; commit or discard on the device. |
| `bad secret` continues on a Junos device after a re-paste | Delete the secret and set it again, to avoid hidden characters |
| A blank device with only a local account | `tacctl device onboard` (Engineer Guide §2.3) |
| Break-glass | A local `system login user` works after the tacplus timeout; `root` on the console is always local |

---

## 4. WTI console servers

### 4.1 A menu walkthrough, not a paste

WTI units are configured through numbered text menus on the serial SetUp
port. `tacctl config wti` and the plans give a walkthrough: `/N`, then the
**TACACS** entry, one value per item, then `[Esc]` until the unit saves.

A WTI plan is a **numbered checklist** of menu steps plus one IP-tables
block. Values take effect as soon as you enter them, and **there is no
rollback**. The plan never types the local accounts or the final IP-tables
`DROP`. Before you start:

- check `/H` (firmware) and `/SN` (other administrators logged in);
- keep a serial console or a second session open.

### 4.2 Levels

The unit asks for the `wti` service and reads the standard `priv-lvl`:

| priv-lvl | WTI access level | Shipped group |
|---|---|---|
| 0–4 | ViewOnly (only the ports granted under Default TACACS User Access) | `readonly` (1) |
| 5–9 | User (only the ports granted under Default TACACS User Access) | `operator` (7) |
| 10–14 | SuperUser (all ports and plugs) | a group with `wti-level superuser` |
| 15 | Administrator | `superuser` (15) |

### 4.3 Limits and settings that bite

| Item | Rule |
|---|---|
| Scope secret | At most 32 characters, no whitespace or punctuation. Regenerate a hex-only key with `tacctl scope secret site-a set $(openssl rand -hex 16)` (superuser). |
| Usernames | WTI's limit is 32 characters |
| Service Name | Must be `wti`, not `shell` |
| Fallback Local | Must be `On` for break-glass to work. With `Off`, nobody gets in until the hold is released. |
| Multiple Logins | `On`, or pulls and second sessions are refused |

WTI symptoms and fixes are in [Troubleshooting](troubleshooting.md) §6.

---

## 5. Break-glass by vendor

How to get into each vendor while the server is deliberately not answering
is in [Break Glass](break-glass.md) §3.

---

*See also:* [Engineer Guide: Device Changes](engineer-guide-device-changes.md) ·
[Troubleshooting](troubleshooting.md) ·
[Cisco](https://github.com/rett/tacctl/blob/master/docs/devices/cisco.md),
[Junos](https://github.com/rett/tacctl/blob/master/docs/devices/junos.md) and
[WTI](https://github.com/rett/tacctl/blob/master/docs/devices/wti.md) (repo) ·
`man tacctl`
