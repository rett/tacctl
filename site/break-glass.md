---
title: "Break Glass"
description: "Local emergency accounts, and holding a device or host back from the server"
permalink: "/break-glass/"
parent: "Emergencies and problems"
nav_order: 4
---

# Break Glass

*Local emergency accounts, and holding a device or host back from the server · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-break-glass.pdf){: .pdf-link }

When a bad change cuts off AAA on a device, nobody can log in with their
tacctl credentials, and the server's refusals stop the device's local
accounts from working too. A **break-glass hold** makes the server stop
answering that one device or host, so its local accounts work while the
server stays up for everyone else. Placing and releasing holds is a
**superuser** task; engineers can list the holds in their own scopes.

> **Example names used on this page**
> Scope: `site-a` · Devices: `sw1` (Cisco), `rtr1` (Junos),
> `pdu1` (WTI) · Host: `web1` · Ticket `CHG-1182`

---

## 1. Before you need it: record the local accounts

Every device should keep a local emergency account for the day the server
can't help. Record which accounts each scope's devices keep, so the
walkthroughs include them and holds point to them:

```bash
tacctl scope breakglass site-a                       # list
tacctl scope breakglass site-a add netadmin          # role defaults to admin
tacctl scope breakglass site-a add noc-local --role operator
tacctl scope breakglass site-a remove noc-local
```

- tacctl **never stores** these passwords or hashes. You create, rotate and
  remove the account on the device yourself.
- `tacctl config validate` warns about scopes with no break-glass accounts:
  a lockout risk.

---

## 2. Hold

```bash
tacctl breakglass hold sw1 --reason "failed AAA paste, CHG-1182"
tacctl breakglass hold web1 --reason "CHG-1182 locked out of sudo"
tacctl breakglass hold "sw2=console recovery,sw3" --reason "CHG-1182 failed paste"
```

- You confirm by **typing the name back**. There is no `--yes`.
- The output shows the way in for the vendor and the local accounts that
  will now work.
- Several devices: a comma list, each with an optional `=reason`. Each
  device is checked on its own; the ones refused are named on a
  `Not held:` line.
- A hold is refused for a name that is not registered, already held, has
  no address, or that no scope covers.

> **Only the registered address is carved out.** If a device sends AAA
> from another address (a Cisco source interface, NAT, IPv6), the server
> still answers it. The hold report warns you when this looks likely.

---

## 3. Get in, by vendor

| Vendor | How to log in while held |
|---|---|
| Cisco IOS | ssh or console as the local account. The device waits a few seconds for the server, then accepts the local password. On the console, `enable` with the local enable secret. |
| Junos | ssh or console as a local `system login user`, after the tacplus timeout. `root` on the console is always local. |
| WTI | Works only if the unit's TACACS+ *Fallback Local* is `On`. With `Off`, nobody gets in until you release the hold; use the serial console. |
| Linux host | The host's local administrator and its console work. tacctl users cannot log in or use `sudo` there. |

The engineer can print the back-out for the failed change with
`tacctl device config plan sw1 --backout`.

---

## 4. While a device or host is held

- `tacctl breakglass list` shows what is held, since when, by whom and why.
- `device remove` and `device config pull` refuse a held device.
- `host sync`, `enroll`, `move`, `unenroll` and `forget` refuse a held host,
  and `host sync --all` skips it (and names it).
- `tacctl ssh` warns you and connects; your tacctl login will fail there.

---

## 5. Fix and release

```bash
tacctl breakglass release sw1
tacctl device config pull sw1 --diff       # confirm the fix
tacctl ssh sw1                             # and log in as yourself again
```

For a host: `tacctl breakglass release web1`, then `tacctl host check web1`.

> **A hold has no timer** and never releases itself. Check
> `tacctl breakglass list` at every shift start.

---

## 6. Quick reference

| Task | Command | Who |
|---|---|---|
| Record local accounts | `tacctl scope breakglass <scope> add <user> [--role <role>]` | Superuser |
| Hold | `tacctl breakglass hold <name> --reason "<ticket>"` | Superuser |
| List holds | `tacctl breakglass list` | Engineer (own scopes) |
| Release | `tacctl breakglass release <name>` | Superuser |
| Back-out for the failed change | `tacctl device config plan <name> --backout` | Engineer |

---

*See also:* [Incident Response Runbooks](incident-response-runbooks.md) R4, R5 ·
[Vendor Notes](vendor-notes.md) · [Emergency Lockdown](emergency-lockdown.md) ·
[Break-glass (repo)](https://github.com/rett/tacctl/blob/master/docs/devices/break-glass.md) ·
`man tacctl`
