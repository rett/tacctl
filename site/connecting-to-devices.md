---
title: "Connecting to Devices"
description: "tacctl ssh by name, plain ssh with pinned keys, and what to do when a connection is refused"
permalink: "/connecting-to-devices/"
parent: "Tasks"
nav_order: 1
doctype: how-to
---

# Connecting to Devices

*tacctl ssh by name, plain ssh with pinned keys, and what to do when a connection is refused · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-connecting-to-devices.pdf){: .pdf-link }

Every tacctl user can open an ssh session to the devices and hosts of their
own scopes by name. This page covers connecting, using plain `ssh` and
`scp` with the same pinned host keys, and the refusals you may meet,
including the one that matters most: a changed host key.

> **Example names used on this page**
> Server: `tacacs.example.net` · Scopes: `site-a`, `site-b` · Devices: `sw1`
> (Cisco), `rtr1` (Junos), `sw7` (IOS 12.4) · Host: `web1` ·
> You: `alice`

---

## 1. Find the device

```bash
tacctl device list                      # the devices and hosts of your scopes
tacctl device list core                 # a bare word matches name, address, vendor or scope
tacctl device list --scope site-a --vendor juniper
tacctl device show sw1                  # one device in full: scope, state, last seen, keys
```

A device must be **configured** (a scope covers its address) for anyone to
log in to it.

---

## 2. Connect with `tacctl ssh`

```bash
tacctl ssh sw1                           # interactive session, as you
tacctl ssh rtr1 -- show chassis alarms   # one remote command, then back
tacctl ssh 10.10.0.1                     # by registered address
```

In the console or `tacctl shell`, type just `ssh sw1`. `exit` on the
device brings you back.

How the login works:

- ssh runs **as you**, with your own tacctl username and password. No
  agent, no key, no other login. As root it refuses.
- Only an active tacctl user whose scopes include the device's scope may
  connect, at every tier. A refusal is logged (`ssh DENY`).
- ssh accepts only the host keys pinned for that device in the registry.
- It needs a terminal.

**Many logins in a row?** Start the shell with the password cache, where
your tier is allowed it, and type your password once per session:

```text
tacctl shell --password-cache
tacctl> ssh sw1
tacctl> ssh rtr1
tacctl> console forget          # drop the cached password now
```

---

## 3. Plain `ssh` and `scp`

To use your own `ssh` and `scp` with the same options and the same pinned
keys:

```bash
tacctl device client-config > ~/.ssh/tacctl.conf
# then put   Include ~/.ssh/tacctl.conf   at the top of ~/.ssh/config
ssh sw1
```

- The file has one `Host` block per device you may see.
- It has no `User` line, so ssh logs in with your **local** username. If
  your local account has another name than your tacctl user, add
  `User <tacctl name>` to your own `~/.ssh/config`.
- Run it again whenever the registry changes.

---

## 4. When ssh refuses

| Message or situation | What it means | What to do | Who |
|---|---|---|---|
| Device not found | Not registered, or not in your scopes | Check `tacctl device list`. Ask an engineer to register it, or a superuser to grant the scope. | E / S |
| Device `unconfigured` | No scope covers its address | A superuser adds the prefix to a scope | S |
| **Pinned and offered fingerprints printed** | The device's host key changed: replaced, reset, upgraded, or something is wrong | **Stop.** Follow §5. Never bypass the pin. | E |
| Unpinned device refused for a pull | No key is pinned | Check the key on the console, then `tacctl device hostkey <name> accept` | E |
| Warning that break-glass is held | The server is deliberately not answering this device | Your tacctl login will fail there. `tacctl device show <name>` says who holds it and why. | — |
| Red `EMERGENCY LOCKDOWN` line | Your group is locked out of the scope | Expected during an incident. Contact the superuser named in the line. | — |
| Refused as root | ssh always runs as you | Run it from your own account | — |
| Old IOS: ssh negotiation fails | The device offers only legacy algorithms | `tacctl device legacy-ssh <name> enable` | E |
| Password refused | Wrong password, disabled account, or missing scope | [Troubleshooting](troubleshooting.md) §2 | O |
| `device check` says unreachable | The server has no route to the management port (may be a false alarm) | Test from your workstation too | O |

---

## 5. A host key changed

`tacctl ssh` and pulls refuse a device whose key no longer matches its pin,
and print the pinned and offered fingerprints. A `hostkey-changed` notice
is raised, and it cannot be acknowledged away.

**1. Assume it is hostile until you have checked it.** Was the device
replaced, reset or upgraded? Check the change record.

**2. Read the key on the device's console**, not over the network:

| Device | Console command |
|---|---|
| Cisco | `show ip ssh` |
| Junos | `file show /etc/ssh/ssh_host_ed25519_key.pub` |
| Linux | `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` |

**3. Only if it matches, re-pin** (engineer for your own scopes, or
superuser):

```bash
tacctl device hostkey sw1                    # show the pinned fingerprints
tacctl device hostkey sw1 set SHA256:<fp>    # pin exactly the key you verified (preferred)
tacctl device hostkey sw1 accept             # or: re-scan and pin every offered key (confirms)
```

**4. If it does not match**, treat it as a possible interception. Don't
connect, and escalate to security
([Incident Response Runbooks](incident-response-runbooks.md) R6).

Operators: report a changed key to an engineer. Do not try to fix it.

---

## 6. Keys are pinned when a device is registered

`device add`, `device enroll` and `device onboard` pin the device's host
keys when they register it, and show the fingerprints with the console
command that displays them. **Compare them with the console before you
trust them.** `enroll` and `onboard` ask you to accept the key by typing the
device's name back. The registration steps are in
[Engineer Guide: Device Changes](engineer-guide-device-changes.md) §2.

---

## 7. Quick reference

| Task | Command | Who |
|---|---|---|
| Find a device | `tacctl device list <text>` | Everyone |
| Connect | `tacctl ssh <name>` | Everyone (own scopes) |
| One command | `tacctl ssh <name> -- <command>` | Everyone |
| Plain ssh config | `tacctl device client-config > ~/.ssh/tacctl.conf` | Everyone |
| Show pinned keys | `tacctl device hostkey <name>` | Engineer |
| Re-pin a verified key | `tacctl device hostkey <name> set SHA256:<fp>` | Engineer |
| Legacy IOS ssh | `tacctl device legacy-ssh <name> enable` | Engineer |

---

*See also:* [Operator Field Guide](operator-field-guide.md) ·
[Troubleshooting](troubleshooting.md) ·
[Host-key pinning (repo)](https://github.com/rett/tacctl/blob/master/docs/security/host-key-pinning.md) ·
`man tacctl`
