---
title: "Getting Started"
description: "Your first login, the console and the shell, and where to go next"
permalink: "/getting-started/"
parent: "Start here"
nav_order: 1
doctype: tutorial
---

# Getting Started

*Your first login, the console and the shell, and where to go next · Checked against tacctl 0.2.19*

[Printable PDF](../pdf/tacctl-getting-started.pdf){: .pdf-link }

This page gets a new operator, engineer or support person working with
tacctl: how to get on, what your tier lets you do, the first commands to
run, and the conventions every command follows.

> **Example names used on this page**
> Server: `tacacs.example.net` · Scope: `site-a` · Devices: `sw1` (Cisco),
> `rtr1` (Junos) · You: `alice`

---

## 1. Get on

### 1.1 The login console

Log in to the tacctl server with ssh. Your login usually lands in the
**tacctl console**:

```text
$ ssh alice@tacacs.example.net
tacctl console on tacacs — type 'help'. Devices: device list. This session is logged.
tacacs>
```

At the console prompt, type commands **without** the `tacctl` prefix, for
example `device list` or `ssh sw1`.

| Key or command | What it does |
|---|---|
| `Tab` | Completes commands and names (devices, users, scopes) |
| `?` | Shows what can come next, and the tier a command needs |
| `help` / `help <command>` | Lists the commands **your tier** can run / one command's usage |
| `passwd` | Changes your own password (asks for the current one first) |
| `console forget` | Drops your cached password now, where your site caches it |
| `exit` | Leaves the console |

What the console does not do:

- It runs tacctl commands and ssh to registered devices, nothing else.
  `scp`, `sftp`, `rsync` and other programs are refused.
- An idle session ends after a set time (30 minutes by default).
- Every session is logged.

To run a single line without opening the console:

```bash
ssh alice@tacacs.example.net 'device list'      # one tacctl line, no terminal needed
```

### 1.2 The tacctl shell

If you have a normal shell on the server, `tacctl shell` gives you the same
kind of prompt (`tacctl>`), with Tab completion and `?` help:

```bash
tacctl shell                    # interactive prompt; leave out the word "tacctl"
tacctl shell --password-cache   # type your network password once for this session
tacctl shell -c 'device list'   # run one line and exit
```

Each line runs through `sudo`, so it is logged and checked against your tier
exactly as it would be from bash. The rest of this documentation shows the full
`tacctl …` form; in the console or the shell, leave out `tacctl`.

### 1.3 The password cache

When you run many device logins in a row (a pull of a whole scope, then a
few `ssh` sessions), the password cache saves retyping. Your password stays
in the session's locked memory and is never written to disk. It works only
if a superuser has allowed it for your tier
(`tacctl console password-cache tiers`). `console forget` clears it.

---

## 2. Your password

```bash
tacctl passwd          # asks for your current password, then the new one twice
```

One tacctl password covers every device and host in your scopes, over
TACACS+ and RADIUS. Any user at any tier can change their own.

Forgotten it? A superuser resets it with `tacctl user passwd <you>`. If you
would rather they never see your new password, create a bcrypt hash
yourself (`tacctl hash commands` prints the recipes for Linux, macOS and
Windows) and send them only the hash.

---

## 3. What your tier allows

Your tacctl **group** sets your **tier**. Tiers, lowest to highest:

| Tier | Typical person | Can do (in short) |
|---|---|---|
| Read-only | Monitoring, help desk | Lists and shows, `ssh` to devices in your scopes, `status`, `passwd` |
| Operator | NOC, tier 1–2 | Read-only plus logs, `config validate`, `device check`, `scan`, `discover`, drift views, `backup list` |
| Engineer | Change engineers | Operator plus device registry and device configuration work **in your own scopes** |
| Superuser | Platform owners | Everything: users, groups, scopes, hosts, lockdowns, break-glass, restores |

In the console and the shell, Tab, `?` and `help` show only what your tier
can run. [Concepts](concepts.md) explains groups, scopes and tiers in full.

---

## 4. First commands

```bash
tacctl status                # is the server healthy?
tacctl device list           # the devices of your scopes
tacctl device show sw1       # one device in full: scope, state, last seen
tacctl ssh sw1               # log in to it, as you
tacctl device notice list    # open notices, each with the command that fixes it
```

Operators can add the first-line checks:

```bash
tacctl log failures            # authentication failures in the last 24 hours
tacctl config validate         # configuration problems; each warning names its fix
```

---

## 5. Conventions every command follows

| Pattern | Meaning |
|---|---|
| A command family with no arguments | Prints its usage (`tacctl device`, `tacctl user`) |
| `add` / `remove` with `a,b,c` | Comma lists are accepted. Every item is checked first; one bad item cancels the whole command. |
| `clear`, `remove --all` | Always ask `[y/N]` and say what the result will be |
| A setter with no value | Prints the current value (`tacctl device location sw1`) |
| `--dry-run`, `--check` | Show what would change and write nothing. Use them before every risky command. |
| Names | Lower case: letters, digits, `_`, `-` (devices and hosts may also use `.`) |
| Secrets | Let the command prompt for them, or use `--hash -` / `--stdin`. Never type a secret on the command line. |

Every change takes a snapshot first and writes an audit line, so a mistake
can be rolled back ([Backups and Undo](backups-and-undo.md)).

---

## 6. Where to go next

| You are… | Read |
|---|---|
| NOC, help desk, support | [Operator Field Guide](operator-field-guide.md) |
| Operator or engineer working from the console | [Day-to-Day Device Operations](day-to-day-device-operations.md) |
| Engineer | [Engineer Guide: Device Changes](engineer-guide-device-changes.md) |
| Superuser | [Superuser Daily Operations](superuser-daily-operations.md) |

Keep the [Quick Reference](quick-reference.md) open while you work.

---

*See also:* [Concepts](concepts.md) · [Connecting to Devices](connecting-to-devices.md) ·
[Glossary](glossary.md) · `man tacctl`
