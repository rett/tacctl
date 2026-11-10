---
title: "Day-to-Day Device Operations"
description: "A console-first guide for operators and engineers"
permalink: "/day-to-day-device-operations/"
parent: "Guides by role"
nav_order: 2
doctype: how-to
---

# Day-to-Day Device Operations

*A console-first guide for operators and engineers · Checked against tacctl 0.2.29*

[Printable PDF](../pdf/tacctl-day-to-day-device-operations.pdf){: .pdf-link }

A quick guide to the tacctl tasks that operators and engineers do every
day, all from the tacctl console. **Section 1** is for operators and
engineers. **Section 2** is for engineers only. For superuser tasks, see
[Superuser Daily Operations](superuser-daily-operations.md).

> **Example names used on this page**
> Server: `tacacs.example.net` · Scope: `site-a` · Devices: `sw1`, `sw2`,
> `sw3` (Cisco), `rtr1`, `rtr2`, `jsw1` (Junos), `pdu1` (WTI) ·
> You: `alice`

> **Read-only users:** you can use the console, `device list`,
> `device show`, `device notice list`, `device reports` (your own), `ssh`
> and `passwd`. The checks, logs and drift views in Section 1 need the
> **operator** tier. In the console, `help` lists exactly what your role can
> run.

---

## 0. The tacctl console

Log in to the tacctl server with ssh (`ssh alice@tacacs.example.net`). You
land at the console prompt, `tacacs>`. Type commands **without** the
`tacctl` prefix. `Tab` completes, `?` (or `--help` after a command) shows
what comes next, `help` lists what your tier can run, `man <command>` opens
the manual page there, `passwd` changes your password and `exit` leaves.
[Getting Started](getting-started.md) §1 covers the console in full.

---

## 1. Operators and engineers

### 1.1 Find a device

```bash
device list                      # every device in your scopes
device list core                 # anything matching "core" (name, address, vendor or scope)
device list --scope site-a       # one site or scope
device list --vendor juniper
device list --probe              # (operator) add REACH: does each device answer on ssh right now
device show sw1                  # full details for one device
```

For a Junos virtual chassis or a Cisco stack, `device show` (operator tier
and up) also prints a `Chassis members:` table under the data block: id,
role, model, serial number, release, status and priority of each member, as
the last `device config pull` read them. A device has none until it has been
pulled again since 0.2.26 ([Vendor Notes](vendor-notes.md) §2.5, §3.3).

### 1.2 Connect to a device

```bash
ssh sw1                          # interactive session
ssh sw1 -- show version          # run one command and come back
ssh rtr1 -- show interfaces terse
```

You are logged in as yourself. `exit` on the device brings you back to the
console.

If ssh prints a **pinned and an offered fingerprint** and refuses, the host
key has changed. Do not work around it: see
[Connecting to Devices](connecting-to-devices.md) §5.

### 1.3 Check a device that isn't behaving (operator)

```bash
device check sw1        # scope, last seen, reachable, host key vs. pin, SNMP name/location/vendor
device check sw1 --sources   # also test the addresses the device sends AAA from
device notice list      # open issues, each with the command that fixes it
```

`device check` connects from the tacctl server. If the server has no route
to the device's management port, a timeout may be a false alarm.

With `--sources`, `device check` also connects to each address the device
sends its AAA requests from (other than its registered address) and compares
its ssh host key with the pinned one, without logging in. A warning that an
address is unreachable (it may be by design) or presents another host key goes
to an engineer ([Engineer Guide](engineer-guide-device-changes.md) §3.1).

### 1.4 Look at authentication logs (operator)

```bash
log failures               # failed logins in the last 24 hours
log search alice           # one user's (or a keyword's) entries; TACACS+: last 7 days
log tail 50                # the 50 most recent entries
log tail -f                # follow live; Ctrl-C to stop
log accounting 50          # the 50 most recent accounting records (commands run on devices)
```

**Narrow it down (0.2.24).** `log tail`, `log search`, `log failures` and
`log accounting` take filters that combine (an entry must pass all of them),
in any place on the line:

```bash
log failures --since -1h                      # failed logins in the last hour
log search alice --since yesterday --until today
log accounting 20 --user alice --device sw1   # alice's last 20 records on sw1
log accounting --type change --since "2026-11-04 08:00"
log accounting 50 --json                      # one JSON object per line, for jq
```

| Filter | Shows |
|---|---|
| `--since <time>`, `--until <time>` | Entries from, and up to, that time |
| `--user <name>` | Entries of that user, as the log writes the name |
| `--device <name or address>` | Entries of that device or enrolled host (of your scopes), or of an address |
| `--type login\|change\|command` | Accounting only: one kind of record |
| `--json` | One JSON object per entry, no headings |

- A time is `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` or `YYYY-MM-DD HH:MM:SS` (local
  time), `now`, `today`, `yesterday`, or an offset such as `-1h`, `-30m` or
  `2 days ago`. Any other form is a usage error, as is a `--since` later than
  the `--until`.
- The filters apply before a count: `log accounting 5 --user alice` is
  alice's last five records. `log tail -f` applies them to new entries.
- A name that is neither a device nor a host you may see is refused. A log
  that names no device shows nothing for `--device` and says so. A filter that
  leaves nothing prints `No matching entries.`
- Each accounting record now names the device that sent it
  (`"Device":"sw1"`; the address when the device is not registered), and
  `<`, `>` and `&` show as typed. Records written before 0.2.24 have no
  `Device`.
- Operators pass the filters through sudo, `log failures` included.

**Example:** a user reports "I can't log in to sw2".

1. Run `log search <user>`.
2. Match the log line:

| Log line | Meaning |
|---|---|
| `failed to validate the user …` | Wrong password |
| `bad secret detected for ip …` | The device's TACACS+ key is wrong. Hand it to an engineer. |
| No line at all | The request never reached the server. Hand it to an engineer. |

### 1.5 See which devices have configuration drift (operator)

```bash
device config list --differs     # devices whose last pull differs from the standard
device list --differs            # the same devices, in the device table
device config list --failed      # devices whose last pull failed
device config list --never       # devices never read
```

Report these to an engineer.

### 1.6 Make a report of your devices

A report is a saved, dated document about the devices of your scopes. It is
made from what tacctl already stores (the registry and the records of the
last pulls), so no device is contacted and no password is asked. Nothing
makes a report by itself, and no report holds a secret, a hash or a
community string. Every tier can make, read and remove **its own** reports.

```bash
device reports generate --type inventory             # saved in your home
device reports generate --type members --format csv  # one row per chassis member
device reports generate --type software --scope site-a
device reports generate --type config --stdout       # print it, store nothing
device reports generate --type inventory --format pdf   # a PDF (needs weasyprint)
device reports list                                  # your reports, newest first
device reports show inventory-20261106 --content     # who, when, the first 200 lines
device reports export inventory-20261106             # print all of it
```

| Type | One row per | Columns |
|---|---|---|
| `inventory` | device | name, address, vendor, scope, model, serial number, release, number of chassis members, location, description, date of the pull |
| `members` | chassis member | device, member id, role, model, serial number, release, status, priority, date of the pull |
| `software` | device | name, vendor, model, release, date of the pull |
| `config` | device | name, scope, state (as `device config list` shows it), date of the pull, date of the last apply |

- **Check the dates before you hand a report on.** Every row carries the date
  of the pull its facts came from, and the heading gives the date of the
  oldest datum. There is no warning for old data: the dates are the
  information. A device that was never pulled is a row with empty facts and
  `never`, not a gap; only `members` leaves it out (it lists the devices that
  have a model or a serial number, and a device that is no chassis is one row).
- `--format text` (the default) is aligned columns, `csv` follows RFC 4180,
  `pdf` is a document to hand on (below) and `json` is one object with `schema`, `type`, `generated`, `oldest_data`,
  `filters`, `columns` and `rows`. A CSV cell that starts with `=`, `+`, `-` or `@` gets
  a leading `'`, so that a spreadsheet shows it and does not run it.
- `--scope` (one of yours) and `--vendor cisco|juniper|wti|other` narrow the
  report and combine. A selection that matches nothing writes a report with
  no rows, after a warning. A superuser's report holds every device.
- A **read-only** user's report follows the rule of `device show`, which
  shows the model, serial number, release and chassis members, the
  configuration state and the date of the last apply from the operator tier
  up. In a read-only user's `inventory` report the `model`, `serial` and
  `release` of every row are empty (`-` in text, an empty cell in CSV, `""` in
  JSON) and `members` is `-` (`0` in JSON); in `software` the `model` and
  `release` are empty; the `members` report has no rows; and `state` and
  `applied` of `config` are `-` (`null` in JSON). The name, address, vendor,
  scope, location, description and the date of the pull stay. A report a
  read-only user made with 0.2.26 keeps what it holds.
- **Engineers** can add `--pull`, which reads the devices first as `device
  config pull` does, with your own password
  ([Engineer Guide](engineer-guide-device-changes.md) §3.2).

**Where the report goes.** The file is
`~/reports/devices/<type>-<yyyymmdd>.<txt|csv|json|pdf>` in your home on the
tacctl server (the directory 0700, the file 0600, made as you), and the first
report creates the directory. A second report of the same type on the same
day is `-2`, then `-3`; `--name <name>` chooses another name (letters,
digits, `.`, `_` and `-`). A name already in use is refused and nothing is
written. Beside each report lies a `.meta` file that records when, by whom,
the command line, the filters and the date of the oldest datum: leave it
alone. A file you put in the directory yourself is listed as `other`, and
`rename`, `remove` and `prune` leave it alone.

tacctl sends a report nowhere itself. `device reports show <report>` prints
the `scp` line that fetches it with your own login, and `export --out <file>`
writes a copy (an existing file needs `--force`). The file of `--out` must
be inside your home: tacctl expands neither `~` nor variables, and a path
outside the home, or one that leaves it through `..` or a link, is refused
before the report is read. The console serves that `scp` line (the `scp` of
OpenSSH 9 or later, which speaks SFTP) and `sftp`, only if file transfer is
enabled for you: it is off for every tier but the superuser tier until a
superuser switches it on for your tier or for you
([Superuser Daily Operations](superuser-daily-operations.md) §10.3). Without
it the line fails: `scp` and `sftp` show only `Connection closed`, and
`ssh alice@tacacs.example.net id` shows `file transfer is not enabled for this
account`. Ask a superuser, or use `export`, which prints a report or writes
it inside the home. `scp -O` and `rsync` are still refused
([Getting Started](getting-started.md) §1.4).

A user whose name has upper case letters or is longer than 32 characters has
no Linux account on the server, and so no home for a report: `generate` then
refuses and stores nothing, and `list`, `show`, `export`, `rename`, `remove`
and `prune` say the same. `--stdout` still prints, and a superuser's `tacctl
user rename` gives the user a name that can be an account.

**A PDF report.** `--format pdf` writes the report as a PDF with the
extension `.pdf`, to hand on or print:

- The page is letter landscape: a title block (the type, when the report was
  made in UTC, the filters and the date of the oldest datum), then the
  table in 8 pt type, with the header row repeated on every page, light
  stripes, no row split across two pages and a page counter. An empty cell
  is `-`.
- It needs `weasyprint` and the DejaVu fonts, which are optional:
  `sudo apt-get install -y weasyprint fonts-dejavu-core`. A superuser
  installs them (`tacctl upgrade` offers them once, see
  [Superuser Daily Operations](superuser-daily-operations.md) §4.11).
  Without them `generate --format pdf` refuses at once, before it reads a
  device or writes a file, with that line and exit status 1.
- A PDF is binary. `--stdout` and `export` refuse to print one to a terminal
  (`PDF is binary: use --out FILE or redirect`) and write the bytes when
  standard output is a file or a pipe (`device reports export
  inventory-20261106 > inventory.pdf` in a shell). `show --content` prints
  `binary PDF, <n> bytes: use export` instead of the first lines.
- A word of more than 24 characters may wrap after every 24: tacctl puts an
  invisible zero-width space there, so copying such a value out of the PDF
  can carry invisible characters. The text, CSV and JSON reports have none.
- A tool that fails, runs over its 120 seconds or makes no PDF gives an error
  with the first lines of its own and writes nothing: no file and no `.meta`.
  A very long report can run over the time; narrow it with `--scope` or
  `--vendor`.

**Looking after your reports:**

```bash
device reports rename inventory-20261106 inventory-before-move
device reports remove inventory-20261106 --yes
device reports prune --older-than 30d --dry-run      # what would go
device reports prune --older-than 30d                # asks once, then removes
```

- `prune --older-than` takes a whole number and `h`, `d` or `w` (`12h`,
  `30d`, `4w`); there is no default. The age is the `generated` date in the
  metadata file, not the time of the file. A file with no metadata is never
  removed. Nothing prunes by itself.
- `remove` and `prune` ask `Confirm removal? [y/N]` first; `--yes` answers it.
- `generate` refuses a report over the size limit (10 MiB by default) or one
  more than the count limit allows (100 by default), names the setting and
  writes nothing. Remove old reports, narrow the report with `--scope` or
  `--vendor`, or print it with `--stdout`; the limits are a superuser's
  ([Superuser Daily Operations](superuser-daily-operations.md) §4.11).
- Another user's reports are a superuser's to reach. Anyone else who names
  them is refused with `Nothing was done.`

---

## 2. Engineers

Everything here works on the devices of **your own scopes**. Other scopes'
devices are refused. Each task links to the step-by-step section of
[Engineer Guide: Device Changes](engineer-guide-device-changes.md).

### 2.1 Bring devices in

| Task | At the console | Details |
|---|---|---|
| Onboard a new address (the usual way) | `device enroll 10.10.0.5` | Engineer Guide §2.2 |
| Enroll every unregistered device that already logs in | `device discover`, then `device enroll --discovered` | Engineer Guide §2.2 |
| Register a device you know | `device add sw3 10.10.0.3 --vendor cisco --pull` | Engineer Guide §2.1 |
| Bring in a blank Junos device | `device onboard 10.10.0.31 --login admin --name jsw1 --check` | Engineer Guide §2.3 |
| Print the walkthrough to paste by hand | `device config show sw3` | Engineer Guide §4.1 |

> Every registration shows the device's ssh key fingerprint. **Compare it
> with the device's console** before you accept it
> ([Connecting to Devices](connecting-to-devices.md) §5).

### 2.2 The daily change routine

```bash
device config pull --scope site-a --diff     # read the scope, then show what differs
device config list --differs                 # which devices differ
device config diff sw2                       # what differs on one device, section by section
device config plan sw2                       # the fix: report, paste region, checks, back-out
device config apply rtr2 --check             # Junos: the device's own commit check; commits nothing
device config apply rtr2                     # Junos: type the name back, commit confirmed, proof
device config pull sw2 --diff                # after a Cisco paste: confirm the fix
```

How each vendor takes the fix:

| Vendor | You do | Details |
|---|---|---|
| Cisco | Paste the region by hand, with a second session open | Engineer Guide §5.5 |
| Junos | Let tacctl apply it under `commit confirmed` | Engineer Guide §5.1 |
| WTI | Type the menu checklist. No paste, no rollback. | Engineer Guide §5.6 |

For several Junos devices, check the scope first (`device config apply --scope
site-a --check`), apply one device to review and prove the change, then apply
the rest (Engineer Guide §5.1; what a shape and a canary are: §5.2 and §5.3).

> **`PENDING until <time>`** on a Junos apply means: **type nothing on that
> device until the time passes.** Any `commit` would confirm the change.

**If a change goes wrong:** `device config plan <name> --backout` prints the
back-out. If you are locked out completely, ask a superuser for a
break-glass hold ([Break Glass](break-glass.md)). `breakglass list` shows the
holds in your scopes.

---

## 3. Common problems

| Problem | What to do | Who |
|---|---|---|
| A device shows `unconfigured` | Its address isn't covered by a scope. Ask a superuser to add it. | Superuser |
| ssh says the host key changed | Check the key on the console, then pin the verified key: `device hostkey <name> set SHA256:<fp>` ([Connecting to Devices](connecting-to-devices.md) §5) | Engineer (own scopes) or superuser |
| You can't see a device | It is outside your scopes. Ask a superuser for access. | Superuser |
| A login is refused on a device | Run `log search <user>` and `log failures` (see §1.4). | Operator |
| `needs pull (syntax unknown)` on a Cisco device | Run `device ios-syntax <name> ios12` (IOS 12.x) or `modern`, then pull again. | Engineer |
| An old Cisco device won't connect | Run `device legacy-ssh <name> enable`. | Engineer |
| A pull fails with `timed out` | Check reachability with `device check <name>`. | Operator |
| A pull or ssh is refused: break-glass held | The server isn't answering that device on purpose. See `breakglass list`. | — |
| Apply says `failed: calls itself '<x>'` | The device's hostname doesn't match the registry. Check you have the right device. | Engineer |
| `device reports generate` names `reports.max_size` or `reports.max_count` and writes nothing | Your reports are over a limit. Remove old ones (`device reports prune`), narrow the report (`--scope`) or print it (`--stdout`). | Everyone; a superuser changes the limit |
| `generate --format pdf` says `PDF reports need weasyprint, which is not installed here` | The PDF tool is optional and is not on this server (or is not root's, or not in `/usr/bin`, `/usr/local/bin` or `/opt/weasyprint/bin`). Nothing was read or written. | A superuser: `sudo apt-get install -y weasyprint fonts-dejavu-core` |

---

## 4. Quick reference

| Task | Command | Who |
|---|---|---|
| Find a device | `device list <text>` | Everyone |
| Connect | `ssh <name>` | Everyone |
| Run one command | `ssh <name> -- <command>` | Everyone |
| Change password | `passwd` | Everyone |
| Health check | `device check <name>` | Operators |
| Failed logins | `log failures` / `log search <user>` | Operators |
| Devices with drift | `device config list --differs` | Operators |
| Report on your devices | `device reports generate --type inventory\|members\|software\|config` (`--format text\|csv\|json\|pdf`) | Everyone |
| Read or fetch a report | `device reports list` · `show <report>` · `export <report>` | Everyone |
| Remove old reports | `device reports prune --older-than 30d` | Everyone |
| Onboard a device | `device enroll <address>` | Engineers |
| Read configurations | `device config pull <name>` or `--scope <scope>` | Engineers |
| What differs | `device config diff <name>` | Engineers |
| How to fix it | `device config plan <name>` | Engineers |
| Fix it (Junos) | `device config apply <name>` | Engineers |
| Report on fresh data | `device reports generate --type <type> --pull` | Engineers |
| Back-out | `device config plan <name> --backout` | Engineers |

For more detail, type `help <command>`, `<command> --help` or
`man <command>` at the console.

---

*See also:* [Operator Field Guide](operator-field-guide.md) ·
[Engineer Guide: Device Changes](engineer-guide-device-changes.md) ·
[Troubleshooting](troubleshooting.md) · `man tacctl`
