---
title: "What's New for Operators"
description: "The changes in each tacctl release that people on shift will notice"
permalink: "/whats-new-for-operators/"
parent: "Reference"
nav_order: 4
doctype: reference
commands: historical
---

# What's New for Operators

*The changes in each tacctl release that people on shift will notice · Checked against tacctl 0.2.30*

[Printable PDF](../pdf/tacctl-whats-new-for-operators.pdf){: .pdf-link }

Release notes describe every change in depth. This page lists only what
changes day-to-day work: renamed commands, new commands and changed
behavior. Each release links to its full notes. The newest release comes
first.

> **Scripts break on renames.** tacctl does not keep aliases for renamed
> commands. Check your scripts against every release you skip.

---

## 1. tacctl 0.2.30

Released 2026-11-10 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.30.md)

| Change | What it means on shift | Page |
|---|---|---|
| **A new user name starts with a letter** | `user add` and the new name of `user rename` take a lower-case letter, then lower-case letters, digits, `_` and `-`, at most 32 characters. A first character that is a digit, `-` or `_` is refused (`Username '1alice' must start with a letter (a to z) ...`) and nothing is changed, so that every new user has a Linux account. The first check that fails is the answer, and a name with upper case is told its lower-case spelling only when that spelling is accepted. Users that exist as `9dave`, `_svc` or `-x` keep working | [Access Lifecycle](access-lifecycle.md) §2, [Troubleshooting](troubleshooting.md) §8 |
| **`config validate` and `--fix-names` follow the rule** | `config validate` warns once per user whose name starts with a digit or `-` (no Linux account) under `Names:` and names `tacctl user rename <name> <new-name>`; a name that starts with `_` has an account and gets no warning. `--fix-names` never offers a rename that `user rename` would refuse: for `1Alice` or a name over 32 characters it offers nothing, and the run exits 0 | [Access Lifecycle](access-lifecycle.md) §2 |
| **A home on an NFS `root_squash` export** | `device config plan --out`, `device reports export --out` and `device support-bundle` check the path as you, so they work in a home that others may not search. A `cannot be resolved` refusal gives the cause and the path and no longer says to spell the path differently (the `~` hint). `config render --dry-run` and `config linux script` and `remove-script` still check the path as root: write the file on the local disk of the host and copy it to your home as yourself | [Superuser Daily Operations](superuser-daily-operations.md) §11.4, [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **`scp -p` creates the file with its mode** | The console reads the permissions of the open request, so a script uploaded at 0755 is created 0700 (the umask is 077) and not 0600, and an interrupted upload leaves that mode. The mode and times set at the end are applied as given: the file still ends with the mode of its source. A request without permissions still gives 0600 | [Getting Started](getting-started.md) §1.4 |
| `tacctl rollback 0.2.29` | The release before this one is a target (sixteen in all). It converts nothing: no key or field removed, no snapshot, no `--yes`, no closing note | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.29:**
>
> - `tacctl upgrade` converts nothing in this release. A user whose name
>   starts with a digit or `-` is carried unchanged; `tacctl config validate`
>   lists it, and `tacctl user rename <name> <new-name>` gives it an
>   account.
> - After `tacctl rollback 0.2.29` and the install of 0.2.29, `user add` and
>   `user rename` take a new name that starts with a digit, `-` or `_` again,
>   the three commands above check the path as root again, and a file
>   uploaded with `scp -p` is created 0600 again; what was done in between
>   keeps its name and its mode.

---

## 2. tacctl 0.2.29

Released 2026-11-09 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.29.md)

| Change | What it means on shift | Page |
|---|---|---|
| **An uploaded script keeps its execute bit** | A new file uploaded through the console gets the mode the client asks for, less the umask 077: a script at 0755 is 0700, a file at 0644 is 0600. A client that asks no mode still gets 0600, and a new directory is 0700. `scp -p` keeps the mode of the source (0755). A file that already exists keeps its mode | [Getting Started](getting-started.md) §1.4 |
| **`tacctl ssh <device> --login <local-user>`** | A session as one of the device's own accounts (also `device ssh`, and `ssh sw1 --login admin` in the console): the way in while break-glass is held. Engineer tier and up, registered devices in your scopes only (a host is refused), and the device needs a pinned host key. The device asks for the account's password; tacctl never asks for it or caches it. The audit lines carry `login=<local-user>` | [Connecting to Devices](connecting-to-devices.md) §2, [Break Glass](break-glass.md) §3 |
| **A new user name is at most 32 characters** | `user add` and the new name of `user rename` refuse a longer one (`Username '<name>' is 33 characters; a user name is at most 32 ...`) and change nothing. A longer name from an earlier release keeps working but has no Linux account; `config validate` warns of it under `Names:` and names the rename | [Access Lifecycle](access-lifecycle.md) §2, [Troubleshooting](troubleshooting.md) §8 |
| `tacctl rollback 0.2.28` | The release before this one is a target (fifteen in all). It converts nothing: no key or field removed, no snapshot, no `--yes`, no closing note | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.28:**
>
> - `tacctl upgrade` converts nothing in this release. A user whose name is
>   longer than 32 characters is carried unchanged; `tacctl config validate`
>   lists it, and `tacctl user rename <name> <shorter name>` gives it an
>   account.
> - After `tacctl rollback 0.2.28` and the install of 0.2.28, a new uploaded
>   file is 0600 again whatever the client asks; the files uploaded in
>   between keep their mode.

---

## 3. tacctl 0.2.28

Released 2026-11-09 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.28.md)

| Change | What it means on shift | Page |
|---|---|---|
| **The console serves file transfer (SFTP)** | `sftp alice@tacacs.example.net` and the `scp` of OpenSSH 9 or later (which speaks SFTP) work for an account that has file transfer, as that user, with the file system's permissions. `scp -O`, `rsync`, programs and shell words are still refused. It is **off for every tier but the superuser tier**, which always has it | [Getting Started](getting-started.md) §1.4, [Superuser Daily Operations](superuser-daily-operations.md) §10.3 |
| **A superuser decides who has it** | `console file-transfer <tier> enable\|disable` and `console file-transfer user <name> enable\|disable\|clear`, a user's setting over the tier's in both directions, as for `console system-shell`. Unlike the system shell, the engineer tier is not closed to it. **Every form of the verb is the superuser's, the reads included**; `console show` (operator tier and up) lists each user's state, quota and rate | [Superuser Daily Operations](superuser-daily-operations.md) §10.3, [Concepts](concepts.md) §2 |
| **A quota on the home, and an optional rate** | The whole home may hold 256M for the read-only, operator and engineer tiers and nothing is limited for the superuser tier until set: `console file-transfer quota <tier> <size>\|unlimited\|default` and `quota user <name> <size>\|unlimited\|clear`. The rate (bytes a second a transfer may go at) is off: `rate <tier> <size>\|off`, `rate user <name> <size>\|off\|clear`. A size is `512K`, `256M`, `2G` (powers of 1024, at most `1T`). A transfer at its rate waits | [Superuser Daily Operations](superuser-daily-operations.md) §10.3 |
| **The home is the root** | The user's home is `/` and `..` does not leave it. `.ssh` is invisible and refused. No symbolic link is followed or made, no hard link is made, and a file with more than one name cannot be opened or changed. The reports and support bundles are in the home, so a user can fetch them | [Getting Started](getting-started.md) §1.4 |
| **New files are 0600, new directories 0700** | The console's umask is 077, so a file uploaded with `scp` has **no executable bit**; set another mode afterwards (`chmod` in `sftp`) | [Getting Started](getting-started.md) §1.4 |
| **What the clients show when a transfer is refused** | Over the quota they show only `Failure` (what was written before stays); an account without file transfer sees only `Connection closed`. `ssh alice@tacacs.example.net id` prints the reason, and the audit log has it (`reason=quota`, `reason=file-transfer`) | [Troubleshooting](troubleshooting.md) §8, [Audit and Compliance](audit-and-compliance.md) §3 |
| **sshd must define `Subsystem sftp ...`** | The stock `sshd_config` of Debian and Ubuntu does; a `Match` block cannot. `console show` and `console file-transfer` print `sshd sftp subsystem: <program>` or `none` and warn in red when file transfer is on for anyone but a superuser and sshd has none. `/proc` must be mounted | [Superuser Daily Operations](superuser-daily-operations.md) §10.3 |
| **Every transfer is audited** | `console sftp start`, a line for each upload, download, delete, rename, mkdir and setstat with the tier and the path, `console sftp DENY ... reason=` for each refusal, `console sftp end`; a refused subsystem is `console DENY ... reason=file-transfer`. A change of the settings is `console set key=file-transfer` | [Audit and Compliance](audit-and-compliance.md) §3 |
| **The `scp` line of `device reports show` works where file transfer is enabled** | In 0.2.27 the console refused it. Now the account that has file transfer fetches a report with it (`scp alice@tacacs.example.net:reports/devices/inventory-20261106.csv .`); without file transfer the client shows `Connection closed` | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| A Cisco IOS support bundle no longer starts with the tail of a command | When a Cisco 2811 cut its display of a long command, the file of that command began with a line of `$` and the rest of the command before the `hostname` line. That tail is dropped now, like the rest of the echo | [Engineer Guide](engineer-guide-device-changes.md) §2.6 |
| `tacctl rollback 0.2.27` | The release before this one is a target (fourteen in all). It converts nothing but the file transfer settings of `console.yaml`, which every target removes (after a snapshot, with no `--yes`) because no older release reads the key | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.27:**
>
> - `tacctl upgrade` converts nothing in this release. File transfer is off
>   for every tier but the superuser tier after the upgrade, so nothing
>   changes for a user until a superuser runs `tacctl console file-transfer`;
>   superusers have it at once, with no quota. Existing reports, bundles and
>   settings are read as they were.
> - Before you switch it on for others, check that sshd defines `Subsystem
>   sftp ...` and that `/proc` is mounted (`tacctl console show` checks the
>   first). Files uploaded with `scp` are 0600 and not executable.
> - A script that relied on `scp` being refused by the console has to be
>   looked at: with file transfer on for the account, `sftp` and the `scp` of
>   OpenSSH 9 or later now work; `scp -O` and `rsync` stay refused.
> - After `tacctl rollback 0.2.27` and the install of 0.2.27, the file
>   transfer settings are gone (0.2.27 cannot read them): set them again
>   after the next upgrade. Until the older release is installed, run no
>   `tacctl console file-transfer` that sets something. The snapshot the
>   rollback took holds the 0.2.28 state, which only 0.2.28 restores.

---

## 4. tacctl 0.2.27

Released 2026-11-09 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.27.md)

| Change | What it means on shift | Page |
|---|---|---|
| **PDF device reports** | `device reports generate --format pdf` writes a letter landscape PDF beside text, CSV and JSON: a title block, then the table with its header row on every page. It needs `weasyprint` and `fonts-dejavu-core`, which are optional (`sudo apt-get install -y weasyprint fonts-dejavu-core`); without them the command refuses at once, before it reads a device, with exit status 1. A PDF is binary: `export` and `--stdout` refuse a terminal (`PDF is binary: use --out FILE or redirect`), and `show --content` says `binary PDF, <n> bytes: use export` | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6, [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| **`tacctl upgrade` offers the PDF tools, once** | Last, on Debian and Ubuntu, if either package is missing, it asks `Install weasyprint and fonts-dejavu-core now? [y/N]`. A no is remembered in `/var/lib/tacctl/pdf-tools-offered`; delete the file to be asked again. Without a terminal nothing is asked and the upgrade prints the `apt-get` line. `install` does not offer them | [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| **The files tacctl writes at a path you name are inside your home** | `device config plan --out` and `--out-dir`, `device reports export --out`, `config render --dry-run --out` and `config linux script` and `remove-script --output` refuse a path outside the home (the home of the person who ran `sudo`), one that leaves it through `..` or a link, and any `~` or `$` for tacctl to expand: the shell expands them, tacctl does not. `--output /dev/stdout` and `/var/tmp/...` are refused now, and so is an `--output` that names a directory. A script that wrote elsewhere fails until it names a path inside the home | [Getting Started](getting-started.md) §5, [Superuser Daily Operations](superuser-daily-operations.md) §11.4, [Engineer Guide](engineer-guide-device-changes.md) §4 |
| **`device support-bundle --out` is a name** | A letter or digit, then letters, digits, `.`, `_` or `-`, at most 64 characters; a `/`, `..`, a leading dot, `~` or `$` is refused with exit status 2 before anything is asked. The bundle is `~/support-bundles/<name>` and its private map `~/support-bundles/<name>.map`. Without `--out` the name is `<device>-<UTC time>`. Before, `--out ~/x` could make a folder named `~` | [Engineer Guide](engineer-guide-device-changes.md) §2.6 |
| **The support-bundle scrubber keeps what the device printed about itself** | Model names (`PID:`, `VID:`, `DESCR:`, the `Model:` line of Junos), object identifiers and the vendors' own host names (`www.cisco.com`) stay; serial numbers are replaced by their field, whatever their length, and the serial column of a hardware table is replaced at its header's column, with the columns after it kept in place; the echo of a long Cisco command is dropped; a vendor's mail address and your own name under a vendor's domain are replaced | [Engineer Guide](engineer-guide-device-changes.md) §2.6 |
| **A read-only user's reports follow `device show`** | Below the operator tier the model, serial number and release of the `inventory` and `software` reports are empty, `members` is `-` and the `members` report has no rows. The operator tier and up see what they saw. A report made before keeps what it holds | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| **A superuser's `prune` of other users' reports is audited before it reads** | One `device reports access verb=prune ... report=*` line for each other user whose directory is read, also when nothing is old enough, with no count. With `--all-users` all the lines come first, so under `audit.strict` one that cannot be written refuses the whole run | [Audit and Compliance](audit-and-compliance.md) §3, [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| **The `scp` line of `device reports show` does not work through the console** | The console is a login shell that accepts one tacctl line and refuses `scp` and `sftp`. `export` prints a report or writes it inside the home; file transfer through the console is planned for a later release | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| A user with no Linux account | A user name with upper case letters or longer than 32 characters has no account, so `generate` refuses and stores nothing; `--stdout` still prints | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| A Cisco stack member with no version | `show switch` rows whose H/W version column is blank (`Provisioned`) are read as members; they were dropped | [Vendor Notes](vendor-notes.md) §2.5 |
| `tacctl rollback 0.2.26` | The release before this one is a target. It converts nothing: no key or field removed, no snapshot, no `--yes` | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.26:**
>
> - `tacctl upgrade` converts nothing in this release. The PDF offer comes
>   last, once, and installs only if you answer yes at a terminal. Existing
>   reports, bundles and settings are read as they were.
> - Check your scripts: a `device support-bundle --out`, `device config plan
>   --out`, `reports export --out`, `config render --dry-run --out` or
>   `config linux script --output` that named a path outside the home, or a
>   `~` for tacctl to expand, fails until it names a path inside the home (a
>   bundle name for `support-bundle`).
> - After `tacctl rollback 0.2.26` and the install of 0.2.26, the limits of
>   the reports, the chassis members and every report stay. A PDF report is a
>   file like the others and the packages stay installed, but 0.2.26 has no
>   PDF format: it lists a PDF, its `show --content` cleans the bytes as text,
>   and `device reports rename` of a PDF drops its `.pdf`. Fetch it first, and
>   remove or rename it before the rollback.

---

## 5. tacctl 0.2.26

Released 2026-11-06 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.26.md)

| Change | What it means on shift | Page |
|---|---|---|
| **`device reports`** | `device reports generate --type inventory\|members\|software\|config` makes a saved, dated report of your devices from what tacctl already stores, with no login: `--format text\|csv\|json`, `--scope`, `--vendor`, `--stdout` to print instead of save. The file is `~/reports/devices/<type>-<yyyymmdd>.<ext>` in your own home. `list`, `show`, `export`, `rename`, `remove` and `prune` look after them. Every tier runs all of it for its own reports; only `generate --pull` (read the devices first, with your password) is the engineer's | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6, [Engineer Guide](engineer-guide-device-changes.md) §3.2 |
| **Chassis members** | A good `device config pull` records the members of a Junos virtual chassis or a Cisco stack (id, role, model, serial number, release, status, priority). `device show` and `device config show` print a `Chassis members:` table (operator tier and up), `device show --json` has `members`, and the `members` report has a row for each. A device has none until it is pulled again | [Vendor Notes](vendor-notes.md) §2.5, §3.3 |
| **Reports are limited** | `generate` refuses a report over `reports.max_size` (10 MiB) and one that would make a user's reports more than `reports.max_count` (100), says which setting and how to get out, and writes nothing. A superuser sets the server's limits with `config reports` and one user's with `user reports-limit` | [Superuser Daily Operations](superuser-daily-operations.md) §4.11 |
| **Old reports** | `device reports prune --older-than 30d` lists and removes the reports made longer ago than that, after one question (`--dry-run` only lists). Nothing prunes by itself | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| **A superuser reaches other users' reports, and it is audited** | `list --user <name>`, `list --all-users`, `<user>/<report>` and `prune --user` or `--all-users`. Each writes one `device reports access` line before anything is read, never a content, and with `audit.strict` an access whose line cannot be written is refused | [Superuser Daily Operations](superuser-daily-operations.md) §4.11, [Audit and Compliance](audit-and-compliance.md) §3 |
| **`tacctl upgrade` renames users whose name has a period** | 0.2.20 and 0.2.21 allowed one; the upgrade used to refuse. Each period becomes `_` (`alice.smith` becomes `alice_smith`), with a snapshot first. If the new name is taken the user gets `_` and four random characters (`alice_smith_k3x9`). Tell the people to log in with the new name | [Access Lifecycle](access-lifecycle.md) §2 |
| **A period in a user name is refused everywhere** | Every `user` verb, `passwd` and `config linux uid` refuse it, existing or not. `config validate` and `rollback` no longer look for such a user | [Access Lifecycle](access-lifecycle.md) §2 |
| **`backup restore` and `recover` of an older snapshot** | A snapshot that holds a user with a period still restores: nothing is rendered, the console settings of that user are dropped, and `tacctl upgrade` then renames the user. A recovery skips such a user and names it | [Backups and Undo](backups-and-undo.md) §4.4 |
| **Break-glass firewall line** | `upgrade` and `install` print one short sentence: `Break-glass firewall: loaded (reject on tcp/49), no address held.` or, with an address held, `Break-glass firewall: 192.0.2.10 refused on tcp/49 (reject).` | [Break Glass](break-glass.md) §2.1 |
| A name in use | The refusal names the way on that fits the command: `--force` for `export --out` and `plan --out`, another `--name` for `generate`, another new name for `rename` | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.6 |
| `tacctl rollback 0.2.25` | The release before this one is a target. It removes the limits of the stored reports (and puts back the sudoers drop-in 0.2.25 wrote); the other targets remove the limits too | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.25:**
>
> - `tacctl upgrade` renames every user whose name has a period, with a
>   snapshot it names (`snapshot <id> holds the state before the rename`);
>   with no such user it takes none and prints nothing. Read its lines: each
>   rename is one line, and a name that was taken is `alice_smith_k3x9` and
>   says why. The people must log in with the new name, the name typed at a
>   device's login. No Linux account is renamed (a name with a period never
>   had one); the new name gets its account at the next sync. A new name with
>   upper case letters, or longer than 32 characters, can never have an
>   account: the upgrade lists each such user with the reason and the fix.
> - A name that is not a user name even with the periods replaced (one with a
>   space, say) stops the upgrade before any change and names the key to edit
>   in the store; run it again afterwards.
> - A snapshot taken by 0.2.25 or earlier can hold such a user. It restores
>   (`tacctl backup restore <id>`), but the store then refuses every write
>   until `tacctl upgrade` has renamed the user. The snapshot the upgrade
>   takes before a rename is one of them.
> - Nothing else is converted. The limits of the stored reports are written
>   only when set, a device has no chassis members until it is pulled again,
>   and the first report creates `~/reports/devices/`.
> - After `tacctl rollback 0.2.25` and the install of 0.2.25, the limits are
>   removed (a user's own limit needs `--yes`, and the dry run names the user
>   and the values); 0.2.25 has no `config reports` or `user reports-limit`.
>   The chassis members of the pull records and every report in the users'
>   homes stay: they are the users' own files, and 0.2.25 cannot list or
>   remove the reports.

---

## 6. tacctl 0.2.25

Released 2026-11-05 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.25.md)

| Change | What it means on shift | Page |
|---|---|---|
| **`device config shapes` stays narrow** | The `NOW` column holds a count (`49 devices`, `1 device`, `-`), and a block headed `At a shape now (last check or apply):` below the table lists the devices of each shape, wrapped at 80 columns. A shape one line from a confirmed one says `1 line differs` | [Engineer Guide](engineer-guide-device-changes.md) §5.3 |
| **Shape, canary and confirmed explained** | The planning pages open with a rollout in five steps and say what a shape, a canary and the states `new`, `confirmed` and `seeded` allow. At the default `--max-failures 1` a failed canary stops the whole run. No behavior changed | [Engineer Guide](engineer-guide-device-changes.md) §5 |
| **Junos NETCONF hello in the XML-namespace spelling** | A device that names its capabilities `urn:ietf:params:xml:ns:netconf:base:1.0` is read as `hello ok` (it was recorded as `no hello`, and an apply that enabled NETCONF was rolled back). A hello that is none says why on the pull line, in `--json` and in the apply message | [Vendor Notes](vendor-notes.md) §3.2 |
| **Slow devices no longer fail with `open: configure exclusive`** | A late answer to the empty line the ssh client types is dropped instead of arriving in front of the first command's echo | [Vendor Notes](vendor-notes.md) §3.2 |
| **Virtual chassis whose master prints its own label** | A two-member chassis whose members both print `fpc0:` and `fpc1:` is applied to; before, every apply on it was rolled back. A refused commit answer shows up to 40 lines | [Vendor Notes](vendor-notes.md) §3.2 |
| **Device text is cleaned further** | C1 controls, the bidirectional overrides and line separators in text a device sends show as `?`, in the terminal and in `--json` | — |
| `tacctl rollback 0.2.24` | The release before this one is a target; it converts nothing, removes no key and needs no `--yes` | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.24:**
>
> - Nothing is converted; no stored file changed.
> - A Junos device recorded as `no hello` because of the namespace prefix shows
>   `hello ok` after a new `tacctl device config pull`; `tacctl device check`
>   shows it.
> - After `tacctl rollback 0.2.24` and the install of 0.2.24, those two Junos
>   failures (the `no hello` record and the labelled-master chassis rolled
>   back) return.

---

## 7. tacctl 0.2.24

Released 2026-11-05 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.24.md)

| Change | What it means on shift | Page |
|---|---|---|
| **Break-glass firewall** | A held address can no longer complete a TCP handshake with the server, so a device that falls back to its local accounts only when the server is unreachable (WTI *Fallback Local* `On (Transport Failure)`, Junos `authentication-order [ tacplus password ]`) does fall back. `tacctl config breakglass-firewall reject\|drop\|off` sets it (`reject` is the default; `off` is the 0.2.23 behavior). The report of a hold and a release has a `Firewall:` line | [Break Glass](break-glass.md) §2.1 |
| A missing `nft` | The hold stands but the command exits 1 and the report says in red what the server still does, with the fix (`sudo apt-get install nftables`, then `tacctl config breakglass-firewall <setting>`). With the setting `off`, or nothing held, it is no failure | [Break Glass](break-glass.md) §2.1, [Exit Codes](exit-codes.md) §1 |
| **Log filters and `--json`** | `log tail`, `search`, `failures` and `accounting` take `--since`, `--until`, `--user`, `--device`, `--type login\|change\|command` (accounting) and `--json` (one object per line). They combine and apply before a count | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.4, [Audit and Compliance](audit-and-compliance.md) §1 |
| **Accounting names the device** | Each record carries `"Device"`, the address it came from; `log accounting` shows the registered name (`"Device":"sw1"`). `<`, `>` and `&` show as typed | [Day-to-Day Device Operations](day-to-day-device-operations.md) §1.4 |
| **No forwarding while a password change is due** | While anyone is held to a password change, the console's sshd drop-in closes every kind of forwarding for them, in every tier. A connection already open keeps its forwardings until it closes (`loginctl terminate-user <name>`) | [Access Lifecycle](access-lifecycle.md) §5.1 |
| **No `single-connection`** | The walkthroughs no longer set it (tacquito closes a connection idle for 15 seconds). `device config plan` and `apply` delete it from tacctl's server on a device that has it; `diff` and `plan` list it as an extra | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| tacquito from the project's fork | `install` and `upgrade` build tacquito from `rett/tacquito`. git asks for no password, user name or key passphrase and drops a stalled transfer | — |
| `tacctl rollback 0.2.23` | The release before this one is a target; it converts nothing and removes the firewall | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.23:**
>
> - Expect one brief interruption of TACACS+. The upgrade rebuilds tacquito
>   once for the patch that adds `"Device"` to accounting records, and restarts
>   it.
> - The upgrade installs the `nftables` package and, with holds standing,
>   loads the firewall table for them: from then on the server refuses the TCP
>   connections of every held address. That is the fix. To keep the 0.2.23
>   behavior, run `tacctl config breakglass-firewall off`. `nftables.service`
>   is never enabled or touched.
> - git asks for nothing. A remote that needs a password fails: use a key, the
>   agent or a credential helper. An ssh remote's host key must be in
>   `known_hosts` already. Your own `GIT_SSH_COMMAND` or `GIT_SSH` is replaced:
>   choose a key with `core.sshCommand` in the clone.
> - No stored file is rewritten. An installed per-tier sudoers drop-in gains
>   the operator's `log failures *`, so an operator can pass the log filters
>   to `log failures` through sudo.
> - The upgrade changes no device. On a device whose configuration still sets
>   `single-connection`, run `tacctl device config plan` and `apply`.
> - The way back is `tacctl rollback 0.2.23`. It removes the setting, the
>   table, the rules file and the boot unit of the firewall (the `nftables`
>   package stays) and converts nothing else; it needs no `--yes`. A hold that
>   stands stays, without the firewall. Until the older release is installed,
>   run no verb that changes the holds, the listeners or the setting. On a
>   device whose `single-connection` was removed, 0.2.23's `diff` and `plan`
>   show the line as missing, and applying that plan types it again.

## 8. tacctl 0.2.23

Released 2026-10-31 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.23.md)

| Change | What it means on shift | Page |
|---|---|---|
| **`device clone`** | Registers a copy of a device (registry, SNMP, NETCONF, timing scale, configuration blocks) at a bench address with `--staging`. Engineers may clone within their own scopes | [Engineer Guide](engineer-guide-device-changes.md) §2.5 |
| **`device rename --replace`** | Removes the original with its files after a snapshot and one confirmation (`--yes` skips it), moves the replacement to its address and ends the bench address. An original with a break-glass hold needs a superuser | [Engineer Guide](engineer-guide-device-changes.md) §2.5 |
| **Emergency lockdown reaches the hosts** | `enable` and `disable` also close SSH key logins and forwarding on the scope's enrolled hosts, through `host sync`, and ask `Sync these hosts now? [y/N]` (`--yes` answers it). A host that is unreachable stays on a pending list that `status` shows | [Emergency Lockdown](emergency-lockdown.md) §3.1 |
| **SNMPv3 user pools** | At each level (server, scope, device) the v3 users are a pool with one default: `v3-user add\|remove\|default\|list`, `--default`, `--none`. A device uses its own default, else its scope's, else the server's. `config snmp version` sets the version | [Superuser Daily Operations](superuser-daily-operations.md) §4.10 |
| **`device check --sources`, `device scan --sources`** | Connect to the source addresses a device sends AAA from and warn when one is unreachable or presents another host key | [Engineer Guide](engineer-guide-device-changes.md) §3.1 |
| AAA source address | A source that no interface of the device holds is a difference and a plan item. The settings a device keeps for its own AAA server (a source address, a routing instance) are no longer listed as differences | [Engineer Guide](engineer-guide-device-changes.md) §3.1 |
| **Email address of a user** | `user add --email`, `user email <name> [<address>\|clear]`: optional, one per user, set by a superuser, shown by `user show`, never logged. No mail is sent | [Access Lifecycle](access-lifecycle.md) §2 |
| Users and this server's accounts | A `user` change that touches an account on this server syncs the server's own accounts at once, so a new user can log in to change the password. Other enrolled hosts get one warning and, on a terminal, the question | [Access Lifecycle](access-lifecycle.md) §2 |
| **`backup keep`, `unkeep`, `recover`** | `keep` copies a snapshot beyond the retention; `recover <snapshot> [--only email,snmp-users]` puts back only what a rollback dropped | [Backups and Undo](backups-and-undo.md) §4.2, §4.3 |
| `device rename`, `host rename` | Carry the bench address that was staged under the old name | [Engineer Guide](engineer-guide-device-changes.md) §2.5 |
| `tacctl rollback 0.2.22` | The release before this one is a target; it removes the email addresses and writes the SNMP credential files in version 1 again | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.22:**
>
> - No file is rewritten at the upgrade. The per-tier sudoers drop-in gains the
>   engineers' rule for `device clone`.
> - Scripts that call `emergency lockdown` and expect no question: with a
>   terminal, `enable` and `disable` now ask whether to sync the hosts. Answer
>   with `--yes`, or run `tacctl host sync <hosts>` yourself; without a
>   terminal nothing runs and a notice names the hosts.
> - The way back is `tacctl rollback 0.2.22`. It removes the users' email
>   addresses and writes the SNMP credential files in version 1 again (one v3
>   user per level, the default), after a snapshot it keeps, and needs `--yes`
>   when it drops anything. Afterwards the older release reports the rendered
>   config as out of date until its first render.
>   `tacctl backup recover <snapshot>` returns what was dropped once 0.2.23 or
>   later is installed
>   again. The rollback is refused while an emergency lockdown has enrolled
>   hosts: lift it and sync the hosts first.

## 9. tacctl 0.2.22

Released 2026-10-29 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.22.md)

**Renamed commands, no aliases.** The old forms are now unknown
sub-commands, and the one-letter form of `--yes` is refused:

| Up to 0.2.21 | From 0.2.22 |
|---|---|
| `config listen ...` | `server listen ...` |
| `config metrics ...` | `server metrics ...` |
| The one-letter form of `--yes`, on any command | `--yes` |
| `device list` (and `--json`) with the enrolled hosts | `host list` (and `--json`) for the hosts; `device list` has devices only |

| Change | What it means on shift | Page |
|---|---|---|
| **`host list`** | Shows state, last seen, by and open notices as `device list` does, with the filters `--name`, `--ip`, `--scope` and `--stale` | [Linux Host Operations](linux-host-operations.md) §1 |
| **`device list --differs`** | The devices whose last pull differs from what is rendered now, with no login (operator tier) | [Superuser Daily Operations](superuser-daily-operations.md) §4.1 |
| **`tacctl server`** | `server show` is this server at a glance (address, name, default method, metrics exporter, backends and listeners); `server name` sets the name the console shows; `server listen` and `server metrics` are the old `config listen` and `config metrics` | [Superuser Daily Operations](superuser-daily-operations.md) §11.3 |
| **Timing scale** | For a device behind a long round trip or with a slow CPU, one whole number from 1 to 10 multiplies the host-key scan, session, SNMP and per-device pull times: `device timeout-scale <name>`, `scope timeout-scale <scope>`, `config devices timeout-scale` (superuser); engineers read it in `device show` and `scope show`. 1, the default, changes nothing | [Connecting to Devices](connecting-to-devices.md) §7, [Superuser Daily Operations](superuser-daily-operations.md) §4.9 |
| **`--timing`** | `device config pull`, `diff --pull`, `plan --pull` and `apply` print, per device, the time of each phase and name the slowest device; `timings` in `--json` | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| `host sync` and `host check` take `--concurrency <n>` | Several hosts at once, output in the order typed; nothing is asked, so a key or agent and a root or passwordless-sudo login are needed | [Linux Host Operations](linux-host-operations.md) §2.1 |
| Unknown sub-command | One error line, a `Did you mean` hint and a pointer to `-h`; below the first word it is answered before `sudo` asks for a password | [Getting Started](getting-started.md) §5 |
| User names | A period is refused again; a user stored with one stays readable and is renamed with `user rename` | [Access Lifecycle](access-lifecycle.md) §2 |
| Host keys of slow devices | A device `ssh-keyscan` reads nothing from is read by tacctl's own ssh client | [Connecting to Devices](connecting-to-devices.md) §6 |
| Junos virtual chassis | The master answers without a label, and the apply reads it | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| Teal command names | The console's lists show command names in teal like the other fixed words | [Superuser Daily Operations](superuser-daily-operations.md) §10.2 |
| Generated tacquito drop-in | Its comment, and the shipped unit comments, name `server listen` and `server metrics`; the first render restarts tacquito once (see below) | [Backups and Undo](backups-and-undo.md) §5 |
| `tacctl rollback 0.2.21` | The release before this one is a target; it removes `server.name` and the timing scale and converts nothing else | [Backups and Undo](backups-and-undo.md) §5 |

> **Before upgrading from 0.2.21:**
>
> - Rename every user whose name has a period (`tacctl user list` shows
>   them; `tacctl user rename <name> <new-name>`). If one is left, 0.2.20 or
>   0.2.21 has already replaced `tacctl` and the tacquito build when the new
>   `tacctl` refuses; the store, the configuration and the services are not
>   changed, and `tacctl upgrade` run again after the rename finishes it.
> - Change scripts, runbooks and notes: `config listen` and `config metrics`
>   become `server listen` and `server metrics`, the one-letter form of
>   `--yes` is spelled out, and a script that reads hosts from `device list`
>   reads `host list`.
> - No sudoers rule and no stored setting needs to change: the `server`
>   family is the superuser's, as `config listen` and `config metrics` were,
>   and writes the same keys. The timing scale needs no conversion either: it
>   is 1 until a superuser sets it, and every timing is as before.
> - Expect one brief interruption of TACACS+. The comment at the top of the
>   generated tacquito drop-in names the current commands, so the first render
>   after the upgrade (the upgrade's own, else the first `config render` or
>   change of a listener, `loglevel` or exporter) rewrites the drop-in,
>   reloads systemd and restarts tacquito once. The upgrade restarts tacquito
>   once at its end for any changed unit file or drop-in, and that is this
>   restart. RADIUS is not touched. A drop-in you edited by hand is saved
>   aside before it is replaced.
> - The way back is `tacctl rollback 0.2.21`. It removes `server.name` and the
>   timing scale (the two `tacctl.yaml` keys and each device's
>   `timeout_scale`), with a note in the plan and no `--yes`. After it the
>   older release's `config validate` reports the rendered config as out of
>   date until its first render writes its own comment, which restarts
>   tacquito once; the rollback itself restarts nothing.

## 10. tacctl 0.2.21

Released 2026-10-28 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.21.md)

| Change | What it means on shift | Page |
|---|---|---|
| **Every user logs in to the server** | Every user can log in to the tacctl server and its console, whatever their scopes, unless disabled or in a group of tier none. The login is a scope called `tacctl` that tacctl manages: reserved, in no listing, edited by no command. Device logins keep the user's own scopes. | [Superuser Daily Operations](superuser-daily-operations.md) §10, §11.1 |
| `install` and `upgrade` set the login up | `install` asks once (`--yes` answers, `--server <ip>` sets the address); `upgrade` asks on a terminal only. `host enroll --local` stays the way to rebuild, move or repair it. | [Superuser Daily Operations](superuser-daily-operations.md) §11.1 |
| `tacctl server addresses` | The address devices and hosts reach the server at is a setting of its own. The device walkthroughs, `config linux script` and `host enroll` default to it. | [Superuser Daily Operations](superuser-daily-operations.md) §11.2 |
| `ssh` asks for the password first | With the password cache on and empty, `ssh` and `device ssh` ask for the password once, before they connect; the next `ssh` asks nothing. | [Getting Started](getting-started.md) §1.3 |
| Walkthroughs follow the listener port | A TACACS+ listener that is not on 49 adds its `port` to the Cisco and Junos walkthroughs and the WTI Authentication Port item. | [Engineer Guide](engineer-guide-device-changes.md) §4.1 |
| Junos chassis of one member | `device config apply` treats it like a single device | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| `tacctl rollback 0.2.20` | The release before this one is a target; every target keeps the users' server login | [Backups and Undo](backups-and-undo.md) §5 |

> **Before the upgrade,** rename a scope of your own that is called `tacctl`
> (`tacctl scope rename tacctl <new-name>`): it is never taken over, and
> while it exists `host enroll --local`, the sync of the server and
> `config validate` stop with one line. **After it,** check the line about
> the machine's own login, and run `tacctl host sync <server>` as before.

## 11. tacctl 0.2.20

Released 2026-10-28 ·
[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.20.md)

**Removed console commands, no aliases.** The old forms are now unknown
sub-commands:

| Up to 0.2.19 | From 0.2.20 |
|---|---|
| `console tiers`, `console user` (who gets the console) | Nothing to set: the console is the login shell of every tacctl user |
| `console system-shell tiers <csv>\|none` | `console system-shell <tier> enable\|disable` |

| Change | What it means on shift | Page |
|---|---|---|
| **Required password change** | A new user, and a user whose password a superuser reset, must change it at the next login to the tacctl server before any device accepts them. `--no-change-required` skips it; `user require-password-change` sets or lifts it. | [Getting Started](getting-started.md) §2.1, [Access Lifecycle](access-lifecycle.md) §5.1 |
| **The console for everyone** | Every tacctl user, of every tier, logs in to the server's console. The system shell is opened by a superuser per tier or per user; engineers never have it. | [Superuser Daily Operations](superuser-daily-operations.md) §10 |
| **Password cache is your choice** | `console password-cache on` turns it on for you, where your tier is allowed it; it is off until you do | [Getting Started](getting-started.md) §1.3 |
| `--help`, `-h` and `tacctl man` | `--help` after a command prints what `?` prints; `man <command>` opens the manual page there, in the console too. In bash, `?` after `tacctl …` prints help. | [Getting Started](getting-started.md) §1 |
| `console color`, `console list-max` | The console's list colours and the longest list it shows without asking | [Superuser Daily Operations](superuser-daily-operations.md) §10.2 |
| **Strict Junos management filter** | `scope mgmt-acl <scope> mode strict` makes the Junos filter deny by default; engineers can read the mode of their scopes | [Vendor Notes](vendor-notes.md) §3.4 |
| **Junos `root` as break-glass** | `scope breakglass <scope> add root`; the walkthrough renders the root password and `root-login allow` as comments to fill in | [Break Glass](break-glass.md) §1.1 |
| `Kept:` and `Secrets:` in plans | A device's own SNMP, system and NETCONF statements are no irregularity any more; the secrets line is information | [Engineer Guide](engineer-guide-device-changes.md) §4 |
| Apply on a virtual chassis | The check and the commits must answer for every member; `PENDING until` is the device's own clock | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| Host keys read one type at a time | A device that gives no key to the scan is asked again, and the refusal says how to pin a key by hand | [Connecting to Devices](connecting-to-devices.md) §6 |
| User names with a period | 0.2.20 and 0.2.21 accept a period between the parts of a user name; such a user has no Linux account. 0.2.22 refuses a period | [Access Lifecycle](access-lifecycle.md) §2 |
| `tacctl rollback 0.2.19` | Goes back to the previous release, with warnings for what it undoes | [Backups and Undo](backups-and-undo.md) §5 |

> **After the upgrade,** run `tacctl host sync <server>` for the server's own
> host entry: the console becomes the login shell of every tacctl user then,
> and not before. No existing user must change their password until a
> superuser says so.

## 12. tacctl 0.2.19

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.19.md)

| Change | What it means on shift | Page |
|---|---|---|
| **Emergency lockdown** (`tacctl emergency lockdown`) | Superusers can refuse the logins of chosen groups on a scope at once. A red notice appears on every command that names a locked scope. | [Emergency Lockdown](emergency-lockdown.md) |
| **Engineers work their own scopes** | Engineers can enroll, collect, onboard, sync and apply for the devices of their own scopes | [Engineer Guide](engineer-guide-device-changes.md) |
| `tacctl device support-bundle` | Collects a scrubbed, read-only bundle of what a developer needs from one device | [Device commands (repo)](https://github.com/rett/tacctl/blob/master/docs/cli/device.md) |
| Wider `system` blocks | Junos and IOS `system` blocks now cover syslog, login banners, login retry and password policy, ssh settings and timestamps; plans can remove a service a scope requires to be off | [Engineer Guide](engineer-guide-device-changes.md) §3 |
| Host names may contain dots | `tacctl host rename web1 web1.example.net` works | [Linux Host Operations](linux-host-operations.md) |
| Unknown commands answered first | A mistyped command is answered before `sudo` asks for a password | — |

## 13. tacctl 0.2.18

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.18.md)

**Renamed commands, no aliases.** The old names are now unknown commands:

| Up to 0.2.17 | From 0.2.18 |
|---|---|
| `device config-syntax <name> [auto\|ios12\|modern]` | `device ios-syntax <name> [auto\|ios12\|modern]` |
| `device add --config-syntax <syntax>` | `device add --ios-syntax <syntax>` |
| `device notices [<name>] [--all]` | `device notice list [<name>] [--all]` |
| `device ssh-config` | `device client-config` |

Also: Tab now completes these names with a space, `?` describes every
command and flag from its own usage, and a mistyped command suggests what
you may have meant (`tacctl enroll` suggests `device enroll` and
`host enroll`). Every tier can run `device notice list` and
`device client-config`.

## 14. tacctl 0.2.17

[Full release notes](https://github.com/rett/tacctl/blob/master/docs/release-notes-0.2.17.md)

| Change | What it means on shift | Page |
|---|---|---|
| **`tacctl device enroll`** | One attended command from a new address to its plan: key, vendor, registration, pull, plan | [Engineer Guide](engineer-guide-device-changes.md) §2.2 |
| **Apply review asks per device** | Approve each Junos device by typing its name. Typing a count no longer works; scripts use `--confirmed --yes`. | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |
| **Host keys accepted one device at a time** | `enroll`, `collect` and `onboard` show the one key they will pin; you accept it by typing the name back | [Connecting to Devices](connecting-to-devices.md) §6 |
| **Audit session id** | Every audit line ends in `sid=<id>`, so one `grep` finds a whole command. Log filters that anchor the end of a line (`$`) need updating. | [Audit and Compliance](audit-and-compliance.md) §2 |
| `cmd start` / `cmd end` lines | Every change writes a start and an end line, with the result and the snapshot taken | [Audit and Compliance](audit-and-compliance.md) |
| Vendor read by SNMP | `device add` and `device check` say which vendor the device reports; `device vendor <name> --from-device` sets it | [Engineer Guide](engineer-guide-device-changes.md) §2.4 |
| New selectors | `device config pull`, `diff`, `plan` and `apply` take `--differs`, `--name` and `--ip`; `apply --pull` reads fresh first | [Engineer Guide](engineer-guide-device-changes.md) §5.1 |

---

## 15. Older releases

Releases 0.2.0 to 0.2.16 are listed on the
[releases page](https://github.com/rett/tacctl/releases), and every change is
numbered in
[`CHANGELOG.md`](https://github.com/rett/tacctl/blob/master/CHANGELOG.md).

---

*See also:* [About These Docs](about-these-docs.md) (which release each page was
checked against) · `tacctl version`
