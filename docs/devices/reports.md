# Device reports

[Documentation](../README.md) › [Network devices](README.md)

A report is a saved, dated document about the registered devices, made on demand from what tacctl already stores about them: the registry (`devices.yaml`) and the records of the last pulls (`device config pull`, see [Device configuration](configuration.md)). `tacctl device reports generate` makes one and keeps it as a file of your own home; `list`, `show`, `export`, `rename`, `remove` and `prune` look after the files. Nothing contacts a device unless you ask for it with `generate --pull`, nothing makes a report by itself (there is no timer), and no report holds a secret, a hash or a community string.

```
tacctl device reports generate --type inventory|members|software|config
                               [--scope <scope>] [--vendor <vendor>]
                               [--format text|csv|json] [--name <name>] [--stdout] [--pull]
tacctl device reports list [--json] [--user <name> | --all-users]
tacctl device reports show <report> [--content]
tacctl device reports export <report> [--out <file> [--force]]
tacctl device reports rename <report> <new>
tacctl device reports remove <report> [--yes]
tacctl device reports prune --older-than <n>h|<n>d|<n>w [--user <name> | --all-users]
                            [--dry-run] [--yes]
```

## Making a report

```
$ tacctl device reports generate --type inventory --format csv
[INFO] Report inventory-20261106 written: /home/user/reports/devices/inventory-20261106.csv
  4 rows, 431 B. See it with: tacctl device reports show inventory-20261106
```

`--type` is required. There are four types, each with a row per device or, for `members`, per chassis member:

| Type | One row per | Columns |
|---|---|---|
| `inventory` | device | `name`, `address`, `vendor`, `scope`, `model`, `serial`, `release`, `members` (the number of chassis members, `-` for none), `location`, `description`, `pulled` |
| `members` | chassis member | `device`, `member` (the id), `role`, `model`, `serial`, `release`, `status`, `priority`, `pulled` |
| `software` | device | `name`, `vendor`, `model`, `release`, `pulled` |
| `config` | device | `name`, `scope`, `state`, `pulled`, `applied` |

- **Where the rows come from.** The record of the last good pull of each device: `model`, `serial`, `release` and the members are the [device facts](configuration.md) and the [chassis members](configuration.md) it read (left out for a read-only user, see [Who may do what](#who-may-do-what)); `location` and `description` are the registry's own fields of the device (`device location`, `device description`: free text an operator wrote); `state` of the `config` report is the word `device config list` shows for the device (`ok`, `differs`, `never`, `failed`, `pull` for a device that needs a pull, `-` for a vendor `other` or a device in no scope), worked out against what tacctl renders now; `applied` is the time of the last successful `device config apply`, `-` for none.
- **A device that was never pulled is a row, not a gap** in the `inventory`, `software` and `config` reports, which list every device of the selection. Its facts are empty and its `pulled` says `never`; a report that left it out would hide that it is unknown. The `members` report is the exception: it lists the devices that have a model or a serial number (or chassis members), so a device with neither, which includes one never pulled, is not in it (see below). Every row carries the date of the pull its facts came from (`pulled`), and the heading of a report gives the date of the oldest datum (`Oldest data:`, or `none (no device was pulled)`). There is no warning for old data: the dates are the information.
- **The roles.** `role` is `master`, `backup`, `linecard` or `member` for both vendors: Junos prints `master`, `backup` and `linecard`; on Cisco `Master` (IOS-XE 16.x and later: `Active`) is `master`, `Standby` is `backup` and `Member` is `member`. A role a vendor prints that is none of these is kept in `status` and `role` is empty.
- **A standalone device is one member.** The `members` report has a row for each unit of a Junos virtual chassis or a Cisco stack (see [Chassis members](configuration.md)) and one row, with the member id `-` and the role `-`, for a device that is none and has a model or a serial number. A device with neither is not in it.
- **Whose devices.** The devices your scopes cover; a superuser's report holds every device. `--scope <scope>` keeps the devices of that scope (one of yours, else the scope is refused) and `--vendor cisco|juniper|wti|other` those of a vendor; the two combine. An enrolled Linux host is not a device and is in no report. A selection that matches nothing writes a report with no rows, after the warning `No device matches: the report has no rows.`
- **Fresh data.** `--pull` first reads the devices of the selection as [`device config pull`](../cli/device.md) does, with your own password (asked for once, never stored) over the transport the pull chooses, then makes the report from the fresh records. It needs the engineer tier, because it logs in to the devices as you, and it reads the devices of your own scopes that have a vendor the pull reads (Cisco, Junos and WTI) and a scope that covers them. A device that cannot be read keeps the facts and the date of its last good pull; `Some devices were not read: the report holds the facts of their last good pull, with its date.` is printed, the report is still made and the exit status is 1. Without `--pull` no device is contacted and no password is asked.

### Formats

`--format` is `text` (the default), `csv` or `json`, and sets the extension of the file (`.txt`, `.csv`, `.json`).

- **text** is aligned columns under a heading that gives the type, when the report was made (UTC), the date of the oldest datum and the number of devices; an empty cell is `-`.
- **csv** follows RFC 4180: a header line with the column names, UTF-8, `\n` line ends, a cell with a comma or a quote in quotes. A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so that a spreadsheet shows it and does not run it; the lone `-` that stands for nothing is left as it is.
- **json** is one object: `schema` (1), `type`, `generated`, `oldest_data`, `filters`, `columns` and `rows`, an object for each row keyed by the column (the member id of the `members` report is `id`; dates are RFC 3339 UTC, `null` for a device never pulled or applied; `members` in the `inventory` report is a count). `filters` holds the `--scope` and `--vendor` of the command as an object with the keys `scope` and `vendor`, each only when it was given (`{}` for none). Each row of the `members` report also has `components`, an empty list in this release.

Text that came from a device or an operator (model, serial number, release, member fields, location and description) is printed as the record keeps it, with control, bidirectional and C1 characters replaced by `?`.

```
$ tacctl device reports generate --type inventory --stdout
Device inventory report
Generated: 2026-11-06 09:30 UTC
Oldest data: 2026-11-03 22:10 UTC
Devices: 4

name  address       vendor   scope   model         serial    release      members  location ...
-----------------------------------------------------------------------------------------------
fw1   2001:db8::1   cisco    lab     -             -         -            -        -
jsw1  192.0.2.10    juniper  site-a  EX4300-48T    SN000001  21.4R3-S5.4  2        Rack 4, DC1
rtr1  198.51.100.1  juniper  site-a  MX204         SN000005  22.2R1.9     -        Lab rack 2
sw1   192.0.2.11    cisco    site-a  WS-C3850-24T  SN000003  16.12.4      2        Rack 4, DC1
```

The `location`, `description` and `pulled` columns are cut off here. The `members` report of the same devices:

```
$ tacctl device reports generate --type members --stdout
Device members report
Generated: 2026-11-06 09:30 UTC
Oldest data: 2026-11-03 22:10 UTC
Devices: 4

device  member  role    model         serial    release      status  priority  pulled
-----------------------------------------------------------------------------------------------
jsw1    0       master  EX4300-48T    SN000001  21.4R3-S5.4  Prsnt   129       2026-11-06 07:30
jsw1    1       backup  EX4300-48T    SN000002  21.4R3-S5.4  Prsnt   129       2026-11-06 07:30
rtr1    -       -       MX204         SN000005  22.2R1.9     -       -         2026-11-03 22:10
sw1     1       master  WS-C3850-24T  SN000003  16.12.4      Ready   15        2026-11-06 07:45
sw1     2       member  WS-C3850-24T  SN000004  16.12.4      Ready   1         2026-11-06 07:45
```

and the `config` report, as CSV:

```
$ tacctl device reports generate --type config --format csv --stdout
name,scope,state,pulled,applied
fw1,lab,never,never,-
jsw1,site-a,ok,2026-11-06 07:30,2026-11-02 09:00
rtr1,site-a,failed,2026-11-03 22:10,-
sw1,site-a,differs,2026-11-06 07:45,2026-11-01 12:00
```

`--stdout` prints the report instead of storing it: no file and no metadata are made, no limit applies, no account is needed, and with `--pull` the pull's own output goes to standard error so that standard output holds the report only.

## Where reports are kept

A report is a file in the home of the user who made it: `~/reports/devices/<name>.<ext>`, in a directory of mode 0700, the file mode 0600, made by tacctl as that user (their own uid; nothing is written as root). It is the home of the user's Linux account on the tacctl server, which every tacctl user has; a user with no account on the server can print a report with `--stdout` and cannot store one (`the user 'carol' has no account on this server`).

- **Names.** The default name is the type and the date in UTC, `inventory-20261106`; a second report of the same type on the same day, in any format, is `inventory-20261106-2`, then `-3`. `--name <name>` replaces it: letters, digits, `.`, `_` and `-`, at most 64 bytes, no leading dot, without the extension. A name that a report or a file of the directory has already, in any format, is refused (`A report or file named 'chassis' exists already`) and nothing is written; `rename` is as strict.
- **The metadata file.** Next to each report lies `<name>.<ext>.meta`, a JSON file of mode 0600 with what `show` prints: the name, the type, the format, the user, the exact command line, the filters, when the report was made, the date of the oldest datum, the size and the number of rows, and the schema number (1). Leave it alone: `list`, `show`, `rename`, `remove` and `prune` read it, and a report whose metadata file cannot be read is listed as a file that tacctl did not make.
- **Files you put there.** A file of the directory with no metadata file is one you put there. `list` shows it with the type `other`, `show` says so, and `rename`, `remove` and `prune` leave it alone; its name counts as taken for a new report.
- **Addressing a report.** By its name without the extension (`inventory-20261106`) or by the file name (`inventory-20261106.csv`). When two files share a name (only a file you put there can), the name is refused with the file names, and the extension is needed.
- **Leaving the server.** tacctl sends nothing anywhere itself. `show` prints the command that fetches a report with your own login, and `export` prints a report or copies it:

```
$ tacctl device reports show inventory-20261106

Report inventory-20261106
--------------------------------------------
  File:         /home/user/reports/devices/inventory-20261106.csv
  Type:         inventory
  Generated:    2026-11-06 09:30 UTC
  User:         alice
  Command:      tacctl device reports generate --type inventory --format csv
  Filters:      none
  Oldest data:  2026-11-03
  Format:       csv
  Rows:         4
  Size:         431 B (431 bytes)
  Download:     scp alice@tacacs.example.net:reports/devices/inventory-20261106.csv .
```

## Looking after reports

- **`list`** prints your reports, newest first, with the name, the type, the format, the size and when each was made (UTC), and the total; `--json` prints a list of objects with the same facts and the command line, the filters and the dates (a file that is not a report has `other: true` and the file, the name, the owner and the size only). A file tacctl did not make has the type `other`. The JSON list cleans every string as the text list does (a control or direction character in a file name or a metadata field is a `?`).
- **`show <report>`** prints the facts above; `--content` adds the first 200 lines of the report, read from the start of the file and no further than 256 KiB (a file with more says `... more` and, when it read all of the file, how many more lines there are); `export` prints all of it.
- **`export <report>`** prints the report on standard output, as it is stored. `--out <file>` writes it there instead, made as you with mode 0600, and refuses a file that exists unless `--force` is given. `export` reads at most the size limit in force for the report's owner (`reports.max_size`, or a larger size the report's own metadata records, 1 GiB at the most) and refuses a file over it. To fetch a report from the server use the `scp` line of `show`.

`show --content` and `export` open the file without following a link and without waiting, and read a regular file only: a link, a FIFO or a device node in the directory (or put there after the listing) is refused with its name, and read by nobody. The same goes for the `.meta` file.
- **`rename <report> <new>`** gives a report and its metadata file a new name; the extension stays. It never overwrites: a name that a report or a file has already is refused, and nothing is changed.
- **`remove <report> [--yes]`** removes a report and its metadata file after one question (`Confirm removal? [y/N]`; `--yes` skips it). A file that tacctl did not make is not removed.
- **`prune --older-than <age>`** removes your reports that were made longer ago than an age: a whole number and one unit, `h` (hours), `d` (days) or `w` (weeks), as `12h`, `30d` or `4w`. There is no default age and no zero. The age of a report is its own `generated` date in the metadata file, not the time of the file. `prune` lists what it would remove (name, type, generated date and size), asks once (`Confirm removal? [y/N]`) and removes the reports with their metadata files; `--yes` skips the question, and `--dry-run` only lists and removes nothing, whatever else is given. A file with no metadata, and anything outside the reports directory, is never removed. Nothing prunes by itself: there is no timer and no setting. The number of reports a user keeps is capped instead (see [Limits](#limits)).

```
$ tacctl device reports prune --older-than 30d --dry-run
Reports older than 30d (2)
-------------------------------------------------------
  NAME                TYPE       GENERATED         SIZE
  -----------------------------------------------------
  software-20261002   software   2026-10-02 08:00  1.1 KiB
  inventory-20261001  inventory  2026-10-01 08:00  431 B

  2 reports, 1.5 KiB in all

[INFO] Dry run: nothing was removed.
```

## Who may do what

Reports are made from stored data, so the read-only tier and up may make, list, show, export, rename, remove and prune their own; only `--pull` needs more.

| Verb | Tier |
|---|---|
| `generate` without `--pull`, `list`, `show`, `export`, `rename`, `remove`, `prune`, of your own reports | read-only and up |
| `generate --pull` | engineer and up |
| `list --user`, `list --all-users`, `<user>/<report>`, `prune --user`, `prune --all-users` | superuser |

A report holds the devices of the scopes of the user who made it, a superuser's every device. A report follows the rule of `device show` and `device list` (see [Tiers](../security/tiers.md)): what the last pull read of a device (its model, serial number, release and chassis members) and the configuration state and the date of the last apply are shown from the operator tier up, so a report of a read-only user does not hold them. In an `inventory` report the `model`, `serial` and `release` of every row are empty (`-` in text, an empty cell in CSV, `""` in JSON) and `members` is `-` (`0` in JSON); in a `software` report `model` and `release` are empty the same way; the `members` report has no rows, because a device with no model, no serial number and no members is not in it; in the `config` report `state` and `applied` are `-` in text and CSV and `null` in JSON. The rest of a row stays: the name, address, vendor, scope, location, description and the `pulled` date, as `device show` shows them to every tier.

**A superuser reaches the reports of other users.** `list --user <name>` and `list --all-users` (which add a USER column), `show <user>/<report>`, `export <user>/<report>`, `rename <user>/<report> <new>`, `remove <user>/<report>` and `prune --user <name>` or `--all-users`. A report is readable whatever devices it holds: a superuser is not held to a user's scopes. What another user wrote is not trusted with your terminal, and a metadata file does not vouch for it (the owner makes that file too): `export <user>/<report>` to the standard output cleans every line as `show --content` does (control and formatting characters, escape sequences and line separators print as `?`), for a report and for a file with no valid metadata file (`other`) alike; `export <user>/<report> --out <file>` copies the bytes as they are, and your own files print as stored. `export` copies the report to the standard output or to the path given, made as the superuser, and nothing writes a report into another user's home: a user makes their own reports, and a superuser already makes a report of every scope, so there is no `generate --as`. Anyone else who names another user's report or asks for another user's list is refused (`... is the superuser's: you reach your own reports only. Nothing was done.`).

```
$ tacctl device reports list --all-users
Device reports (3)
-------------------------------------------------------------------------
  USER   NAME                  TYPE       FORMAT   SIZE  GENERATED
  -----------------------------------------------------------------------
  alice  inventory-20261106-2  inventory  text    891 B  2026-11-06 09:30
  alice  inventory-20261106    inventory  csv     431 B  2026-11-06 09:30
  bob    inventory-20261106    inventory  text    716 B  2026-11-06 09:41

  3 reports, 2.0 KiB in all
```

**Every access to another user's reports is audited**, before anything is read or changed, with one line that says who, whose and which, and never the contents:

```
device reports access verb=show owner=bob report=inventory-20261106 by=alice sid=k3x9a0bq
device reports access verb=list owner=* report=* by=alice sid=k3x9a0bq
device reports access verb=prune owner=bob report=* by=alice sid=k3x9a0bq
```

`verb` is `list`, `show`, `export`, `rename`, `remove`, `prune` or `prune-dry-run`. `list --all-users` writes one line with `owner=*`; a `prune` of other users' reports writes one line, with `report=*`, for each other user whose directory it reads (`prune --all-users` for every user tacctl knows that has an account on the server), also for a user none of whose reports is old enough, and never a report name; all the lines of a run are written before the first directory of another user is read. The lines are at `auth.notice` and they are reveals: with `audit.strict` on, an access whose line cannot be written is refused before anything is shown ([Audit log](../security/audit.md)). Your own reports write a detail line only when something changes: `device reports generate type= name= format= rows=`, `device reports rename name= new=`, `device reports remove name=` and `device reports prune older-than= removed=`; `list`, `show` and `export` write none.

## Limits

A directory of reports cannot grow without bound: `generate` refuses a report that is too large, or that would be one too many for the user. There are two limits, each with a value for the whole server and an own value a superuser can give one user, and 0 means no cap:

| Limit | Server setting (`tacctl.yaml`, `config reports`) | Default | Own value of a user (`user reports-limit`) |
|---|---|---|---|
| The largest report | `reports.max_size`, `config reports max-size`, in bytes or with `Ki`, `Mi`, `Gi`; 0 to 1Gi | 10 MiB (the inventory of about 20,000 devices) | `user reports-limit <user> max-size <value>` |
| The most reports a user keeps | `reports.max_count`, `config reports max-count`; 0 to 100000 | 100 | `user reports-limit <user> max-count <value>` |

The limits count the reports tacctl made: the files that have a valid `.meta` file beside them. They are a guard rail against a directory growing by itself, not a quota that is enforced against the user: the directory is the user's own, and whoever has a login can put files in it (they count for neither limit, show as `other`, and nothing removes them) or edit and delete what is there, including a `.meta` file, whatever the limits say. `generate` checks them when it makes a report, and nothing else does.

```
$ tacctl config reports
  Stored reports ('tacctl device reports')
  max-size:  10 MiB   (default; 0-1Gi, the largest report; 0 is no cap)
  max-count: 100 reports   (default; 0-100000, the most reports per user; 0 is no cap)

  A user's own limit wins ('tacctl user reports-limit').
$ tacctl config reports max-size 20Mi
[INFO] The largest report set to 20 MiB.
$ tacctl user reports-limit carol max-count 10
[INFO] The max-count of 'carol' set to 10 reports.
```

The value that holds for a user is their own, else the server's, else the default; `clear` returns a user to the server's value (`user reports-limit carol clear`, or `carol max-count clear` for one limit), and an own `0` lifts a limit for that user. The size is that of the report as it would be stored; the count is the reports tacctl made (a file you put in the directory does not count). A `generate` over a limit is refused, names the setting and the way out, and writes nothing (the message is one line, wrapped here):

```
[ERROR] Cannot save the report: that would be 2 reports, over the count limit of 1 reports
    (the setting reports.max_count; a superuser changes it with:
    tacctl config reports max-count <n>). Remove one with: tacctl device reports remove <name>
[ERROR] Nothing was written.
```

A report that is too large can be made smaller (`--scope`, `--vendor`), printed (`--stdout` has no limit) or allowed by a larger setting; nothing deletes a report to make room, and nothing by age except `prune` (see Looking after reports, above). The settings are the superuser's; every user sees their own limit in `user show`.

## Older releases

A release before 0.2.26 has no `device reports` verb. `tacctl rollback` (see [Rolling back](../install/upgrading.md#rolling-back)) leaves the reports and their metadata files where they are, because they are the users' own files, and says so; it removes the limits of this page (the two settings and the users' own limits, after a snapshot, and `--yes` while a user has one), and puts back the per-tier sudoers drop-in without the `device reports` rows. The `members` of the pull records stay too: an older release ignores them.

## Exit status

0 on success; 1 when a request was refused (a name in use, a user with no account, no such report, a scope that is not yours, a limit) or when `generate --pull` could not read some device; 2 for wrong arguments (no `--type`, an unknown type or format, a bad name or age, `--name` with `--stdout`).
