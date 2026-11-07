# tacctl 0.2.26

0.2.26 adds saved, dated device reports and the chassis members they need. A
good `device config pull` now records the members of a Junos virtual chassis
or a Cisco stack, and `tacctl device reports` makes inventory, members,
software and configuration reports from what tacctl stores, as text, CSV or
JSON, in the user's own home. The reports have size and count limits, a
superuser reaches other users' reports with an audit line, and `tacctl
rollback 0.2.25` is a target. A user name with a period is renamed by `tacctl
upgrade` and accepted nowhere else, and the break-glass firewall line of
`upgrade` and `install` is one short sentence. The numbered list in
`CHANGELOG.md` (0.2.26) is everything that differs from 0.2.25.

## Reports

- `tacctl device reports generate --type inventory|members|software|config`
  makes a report from the stored records, with no login. `inventory` has a row
  for each device (address, vendor, scope, model, serial number, release, the
  number of chassis members, location, description, the date of the pull),
  `members` a row for each chassis member (a device that is no chassis is one
  row, from its own model and serial number), `software` the model and release
  of each device, and `config` the state `device config list` shows, with the
  dates of the pull and the apply. A device that was never pulled is a row with
  empty facts and `never` in the `inventory`, `software` and `config` reports;
  the `members` report lists the devices that have a model or a serial number.
  Every row carries the date of the pull its facts came from, and the heading
  gives the date of the oldest datum.
- `--format text|csv|json` (text is the default; a CSV cell that starts with
  `=`, `+`, `-` or `@` is quoted with a leading `'`, so that a spreadsheet does
  not run it), `--scope` and `--vendor` narrow the report, `--name` names it,
  `--stdout` prints it and stores nothing, and `--pull` reads the devices first
  as `device config pull` does, with your own password (the engineer tier). A
  report holds the devices of your scopes (a superuser's: all) and no secret,
  hash or community string.
- A report is the file `~/reports/devices/<type>-<yyyymmdd>.<txt|csv|json>` of
  your home (the directory 0700, the file 0600, made as you; a second report
  of a day is `-2`), with a `.meta` file beside it that records when, by whom,
  the command line, the filters and the date of the oldest datum. `list`,
  `show` (which prints the `scp` line that fetches the file), `export [--out
  <file>]`, `rename` and `remove` look after them, a file you put in the
  directory is `other` and left alone, and every tier can run them for its own
  reports; only `--pull` is the engineer's. The `state` and `applied` columns
  of the `config` report are the configuration state that `device list` and
  `device config list` keep for the operator tier and up: for a read-only user
  both are `-` in text and CSV and `null` in JSON. The first report creates the
  directory.
- `tacctl device reports prune --older-than <n>h|<n>d|<n>w` lists the reports
  made longer ago than that and removes them with their `.meta` files after
  one question (`--yes` skips it, `--dry-run` only lists). The age is the
  `generated` date in the metadata file, not the time of the file; a file with
  no metadata and anything outside the reports directory is never removed.
- A superuser reaches the reports of other users: `list --user <name>`, `list
  --all-users`, `show`, `export`, `rename` and `remove` with
  `<user>/<report>`, and `prune --user <name>` or `--all-users`. Each writes
  one `device reports access verb=... owner=... report=... by=...` line at
  `auth.notice` before anything is read or changed, and never a content; with
  `audit.strict` an access whose line cannot be written is refused. No verb
  writes into another user's home and there is no `generate --as`. A user's own
  `generate`, `rename`, `remove` and `prune` write detail lines.
- A report file is opened without following a link and without waiting, and
  only a regular file is read, so that a file a user grew cannot exhaust the
  memory of the process that reads it with a superuser's reach. `list --json`
  and the export of another user's file to the standard output clean every
  string as `show --content` does (control and formatting characters, escape
  sequences and line separators print as `?`), whether or not the file has a
  valid metadata file; `--out` copies the bytes as they are.
- `generate` refuses a report larger than `reports.max_size` (default 10 MiB)
  and one that would make a user's reports more than `reports.max_count`
  (default 100), names the setting and the way out, and writes nothing. A
  superuser sets the two for the server with `tacctl config reports
  [show|max-size|max-count] [<value>]` (a size is bytes or a number with `Ki`,
  `Mi` or `Gi`, up to 1Gi; a count up to 100000; 0 is no cap), and gives one
  user a value of their own that wins for that user with `tacctl user
  reports-limit <user> [max-size|max-count [<value>|clear] | clear]`. `user
  show` prints a `Report max-size:` and a `Report max-count:` line for a user
  who has an own limit. The keys `reports.max_size` and `reports.max_count` of
  `tacctl.yaml` and the fields `reports_max_size` and `reports_max_count` of a
  user in `store.yaml` are written only when set, so nothing changes for an
  installation that sets none.
- A name in use is refused with the way on that fits the verb: `export --out`
  and `plan --out` say `--force` replaces it, `generate` says to choose another
  name with `--name`, and `rename` to give another new name.

The pages are `docs/devices/reports.md` and the `device reports` entries of
the manual page.

## Devices

- A good `tacctl device config pull` records the members of a Junos virtual
  chassis (`show virtual-chassis status`, with the `show chassis hardware` and
  `show version` it reads already) or a Cisco stack on IOS and IOS-XE (`show
  switch`, with `show inventory` and, when a stack is found, `show version`
  for the release of each switch). Each member is recorded with its id, role
  (`master`, `backup`, `linecard` or `member`; Cisco `Master`, and `Active` as
  IOS-XE 16.x and later print it, are `master`, and `Standby` is `backup`),
  model, serial number, release, status and priority, at most 32 per device.
  A device that lists one unit, has no chassis, refuses a command or prints
  something else has no members and the pull does not fail; a pull that reads
  none leaves the list empty, never the old one.
- `device show` and `device config show` print a `Chassis members:` table
  under the data block, and `device show --json` has a `members` list; they are
  shown to the operator tier and up, as the release, model and serial number
  are. An existing record has no members until its device is pulled again.
- The break-glass firewall line of `tacctl upgrade` and `install` is one short
  sentence: `Break-glass firewall: loaded (reject on tcp/49), no address held.`
  or, with an address held, `Break-glass firewall: 192.0.2.10 refused on tcp/49
  (reject).` The boot unit is described in the break-glass pages, and `status`
  still shows its state.

## Users

- `tacctl upgrade` renames a user whose name has a period, replacing each
  period with `_` (`alice.smith` becomes `alice_smith`). 0.2.20 and 0.2.21
  allowed periods; a name is letters, digits, `_` and `-` since 0.2.22, and the
  upgrade used to refuse while one was stored. The rename carries everything
  that follows a user name: the store record, the user's line in `linux-uids`
  and the user's settings in `console.yaml`. A snapshot is taken first and
  named in the output, and none is taken when no user has a period. Each
  rename is one line with an audit line, followed by a note to tell the people
  to log in with the new name.
- When the new name is taken, the user gets `_` and four random lowercase
  letters or digits after it (`alice_smith_k3x9`) and the line says why; the
  first of two names that meet keeps the name without the suffix. A name that
  is not a user name even with the periods replaced stops the upgrade before
  any change, naming the key to edit in the store. A user whose new name no
  Linux account can have (upper case, or longer than 32 characters) is listed
  after the renames with the reason and the fix.
- The upgrade checks that the ledger and `console.yaml` can take the renames
  before it writes anything. The renames are recorded in `upgrade-renames` in
  the state directory, and an upgrade that stops after the store is finished
  by the next one. Until then `user add`, `user remove` and `user rename`
  refuse a name the record holds, and `store import` and the restore of an
  old-style backup refuse. A key with a period in `console.yaml` that no
  rename covers is dropped, with a line naming it. A second upgrade does
  nothing.
- A user name with a period is not accepted anywhere else: every `user` verb,
  `passwd` and `config linux uid` refuse it, existing or not, and the store and
  `console.yaml` validate user names strictly. A store that still holds one
  fails every write, and `tacctl upgrade` is the way out. `config validate` and
  `tacctl rollback` no longer look for such a user.
- `backup restore` and `backup recover` still read a snapshot that holds such a
  user. A restore says which users have a period, renders nothing, and installs
  the snapshot's `console.yaml` without those users' settings, naming each one;
  `tacctl upgrade` then renames the users and renders. A recovery skips such a
  user, naming it.

## Rollback

`tacctl rollback 0.2.25` is new. It is prepared like the older targets: a dry
run that lists the steps, `--apply` to convert, `--yes` for what needs a
decision. 0.2.25 reads every file this release writes but the limits of the
stored reports, so the target removes `reports.max_size` and
`reports.max_count` from `tacctl.yaml` and the users' own `reports_max_size`
and `reports_max_count` from `store.yaml` (0.2.25 refuses both), and puts back
the per-tier sudoers drop-in 0.2.25 wrote, this release's without the rows of
`device reports`, when the file is exactly this release's text. It takes a
snapshot only when it removes a key or a field. A user's own limit is a
warning that `--apply` refuses without `--yes`, naming each user and the
values; the audit line names the users (`limit-users=`), never a value.

It leaves the chassis `members` of the pull records (0.2.25 ignores the key)
and every report in the users' homes, which are the users' own files and which
0.2.25 cannot list or remove. The closing note says so and names the three
commands that would write a limit again (`config reports max-size`, `config
reports max-count`, `user reports-limit`).

Every other target gets the same removal, the same warning and the same
closing note, since none of them reads the limits. The target `0.2.24`, which
converted nothing before, now removes the limits and puts back the same
sudoers drop-in as `0.2.25`, and the targets `0.2.23` and older name the
users' limits in their warnings. The rollback pages and the manual page list
`0.2.25` as the release before this one.

## Upgrading

`tacctl upgrade` converts one thing: users whose name has a period are renamed,
with a snapshot taken first, and the output names it. A name that is taken gets
a random suffix, so read the lines of the upgrade: the people must log in with
the new name, which is the name typed at a device's login. A name with a period
never had a Linux account, so no account is renamed; the new name gets its
account at the next sync.

Nothing else is converted. The keys `reports.max_size` and `reports.max_count`
and the users' `reports_max_size` and `reports_max_count` are written only when
set, existing pull records have no chassis members until their devices are
pulled again, and the first report creates `~/reports/devices/`.

A snapshot that holds such a user is restorable, with its console keys dropped
as the restore says, and the next `tacctl upgrade` renames the user. A snapshot
taken by the upgrade before its rename is one of them.

## Known limits

- No capture of a Junos virtual chassis or a Cisco stack of more than one
  member was available: the members are read by readers whose multi-member
  fixtures are written by hand from the vendors' documented formats
  (`tests/fixtures/devconf/members/`), and the captures of a device that has no
  chassis or no stack are the only real ones.
- The `software` report has no `gate` column: it is added when the version
  gates exist.
- The limits of the reports are a guard rail against a directory growing, not a
  quota: they count the reports tacctl made (the files with a valid `.meta`
  file) and are not enforced against a user who edits their own directory.
