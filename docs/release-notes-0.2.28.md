# tacctl 0.2.28

0.2.28 gives the tacctl console a built-in file transfer: SFTP, which `sftp` and the `scp` of
OpenSSH 9 or later speak. It is off by default for every tier but the superuser tier, and a
superuser decides who else has it, with a quota on the home and an optional rate. The release
also drops the tail of a long command's echo from the support bundle of a Cisco IOS device,
and `tacctl rollback 0.2.27` is a target. The numbered list in `CHANGELOG.md` (0.2.28) is
everything that differs from 0.2.27.

## File transfer through the console

In 0.2.27 the console refused `scp` and `sftp` as it refuses every program, so the `scp` line
that `device reports show` prints could not be used by a user whose login shell is the
console. This release serves that line.

**File transfer through the console: its settings, off by default.** A superuser decides who has
the console's file transfer. Every form of `console
file-transfer` is the superuser's, the reads included.

```bash
tacctl console file-transfer operator enable
tacctl console file-transfer user alice enable
tacctl console file-transfer user alice clear
tacctl console file-transfer
```

- `console file-transfer <tier> enable|disable` opens it to a tier and `console
  file-transfer user <name> enable|disable|clear` to one user, over the tier's setting in
  both directions, as `console system-shell` does: an enable lasts only while the user stays
  in the tier it was set for (a move to another tier leaves it listed as stale), a disable
  holds in any tier, `clear` returns the user to the tier's setting, and `user rename` and
  `user remove` move or drop a user's settings.
- It is off for every tier but the superuser tier, which always has it and cannot be
  disabled. Unlike the system shell and forwarding, the engineer tier is not closed to it,
  because a transfer reaches the user's home only. A caller with no tier never has it.
- The quota is the bytes the whole home may hold: 256M for the readonly, operator and
  engineer tiers and none for the superuser tier until it is set (`console file-transfer
  quota <tier> <size>|unlimited|default`, `quota user <name> <size>|unlimited|clear`). The
  rate is the bytes a second a transfer may go at, off by default (`rate <tier> <size>|off`,
  `rate user <name> <size>|off|clear`). A size is a number of bytes or a number with `K`,
  `M`, `G` or `T` (powers of 1024: `512K`, `256M`, `2G`), printed back in the largest unit
  that holds it exactly. Zero, a negative number, a fraction, an overflow and more than `1T`
  are refused, and a user's value wins over the tier's.
- With no argument, `console file-transfer`, `quota` and `rate` list the tiers and the
  users with a setting of their own. `console show`, which the operator tier and up can run,
  lists each tier's state, quota and rate and each user's next to the system shell.
- The settings are `settings.file_transfer` in `console.yaml`, written only when something
  in it is not the built-in setting. They apply from the next console login, are logged as
  `console set key=file-transfer` at `auth.notice`, and reach the console through `tacctl
  _console-policy`. The console fails closed: a policy it cannot read is no file transfer.

**The console serves SFTP to the accounts that have file transfer.** The sftp subsystem,
which sshd's `ForceCommand` hands to the console, is no longer refused for everyone: for an
account that has file transfer the console serves the protocol itself, as the logged-in user
(no change of privilege), so the file system's permissions apply as they do in the user's
shell.

- **Clients.** `sftp alice@tacacs.example.net` and the `scp` of OpenSSH 9 or later (which
  speaks SFTP) work, for example
  `scp alice@tacacs.example.net:reports/devices/inventory-20261106.csv .`. `scp -O`, `rsync`,
  programs and shell words stay refused with `the tacctl console does not run programs or
  shell commands; file transfer is SFTP only (sftp, scp of OpenSSH 9 or later)`.
- **The home is the root.** The user's home directory, as the account database names it and
  never `$HOME`, is `/`, and `..` does not leave it. `.ssh` is not listed and every request
  for it is refused. No symbolic link is followed, and neither a symbolic link nor a hard
  link can be created through the console. A file that already has more than one name (a
  hard link made outside SFTP) cannot be opened, downloaded or written, and its mode and
  times cannot be changed (refused, reason `link`); it can still be listed, renamed and
  removed. The owner cannot be changed. The reports and support bundles of the user are in
  the home, so a user can fetch them.
- **The quota.** The home may hold 256M by default (none for superusers; per tier and per
  user, see above). The quota counts the sizes of the regular files, each inode once, the
  reports, the support bundles and `.ssh` included, never directories, links or inodes. A
  write that would take the home over it is refused whole (`disk quota exceeded`), and so is
  a size that would grow a file over it. The size of a regular file can be set (cut, or
  extended with zeros), which is what `scp` does after an upload; it counts like a write.
- **The rate.** The rate is off by default. When set it is the bytes a second one session
  moves, reads and writes together, with a burst of one second; a transfer at its rate
  waits, it is not refused.
- **Modes.** The console's umask is 077. A new directory gets the mode the client asks for
  and a new file 0644, both reduced by the umask, so a directory is 0700 and a file 0600;
  the set-user-ID, set-group-ID and sticky bits are ignored. So a file uploaded with `scp`
  has no executable bit; a client that wants another mode sets it afterwards (for example
  the `chmod` of `sftp`), which is applied as given. Setting the mode of a directory without
  the owner's read and search bits is refused.
- **What the clients show.** The OpenSSH `sftp` and `scp` show only `Failure` for a refused
  write over the quota (the reason, `reason=quota`, is in the audit log), and an upload
  refused part way leaves what was written before in the home. An account without file
  transfer gets `file transfer is not enabled for this account; an administrator can switch
  it on (tacctl console file-transfer)` (status 126), which the clients show only as
  `Connection closed`, since sshd shows no error text of a subsystem; `reason=file-transfer`
  is in the audit log.
- **The audit.** A transfer is in the console's own log under the tag `tacctl-console`:
  `console sftp start` (the tier, the home, the quota and the rate in effect), one line for
  each upload, download, delete, rename, mkdir and setstat, each with `tier=`, `console sftp
  DENY ... reason=` for each refused request at `auth.warning` (`.ssh`,
  `outside-the-home`, `symlink`, `link`, `quota`, `unsupported`, `bad-path`,
  `too-many-open-files`), and `console sftp end` (the bytes up and down, the requests, the
  refusals). A path is logged as a double-quoted string with control characters escaped and
  cut at 200 bytes. A refused subsystem is `console DENY ... reason=file-transfer|
  password-change|policy|home|stream subsystem=sftp`. A successful `stat`, listing,
  `readlink` or `realpath` is not logged.
- **What sshd and the server need.** sshd starts the subsystem only if its configuration
  defines `Subsystem sftp ...` (the stock `sshd_config` of Debian and Ubuntu does), which a
  `Match` block cannot. `console file-transfer` with no argument and `console show` print
  `sshd sftp subsystem: <program>` or `none` and warn in red when file transfer is on for a
  tier other than the superuser tier, or for a user, and sshd defines none. Changing a mode
  or times goes through `/proc/self/fd`, so `/proc` must be mounted.
- **The session.** The console's idle timeout does not apply to a transfer: it lasts as long
  as the connection and ends with status 0 when the client closes it. A protocol error ends
  it with status 1 and one line on standard error. A listing comes in the order of the file
  system, not sorted, and a session has at most 256 files and listings open at once (reason
  `too-many-open-files`).

The pages are `docs/cli/console.md` (File transfer), `docs/security/login-console.md`,
`docs/security/audit.md`, `docs/devices/reports.md` and the manual page.

## Known limits

- The quota is measured per session, so N sessions of one user at once can reach about N
  times the quota.
- The quota counts the sizes of regular files only. A file deleted while a session's handle
  still holds it stays counted until the handle is closed, and a directory in the home that
  the session cannot read or search (for example one owned by root with mode 0700) makes
  the home count as full: every upload that grows it is refused with `disk quota exceeded`
  until the directory is readable.
- The console does not honour the mode a client asks for on a new file: it is 0644 under the umask,
  and the client sets another mode afterwards (see Modes).
- If `logger` cannot write an audit line, the warning `The audit line was not written
  (logger: <reason>); the command continues.` can appear on standard error and the transfer
  goes on, unaudited.

## The support bundle of a Cisco IOS device

**A support bundle from a Cisco IOS device no longer starts the identity lines with the tail
of the command.** 0.2.27 dropped the echo of a command longer than the terminal is wide, but
only when the first line of the answer was the start of the command. On a Cisco 2811 the
file of `show running-config | include ^(hostname|ip domain|clock timezone|snmp-server
location|snmp-server contact)` began with the tail of the command after a `$` (the `$` is
where the device cut its display), and then the `hostname` line. The tail is dropped as well
now: a first line of `$` and pieces of the command, the last of which ends the command, is
the echo, whether or not the start of the echo stands before it. Nothing else is dropped: a
line with text that is not in the command, a tail that does not end the command, and an
output line that begins with `$` stay. The page is `docs/devices/support-bundle.md`.

## Rollback

**`tacctl rollback 0.2.27`, the release before this one, is a target.** It converts nothing
but the file transfer settings of `console.yaml`. 0.2.27 and every older release reject the
key `settings.file_transfer` (their reader answers `settings: unknown key 'file_transfer'`),
so every `tacctl rollback` target removes it. With those settings set, `--apply` takes a
snapshot first, removes the key, keeps every other setting, needs no `--yes` and ends with a
note: until the older release is installed, run no `tacctl console file-transfer` that sets
something, and the snapshot holds the 0.2.28 state, which only 0.2.28 restores. The settings
are kept nowhere else: set them again after the upgrade.

With the settings unset, `rollback 0.2.27` removes no key and no field, takes no snapshot
and needs no `--yes`. The limits of the stored reports, the chassis members of the pull
records, every report in the users' homes (the PDF ones included), the marker
`/var/lib/tacctl/pdf-tools-offered` with its packages, the per-tier sudoers drop-in and the
other settings 0.2.27 knows all stay. It is refused while a device's apply is not settled,
and it ends with `tacctl upgrade --branch 0.2.27`. `rollback 0.2.26` and older behave as
before, and `tacctl rollback` now takes fourteen targets. What this release changed outside
the stored files is 0.2.27's to undo or keep: after the rollback the support bundle of a
Cisco IOS device starts its identity lines with the tail of a long command's echo again.

## Upgrading

`tacctl upgrade` converts nothing in this release. File transfer is off for every tier but
the superuser tier after the upgrade, so nothing changes for a user until a superuser runs
`tacctl console file-transfer`; superusers have it at once, with no quota. Before switching
it on for others, check that sshd defines `Subsystem sftp ...` and that `/proc` is mounted
(`tacctl console show` checks the first). Existing reports, bundles and settings are read as
they were.
