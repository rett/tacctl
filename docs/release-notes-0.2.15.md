# tacctl 0.2.15

0.2.15 finishes the host work of 0.2.14. A restore no longer runs beside a
rotation, a sync no longer uses up a snapshot, several hosts can be synced
or checked in one command, `config validate` gains a JSON form and can
rename the names it flags, and a restore can leave the UID ledger alone.
There is no new setting and no new way of writing to a device. The numbered
list in `CHANGELOG.md` (0.2.15, items 1 to 9) is everything that differs from
0.2.14.

## Restores and snapshots

`backup restore` (and `config restore`) now tries the per-host lock that
`host provisioner rotate`, `host rename` and `host forget` hold, for every
host in the live registry and in the snapshot's, without waiting. If another
command holds one it stops before the snapshot of the current state, changes
nothing and names the host; run it again when that command has finished. The
restore can no longer interleave with a running rotation. The three
refusals for a busy host lock read the same way.

`--keep-uids` restores a snapshot's registry, host records and staging but
not the UID ledger. Use it when the snapshot is wanted for its users,
groups, scopes or devices and the hosts have synced since: the live ledger
is the one the hosts agree with. A restored user with no line gets one at
the next `host sync`.

A `host sync` or `host enroll` writes `last_sync` and `facts` into each
host record on every run. The comparison that decides whether the state
equals the newest snapshot now ignores both and compares the `provisioner`
entry only, so a sync no longer makes the next command take a snapshot.
The snapshot that a restore takes first still compares everything, so its
undo puts the records back as they were.

## Several hosts at once

`tacctl host sync <name>...` syncs the hosts named, in the order typed, as
`--all` would. Every name is checked before the first host is touched: an
unknown name or a host with a break-glass hold among them refuses the whole
run, and names together with `--all` are a usage error. A host that fails
does not stop the others and the exit status is 1.

`tacctl host check <name>... | --all [--json]` is the read-only comparison
of `host show <name> --check` for several hosts: one result each (`as
tacctl would make it`, its differences with the command that fixes each,
`skipped` for a held host, or `could not be checked`), a count by state, and
exit status 1 when a host differs or could not be checked. `--json` prints
an array. It is the superuser's and changes nothing here or on any host.

## `config validate`

`config validate --json` prints one object: `valid`, `errors`, `warnings`,
`mode`, `counts`, `backends` and `findings`, each finding with a `section`,
a `level`, its `text`, the `fix` that puts it right and, where they apply,
`backend` or `hosts`. Nothing else goes to standard output and the exit
status is the text report's. The verb stays the operator's: the sudoers rule
gains the exact `config validate --json` row. An option other than `--json`
is now a usage error.

`config validate --fix-names [-y]` follows the report with one question for
each device, host, user and scope that has upper case in its name
(`Rename user 'Alice' to 'alice'? [y/N]:`). Each rename is the existing verb
with its own snapshot, so each can be undone separately. A name whose
lower-case spelling is taken is not offered and its line names the verb that
picks another name. It is the superuser's and needs the store.

## Smaller changes

- The client script's UID check no longer says `Nothing was changed.` when
  an account was renamed earlier in the same run, and the line for a renamed
  account shows the account's own UID.
- `host list` counts the `Names:` findings about hosts in its footer, and
  `host list --json` lists them under `findings`.
- `device config apply --hold` takes an answer typed before the first
  question as that device's answer, and an answer after a device's window
  is dropped instead of given to the next device. This also closes an
  occasional wrong rollback when the review's answer and the hold's were
  typed together.

## Upgrading from 0.2.14

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade rewrites the operator sudoers drop-in for `config validate
--json`. Nothing is written to a device and no file is converted. The
client script is the one `host sync` sends, so each host has the new wording
from its next sync.

## Known limits

- `host enroll` checks the device name before its script runs on the host,
  which can take minutes, and does not check again: a host and a device can
  still end up with one name that way. `config validate` reports it.
- The configuration the backends render still reads `(device <name>)` in a
  comment for a held host.
- Until every host has synced a user rename, do not give the old name to a
  new user: that host's UID check refuses the sync.
- The ledger has no lock of its own: a `host sync` that reads it at the
  moment of a rename sees the file before or after it.

## Rolling back

No state format changed. `tacctl upgrade
--branch 0.2.14` installs 0.2.14 over it; the operator sudoers drop-in keeps
its extra `config validate --json` row, which sudo accepts, until the next
`tacctl upgrade` rewrites it. `tacctl rollback` to 0.2.3 recognises the
0.2.15 and 0.2.14 texts of the drop-in as tacctl's own.
