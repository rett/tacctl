# tacctl 0.2.16

0.2.16 closes what 0.2.15 left open on the host side. The UID ledger gets a
lock, `host enroll` checks names again after its script has run, a held host
is worded as a host in the rendered backend files, and `config validate`
refuses a stray argument. There is no new setting and no new way of writing
to a device. The numbered list in `CHANGELOG.md` (0.2.16, items 1 to 6) is
everything that differs from 0.2.15.

## The UID ledger has a lock

`linux-uids` was read and written by several commands with nothing between
them. Two `host sync` runs that met a new user each took the same next
number, so the user got two lines or two users shared a number. Every
command that writes the ledger or decides from it now holds
`/etc/tacctl/.linux-uids.lock` for its read-and-write window and nothing
longer: `host enroll`, `host sync` and `config linux script` while they work
out the users (never while the script runs on a host), `config linux uid`,
`config linux uid-range`, the move of `user rename`, and the put of
`backup restore`. Every snapshot copies the ledger under it. A command that
finds the lock held waits up to 30 seconds, then stops with nothing changed.
Commands that only show the ledger take no lock. `--keep-uids` takes none.
No file format changes.

## Host names

`host enroll` repeats its check of the new name against the device registry
after the client script has run, under the device registry's lock. A host and
a device can no longer end up with one name because a `device add` finished
while the script ran. A conflict takes the registry line back, exits 1, and
warns of what the command did before the script (the host's own scope opened
to both protocols, a `--staging` bench address) with the command that undoes
it. `host enroll` also refuses a new name that a break-glass hold is recorded
under, as `host rename` already did.

The comment block of `tacquito.yaml` and the RADIUS `clients.conf` reads
`(host <name>)` for a hold on an enrolled host and `(device <name>)` for a
held device. `backup restore` words a hold by the registry it puts back,
rendering the files again after the host files are in place.

## `config validate`

`config validate extra` refuses the word (`Unknown argument: 'extra'`, exit
status 1, no report). `--fix-names` counts a host renamed whose own scope is
refused as renamed, prints one line for the scope with the command to retry
it, and no longer offers the scope a second time in the same run; the run
exits 1 because a name was not offered.

## Upgrading from 0.2.15

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no file is converted. The ledger lock
file is created by the first command that needs it. The pinned
`actions/upload-artifact` of the reproducible-build workflow moves to 7.0.2.

## Known limits

- A `host sync` that gives a number out in the few seconds between the
  snapshot a `backup restore` takes and the put of the ledger is in neither
  the note nor the undo.
- `config linux uid-range` writes `tacctl.yaml` between its two ledger
  windows; a `config linux uid <user> <uid>` that runs between them sees the
  new range.
- Most verbs that change users, groups, scopes or the device registry write
  no audit line to syslog yet. The audit lines are planned for 0.2.17
  (`docs/plans/0.2.17-plan.md`).
- The configuration the backends render for an orphan hold (a hold with no
  device or host) still reads `(device <name>)`.

## Rolling back

No state format changed. `tacctl upgrade --branch 0.2.15` installs 0.2.15
over it; 0.2.15 ignores the lock file, and the two releases do not take each
other's locks, so do not run commands of both at once. The ledger itself is
the same file.
