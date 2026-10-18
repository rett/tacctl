# tacctl 0.2.14

0.2.14 is about enrolled Linux hosts and the names things are given. A
break-glass hold follows its device when the address changes and can be put
on a host; a host can be renamed and forgotten without ssh; a snapshot holds
the host state; new names are lower case; and `user rename` keeps the user's
Linux UID. There is no new setting and no new way of writing to a device.
The numbered list in `CHANGELOG.md` (0.2.14, items 1 to 10) is everything
that differs from 0.2.13.

## Break-glass holds

`device address` on a held device used to be refused until the hold was
released, and releasing answered the old address again. It now moves the
hold. The new address must pass what a new hold passes (not a loopback
address, not one a listener binds, not an enrolled host's address, not held
by another record, covered by a scope), and one line names both addresses
and asks to confirm (`-y` skips it). The registry and the record are
written together, rendered once, and each backend whose file changed is
restarted once. A refused address changes nothing; a restart that fails is
reported as `NOT restarted` and the verb exits 1, with both on the new
address.

`tacctl breakglass hold|release|list` now name hosts and devices alike, with
the same record and the same carve-out: the server answers no login and no
sudo check for the host's address, while the host's local administrator and
its console keep working. A host is held by its name. The verbs that log in
to the host (`host sync`, `host show --check`, `host target`, `host
provisioner rotate`, `host unenroll`, and enrolling a registered host) refuse
for a held host and attempt nothing; `host sync --all` skips it. `host list`
and `host show` mark a held host, and engineers see the holds of the hosts in
their own scopes. A name that is both a host and a device is refused as
ambiguous.

## Host names, `host rename` and `host forget`

A new host name follows the device rules: no tacctl word (`all`, `scope`,
`local`), no generic name, and no name equal to an enrolled host or a
registered device in any case. A refusal changes nothing and attempts
nothing over ssh. A missing option value in `host enroll` is a usage error
that names the option instead of a silent exit 1. Two enrolments of one name
started together can no longer both be written.

`tacctl host rename <old> <new>` is the superuser's and local: nothing is
sent to the host, so a held host may be renamed. After a snapshot it renames
the registry line, the pinned keys, address and history, the record, the
staging addresses, the hold and the host-key scan result. What an earlier
host of the new name left behind is listed and replaced after a confirmation.
When the host's scope is `linux-<old>` and no other host uses it, the command
offers to rename the scope too; `--yes` answers both questions.

`tacctl host forget <name>` drops this server's record of a host (registry
line, pins, record, staging addresses, scan result) after a snapshot, with no
ssh; the host itself is not touched. `host unenroll` now drops the staging
addresses too. `config validate` and `host list` report two names equal
ignoring case, a host named like a device, two hosts at one address and
port, and a pin, record or staging entry no registry line has, each with the
verb that repairs it.

`host list --json` prints the hosts as an array (name, target, port, scope,
server, method, address, users, drift, hold, findings), the table has an
ADDRESS column, and `host show` says `no record under this name` for a host
with no record. The engineer sudoers rule gains `host list --json`.

## Snapshots hold the host state

A snapshot now also holds `linux-hosts`, `hosts/`, `staging` and
`linux-uids`. `linux-hosts` is in every snapshot, empty when there is no
registry, so the first snapshot after the upgrade is taken once even when
nothing else changed. `host enroll`, `host move` (one snapshot for `--all`)
and `host unenroll` take a snapshot just before the registry changes.

`backup restore` of a snapshot that knows the hosts puts the four back under
the apply lock; the snapshot it takes first holds the live files, so the
restore can be undone. No host is touched. Before the question and after the
restore a note names the hosts that come back, go or are registered
differently, and every user whose UID the restored ledger drops or changes,
since a host may already hold that number. A snapshot of 0.2.13 or older
leaves the host files alone, and `backup diff` says so.

## Lower-case names

`device add|rename`, `host enroll|rename`, `user add|rename` and `scope
add|rename` refuse a name with an upper-case letter. Names that exist with
upper case keep working as they are: nothing is migrated, and a rename to the
lower-case spelling is how one is fixed. `config validate` lists each in a
`Names:` warning with the verb that renames it. `device import`, a CSV and
`store import` load such names as they are and say how many. The name
derived from a target's host name is lowercased silently.

## `user rename` keeps the UID

The ledger line of the old name becomes the new name's, in place, inside the
apply lock after the snapshot. At the next `host sync` the client script
renames the account on each host (`usermod -l`: the login name only, the home
keeps its path) instead of removing it and creating another. This holds for
a host that was offline or a user renamed twice, for a host on an earlier UID
range, and for a disabled user or one kept without a login. A user who is
logged in defers the rename to the next sync. A new name that already has a
UID keeps it and a warning says the old account is removed. The script
protocol stays 6; a script written by an earlier release with `config linux
script` has no rename and stops at the UID check until it is written again.

## Host verbs

`host enroll`, `host move`, `host rename` and `host forget` take `-y` as well
as `--yes`, and their questions have the shape of the device questions.

## Upgrading from 0.2.13

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade rewrites the engineer sudoers drop-in for `host list --json`.
Nothing is written to a device and no file is converted. The client script
that renames accounts is the one `host sync` sends, so each host has it from
its next sync.

## Known limits

- `host enroll` checks the device name before its script runs on the host,
  which can take minutes, and does not check again: a host and a device can
  still end up with one name that way. `config validate` reports it.
- `backup restore` does not wait for a running `host provisioner rotate`.
- The configuration the backends render still reads `(device <name>)` in a
  comment for a held host.
- Until every host has synced a user rename, do not give the old name to a
  new user: that host's UID check refuses the sync.
- The ledger has no lock of its own: a `host sync` that reads it at the
  moment of a rename sees the file before or after it.

## Rolling back

No state format changed: 0.2.13 ignores the new snapshot entries.
`tacctl upgrade --branch 0.2.13` installs 0.2.13 over it and recognises the
new sudoers drop-in as tacctl's own. Release any hold on a host first (`tacctl
breakglass release <host>`); 0.2.13 treats such a record as an orphan.
