# tacctl 0.2.12

0.2.12 finishes the lock work of 0.2.11, finds leftovers in the store that
`config validate` did not, and lets `breakglass hold` and `release` take
several devices at once. There is no change of state format, no new setting
and no new way of writing to a device. The numbered list in `CHANGELOG.md`
(0.2.12, items 1 to 8) is everything that differs from 0.2.11.

## Breakglass holds for several devices

`tacctl breakglass hold sw1=<reason>,sw2 --reason "<text>"` holds a list of
devices in one command, each with its own reason after `=` or the `--reason`
default. `tacctl breakglass release sw1,sw2` releases a list. The list is one
argument; quote it when a reason holds a space.

- The list is best effort. Each device is checked as a single one is; the
  ones that pass are held together in one write, one render and one restart
  of each backend, and every refused or already-held device is named with
  its reason on a `Not held:` line (`Not released:` for a release). The exit
  code is 1 when any device was not held or released.
- The names that pass are typed back, comma separated, to confirm.
- One device is held, asked and reported exactly as before.

## Finding leftovers

- `config validate` now warns of settings that name a group or scope the
  store does not have, for `privileges.<group>`, `commands.<group>` and every
  per-scope key, as it did for `tier`, `wti_level` and `junos` (`Orphan
  settings:`).
- It also warns of files that belong to a device or scope that is not
  registered: the records of a device's last pull, and SNMP credentials of a
  device or a scope (`Orphan files:`), with the command that removes each
  where there is one.
- Both are warnings; the exit code does not change.

## Smaller changes

- `config get` and `config get-list` complete every key of the schema, and
  the groups and scopes of the store after a family prefix such as `tier.` or
  `snmp_scope.`.
- A re-run of `tacctl install` over a live store takes the apply lock from
  the seed to the end of the start phase, as `upgrade` does. Ctrl-C while
  `install` or `upgrade` waits for it says that the store, `tacctl.yaml` and
  the services were not changed and to run the command again.
- The plan and the diff name a source interface typed inside `aaa group
  server` as an older per-group form; nothing is rendered differently.
- The sentences that explain the tier a verb needs are a field of the tier
  table; no help text changes.

## Release tooling

A `test` workflow runs the Go tests on every pull request and on pushes to
`develop` and `master`: gofmt, `go vet`, every package but `internal/cli`
with the race detector, and `internal/cli` in four shards, each with and
without the test knobs. The actions of both workflows run on Node 24 and are
pinned by commit. The bats suite, the diff corpus and the container matrix
stay on the maintainer's machine.

## Upgrading from 0.2.11

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no sudoers drop-in changes. No file is
added or converted; `tacctl.yaml`, `store.yaml` and `devices.yaml` are read
by 0.2.11 as they are.

## Known limits

- The orphan warnings do not remove anything; removing a setting or a file is
  a hand edit or the named command.
- A device named by its name and by its address in one hold list is a usage
  error, not two holds.
- The container matrix and the bats suite are not run in CI.

## Rolling back

No state changed, so there is no conversion: `tacctl upgrade --branch
0.2.11` installs 0.2.11 over it.
