# tacctl 0.2.11

0.2.11 hardens the commands that change the configuration and makes a few
things easier to see. There is no change of state format, no new setting and
no new way of writing to a device. The numbered list in `CHANGELOG.md`
(0.2.11, items 1 to 10) is everything that differs from 0.2.10.

## Commands that change the configuration wait for each other

A command that failed put back the whole of `store.yaml`, `tacctl.yaml` and
`rendered.json` from the copies it took at its start, and with them whatever
another command had written in between. The other command had printed
success. The next change then found the rendered file recorded as
hand-edited and was refused.

Every command that changes the store or `tacctl.yaml` now takes one lock,
`.store-apply.lock` in the state directory, from before it copies the files
it may put back to after its last restart:

- A second command prints `Waiting for another tacctl command that is
  changing the configuration...` once and runs when the first is done.
  Ctrl-C ends the wait with `Nothing was changed.` and exit 1.
- It covers the store commands, `config render`, `config
  listen|loglevel|metrics`, the RADIUS listener changes, `backend
  enable|disable`, `store import` and `store rollback`, `backup restore`,
  every write of `tacctl.yaml`, and `upgrade` after its self-update.
  Commands that only read take none.
- A file that was edited by hand while a command ran is saved as
  `<file>.overwritten-<stamp>` in the state directory, and named in a
  warning, before the command puts its own copy back.
- `config validate` warns about a private copy of the configuration that a
  killed command left in the state directory (`.apply.*`, `.restore.*`,
  `.enable.*`, `.units.*`, `.disable.*`) when it is older than ten minutes
  and no command holds the lock.

## Seeing more

- `group preset roles` shows, under each setting it would change, the value
  now and the preset's, and the rules and deny-set patterns removed and
  added, in the form `group reset` uses. A setting that is written without
  changing what applies says so.
- `device list` and `device show` read the backends' logs again when the
  seen cache is older than five minutes, so a login shows without `device
  scan`. Logs only, at most ten seconds, only for a caller who may scan,
  never the first scan of an install, never the catch-up of a cache older
  than `stale-days`; a failure leaves the cache as it was.
- `group list` says when no group has the engineer tier, and `config
  validate` and `group privilege list` name an empty `privileges.<group>`
  that hides a shipped default.
- Completion offers the values of `--tier`, `--wti-level`, `--priv` and
  `group edit <group> tier`; the `config devices` help says the apply
  transport defaults to `cli`.
- The NETCONF connection and rate limits bound the service's own port (830),
  not the SSH subsystem that `device config apply` and the pull use; the
  manual and `docs/cli/scope.md` say so.

## Release tooling

The repository gains its first workflow, `release-reproducible`: when a
release is published it rebuilds both binaries from the tag on a clean runner
and compares them with the published, signed `SHA256SUMS`. `make
release-reproduce TAG=<tag>` does the same by hand. `make release-verify`
also checks both binaries for test knobs and the commit stamp, and `make
release-assets` checks the release metadata first.

## Upgrading from 0.2.10

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no sudoers drop-in changes.

- **New files.** `.store-apply.lock` (empty, mode 0600) in the state
  directory, and `.overwritten-*` copies only when a hand edit was found.
  `uninstall` removes the state directory with them.
- **No new settings.** `tacctl.yaml`, `store.yaml` and `devices.yaml` are
  read by 0.2.10 as they are.
- A 0.2.10 process that is still running while the upgrade finishes does not
  take the lock; this lasts until it exits.

## Known limits

- The lock is taken by tacctl commands. A hand edit of a file, or another
  program writing the state directory, is not serialised; a rollback that
  finds such a change saves it first (above).
- A re-run of `tacctl install` takes no lock.
- The restart of a daemon stays part of the command that changed it; a
  restart that fails leaves the rendered files in place, as before.
- The NETCONF limits were tried on one switch and one Junos release.

## Rolling back

No state changed, so there is no conversion: `tacctl upgrade --branch
0.2.10` installs 0.2.10 over it. Delete `.store-apply.lock` and any
`.overwritten-*` copies only if you want the state directory as it was; 0.2.10
ignores them.
