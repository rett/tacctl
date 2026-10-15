# tacctl 0.2.10

0.2.10 adds a NETCONF service setting for Junos devices and a second
transport for `device config apply`. A scope or a device can say that the
NETCONF service is enabled, disabled or left alone; `apply` can load,
check, commit under a confirmed commit and confirm over NETCONF where a
device offers it, with the command line as before for the rest. The numbered
list in `CHANGELOG.md` (0.2.10, items 1 to 6) is everything that differs from
0.2.9.

"Upgrading" covers 0.2.9 to 0.2.10. Nothing is written to a device unless you
run `device config apply` or `device onboard` and answer its question.

## What changes for existing devices

`device config apply` now chooses its transport per device (`--transport
auto`, the default). A Junos device whose last read found NETCONF answering,
and whose login may commit, is applied over NETCONF; every other device is
applied over the command line as in 0.2.9, and the device's line says why
(`[via cli: NETCONF port closed at the last read]`). A device never read
says nothing and uses the command line.

To keep the 0.2.9 behaviour, either run with `--transport cli` or set it
once:

```bash
tacctl config devices apply-transport cli
```

`netconf` never falls back: a device that does not answer or cannot confirm
is failed with the reason.

Over NETCONF the change is loaded in a private session, checked, committed
under a confirmed commit and confirmed by the session that made it. A
session that closes without confirming is rolled back by the device at once,
and the fresh login still proves the device before the confirming commit.
A device that refuses a confirmed commit in a private session is run again,
whole, in an exclusive one (`[via netconf, exclusive session]`).

## The NETCONF service setting

```bash
tacctl scope netconf <scope> enable [--connection-limit <n>] [--rate-limit <n>]
tacctl scope netconf <scope> disable
tacctl scope netconf <scope> leave              # the default
tacctl device netconf <name> enable|disable|leave|clear
```

- `leave`, the default, plans and compares nothing of the service: a scope
  that never ran these verbs renders, pulls, diffs and plans exactly as in
  0.2.9.
- `enable` renders and plans `set system services netconf ssh`, or the
  statements of the limits that are set; `disable` plans `delete system
  services netconf`. A device's own value wins over its scope's; `clear`
  gives the decision back to the scope.
- `apply` writes only those statements. Everything else under `system
  services` (the SSH service, the web management, a trace option, the port)
  stays on the list of what is never written; a limit the setting states
  none of is the device's own and is kept.
- A change to the service is always made over the command line, because the
  confirmation depends on the service: an enabling change must be answered
  by a NETCONF hello as you before it is confirmed, and a disabling one must
  find the service no longer answering. A probe that cannot tell rolls the
  change back.
- Disabling the service ends it for every NETCONF client of the device, not
  only tacctl's; the plan says so.

## Upgrading from 0.2.9

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade writes nothing to a device and no sudoers drop-in changes.

- **New settings are absent until set.** `device.apply.transport` and the
  `netconf_scope` keys are written to `tacctl.yaml` only when you set them;
  a device's own setting is a `netconf:` map of its `devices.yaml` entry,
  written only by `device netconf`.
- **Records gain a field.** The `applied` part of a record names the
  transport that wrote it (`via`). A record made by 0.2.9 has none and was
  the command line. 0.2.9 ignores the field.
- A device's rendered configuration is unchanged until a scope or a device
  is given a NETCONF setting.

## Known limits

- **The NETCONF transport has not been run against a real device in this
  release.** It is tested against the fake device, which models the
  configuration RPCs, the confirmed commit and the session-close rollback.
  Seven things are still to be confirmed on a real Junos device before
  `auto` can be trusted on a fleet: whether a confirmed commit is accepted in
  a private NETCONF session (N1), what the device does when a session closes
  without confirming and when its connection drops (N2), the reply shapes of
  a load with a bad statement among good ones (N3), a dirty shared candidate
  and another editor's commit during the session (N4), the history the
  device reports as a pending marker (N5), what an open session sees when
  the service is deleted (N6), and a whole enable and disable compared byte
  for byte (N7). Until then `--transport cli` is the proven path.
- The connection and rate limits are checked at 1 to 250 from the Junos
  reference, not on a device.
- A change to the NETCONF service is always made over the command line, and
  `--transport netconf` refuses it.
- `device config rollback` (undoing an apply from the device's commit
  history), device accounts and break-glass rotation, and unattended drift
  detection are not in this release.
- Apply is Junos only; Cisco devices and WTI units are refused as in 0.2.9.

## Rolling back

`tacctl rollback 0.2.9` takes the release before this one as a target, as a
dry run until `--apply [--yes]`:

```
tacctl rollback 0.2.9                  # the dry run: steps, warnings, nothing written
tacctl rollback 0.2.9 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.9          # install 0.2.9
```

It removes `device.apply.transport` and the `netconf_scope` keys from
`tacctl.yaml` and the `netconf:` map of each device from `devices.yaml`
(0.2.9 refuses them; `--yes` is needed while one is set). It rewrites no
drop-in: this release changed none. It lists, and does not delete, what
0.2.10 left that 0.2.9 ignores: the `via` field of the apply records.

**An apply that is not settled stops the rollback**, the dry run too: a
device whose record says `pending` or `unknown` is named with its time and
the command that settles it, `tacctl device config apply <name> --check`
(or `tacctl device config forget <name>` once the device was looked at by
hand). Until 0.2.9 is installed, do not run `scope netconf`, `device
netconf`, `config devices apply-transport` or `device config apply
--transport`; they write the settings again.

`tacctl rollback 0.2.3` works as before and removes the same settings with
the other keys 0.2.3 lacks. `0.2.8` is no longer a target: roll back to 0.2.9
and then use 0.2.9's own `tacctl rollback 0.2.8`.
