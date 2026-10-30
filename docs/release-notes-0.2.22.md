# tacctl 0.2.22

0.2.22 fixes what a live network showed (a host key that could not be read,
a Junos virtual chassis that could not be applied to), cleans up the lists,
the `--yes` flag and the answer to an unknown word, adds `host sync|check
--concurrency`, gathers the settings of this server under `tacctl server`,
and adds a timing scale and `--timing` for slow or distant devices. The
numbered list in `CHANGELOG.md` (0.2.22) is everything that differs from
0.2.21.

## Devices

- A device that `ssh-keyscan` reads nothing from, but plain `ssh` reaches
  (a device slow to start its ssh service), gets its host key read by the
  built-in client, one connection at a time.
- A Junos virtual chassis whose master answers without a label is applied
  to: the check, the confirmed commit and the commit.
- `device list` shows network devices only; the enrolled Linux hosts,
  this server included, are in `host list`, which takes the columns and
  filters of `device list`. `device list --differs` keeps the devices whose
  last pull differs from what tacctl renders now.
- `tacctl device timeout-scale`, `scope timeout-scale` and `config devices
  timeout-scale` set a scale from 1 to 10 for the network timings
  used to reach a device (the host-key scan, the ssh and NETCONF connect,
  SNMP, the per-device time of a pull). 1 changes nothing.
- `--timing` on `device config pull`, `diff --pull`, `plan --pull` and
  `apply` shows where the time of each device went.

## Users and hosts

- User names are letters, digits, `_` and `-`. A user stored with a period
  stays readable so that `user rename` can fix it; `config validate` reports
  it and `tacctl upgrade` refuses until it is renamed.
- `host sync|check --concurrency <n>` runs several hosts side by side. The
  default, 1, is as before.

## The command line

- `-y` is gone; `--yes` stays.
- An unknown sub-command is one short answer with a suggestion, and below
  the first word it is given before sudo asks for the password.
- Command names in the lists are teal like the sub-commands.

## The server

- `tacctl server show` shows this server at a glance; `server listen` and
  `server metrics` are `config listen` and `config metrics` moved whole;
  `server name` sets the name the console shows.
- The generated tacquito drop-in and the shipped unit comments name the
  current commands.

## Rollback

`tacctl rollback 0.2.21` is new. It removes `server.name` and the timing
scale keys, which 0.2.21 cannot read, converts nothing else and needs no
`--yes`.

## Upgrading

The first render after the upgrade rewrites the tacquito drop-in (its
comment changed) and restarts tacquito once. A user name with a period
stored: `tacctl upgrade` replaces the binary and the tacquito build, then
refuses; rename the user and run it again. After a rollback, the older
release reports the rendered config as out of date until its first render.
