# tacctl 0.2.8

0.2.8 records what each device reports about itself, gates statements on the
device's release, extends the IOS blocks to VRFs and informs hosts, logs the
address of the person behind a device's login, and colours help and listings
on a terminal. The documentation is now a tree of topic pages. The numbered
list in `CHANGELOG.md` (0.2.8, items 1 to 14) is everything that differs from
0.2.7.

"Upgrading" covers 0.2.7 to 0.2.8. Nothing is written to a device by tacctl:
the walkthroughs and the plan print what a person pastes.

## What is new

- **Device facts** (item 6). A pull records the release, model and serial
  number of the device. `device show` has `Release:`, `Model:` and `Serial:`
  rows, `device config list` a `RELEASE` column, and `--json` of `device
  show`, `device list` and `device config list` the fields `release`,
  `model` and `serial`.
- **Statements gated on the release** (item 7). A Junos walkthrough sets
  `idle-timeout` per login class for a device whose recorded release is older
  than 16.1; the statements a release lacks are rows of one table
  (`internal/devices/gates.go`).
- **IOS blocks** (items 8, 9). The `system` and `snmp` blocks take the VRF
  forms (`ntp server vrf`, `ip name-server vrf`, `ip domain name vrf`, `ip
  domain list vrf`) and `snmp-server host ... informs`. A trap host is
  identified by address, vrf, kind, `udp-port` and community. The compare
  reads `clock timezone UTC 0` as present on a device with no `clock
  timezone`, and an IOS 12.x device is compared without the default `version
  3` of an NTP server.
- **Where a login came from** (items 2, 3). tacquito's authentication lines
  carry the client's address and port (patch `0003`), and the `auth.info` and
  `auth.warning` lines of `tacctl ssh` and `device ssh` carry `from=<address>`.
- **Colour only on a terminal** (items 10, 13). `NO_COLOR` and
  `TACCTL_COLOR=always|never` decide; help text and the shell's `?` listing
  are highlighted. The sudoers drop-ins keep both variables through sudo.
- **`tacctl help`, `version --long`** (items 11, 12). The help names the
  project, copyright holder and licence; `version --long` no longer asks for a
  password through sudo.
- **A tree of topic pages** (item 1, 5). `README.md` is the quick start and an
  index; the reference is under `docs/`. `install` and `upgrade` no longer put
  a copy of the README in `/etc/tacquito`.
- **Go 1.27.2** (item 14), and the restore point's `archive config` form no
  longer carries the "not lab-tested" note (item 4).

## Upgrading from 0.2.7

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.

- **Sudoers.** The per-tier drop-in and an unedited group drop-in are
  rewritten (`version --long`, and `NO_COLOR TACCTL_COLOR` in `env_keep`); an
  edited group drop-in is left, with the warning that names `tacctl config
  sudoers install <group>`.
- **tacquito** is rebuilt with patch `0003`; the service restarts once. The
  `accepting user` lines gain `; client [<address>] port [<port>]`.
- **Go** 1.27.2 replaces 1.26.2 as the toolchain the host builds tacquito
  with, fetched and verified by the installer.
- **`/etc/tacquito/README.md`** is removed (`Removed: README.md`).
- **Release, model and serial** are empty until a device is pulled again with
  `tacctl device config pull`.
- A device's rendered configuration is unchanged, except a Junos device whose
  recorded release is older than 16.1 and an IOS 12.x device with NTP servers
  (see above); neither is changed until you run `device config plan`.

## Limits

- Not run on a device: the system block's NTP key lines, a banner with
  another delimiter, and the VRF forms on IOS 12.4 (where the syntax is
  `ip vrf`).
- Facts are read from commands the device may refuse; a field it refuses is
  empty and the pull still succeeds.

## Rolling back

0.2.8 adds no key, file or entry that 0.2.7 refuses. The record fields
`release`, `model` and `serial` are ignored by older releases. `tacctl
upgrade --branch 0.2.7` goes back; the group drop-in 0.2.8 wrote is then
reported as edited and left, and `tacctl config sudoers install <group>`
writes 0.2.7's text again. `tacctl rollback 0.2.3` works as in 0.2.7 and puts
0.2.3's sudoers text back over both drop-ins.
