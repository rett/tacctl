# tacctl 0.2.4

0.2.4 reads device configuration. `tacctl device config pull` logs in to the
network devices as you, reads what each one runs, and compares the sections
tacctl manages (AAA, roles, the management filter, SNMP, NETCONF, break-glass
users) with what tacctl would render for that device; `device config diff`
shows the differences, `device config list` the state of every device. It adds
the password cache that lets a batch ask for your network password once,
per-device SNMP settings, and `tacctl rollback 0.2.3`. The numbered list in
`CHANGELOG.md` (0.2.4, items 1 to 17, grouped by theme) is everything that
differs from 0.2.3; the item numbers below point into it. **Nothing is written
to a device:** the walkthroughs of 0.2.3 are still how a device is configured.

"Upgrading" covers 0.2.3 to 0.2.4.

## What is new

### Reading device configuration

- **`tacctl device config pull`** (item 1). Names (`a,b`), or `--all`, or
  `--scope`, `--vendor` and `--stale` together. The login is the user who
  invoked tacctl, never root, with that user's tacctl password (asked for
  once, without echo, never stored); an unpinned host key refuses the device
  (`device hostkey <name> accept`), a changed one is `host-key-mismatch`.
  Junos is read over NETCONF where the device answers and over an ssh exec
  channel otherwise (`--transport auto|netconf|ssh`); IOS and IOS-XE over the
  ssh command line. One line per device, then a summary (`12 ok, 2 differ, 1
  failed`); `--diff`, `--json`, `--timeout`, `--max-failures`, and
  `--concurrency` (never above `device.config.max_concurrency`, default 8).
  The first rejected password stops the batch; the first Ctrl-C stops starting
  devices, a second cuts the running ones off. Exit status: 0, 1 (a device
  failed), 2 (wrong arguments), 130 (interrupted); differences are not
  failures.
- **`tacctl device config diff`** (item 2). The managed sections of the last
  pull against what tacctl renders now: `-` a statement the device lacks, `+`
  one it has that tacctl does not render, `!` a reordering, `?` a secret the
  login could not see, `=` a secret that is present. `--pull` reads first,
  `--section`, `--json`, `--exit-code` (exit 2 on a difference, as `git
  diff`).
- **Records** (items 3, 4, 5). A pull keeps
  `/var/lib/tacctl/devices-config.json` and
  `/var/lib/tacctl/device-config/<name>.yaml` (derived, never in a snapshot).
  `device config list [--stale]` computes each device's state (`ok`,
  `differs`, `never`, `failed`) against today's rendering; `device config
  forget` deletes records. `device list` gains a CONFIG column and `device
  show` a Configuration row (operator tier and up); `device check` shows what
  the last NETCONF probe found.
- **`tacctl config devices`** (item 6) sets `device.config.max_concurrency`
  (1-64, default 8), `device.config.transport` (default `auto`) and
  `device.config.timeout` (10-600 seconds, default 90).

### The password cache

- **Off until you open it** (items 8-11). `tacctl console password-cache tiers
  operator,engineer,superuser|none` (default `none`), `idle` (1-120 minutes,
  default 15) and `max` (1-24 hours, default 8). The login console keeps your
  network password in the memory of your session for the tiers listed, and
  `tacctl shell --password-cache` asks the same policy; a pull, a diff and the
  `ssh` lines after it then ask once. `console forget` (a word of the shell
  and the console) forgets it now; it is also forgotten at the end of the
  session, after the idle time, after the maximum lifetime, when you change
  your password, and when a device refuses it.
- **Never stored.** The password lives in a locked page of the session's own
  process, zeroed when forgotten, in no file, log, argument or environment.
  The agent answers only while one of the four command lines that use it runs
  (`device config pull`, `device config diff`, `ssh`, `device ssh`), only the
  same user or root, once, with a token made for that line. `tacctl ssh` uses
  it for a device with a pinned host key, through `SSH_ASKPASS`.
- A password a pull prompted for is stored only after a device accepted it;
  one that came from the cache is never stored again, so the maximum lifetime
  cannot be stretched by use.

### Per-device SNMP settings

- **`tacctl device snmp <name> [show [--reveal] | version | port | timeout |
  clients | community | v3-user | clear]`** (items 13-15) gives one device its
  own SNMP version, port, wait, allowed clients and credentials over its
  scope's and the default's: the device's value, then the scope's, then the
  default's, then the built-in, one setting at a time. The non-secret settings
  are an optional `snmp:` map in `devices.yaml`; the credentials are
  `/etc/tacctl/snmp/devices/<name>.yaml` (0600).
- **Where it shows** (item 14). `device show`, `device check`, `scope snmp
  <scope> show`, `device config show` and the walkthrough say which value is
  used and where it comes from; the name and location reads and the SNMP
  section of a pull use the device's own settings.
- **Tiers and snapshots** (item 15). Setting and clearing are the superuser's;
  an engineer reads the devices of their own scopes and each `--reveal` is
  logged (`secret-read kind=snmp-device`). Snapshots hold `snmp/devices/`, and
  a credential is snapshotted before it changes. A device's credentials file
  counts only while the device has an `snmp:` map; one without (what a rollback
  leaves) is ignored and said once by `device show`.

### Tiers

| Verb | Tier |
|---|---|
| `device config list`, the CONFIG column and the Configuration row, `console forget` | operator |
| `device config show`, `pull`, `diff`; `device snmp <name> [show [--reveal]]` | engineer, for the devices of their own scopes |
| `device config forget`, `config devices`, `console password-cache`, `device snmp` setters and `clear` | superuser |

The tiers sudoers drop-in carries the new rows (item 7).

### Rollback and the test build

- **`tacctl rollback 0.2.3`** (item 16) replaces the 0.2.2 target of 0.2.3's
  tool; see "Rolling back".
- **Test builds only** (item 17): `tacctl _fake-device` and two environment
  knobs; the installed binary has neither.

## Upgrading from 0.2.3

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
There is nothing to re-paste on a device and nothing to decide before you run
it.

### What `tacctl upgrade` does by itself

- **The tiers sudoers rules** are rewritten when the file is installed and
  differs from this release's rules (`Updated: tiers sudoers`): the operator
  gains `device config list` and `console forget`, the engineer `device config
  show|pull|diff` and `device snmp`, and `TACCTL_ASKPASS` is kept for the four
  command lines that use the password cache. **An upgrade never creates the
  file**: without `/etc/sudoers.d/tacctl-tiers` the lower tiers have no sudo
  rows for tacctl (`tacctl config sudoers tiers install`).
- **The group drop-in** (item 12) that `tacctl config sudoers install <group>`
  wrote is rewritten the same way when it is exactly the text an earlier
  release wrote for the group its header names (`Updated: sudoers for group
  <name>`, after `visudo -cf`; when `visudo` refuses, a warning and the old
  file). A file an administrator edited is left as it is with `customised`,
  naming `tacctl config sudoers install <group>`; a file that is not tacctl's,
  a current one and an absent one are left alone.
- Nothing else changes: no rendered backend file, no unit file, no device
  template, no setting in `tacctl.yaml`, `console.yaml` or `devices.yaml`. The
  man page and the shell completion are refreshed as at every upgrade.

There is nothing else to do.

### Settings that start in their defaults

- **The password cache is off** for every tier until `tacctl console
  password-cache tiers <tiers>` opens it. Decide who may keep a network
  password in session memory; the lifetimes (15 minutes idle, 8 hours at most)
  are in "Known limits".
- **`device.config.*`** start at 8 concurrent devices, transport `auto` and 90
  seconds per device; they are written to `tacctl.yaml` only when you change
  them with `tacctl config devices`.
- **No device has SNMP settings of its own**, and no device has been read:
  `device list` shows `never` in the CONFIG column of a device a pull can read
  until the first pull.

### Behaviour changes that may surprise

- **`device list` and `device show`** have a CONFIG column and a Configuration
  row for the operator tier and up (`config` in `--json`); `device check` has
  NETCONF and SNMP rows (`netconf` and `snmp` in `--json`). A script that
  reads these tables by column position should read `--json`. `device list
  --stale` keeps its meaning (not seen in the logs); the configuration's
  staleness is `device config list --stale`.
- **`tacctl rollback 0.2.2` is refused** on this release (each release's tool
  prepares the state for the one before it); see "Rolling back".
- **The operator tier's `device config show`** refusal now names the verb.
- **`tacctl ssh`** with a cached password and a pinned host key starts ssh as
  you directly, without sudo, with the user's own ssh configuration left out;
  without a cached password nothing changes.

## Rolling back

`tacctl rollback 0.2.3` prepares the state for the earlier release; going back
is not a plain checkout, because 0.2.4 writes keys a 0.2.3 binary refuses
(`console.yaml` and `devices.yaml` are read strictly; its `config validate`
and `backup restore` report or refuse a `tacctl.yaml` with a key it does not
know).

```
tacctl rollback 0.2.3                  # the dry run: every step and warning, nothing written
tacctl rollback 0.2.3 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.3          # install 0.2.3: switches the clone to the tag, builds, re-executes
```

- **`--apply`** takes a snapshot, then removes
  `device.config.max_concurrency`, `.transport` and `.timeout` (and any key
  0.2.3 does not know) from `tacctl.yaml`, `settings.password_cache` from
  `console.yaml` (the cache is off again; every other setting stays), and the
  `snmp:` map of every device from `devices.yaml` (the devices are read with
  their scope's or the default's settings again). It rewrites the tiers
  sudoers drop-in and the group drop-in with 0.2.3's text, after `visudo -cf`,
  when the file is exactly this release's text; an edited file, or one
  `visudo` refuses, is left and named. A second `--apply` changes nothing.
- **It leaves, and lists:** `snmp/devices/` (0.2.3 never opens the
  subdirectory; after an upgrade, 0.2.4 ignores a device's file until the
  device has settings of its own again, since its `snmp:` map gates the file,
  and `device snmp <name> clear` removes it), the records of the pulls in
  `/var/lib/tacctl` (`devices-config.json`, `device-config/`: derived and
  never snapshotted, ignored by 0.2.3), `store.yaml` and the rendered backend
  files. Nothing is re-rendered or restarted. **`tacctl device config forget
  --all` before the rollback** deletes the records if you do not want them
  kept.
- **Warnings that need a human:** `--apply` refuses without `--yes` while a
  setting is dropped (a device's own SNMP settings, the `device.config`
  values, the cache's tiers and lifetimes). They stay in the snapshot.
- **`--hosts`** is accepted and does nothing: 0.2.4 changed nothing on the
  enrolled Linux hosts.
- **Until 0.2.3 is installed** (between `rollback --apply` and `upgrade
  --branch 0.2.3`), do not run a command that writes the console's settings, a
  device's SNMP settings or `config devices`: it writes the 0.2.4 form again.
  If one did, run `tacctl rollback 0.2.3 --apply` again.
- **The snapshot holds the 0.2.4 form.** Restore it with 0.2.4 (`tacctl backup
  restore`), not with 0.2.3, whose restore refuses a `tacctl.yaml` with a key
  it does not know. The fallback that needs no tool is `tacctl backup restore
  <id>` of a snapshot of the time you want back; it loses what changed since.
- **Back to 0.2.2 is two steps:** `tacctl rollback 0.2.3 --apply --yes` and
  `tacctl upgrade --branch 0.2.3`, then, with 0.2.3 installed, its own `tacctl
  rollback 0.2.2 --apply --yes --hosts` (the 0.2.3 notes describe it) and
  `tacctl upgrade --branch 0.2.2`.

## Known limits

- **WTI units are not read.** A WTI unit named in `device config pull` is
  recorded `unsupported` and the run exits 1; `--all`, `--scope` and `--stale`
  leave it out and say so; `device list` shows `-` in the CONFIG column.
- **Cisco reads are not lab-tested.** The IOS and IOS-XE extraction and
  comparison are written from the vendor references and verified against
  reference texts and fixtures, not against a live device. Three shapes are
  assumptions: `aaa session-id common`, the `privilege` parent lines IOS adds,
  and the `snmp-server user` lines, which `show running-config` does not print
  (they are not compared). A Cisco device is never read over NETCONF; the
  Junos reader is tested against captured Junos output (a superuser's and an
  engineer's masked view).
- **Secrets are compared by presence only.** A changed server key, community
  or hash is not a difference; a missing one is. No output, record or file
  holds a device's secret value. A login that cannot see secrets (a Junos
  class without the secret permission) gets `?` for a statement the device
  omits.
- **Pulls need a person.** The login is yours and the password is never
  stored, so there is no unattended pull; the cache is for an interactive
  session only (`-c` and batch lines use none, and the plain CLI from bash
  asks per run).
- **The password cache and what it does not protect against.** It protects the
  password against other users and against its landing in files, logs,
  arguments or the environment, and it is forgotten after 15 minutes without a
  use or 8 hours after it was cached (both settable). Root can read any
  process, and hibernation can write the locked page to disk. A process of
  your own user that reads the environment of a running pull or ssh line, and
  reaches the cache's socket before that line's one request, is answered as
  the line would be.
- **Nothing is written to a device.** `config cisco|juniper|wti` print
  walkthroughs; the engineer provisions a device by pasting them. Everything
  0.2.3 lists as not lab-tested (the SNMP syntax of the three vendors, the
  SHA-256 keywords, the WTI menus and IP Tables, the NETCONF steps, the IOS
  behaviours the baseline depends on) is unchanged.
- **Selection** is by name, scope, vendor and staleness; there is no tag.
