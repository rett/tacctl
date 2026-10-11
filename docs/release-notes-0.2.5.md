# tacctl 0.2.5

0.2.5 reads device configuration and says what to paste to make a device
match. `tacctl device config pull` logs in to the network devices as you,
reads what each one runs, and compares the sections tacctl manages (AAA,
roles, the management filter, SNMP, NETCONF, break-glass users) with what
tacctl would render for that device; `device config diff` shows the
differences, `device config list` the state of every device, and `device
config plan` turns the last pull into a report in plain words and one region
that a technician copies once and pastes once, with the check, the follow-up
and the back-out beside it. The Cisco walkthrough is now a standard AAA block
(a `CONSOLE` login list, `enable` asking the server first, a hardening
checklist as Step 0), the operator and the viewer can no longer interrupt
service even intermittently, `tacctl breakglass hold` makes the server stop
answering one device so that its local accounts can be used while the server
is up, a password cache lets a batch ask for your network password once, a
device can have SNMP settings of its own, and `tacctl rollback 0.2.3` prepares
the state for the earlier release. **Nothing is written to a device by
tacctl:** the walkthroughs and the plan print what a person pastes. The
numbered list in `CHANGELOG.md` (0.2.5, items 1 to 81; the numbers 62 to 69
are not used) is everything that differs from 0.2.3; the item numbers below
point into it. Items 1 to 29 were drafted under the working name 0.2.4; there
is no 0.2.4 release.

"Upgrading" covers 0.2.3 to 0.2.5.

## What is new

### Reading device configuration

- **`tacctl device config pull`** (item 1). Names (`a,b`), or `--all`, or
  `--scope`, `--vendor` and `--stale` together. The login is the user who
  invoked tacctl, never root, with that user's tacctl password (asked for
  once, without echo, never stored); an unpinned host key refuses the device
  (`device hostkey <name> accept`), a changed one is `host-key-mismatch`.
  Junos is read over NETCONF where the device answers and over an ssh exec
  channel otherwise (`--transport auto|netconf|ssh`); IOS and IOS-XE over the
  ssh command line, never NETCONF. One line per device, then a summary (`12
  ok, 2 differ, 1 failed`); `--diff`, `--json`, `--timeout`,
  `--max-failures`, and `--concurrency` (never above
  `device.config.max_concurrency`, default 8). The first rejected password
  stops the batch; the first Ctrl-C stops starting devices, a second cuts the
  running ones off. Exit status: 0, 1 (a device failed or was refused), 2
  (wrong arguments), 130 (interrupted); differences are not failures.
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
  forget` deletes records; `device rename` carries a record along and `device
  remove` drops it. `device list` gains a CONFIG column and `device show` a
  Configuration row (operator tier and up); `device check` shows what the
  last NETCONF probe found.
- **`tacctl config devices`** (items 6, 38) sets `device.config.max_concurrency`
  (1-64, default 8), `device.config.transport` (default `auto`),
  `device.config.timeout` (10-600 seconds, default 90) and
  `device.config.confirm_timeout` (`confirm-timeout`, 1-60 minutes, default
  5, the wait of a Junos plan's confirmed commit).
- **What a Cisco pull records and compares** (items 23, 24, 27, 28, 32, 60,
  61). The read adds `show version | include Version`; the image's version
  line is kept on the record as `os`, and the configuration syntax derived
  from it as `syntax`. The comparison reads how the console and VTY lines log
  in and whether the device has an `enable` secret (by presence), takes the
  forms IOS stores for what was typed as the typed ones (`snmp-server
  queue-length`, the shortened `privilege exec` line of an image that lacks
  the last words, the parents IOS adds), and treats the `privilege exec
  level N <command>` line that IOS 15.x and IOS-XE keep at the command's own
  level after a `no` as the image's own: neither compared nor reported.
  `aaa session-id common` is a statement like the others. A device whose
  version line maps to no syntax is never guessed: it is `needs pull (syntax
  unknown)` until it is pulled or has a setting.
- **The configuration syntax is a setting of its own** (items 25-29).
  `tacctl device config-syntax <name> [auto|ios12|modern]` (also `device add
  --config-syntax`) is the syntax a Cisco device is compared and walked
  through in; with `auto` it comes from the last pull's version line. `legacy-ssh`
  is the ssh algorithms and nothing else (items 26): a router of IOS 15.6 or
  IOS-XE 16.7 may need it and still speak the modern `tacacs server NAME`
  syntax. A setting the pull's image contradicts wins and is shown
  (`syntax_conflict`).
- **Old IOS over ssh** (items 21, 22). `legacy-ssh` also offers the CBC
  ciphers IOS 12.4 has, and `device add` and the host-key re-scans read a
  `legacy-ssh` device's key with the built-in client when `ssh-keyscan`
  reads none (no password is ever sent).
- **Smaller changes.** The Junos walkthrough writes the management filter's
  deny terms as plain `set` statements (item 20). `tacctl uninstall` removes
  the device records of `/var/lib/tacctl` (item 19).

### The password cache

- **Off until you open it** (items 8-11). `tacctl console password-cache tiers
  operator,engineer,superuser|none` (default `none`), `idle` (1-120 minutes,
  default 15) and `max` (1-24 hours, default 8). The login console keeps your
  network password in the memory of your session for the tiers listed, and
  `tacctl shell --password-cache` asks the same policy; a pull, a diff, a
  plan with `--pull` and the `ssh` lines after it then ask once. `console
  forget` (a word of the shell and the console) forgets it now; it is also
  forgotten at the end of the session, after the idle time, after the
  maximum lifetime, when you change your password, and when a device refuses
  it.
- **Never stored.** The password lives in a locked page of the session's own
  process, zeroed when forgotten, in no file, log, argument or environment.
  The agent answers only while one of the command lines that use it runs
  (`device config pull`, `device config diff --pull`, `device config plan
  --pull`, `ssh`, `device ssh`), only the same user or root, once, with a
  token made for that line. `tacctl ssh` uses it for a device with a pinned
  host key, through `SSH_ASKPASS`.
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
  a credential is snapshotted before it changes.
- **The map gates the file** (item 18). A device's credentials file counts
  only while the device has an `snmp:` map; one without (what a rollback
  leaves, or a stray) is ignored and said once by `device show`, with
  `clear` as the way out.

### The standard Cisco AAA block

- **One block for every Cisco device** (item 30). `config cisco` and `device
  config show` print, and the managed `aaa` section is, the same lines in one
  order: `aaa new-model` first, the server block and its group, the login
  lists, exec authorization, accounting, `aaa session-id common`, the
  `privilege exec level` lines, SNMP, the VTY access list, the NETCONF step
  (commented) and the console and VTY login leaves. Command authorization is
  a Step 2 of its own, typed after a check that a session of your own
  account gets in, because a server that answers `fail` for a name it does
  not know never falls through to `local`.
- **The console has a list of its own, and `enable` asks the server first**
  (items 31, 32). `aaa authentication login CONSOLE local` keeps a local
  user able to log in on the console while the server is up (at privilege 1);
  `aaa authentication enable default group <G> enable` makes `enable` ask the
  server, so nobody types it with the server up, and the local enable secret
  is the way to privilege 15 only while no server answers. There is no enable
  password in the login path.
- **A source interface per scope** (item 33). `tacctl config cisco
  source-interface <scope> <interface>|none` is rendered as `ip tacacs
  source-interface` (`ip radius source-interface`) and compared; unset,
  nothing is rendered or compared and the walkthrough prints the line
  commented.
- **Nothing is renamed** (item 34). The server block `TACACS`, its group
  `TACACS-GROUP`, `VTY-ACL` and `TACCTL-SNMP` are the names tacctl has always
  rendered; the old forms a device may carry are listed as extras, and
  `device config plan` replaces or removes them.
- **Step 0** (items 35, 36) is a commented hardening checklist, the local
  enable secret and the scope's break-glass accounts, which moved there from
  the end so that the local user exists before AAA is turned on. A device
  configured from an earlier walkthrough reads as missing the new lines until
  they are pasted.

### Planning a change: `device config plan`

- **The report first, then one region** (items 37, 41, 49). Per device, from the
  last pull: the irregularities in plain words (missing, different, out of
  order, extra, a secret not visible, not plannable for this login, each
  with its section, severity `ACCESS`, `MONITORING` or `COSMETIC`, and what
  the paste does about it), one region between `PASTE FROM HERE` and `PASTE
  TO HERE`, the check and the one line to type yourself afterwards, and the
  back-out as comments. `--plain` (for `load set <file>`), `--json`, `--out`,
  `--out-dir` (0600 files, written as the user who ran sudo, an existing file
  refused unless `--force`, `COVER.txt` for several devices). It writes to no
  device and reads one only with `--pull`.
- **Safe when pasted whole** (item 38). On Junos the region is `configure
  private`, the statements, `show | compare | no-more`, `commit check` and
  `commit confirmed N comment "..."`: without the one word `commit`, typed
  after the check, the switch undoes the paste in N minutes. On IOS the
  region is `configure terminal`, the lines and `end`; the change is live
  and nothing rolls it back by itself, and the report says so and asks for a
  second privilege-15 session. `write memory` is typed by hand. The region
  never holds a `breakglass` or `netconf` statement, a plain `commit`,
  `exit`, `rollback`, `write memory`, `reload`, or a `line` header.
- **`--converge` and `--backout`** (items 39, 40, 46-48, 51-55). A statement
  the standard does not have is reported with the line that removes it and
  left alone; `--converge` makes a separate cleanup region for a device
  that has nothing else to paste (a device with a first region gets that
  region and the cleanup comes after it is pasted and verified), limited to
  the scope's own protocol and never removing what a staying statement
  names. Every plan with changes keeps its back-out beside the record, and
  `--backout` prints it after the check pull.
- **Secrets** (item 42). A secret the device lacks is typed in its line and
  the output says `THIS OUTPUT HOLDS THE TACACS+ KEY OF SCOPE <scope>`; one
  it has, or one the login could not see, is neither printed nor changed
  unless `--secrets`; `--no-secrets` leaves each as a comment.
- **Cisco** (items 43, 50). The region follows the standard's order and holds
  command authorization back until the pulled configuration already uses the
  scope's server; a server entry of another name at the standard's address is
  replaced in an order that keeps the pasting session.
- **Who** (items 44, 45). An engineer plans the devices of their own scopes;
  a section their Junos login class cannot commit is not in the region and
  the report says `Not fixable by this login`. A Junos pull also reads the
  plain view, so a statement a group applies is never changed.

### Operator and viewer rules

- **An operator cannot interrupt service, even intermittently** (items 56,
  57, 59). The shipped `operator` rules and privileges lose `monitor
  capture` and the `clear` forms (`counters`, `line`, `ip arp`, `arp-cache`,
  `mac address-table dynamic`), and `ping` and `traceroute` stay only as
  one-line forms with every number inside a bound (`repeat 1-1000`, `size
  1-9999`, `timeout 1-10`, `probe 1-10`, `ttl 1-255`); the interactive dialog
  and `sweep` are denied, for the viewer (`readonly`) too. The engineer runs
  every form. `privileges.operator` is `undebug all` alone, and the rendered
  `privilege exec` lines are `level 1 show running-config` and `level 7
  undebug all` and nothing else. On Junos `OP-CLASS` has no `clear` bit, and
  the role preset's operator denies `clear` and `monitor traffic` whole and
  both lower roles deny `ping ... rapid` and `ping ... interval`. `group
  commands seed` writes the shipped rules, so it cannot hand an operator
  what was removed.
- **Moving from 0.2.3's rules** (item 58). The upgrade drops a stored
  `privileges.operator`, `commands.operator` or `commands.readonly` that is
  exactly what 0.2.3 shipped and names every other stored value that still
  carries a removed entry; see "Upgrading".

### Break-glass hold

- **`tacctl breakglass hold <device> --reason "<text>"`** (items 70, 71)
  makes the server stop answering one registered device, so that the device's
  local accounts can be used while the server is up; `release <device>`
  answers it again, and `list [--json]` shows the holds. It is the
  superuser's, asks for the device's name typed back at a terminal, has no
  timer and no automatic release, and prints the way in for the device's
  vendor. The renderers take the device's registered address out of every
  scope's prefixes (a `/24` becomes the eight prefixes that do not hold it);
  the store is never changed, `release` renders the original bytes, and each
  is one restart of each backend whose file changed.
- **Shown wherever the device is shown** (items 72, 73). `status`, `device
  show|list|check`, `device scan`, `scope routing|show|list|lookup` and
  `config validate`; `device address` and `device remove` of a held device
  and a pull of one are refused (a batch skips it); a plan of the last pull
  works and says so; `backup restore` names the devices held now and after.
- **What it carves, and what it does not** (item 77). Only the registered
  address: a device that sends its AAA from another address (a source
  interface, a NAT) is still answered, and the report says so.
- **Records and failures** (items 78-81). A record holds a device only while
  the device is registered at the record's address; any other is an orphan,
  shown as such and removed by `release`. A restart that failed is reported
  as not restarted and the command exits 1. Two superusers cannot both hold
  one device.
- **Tiers, log and rollback** (items 74-76). `hold` and `release` are the
  superuser's, `list` an engineer's for the devices of their own scopes; both
  log the reason; `tacctl rollback` is refused while a hold stands. The
  README and the manual page say how to use the console's local login on
  purpose.

### Tiers

| Verb | Tier |
|---|---|
| `device config list`, the CONFIG column and the Configuration row, `console forget` | operator |
| `device config show`, `pull`, `diff`, `plan`; `device config-syntax`; `device snmp <name> [show [--reveal]]`; `breakglass list`; `config cisco source-interface <scope>` (reading), for the devices and scopes of their own | engineer |
| `device config forget`, `config devices`, `console password-cache`, `device snmp` setters and `clear`, `config cisco source-interface` (setting), `breakglass hold` and `release` | superuser |

The tiers sudoers drop-in carries the new rows (item 7).

### Rollback and the test build

- **`tacctl rollback 0.2.3`** (items 16, 29, 36, 75) replaces the 0.2.2 target
  of 0.2.3's tool; see "Rolling back".
- **Test builds only** (item 17): `tacctl _fake-device` and two environment
  knobs; the installed binary has neither.

## Upgrading from 0.2.3

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Read "What a person decides or does" afterwards: the upgrade ends with a red
notice about the operator rules, and the devices are yours to re-paste.

### What `tacctl upgrade` does by itself

- **The tiers sudoers rules** are rewritten when the file is installed and
  differs from this release's rules (`Updated: tiers sudoers`): the operator
  gains `device config list` and `console forget`, the engineer `device config
  show|pull|diff|plan`, `device config-syntax`, `device snmp` and `breakglass
  list`, and `TACCTL_ASKPASS` is kept for the command lines that use the
  password cache. **An upgrade never creates the file**: without
  `/etc/sudoers.d/tacctl-tiers` the lower tiers have no sudo rows for tacctl
  (`tacctl config sudoers tiers install`).
- **The group drop-in** (item 12) that `tacctl config sudoers install <group>`
  wrote is rewritten the same way when it is exactly the text an earlier
  release wrote for the group its header names (`Updated: sudoers for group
  <name>`, after `visudo -cf`; when `visudo` refuses, a warning and the old
  file). A file an administrator edited is left as it is with `customised`,
  naming `tacctl config sudoers install <group>`; a file that is not tacctl's,
  a current one and an absent one are left alone.
- **The operator rules** (item 58). A `privileges.operator`,
  `commands.operator` or `commands.readonly` in `tacctl.yaml` that is exactly
  what 0.2.3 shipped is removed, with an info line each, and the shipped
  values of this release apply on every install, a RADIUS-only one included;
  the same exact match is dropped when the `tacquito.yaml` of an installation
  without a store is migrated. Any other stored value is kept.
- **A red notice** ends the upgrade (see below). It is shown once by the first
  upgrade onto this release (the marker `operator-policy-noted` in
  `/var/lib/tacctl`; a fresh install writes it at once and `tacctl uninstall`
  removes it) and again at each upgrade while a stored setting still carries
  a removed entry. `tacctl config validate` prints the stored settings as a
  warning, `Operator policy:`, which does not fail the validation.
- Nothing else changes: nothing is written to a device, no template of yours
  is replaced (the new version is beside it as `<name>.template.new`), and
  the man page and the shell completion are refreshed as at every upgrade.

### Settings that start in their defaults

- **The password cache is off** for every tier until `tacctl console
  password-cache tiers <tiers>` opens it. Decide who may keep a network
  password in session memory; the lifetimes (15 minutes idle, 8 hours at most)
  are in "Known limits".
- **`device.config.*`** start at 8 concurrent devices, transport `auto`, 90
  seconds per device and a confirm timeout of 5 minutes; they are written to
  `tacctl.yaml` only when you change them with `tacctl config devices`.
- **No device has SNMP settings of its own**, no device has been read (`device
  list` shows `never` in the CONFIG column of a device a pull can read until
  the first pull), and no device has a configuration syntax setting (`auto`).
- **No scope has a Cisco source interface**: nothing is rendered or compared
  until `tacctl config cisco source-interface <scope> <interface>` sets one.
- **No break-glass hold stands.**

### What a person decides or does

- **Devices configured by an earlier walkthrough keep the lines they were
  given.** Run `tacctl device config pull <device>` then `tacctl device
  config plan <device>` (or `--all`, `--scope`, `--vendor`): it prints the
  report and the one region that brings the device to this release's
  standard, in the form its image stores each line. A Cisco device reads as
  missing `aaa authentication login CONSOLE local`, `aaa authentication
  enable default group <G> enable`, `aaa session-id common` and the console's
  `login authentication CONSOLE` (items 30, 31, 36); a Junos device keeps
  `clear` in `OP-CLASS` until its Step 1 is pasted again (item 57). Pull
  needs a pinned host key (`device hostkey <name> accept`) and your own
  tacctl account with the device's scope.
- **The operator rules reach the devices only when the lines are removed.**
  Until then a device's operators keep the old reach whenever the server does
  not answer, and always over RADIUS. The notice lists the lines. On Cisco,
  in configuration mode:

  ```
  no privilege exec all level 7 ping
  no privilege exec all level 7 traceroute
  no privilege exec all level 7 monitor capture
  no privilege exec level 7 clear counters
  no privilege exec level 7 clear line
  no privilege exec level 7 clear ip arp
  no privilege exec level 7 clear arp-cache
  no privilege exec level 7 clear mac address-table dynamic
  ```

  On Junos:

  ```
  delete system login class OP-CLASS permissions clear
  ```

  `device config plan` prints exactly the lines a pulled device needs; an
  IOS 15.x image keeps a default-level line such as `privilege exec level 15
  clear counters` after a `no`, which is the image's own and is not reported.
- **Stored settings the notice names.** Look at each with `--dry-run`, then run
  the command it names: `tacctl group privilege reset operator`, `tacctl
  group commands reset <group>`, or, for the values 0.2.3's `group preset
  roles` stored (its `show` deny and the Junos deny sets), `tacctl group reset
  <group> --preset --only commands,junos` (`--only junos` for the Junos set
  alone), which puts the preset's current value back and loses no deny.
- **A Cisco device the version line does not map** (IOS 11.x, IOS 15.0 and
  15.1, an IOS XR unit) is refused by a pull until `tacctl device
  config-syntax <name> ios12|modern` says what it speaks.
- **Custom Cisco templates** in `/etc/tacctl/templates` keep their text; the
  walkthrough templates were rewritten (item 30) and the new version is
  written beside yours as `<name>.template.new`: compare, and take what you
  want.
- **Decide** who may keep a network password in session memory
  (`console password-cache tiers`), and a source interface per scope if the
  devices send their AAA from one.
- **Check** that `/etc/sudoers.d/tacctl-tiers` exists (`tacctl config sudoers
  tiers install`), or the lower tiers have no sudo rows for the new verbs.

### Behaviour changes that may surprise

- **`device list`, `device show` and `device check`** have a CONFIG column and
  a Configuration row for the operator tier and up (`config` in `--json`),
  NETCONF, SNMP and Config syntax rows and a Break-glass row or state
  (`netconf`, `snmp`, `syntax` and `breakglass` in `--json`). A script that
  reads these tables by column position should read `--json`. `device list
  --stale` keeps its meaning (not seen in the logs); the configuration's
  staleness is `device config list --stale`.
- **`config cisco` and `device config show` print a different block** (items
  30-35): the order, the `CONSOLE` list, the hardening checklist in Step 0,
  command authorization as a step of its own after a check, and the
  `privilege` lines shortened to the two the operator rules leave.
- **`legacy-ssh` no longer decides the Cisco syntax** (items 25, 26): a
  device that needs the SHA-1 algorithms and speaks the modern syntax is
  compared and walked through in it.
- **A privilege line removed from a device is not reported** when the image
  keeps its own default-level line (items 60, 61).
- **`tacctl rollback 0.2.2` is refused** on this release (each release's tool
  prepares the state for the one before it); see "Rolling back".
- **The operator tier's `device config show`** refusal names the verb, and a
  tier denial of `device config pull|diff|plan` is logged.
- **`tacctl ssh`** with a cached password and a pinned host key starts ssh as
  you directly, without sudo, with the user's own ssh configuration left out;
  without a cached password nothing changes. A held device is warned about
  and connected.
- **`tacctl uninstall`** removes the device records of `/var/lib/tacctl`.

## Rolling back

`tacctl rollback 0.2.3` prepares the state for the earlier release; going back
is not a plain checkout, because 0.2.5 writes keys a 0.2.3 binary refuses
(`console.yaml` and `devices.yaml` are read strictly; its `config validate`
and `backup restore` report or refuse a `tacctl.yaml` with a key it does not
know). The real 0.2.3 release, built from its tag, is run against the state
before and after in the test suite.

```
tacctl rollback 0.2.3                  # the dry run: every step and warning, nothing written
tacctl rollback 0.2.3 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.3          # install 0.2.3: switches the clone to the tag, builds, re-executes
```

- **A break-glass hold stops it** (item 75), the dry run too: the older
  release has no such record, so the device would stay unanswered until its
  first render and then be answered without anyone releasing the hold. The
  refusal names each held device; `tacctl breakglass release <device>`, then
  run it again.
- **`--apply`** takes a snapshot, then removes `device.config.max_concurrency`,
  `.transport`, `.timeout` and `.confirm_timeout` and every
  `cisco.source_interface.<scope>` (and any key 0.2.3 does not know) from
  `tacctl.yaml`, `settings.password_cache` from `console.yaml` (the cache is
  off again; every other setting stays), and the `snmp:` map and the
  `config_syntax` key of every device from `devices.yaml` (the devices are
  read with their scope's or the default's settings again, and the older
  release compares a `legacy-ssh` Cisco device as IOS 12.x again). It rewrites the
  tiers sudoers drop-in and the group drop-in with 0.2.3's text, after
  `visudo -cf`, when the file is exactly this release's text; an edited file,
  or one `visudo` refuses, is left and named. A second `--apply` changes
  nothing.
- **It leaves, and lists:** `snmp/devices/` (0.2.3 never opens the
  subdirectory; after an upgrade, this release ignores a device's file until
  the device has settings of its own again, since its `snmp:` map gates the
  file, and `device snmp <name> clear` removes it), the records of the pulls
  in `/var/lib/tacctl` (`devices-config.json`, `device-config/`: derived and
  never snapshotted, ignored by 0.2.3), `store.yaml` and the rendered backend
  files. Nothing is re-rendered or restarted, and nothing is changed on a
  device. **`tacctl device config forget --all` before the rollback** deletes
  the records if you do not want them kept.
- **The shipped rules of 0.2.3 permit the commands again.** An installation
  on the shipped rules is told by 0.2.3's `config validate` that its rendered
  configuration is out of date until `tacctl config render` there brings the
  permits back.
- **Warnings that need a human:** `--apply` refuses without `--yes` while a
  setting is dropped (a device's own SNMP settings or configuration syntax,
  the `device.config` values, a scope's source interface, the cache's tiers
  and lifetimes). They stay in the snapshot.
- **`--hosts`** is accepted and does nothing: 0.2.5 changed nothing on the
  enrolled Linux hosts.
- **Until 0.2.3 is installed** (between `rollback --apply` and `upgrade
  --branch 0.2.3`), do not run a command that writes the console's settings,
  a device's SNMP settings or configuration syntax, a scope's Cisco source
  interface or `config devices`: it writes the 0.2.5 form again. If one did,
  run `tacctl rollback 0.2.3 --apply` again.
- **The snapshot holds the 0.2.5 form.** Restore it with 0.2.5 (`tacctl backup
  restore`), not with 0.2.3, whose restore refuses a `tacctl.yaml` with a key
  it does not know. The fallback that needs no tool is `tacctl backup restore
  <id>` of a snapshot of the time you want back; it loses what changed since.
- **Back to 0.2.2 is two steps:** `tacctl rollback 0.2.3 --apply --yes` and
  `tacctl upgrade --branch 0.2.3`, then, with 0.2.3 installed, its own `tacctl
  rollback 0.2.2 --apply --yes --hosts` (the 0.2.3 notes describe it) and
  `tacctl upgrade --branch 0.2.2`.

## Known limits

- **WTI units are not read or planned.** A WTI unit named in `device config
  pull` is recorded `unsupported` and the run exits 1; `--all`, `--scope` and
  `--stale` leave it out and say so; `plan` cannot plan one; `device list`
  shows `-` in the CONFIG column.
- **Cisco ASA is not supported.** There is no `asa` vendor, no walkthrough and
  no read for it: a unit registered as `cisco` has a version line that maps to
  no syntax (a pull is refused until a setting is given, which would compare
  it as IOS), and its command syntax is not IOS's.
- **Nothing is written to a device.** `config cisco|juniper|wti` and `device
  config plan` print what a technician pastes. The WTI menus, IP Tables and
  RADIUS walkthrough are not verified on a unit, and the README's "Not
  lab-verified" list for the SNMP and NETCONF steps stands.
- **What was not checked on a device.** The plan's Junos `commit confirmed N
  comment "..."` line (the `comment` form; `commit confirmed N` and its expiry
  were); what an RADIUS server answers to IOS's `enable` request (the RADIUS
  walkthrough carries the line commented and neither renders nor compares
  it); the one-line `sweep` form of `ping`, and whether the `vrf` and `mpls`
  forms are level 15 on an image; whether IOS 11.x, 15.0 and 15.1 use the
  `tacacs server NAME` syntax (believed from 15.2); which Junos bit `test
  interface restart-auto-negotiation` needs; the `snmp-server user` lines,
  which `show running-config` does not print and are not compared; whether
  IOS takes a named `tacacs server` block beside an old `tacacs-server host`
  entry at the same address.
- **IOS has no automatic rollback of a plan.** There is no revert timer on
  IOS, because on 15.x it reverts only while the session that armed it stays
  open; the change is live at `end`, and the report asks for a second
  privilege-15 session until the end.
- **Junos deny sets apply where they are sent.** The removal of the `clear`
  bit is the protection every install has; `ping ... rapid`, `ping ...
  interval` and an unbounded `monitor traffic` are denied only where the role
  preset, sets of your own or the RADIUS `Juniper-Deny-Commands` attribute
  send the deny sets. Over RADIUS and with the server unreachable, an
  operator has IOS's own basic `ping` and `traceroute` and nothing beyond
  them.
- **A hold carves one address.** The device's registered address only; a
  device that sends its AAA from another address is still answered. Nothing a
  held device does is accounted on the server.
- **Secrets are compared by presence only.** A changed server key, community
  or hash is not a difference; a missing one is. No output, record or file
  holds a device's secret value, except a plan, which types a secret the
  device lacks and says so. A login that cannot see secrets (a Junos class
  without the secret permission) gets `?` for a statement the device omits.
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
- **Selection** is by name, scope, vendor and staleness; there is no tag.

## Verified against

The behaviour was checked against these images, stated generically:

- **Junos 25.4R1** (an EX-series switch): the configuration text over an ssh
  exec channel, the NETCONF `<command>` RPC and `<get-configuration
  format="set"/>` is the same; an engineer-class login gets secrets masked or
  omitted; the NETCONF probe states; 8, 16 and 32 concurrent sessions; `commit
  confirmed N` and its expiry; what an `EN-CLASS` login can and cannot load
  (the management filter, not the server, accounting, login classes or SNMP);
  comments in a paste, `insert`, and `configure private` with another
  session's uncommitted work. Loads were made in a private session and rolled
  back, or under `commit confirmed` and compared with the configuration
  beforehand.
- **IOS 12.4(15)SW** (a 7200 router emulator): the read, the statements the
  legacy rendering uses, what `show running-config` stores for each, the
  lock-outs, and timed replace; a sanitised capture of its running
  configuration is a test fixture. The ITP image of a 2800-series router
  (12.4(15)SW4) is the same train; its version line was taken from a paste,
  not read live.
- **IOS 15.6(2)T** (a virtual router): the standard block pasted line by
  line and backed out, the version line, the stored forms, the privilege
  lines the image keeps, and the revert timer's behaviour that dropped it from
  the plan.
- **IOS-XE 16.7.1** (a virtual router): the version line, the comparison
  against the standard block and the standard block pasted and verified end
  to end; it needs the `legacy-ssh` algorithms and speaks the modern
  `tacacs server NAME` syntax.

Cisco ASA was not checked in this release and is not supported.
