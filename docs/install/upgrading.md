# Upgrading

[Documentation](../README.md) › [Installation and upgrades](README.md)

```bash
tacctl upgrade

# Switch to a specific branch during upgrade
tacctl upgrade --branch develop
```

The upgrade command:
1. Moves tacctl state into `/etc/tacctl` if it is not there yet (idempotent)
2. Pulls the latest tacquito server source and rebuilds the binary if upstream or the patch overlay changed. The overlay's `0003` makes tacquito log the address a device connected from, which `tacctl log` and `device scan` read, and the address and port of the client the device reports; `0004` stops it sending a server message with a failed login; `0005` records in the accounting log the accounting of a device's local accounts and daemons, which tacquito refused (Junos: `AUDITD_TACPLUS_START_NO_RESPONSE`). A server upgraded from 0.2.0 rebuilds tacquito once for them (see [patches/README.md](../../patches/README.md))
3. Pulls the latest tacctl repository into `/opt/tacctl` (after switching to the `--branch` given). If the installed binary was not built from the commit now checked out, it replaces it, with the verified release binary when the clone is at a release tag (`Installing the <tag> release binary (linux/<arch>, verified)`), otherwise built from the clone (`Building /usr/local/bin/tacctl from /opt/tacctl...`), and re-executes itself once, so the binary always matches the clone
4. Installs packages a newer tacctl needs
5. Brings the configuration in line with this release: re-renders each enabled backend from the store (RADIUS: and restarts it when its files or its unit drop-in changed); without a store, runs the in-place migrations of `tacquito.yaml`
6. Updates system files (unit files and drop-ins, logrotate, the tiers sudoers rules and the group drop-in `config sudoers install <group>` wrote, if those files are installed, the completion `tacctl completion bash` generates, the man page, templates you have not customized) if changed, and reports each one as `Updated:` or `Unchanged:`; a template you customized is kept, with the new release's version beside it as `<name>.template.new` (see [Custom Templates](../devices/templates.md#custom-templates))
7. For an install without a store: moves it into the store once the store gate (`tacctl store import --check`) passes
8. Restarts tacquito only if what it reads changed (its binary, a unit or drop-in, or `tacquito.yaml`), and rolls the binary and unit files back if it does not come up. A new README, logrotate file, completion or template restarts nothing, and neither does an upgrade with nothing new

The upgrade changes an override only when it is exactly a value an earlier release shipped (the 0.2.3 rules of `operator` and `readonly` and the `operator` privileges list, which `group commands add` and `group privilege add` copy into `tacctl.yaml`): that one is dropped, with an info line, and the shipped value applies. Every other override stays as it is. An install that ran `tacctl group preset roles` on 0.2.2 carries that preset's engineer rules as overrides. Their Cisco denies did not hold (tacquito matches the whole arguments string, so `no aaa new-model`, `enable secret ...`, `ip ssh ...` and `do reload in 5` were permitted), so while `engineer` still has exactly those values the upgrade ends with a red notice that names `tacctl group reset engineer` (look first with `--dry-run`).

**From 0.2.1 to 0.2.3.** Before upgrading, note the newest entry of `tacctl backup list`: snapshots are taken before every change, the upgrade adds one only when it records a tier, and that entry is your way back (see [Rolling back](#rolling-back)). The first upgrade records `tier.<group>: superuser` for every group at priv-lvl 15 that has no setting and leaves `/var/lib/tacctl/tier-pinned`; an engineer group stays a superuser group until you set it, in this order: `tacctl config linux engineer-sudo all|<cmd>[,<cmd>...]` first (while it is unset, the first sync gives `%tac-engineer ALL=(ALL:ALL) ALL`), then `tacctl group edit <group> tier engineer` (it syncs this server's accounts at once), then `tacctl host sync --all`: engineer accounts move from `tac-superuser` to `tac-engineer` at the first sync after the tier is set, not at the upgrade. Engineers who were kept off the server's own scope go back with `tacctl user scope <user> add <server-scope>`; without `tacctl console install` they get `/usr/sbin/nologin` there. The upgrade never creates the tiers sudoers: check that `/etc/sudoers.d/tacctl-tiers` exists or run `tacctl config sudoers tiers install`. Then re-paste the device walkthroughs you want; the SNMP step of `config cisco` and `config juniper` is live (see [SNMP and NETCONF in the walkthroughs](../devices/walkthroughs.md#snmp-and-netconf-in-the-walkthroughs)).

**From 0.2.3 to 0.2.5.** The upgrade changes nothing on a device, and a device configured earlier keeps its lines; no walkthrough needs a re-paste to keep working, and the SNMP step differs from 0.2.3's only for a device with SNMP settings of its own. To see what a device needs to match this release, run `tacctl device config pull <device>` and then `tacctl device config plan <device>`, which prints exactly the lines the device needs, in the form its image stores them (an IOS 15.x image keeps a default-level line such as `privilege exec level 15 clear counters` where a privilege line is removed; it is the image's own and is not reported). A Cisco device configured from an earlier walkthrough reads as missing the lines of the standard block (see **A device configured from an earlier walkthrough** in [Cisco IOS / IOS-XE](../devices/cisco.md)), and the configuration syntax a Cisco device is compared in is its own setting, read from the pull's version line (`tacctl device ios-syntax`). The upgrade rewrites an installed tiers sudoers file that differs from this release's rules, and an installed group drop-in (`config sudoers install <group>`) that is exactly the text an earlier release wrote (one you edited is left, with a warning that names `tacctl config sudoers install <group>`); the tiers file gains the rows of `device config`, `device snmp`, `device ios-syntax`, `breakglass list` and `console forget`, and both keep `TACCTL_ASKPASS` for the command lines that use the password cache. The password cache is off for every tier until `tacctl console password-cache tiers` opens it, and no device is read until you run `tacctl device config pull`. An operator cannot interrupt service, even intermittently (see [Default Groups](../security/command-authorization.md#per-command-authorization)): the shipped rules and privileges lose `clear`, `monitor capture` and the unbounded and interactive forms of `ping` and `traceroute`, and Junos `OP-CLASS` loses the `clear` bit. Until the lines are removed from a device its operators keep the old reach whenever the server does not answer, and always over RADIUS. The lines are, on Cisco, `no privilege exec all level 7 ping`, `no privilege exec all level 7 traceroute`, `no privilege exec all level 7 monitor capture`, `no privilege exec level 7 clear counters`, `clear line`, `clear ip arp`, `clear arp-cache` and `clear mac address-table dynamic`, and on Junos `delete system login class OP-CLASS permissions clear`; the first upgrade onto this release prints this list. A stored `privileges.operator`, `commands.operator` or `commands.readonly` that is exactly what 0.2.3 shipped is dropped (also on a RADIUS-only install); any other stored value is named in a red notice with the command that puts it right (`tacctl group privilege reset operator`, `tacctl group commands reset <group>`, or `tacctl group reset <group> --preset --only commands,junos` for the values of a role preset of 0.2.3, which keeps its `show` denies), and `tacctl config validate` repeats the warning. Going back is `tacctl rollback 0.2.3` (see [Rolling back](#rolling-back)).

**From 0.2.5 to 0.2.6.** The upgrade changes nothing on a device or on the server. The Cisco rendering has no `aaa authentication enable` line (see **The `enable` design** in [Cisco IOS / IOS-XE](../devices/cisco.md)), so a pulled Cisco device that has the list reads `differs` in `tacctl device config list` until `tacctl device config plan <device>` is pasted; the pull need not be repeated, because the rendering is what changed. On a device that has the list the 0.2.5 walkthrough rendered, the plan is one line in its `aaa` region, `no aaa authentication enable default group <G> enable` (the back-out types it again); a list of another name stays, `aaa authentication enable default enable` is left as IOS's own default, and a device with no list has nothing to paste for it. Until the line is removed, `enable` on that device asks the server, and any user the server knows reaches privilege 15 with their own password. A device with no enable secret has no `enable` once the list is gone: set one first (Step 0), and the plan warns when there is none.

Running `tacctl upgrade` again right after an upgrade changes nothing. `--branch` switches to a different branch (for example `develop` for pre-release features); `tacctl config branch <name>` switches without upgrading.

**The store gate.** An install that has no store yet runs the legacy migrations of `tacquito.yaml`, then `tacctl store import --check` with the running binary: import (nothing unrepresentable), render, equivalence of what tacquito would load from the two files, and a load test of the rendered file on a loopback port. Only when all of that passes is `/etc/tacctl/store.yaml` written, the old file kept as `/etc/tacctl/backups/legacy/tacquito.yaml.pre-store.<timestamp>`, `tacquito.yaml` rendered from the store and tacquito restarted.

**When the gate stops**, the upgrade still completes: the code is installed, `tacquito.yaml` and the running daemon are left exactly as they were, and tacctl runs in **legacy read-only mode** (read commands work, changes are refused). The report says why: content the store cannot hold (another service on a group, a non-bcrypt authenticator, an unknown top-level key, ...), a render that is not equivalent, or a failed load test. It never forces either through. Fix what `tacctl store import --check` reports and upgrade again, or accept the difference: `tacctl store import --force`, then `tacctl config render --force`.

**Undoing the move into the store.** `tacctl store rollback` restores the kept pre-store `tacquito.yaml` and legacy read-only mode (refused while RADIUS is enabled: `tacctl backend disable radius` first).

After an upgrade: `tacctl status`, `tacctl config validate` (store, rendered config, drift), and `tacctl backup list` (the pre-store file is under the old-style backups).

**The login console on every account (0.2.20).** The console is the login shell of every managed user of every tier on the tacctl server, and there is no switch for it. The `tiers` and `users` mappings of `/etc/tacctl/console.yaml` (the per-tier and per-user switches of earlier releases) are ignored, never written again and left in the file; every managed user gets the console at the next `tacctl host sync <name of this server>`, which also puts sshd's drop-in in force for all of them. Local accounts that are not tacctl users are not touched.

## Rolling back

`tacctl rollback` takes five targets: `0.2.18`, the release before this
one, `0.2.17`, `0.2.16`, `0.2.9` and `0.2.3`. All are the dry run described
below until `--apply` is given, all refuse while an apply is not settled, an
emergency lockdown locks a group or a user name has a period, and each release's tool prepares the state
for the releases it knows. `0.2.4` to `0.2.8` and `0.2.2` and older are
refused with the way there (one release at a time, or `tacctl backup restore`
of a snapshot of the time); `0.2.10` to `0.2.15`, this release and any other
word are refused with the five targets named.

**An emergency lockdown stops every rollback** (the dry run too): an older
release has no such record and would render every locked user back into the
scope. The refusal lists each lockdown and the command that lifts it
(`tacctl emergency lockdown <scope> disable`); lift them, then run the
rollback again. A record that locks nothing (a hand-edited, partial one) is
removed by the rollback, because the older schemas refuse its keys.

**A user name with a period stops every rollback** (the dry run too): a user name may hold
periods from 0.2.20, and no target reads one (it fails with `user '<name>': invalid name` on every
store command). The refusal lists each such user of the store with the command that fixes it
(`tacctl user rename <name> <new-name>`); do that, then run the rollback again. Nothing is changed
while it refuses. An override under such a name in the ignored `users` mapping of `console.yaml`
does not stop it: the rollback takes that entry out of the file.

**The password cache is the user's choice (0.2.20).** `console password-cache tiers` is now only the permission: a tier that is listed no longer has the cache on for everyone in it. Each user turns it on for themselves with `console password-cache on` (off by default), so a console that had the cache on for a tier has it off for every user until they do; `tacctl shell --password-cache` is unchanged. The choices are stored in `settings.password_cache_users` (written only when a user turned it on). No older release reads that key: the rollback removes it for every target (the plan names the users), and the older release then has the cache on for every user of a listed tier, as it always did.

**The system shell of single users.** `settings.system_shell_users` (`console system-shell user`, written only when a user has a setting) is a key no older release reads: the rollback removes it (the plan names the users and their setting), and the older release has the tiers' list `settings.system_shell_tiers` alone. That list always holds `superuser` once this release has written it.

**The console switches of `console.yaml`.** The `tiers` and `users` mappings that this release
ignores stay in the file, and the release a rollback goes to reads them as it always did: a tier or
a user switched off there gets a plain shell again at the next `host sync` of that release. A file
without the mappings is read there as the console on for every tier. The rollback lists every user
who would gain a system shell this way, and every user who would gain the password cache back (a
tier that is allowed it has it for everyone again), with the reason, as a warning: `--apply` refuses
without `--yes` while there is one (the dry run too shows it). To avoid it, remove the `tiers` and
`users` entries that switch the console off and run `console password-cache tiers none` before the
rollback; a system-shell `disable` of one user is dropped by the rollback, so that user has their
tier's setting.

**System blocks that use 0.2.19's statements.** This release added to the
grammar of the Junos and IOS `system` blocks: the syslog, login-policy, ssh and
summer-time statements, the login announcement, the `absent` lines and the IOS
`banner motd` and `banner exec`. Every older release lints a block that holds
one as an error and plans nothing for the devices it reaches. The rollback
does not rewrite the block files (they are your text); the dry run lists the
blocks that hold such statements, by scope or device, vendor and count, in a
warning that `--apply` refuses without `--yes`. Take the statements out
(`tacctl scope block ... system edit`, `tacctl device block ... system edit`)
before the upgrade, or expect the errors. Targets 0.2.18, 0.2.17, 0.2.16 and
0.2.9 warn so; 0.2.3 has no blocks.

**Console settings of 0.2.20.** `console.yaml` may hold `settings.color` (the
`console color` setting, written only when it is `on` or `off`) and a
`settings.list_max` of `-1` (`console list-max` with a negative number: never
ask). No older release reads either (it answers `unknown key 'color'` or
`settings.list_max must be 1-1000`, the console falls back to its defaults and
its writes fail), so every target takes them out: `--apply` removes
`settings.color`, writes `list_max: 1000` in place of `-1`, keeps every other
setting, and takes the snapshot first. The dry run lists the change as a step
of its own.

**A scope's strict management filter mode.** The mode of the Junos
management filter (`tacctl scope mgmt-acl <scope> mode`, 0.2.20) is stored as
`scope_mgmt_acl.mode.<scope>` (only `strict` is stored), a key every older
release refuses. Every target therefore removes it from `tacctl.yaml` after a
snapshot, and the dry run lists the scopes that were strict in a warning that
`--apply` refuses without `--yes`. The older release renders and plans the
`ssh-only` filter for them, which ends in a `default-accept` term, so its
`device config plan` or `device config apply` would put that filter back on a
device that holds the strict one, and the device would accept by default
again, without saying so. Nothing contacts a device. To stay deny by default,
keep this release, or leave the management filter of those scopes out of the
older release's plans.

### To 0.2.18

The per-tier sudoers drop-in of this release grants the engineer the rows of
`device config apply`, `device enroll`, `device collect`, `device onboard`,
`device sync` and `device support-bundle`; 0.2.18 has none of them. `--apply`
rewrites `/etc/sudoers.d/tacctl-tiers`, when it is exactly the text this
release writes (or the one 0.2.19 wrote), with the text 0.2.18 writes (after
`visudo -cf`); an edited file is left, and 0.2.18's upgrade rewrites it.
Nothing else is converted: `devices.yaml` (0.2.18 reads `ios_syntax`),
`store.yaml`, the group drop-in, the apply state and the hosts are in formats
0.2.18 reads. `--hosts` is accepted and does nothing. Until 0.2.18 is
installed, do not run `tacctl emergency lockdown`: it writes the record 0.2.18
refuses.

```bash
tacctl rollback 0.2.18          # the dry run: steps, warnings, writes nothing
tacctl rollback 0.2.18 --apply  # convert
```

### To 0.2.17

Three verbs have other names in 0.2.17: `device ios-syntax` is `device
config-syntax`, `device notice list` is `device notices` and `device
client-config` is `device ssh-config`, and the per-tier sudoers drop-in grants
the names of the release that wrote it. `--apply` rewrites
`/etc/sudoers.d/tacctl-tiers`, when it is exactly the text this release writes
(or the one 0.2.19 or 0.2.18 wrote), with the text 0.2.17 writes (after
`visudo -cf`); an edited file is left, and 0.2.17's upgrade rewrites it. This
release also stores a device's configuration syntax setting in `devices.yaml`
as `ios_syntax`, which 0.2.17 refuses (`unknown key 'ios_syntax'`): when a
device has one, `--apply` takes a snapshot first (`tacctl backup list`) and
writes the setting under `config_syntax`, the key 0.2.5 to 0.2.17 read; the
value and every other key stay. A partial lockdown record in `tacctl.yaml` is
removed (0.2.17 refuses its keys). Nothing else is converted: `store.yaml`,
the group drop-in and the hosts are in formats 0.2.17 reads. `--hosts` is
accepted and does nothing. Until 0.2.17 is installed, do not run a command
that changes the device registry: it writes `ios_syntax` again (run the
rollback again if one did).

```bash
tacctl rollback 0.2.17          # the dry run: steps, writes nothing
tacctl rollback 0.2.17 --apply  # convert (after a snapshot when needed)
tacctl upgrade --branch 0.2.17  # install 0.2.17
```

### To 0.2.16

0.2.17 added one setting that a 0.2.16 binary refuses, `audit.strict`
(its `config validate` reports `audit.strict: unknown config key` and its
`backup restore` refuses a snapshot that has it). Everything else it writes, a
0.2.16 binary reads or ignores. Run the rollback on this release first, then
install the tag:

```bash
tacctl rollback 0.2.16          # the dry run: steps, warnings, writes nothing
tacctl rollback 0.2.16 --apply  # convert (after a snapshot)
tacctl upgrade --branch 0.2.16  # install 0.2.16: switches the clone to the
                                # tag, builds it, re-executes it
```

`--apply` takes a snapshot first (`tacctl backup list`), then removes
`audit.strict` from `tacctl.yaml` when it is set, and the `audit:` mapping
with it. When the value is `true` the dry run warns that 0.2.16 runs a command
whose audit line cannot be written, and `--apply` refuses without `--yes`; a
`false` value is removed without a warning. The configuration syntax setting
of `devices.yaml` is written under `config_syntax`, as for 0.2.17. Nothing
else is converted: `store.yaml`, the sudoers drop-ins, the
SNMP credentials, the blocks, `/var/lib/tacctl/device-apply/` and the rendered
backend files are in formats 0.2.16 reads, nothing is re-rendered or restarted
and no device is contacted. `--hosts` is accepted and does nothing.

Until 0.2.16 is installed, do not add the `audit` setting to `tacctl.yaml`
again, and do not change the device registry; if one was, run `tacctl rollback
0.2.16 --apply` again. The snapshot the rollback takes holds this release's
form: restore it with this release, not with 0.2.16.

### To 0.2.9

This release adds settings that a 0.2.9 binary refuses (`device.apply.transport`, the `netconf_scope` settings of `scope netconf`, and the `netconf:` map that `device netconf` writes to a device of `devices.yaml`: its `config validate` reports the keys, its `backup restore` refuses a snapshot that has them, and its parser answers `unknown key 'netconf'` for the registry); everything else it writes, a 0.2.9 binary reads or ignores, and it changed no sudoers text. Run the rollback on this release first, then install the tag:

```bash
tacctl rollback 0.2.9                  # the dry run: steps, warnings, nothing written
tacctl rollback 0.2.9 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.9          # install 0.2.9: switches the clone to the tag, builds it,
                                       # re-executes it
```

`--apply` takes a snapshot first (`tacctl backup list`), then, in this order:

1. **`tacctl.yaml`**: removes `audit.strict`, `device.apply.transport` and every `netconf_scope.<scope>` key when set (the dry run warns with their values, and `--apply` refuses without `--yes` while a `device.apply.transport` or `netconf_scope` key is set, or `audit.strict` is `true`; the snapshot keeps them, and `tacctl backup restore` of it, **with this release**, brings them back). Every other key stays, `device.apply.confirm_timeout` and `device.apply.pause` included.
2. **`devices.yaml`**: removes the `netconf:` map of every device that has one, and writes the configuration syntax setting under `config_syntax` (as for 0.2.17: 0.2.9 refuses `ios_syntax`). The devices then follow their scope's setting, which is gone too: 0.2.9 neither plans nor compares the NETCONF service, and a service a device runs, or has had deleted, stays as it is.
3. **Leaves, and lists**, what this release wrote that 0.2.9 ignores; nothing is deleted. In `/var/lib/tacctl/devices-config.json` (version 1, as 0.2.9 reads it) this is the `via` field of the `applied` part of the records (the transport the apply wrote through): 0.2.9 reads the file without the field and does not write it back.
4. **Everything else** is in a format 0.2.9 reads: the sudoers drop-ins (this release changed none), `store.yaml`, the SNMP credentials, the blocks, `/var/lib/tacctl/device-apply/` and the rendered backend files are not touched, nothing is re-rendered or restarted and no device is contacted. `--hosts` is accepted and does nothing.

**An apply that is not settled stops the rollback** (the dry run too): a device whose record says `pending` (a confirmed commit whose window has not ended) or `unknown` (its outcome could not be read) is named with its time and the apply's identifier, because a rollback that cannot read the device must not hide an open window. `tacctl device config apply <name> --check` reads the device and settles the record, or `tacctl device config forget <name>` drops it once the device has been dealt with by hand; then run the rollback again. A records file that cannot be read stops it for the same reason (move it aside when no apply is pending: a pull rebuilds it).

Until 0.2.9 is installed, do not run `scope netconf`, `device netconf`, `config devices apply-transport`, `device config apply --transport` or another command that changes the device registry: they write the settings (and `ios_syntax`) again. If one did, run `tacctl rollback 0.2.9 --apply` again. Installing the tag is the documented next step (`tacctl upgrade --branch 0.2.9`, and the output says so). **Back to 0.2.8** is two steps, one rollback per release: this rollback and the install of 0.2.9, then 0.2.9's own `tacctl rollback 0.2.8`.

### To 0.2.3

This release writes keys and fields that a 0.2.3 binary refuses (it reads `console.yaml` and `devices.yaml` strictly, and its `config validate` and `backup restore` report or refuse a `tacctl.yaml` with a key it does not know). Going back is therefore not a plain checkout of the old tag: run `tacctl rollback 0.2.3` on this release first. Without `--apply` it is a dry run, which lists every step and every warning and changes nothing. Each release's tool converts what that release changed, so `0.2.2` and older are refused (go back one release at a time: this rollback, `tacctl upgrade --branch 0.2.3`, then the rollback of that release; or restore a snapshot of the time with `tacctl backup restore`), and anything else is refused as unknown. The apply state of `device config apply` (`/var/lib/tacctl/device-apply/` and the `applied` part of the pull records) is left and listed, as for 0.2.9; an apply that is not settled stops this rollback too.

```bash
tacctl rollback 0.2.3                  # the dry run: steps, warnings, nothing written
tacctl rollback 0.2.3 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.3          # install 0.2.3: switches the clone to the tag, builds it,
                                       # re-executes it
```

`--apply` takes a snapshot first (`tacctl backup list`), then, in this order:

1. **`tacctl.yaml`**: removes `device.config.max_concurrency`, `device.config.transport`, `device.config.timeout`, `device.config.confirm_timeout`, `device.apply.confirm_timeout`, `device.apply.pause`, `device.apply.transport` and `audit.strict`, every `netconf_scope.<scope>`, `cisco.source_interface.<scope>` and `breakglass_hold.<device>` key (the keys 0.2.5 added, and any other key 0.2.3 does not know). Every other key stays. A break-glass hold that stands stops the rollback instead, so no hold is ever dropped by it.
2. **`console.yaml`**: removes `settings.password_cache` (the password cache's tiers and lifetimes: 0.2.3's parser rejects the key, the console would fall back to the defaults and its writes would fail), so the cache is off again; `settings.color` and a `list_max` of `-1` go as for every target (above); every other setting stays, `tiers.engineer` and `settings.space_completion` included (they are 0.2.3's own).
3. **`devices.yaml`**: removes the `snmp:` map of every device (a device's own SNMP version, port, timeout and allowed clients: 0.2.3's parser answers `unknown key 'snmp'` and cannot read the registry) the `ios_syntax` key of every Cisco device that has one (`device 'x': unknown key 'ios_syntax'`) and the `netconf:` map of every Junos device that has one (`unknown key 'netconf'`). The devices are then read with their scope's or the default's settings, and the dry run warns that 0.2.3 compares a `legacy-ssh` Cisco device as IOS 12.x again; the locations and everything else stay.
4. **The sudoers drop-ins**: a per-tier drop-in (`/etc/sudoers.d/tacctl-tiers`) or a group drop-in (`config sudoers install <group>`) that is exactly the text this release writes (or the one 0.2.4 to 0.2.8 wrote) is rewritten with the text 0.2.3 writes, after `visudo -cf` (it loses the `TACCTL_ASKPASS` alias and `env_keep` line, and, in the per-tier file, the rows of `device config`, `device snmp`, `device ios-syntax`, `breakglass list` and `console forget`). A file an administrator edited is left as it is; a drop-in that `visudo` refuses is left and named, and the rollback goes on (0.2.3's upgrade rewrites the per-tier file with its own text).
5. **Leaves** `snmp/devices/` (the devices' own SNMP credentials, mode 0600: 0.2.3 opens `snmp/<scope>.yaml` by name and never lists the directory, so it ignores the subdirectory; 0.2.5 ignores a device's file too until the device has settings of its own again (its `snmp:` map gates the file), and `device snmp <name> clear` removes it; they are in the snapshot), the records of the configuration pulls in `/var/lib/tacctl` (`devices-config.json` and `device-config/`: derived from the devices and never in a snapshot, which 0.2.3 does not open and 0.2.5 rebuilds; `tacctl device config forget --all` of 0.2.5, before the rollback, deletes them), `store.yaml` (0.2.5 did not change its format) and the rendered backend files (nothing it removes reaches them, so nothing is re-rendered or restarted).
6. **`--hosts`** is accepted and does nothing: 0.2.5 changed nothing on the enrolled Linux hosts, so no host is synced.

**A break-glass hold stops the rollback** (the dry run too): `Break-glass is held on <device> (<address>, by <user> since <time>). 0.2.3 has no such record: the device would stay unanswered until 0.2.3's first render and then be answered without anyone releasing it. Release it first: tacctl breakglass release <device>. Nothing was changed.` Release the holds (`tacctl breakglass list`), then run it again.

**A management ACL entry with services stops the rollback** (the dry run too): 0.2.3 reads `mgmt_acl.permits` and `scope_mgmt_acl.permits.<scope>` as plain CIDRs, so it would refuse the file, and rewriting an entry to its CIDR would permit every protocol and port from that source. The refusal lists each entry with its key and the command that removes it (`tacctl config mgmt-acl remove <entry>`, `tacctl scope mgmt-acl <scope> remove <entry>`); remove them, or replace each with the plain CIDR you mean it to be, then run the rollback again. Nothing is changed.

**Warning that needs a human**: *Settings 0.2.3 cannot use are dropped* lists the devices that lose their own SNMP settings (what each set), the devices that lose their configuration syntax (`device ios-syntax`; 0.2.3 compares a `legacy-ssh` Cisco device as IOS 12.x again), the `device.config` values, the Cisco source interface of each scope and the password cache's settings, and `--apply` refuses without `--yes` while any applies. Everything removed from `tacctl.yaml`, `console.yaml` and `devices.yaml` stays in the snapshot; `tacctl backup restore` of it, **with 0.2.5**, brings it back (0.2.3's restore refuses a `tacctl.yaml` with a key it does not know). Without a store there is no snapshot to take; copy the three files first.

Until 0.2.3 is installed (between `rollback --apply` and `upgrade --branch 0.2.3`), do not run a command that writes the console's settings, a device's SNMP settings or configuration syntax, a scope's Cisco source interface or the `device config` settings (`config devices`). If one did, run `tacctl rollback 0.2.3 --apply` again. Once 0.2.3 is installed a 0.2.5 command cannot run. The fallback that needs no tool is `tacctl backup restore <id>` of a snapshot of the time you want back: it brings back the state of that day and loses what changed since.

**Back to 0.2.2** is two steps, one rollback per release: (1) `tacctl rollback 0.2.3 --apply --yes` and `tacctl upgrade --branch 0.2.3`; (2) with 0.2.3 installed, its own `tacctl rollback 0.2.2` (and `--hosts` there, which takes the engineers' sudo off the enrolled hosts), then `tacctl upgrade --branch 0.2.2`.
