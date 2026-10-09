# tacctl 0.2.3

0.2.3 finishes the engineer tier: a fourth tacctl tier between operator and
superuser, set on a group (`tacctl group edit <group> tier engineer`), for the
people who provision and configure the network devices of their own scopes.
It also adds the things an engineer and an operator need around it: Junos-style
spaces at the shell and console prompt, rotation of the account tacctl logs in
to a Linux host with, a baseline of command rules and privileges for the four
roles, `group reset`, SNMP, NETCONF, WTI IP Tables and break-glass users in the
device walkthroughs, and `tacctl rollback`, which prepares the state for
0.2.2. The numbered list in `CHANGELOG.md` (0.2.3, items 1 to 106, grouped by
theme) is everything that differs from 0.2.2; the item numbers below point
into it. Nothing changes on a device until you re-paste a walkthrough, and no
device configuration is pushed by tacctl: that is 0.2.4 and later.

This is the first release since 0.2.1 that production can reach, so
"Upgrading" covers 0.2.1 to 0.2.3, 0.2.2's steps included.

## What is new

### The engineer tier

- **A tier set on the group.** `tier.<group>` in `tacctl.yaml`
  (`group add --tier`, `group edit <group> tier readonly|operator|engineer|superuser|auto`)
  decides, else the priv-lvl band as before. A group at priv-lvl 15 on the
  devices can be engineers in tacctl (item 1).
- **What an engineer may do.** What an operator may, and for the devices of
  their own scopes: `device add|remove|rename|address|hostname|vendor|port|description|location|legacy-ssh|hostkey`,
  `device import -` (standard input only), `scope devices`, and
  `config cisco|juniper|wti` (also with `--staging`). They read the shared
  secret and the SNMP credentials of their own scopes (`scope secret <scope>
  show`, `scope snmp <scope> show --reveal`; every read is logged, never the
  value; `scope show` shows the scope and the secret's length only) and the hosts and staging addresses of those scopes
  (`host list`, `host show`, `scope staging list`). Another scope's device,
  host or secret is "not found". Users, groups, scopes, the change of any
  secret, backends, backups, upgrades and every global setting stay the
  superuser's (items 17-21). **Linux host deployment is the superuser's**:
  `host enroll`, `sync`, `move`, `target`, `provisioner`, `unenroll` and
  `default-method` are refused to an engineer, and a test checks that nothing
  an engineer can run changes an input of a host sync (item 26).
- **Safety rules around it.** A group at priv-lvl 15 other than the built-in
  `superuser` always has an explicit tier, and one that lost it holds back only
  its own members at the operator tier (items 7-9). While `tacctl.yaml` cannot
  be read, or holds a tier that is not one, no tacctl user is trusted above the
  operator tier and `host enroll`/`host sync` refuse, so a broken file never
  makes an engineer a superuser (item 3). On the tacctl server an engineer has
  the console or no login: its switch is always on, and sshd gets a drop-in
  (`00-tacctl-engineer.conf`) that closes forwarding and tunnels for them
  whatever their shell (items 4-6). Lowering a tier (`group edit ... tier`,
  `priv-lvl`, `user move|disable|remove|rename`, `user scope ...`, `group
  remove`, `group preset roles --force`, `group reset`) syncs this server's
  accounts at once, or says what to run (item 14).

### Linux hosts

- **Client script protocol 6.** Engineers are in a new group `tac-engineer`
  (GID the UID range's first number + 5) instead of `tac-superuser`, with
  every command through sudo on a host other than the tacctl server, or only
  the commands `tacctl config linux engineer-sudo all|<cmd>[,<cmd>...]` names
  (a shell, an interpreter or an editor in that list is warned about). A
  machine that runs tacctl gets no engineer sudo line, and this server is
  enrolled with `--local` only (items 1, 22-24).
- **`host show` and `host show --check`** know the tier and the group, and
  report an engineer still in `tac-superuser` (items 22, 27).
- **Provisioning-account rotation.** `tacctl host provisioner <name> rotate
  <user> (--key <file>|--password) [--remove-old [--remove-home]] [--dry-run]
  [--yes]` creates the new account over the current login, proves it with a
  fresh login that reaches root (ssh trusting the pinned host keys only),
  switches the registry target and removes the old account last, over the new
  one. A password is typed into the host's own `passwd` and never passes
  through tacctl. It is the superuser's, and one rotation of a host runs at a
  time (items 28-38).

### The shell and the console

- **Junos-style spaces.** A space is refused where it would be a second one; at
  the end of a command, sub-command, fixed choice or flag name a space
  completes the word when exactly one matches (`de` and a space give
  `device `); several matches are listed once. Free text, names from the store
  and quotes get the space as typed. Pastes are unchanged, except that one
  arriving at a pending `Show all` question or pager ends it. `tacctl console
  space-completion on|off` (server-wide, on by default) and `tacctl shell
  --space-completion on|off` (items 39, 40).
- **Only what you can run.** Tab, `?`, a typed space and the top-level `help`
  list only the commands your tier can run; `help <command>` still describes
  every verb and names the tier it needs. Display only: the gate is still the
  check (items 41-46).

### Baseline commands and privileges

- **Shipped defaults.** `readonly` is the account for monitoring and backup
  systems (SolarWinds NCM): it keeps `show`, `ping`, `traceroute` and gains
  `dir`, `terminal length|width`, `exit`, `logout`, and its `privilege exec`
  list lowers `show running-config` to level 1 (a filtered configuration on
  Cisco, which you should check before pointing NCM at a fleet). `operator`
  gains `dir`, `ssh`, `telnet`, `undebug`, `monitor capture` and single-entry
  `clear` forms, and a new privilege list. All of it is permit-only (item 50).
- **Every command regex is rendered whole**, `^(?:regex)$`, so tacquito's own
  anchoring cannot change what a rule says (item 48).
- **The role preset** (`tacctl group preset roles`, opt-in) is rewritten for
  Cisco and Junos (items 51, 52); `group commands add` and `config validate`
  lint what they write (item 49); `tests/tools/permcheck.py` asks a lab server
  what it decides (item 53).
- **Reset verbs.** `tacctl group reset <group> [--preset] [--only ...]
  [--dry-run] [--yes]`, `group privilege reset` and `group commands reset`
  show the difference, ask, snapshot, write and restart once (items 56-61).

### Device walkthroughs

- **SNMP per scope.** `tacctl scope snmp <scope> ...` keeps a scope's SNMP
  version, credentials, allowed clients and contact, with the global `config
  snmp` as the default beneath; `config cisco|juniper|wti` end with an SNMP
  step (the server's /32 first, the scope's ranges, then everything else
  refused). `tacctl device location` sets the SNMP location (items 62-66).
- **`--name`, `--server`, `--source`, `--snmp-location`** on `config
  cisco|juniper|wti`, for devices behind a translating firewall (item 68);
  `--source` is also permitted for ssh by the Cisco VTY-ACL and the Junos
  management filter, and is the server's /32 of the WTI IP Tables list.
- **A commented NETCONF step** in the Junos and Cisco walkthroughs, so the
  fleet can be prepared before 0.2.4 (item 69).
- **WTI IP Tables** rendered from the scope's management permit list; the
  final DROP is a separate last step that is never applied for you; the SNMP
  step is Step 6 and the later steps move down (items 67, 70-75).
- **Break-glass local users per scope** (`tacctl scope breakglass`): names
  and roles only, rendered as commented lines with a placeholder for the
  credential, which tacctl never stores (items 76-83).

### Rollback and the manual page

- **`tacctl rollback <version> [--apply] [--yes] [--hosts]`** prepares the state
  for 0.2.2 (items 84-88; see "Rolling back").
- **The manual page is checked against the code**: `make lint` runs the Man
  tests and `groff -k -ww`, and the TIERS, CONFIGURATION KEYS, EXIT STATUS and
  ENVIRONMENT sections are new (items 89-91).

## Upgrading from 0.2.1

Production is on 0.2.1. Upgrade with `sudo tacctl upgrade` as always; a
second run changes nothing. **Before upgrading, note the newest entry of
`tacctl backup list`** (snapshots are taken before every change; the upgrade
adds one only when it records a tier). That entry is your way back (see
"Rolling back"). Read this section before you run it, and do the device steps
afterwards.

### What `tacctl upgrade` does by itself

From 0.2.2:

- **FreeRADIUS restarts once** on an install that runs the RADIUS backend: its
  configuration is rendered again (post-auth copies the new Juniper
  attributes, the reject scrub removes them). `tacquito.yaml` changes only
  where a group has a Junos set or a WTI level, or through 0.2.3's rendering
  below.
- **Linux hosts** take the client script's changes at their next `tacctl host
  sync` (duplicate `tac-users` entries removed, protocol and PAM checksums
  recorded for `host show --check`).

From 0.2.3:

- **The tier of every group at priv-lvl 15 is recorded, once.** The first
  upgrade writes `tier.<group>: superuser` for every group at priv-lvl 15 that
  has no setting, which is what 0.2.1 and 0.2.2 treated it as, one line each:
  `Group '<g>' (priv-lvl 15): tier recorded as superuser in <file> ...`. It
  leaves the marker `/var/lib/tacctl/tier-pinned` (written once the migration
  is complete; it takes a snapshot first when there is a group to record) and
  never does it again, so a setting lost later is not silently made a
  superuser's. `tacctl rollback` removes the marker; if you restored a
  snapshot by hand instead, check that `/var/lib/tacctl/tier-pinned` is absent
  before upgrading to 0.2.3 again, or the migration will not run.
  **An engineer group stays a superuser group until you say otherwise.** In
  this order:
  1. Decide what engineers may run through sudo on the hosts:
     `tacctl config linux engineer-sudo all|<cmd>[,<cmd>...]`. While it is
     unset the first sync gives `%tac-engineer ALL=(ALL:ALL) ALL` (every
     command, their own password), so set it before the tier.
  2. Look at `tacctl group show <group>`, then run `tacctl group edit <group>
     tier engineer`. It syncs this server's accounts at once.
  3. Run `tacctl host sync --all` (or `host sync <name>` per host). Engineer
     accounts move from `tac-superuser` to `tac-engineer` at the first sync
     after the tier is set (`'<user>': moved from tac-superuser to
     tac-engineer`), not at the upgrade.
  4. Keep engineers out of the server's own scope until the tier is set; then
     put them back with `tacctl user scope <user> add <server-scope>`. On the
     server they get the console (`tacctl console install` provisions it);
     without it they get `/usr/sbin/nologin`.
- **The engineer sshd drop-in** `00-tacctl-engineer.conf` is created, or the
  earlier `tacctl-engineer.conf` renamed, on an install that has the console's
  drop-in, and checked with `sshd -t`.
- **The tiers sudoers rules** are rewritten when the file is installed and
  differs (`Updated: tiers sudoers`), so the engineer's rows and the new verbs
  reach the tiers. **An upgrade never creates the file:** check that
  `/etc/sudoers.d/tacctl-tiers` exists, or run `tacctl config sudoers tiers
  install`; without it the lower tiers have no sudo rows for tacctl.
- **Command rules are rendered whole** (`^(?:regex)$`) and tacquito restarts
  once. The shipped rules of `readonly` and `operator` are the new baseline
  (permit-only), and your own overrides are never touched.
- **A red notice** if `commands.engineer` and the two Junos sets of `engineer`
  still hold the text of 0.2.2's role preset: its Cisco denies did not hold.
  Run `tacctl group reset engineer --dry-run`, look, then `tacctl group reset
  engineer` (items 54, 55). Production did not run the preset on 0.2.1, so you
  will not see it there.
- **Templates you customized** keep their numbers and their text; the new
  version is written beside them as `<name>.template.new`.

### Steps on the devices

Nothing changes on a device until you paste.

- **Cisco:** re-paste `tacctl config cisco`. It brings 0.2.2's per-level
  `aaa authorization commands <level>` and `config-commands` (a level where a group has no rules gets
  its line commented out, with the fix named), the
  `privilege` lines of the baseline, an SNMP step (live; read "Optional"
  below before pasting it) and the break-glass step.
  Then remove the old operator privilege mappings, which 0.2.1 put at level 7
  and which stay until you remove them: for each of `show startup-config`,
  `show tech-support`, `show archive`, `show access-list` and `show ip route`
  that a device carries, enter `no privilege exec level 7 <command>` (`show
  running-config` needs none: the new `privilege exec level 1 show
  running-config` replaces its mapping). Until the re-paste an operator cannot
  yet `clear counters` or `clear line`. **Custom Cisco templates** in
  `/etc/tacctl/templates` keep the 1/7/15 accounting lines they have: compare
  with `<name>.template.new` and take what you want.
- **Junos:** re-paste `tacctl config juniper`. The class names and permission
  bits are **unchanged** in 0.2.3 (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`, and
  `ENG-CLASS` for a group that uses it). Step 3 is a read-only summary of what
  the server sends at login and lists the `delete ... allow-commands` lines
  that remove what an earlier walkthrough wrote on the classes. The
  break-glass step is Step 7 and Commit is Step 8. A group whose
  class is `ENG-CLASS` needs its template user on the device (Step 1). A
  rename of the classes (to `EN-CLASS` and `SU-CLASS`) and the changes to the
  viewer and operator permission bits are held for the release that pushes
  configuration (0.2.5).
- **WTI:** a unit whose Service Name was set to `shell` by an earlier
  walkthrough must be set back to its factory `wti` for per-group WTI levels
  to apply. The SNMP step is Step 6 now, so Save, the second-session test and
  the debug step move down; the IP Tables list (Step 5) and the final DROP
  (Step 11) are new.
- **Optional, new in 0.2.3:** the SNMP step (record the scope's version,
  credentials, allowed clients and contact first: `tacctl scope snmp <scope>
  ...`; **it is live:** it binds an existing community to a client list that
  allows only the server and the scope's ranges, and overwrites the location
  and contact, so pollers and NCM using that community lose access. Before
  pasting it, add your pollers with `tacctl scope snmp <scope> clients add
  <cidr>`, or leave the step out), the NETCONF step on Junos and Cisco (commented, review and uncomment
  per device), the WTI IP Tables list (keep a serial session open before the
  DROP), and break-glass local users (`tacctl scope breakglass <scope> add
  <name>`; paste your own hash where the placeholder is).

### New settings to decide

- **`console space-completion`** is **on** for every console user after the
  upgrade. If you do not want typing to change, run `tacctl console
  space-completion off` before anyone logs in.
- **Per-scope SNMP and break-glass users** are empty until you set them; a
  scope with no break-glass user raises a `config validate` warning (the exit
  status is unchanged).
- **`linux.engineer_sudo`** is unset: engineers get every command through
  sudo on enrolled hosts (other than the tacctl server) until you set it.
- **An engineer group's tier**, as above.

### Behaviour changes that may surprise

- **Typing at the console and the shell** changes with space completion, as
  above; a repeated space is silently refused.
- **Host deployment is the superuser's.** An engineer reads `host list` and
  `host show` for their own scopes and deploys nothing; their accounts and sudo
  on a host come from a superuser's sync.
- **Engineers read the secrets** of their own scopes: the shared secret, the
  SNMP credentials, and the walkthroughs that print them, each read logged.
- **An account whose tier is none** (a disabled or unknown user) gets
  `/usr/sbin/nologin` on the tacctl server, no longer a real shell.
- **`host enroll` of an address of this machine** without `--local` is refused
  for everyone.
- **Regexes with a bare alternation.** A rule whose `--match` is `crypto|trace`
  used to be tested as `^crypto|trace$` (a prefix on the first branch, a
  suffix on the last); it is now tested as `^(?:crypto|trace)$`. A rule with a
  top-level `|` and no anchors, or one that ended in a prefix form tacquito
  closed with `$`, matches differently: what it was meant to match now
  matches. Review `tacctl group commands list <group>` for such rules.
- **`group privilege clear` and `group commands clear` are gone** (`Unknown
  subcommand`). Use `group privilege reset <group>` and `group commands reset
  <group>`. A `privileges.<group>: []` that `clear` left behind is shown by
  `group privilege reset` as a change to the shipped default and removed.
- **`--name <device>`** on `config cisco|juniper|wti` now also names a
  registered device without `--staging`.
- **`readonly` and `operator` run more** than before (permit-only additions),
  and a Cisco `readonly` login reads the configuration the level may see.

## Rolling back

`tacctl rollback 0.2.2` prepares the state for the earlier release; going back
is not a plain checkout, because 0.2.3 writes keys a 0.2.2 binary refuses
(`console.yaml` and `devices.yaml` are read strictly; its `config validate`
and `backup restore` report or refuse a `tacctl.yaml` with a key it does not
know) and 0.2.2 derives a user's tier from the priv-lvl alone.

```
tacctl rollback 0.2.2                         # the dry run: every step and warning, nothing written
tacctl rollback 0.2.2 --apply --yes --hosts   # convert (after a snapshot), then sync the hosts
tacctl upgrade --branch 0.2.2                 # install 0.2.2: switches the clone to the tag, builds, re-executes
```

- **`--apply`** takes a snapshot, then removes `linux.engineer_sudo`,
  `snmp_scope.*` and `breakglass_scope.*` from `tacctl.yaml` (every
  `tier.<group>` stays), `tiers.engineer` and `settings.space_completion` from
  `console.yaml`, and every device `location` from `devices.yaml`; leaves
  `store.yaml` alone; and re-renders the enabled backends. A second `--apply`
  changes nothing. The only target is `0.2.2`: `0.2.1` and older are refused
  (0.2.2's own settings are not covered; restore a snapshot with `tacctl backup
  restore`).
- **It moves and removes, and lists what it leaves.** It moves the `snmp/`
  directory (the scopes' credential files; 0.2.2 never looks there) aside to
  `snmp.rolled-back-<timestamp>/` beside it, and removes the marker
  `/var/lib/tacctl/tier-pinned`, so that the upgrade that follows records the
  tier of a group made or raised to priv-lvl 15 under 0.2.2 (the migration runs
  once; the marker is what says it did). It leaves the host records and the engineer sshd drop-in.
  If you restored a snapshot by hand instead, check that
  `/var/lib/tacctl/tier-pinned` is absent before upgrading to 0.2.3 again.
- **Warnings that need a human**, and `--apply` refuses without `--yes` while
  one applies: *engineers become superusers under 0.2.2* (a group at priv-lvl
  15 is a superuser group whatever its tier says, on this server and, at the
  next 0.2.2 sync, on every host; the users are named; take the engineer
  groups out of the server's own scope first); *groups change tier*; *settings
  0.2.2 cannot use are dropped* (the engineer sudo list, the per-scope SNMP
  settings, the break-glass users, the device locations, which stay in the
  snapshot).
- **`--hosts`** syncs every enrolled host but this server's own entry with
  `TAC_REVOKE_ENGINEER=1`, so the `%tac-engineer` sudoers line goes and the
  engineers have no sudo on the host, until the next 0.2.2 sync, which puts an
  engineer at priv-lvl 15 in `tac-superuser` again: take engineer groups out
  of those scopes or lower their priv-lvl first. A host that fails is named
  and the exit status is 1; run it again once the cause is fixed.
- **Until 0.2.2 is installed** (between `rollback --apply` and `upgrade
  --branch 0.2.2`), do not run a command that writes the console settings or
  the other converted files (a scope's SNMP settings, a device location, an
  engineer sudo list). If one did, run `tacctl rollback 0.2.2 --apply` again.
  Once 0.2.2 is installed a 0.2.3 command cannot run. 0.2.2's `config
  validate` says the rendered config is out of date until its own `config
  render` or upgrade.
- **The fallback that needs no tool** is `tacctl backup restore <id>` of the
  entry you noted in `tacctl backup list` before the upgrade to 0.2.3; it
  loses what changed since. Command rules with a top-level `|` in a regex
  match differently again under 0.2.2 (it renders them unwrapped).
- **Back to 0.2.1, which is where production came from.** The tool targets
  0.2.2 only, so the way is in four steps:
  1. `tacctl rollback 0.2.2 --apply --yes --hosts`: old releases never remove
     `%tac-engineer` or membership of `tac-engineer`, so the hosts are synced
     while 0.2.3 is still installed. Take engineer groups out of the scopes
     (or lower their priv-lvl) first, as above.
  2. `tacctl backup restore <the id you noted before the upgrade>`.
  3. `tacctl upgrade --branch 0.2.1`.
  4. `rollback` removes the marker `/var/lib/tacctl/tier-pinned`; because you
     restored a snapshot by hand, check that it is absent before upgrading to
     0.2.3 again.
- **Rolling back past 0.2.2** (to 0.2.1) is otherwise not covered by the tool:
  remove every group's Junos sets and WTI level, the SNMP settings and
  privilege entries that name a mode, as the 0.2.2 notes say, or restore a
  snapshot.

## What is not lab-tested

Written from the vendors' documents and the tests that run here; the lab
acceptance is still to do. **Only some of the output says so.** Marked "not
verified" in the walkthroughs: the WTI SNMP step (the menu names and the client
restriction), the WTI IP Tables list and when the unit applies a changed list,
the WTI RADIUS walkthrough, the SHA-256 keyword lines on Cisco and Junos, and
the Junos line saying a client list does not restrict a v3 user. **Everything
else below is just as unverified and carries no marker**:

- **SNMP:** the syntax of the SNMP step for Cisco and Junos (unmarked), the
  SHA-256 keywords on Cisco and Junos and whether a Junos client list
  restricts a v3 user (the output says it does not) (marked), and the WTI menu
  names (marked).
- **WTI IP Tables:** how the unit takes the list (the menu under `/N`, and
  `-m conntrack` or the older `-m state`; the list's header says "Not verified
  on a unit"), whether a changed list applies on entry or on save (marked), and
  that the TACACS+ login and the `sysName` read still work with the DROP in
  place (unmarked). WTI has no NETCONF.
- **NETCONF steps** on Junos and Cisco (unmarked).
- **IOS behaviours the baseline depends on** (see `docs/plans/0.2.3-baseline-design.md`):
  what `show running-config` shows at level 1 and at level 7, whether a
  lowered `show startup-config` is filtered, the level of `dir`, whether IOS
  authorizes `exit`, `logout`, `enable` and `end`, `privilege exec all level 7`
  reaching `monitor capture ... export`, how `do <command>` is authorized in
  configuration mode, the `local` fallback with the server stopped.
- **The Cisco AAA block, per-level authorization and `config-commands`**, and
  the WTI Service Name and per-group levels, carried from 0.2.2.
- **The hosts container run** for the rotation (`--key`, a sync through the
  new account, `--remove-old`; SELinux on `almalinux-9`) and for `rollback
  --hosts`.

## Known limits and what comes next

- **Nothing is pushed.** `config cisco|juniper|wti` print walkthroughs; the
  engineer provisions a device by pasting them. **0.2.4** reads device
  configuration (read-only `device config pull|diff` of the managed sections,
  per-device records, `--stale`, parallel sessions under one global maximum
  concurrency), over NETCONF with an SSH fallback, caches the user's password in
  memory for their session only (never stored), and reads a device's SNMP
  configuration to offer the gaps, with per-device SNMP overrides. **0.2.5**
  applies it with a confirmed commit or revert timer, in batches with a canary,
  and carries the Junos class rename and the viewer/operator bit changes.
  **0.2.6** WTI configuration, **0.2.7** device account rotation.
- **`engineer` is an ordinary group** in 0.2.3 (the role preset creates it if
  absent, an existing one is taken as it is). A built-in `engineer` group with a
  migration for existing ones is planned for 0.3.0.
- **A device's break-glass credential is yours.** tacctl records names and
  roles and renders commented lines; it stores no password or hash, and
  generating, rotating and removing the account on devices is 0.2.7.
- **Engineers are unrestricted in Cisco configuration mode** under the
  canonical rules, and on Junos the `ENG-CLASS` bits are the only limit on
  configuration. A site that wants a boundary adds rules with `group commands
  add` or sets `group junos <group> deny-configuration`.
