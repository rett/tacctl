# tacctl 0.2.2

0.2.2 lets each group carry its own device settings, sent by the server at
login: Junos deny patterns (`tacctl group junos`), sent with the login class
over TACACS+ and RADIUS, and a WTI access level of its own (`tacctl group
edit <group> wti-level`). `tacctl group show` prints every setting of a
group, and `tacctl group preset roles` writes starting values for four
roles (viewer, operator, engineer, superuser). It also adds `tacctl host
show` (one enrolled host in full, with `--check`), an SNMP `sysName` hint
at `tacctl device add`, fully qualified device names, the `group commands`
remove selector and rule placement, and privilege modes for `group
privilege`. Nothing changes on a device or a host until you use the new
settings or re-paste a walkthrough. The numbered list below is everything
that differs from 0.2.1, and nothing else.

## Upgrading from 0.2.1

Upgrade with `sudo tacctl upgrade` as always. What to expect:

- **`tacquito.yaml` is unchanged** until a group has a Junos set or a WTI
  level. **The RADIUS configuration is rendered again** on every install
  that runs the RADIUS backend: post-auth gains the lines that copy the
  new Juniper attributes, and the reject scrub removes them (item 9).
- **Linux hosts** take the client script's changes at their next `tacctl
  host sync`: the duplicate `tac-users` member entries are removed (item
  3), and the host records the protocol it ran and its PAM checksums for
  `host show --check` (item 7). The client script protocol stays 5.
- **Devices:** nothing changes until you re-paste a walkthrough. Re-paste
  the Cisco AAA block to get per-level command authorization and
  `config-commands` (item 5). On Junos, `config juniper` Step 3 no longer
  writes `allow-commands`/`deny-commands` on the classes; it lists the
  `delete` lines that remove what an earlier walkthrough put there. A WTI
  unit needs its factory Service Name `wti` only for groups with a WTI
  level set; a unit left on `shell` keeps today's priv-lvl bands.
- **The engineer tier is not in this release** (it moves to 0.2.3). A
  group's tacctl tier still comes from its priv-lvl, so an engineer group
  at priv-lvl 15 is a superuser on the tacctl server: keep engineers out
  of the server's own scope until 0.2.3.

## Rolling back to 0.2.1

Remove what 0.2.1 does not know before rolling back: every group's Junos
sets (`tacctl group junos <group> clear`) and WTI level (`tacctl group edit
<group> wti-level auto`), the SNMP settings (`tacctl config snmp clear`,
which also removes `/etc/tacctl/snmp.yaml`), and privilege entries that
name a mode (item 6). `tacctl group show <group>` lists what is set.

## What changed

1. **A release install leaves nothing in root's home.** The bootstrap shim
   downloads Go and the release binaries with `wget --no-hsts`, so wget no
   longer writes its HSTS cache (`/root/.wget-hsts`) on the server; found
   by the 0.2.1 release check (`tests/containers/fresh/run.sh --release`).

2. **A device name may be a fully qualified host name of up to 253
   characters.** `tacctl device add sw1.site-a.example <address>` was
   already accepted; the limit was 63 characters for the whole name, and is
   now 253, each dotted part 1 to 63 characters (no empty part, no trailing
   dot): `Invalid device name '<name>'. Use letters, digits, '.', '_' or '-',
   starting with a letter or digit; at most 253 characters, each dotted part
   at most 63.` The `name-mismatch` notice no longer fires when a device
   registered as `sw1.site-a.example` sends `sw1` as its NAS-Identifier (the
   registry name's first label). The `ambiguous-nas-id` notice's remedy says
   that a fully qualified host name tells the devices apart. Enrolled host
   names are unchanged, because a host's name also names its scope
   (`linux-<name>`).

3. **An account whose primary group is `tac-users` is no longer listed in
   it a second time.** 0.2.0 put every account tacctl manages in
   `tac-users` as a supplementary group, and 0.2.1 made `tac-users` the
   primary group but kept the old entry, so `getent group tac-users` still
   listed them. A sync now takes each managed account whose primary group
   is `tac-users` out of the group's member list (`gpasswd -d`) and says so
   once per account; it no longer adds `tac-users` as a supplementary group
   either, except to an account whose primary group could not be changed
   yet. Other accounts in the group are left to the existing cleanup.
   `client-remove.sh` now finds tacctl's accounts by their primary group as
   well when it reports those left without a way to log in.

4. **`group commands remove` no longer drops several rules of a name at
   once, and `group commands add` can place a rule.** When more rules than
   one share the name, `remove` refuses (`[ERROR] Group 'operator' has 2
   rules named 'show'; select one with --match/--action (see 'tacctl group
   commands list operator'), or pass --all.`, exit 1) unless `--match` (the
   rule's regexes, all of them, in order) and `--action` narrow them to one;
   `--all` removes them all, as `remove` did before. A removal names the
   rule it took: `Removed rule #3 'show' (deny, match=[^crypto( .*)?]) from
   group 'operator'.` The name is now compared literally, so `remove
   operator 'sh.w'` warns that there is no such rule. `add --before <name>`
   puts the rule before the first rule of that name (`No rule named 'x' in
   group 'operator'.`, exit 1, when there is none) and `add --first` puts it
   first; without them it goes before the catchall as before. `group
   commands list` gains a `#` column with each rule's position, and the
   `group commands` usage says how tacquito tests a `--match` (anchored at
   both ends, against the arguments joined by spaces).

5. **`config cisco`, `config juniper` and `config wti` say what the server
   now sends and what stays on the device.**
   - **Cisco:** `aaa accounting commands <level>` is printed for every
     privilege level a group uses, not for 1, 7 and 15 only. Once any group
     has command rules, `aaa authorization commands <level>` follows for
     every level in use, with `aaa authorization config-commands` and a
     commented `aaa authorization console` to uncomment for the console
     line. A level where a group has no rules gets its line commented out,
     naming the group and the fix (`tacctl group commands default <group>
     permit`), since the server would deny that group every command. The
     notes say that a group at priv-lvl 15 is kept apart from the
     superusers only by the server's rules, so the `local` fallback lets it
     run everything while the server is unreachable. The shipped
     `cisco.template` and `cisco-legacy.template` take the accounting lines
     from the new `${ACCT_COMMANDS_BLOCK}`; a template copied to
     `/etc/tacctl/templates` before 0.2.2 keeps the 1/7/15 lines it has
     (`tacctl upgrade` writes this release's version beside it as
     `<name>.template.new`). Re-paste the AAA block on Cisco devices.
   - **Junos:** Step 3 no longer turns the `group commands` rules, which
     are Cisco's, into class `allow-commands`/`deny-commands` lines. It is
     a read-only summary of what the server sends per class at login: the
     group's `deny-commands` and `deny-configuration` values with their
     sizes against the 241 and 236 byte limits, or `none`, over TACACS+ and
     over RADIUS (`Juniper-Deny-Commands`, `Juniper-Deny-Configuration`).
     The classes keep their permission bits, and Step 3 lists the `delete
     system login class <class> allow-commands` lines that remove what an
     earlier walkthrough put there. A group whose class is `ENG-CLASS` gets
     the engineer permission bits and its template user. The verify list
     gains `show cli authorization`, and the group summary shows each set's
     size.
   - **WTI:** the Service Name is the factory `wti` again, which per-group
     WTI levels need. A unit set to `shell` by an earlier walkthrough still
     logs every group in at its priv-lvl band but ignores the WTI levels set
     on groups until its Service Name is set back to `wti`. The summary
     shows a group's level set with `wti-level` next to its band
     (`priv-lvl 15 → SuperUser (wti-level override; auto: Administrator)`),
     over TACACS+ and RADIUS, and the hint for an empty SuperUser band
     points at `tacctl group edit <group> wti-level superuser`.
   - The `group commands` usage says that Junos devices do not use these
     rules.

6. **`tacctl group privilege` entries may name a mode.** An entry may start
   with `exec:` (the default when there is none), `exec all:`, `configure:`
   or `configure all:` (`tacctl group privilege add operator 'configure:
   router bgp','exec all: show ip'`); `config cisco` renders it as
   `privilege <mode> [all] level <N> <command>`. `group privilege list`
   shows each mapping's mode in a column, and an unknown mode is refused
   (`Unknown privilege mode 'config' in 'config: router bgp'.`). Entries
   stay in `privileges.<group>` of `tacctl.yaml`. A 0.2.1 binary reports an
   entry with a mode as invalid in `config validate` and prints it after
   `privilege exec level <N>` as it is, so remove such entries before
   rolling back.

7. **`tacctl host show <name> [--all] [--json] [--check]` shows one
   enrolled host in full.** Its connection, its scope and the scope that
   answers its address today (with the drift warning of `host list` and a
   pending staging /32), its address history, pinned keys, sightings,
   notices, the accounts the next sync makes there, and two new records:
   the last enroll or sync (when, by whom, the result or why it failed, the
   client script protocol, the accounts created, updated and removed) and
   the host's facts read over that run's session (OS, sshd version, PAM
   module and version, `useradd`'s UID range). They are kept in
   `/etc/tacctl/hosts/<name>.json`, written by every `host enroll` and
   `host sync` (a failed sync too) and removed by `host unenroll`, and are
   only ever shown; a host not synced since this release shows `not
   recorded (before 0.2.2)`. `--check` logs in read-only and compares the
   host with what tacctl would make it (groups and GIDs, each account's
   UID, primary group and home mode, the PAM files, the client script
   protocol, the host keys against the pins), one line per difference with
   the command that fixes it, exit 1 when there is one. For it the client
   script now records on the host the protocol it ran and the checksums of
   the PAM files it writes (`/var/lib/tacctl-client/protocol` and
   `pam.sha256`; the removal script deletes them). Same tier as `host list`.

8. **`tacctl device add` says what the device calls itself.** With SNMP set
   up, it reads the device's `sysName.0` next to the host-key scan and prints
   `The device calls itself '<sysName>' (SNMP sysName).`; when that is not the
   name given, its `--hostname`, or the first label of either, a warning
   names the fixes (`add --hostname <sysName>, or register it as <name>`) and
   the add goes ahead. A device that does not answer within the timeout (2 s
   by default, one retry), an empty sysName, or no SNMP set up is one info
   line (`No SNMP answer from <address>; no name hint.`), and a NAS-Identifier
   a scan recorded for the address is shown in its place, labelled as such;
   `--no-lookup` skips it. `tacctl device add <address>` with no name offers
   the sysName, lowercased, and takes it after a `y` at a terminal; without a
   terminal or an answer, or for a generic sysName such as a WTI unit's `WTI`,
   it is refused with the usage line. `device check` gains an `SNMP name` row
   (`match` or `differs`) and a `--json` option with a `sysname` field.
   SNMP is v2c or v3 at authPriv (SHA or SHA-256, AES-128), spoken by tacctl
   itself: `tacctl config snmp community|v3-user <user>` asks for the secrets
   without echo (or reads them with `--stdin`) and keeps them in
   `/etc/tacctl/snmp.yaml` (0600, never printed); `config snmp show`, `port`,
   `timeout`, `clear` and `test <address>` complete it, with `snmp.version`,
   `snmp.port`, `snmp.timeout`, `snmp.v3.auth` and `snmp.v3.priv` in
   `tacctl.yaml`. `config snmp` is for administrators only. Nothing of the
   hint is stored.

9. **Each group carries its own device settings, sent by the server at
   login.** `tacctl group junos <group> deny-commands|deny-configuration
   list|add|remove|clear` keeps a group's Junos deny patterns; the server
   sends them, joined into one value, with the group's login class over
   TACACS+ (`junos-exec`) and RADIUS (`Juniper-Deny-Commands`,
   `Juniper-Deny-Configuration`, only where `Juniper-Local-User-Name` is
   sent). A set may not exceed 241 bytes (deny-commands) or 236
   (deny-configuration), the TACACS+ argument limit: `add` refuses a
   pattern that would make it longer, and the render refuses a hand-edited
   one. `tacctl group edit <group> wti-level viewonly|user|superuser|
   administrator|auto` gives a group its own WTI access level instead of
   its priv-lvl band, sent as a `wti` service over TACACS+ (WTI units need
   their factory Service Name `wti`) and as `WTI-Super` over RADIUS.
   `group add` takes `--wti-level`; `group show <group>` prints every
   setting of a group and where it comes from, and is open to the
   read-only tier; `group remove` drops the group's settings. `tacctl
   group preset roles [--dry-run] [--force] [--mgmt-filter <name>]` writes
   starting values for viewer (`readonly`), operator, engineer (created at
   priv-lvl 15 with class `ENG-CLASS` when absent) and superuser: their WTI
   levels, the Junos deny sets of the first three and engineer's Cisco
   command rules; a value already there and different is kept unless
   `--force`, and no user is moved. The settings live in `tacctl.yaml`
   (`junos.<group>`, `wti_level.<group>`). A model without them renders
   `tacquito.yaml` as 0.2.1 did; the RADIUS configuration gains the
   post-auth and reject lines for the new attributes on every install.
   Until the engineer tier (0.2.3), a group's tacctl tier still comes from
   its priv-lvl, so an engineer group at 15 is a superuser on the tacctl
   server: keep engineers out of the server's own scope.
