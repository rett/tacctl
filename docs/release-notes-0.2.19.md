# tacctl 0.2.19

0.2.19 widens what the device configuration blocks can state, lets
engineers do the device work of their own scopes, adds an emergency
lockdown and fixes several device reads. The numbered list in
`CHANGELOG.md` (0.2.19, items 1 to 18) is everything that differs from
0.2.18.

## Emergency lockdown

`tacctl emergency lockdown <scope> enable|disable|status` is the
superuser's. It refuses the logins of the groups named (default every
group that is not a superuser's, or the groups of one `--tier`) on a scope
or on every scope, at render time: the server keeps answering and says no, and the groups of the
superuser tier are never locked. There is no timer; `disable` renders the
files back as they were. Every command that names a locked scope prints a
red notice, and `status`, `config validate` and `backup restore` show a
lockdown that stands. Read `docs/cli/emergency.md` before using it.

## Blocks

- The Junos and IOS `system` blocks are closed tables of statements:
  syslog, the login announcement, login retry and password policy, `ip ssh`
  settings, `clock summer-time`, timestamps and the IOS `banner motd` and
  `banner exec` beside `banner login`. They are compared, planned in place,
  adopted from a device and admitted by the apply allow-list.
- An `absent` line (`absent system services telnet`, `absent ip http
  server`) states a service the scope requires to be off; the plan deletes
  it once, and the apply admits exactly that delete.
- A plan and a walkthrough say which block each statement comes from. A
  scope's block states only what is the same for every device (the
  statements that name the device itself belong to the device's block), and
  `block show` prints the login message as it is.
- `?` describes the vendors, the verbs and the block names of `scope block`
  and `device block`.

## Devices

- Engineers enroll, collect, onboard, sync and apply for the devices of
  their own scopes; `device config forget` and `shapes` stay the
  superuser's. `tacctl upgrade` rewrites the tiers sudoers drop-in.
- `device support-bundle` collects a scrubbed, read-only bundle of what a
  developer needs of a device.
- A mixed Junos virtual chassis and an older Junos release pass the
  pre-flight, and a login's permissions are read from the name of each row.

## Hosts and commands

- A host name may hold dots (`host rename web1 web1.example.net`); the
  target, address and scope of the host stay as they are.
- An unknown command is answered before `sudo` asks for a password.

## Rollback

`tacctl rollback 0.2.18` is new and takes the release before this one: its
`--apply` puts back the tiers drop-in 0.2.18 writes. Every rollback target
now refuses while an emergency lockdown locks a group (an older release
would render every locked user back into the scope), removes a partial
lockdown record, and warns, until `--yes`, of the `system` blocks that use
statements this release added; an older release lints those as errors, so
take the statements out before the upgrade. The block files are not
rewritten.

No setting changes its default and no exit status changes. The new
`emergency.lockdown.<scope>.*` keys of `tacctl.yaml` exist only while a
lockdown stands.
