# tacctl 0.2.23

0.2.23 lets a user have an email address, gives each SNMPv3 level a pool of
users with one default, registers a copy of a device at a bench address
(`device clone`) and moves it into place (`device rename --replace`), extends
`emergency lockdown` to the enrolled Linux hosts, and checks the source
addresses a device uses to reach this server. The numbered list in
`CHANGELOG.md` (0.2.23) is everything that differs from 0.2.22.

## Devices

- `tacctl device clone <name> <new> --staging <bench-ip>` registers a copy of
  a device's intent (the registry settings, the SNMP settings and
  credentials, the NETCONF settings, the timing scale, the configuration
  blocks) at a bench address. It does not copy the address, the name, the
  host keys, the acknowledged notices, the break-glass hold or the pull
  record. Engineers may clone within their own scopes.
- `tacctl device rename <replacement> <name> --replace` removes the original
  with its files after a snapshot and one confirmation, moves the replacement
  to the original's address, which ends the bench address, and clears the
  original's hold. An original with a hold needs a superuser.
- `device rename` and `host rename` carry the bench address that was staged
  under the old name.
- The settings a device keeps for its own AAA server (a source address, a
  timeout, a retry, a routing instance) are no longer listed as differences.
- The source address of the AAA client must be an address of the device; a
  source that no interface holds is an irregularity in the plan, the diff and
  the lists. `device check --sources` and `device scan --sources` connect to
  such a source address and warn when it is unreachable or presents another
  host key.

## SNMPv3

- The version, the port, the timeout and the two protocols stay one setting
  per level (the config, a scope, a device). The v3 users are a pool of
  names with their passphrases and one default: `v3-user add|remove|default|
  list`. A device uses its own default, else its scope's, else the config's,
  or any user of the pools it can see.
- A version 1 credential file reads as a pool of one user, nothing rewrites
  it at the upgrade, and a command saves version 1 again whenever the
  content fits it.

## Users and hosts

- `user add --email <address>` and `user email <name> [<address>|clear]` set
  an optional email address; the superuser sets it, `user show` and
  `store show --json` carry it, an audit line never does, and no mail is
  sent.
- A user change that touches an account on this server (add, remove, rename,
  group, scope, enable, disable, `require-password-change`) syncs this
  server's own accounts at once, so a new user can log in to change the
  password. The other enrolled hosts it reaches are named in one notice and,
  on a terminal, offered a sync.
- `emergency lockdown enable|disable` also closes SSH key logins and
  forwarding on the enrolled hosts of the scope, through `host sync` (a
  static sshd drop-in, script protocol 7). A host that is unreachable stays
  on a pending list that `status` shows; a host enrolled or synced during a
  lockdown gets the drop-in; `enable` ends the live sessions of the accounts
  the drop-in matches.

## Backups

- `tacctl backup keep` and `backup unkeep` persist a snapshot beyond the
  retention. `backup recover <snapshot> [--only email,snmp-users]` puts back
  only what a rollback dropped.

## Rollback

`tacctl rollback 0.2.22` is new. 0.2.22 reads every file this release writes
but the users' email addresses and the SNMP credential files in version 2, so
the target removes the email addresses and writes the credential files in
version 1 again, after a snapshot that it keeps, and needs `--yes` when it
drops anything. It also puts back 0.2.22's per-tier sudoers drop-in. The
older targets do the same. `backup recover` returns what was dropped.

## Upgrading

No file is rewritten at the upgrade. The per-tier sudoers drop-in gains the
engineers' rule for `device clone`. After a rollback, the older release
reports the rendered config as out of date until its first render.
