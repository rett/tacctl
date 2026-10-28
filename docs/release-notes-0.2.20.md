# tacctl 0.2.20

0.2.20 adds a required password change, makes the console the login shell of
every managed user, adds a strict mode for the Junos management filter, makes
`root` a break-glass account of a scope's Junos devices, reads more devices
and chassis correctly, and adds `tacctl man`. The numbered list in
`CHANGELOG.md` (0.2.20) is everything that differs from 0.2.19.

## A required password change

A user can be required to change the password before logging in to anything
but the tacctl server. `tacctl user add` and an administrator's
`tacctl user passwd <name>` require it by default (`--no-change-required`
skips it); `tacctl user require-password-change <name>|--all [on|off]` sets
it for existing users, and no existing user is flagged by the upgrade.
Superusers are never held. While the change is required, no device accepts
the user over TACACS+ or RADIUS and no enrolled Linux host answers the
account; on the server the console shows a notice and the password change
dialog, and nothing else runs until the password is changed. Read
`docs/security/login-console.md` before turning it on for everyone.

## Console

- The console is the login shell of every managed user at the next
  `host sync` of the server; there is no switch for it any more. The system
  shell is an opt-in, set by superusers per tier or per user
  (`console system-shell`), and the password cache is each user's own choice
  within the tier's permission (`console password-cache`).
- `console color` and `console list-max` set the colours and the length of
  the console's lists; `-h` and `--help` print the help that `?` prints;
  Tab lists the words alone and bash can bind a help key.
- `tacctl man [topic]` opens the manual page, in the shell and in the
  console, for every tier.

## Junos

- `scope mgmt-acl <scope> mode strict` renders the management filter
  deny-by-default; read the walkthrough conditions before using it.
- `root` is a break-glass account of a scope's Junos devices
  (`scope breakglass <scope> add root`): the walkthrough renders the root
  password and `root-login allow` as comments to fill in, and
  `device config pull|diff` checks them by presence.
- `device config apply` reads every spelling of a commit command, answers
  from a virtual chassis or cluster must name their members, and the end of
  a pending commit is the device's own wall clock.
- A device's own SNMP, system and NETCONF statements are no irregularity in
  `device config plan`; the report lists them on a `Kept:` line.
- A device that does not answer the combined host key scan is asked one key
  type at a time, and the built-in ssh client reads the keys of any device.

## Rollback

`tacctl rollback 0.2.19` is new and takes the release before this one. Every
target now warns, until `--yes`, of users who would gain a system shell or
the password cache and of scopes that record `root`, and removes the
required password change from the store. `docs/install/upgrading.md` lists
what each target does.

## Upgrading

After `tacctl upgrade`, run `tacctl host sync <server>` for the server's own
host entry: the console becomes the login shell of every managed user then,
and not before. Nothing else changes a default; existing users are not
required to change their password until you say so.
