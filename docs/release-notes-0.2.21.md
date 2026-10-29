# tacctl 0.2.21

0.2.21 lets every user log in to the tacctl server and its console, sets up
the machine's own login during `install` and `upgrade`, records the server
address as a setting of its own, and makes `ssh` ask for the password once,
before it connects. The numbered list in `CHANGELOG.md` (0.2.21) is
everything that differs from 0.2.20.

## The server login

- Every user can log in to the tacctl server and its console, whatever
  their scopes, unless disabled or in a group of tier none. The login is a
  scope called `tacctl` that tacctl manages: it is reserved, hidden from
  every listing and completion, and no command edits it. Device logins keep
  the user's own scopes.
- `tacctl install` and `tacctl upgrade` set this machine's own login up
  (`install -y` agrees, an upgrade asks on a terminal only, and nothing is
  half applied when a step is refused). `tacctl host enroll --local` stays
  the way to rebuild, move or repair a server.
- The address devices and hosts reach the server at is the new setting
  `server.addresses` (a list that holds one address for now), shown and
  changed by `tacctl server addresses [list]|add|remove|replace <ip>`. With
  no setting, the address of the interface with the default route is used
  and said. The device walkthroughs, `config linux script` and host
  enrolment default to it, and follow the listener ports you configured.

## Devices and ssh

- A Junos virtual chassis of one member is applied to like a single device.
- With the password cache on, `ssh` and `device ssh` ask for the password
  themselves the first time, before they connect, and store it; the next
  `ssh` to any device asks nothing.
- `user rename` to a name with a period names the ways forward.

## Rollback

`tacctl rollback 0.2.20` is new. Every target adds the `tacctl` scope to the
scopes of each user who logs in to the server, since the older releases need
it there; it warns, and `--apply` needs `--yes`.

## Upgrading

A scope that you created and called `tacctl` is never taken over. While it
exists, `host enroll --local`, the sync of the server and `config validate`
stop with one line; rename it first (`scope rename tacctl <new-name>`).
After `tacctl upgrade`, check that the new line about the machine's own
login is as you expect, and run `tacctl host sync <server>` as before.
