# User Commands — `tacctl user`

[Documentation](../README.md) › [CLI reference](README.md)

```
user list

    List all users (name, group, status, pw age, scopes)

user show <name>

    Show user details incl. scope membership and last login (no password prompt)

user add <name> <group>

    Add a new user; lands in default scope. The name is lower case (`Names are lower case: use
    'alice'.`): lower-case letters, digits, `_` and `-`. A period is refused (`Username must
    contain only letters, numbers, underscores and hyphens (a period cannot be part of a Linux
    account name).`): every user has an account on the tacctl server. Reserved names `root` and
    `tacquito` are rejected (they collide with OS accounts tacquito resolves locally). A new user
    must change the password at the first login to this server (see "A required password
    change").

user add <name> <group> --no-change-required

    Skip the required password change

user add <name> <group> --scopes <name>[,name...]

    Grant specific scopes at creation

user add <name> <group> --hash <hash>|-

    Add user with pre-generated bcrypt hash (`-`: read it from standard input)

user remove <name>

    Remove a user (with confirmation); the user's `console system-shell user` and `console
    password-cache` settings, if any, are dropped and the command says so. Refused, with nothing
    changed, while console.yaml cannot be read (so that no setting is left for the next user of the
    name); the same holds for `user add` and `user rename`

user passwd <name>

    Change password (with confirmation); the reset requires a password change of the user, as a
    new user does (see "A required password change")

passwd

    Change your own password (asks for the current one, which the new one must differ from; all
    tiers); it lifts a password change that was required

user passwd <name> --hash <hash>|-

    Change password with pre-generated bcrypt hash (`-`: read it from standard
    input)

user passwd <name> --no-change-required

    Skip the required password change (lifts one that stands)

user require-password-change <name> [on|off]
user require-password-change --all [on|off]

    Require (on, the default) or lift (off) a password change, of one user or every user

user disable <name>

    Disable (preserves hash for re-enable)

user enable <name>

    Re-enable a disabled user

user rename <old> <new>

    Rename a user; the new name is lower case and follows the rules of `user add`. The user's
    `console system-shell user` setting moves to the new name, and the command says so. Changing
    only the spelling (`user rename Alice alice`) fixes a name from before. Devices match the
    typed login name exactly, so the rename changes what the person types at the device. The user
    keeps the Linux UID: the line of the old name in `linux-uids` becomes the new name's, in
    place, and the command says `UID <uid> follows the rename (linux-uids).` With enrolled hosts
    that list the user it also says that the next `host sync` renames the account there by its
    UID, home kept where it is. A user with no line is renamed as before. A new name that already
    has a line keeps its own number, the ledger is left alone and a warning says that hosts remove
    the old account and create the new one. If the ledger cannot be written after the rename, the
    command names the snapshot to restore and exits 1. The move is made under the ledger's lock: a
    `host sync` builds its script from the ledger under the same lock, so it sends the names as
    they were before the rename or after it, never a mix; an account created under the old name is
    renamed at that host's next sync. If the ledger is locked by another command for 30 seconds,
    the rename stops at the snapshot with nothing changed (see [Consistent UIDs and
    GIDs](../hosts/ids-and-groups.md)). A user whose name has a period (see "A name with a period"
    below) is renamed to a name that has none.

user move <name> <group>

    Move user to a different group (keeps password)

user verify <name>

    Show user details and verify password

user scope <name>

    List the user's scopes (orphan refs flagged red)

user scope <name> add <s>[,s...]

    Grant one or more scopes

user scope <name> remove <s>[,s...]

    Revoke one or more scopes

user scope <name> replace <s>[,s...]

    Replace the full scope list

user scope <name> remove --all

    Revoke every scope (with confirmation)
```

**Scopes and this server.** A user's scopes are where the user logs in to
devices and enrolled hosts. Every user also logs in to the tacctl server and
its console, unless disabled or of tier none, without a scope for it: the
listings and Tab do not offer one, and a scope list that is empty means no
device. A user kept off the server is disabled (`user disable`) or in a group
of tier none. When a command next writes a user's record, a stored copy of the
server's own scope (from an install before 0.2.21) is dropped from it.

**A name with a period.** A user name is letters, digits, `_` and `-`. A period cannot be part of a
Linux account name, and every user has an account on the tacctl server. A store from 0.2.20 or 0.2.21
can still hold a name with periods; it keeps loading, so the user can be shown, listed, disabled,
moved, given scopes, removed and renamed. `user rename <old> <new>` is the way out, and the new name
has no period. Meanwhile:

- `config validate` reports each such user as an error with the command that renames it
  (`tacctl user rename alice.smith <new-name>`), and `config validate --fix-names` does not offer a
  name with a period.
- `tacctl upgrade` refuses and names each user with the rename command. Rename such a user
  *before* upgrading from 0.2.20 or 0.2.21 (`user rename` works there): the old release's upgrade
  has already replaced `tacctl` and the tacquito build when the new `tacctl` refuses, and says so
  (the store, the configuration and the services are not changed); after the rename, `tacctl
  upgrade` finishes it.
- `tacctl rollback` to any target but 0.2.20 (which reads such a name) is refused (the dry run too),
  since the releases it goes to refuse the name; the refusal lists each user with the rename
  command.
- `tacctl passwd`, `user passwd` and `user require-password-change` refuse the name, and for a user
  that stands add `rename it first: tacctl user rename <name> <new-name>`. `config linux uid <user>`
  prints the number the ledger has for the user, if any, and `config linux uid <user> <uid>` is
  refused. `host sync` skips the user with a warning (no account on enrolled hosts).

**A required password change.** A user who must change the password can log in to the tacctl
server only: every device refuses the user, as it refuses an unknown user, and every other enrolled
Linux host has the account expired from its next `host sync`, until the password is changed (a
device in a scope shared with the server and port forwarding by a tier of `console forwarding
tiers` excepted: see *Devices* below and [Console](console.md)). `user add` and `user passwd` (an
administrator's reset, as opposed to the user's own `tacctl passwd`) require it by default and
`--no-change-required` skips it; `user require-password-change <name>|--all [on|off]` flags or
clears users on demand. An existing user is
not flagged by an upgrade. The flag is the user's `password_change_required` in `store.yaml`, written
only when set.

- *Superusers are never held to it.* The tier of the user's group decides each time the flag is used
  (a render, a login, a command), not when it is set: a flagged user moved into a superuser group is
  exempt from then on, and one moved out must change the password. `user add`, `user passwd` and
  `require-password-change on` do not set it for a superuser and say so, and `on` ends with `Flagged
  N, skipped M, already required K.`
- *A reset keeps what stands.* Only `user passwd --no-change-required`, the user's own `tacctl
  passwd`, `require-password-change off` and a superuser's reset clear the flag. A reset that cannot
  require a change for another reason (no login on the server, the host registry cannot be read) leaves
  a flagged user flagged and says so with the reason; for an unflagged user it says the change could not
  be required.
- *Accounts are made by the sync.* The account of a new (or renamed) user exists on the server only
  after the next `host sync` of it; `user add` and `user rename` of a user who must change the password
  say so, since until then the user can neither log in nor change the password.
- *A user must be able to change it.* The flag is not set, and the verb says why, for a user with no
  login on this server: the server is not enrolled (`host enroll --local`), the name is no Linux
  account name (a leftover name with a period), the user is disabled, the group has no priv-lvl, or,
  for a server still registered in a scope it shares with devices, the user is not in that scope.
  `off` clears the flag of the user or of every user who has it, a superuser's included.
- *Devices.* The TACACS+ and RADIUS configuration put the user in the scope this server is enrolled
  in (`host enroll --local`) and in no other, and only in the protocol of the method it is enrolled
  with; in the other protocol the user is not rendered at all, so a catch-all scope of that protocol
  does not keep its devices open. The login at tacctl, which comes from the server, works and a
  device finds no scope the user is in. The server's logins come from `127.0.0.1`, and from the
  server address (`server.addresses`, set by `host enroll --local`), and the server's own login
  answers both. The stored scopes are not changed, and clearing the flag puts the user back. A change
  of the flag restarts the backend whose file changed (see [Service restart](conventions.md)). An
  install from before 0.2.21 whose server is still registered in a scope it shares with devices
  (until `host enroll --local`) keeps the devices of that scope accepting the user, and the verbs
  that flag warn and name the prefixes.
- *Enrolled hosts.* On every enrolled Linux host but this server (`host enroll --local`), the next
  `host sync` expires the account of a user who must change the password, as it expires a disabled
  user's (a password and an SSH key both fail; the files are kept), and the sync after the change
  opens it again. The server's own sync keeps the account: the password is changed there. Until a
  host is synced it is as it was, so `require-password-change`, `user passwd` and `tacctl passwd`
  name the hosts of the user's scopes with `tacctl host sync --all`.
- *A flagged user must be able to log in.* A user who must change the password and has no login on
  the server (the server's own login no longer answers its addresses, the backend of the server's
  own logins is not enabled, the server not enrolled) could change nothing and enter
  nothing, so a change that would leave one is refused with nothing changed, with the command that
  lifts the requirement first (`user require-password-change <name> off`):
  - before anything is written: `user scope` removing the scope or replacing the list, `scope
    prefixes` removing a prefix, `scope protocols`;
  - by the guard of every other write of the store or `tacctl.yaml`, under the apply lock, put back
    before anything is rendered (after the pre-change snapshot): `scope add` of a scope that answers
    the server's address more closely than its own, `group edit <group> tier` or `priv-lvl` (or
    another group write) that newly holds a member with no login on the server, `backend disable` of
    the backend of the server's own logins;
  - `host forget` and `host unenroll` of this server, and `host enroll --local` with another method
    than the registered one, while any user is flagged (the backends' files are rendered from the
    server's registration, so it is changed with the requirement lifted). `host enroll --local` with
    the registered method is not refused, also for a server registered in a scope it shares with
    devices: it gives the server the managed scope, which every user is a member of, so a flagged
    user keeps a login on the server, and the devices of the old scope stop accepting the old
    password (this is what the shared-scope warning asks for). It is refused only when it would
    leave a flagged user with no login on the server.

  `scope rename` renames the registration with the scope, before the backends render.
- *Commands.* While a password change is required of the caller, and the caller is no superuser,
  every command but `passwd`, `version` and `help` is refused with one message and exit status 1
  (`A password change is required of '<user>': ...`). This covers a plain shell and `ssh <server>
  tacctl ...`; root, a superuser and a local administrator who is no tacctl user are not affected.
  The refusal is logged as `password-change DENY` ([Audit log](../security/audit.md#refusals)); the live names that Tab asks for in a plain shell are refused without a message or a line.
- *Listing.* `user list` marks the date of a user who must change the password with `(change
  required)`, `user show` has a `Password change` line, and `status` counts the users pending. A
  flagged user who cannot log in to change it is marked `flagged, cannot log in to change it` (with
  the reason in `user show`), and one whom devices of a shared scope still accept `flagged, devices in
  a scope shared with the server still accept the password`; `status` names both groups.
- *Older releases.* A release before 0.2.20 refuses the key, so every `tacctl rollback` target
  removes it after a snapshot and warns which users get their device access back (see
  [Rolling back](../install/upgrading.md#rolling-back)).

**A hash kept off the command line.** `--hash -` reads the hash from one line
of standard input (typed without echo at a terminal; a control character in
it is refused), so it is not on the command line: sudo's log records the whole command line and `ps` shows it
while the command runs. `--hash <hash>` works as well.

Each change also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `user add name= group= scopes=`, `user passwd name= source=prompt|hash|generated`, `user rename from= to= uid=`, `user scope name= op= scopes=` and the like, and `user password-change name= state=required|cleared via=require|add|passwd|self` when a requirement is set or lifted, never a password or a hash ([Audit log](../security/audit.md#detail-lines)).
