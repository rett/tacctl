# User Commands — `tacctl user`

[Documentation](../README.md) › [CLI reference](README.md)

```
user list

    List all users (name, group, status, pw age, scopes)

user show <name>

    Show user details incl. scope membership and last login (no password prompt)

user add <name> <group>

    Add a new user; lands in default scope. The name is lower case (`Names are lower case: use
    'alice'.`): lower-case letters, digits, `_` and `-`, and a period between two of them
    (`alice.smith`): never first, never last, never two in a row (`.alice`, `alice.`,
    `alice..smith`, `.` and `..` are refused). Reserved names `root` and `tacquito` are
    rejected (they collide with OS accounts tacquito resolves locally). A name with a period is
    no Linux account name: `host sync` skips it with a warning, so the user has no account on
    enrolled hosts and logs in at devices only (see "A period in a name" below).

user add <name> <group> --scopes <name>[,name...]

    Grant specific scopes at creation

user add <name> <group> --hash <hash>|-

    Add user with pre-generated bcrypt hash (`-`: read it from standard input)

user remove <name>

    Remove a user (with confirmation)

user passwd <name>

    Change password (with confirmation)

passwd

    Change your own password (asks for the current one; all tiers)

user passwd <name> --hash <hash>|-

    Change password with pre-generated bcrypt hash (`-`: read it from standard
    input)

user disable <name>

    Disable (preserves hash for re-enable)

user enable <name>

    Re-enable a disabled user

user rename <old> <new>

    Rename a user; the new name is lower case, with periods as for `user add`. Changing only the
    spelling (`user rename Alice alice`) fixes a name from before. Devices match the typed login
    name exactly, so the rename changes what the person types at the device. The user keeps the
    Linux UID: the line of the old name in `linux-uids` becomes the new name's, in place, and the
    command says `UID <uid> follows the rename (linux-uids).` With enrolled hosts that list the
    user it also says that the next `host sync` renames the account there by its UID, home kept
    where it is. A user with no line is renamed as before. A new name that already has a line
    keeps its own number, the ledger is left alone and a warning says that hosts remove the old
    account and create the new one. If the ledger cannot be written after the rename, the command
    names the snapshot to restore and exits 1. The move is made under the ledger's lock: a `host
    sync` builds its script from the ledger under the same lock, so it sends the names as they
    were before the rename or after it, never a mix; an account created under the old name is
    renamed at that host's next sync. If the ledger is locked by another command for 30 seconds,
    the rename stops at the snapshot with nothing changed (see [Consistent UIDs and
    GIDs](../hosts/ids-and-groups.md)). A user that has a UID in `linux-uids`, or an account on an
    enrolled host, is not renamed to a name with a period: the next sync would remove the account.
    The command says so and changes nothing.

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

**A period in a name.** A user name may hold periods between its parts (`alice.smith`, `a.b-c_d`):
letters, digits, `_` and `-` in runs joined by single periods. It never starts or ends with a period,
never has two in a row, and is never only periods; the length and the reserved names (`root`,
`tacquito`) are as before. Group, scope and device-class names are not changed: a Juniper class name
has the shape a user name had (letters, digits, `_` and `-`) and still has it, so a class cannot hold
a period. What a period means elsewhere:

- *Linux accounts.* A Linux account name here is lower-case letters, digits, `_` and `-`
  ([Account lifecycle](../hosts/account-lifecycle.md)), so `host sync` and `host enroll` skip a user
  with a period (`Skipping 'alice.smith': not a valid Linux account name ...`), `host show` lists it
  as skipped, and no UID is given to it. The user logs in at devices over TACACS+ or RADIUS only.
  `config linux uid <user> <uid>` refuses such a user, and `user rename` refuses to give a name with
  a period to a user that has a UID or an account on a host.
- *Rendered configuration.* The user is written to `tacquito.yaml` as a quoted name, and its
  password authenticator gets an anchor with each period written `_dot_` (YAML anchors cannot hold a
  period); the FreeRADIUS `users` file takes the name as it is.
- *Older releases.* A release before 0.2.20 refuses a store with such a name: rename those users
  before `tacctl rollback`.

**A hash kept off the command line.** `--hash -` reads the hash from one line
of standard input (typed without echo at a terminal; a control character in
it is refused), so it is not on the command line: sudo's log records the whole command line and `ps` shows it
while the command runs. `--hash <hash>` works as well.

Each change also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `user add name= group= scopes=`, `user passwd name= source=prompt|hash|generated`, `user rename from= to= uid=`, `user scope name= op= scopes=` and the like, never a password or a hash ([Audit log](../security/audit.md#detail-lines)).
