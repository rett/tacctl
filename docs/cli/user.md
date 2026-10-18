# User Commands — `tacctl user`

[Documentation](../README.md) › [CLI reference](README.md)

```
user list

    List all users (name, group, status, pw age, scopes)

user show <name>

    Show user details incl. scope membership and last login (no password prompt)

user add <name> <group>

    Add a new user; lands in default scope. The name is lower case (`Names are lower case: use
    'alice'.`): lower-case letters, digits, `_` and `-`. Reserved names `root` and `tacquito` are
    rejected (they collide with OS accounts tacquito resolves locally).

user add <name> <group> --scopes <name>[,name...]

    Grant specific scopes at creation

user add <name> <group> --hash <hash>

    Add user with pre-generated bcrypt hash

user remove <name>

    Remove a user (with confirmation)

user passwd <name>

    Change password (with confirmation)

passwd

    Change your own password (asks for the current one; all tiers)

user passwd <name> --hash <hash>

    Change password with pre-generated bcrypt hash

user disable <name>

    Disable (preserves hash for re-enable)

user enable <name>

    Re-enable a disabled user

user rename <old> <new>

    Rename a user; the new name is lower case. Changing only the spelling (`user rename Alice
    alice`) fixes a name from before. Devices match the typed login name exactly, so the rename
    changes what the person types at the device. The Linux UID ledger is keyed by name and is left
    alone: the new name gets a number at the next host sync and the old one keeps its own

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
