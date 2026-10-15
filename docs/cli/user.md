# User Commands — `tacctl user`

[Documentation](../README.md) › [CLI reference](README.md)

```
user list

    List all users (name, group, status, pw age, scopes)

user show <name>

    Show user details incl. scope membership and last login (no password prompt)

user add <name> <group>

    Add a new user; lands in default scope. Reserved names `root` and `tacquito` are rejected (they
    collide with OS accounts tacquito resolves locally).

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

    Rename a user

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
