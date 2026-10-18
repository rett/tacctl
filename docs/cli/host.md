# Host Commands — `tacctl host`

[Documentation](../README.md) › [CLI reference](README.md)

```
host list

    Show enrolled Linux hosts (target, scope, server, METHOD, users); a host with a break-glass
    hold is marked BREAK-GLASS in a STATE column

host show <name> [--all] [--json] [--check]

    One enrolled host in full: connection, scope (and the one answering its address), address
    history, pinned keys, sightings, notices, the accounts the next sync makes, the last enroll or
    sync and the host's facts; --check compares the host with what tacctl would make it (exit 1 on a
    difference; superuser only: it logs in). A held host shows its break-glass hold (breakglass in
    --json) and is not checked

host enroll <[user@]host>|--local [opts]

    Install TACACS+ or RADIUS login on a host over SSH and register it

    --method tacplus|radius
        pam_tacplus (TACACS+) or pam_radius_auth (RADIUS); re-enroll with the other to switch
    --scope <name>
        The host's scope (default: its registered one, else the scope covering its address)
    --server <address>
        Address the host should use for this server (default: detected)
    --name <name>
        Registry name (default: short hostname; not a tacctl word; names are not case-sensitive)
    --port <n>, --identity <file>
        SSH port and key
    --build-on-host
        (tacplus) compile pam_tacplus on the host instead of in a container here
    --yes
        (enroll and move) Move a registered host to another scope even when that deletes accounts
    --staging
        (with --scope) Provisioned off-site: the bench address joins the scope as a /32 until the
        host is seen in place

host sync <name>|--all

    Push account adds, deletions, expiries and tier changes; pins the host's ssh keys if none are
    (enroll pins them too)

    --allow-uid-mismatch
        (enroll and sync) accept a UID conflict on the host instead of stopping
    --remove-home
        (enroll and sync) delete removed users' home directories without asking (on a terminal each
        is asked; without one they are kept)

host move <name> [<scope>]|--all

    Move an enrolled host to another scope (default: the one answering its address; --all: every
    host another scope answers); asks before deleting accounts

host provisioner <name> rotate <user> (--key <file>|--password) [--remove-old [--remove-home]]
                 [--dry-run] [--yes]

    Switch the account tacctl logs in to the host with: create it over the login in use, prove it in
    a new connection (sudo id -u gives 0), then change the registry; --remove-old removes the old
    account last, over the new one

host unenroll <name> [--force]

    Remove the login method from the host (accounts are kept) and its pinned host keys; --force
    drops it from the registry even if the removal fails

host default-method [tacplus|radius]

    Show or set the method for hosts enrolled without --method (host.default_method)
```

`host enroll` (so `host move`) and `host unenroll` take a snapshot just
before the registry changes, once the script on the host has succeeded; `host
sync` takes none. It holds the registry, the host records, `staging` and the
UID ledger, so `backup restore` can put them back (see
[Backup commands](maintenance.md#backup-commands--tacctl-backup)).

A host with a [break-glass hold](breakglass.md)
(`tacctl breakglass hold <host>`) is one the server does not answer, so that
its local administrator and console work. The `host` verbs that log in over
ssh refuse it: `host sync`, `host show --check`, `host enroll` of the
registered host (and so `host move`), `host target <name> <target>`,
`host provisioner <name> rotate` and `host unenroll` (also with `--force`).
They name the hold (since, by whom, why) and
`tacctl breakglass release <name>`; nothing is attempted over ssh and nothing
is changed. The same refusal stands when the device registry, which records
the host's address, cannot be read. `host sync --all` skips a held host and
says so.
`host target <name>` without a change, `host list` and `host show` only read,
and `tacctl ssh` warns and connects.
