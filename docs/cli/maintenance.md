# Maintenance commands

[Documentation](../README.md) › [CLI reference](README.md)

## Backend Commands — `tacctl backend`

```
backend list

    Every backend: protocol, implementation, installed, enabled, service

backend status [<id>]

    Service and listener state of every backend (or one)

backend enable <id> [-y]

    Install the backend if needed, enable it, render its config, start it

backend disable <id> [-y]

    Stop and disable it, take it out of backends.enabled (confirms); its package and rendered files
    stay
```

## Store Commands — `tacctl store`

```
store show [--json]                          Print the model (users, groups, scopes, filters);
                                             superuser-only (secrets, hashes)
store import [--check|--force] [--replace] [<file>]
                                             Import an old-style tacquito.yaml (default: the live
                                             one). --check writes nothing and proves equivalence;
                                             --force drops what the store cannot represent;
                                             --replace overwrites a store
store rollback                               Restore the pre-store tacquito.yaml, remove the store,
                                             restart (legacy read-only mode)
```

## Log Commands — `tacctl log`

```
log tail [-f|--follow] [n] [--backend <id>]

    Last N entries (default 20): TACACS+ journal; RADIUS auth log and daemon log; -f/--follow
    follows new ones until Ctrl-C

log search <term> [--backend <id>]

    Search the logs for a username or keyword (TACACS+: last 7 days)

log failures [--backend <id>]

    Auth failures from the last 24 hours

log accounting [n] [--backend <id>]

    Last N accounting records

log clear [--force|-y] [--backend <id>]

    Purge the TACACS+ journal and truncate the accounting logs; truncate the RADIUS auth, accounting
    and daemon logs (prompts)
```

With more than one backend enabled each subcommand shows every backend's log in a section headed by its name; `--backend <id>` (anywhere on the line) shows one.

TACACS+ authentication lines read `accepting user [<user>] from [<address>] using a bcrypt password` (or `failed to validate the user ...`). `<address>` is the device or host that asked; when it sent them, `; client [<address>] port [<port>]` follows: the person's address and terminal as the client reports them. Devices and `sshd` give them; a `sudo` prompt on the server itself gives none, so such a line names the server (`127.0.0.1`) only.

## Backup Commands — `tacctl backup`

```
backup list                    Show snapshots (newest first), then old-style backups
backup diff [timestamp]        Diff store.yaml and tacctl.yaml against a snapshot (default: most
                               recent)
backup restore <ts> [--legacy] Restore a snapshot (with confirmation); --legacy for an old-style
      backup
```

A backup is a snapshot of the canonical files, `/etc/tacctl/backups/<timestamp>/{store.yaml,tacctl.yaml,manifest}`, taken automatically before every change that would alter them (nothing is added when they already equal the newest snapshot). The manifest records `rendered.json` and the tacctl version. The newest 30 snapshots are kept. Snapshots hold shared secrets and password hashes: the directory is `0700`, the files `0600`, and `backup diff` and `backup restore` are superuser-only.

A snapshot also holds the files of the enrolled Linux hosts: `linux-hosts`
(the registry), `hosts/` (one record per host), `staging` (the staging
addresses) and `linux-uids` (the UID ledger), in the same modes. `linux-hosts`
is in every snapshot, empty when there is no registry, so a snapshot that has
it knows the hosts; the provisioner's lock files and the caches are not kept.
`host enroll`, `host move` and `host unenroll` take a snapshot just before they
change the registry; `host sync` takes none. A snapshot made by tacctl 0.2.13
or older has no `linux-hosts`, and tacctl 0.2.13 ignores the host entries of a
newer one.

`backup restore <ts>` puts back both files, re-renders every enabled backend's config (a hand-edited file is kept under `backups/legacy/` first), and restarts the backends. It snapshots the current state first, so a restore can be undone with another restore, and it changes nothing if the snapshot is invalid or the render fails. The snapshot's `backends.enabled` comes back with the rest of `tacctl.yaml`: a backend it enables must already be installed (otherwise nothing changes and the message says to run `backend enable`) and is started; one it leaves out is stopped and disabled.

A snapshot that knows the hosts also puts the host files back: `linux-hosts`
whole, `hosts/` made to match (a record the snapshot lacks is removed),
`staging` back or removed, and `linux-uids` as it was. A snapshot without
`linux-hosts` leaves all four as they are. No host is touched and nothing is
reconciled. Before the question, and again after the restore, a note names the
hosts that come back, those that go and those registered differently. The
restored ledger can forget a number that a host already holds, so the note also
names every user whose UID it drops or changes. A host that comes back after
`host unenroll` is still cleaned up: `host sync`, `host show <name> --check`,
or `host unenroll <name>` again. A host that goes stays set up: `host enroll`
it again, or `host unenroll <name> --force` after that. The snapshot of the
current state taken first holds the live host files, so another restore undoes
this one.

`backup diff` adds `linux-hosts`, `staging`, `linux-uids` and each host record,
each only where either side has one. A snapshot that does not know the hosts
(taken by 0.2.13 or older) is not compared with them, because a restore of it
leaves the live host files alone: one line, `host files: not in this snapshot
(it predates 0.2.14)`, stands in their place, and only when the server has
host files. `backup list` is unchanged, and `restore --legacy` leaves the host
files alone.

Old-style `tacquito.yaml.<timestamp>` files (made before the store existed, or kept in `backups/legacy/`) are listed after the snapshots. `backup restore <timestamp> --legacy` runs `store import --check` on one, then imports it. Without a store (legacy read-only mode) `list`, `diff` and `restore` work on those files.
