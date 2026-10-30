# Maintenance commands

[Documentation](../README.md) › [CLI reference](README.md)

## Backend Commands — `tacctl backend`

```
backend list

    Every backend: protocol, implementation, installed, enabled, service

backend status [<id>]

    Service and listener state of every backend (or one)

backend enable <id> [--yes]

    Install the backend if needed, enable it, render its config, start it

backend disable <id> [--yes]

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
                                             --replace overwrites a store (keeping what the
                                             file cannot hold: password dates, a required
                                             password change)
store rollback                               Restore the pre-store tacquito.yaml, remove the store,
                                             restart (legacy read-only mode)
```

## Log Commands — `tacctl log`

```
log tail [-f|--follow] [<n>] [--backend <id>]

    Last <n> entries (default 20): TACACS+ journal; RADIUS auth log and daemon log; -f/--follow
    follows new ones until Ctrl-C

log search <term> [--backend <id>]

    Search the logs for a username or keyword (TACACS+: last 7 days)

log failures [--backend <id>]

    Auth failures from the last 24 hours

log accounting [<n>] [--backend <id>]

    Last <n> accounting records

log clear [--force|--yes] [--backend <id>]

    Purge the TACACS+ journal and truncate the accounting logs; truncate the RADIUS auth, accounting
    and daemon logs (prompts)
```

With more than one backend enabled each subcommand shows every backend's log in a section headed by its name; `--backend <id>` (anywhere on the line) shows one.

TACACS+ authentication lines read `accepting user [<user>] from [<address>] using a bcrypt password` (or `failed to validate the user ...`). `<address>` is the device or host that asked; when it sent them, `; client [<address>] port [<port>]` follows: the person's address and terminal as the client reports them. Devices and `sshd` give them; a `sudo` prompt on the server itself gives none, so such a line names the server (`127.0.0.1`) only.

## Backup Commands — `tacctl backup`

```
backup list                    Show snapshots (newest first), then old-style backups
backup diff [<timestamp>]      Diff store.yaml and tacctl.yaml against a snapshot (default: most
                               recent)
backup restore <ts> [--legacy|--keep-uids]
                               Restore a snapshot (with confirmation); --legacy for an old-style
                               backup; --keep-uids leaves the UID ledger as it is
backup keep <ts> [--note <text>]
                               Copy a snapshot to backups-kept/, where no retention reaches it
backup unkeep <ts> [--yes]     Remove the kept copy of a snapshot (with confirmation)
```

A backup is a snapshot of the canonical files, `/etc/tacctl/backups/<timestamp>/{store.yaml,tacctl.yaml,manifest}`, taken automatically before every change that would alter them (nothing is added when they already equal the newest snapshot). The manifest records `rendered.json`, the tacctl version and who took the snapshot: `sid` (the session id of the audit lines), `user` and `command` (the command's words, without arguments). The newest 30 snapshots are kept. Snapshots hold shared secrets and password hashes: the directory is `0700`, the files `0600`, and `backup diff`, `backup restore`, `backup keep` and `backup unkeep` are superuser-only.

A snapshot also holds the files of the enrolled Linux hosts: `linux-hosts`
(the registry), `hosts/` (one record per host), `staging` (the staging
addresses) and `linux-uids` (the UID ledger), in the same modes. `linux-hosts`
is in every snapshot, empty when there is no registry, so a snapshot that has
it knows the hosts; the provisioner's lock files and the caches are not kept.
`host enroll`, `host move`, `host unenroll`, `host rename` and `host forget`
take a snapshot just before they change the registry; `host move --all`
takes one before the first move and none per host, so a long batch does not
push the state before it out of the newest 30. `host sync` takes none. A
snapshot made by tacctl 0.2.13 or older has no `linux-hosts`, and tacctl
0.2.13 ignores the host entries of a newer one.

"Equal to the newest snapshot" compares the files byte for byte, but for the
host records: `host enroll` and `host sync` rewrite `last_sync` and `facts`
in a record on every run, so those two are ignored, and a record counts as
equal when its `provisioner` entry is (a record on one side only counts when
it has none). A sync alone therefore does not make the next command take a
snapshot; a rotation of the provisioner does. A snapshot that is taken holds
the records whole. The snapshot `backup restore` takes first compares
everything, records included, since it is what undoes the restore.

`backup restore <ts>` puts back both files, re-renders every enabled backend's config (a hand-edited file is kept under `backups/legacy/` first), and restarts the backends. It snapshots the current state first, so a restore can be undone with another restore, and it changes nothing if the snapshot is invalid or the render fails. The snapshot's `backends.enabled` comes back with the rest of `tacctl.yaml`: a backend it enables must already be installed (otherwise nothing changes and the message says to run `backend enable`) and is started; one it leaves out is stopped and disabled.

`backup keep <ts> [--note <text>]` copies a snapshot to
`/etc/tacctl/backups-kept/<ts>/` (0700, the files 0600), where no retention
reaches it: this release prunes `backups/` beyond the newest 30, and the older
releases a rollback goes to do the same without knowing any marker. The copy
is a snapshot like any other (the same files, the manifest included) with a
file `kept` that records the note, who last set it (the user and the session
id of the audit lines) and when: the keeper until a new `--note` replaces the
note, and then whoever replaced it. The note is free text of at most 200
printable characters (no control or format character, no line break); it is
stored in the copy and shown by `backup list`, and it is not a place for
secrets. Keeping a snapshot that is kept already says so and changes nothing,
but for `--note`, which replaces the note. `backup list` marks a kept snapshot
`snapshot, kept` and shows its note in a NOTE column, and `kept only` when its
original has been pruned from `backups/`. `backup diff`, `backup restore` and
`backup recover` look an id up in `backups/` first and then among the kept
copies, so they work on a copy whose original is gone; a restore does not
touch `backups-kept/`. `backup unkeep <ts>` removes the kept copy after a
confirmation (`--yes` does not ask), and says first when no snapshot of that
id remains in `backups/` (the kept copy is then the only copy); the snapshot
in `backups/` is not touched. `uninstall` archives `backups-kept/` with
`backups/` when the backups are preserved. The audit lines are `backup keep
id= note=yes|no already=yes|no` and `backup unkeep id= only-copy=yes|no`, and
the note is written as `<redacted>` in the command line they follow.

A snapshot that knows the hosts also puts the host files back: `linux-hosts`
whole, `hosts/` made to match (a record the snapshot lacks is removed),
`staging` back or removed, and `linux-uids` as it was. A snapshot without
`linux-hosts` leaves all four as they are. No host is touched and nothing is
reconciled. Before the question, and again after the restore, a note names the
hosts that come back, those that go and those registered differently. The
restored ledger can forget a number that a host already holds, so the note
also names every user whose UID it drops or changes. The note after the
restore compares the ledger as the snapshot of the current state holds it
with the one that was put back, so it covers a number given out while the
question was open. A number given out in the seconds between that snapshot
and the put is in neither the note nor the undo. If a host file cannot be
read, the note says `could not compare the host files` with the error, and the
restore still puts them back. A host that comes back after `host unenroll` is
still cleaned up: `host sync`, `host show <name> --check`, or
`host unenroll <name>` again. A host that goes stays set up: `host enroll` it
again, or `host unenroll <name> --force` after that. The snapshot of the
current state taken first holds the live host files, so another restore undoes
this one. A break-glass hold on a name that the restore enrolls or forgets is
worded as a host's or a device's in the backend files, so when the enrolled
names change the files are rendered again once the registry is back (no more
than the one restart the restore makes); if that render fails the restore
stands, a warning says so, and `tacctl config render` does it.

The restore holds the host registry's lock from before it changes anything.
When another tacctl command keeps the lock for 30 seconds, the restore stops
with the registry busy and nothing changed. It also tries the lock of each
host (the one `host provisioner rotate`, `host rename` and `host forget` hold
while they run) for every name in the live registry and in the snapshot's,
without waiting. If another command holds one, the restore stops before it
takes the snapshot of the current state, with nothing changed:

    Snapshot <ts> was not restored: 'web1' is locked by another tacctl command
    (a rotation, rename or forget of it is running). Nothing was changed. Run
    this again when it has finished.

The restore also takes the lock of the UID ledger
(`/etc/tacctl/.linux-uids.lock`) for the time it puts the host files back,
waiting up to 30 seconds as for the registry's; with `--keep-uids` it takes
none and a held ledger does not stop it. Every snapshot copies the ledger
under that lock, so a ledger another command keeps for 30 seconds stops the
snapshot of the current state, and the restore with it, before anything
changes:

    [ERROR] the UID ledger (linux-uids) is locked by another tacctl command;
    try again in a moment (waited 30s)

The locks are released when the host files are back. A snapshot that does not
know the hosts takes neither lock. The host files are put back last: if that
step fails, the rest of the restore stands and the backends are restarted, and
two warnings name the error, the snapshot of the state from before the restore
and the commands that undo the restore (`backup restore` of that snapshot) or
try the host files again (`backup restore` of this one).

`backup restore <ts> --keep-uids` leaves the UID ledger (`linux-uids`) as it
is; the registry, the records and `staging` come back as above. Use it when
the snapshot is wanted for its users, groups, scopes or devices and the hosts
have synced since: the live ledger is the one the hosts agree with. In place
of the list of users whose number the restore would drop or change, the note
before the question, and again after the restore, is one line: the ledger is
kept, and the restored users keep the numbers they have now. A user the
snapshot brings back who has no line in the live ledger is numbered afresh at
the next `host sync`, as any new user is; the line of a user the snapshot
lacks stays, as after `user remove`. The snapshot of the current state taken
first is made as always and holds the live ledger. A snapshot that does not
know the hosts never touches the ledger: the flag is accepted and one line
says so. `--keep-uids` with `--legacy`, or without a store, is a usage error:
an old-style restore never touches `linux-uids`.

`backup diff` adds `linux-hosts`, `staging`, `linux-uids` and each host
record, each only where either side has one. A snapshot that does not know the
hosts (taken by 0.2.13 or older) is not compared with them, because a restore
of it leaves the live host files alone: one line,
`host files: not in this snapshot (it predates 0.2.14)`, stands in their
place, and only when the server has host files. `backup list` is unchanged,
and `restore --legacy` leaves the host files alone.

Old-style `tacquito.yaml.<timestamp>` files (made before the store existed, or kept in `backups/legacy/`) are listed after the snapshots. `backup restore <timestamp> --legacy` runs `store import --check` on one, then imports it. Without a store (legacy read-only mode) `list`, `diff` and `restore` work on those files.

`store import` of a rendered `tacquito.yaml` that cut users out of their scopes (a required password change, an emergency lockdown: the users section names them in a `# tacctl-carved reason= protocol= users=` comment) lists each as something the store cannot represent, since the file holds neither the scopes they had nor the requirement, and wants `--force`; `--check` reports them the same way.

The scope `tacctl` of a rendered file is the login of the server the file came from, which every user is in: `store import` does not import it and takes it out of the users' scopes, with one line that says so, so a migrated store enrols its own server cleanly (`host enroll --local`). A server that is registered in its own scope `tacctl` keeps it, with its secret and prefixes. A scope of that name that answers other addresses than a server's own login (one or two single-address prefixes, `127.0.0.1` among them) is yours and is imported as it is.

`backup restore`, `store import`, `store rollback`, `install`, `upgrade`, `uninstall` and `rollback` each write a line of their own beside the `cmd start` and `cmd end` pair, at `auth.notice`: `backup restore id= pre= keep-uids= legacy=`, `upgrade from= to= branch=` and so on, and `store show`, `config dump` and `backup diff` log the secrets they print as `secret-read` for every caller ([Audit log](../security/audit.md#detail-lines)).
