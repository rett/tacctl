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
                                             password change, email addresses, the users' own
                                             limits of the stored reports)
store rollback                               Restore the pre-store tacquito.yaml, remove the store,
                                             restart (legacy read-only mode)
```

## Log Commands — `tacctl log`

```
log tail [-f|--follow] [<n>] [--backend <id>] [<filters>]

    Last <n> entries (default 20): TACACS+ journal; RADIUS auth log and daemon log; -f/--follow
    follows new ones until Ctrl-C

log search <term> [--backend <id>] [<filters>]

    Search the logs for a username or keyword (TACACS+: last 7 days)

log failures [--backend <id>] [<filters>]

    Auth failures from the last 24 hours

log accounting [<n>] [--backend <id>] [<filters>]

    Last <n> accounting records

<filters> (tail, search, failures and accounting):
    [--since <time>] [--until <time>] [--user <name>] [--device <name|address>]
    [--type login|change|command] [--json]

log clear [--force|--yes] [--backend <id>]

    Purge the TACACS+ journal and truncate the accounting logs; truncate the RADIUS auth, accounting
    and daemon logs (prompts)
```

With more than one backend enabled each subcommand shows every backend's log in a section headed by its name; `--backend <id>` (anywhere on the line) shows one.

`log accounting` shows each TACACS+ record as tacquito wrote it (a line of JSON after the date, time and source of the logger) with the values decoded, and names the device that sent it: tacquito built with `patches/0006` adds `"Device"`, the address the device connected from, to every record, and `log accounting` shows the name of the registered device or enrolled host at that address (`"Device":"sw1"`), the address when none is registered (a device covered by a scope's prefix only, or one outside the scopes of an operator, engineer or read-only caller, who is told the names of their own scopes' devices only), and no `Device` for a record written before the patch. `"RemAddr"` stays what it was: where the person connected from, as the device reports it. Records written before the patch keep `\u003c`, `\u003e` and `\u0026` for `<`, `>` and `&` in the log file; they are shown as the characters. The `<cr>` Junos appends to a `cmd=` value is left out of the display; the file keeps it. `log tail` and `log search` read the journal: their display is not affected (their filters are below).

### Log filters

The filters of `log tail`, `log search`, `log failures` and `log accounting` combine (an entry must pass all of them), are written `--name value` or `--name=value` anywhere on the line, and apply before a count: `log accounting 5 --user alice` is alice's last five records. `log tail -f` applies them to the new entries too. `--type` is the accounting log's only. Without a filter and without `--json` the commands print what they always did. An operator may pass the filters, and `--backend`, to all four commands through sudo: the per-tier sudoers drop-in allows `log failures` with arguments from this release on (`tacctl upgrade` rewrites an installed one).

| Filter | Shows |
| --- | --- |
| `--since <time>`, `--until <time>` | Entries from, and up to, that time (both inclusive). |
| `--user <name>` | Entries of that user, exactly as the log writes the name. |
| `--device <name\|address>` | Entries of that device or host. |
| `--type login\|change\|command` | One kind of accounting record. |
| `--json` | One JSON object per entry, no headings, for `jq`. |

`<time>` is one of `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` and `YYYY-MM-DD HH:MM:SS` (local time; a date alone is that day's midnight; a `T` may stand for the space), `now`, `today` and `yesterday` (midnight), or an offset from now: `-1h`, `-30m`, `2 days ago`, with the units `s`, `m`, `h`, `d` and `w` (or `seconds`, `minutes`, `hours`, `days`, `weeks`). Any other form is a usage error, as is a `--since` later than the `--until`. On TACACS+ `tail`, `search` and `failures` hand the window to `journalctl` (without one, `search` reads the last 7 days and `failures` the last 24 hours). The RADIUS logs and the accounting logs are compared line by line with the time of the line or record (the date and time of the logger's prefix of a TACACS+ record, the date at the start of a RADIUS auth or daemon log line, the first line of a RADIUS accounting record); one whose time cannot be read is left out. With `tail -f` a new entry has the time it arrives.

`--device` takes the name of a registered device or enrolled host that the caller may see (an operator, an engineer or a read-only user sees the devices and hosts of their own scopes), which stands for its recorded address, or an address, which is compared in canonical form (`2001:DB8:0:0::1` is `2001:db8::1`, and `::ffff:192.0.2.10` is `192.0.2.10`). A name that is neither is refused, and so is a device that has no address recorded. What each log can match:

| Log | `--user` | `--device` |
| --- | --- | --- |
| TACACS+ accounting | the record's `User` | the record's `Device` (a record written before `patches/0006` has none and never matches) |
| TACACS+ journal | a line that names the user in brackets (`accepting user [alice] ...`) | the address a tacquito line names for the device that asked: `from [A]`, `bad secret detected for ip [A:port]`, `remote [A:port] has no secret providers`, and the debug line `matches remote [A]`; the person's address in `client [A]` is not the device. A line that names no device never matches. |
| RADIUS auth log | the last `user=` of the line | `client=` |
| RADIUS daemon log | a line that names the user in brackets (`[alice]`, `[alice/<via Auth-Type = PAP>]`) | cannot be matched (it names clients and not addresses): with `--device` its section says so and shows no line |
| RADIUS accounting | `User-Name` | `NAS-IP-Address`, `NAS-IPv6-Address`, `Packet-Src-IP-Address` or `Packet-Src-IPv6-Address` |

`--type` classifies a TACACS+ accounting record by its fields. A record with a `cmd=` argument that is not empty is a `change` when the command has the shape of a Junos change-log entry (a verb, a colon and the configuration path in brackets: `cmd=set: [interfaces ge-0/0/1 description] ...`), and a `command` otherwise. A record without one is a `login` when its flags start or stop a session (the TACACS+ START and STOP flags). A watchdog update is none of the three. RADIUS accounting has `login` records only (`Acct-Status-Type` Start or Stop): `--type change` and `--type command` say so and show nothing.

A filter that leaves nothing says so (`No matching entries.`). With `--json` the headings and such lines are left out and a note goes to standard error, so that standard output is one object per line:

```
{"time":"2026-11-04T12:00:00Z","backend":"tacacs","unit":"tacquito.service","message":"...",
 "user":"alice","address":"192.0.2.10","device":"sw1","outcome":"accept"}
```

The time is UTC; `user`, `address`, `device` (the registered name) and `outcome` are there when the line has them. `unit` is the journal's (TACACS+), `log` the log a RADIUS line comes from (`auth` or `daemon`). A TACACS+ accounting record is the record with its fields decoded as the display has them (`Device` the address as it was logged), then `DeviceName` (when the address is a device or host the caller sees) and `Time` (the logger's, UTC). A RADIUS accounting record is `time`, `backend`, `log`, `user`, `address`, `device` and `attributes`, the record's attributes.

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
backup recover <snapshot> [--only <kind>[,<kind>...]] [--dry-run] [--yes]
                               Put back one kind of data from a snapshot (kinds: email,
                               snmp-users); nothing else changes
```

A backup is a snapshot of the canonical files, `/etc/tacctl/backups/<timestamp>/{store.yaml,tacctl.yaml,manifest}`, taken automatically before every change that would alter them (nothing is added when they already equal the newest snapshot). The manifest records `rendered.json`, the tacctl version and who took the snapshot: `sid` (the session id of the audit lines), `user` and `command` (the command's words, without arguments). The newest 30 snapshots are kept. Snapshots hold shared secrets and password hashes: the directory is `0700`, the files `0600`, and `backup diff`, `backup restore`, `backup keep`, `backup unkeep` and `backup recover` are superuser-only.

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

A snapshot taken by 0.2.25 or earlier (or by `tacctl upgrade` just before it renames the users) can hold a user whose name has a period, which 0.2.20 and 0.2.21 allowed. The restore reads such a snapshot: only the user-name rule is relaxed, for the snapshot's store, and every other problem still refuses it. It says before the question and after the restore which users have a period, and it **renders nothing and changes no backend's file**, because no renderer writes such a name (tacquito's parser refuses a period in an anchor); the services keep the configuration they have, and a snapshot of that kind that enables a backend the machine does not run now is refused with nothing changed. The store then reads, and every write to it is refused until `tacctl upgrade` renames the users (each period becomes `_`) and renders. This is also the way back when the upgrade's rename stops half way: `tacctl backup restore <id>` of the snapshot it named, then fix the file and run the upgrade again. The snapshot's `console.yaml` is installed without the settings of such a user (the system shell, the password cache and the ignored `users` override): the console cannot read a name with a period, and a file that kept one would hold every user below the superuser at the password change. Each dropped setting is named before the question and after the restore (`dropped console setting of user alice.smith: system shell enable:operator`), every other setting is kept, and the setting is set again once the upgrade has renamed the user.

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

`backup recover <snapshot>` puts back from a snapshot one kind of data and
leaves everything else as it is, where `backup restore` puts back the whole
state. It is the way back for what `tacctl rollback` removed: the rollback
keeps the snapshot it took (`backup keep`) and names it (see [Rolling
back](../install/upgrading.md#rolling-back)). The kinds are `email` (the email
addresses of users, `user email`) and `snmp-users` (the SNMPv3 users a
rollback dropped). Without `--only` it recovers every kind. For `snmp-users`
it reads the credential files of the snapshot (`snmp.yaml`, `snmp/<scope>.yaml`,
`snmp/devices/<device>.yaml`) and adds each user to the pool of the same level
now, and a default where the level has none and the user it chose is there; it
never overwrites a default. A scope or a device that no longer exists is
skipped and named, a user the level has already is nothing to do, and a name
that another pool a device can see holds now is skipped (the current user is
kept), saying which pool; the lists name levels and count users, never a user
or a passphrase, and the audit line holds counts and snapshot ids. For `email` it reads
the snapshot's `store.yaml` and sets the address of each user who has one
there and exists now with none, in one store write that goes through the same
validation as `user email`. A user who no longer exists, a user who has
another address now (the current one is kept) and an address another user
holds now are skipped and named; a user who has the address already is nothing
to do. The lists name users, never an address. The snapshot is looked up in
`backups/` and then among the copies `backup keep` made in `backups-kept/`,
which no retention reaches (a rollback keeps the snapshot it names there, so
the data it dropped can be recovered after an older release pruned
`backups/`); a kept copy that was read is named, with `backup unkeep`, which
removes it once the data is recovered. `--dry-run` lists what would be
recovered and changes nothing; otherwise the command asks for confirmation
(`--yes` does not), snapshots the current state first (the snapshot being read
is not taken by the retention), and ends with the number recovered and
skipped. Nothing is rendered or restarted. A user of the snapshot whose name has a period (a snapshot of 0.2.25 or earlier) is skipped and named, with a note that `tacctl upgrade` renames such users: a recovery sets data on users that exist and adds none, so no such name reaches the live store. A snapshot from before the data
existed, or an old-style backup, recovers nothing. The audit line is `backup
recover id= pre= kinds= restored= skipped=`, with no address.

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

`store import`, `backup restore` (a snapshot or an old-style backup) and `store rollback` rewrite the list of users held to a password change in the console's sshd drop-in once they have changed the store (the rollback writes it empty: legacy mode holds nobody), when the drop-in is installed; the list is read under the apply lock and a failure is one warning that names `tacctl console install` ([Login console](../security/login-console.md)). Nothing else that writes the store does this, apart from the verbs that sync this server and the ones that change who is held (`user require-password-change`, `user add`, `remove`, `rename`, `move` and `passwd`, `passwd`, the group commands that lower a tier), which rewrite it themselves.

`backup restore`, `store import`, `store rollback`, `install`, `upgrade`, `uninstall` and `rollback` each write a line of their own beside the `cmd start` and `cmd end` pair, at `auth.notice`: `backup restore id= pre= keep-uids= legacy=`, `upgrade from= to= branch=` and so on, and `store show`, `config dump` and `backup diff` log the secrets they print as `secret-read` for every caller ([Audit log](../security/audit.md#detail-lines)).
