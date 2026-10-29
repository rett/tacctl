# Host Commands — `tacctl host`

[Documentation](../README.md) › [CLI reference](README.md)

```
host list [--name <text>] [--ip <addr|cidr|text>] [--scope <scope>] [--stale] [--json]

    Show enrolled Linux hosts sorted by name, as `device list` shows devices: target, ADDRESS,
    scope, STATE (configured: the host's scope exists; unconfigured; stale; BREAK-GLASS while the
    host is held), LAST SEEN and BY from the seen cache, server, METHOD, users and open notices. A
    last line gives the age of the seen data and, when the hosts have open notices, how many; when
    the registrations have findings (below), another says how many and points to `config validate`

    --name <text>
        Only names containing the text (one value or a comma list: any of them)
    --ip <addr|cidr|text>
        Only an address equal to, inside or containing the text (a comma list)
    --scope <scope>
        Only the hosts that scope answers (a comma list)
    --stale
        Only the hosts not seen for stale-days (`device stale-days`)
    --json
        Print a JSON array (`[]` for no host) and no table: name, local, target, port, scope,
        server, method, identity, address, users, state, seen (while the address was seen),
        notices, drift, breakglass (while held) and findings

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
        The host's scope (default: its registered one, else the scope covering its address; not with
        --local)
    --server <address>
        Address the host uses for this server (default: recorded, else detected)
    --name <name>
        Registry name (default: short hostname, lowercased; lower case, not a tacctl word)
    --port <n>, --identity <file>
        SSH port and key
    --build-on-host
        (tacplus) compile pam_tacplus on the host instead of in a container here
    -y, --yes
        (enroll and move) Move a registered host to another scope even when that deletes accounts
    --staging
        (with --scope) Provisioned off-site: the bench address joins the scope as a /32 until the
        host is seen in place

host sync <name>... | --all

    Push account adds, renames, deletions, expiries and tier changes (a renamed user's account is
    renamed, keeping its UID and home); pins the host's ssh keys if none are (enroll pins them too).
    Several names run in the order typed, each as --all would run it. Every name is checked first
    (an unknown one refuses the run, one given twice counts once); a host that fails does not stop
    the rest, and the exit status is 1. Names and --all are not given together. The numbers of
    new users are given out under the UID ledger's lock, held while the script is built and never
    while it runs on the host, so two syncs at once give a user one number; a ledger another
    command keeps for 30 seconds stops the sync (see Consistent UIDs and GIDs)

    --all
        Every enrolled host
    --allow-uid-mismatch
        (enroll, sync and move) accept a UID conflict on the host instead of stopping
    --remove-home
        (enroll, sync and move) delete removed users' home directories without asking
        (on a terminal each is asked; without one they are kept)

host check <name>... | --all [--json]

    Compare each host with what tacctl would make it, read-only, as `host show <name> --check`
    does (superuser only: it logs in); nothing is changed on a host or here. Every name is checked
    first (an unknown one refuses the run, one given twice counts once); names and --all are not
    given together. One result per host on standard output: as tacctl would make it, the
    differences with the command that fixes each, skipped (a held host), or could not be checked.
    More than one host ends with a count of each. Exit 1 when a host differs or could not be
    checked

    --all
        Every enrolled host
    --json
        Print a JSON array (`[]` for no host) and nothing else on standard output: name, target,
        state (ok, differences, failed or held), differences (text and fix), notes, error and
        breakglass (while held)

host move <name> [<scope>]|--all

    Move an enrolled host to another scope (default: the one answering its address; --all: every
    host another scope answers); asks before deleting accounts

host provisioner <name> rotate <user> (--key <file>|--password) [--remove-old [--remove-home]]
                 [--dry-run] [--yes]

    Switch the account tacctl logs in to the host with: create it over the login in use, prove it in
    a new connection (sudo id -u gives 0), then change the registry; --remove-old removes the old
    account last, over the new one

host rename <old> <new> [-y]

    Give an enrolled host another name (lower case; `host rename Web1 web1` fixes a name from
    before); nothing is sent to the host. Its pinned host keys, record, staging addresses and
    break-glass hold follow; asks about its own linux-<name> scope

host forget <name> [-y]

    Drop a host's registration from this server (registry line, pinned keys, record, staging
    addresses, host-key scan result) and send nothing to the host; also what a registry line no
    longer has. Refused for a held host

host unenroll <name> [--force]

    Remove the login method from the host (accounts are kept), then its pinned host keys, record
    and staging addresses; --force drops it from the registry even if the removal fails

host default-method [tacplus|radius]

    Show or set the method for hosts enrolled without --method (host.default_method)
```

**Enrolling a host and the device registry.** A new host name is checked
against the device registry before the client script runs and again when the
registry line is written, after it. A device registered meanwhile puts the
line back, writes no record, pin or audit line and exits 1 with `A device
named 'web1' (192.0.2.60) was registered while the client script ran; a host
and a device cannot share a name.` and the `host enroll` command to run again
with another `--name`. The script has already run on the host, which
authenticates through this server while the scope covers its address. What
the command did before the script stays, and is warned of: a scope opened to
both protocols for the host (`Scope 'linux-web1' is still open to tacacs,
radius; see 'tacctl scope protocols linux-web1'.`) and a `--staging` bench
address (`tacctl scope staging remove <address>/32` removes it). The same
holds when another enrolment of the name finishes first. A host that is
enrolled already keeps its own name and is not checked again. A break-glass
hold recorded under a new name is refused before anything is done, as for
`host rename`: only `breakglass release` removes a hold.

**Renaming a host.** `tacctl host rename <old> <new>` is the superuser's. It
runs nothing on the host (the machine records no registry name), so a host
with a break-glass hold may be renamed. The new name follows the rules of a
new host name (see [Enrolling hosts](../hosts/enrolling.md)) with no way
round them: lower-case letters, digits, `.`, `_` or `-`, starting with a
letter (253 at most, each dotted part 63 at most); no tacctl word; no generic
name; and not equal, in any case, to another host or a registered device. A
name with upper case is refused (`Names are lower case: use 'web1'.`). The
target, port, scope, server and the address pinned for the host stay as they
are; a host's own `linux-<name>` scope keeps its name when the new one has a
dot (a scope name has none), and one line says so. Changing only the spelling to lower
case (`Web1` to `web1`) is allowed and is how a name from before is fixed;
the same name is refused (`'web1' already has that name.`). A
running rotation, rename, forget or restore of the host refuses the rename
(`'web1' is locked by another tacctl command`). Everything is checked before
anything is written, and a refusal changes nothing. The
device registry is checked once more under its lock when it is written: a
device registered under the new name since the checks (another command, at
the same moment) puts the registry line back and changes nothing, and
`device add|rename` likewise refuse a name that an enrolled host has taken
meanwhile. A `host sync` running on the host at the moment of the rename can
write its record and its pin under the old name; `host list` and
`config validate` then report them as leftovers of a host that is not
enrolled, and `host forget <old>` removes them.

What an earlier host of the new name left (a pinned key and address in the
device registry, a record, staging addresses) is listed and replaced after a
confirmation; `-y` skips it and declining changes nothing. A break-glass
hold recorded under the new name is refused whatever `-y` says: only
`breakglass release` removes a hold.

A snapshot is taken, then the registry line is renamed where it is and one
write of the device registry renames the host's pinned keys, recorded
address, address history and acknowledged notices (the generated
`known_hosts` follows). If that write fails the registry line is renamed
back and the command says that nothing was changed. After that the record
(`/etc/tacctl/hosts/<name>.json`), the staging addresses, the break-glass
hold (same address, new name) and the host-key scan result of the seen cache
follow; a step that fails is a warning that names what stayed and the command
that puts it right. The log line is `host rename old= new= by=`.

When the host's scope is `linux-<old>` (the scope earlier releases made for
it), no other host uses it, the store has it, `linux-<new>` does not exist and
`scope rename` would accept the name, both questions come before the first
write (the prompt is one line, shown wrapped):
```
  Scope 'linux-web1' is this host's own (no other host uses it).
  Rename it to 'linux-web9' too? [y/N]:
```
`-y` answers both yes. The host is renamed whole first; then the scope is
renamed as `scope rename` does it, with a snapshot of its own (two points to
undo to), and the host's registry line and its staging addresses follow the
scope. Answering no keeps the scope and ends with
`tacctl scope rename linux-web1 linux-web9`; a scope that cannot be offered
(shared, missing, `linux-<new>` taken, or refused by `scope rename`) stays,
and one line says why. If the scope step fails the host stays renamed in
`linux-<old>`, which is a valid state: `Host renamed. Scope 'linux-web1' was
NOT renamed: <reason>; the host keeps it. Retry: tacctl scope rename
linux-web1 linux-web9.` and exit status 1. Without the question, enrolling
the renamed host again without `--scope` would default to `linux-<new>` and
move it.

**Unenroll or forget.** `host unenroll` cleans the host (its tacctl login
method: the PAM setup and the secret; local accounts and homes stay) and then
removes the registration. `host unenroll --force` removes the registration
even when the host cannot be cleaned. `host forget` only drops this server's
record of a host (registry line, pinned keys, record, staging addresses) and
touches nothing on the host.

**Forgetting a host.** `tacctl host forget <name>` is the superuser's and
local: it sends nothing to the host and runs no ssh. After a snapshot it
drops, for the name, the registry line, the pinned keys, recorded address and
history in the device registry (the generated `known_hosts` follows), the
record (`/etc/tacctl/hosts/<name>.json`), the host's staging addresses from
the `staging` file and the host-key scan result of the seen cache. It lists
what it would drop and asks (`-y` skips the question). The host itself is
not touched: its accounts, secrets and PAM setup stay, so the command is for a
registration that is wrong, not for taking a host out of service (`host
unenroll` does that on a host that can be reached, and drops the host's
staging addresses and record the same way). A scope's staging /32 stays a
prefix of the scope; both commands print the `scope prefixes <scope> remove`
line for it, and the scope of a host that was the last one using it is named
with `scope remove`. The log line is `host forget name= by=`.

This server's own host (`host enroll --local`) is the exception. Forgetting it
runs nothing here, so this server's PAM setup and console accounts keep using
its scope: the command says so before it asks, and does not suggest removing
the scope. `host unenroll <name>` is what takes this server's own host out of
service; `host forget` of it is for a stray duplicate line only.

The name is the registered spelling. A leftover that no registry line has (an
orphan: a pin, a record or a staging entry) is named by exactly its spelling
and forgotten the same way. A name that matches neither exactly but one
enrolled host ignoring case is that host (this is how a stray `Web1` is
forgotten by typing `web1`); several such hosts are refused, naming them. The
pins and the scan result are shared by names equal ignoring case, so they stay
while another enrolled host has such a name (a device of that name keeps the
scan result). A host with a [break-glass hold](breakglass.md) is refused:
`tacctl breakglass release <name>` first, and so is the leftover of a name
that a hold is recorded under. A running rotation, rename, forget or restore
of the host refuses it. `host unenroll --force` is not the repair for a
duplicate: it runs the removal script on the machine that the surviving
registration shares.

**Listing.** ADDRESS is the address recorded at the host's last `host enroll`
or `host sync` (the one a break-glass hold carves out), else the single
address of its scope, `-` when neither is known; LAST SEEN and BY are what the
seen cache holds for that address (`tacctl device scan` refreshes it), and the
summary under the table says how old the data is. The options narrow the list
as those of `device list` do (the options must all match; a host of another
scope, for an engineer, is not counted). This server's own login has no scope
column (`-`) and `--scope` never selects it. In
`host list --json` each host has `name`, `local`, `target`, `port` (22 unless
the registry gives one; 0 for this server's own host), `scope`, `server`,
`method`, `identity` (the path only), `address` (empty when unknown), `users`,
`state`, `seen` (first, last, count, last user, outcome, via, NAS identifier
and stale, as in `device list --json`; absent when the address was never
seen), `notices` (kind, text and acknowledged; `device notice list` and
`host show --all` list them), `drift` (the warning the table prints when the scope no longer answers the
host, empty when none), `breakglass` (the hold, as in `host show --json`,
only while the host is held) and `findings` (those of the next paragraph that
name the host, with the `Names:` findings of `config validate` about the host,
each `text` and `fix`; always empty for an engineer, who is told no findings). An engineer lists the hosts of their own scopes. The
table's footer and warnings are not printed with `--json`.

**Findings.** `config validate` (under `Linux hosts:`, warnings that change no
exit status) and `host list` (one last line, `N finding(s): see tacctl config
validate`) report, for the superuser, registrations that cannot all be right
(`config validate` prints the last row under `Names:`; the `host list` count
includes it). Nothing is repaired where they are reported; each names the
verb that does.

| Finding | Fix |
|---|---|
| two enrolled names equal ignoring case (they share one record of pinned keys) | `host forget <name>`, or `host rename <name> <new>` |
| a host named like a registered device | `host rename <name> <new>` |
| two hosts with the same recorded address and ssh port (the address `enroll` or `sync` recorded; nothing is resolved; one address on another port is another machine) | `host forget <name>` for a registration made twice |
| a pin, a record or a staging entry with no registry line | `host forget <name>` |
| a name with upper case (a `Names:` finding in `config validate`) | `host rename <name> <lower-case name>` |

A break-glass hold with no host is the hold's own orphan line in
`config validate` and `breakglass list`: `tacctl breakglass release <name>`.

`host enroll` (so `host move`), `host unenroll`, `host rename` and `host
forget` take a snapshot just before the registry changes (for `host enroll`
once the script on the host has succeeded); `host sync` takes none. It holds
the registry, the host records, `staging` and the UID ledger, so `backup
restore` can put them back (see [Backup
commands](maintenance.md#backup-commands--tacctl-backup)).

A host with a [break-glass hold](breakglass.md)
(`tacctl breakglass hold <host>`) is one the server does not answer, so that
its local administrator and console work. The `host` verbs that log in over
ssh refuse it: `host sync`, `host show --check`, `host enroll` of the
registered host (and so `host move`), `host target <name> <target>`,
`host provisioner <name> rotate` and `host unenroll` (also with `--force`);
`host forget` is refused too, though it logs in nowhere. They name the hold
(since, by whom, why) and
`tacctl breakglass release <name>`; nothing is attempted over ssh and nothing
is changed. The same refusal stands when the device registry, which records
the host's address, cannot be read. `host sync --all` skips a held host and
says so; a held host among the names typed to `host sync` refuses the whole
run before any host is reached. `host check` skips a held host, typed or not
(it only reads, so there is nothing to refuse), and the skip is not a failure.
`host target <name>` without a change, `host list` and `host show` only read,
and `tacctl ssh` warns and connects.

Each `host sync` writes a line of its own for every host (`host sync name= target= created= updated= renamed= removed= remove-home= result=`, with `reason=` when it failed), a batch `host move` one summary (`host move scope= moved= failed=`), and the lines of `host enroll`, `host unenroll`, `host rename`, `host forget` and `host target` end in `result=ok`, or are written with `result=failed reason=` when the change failed ([Audit log](../security/audit.md#detail-lines)).
