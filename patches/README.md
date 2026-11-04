# tacquito source patches

`tacctl` builds the tacquito server from a checkout of the project's fork,
[`rett/tacquito`](https://github.com/rett/tacquito), at `/opt/tacquito-src`.
The fork's `main` is upstream
[`facebookincubator/tacquito`](https://github.com/facebookincubator/tacquito)
and nothing else: it moves only when upstream changes are merged into it
(below), so a host builds only the upstream changes that were reviewed. A few
behaviors we depend on are not upstream; we carry them here as a **patch
overlay**, not as commits on the fork, so merging upstream stays
conflict-free.

Every `*.patch` in this directory is a `git apply`-able unified diff rooted at
the tacquito source tree. On `tacctl install` and `tacctl upgrade`, after the
upstream `git pull`, tacctl:

1. reverts any previously-applied patch hunks (`git checkout -- .`) so the pull
   is clean and the apply is deterministic,
2. re-applies every patch here (in filename order) on top of pristine upstream,
3. rebuilds the binary.

This means patches **survive upstream updates** automatically. If upstream
later changes a file a patch touches, the apply will fail loudly during
upgrade and the patch needs refreshing (regenerate it against the new
upstream and replace the file here). Patches are idempotent: an
already-applied patch is detected (reverse-check) and skipped.

Keep patches to **modifications of existing files only** (no new files), so the
revert-before-pull step (`git checkout -- .`) fully cleans the tree.

## Following upstream

The fork is updated by hand, periodically and whenever upstream moves; it is
never synced automatically. From a clone of the fork:

```
git remote add upstream https://github.com/facebookincubator/tacquito.git  # once
git fetch upstream
git log --oneline main..upstream/main      # what upstream changed
git diff main...upstream/main              # review it
git checkout main
git merge --ff-only upstream/main          # main carries no commits of its own
git push origin main
```

Before the push, check that every patch here still applies and the server
builds (`git apply --check patches/*.patch` in a scratch copy of the merged
tree, then `go build ./cmds/server`); refresh a patch that no longer applies
in the same tacctl change that documents it. The next `tacctl upgrade` on a
host pulls the merged commit and rebuilds.

A checkout cloned from upstream by a release before 0.2.24 is pointed at the
fork the next time `tacctl install` or `tacctl upgrade` pulls it (`git remote
set-url origin`: both have the same history). An origin set to any other URL
is left alone.

## Current patches

### `0001-stringy-default-service-permit.patch`
Adds `default service = permit` semantics to the session (exec) authorizer
(`cmds/server/config/authorizers/stringy/session.go`).

Some third-party TACACS+ clients — notably **Peplink Balance** — send a *bare*
exec authorization request with no `service=` argument after a successful
authentication. tacquito's session authorizer is fail-closed: it only returns
AVPs when an inbound arg matches a configured service name, so a serviceless
request matches nothing and is denied (`not authorized`), which the device
surfaces to the operator as "invalid password". shrubbery `tac_plus` handles
these via `default service = permit`.

The patch mirrors that: for any session (exec) authorization that is **not** a
command authorization and matched **no** configured service, it authorizes the
session using the user's `shell` service values (e.g. `priv-lvl`). This covers
both a bare request (no `service=`) and a request naming a service we don't
explicitly configure (Peplink sends a non-`shell` service). The fallback is
**bounded by the user's own group** — it can never grant more than the user's
configured `shell` priv-lvl — so it is safe. Requests that match a configured
service (normal Cisco `service=shell`, Juniper `service=junos-exec`) take the
existing path unchanged, and command authorizations are handled by the command
authorizer, never silently permitted here. The patch also logs the raw client
args at debug level, which helps when onboarding a new third-party device.

### `0002-acct-success-empty-server-msg.patch`
Drops the `server_msg` from successful accounting replies in both accounters
(`cmds/server/config/accounters/local/local.go` and `syslog/syslog.go`), and
updates the matching upstream tests in `cmds/server/test/`.

Upstream answers every successful accounting request with a human-readable
message (`success, logging started`, `success, logging stopped`,
`success, watchdog`, `success, watchdog update`). Most TACACS+ servers
(shrubbery `tac_plus`, Cisco ISE) send these replies with an empty message, and
some clients do not tolerate one: **WTI console servers** (v8.x, whose TACACS+
client is pam_tacplus-style) authenticate and authorize an SSH login, send the
accounting START, and then drop the session as soon as the reply arrives
(`client_loop: send disconnect: Broken pipe`, no accounting STOP). Disabling
the WTI's Session Management Module (accounting) makes the login work, which
isolates the accounting reply.

The patch only removes the message; the reply status is still
`AcctReplyStatusSuccess`, and error replies (`accounting failure`,
`unexpected accounting flag`, ...) keep their messages. Clients that ignore the
message (Cisco, Juniper, ...) see no difference.

### `0003-authen-log-addresses.patch`
Names the device and the client on the bcrypt authenticator's log lines
(`cmds/server/config/authenticators/bcrypt/bcrypt.go`): `accepting user [u]
using a bcrypt password` becomes `accepting user [u] from [addr] using a bcrypt
password`, and `failed to validate the user [u] using a bcrypt password`
becomes `failed to validate the user [u] from [addr] using a bcrypt password`.
When the client sent an address or a port, they follow the message:
`...using a bcrypt password; client [10.0.0.5] port [pts/0]`.

`addr` is the address of the TACACS+ client (the network device) as the server
saw the connection: the value tacquito's server stores in the request context
under `tq.ContextConnRemoteAddr` for every packet of a connection. It reads
`unknown` when the context carries none. `client` and `port` are the
`rem_addr` and `port` fields of the authentication start packet (the end
user's address and the terminal or line name, as the client fills them in),
which the patch stores in the request context under `tq.ContextClientAddr` and
`tq.ContextClientPort` (`ctx_keys.go`, `cmds/server/handlers/authen.go`). They
are left out when the client sent none, and the log keeps only printable
ASCII without brackets in them, at most 64 characters (the client chooses the
bytes); the common case is a device, which
fills in the address of the person logging in, and `sshd` on a Linux host
(through `PAM_RHOST`); `sudo` gives none. Nothing else in the behavior changes.

Why: the accounting log's `RemAddr` is the user's address, not the device's,
and the journal names the device only at debug level or on errors. With the
addresses on the authentication lines, `tacctl log search` shows which device a
login came from and from where the person logged in, and `tacctl device scan`
reads these lines to learn which devices use the server.

### `0004-authen-fail-no-server-msg.patch`
Drops the server message from the bcrypt authenticator's failure replies
(`cmds/server/config/authenticators/bcrypt/bcrypt.go`): a wrong password, an
undecodable stored hash or a failed keychain lookup still answers `FAIL`, but
without the text `login failure`. Nothing else in the behavior changes.

Why: pam_tacplus hands a reply's server message to sshd as a PAM message. With
password authentication (`KbdInteractiveAuthentication no`, the default on
Ubuntu and Debian) sshd cannot show a PAM message during the login, so it keeps
every one and prints them all after the next successful login: two wrong
passwords, then the right one, greet the user with `login failure` twice. The
message carries nothing that `Permission denied` has not already said, and
network devices print their own failure text without it.

### `0005-acct-unknown-user-sink.patch`
Records accounting for users a scope does not know instead of refusing it
(`cmds/server/handlers/acct.go`).

tacquito looks up the user of every accounting request among the users of
the device's scope and answers an unknown one with an error (`failed to
lookup user [x] for accounting login`; upstream marks the spot `TODO
implement a fallback for cases where a username may not be present`).
Devices send accounting for every login and commit, local accounts and
daemons included: Junos discards each refused record and logs
`AUDITD_TACPLUS_START_NO_RESPONSE: Discarded Accounting-Request message; no
positive response from TACACS+ servers`, so a local `admin` login or a
commit by it is lost from the audit trail.

The patch records such a request through the scope's accounter: `root` (the
accounting-only user tacctl keeps for Junos daemons) when the scope has it,
else the first of the scope's users by name. tacctl gives every user the
same file accounter, so the record lands in the accounting log with the
user the device sent, and the device gets a success reply. Only accounting
changes: an unknown user still fails authentication and authorization, and
a scope with no users at all still refuses the record.

Records of `root` with no terminal (port `non-tty`, which Junos sends for
them, `unknown`, or empty) are answered with success and not recorded, with
a debug line. Junos opens
short `root` CLI and junoscript sessions with no terminal for its own
process and health checks (`show system processes extensive`, several a
minute), and every login and logout of them is an accounting record. A
`root` login on the console or over ssh has a port (Junos: a tty name, or
`0` over ssh) and is recorded, its commands included.
The device still logs `AUDITD_TACPLUS_MSG_SENT` for each one it sends:
that line is the device's, and only its syslog configuration can drop it.

### `0006-acct-device-address.patch`
Names the device in every accounting record, and writes the record readably
(`cmds/server/config/accounters/local/local.go` and `syslog/syslog.go`, with a
test in `cmds/server/test/local_acct_test.go`).

Both accounters write one JSON line per request, e.g. a Junos `change-log`
record:

```
{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"alice","Port":"ttyp0","RemAddr":"192.0.2.50","Args":["task_id=3","service=shell","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"test\"<cr>"]}
```

`RemAddr` is where the *user* connected from, as the device reports it; nothing
in the line says which *device* sent the record, so with several devices the
log cannot answer "which device was changed". The patch appends one field,
`"Device"`, with the address of the TACACS+ client as the server saw the
connection: the value tacquito's server stores in the request context under
`tq.ContextConnRemoteAddr` for every packet (the one patch `0003` puts in the
authentication log lines), `unknown` when the context carries none.

The record is the request's struct followed by the new field, so the existing
fields keep their names, their order and their values, and a reader that does
not know `Device` ignores it (the line stays one line of valid JSON).
`tacctl log accounting` shows the device's registered name for it
(`docs/cli/maintenance.md`); a record written before the patch has no
`Device` and is shown without one.

The patch also writes `<`, `>` and `&` as they are. Go's `json.Marshal`
escapes them for HTML (`<`, `>`, `&`), so the log read
`<unconfigured> -> "test"<cr>` for the command
above. The record is now written with a `json.Encoder` that has
`SetEscapeHTML(false)`, and the newline `Encode` adds is cut off, so the
accounter logs one line per record as before. Both forms are valid JSON and
decode to the same strings; records already in the log keep their escapes, and
`tacctl log accounting` shows them decoded (and leaves out the `<cr>` Junos
appends to a command, in the display only).

Why it is safe: the field comes after the request's own, nothing is read from
the client for it, and the replies are unchanged. `Device` is one more key in
an object that JSON readers already take unknown keys of.

