# tacquito source patches

`tacctl` builds the tacquito server from an upstream checkout of
[`facebookincubator/tacquito`](https://github.com/facebookincubator/tacquito)
at `/opt/tacquito-src`. A few behaviors we depend on are not upstream, so we
carry them here as a **patch overlay** rather than forking.

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

### `0003-authen-log-conn-remote-addr.patch`
Names the device on the bcrypt authenticator's log lines
(`cmds/server/config/authenticators/bcrypt/bcrypt.go`): `accepting user [u]
using a bcrypt password` becomes `accepting user [u] from [addr] using a bcrypt
password`, and `failed to validate the user [u] using a bcrypt password`
becomes `failed to validate the user [u] from [addr] using a bcrypt password`.

`addr` is the address of the TACACS+ client (the network device) as the server
saw the connection: the value tacquito's server stores in the request context
under `tq.ContextConnRemoteAddr` for every packet of a connection. It reads
`unknown` when the context carries none. Nothing else in the behavior changes.

Why: the accounting log's `RemAddr` is the user's address, not the device's,
and the journal names the device only at debug level or on errors. With the
address on the authentication lines, `tacctl log search` shows which device a
login came from, and `tacctl device scan` reads these lines to learn which
devices use the server.
