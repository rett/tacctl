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

The patch mirrors that: when the client named **no** `service`/`cmd` and nothing
matched, it authorizes the exec session using the user's `shell` service values
(e.g. `priv-lvl`). Requests that *do* name a service we don't authorize remain
strictly denied, and normal Cisco/Juniper requests (which always name a service)
are unaffected.
