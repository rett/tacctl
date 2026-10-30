# Troubleshooting

[Documentation](../README.md) › [Installation and upgrades](README.md)

## Common Issues

**`bad secret detected for ip [x.x.x.x]`**
- Shared secret mismatch between server and device
- Identify which scope the client falls into: `tacctl scope lookup <ip>` / `tacctl scope show <name>`
- Regenerate that scope's key: `tacctl scope secret <name> generate`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `tacctl user verify <username>`
- Reset: `tacctl user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `tacctl config juniper`

**A command is refused with exit 3 / `DRIFT` in `tacctl status`**
- A generated file was edited by hand; tacctl will not overwrite it. `tacctl config validate` names the file and both ways out: keep the edit (`tacctl store import --replace`, then `tacctl config render --force`; TACACS+ only) or discard it (`tacctl config render --force`, the edited copy is kept under `/etc/tacctl/backups/legacy/`)

**`store not initialised`**
- The install is in legacy read-only mode (the upgrade's store gate stopped, or after `store rollback`). See [Upgrading](upgrading.md#upgrading)

**RADIUS: no answer, or `Access-Reject`**
- `tacctl log failures --backend radius` gives the reason per reject (`not an enabled user of this scope`: the user lacks the scope the device's address falls in, or is disabled; `Crypt digest does not match`: wrong password)
- No line at all: the client is in no scope RADIUS serves (`tacctl scope lookup <ip>`, `tacctl scope protocols <scope>`), its secret is wrong, or a connection filter drops it
- Logged in at the wrong level, or without one: the scope does not send that vendor's attribute (`tacctl scope vendor-attrs <scope>`, `tacctl scope devices <scope>`)

**WTI login refused, or lands at the wrong access level**
- `tacctl config loglevel debug`, retry, then `tacctl log tail 50`: the `client args [...]` line shows the service name the unit sent. If it is not `wti`, set TACACS Parameters → Service Name back to `wti` (with `shell` the WTI levels set on groups are ignored); a group without one is answered through the default-service-permit patch (`tacctl status` shows whether it is applied)
- No authorization request at all → Account Management Module is Disabled on the unit
- `failed to validate the user [x] using a bcrypt password` on every attempt although `tacctl user verify` accepts the password → Default User Access is `Off` on the unit (its sshd sends a junk password for users it cannot resolve); set it `On` / Access Level `ViewOnly`
- Nothing in the tacquito log while the unit waits the Fallback Timer, SYNs visible in tcpdump → the unit's IP Tables drop tacquito's replies; add the `ESTABLISHED,RELATED` accept rule before the final DROP
- Login succeeds, then the session drops (`Broken pipe`) with an accounting start but no stop → tacquito lacks `patches/0002`; run `tacctl upgrade`, or disable the unit's Session Management Module until it is rebuilt
- Level is right but no ports are reachable → User/ViewOnly-level accounts only get the ports granted under Default TACACS User Access → Configure Port Access (factory: none)
- Level is wrong for one user only → a same-named local account on the unit overrides the server-assigned level
- `bad secret detected` in `tacctl log failures` → Secret Word was mistyped or truncated on the unit; `unknown authenticate start packet type` → the unit did not send PAP with TACACS+ minor version 1 (open an issue)
- Set TACACS Parameters → `12. Debug: On` on the unit to see the exchange from its side

**No connection attempts reaching the server**
- Verify the TACACS+ listener's port is reachable (49 by default; `tacctl server listen show`): `telnet <server_ip> <port>` from the device (RADIUS: the `auth` and `acct` listeners, UDP 1812/1813 by default, not testable with telnet)
- Check service is running: `tacctl status` / `tacctl backend status`
- Check listener network/address: `tacctl server listen show` (`--backend radius` for RADIUS)

**Config change not taking effect**
- Changes made through tacctl are rendered and restart what changed; a file edited by hand is drift, which tacctl will not overwrite (see the exit-3 item above)
- Check for errors: `tacctl config validate`

## Useful Commands

```bash
tacctl status          # Health check with auth stats, per backend
tacctl backend status  # Services and listeners
tacctl log failures    # Recent auth failures
tacctl config validate # Store, tacctl.yaml, rendered configs, drift
tacctl config diff     # What changed since the last snapshot
```
