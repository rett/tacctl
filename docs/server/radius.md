# RADIUS

[Documentation](../README.md) › [Server](README.md)

```
tacctl backend enable radius
```
installs FreeRADIUS from the distribution (`freeradius freeradius-utils`; on the RHEL family from AppStream, no EPEL), renders tacctl's configuration, and starts the distribution's unit (`freeradius` or `radiusd`) with a drop-in that runs **tacctl's own instance** (`-n tacctl-radius`): the package's `radiusd.conf`, `clients.conf`, `sites-enabled/` and `mods-enabled/` are not read, edited or unlinked, so there is no EAP, inner tunnel, proxying, Status-Server or default `localhost/testing123` client. The module knows the Debian/Ubuntu and the RHEL-family layouts.

- **An existing FreeRADIUS is never taken over.** If the unit is running or enabled without tacctl's drop-in, `backend enable radius` refuses and says what to run if it is not in use (`systemctl disable --now freeradius`). On Debian/Ubuntu the package starts its own configuration on install; tacctl stops and disables that before starting its own.
- **Same users, groups, scopes and secrets.** One RADIUS client per prefix of every scope that RADIUS serves (no `protocols` filter, or one that names `radius`), with that scope's secret; overlapping prefixes resolve to the most specific, as with TACACS+. A user authenticates only from a client in a scope they belong to; disabled users and the `root` sink never authenticate. The connection filters (`config allow|deny`) apply.
- **PAP only**, against the stored bcrypt hashes. CHAP, MS-CHAP and EAP are rejected.
- **What RADIUS does not do:** no per-command authorization (`group commands` rules are not enforced by the server; see [Per-command authorization](../security/command-authorization.md#per-command-authorization)), no command accounting (login/exec accounting only, to a detail file), no Prometheus counters. Every change restarts FreeRADIUS (it reads clients only at start); requests in flight are retransmitted by the NAS.
- **Status and logs.** `tacctl status` has a RADIUS section (service, listeners, accepts and rejects of the last 24 hours from `tacctl-auth.log`, recent rejects with their reason, which vendor attributes are sent); `tacctl log tail|search|failures|accounting|clear --backend radius`; `tacctl user show` reads the last login from the auth log.
- **Secrets.** Any secret is rendered that FreeRADIUS can read back unchanged (refused: one with both a backslash and a `$`); beyond 63 characters, or with a space or non-ASCII character, `config render` warns, as some RADIUS clients take no more. Device configs refuse secrets a device CLI would misread (see [RADIUS device configuration](../devices/radius.md)).
- **Server-side BlastRADIUS:** FreeRADIUS 3.2.5 and 3.0.27 log a "BlastRADIUS check" block the first time a client sends Message-Authenticator, and from then on require it from that client (the package default, kept). For clients that send none, see [Login for Linux hosts](../hosts/README.md).

## What an Access-Accept carries

A RADIUS server cannot tell what kind of device is asking, and one vendor's privilege attribute has no business on another vendor's device, so the RADIUS backend sends a vendor attribute only where the operator said so:

| Sent | When |
|---|---|
| `Service-Type` (`Administrative-User` at priv-lvl 15, else `NAS-Prompt-User`) | always (a standard attribute) |
| `Cisco-AVPair = "shell:priv-lvl=N"` | the scope enables `cisco`, or the device's address is tagged `cisco` |
| `Juniper-Local-User-Name = "<class>"` | the scope enables `juniper`, or the address is tagged `juniper` |
| `WTI-Super = 0..3` (ViewOnly, User, SuperUser, Administrator; the bands of the TACACS+ WTI mapping) | the scope enables `wti`, or the address is tagged `wti` |

- `tacctl scope vendor-attrs <scope> enable|disable <vendor>[,<vendor>...]` sets what a scope's devices get. It is an opt-in: **a new scope sends none** ("Vendor attributes: not sent").
- `tacctl scope devices <scope> set <ip|cidr> <vendor>` tags an address: it gets its own vendor's attribute and no other, whatever the scope enables (`unset` removes the tag). The address must be one `scope lookup` answers with this scope; `scope prefixes remove` refuses to leave a tag outside the scope.
- An Access-Reject carries none of them. Linux hosts (`pam_radius_auth`) read none, so a scope of Linux hosts needs nothing enabled.
- `tacctl config validate` warns about a scope served over RADIUS that sends nothing and is not a Linux-host scope (one used by enrolled hosts whose prefixes are their single addresses); `tacctl status` counts the scopes that send something.
- Rendering: one FreeRADIUS client per prefix and per tagged address, the group's values in tacctl-internal attributes that never leave the server, and a policy that adds a vendor attribute only on an exact match.

## Which protocol a scope uses

- `tacctl scope protocols <scope> set tacacs|radius|tacacs,radius` limits which backends serve a scope (a filter: `clear` means every enabled backend). A backend leaves a scope it does not serve out of its config entirely: its devices get no answer.
- `tacctl scope auth-method <scope> tacacs|radius|clear` is the protocol a scope's devices and hosts use when a command names none: `config cisco|juniper|wti` without `--protocol`, and `host enroll` (a host not registered yet) / `config linux script` without `--method`. Without it, the one protocol the `protocols` filter names is used, else TACACS+ (device configs) or `host default-method` (hosts). It must be allowed by the scope's `protocols` filter, and `scope protocols set` refuses a list without it.
- `tacctl scope radius-group <scope> [label]` is the RADIUS twin of `tacacs-group`: the Cisco `aaa group server radius <LABEL>` name (default `RADIUS-GROUP`).
