# RADIUS backend: what was checked against real FreeRADIUS

The design is in the header of `lib/backends/radius.sh`. This file records
what that design rests on: what was run against real FreeRADIUS, on which
versions, with what result, and what was not verified. It replaces the
assumptions marked [A] in `docs/plans/pluggable-backends.md` §5 and answers
§9 items 1-3 and (partly) 7.

Everything below was run on 2026-10-02 in rootless podman 4.9.3 containers
with `tests/containers/radius/run.sh` (procedure: `tests/README.md`, "RADIUS
in containers"), against the renderer as it is in this tree. The vendor
attributes (opt-in per scope and per address, tacctl's dictionary) were
added later the same day and checked the same way, on the same three
versions: "Vendor attributes and tacctl's dictionary" below.

| Distro image | FreeRADIUS | libcrypt | How |
|---|---|---|---|
| `ubuntu:noble` | 3.2.5+dfsg-3~ubuntu24.04.3 | libcrypt1 1:4.4.36-4build1 | systemd container; `tacctl backend enable radius` for real |
| `almalinux:9` | 3.0.27-3.el9_7 (AppStream) | libxcrypt 4.4.18-3.el9 | systemd container; `tacctl backend enable radius` for real |
| `almalinux:8` | 3.0.20-15.module_el8.10.0 (AppStream) | libxcrypt 4.1.1-6.el8 | files rendered on the host for the RHEL layout, daemon started by hand (python 3.6 there cannot run tacctl) |

## Distro facts (plan §9 item 3)

| | Debian/Ubuntu | RHEL family |
|---|---|---|
| packages | `freeradius`, `freeradius-utils` | the same; AppStream, **no EPEL** |
| raddb | `/etc/freeradius/3.0` (parent `/etc/freeradius` is 2750 `freerad:freerad`) | `/etc/raddb` |
| unit | `freeradius.service`, `Type=notify`, **`User=freerad`**, sandboxed, `ExecStartPre=freeradius $FREERADIUS_OPTIONS -Cx -lstdout` | `radiusd.service`, `Type=forking`, starts as root and drops to `radiusd`, `PIDFile=/run/radiusd/radiusd.pid` |
| account | `freerad:freerad` | **`radiusd:radiusd`** (the plan assumed `radius`) |
| binary | `/usr/sbin/freeradius` | `/usr/sbin/radiusd` |
| logs | `/var/log/freeradius` (0755 `freerad:adm`) | `/var/log/radius` (0700 `radiusd:radiusd`) |
| modules | `/usr/lib/freeradius` | `/usr/lib64/freeradius` |
| after package install | unit **enabled and running** the package's default sites | unit disabled, not running |
| daemon log | `log { destination = files }`, `auth = no`: nothing about logins in the journal or in `radius.log` | the same |

On EL9 the package's own configuration does not start as shipped (the unit
fails in a pristine container), with or without tacctl.

## Findings that shaped the design

1. **`rlm_pap` + `Crypt-Password` verifies the stored bcrypt hashes** on all
   three versions: `$2b$` cost 10 and 12, and `$2a$`. (§9 item 1.) Wrong
   password: `tacctl_pap: Crypt digest does not match "known good" digest`,
   Access-Reject.
2. **Switching `sites-enabled/` is not enough.** With `default` and
   `inner-tunnel` unlinked and a tacctl site linked, 3.2.5 refuses to start:
   `mods-enabled/eap[14]: Failed to find 'Auth-Type EAP' section`. The
   package's module set depends on its sites. Hence the instance of tacctl's
   own: `-n tacctl-radius` makes the daemon read `<raddb>/tacctl-radius.conf`
   as its main configuration and nothing of the package's
   (`radiusd.conf`, `clients.conf`, `sites-enabled/`, `mods-enabled/`).
   `${confdir}` is predefined from `-d`.
3. **`radiusd -C` does not prove a start.** A main config without `prefix`
   and `localstatedir` passes `-C` and then fails at start (`Reference
   "${prefix}" not found`); without `libdir` it works on Debian and fails on
   EL (`/usr/lib/rlm_files.so: cannot open`), there already at `-C`. All
   three are rendered. `backend enable` therefore also requires the unit to
   be active after the start and undoes itself when it is not.
4. **`-C` drops to the service account before reading the users file.** A
   staging directory under `/tmp` (0700 root) gives `Unable to check file
   ...: Permission denied`. The check runs on a copy in
   `<raddb>/.tacctl-check.XXXXXX` (0750 `root:<group>`, files 0640), removed
   afterwards. On Debian the unit runs entirely as `freerad`, so the
   artifacts must be group-readable: 0640 `root:<group>` works on both.
5. **Custom client fields are readable as `%{client:tacctl_scope}`**, CIDR
   `ipaddr`/`ipv6addr` work, clients defined inside `server tacctl { }`
   are the only clients of its listeners. (§9 item 2.) The package's
   `localhost`/`testing123` client is not loaded at all.
6. **Overlapping client networks: the longest prefix wins.** A request from
   127.0.0.2 with the secret of the scope owning 127.0.0.0/8 gets no answer
   when another scope owns 127.0.0.2/32; with that scope's secret it is
   processed as that scope. Same rule as tacquito's ordered list.
7. **`rlm_files` check items against a request attribute set by unlang work**
   (`Tmp-String-0 == "<id>/<scope>"`); no match returns `noop`, a match `ok`.
   A module instance named `tacctl_pap` sets `Auth-Type` to its own name, so
   `authenticate { tacctl_pap }` (not `Auth-Type PAP { }`). `reject` and
   `handled` are instances of `rlm_always` in the package's `mods-enabled/`;
   tacctl defines its own.
8. **An Access-Reject carries the reply items the users file added** unless
   they are removed in `Post-Auth-Type REJECT` (the package does it with
   `attr_filter.access_reject`). tacctl's policy removes its four
   (`Service-Type` and the three vendor attributes).
9. **unlang prefix containment is `<=`, not `<`**
   (`&Packet-Src-IP-Address <= 127.0.0.66/32` is true for that address; `<`
   is false), and comparing an attribute the packet does not have is an
   error line per request; hence the existence guard. IPv4 and IPv6 forms
   verified. `Response-Packet-Type := Do-Not-Respond` plus an `always`
   instance with `rcode = handled` gives no answer; `post-auth` still runs,
   so the auth-log call is skipped for such a packet.
10. **Secrets in the config file.** Twenty secrets were rendered both ways
    and used by `radclient -S` on each version:

    | Form | Reads back unchanged | Does not |
    |---|---|---|
    | single-quoted, `'` as `\'` | everything without a backslash: spaces, `"`, `'`, `#`, `;{},=`, `%{User-Name}`, `${confdir}`, `$ENV{HOME}`, UTF-8, 200 characters | a backslash on 3.2.5 (3.0.20 and 3.0.27 take it; the versions disagree) |
    | double-quoted, `\` and `"` escaped | everything without `$`: backslashes anywhere, `\n` as two characters, quotes | `${...}` and `$ENV{...}` are expanded (all three versions) |

    So: no backslash → single quotes; backslash and no `$` → double quotes;
    both → refused. Length: 200 characters verified; the package's
    `clients.conf` says "up to 8k". Control characters are refused by the
    store.
11. **Reload.** `systemctl reload` (config check, then HUP) keeps serving,
    but FreeRADIUS 3 re-reads only HUP-safe modules (the users file), not
    clients or the policy. tacctl always restarts. The render id makes a
    HUP on a half-new set match nobody.
12. **3.2.5 and 3.0.27 log a loud "BlastRADIUS check" block** in the daemon
    log the first time a client sends Message-Authenticator and then require
    it from that client for the life of the process
    (`require_message_authenticator = auto`, the default). Left at the
    default: the option does not exist in 3.0.20.
13. **Empty states are served**: no clients and an empty users file pass
    `-C` and start; unknown clients are ignored. Unlike tacquito, nothing to
    warn about.
14. `Status-Server` is ignored with `status_server = no`; CHAP for a valid
    user is rejected (`No Auth-Type found`).

## Cases run (all three versions; `tests/containers/radius/cases.sh`)

Store: `tests/containers/radius/make-store.py`. 42 cases, all pass on all
three. Sources are told apart by address (`Packet-Src-IP-Address` in the
radclient request file; the container's own address for scope `prod`).
Every reply is decoded with tacctl's dictionary (`radclient -D`) and
compared attribute by attribute: an Accept carries exactly the attributes
named below (the Message-Authenticator aside), a Reject none.

| Case | Result |
|---|---|
| right password, user in the client's scope, a scope that enables no vendor | Access-Accept with `Service-Type = Administrative-User` and nothing else |
| operator / custom group (priv 10) / readonly | Accept with `Service-Type = NAS-Prompt-User` and nothing else |
| scope `lab` enables nothing; 127.0.0.10, .11, .12 tagged cisco, juniper, wti | `Cisco-AVPair = "shell:priv-lvl=15"`, `Juniper-Local-User-Name = "RW-CLASS"`, `WTI-Super = Administrator` respectively, each alone after `Service-Type` |
| scopes enabling one vendor each (cisco, juniper, wti), untagged address | that vendor's attribute only |
| the same scopes, an address tagged with another vendor (juniper in the cisco scope, wti in the juniper scope, cisco in the wti scope) | the tag's vendor only, not the scope's |
| a cisco scope, an address tagged cisco | Cisco only |
| a scope enabling all three, untagged | `Service-Type`, `Cisco-AVPair`, `Juniper-Local-User-Name`, `WTI-Super`, in that order; readonly gets `priv-lvl=1`, `RO-CLASS`, `WTI-Super = ViewOnly` (0), priv 10 gets `SuperUser` (2) |
| the same scope, an address tagged wti | WTI only |
| wrong password in the all-vendor scope (untagged and tagged); a user outside the scope | Access-Reject, no attribute |
| every reply above | no `Tacctl-*`, `Tmp-*` or undecodable (`Attr-*`) attribute |
| wrong password, empty password | Access-Reject, no reply attributes |
| user of another scope only | Access-Reject (`not an enabled user of this scope` in the auth log) |
| disabled user with the right password; `root` sink; unknown user | Access-Reject |
| overlap: /32 of scope `inner` inside /8 of `lab` | `lab`'s secret: no answer; `inner`'s secret: processed as `inner` |
| scope with `protocols: [tacacs]` | its secret gets no answer; its /32 falls to the enclosing RADIUS scope, whose users only are accepted |
| secret with backslash and both quotes; secret with `'`, `"`, `#`, `${confdir}`, `%{User-Name}`, spaces | Accept |
| `filters.deny` address inside an allowed range; address outside `filters.allow` | no answer (auth and accounting), nothing logged, no accounting record |
| the package's `localhost`/`testing123` client | no answer |
| IPv6 client `::1` (udp6 listener, IPv6 allow filter) | Accept |
| CHAP request; Status-Server | Reject; no answer |
| Accounting Start | Accounting-Response, record in `tacctl-accounting.log` |

With systemd (Ubuntu noble, AlmaLinux 9; `flow.sh`, 73 and 71 checks, all passing):
package install by `backend enable`, daemon running as the service account
under the distro unit with the drop-in, artifacts 0640 `root:<group>` and
unreadable to others, package files unmodified (`dpkg --verify` /
`rpm -V`), `user disable|enable`, `scope protocols`, `scope vendor-attrs` and `scope
devices` reaching the daemon,
an unrenderable secret refused with the store unchanged, a udp6 listener
added and removed, an unbindable listener address rolled back, drift
refusal and `config render --force`, `systemctl reload`, `backend disable`
(unit stopped, disabled, drop-in gone, package unit as shipped), re-enable
without the package manager, the uninstall phases, and the way from the
release before the vendor attributes (below). On Ubuntu also: after
`disable` the package's own configuration starts under the unit, and
`enable` is then refused and leaves it running.

## Vendor attributes and tacctl's dictionary

The design is in the header of `lib/backends/radius.sh` ("Vendor
attributes: opt-in per scope, per address"). What it rests on, verified on
3.0.20, 3.0.27 and 3.2.5 unless noted:

1. **`-D <dir>` with a dictionary of tacctl's own works with a started
   daemon.** `<raddb>/tacctl-radius-dictionary/dictionary` holds `$INCLUDE
   /usr/share/freeradius/dictionary` (the package's main dictionary; that
   path on Ubuntu 24.04 and on AlmaLinux 8 and 9) and then defines the WTI
   vendor and tacctl's three internal attributes. `radiusd -C` with `-D`, the
   unit's ExecStartPre and ExecStart with `-D` (Debian: `-f` under
   `Type=notify`; EL: forking), and Access-Accepts carrying `WTI-Super` all
   work. Relative `$INCLUDE`s inside the package's dictionary are resolved
   against its own directory. The package's `<raddb>/dictionary` (for local
   attributes) is still read after it. No package file is edited
   (`dpkg --verify` / `rpm -V` clean in `flow.sh`).
2. **radclient decodes `WTI-Super` only with the same dictionary**
   (`radclient -D <that directory>`: `WTI-Super = Administrator`); without
   it the attribute shows as `Attr-26.24496.41 = 0x00000003`. Hence `-D` in
   `cases.sh`.
3. **Check items with `:=` on a users entry's first line land in the
   control list** (`Tacctl-Priv-Lvl := 15, Tacctl-Juniper-Class :=
   "RW-CLASS", Tacctl-WTI-Super := 3` next to the hash) and are readable in
   post-auth. `&control:Tacctl-WTI-Super` tests existence: true for the
   value 0 (the ViewOnly case passes).
4. **The policy adds attributes as written:** `&Cisco-AVPair :=
   "shell:priv-lvl=%{control:Tacctl-Priv-Lvl}"`,
   `&Juniper-Local-User-Name := &control:Tacctl-Juniper-Class` and
   `&WTI-Super := &control:Tacctl-WTI-Super` (an attribute reference, integer
   to integer), each inside `if (("%{client:tacctl_send_<vendor>}" == "yes")
   && &control:...)`. They are added in that order, after the users file's
   `Service-Type`, and only in the main post-auth section: an Access-Reject
   runs `Post-Auth-Type REJECT`, which strips all four anyway.
5. **Attributes numbered 3990-3992 never reach the wire.** Besides the
   control list never being encoded, a probe that copied the internal
   attributes into the reply list on purpose (`update reply {
   &Tacctl-Priv-Lvl := 9, &Tacctl-Juniper-Class := "LEAKTEST" }` in
   post-auth) got Access-Accepts without them: same length as without the
   probe, nothing decoded by name or as `Attr-*`. Checked by hand in kept
   containers on all three versions (it is not part of the rendered policy).
6. **A tagged address is a client of its own** inside its scope's prefix
   (127.0.0.10/32 inside 127.0.0.0/8, 127.0.0.17/32 inside 127.0.0.16/30):
   the longest prefix wins as for overlapping scopes (finding 6), and a
   request with another scope's secret from that address gets no answer.
7. **The way from the release before (commit 7a8d53f) works both ways it
   can happen** (`flow.sh`, last section, both systemd containers): that
   release's own `backend enable radius` (two files, drop-in without `-D`,
   every Accept with Cisco and Juniper attributes), then this release's
   `upgrade config` step re-renders all three files as a normal render (no
   drift reported), installs the drop-in with `-D` and restarts once; and,
   back on the old files and drop-in, the next mutation with this release's
   code renders the three files and brings the drop-in in line before its
   restart. `config validate` is clean afterwards in both. The Accept then
   carries `Service-Type` only until a scope enables a vendor (the upgrade
   says so).

## Not verified

- **Real devices.** That Cisco IOS/IOS-XE honours `Cisco-AVPair =
  "shell:priv-lvl=N"` with `Service-Type` 6/7 for exec authorization, that
  Junos maps `Juniper-Local-User-Name` to a template user, and that a WTI
  unit takes its access level from `WTI-Super` is documented vendor
  behaviour, not tested here; so is what each does with an Accept that
  carries `Service-Type` alone (the state of a scope that enables nothing).
  `Service-Type = Administrative-User` for priv 15 and `NAS-Prompt-User`
  otherwise is a choice.
- **NAS limits on the shared secret** (§9 item 7). FreeRADIUS takes far
  more than any client. Figures found in vendor documentation (not tested):
  Junos 256 characters, Microsoft NPS 128, Aruba 63; none found for Cisco
  IOS-XE. `secret_constraints` reports the smallest (63, printable ASCII
  without a space) as advice; the renderer warns beyond it and refuses only
  what it cannot write.
- **SELinux.** Containers do not enforce it. The files live where the
  package's policy expects them (`/etc/raddb`, `/var/log/radius`,
  `/run/radiusd`) and the daemon is started by the package's unit, but a
  listener port other than 1812/1813 will need `semanage port`. WP4.3.
- **Debian proper, AlmaLinux 10, a host that is not a container** (the
  Debian unit's sandboxing needed `--cap-add SYS_ADMIN` in a rootless
  container; a real host does not).
- **The takeover refusal on EL** with a running package configuration (it
  does not start there as shipped); verified on Ubuntu and by stubbed test.
- **A crash between the two renames of a commit**, and a HUP on a daemon
  that was not restarted: the render id is designed for both; only its
  normal path (ids agree) was exercised.
- **Load.** Each PAP check is one bcrypt verification (cost 12: about a
  quarter of a second of one thread); the thread pool is the package's
  default of 5 to 32.

# Linux hosts over RADIUS (`host enroll --method radius`)

The design is in the comments of `config/linux/client-install.sh` (the
`*_radius` functions) and `lib/linux_hosts.sh`. This part records what it
rests on: plan §9 items 4 and 5, answered by running the packaged modules.

Everything below was run on 2026-10-02 in rootless podman 4.9.3 with
`tests/containers/hosts/` (procedure: `tests/README.md`, "Linux hosts in
containers"): a server container running tacctl, FreeRADIUS and tacquito,
and `tacctl host enroll` over real SSH into a client container.

## The module, per distribution

| Host | Package (source) | Version | `account` step | accounting records | `require_message_authenticator` |
|---|---|---|---|---|---|
| Ubuntu 24.04 | `libpam-radius-auth` (universe) | 2.0.1-1 | returns success, sends nothing | **malformed** (`Acct-Status-Type = 14892`, random `NAS-IP-Address`) | no |
| Debian 12 | `libpam-radius-auth` (main) | 2.0.0-1 | the same | correct | no |
| Debian 13 | `libpam-radius-auth` (main) | 3.0.0-1 | **none** (`PAM_MODULE_UNKNOWN`) | correct | yes |
| AlmaLinux / Rocky 8 | `pam_radius` (EPEL 8) | 2.0.0-4.el8 | returns success, sends nothing | correct | yes (backported) |
| AlmaLinux / Rocky 9 | `pam_radius` (EPEL 9) | 2.0.0-4.el9 | the same | correct | yes (backported) |
| AlmaLinux / Rocky 10 | `pam_radius` (EPEL 10) | 3.0.0-2.el10_1 | **none** | correct | yes |

- Default server file: `/etc/pam_radius_auth.conf` (Debian family, EL10),
  `/etc/pam_radius.conf` (EL8, EL9). tacctl uses neither: `conf=` with an
  absolute path works on all of them, and the packaged file is left as
  shipped.
- Line syntax `server[:port] secret [timeout]`, IPv6 as `[addr]:port`
  (from the packaged files' own comments; **an IPv6 server was not run**).
  Without a port the module looks up service `radius`: on a minimal Debian
  12 without `/etc/services` every request then fails at once
  (`Servname not supported`). tacctl always writes the port.
- The timeout is clamped to at least 3 seconds (1 and 2 behave as 3).
  `retry=N` re-sends an Access-Request N times; accounting is sent once.
- Accounting goes to the authentication port **plus one**, whatever the
  server's accounting listener is (verified with a listener on each port).
- The Debian package ships a `pam-auth-update` profile with `Default: no`:
  installing it changes nothing in `/etc/pam.d` (the snapshot comparison
  in every run confirms it).
- The modules bind their socket to port 0 on the wildcard address (strace,
  EL8/9/10).
- EPEL: `dnf install epel-release` works on AlmaLinux, Rocky and CentOS
  Stream (their `extras` repository); on RHEL (UBI 8/9/10 images) and Oracle
  Linux 9 it does not, and `dnf install
  https://dl.fedoraproject.org/pub/epel/epel-release-latest-<major>.noarch.rpm`
  does. `pam_radius` needs only glibc and pam: no CRB or PowerTools. On
  Oracle Linux `dnf install epel-release` exits 0 without installing
  anything, so the script checks `rpm -q`, not the exit status.

## What `pam_radius_auth` returns (`run.sh <client> probe`)

The same on 2.0.0, 2.0.1 and 3.0.0 unless noted:

| Case | Return | Took |
|---|---|---|
| Access-Accept | `PAM_SUCCESS` | at once |
| Access-Reject: wrong password, empty password, user not in the scope | `PAM_AUTH_ERR` | 1 s (the server's reject delay) |
| no answer (packets dropped, or a port nobody listens on) | `PAM_AUTHINFO_UNAVAIL` | 3 s x (retry + 1) |
| wrong shared secret | `PAM_AUTHINFO_UNAVAIL` | 1 s where the module does not send Message-Authenticator (Debian 12, Ubuntu 24.04: the server answers with a reject the module cannot verify, and it gives up at once); the full timeout on the others (the answer is discarded, or the server drops the request) |
| server name that does not resolve | `PAM_AUTHINFO_UNAVAIL` | at once |
| server file missing or unreadable | `PAM_ABORT` | at once |
| `account` | `PAM_SUCCESS` without asking the server (2.0.x); `PAM_MODULE_UNKNOWN` (3.0.0) | |
| session open / close | `PAM_SUCCESS`; `PAM_AUTHINFO_UNAVAIL` after 3 s when the server is silent | |
| password change | `PAM_AUTHTOK_ERR` after "You must choose a new password" (2.0.x); `PAM_MODULE_UNKNOWN` (3.0.0) | |

Hence the lines (the gate and the control are those of the pam_tacplus stack):

```
# tacctl-auth
auth    [success=ok default=1]                               pam_succeed_if.so quiet user ingroup tac-users
auth    [success=done authinfo_unavail=ignore default=die]   pam_radius_auth.so conf=/etc/tacctl-pam_radius.conf retry=1 [require_message_authenticator]
@include common-auth                                         (Debian family; on the RHEL family the service's own password-auth line follows)
# tacctl-account: no module line (only '@include common-account' on the Debian family)
# tacctl-session (left empty on pam_radius_auth 2.0.1, or when the accounting port is not auth+1)
session [success=ok default=1]                               pam_succeed_if.so quiet user ingroup tac-users
session optional                                             pam_radius_auth.so conf=/etc/tacctl-pam_radius.conf
```

`/etc/tacctl-pam_radius.conf` is `<server>:<port> <secret> 3`, 0600 root.
`require_message_authenticator` is added when the installed module has the
option (the string is in the binary); both FreeRADIUS versions tacctl runs
on put a Message-Authenticator in every answer (3.2.5 seen with radclient;
3.0.27 by the passing run with an AlmaLinux 9 server).

## The runs

`radius`, `tacplus`, `switch` as described in `tests/README.md`; every case
passed in every run listed.

| Client | pam / OpenSSH / sudo | radius | tacplus | switch |
|---|---|---|---|---|
| Ubuntu 24.04.5 | 1.5.3-5ubuntu5.7 / 9.6p1 / 1.9.15p5 | 56 pass (also with the AlmaLinux 9 server) | 50 pass | 82 pass |
| Debian 13 | 1.7.0-5 / 10.0p2 / 1.9.16p2 | 57 pass | 50 pass | |
| Debian 12 | 1.5.2-6+deb12u2 / 9.2p1 / 1.9.13p3 | 57 pass | | 82 pass |
| AlmaLinux 8.10 | 1.3.1-40.el8_10 / 8.0p1 / 1.9.5p2 | 57 pass | | |
| AlmaLinux 9.8 | 1.5.1-28.el9 / 9.9p1 / 1.9.17p2 | 57 pass (also with the AlmaLinux 9 server) | | |
| AlmaLinux 10.2 | 1.6.1-9.el10_2.1 / 9.9p1 / 1.9.17p2 | 57 pass | 50 pass | 82 pass |
| Rocky 8.9 | 1.3.1-27.el8 / 8.0p1 / 1.9.5p2 | 57 pass | | 82 pass |
| Rocky 9.3 | 1.5.1-15.el9 / 9.9p1 / 1.9.17p2 | 57 pass | 50 pass | 82 pass |
| Rocky 10.2 | 1.6.1-9.el10 / 9.9p1 / 1.9.17p2 | 57 pass | | |

After the vendor attributes changed the server's render (the dictionary,
`-D` in the drop-in, `device=` in the auth log), `radius` was run again for
Debian 12 (server Ubuntu 24.04, FreeRADIUS 3.2.5) and AlmaLinux 9.8 (server
AlmaLinux 9, FreeRADIUS 3.0.27): 57 pass each. pam_radius_auth reads no
vendor attribute, so a per-host scope needs none enabled.

Servers: Ubuntu 24.04 with FreeRADIUS 3.2.5 and tacquito (the binary of the
machine that built the image); AlmaLinux 9 with FreeRADIUS 3.0.27 (radius
only). pam_tacplus 1.7.0 was compiled on the client in every tacplus run
(no podman inside the server container).

Timings seen with the server made silent (nft drop at the server):

| | radius | tacplus |
|---|---|---|
| local administrator (not in `tac-users`): login, sudo | no delay (0 s) | no delay |
| user without a local password: refused after | 8-9 s | 5-6 s |
| adopted account, local password accepted after | 6 s (Ubuntu 24.04, no accounting line) or 9 s (6 s of authentication, 3 s for the accounting packet at session start); 3 s more at logout | 7-8 s |

One run differed: Debian 12 took 14 s for both (not looked into; its probe
shows the same 6 s for `retry=1`).

A wrong shared secret on the host behaves like a silent server for both
methods: users without a local password are refused, an adopted account's
local password is accepted, the local administrator is unaffected.

## SELinux (not verified in enforcing mode)

Containers do not enforce SELinux; nothing here was exercised. From the
EL8 (3.14.3-139), EL9 (38.1.75) and EL10 (42.1.18) targeted policies with
`sesearch`/`seinfo`, and the system calls the module makes:

- UDP has no `name_connect`; the port needs no label, default or not.
- The module binds port 0, for which the kernel checks `node_bind` only.
  `sshd_t`, `xdm_t` (and `sshd_session_t` on EL10) have it unconditionally;
  `local_login_t` and the sudo domains of confined users have it only
  through `kerberos_enabled` (on by default) or `nis_enabled`. The CIL
  module `tacctl_pam_radius` allows `local_login_t` and `sudodomain`
  `node_t:udp_socket node_bind` directly; it compiles and installs
  (`semodule -n -i`) against all three policies.
- `authlogin_radius` only adds `name_bind` on unreserved ports for login
  programs, which a module that binds port 0 does not need; it is not set.
  If RADIUS logins are denied on an enforcing host, `ausearch -m avc -c
  sshd` and that boolean are the first things to look at.
- The login domains may read `etc_t` files and not `var_lib_t` ones, which
  is why the server file is `/etc/tacctl-pam_radius.conf` and not in
  `/var/lib/tacctl-client` (plan §6.1 had it there).

## Not verified

- SELinux enforcing (above); a real desktop login through GDM or SDDM (the
  `gdm-password` service was driven by a PAM client against a stand-in
  service file); KDE's lock screen (a PAM client that is not root fails, as
  with pam_tacplus: the server file is root-only); an IPv6 server address;
  RHEL proper and Oracle Linux beyond installing EPEL and the package in
  their container images; Ubuntu with `universe` disabled (the script only
  says where the package is).
- pam_radius_auth 2.0.x does not send Message-Authenticator and, without
  the option, does not check the one in the answer (BlastRADIUS,
  CVE-2024-3596): Debian 12 and Ubuntu 24.04 hosts are in that position,
  and FreeRADIUS logs its "BlastRADIUS check" block for them.

# WTI units over RADIUS: what the vendor documents

What is built on it: the RADIUS backend sends `WTI-Super` (from the group's
priv-lvl, in the bands of the TACACS+ mapping) to the devices of a scope
that enables `wti`, or to an address tagged `wti`; its dictionary defines
the attribute; `tacctl config wti --protocol radius` (or a scope that
resolves to RADIUS) prints a walkthrough of the unit's RADIUS menu written
from the documents below. **None of it has been tried on a WTI unit.** This
part records what WTI's own documents say, read on 2026-10-02.
Each statement is marked **[D]** (in the named document), **[C]** (checked
here, in a container or on this machine) or **[I]** (inferred; not stated
anywhere that was read). No WTI unit was involved at any point.

## Sources

| | Document | How it was read |
|---|---|---|
| S1 | `https://ftp.wti.com/InfoCenter/rsa/dictionary/dictionary.wti` | the file itself (873 bytes, sha256 `5d750697120ab043e4113829cbcf12bdbd1aa8a2c375b3a319cc8d9b54b98e92`) |
| S2 | WTI knowledge base, "Installing the WTI Dictionary to FreeRadius": `https://wti.com/blogs/knowledge-base/basic-linux-freeradius-setup-with-wti-dictionary-install` | through a fetch tool that returns the page as extracted text; wording may not be verbatim |
| S3 | WTI knowledge base, "RADIUS client configuration": `https://www.wti.com/blogs/knowledge-base/radius-client-configuration` | as S2 |
| S4 | "WTI User's Guide, Software SetUp and Operation", Part No. 14527 Rev. C, February 2021 (CPM, DSM, NBB, NPS, REM, RPC, VMR series), sections 7.3.1.14 to 7.3.1.14.2: `https://ftp.wti.com/download/manuals/wti_firmware_guide.pdf` | the PDF, as text (`pdftotext`) |
| S5 | "DUO with Active Directory and Cisco ISE NAS-Identifier with WTI Radius client": `https://ftp.wti.com/pub/TechSupport/Articles/DUO_AD_CiscoISENASIdentifierwithRadiusclient.pdf` | the PDF, as text; its screenshots (the unit's RADIUS screen among them) are images and were not read |
| S6 | RSA SecurID Access implementation guide for WTI devices (tested December 1, 2017): `https://ftp.wti.com/InfoCenter/rsa/certdoc/rsacertdoc.pdf` | as S5 |

None of them names a firmware version. tacctl's TACACS+ walkthrough was
verified on a v8.10 unit; whether the RADIUS menu of that firmware is the one
S4 describes is **[I]**.

## The dictionary (S1)

```
VENDOR        WTI                 24496
ATTRIBUTE     WTI-Port            40    integer
ATTRIBUTE     WTI-Super           41    integer
ATTRIBUTE     WTI-Port-Access     42    string
ATTRIBUTE     WTI-Plug-Access     43    string
ATTRIBUTE     WTI-Group-Access    44    string
ATTRIBUTE     WTI-Modem-String    45    string
ATTRIBUTE     WTI-Text            46    string
```

- **[D]** Those seven attributes between `BEGIN-VENDOR WTI` and `END-VENDOR
  WTI`, and nothing else: **no `VALUE` lines**, so the access levels are
  written as numbers. The vendor id 24496 and `WTI-Super` = 41, integer, are
  repeated in S5.
- **[D]** The file carries `$Id: dictionary.wti,v 1.1 2010/10/06 ...` and no
  licence or redistribution statement. Its two comment blocks (about
  `dictionary.ascend`, and about a binary-coded-decimal format) describe none
  of its attributes; **[I]** they were carried over from another dictionary.
- **[I]** Redistribution is therefore unclear. The numbers above are facts;
  a tacctl-owned dictionary would be written from them rather than be a copy
  of the file.
- **[C]** FreeRADIUS does not ship it: no file under `/usr/share/freeradius`
  mentions vendor 24496 in 3.0.20 (AlmaLinux 8) or 3.2.5 (Ubuntu 24.04).

## What the attributes mean

- **[D]** `WTI-Super` "sets the command access level for the user": 0 =
  ViewOnly, 1 = User, 2 = SuperUser, 3 = Administrator (S4; S2 has the same
  four as "Read Only Rights", "User Rights", "SuperUser Rights",
  "Administrator Rights"; S5 defines Administrator = 3 and User = 1 in ISE).
  These are the unit's four access levels, the ones the TACACS+ mapping in
  `wti_access_level_for_privlvl` ends in.
- **[D]** `WTI-Port-Access`: a string with one character per serial port, 0
  = deny, 1 = allow (S4: "an 8 character string", example `"11101001"` for
  ports 1, 2, 3, 5 and 8; S2: `"00111100"` for ports 3 to 6).
- **[D]** `WTI-Plug-Access`: the same for switched outlets, on power-control
  and combo products only (S4: "a four character string", example `"0101"`;
  S2's example is eight characters, `"11100000"`).
- **[I]** The string length follows the number of ports or plugs of the
  model; neither document says what a unit does with a string of another
  length, or with more than eight ports.
- `WTI-Group-Access`, `WTI-Port`, `WTI-Modem-String`, `WTI-Text`: in S1,
  described nowhere that was read. **[I]** `WTI-Group-Access` is the plug-group
  counterpart of the "Configure Plug Group Access" item of S4.
- **[D]** The example users entry of S2, for FreeRADIUS 3.0.16 built from
  source (`/usr/local/...`), the dictionary installed by copying it to
  `/usr/local/share/freeradius` and adding `$INCLUDE dictionary.wti` to the
  main `dictionary` there:

  ```
  testuser Cleartext-Password := "userpassword"
  User-Name = "testuser",
  WTI-Super="1",
  WTI-Port-Access="00111100",
  WTI-Plug-Access="11100000"
  ```

- **[D]** S5's flow ends: "Cisco ISE return to WTI with Access Accept +
  Radius attribute 41 and WTI permits the user access."

## When no WTI attribute comes back

- **[D]** S4, "Default RADIUS User Access": "When enabled, allows RADIUS
  users to access the unit without first defining a RADIUS user account on
  the WTI Device. When new RADIUS users access the unit, they will inherit
  the default Access Level, Port Access and Service Access". Its `Enable`
  defaults to **On**, its `Access Level` to **User**; port, plug and plug
  group access default to all on for Administrator and SuperUser and to
  undefined for User and ViewOnly; service access to serial, Telnet/SSH, Web
  and RESTful API on, outbound off.
- **[D]** S3 on the same item: without the VSA on the server "by default a
  logged in user will only have View rights. When enabled, this parameter
  gives undefined valid users these default rights when logging in". The two
  documents disagree on the level a factory-default unit hands out (User in
  S4, View in S3); neither was checked on a unit.
- **[I]** So an Access-Accept without `WTI-Super` logs the user in at the
  Default User Access level when that item is enabled. This is what a WTI
  unit pointed at a scope of tacctl's that sends no `WTI-Super` would do;
  `config wti --protocol radius` refuses such a scope, and its walkthrough
  sets the level to ViewOnly explicitly because the documents disagree.
- Not documented: what happens to such a login with Default User Access
  disabled (**[I]** from "without first defining a RADIUS user account": it
  then needs an account of that name on the unit), whether a `WTI-Super`
  in the reply overrides a same-named local account (for TACACS+ the local
  account wins, see the walkthrough), and whether `WTI-Port-Access` absent
  means "the level's default ports" or "none".

## Service-Type

Not mentioned in S1 to S6: not as something the unit sends, not as something
it reads. S2's working example returns none. **[I]** The reply's
`Service-Type` (which tacctl sends for Cisco) is ignored by the unit; not
verified.

## What the unit sends in an Access-Request

- **[D]** Only indirectly: S5 builds its ISE policy set on the condition
  `Radius-NAS-Identifier START_WITH CPM (DSM or REM)`. So the unit sends a
  `NAS-Identifier`, and it begins with the product family.
- Not documented: the full `NAS-Identifier` (model, site id or hostname) and
  whether it can be set; `NAS-IP-Address`, `NAS-Port`, `NAS-Port-Type`,
  `Service-Type`; any vendor attribute in the request; whether the password
  goes as PAP (**[I]** yes: S2's example checks a `Cleartext-Password` and S6
  passes one-time passwords through it); whether it sends or requires
  `Message-Authenticator`; limits on the secret.
- **[I]** For a server that must recognise a WTI unit, `NAS-Identifier` is
  the only handle the documents give, and it is under the device's control,
  not the server's. tacctl's own handle is the client's scope (the source
  prefix and its secret). tacctl's auth log already records the value
  (`nas=` in `tacctl-auth.log`, from `NAS-Identifier`, else `NAS-IP-Address`),
  so one login from a real unit against the RADIUS backend shows what it
  sends.

## The unit's RADIUS menu

- **[D]** Reached with `/N`, then item 29 (S3: "/n 29"; S5: "/N option 29
  for Radius"; S6: "enter \n and then choose option 29"). The TACACS menu is
  28 on the unit tacctl was tested with; **[I]** these numbers vary by model
  and firmware as that one does.
- **[D]** Items and factory defaults (S4, in the order printed there; the
  item numbers inside the menu are not given):

  | Item | Default | |
  |---|---|---|
  | Enable | Off | |
  | Primary Host/Address IPv4, IPv6 | undefined | address or name |
  | Primary Secret Word | undefined | |
  | Secondary Host/Address IPv4, IPv6 | undefined | |
  | Secondary Secret Word | undefined | |
  | Fallback Timer | 3 seconds | how long the primary is tried before the secondary |
  | Fallback Local | Off | Off; On (All Failures): also after a reject; On (Transport Failure): only when no server can be contacted |
  | Retries | 3 | per server |
  | Authentication Port | 1812 | |
  | Accounting Port | 1813 | |
  | OneTime Auth | Off | for one-time-password schemes |
  | OneTime Auth Timer | 5 minutes | |
  | Session Module Type | none given | "Enables/disables queries of session parameters" |
  | Ping RADIUS Servers | | ICMP to the configured servers |
  | Default RADIUS User Access | Enable On, Access Level User | see above |

- **[D]** S3 also lists a `Debug` item ("will add useful debug information
  to the log files internal to the WTI Device"); S6 uses it. S4's table has
  none.
- **[D]** With Fallback Local Off, a failed RADIUS login is final (S3: "the
  attempt is over and the user fails the login process"): with the factory
  default, a unit whose server is unreachable admits nobody over the network
  services RADIUS covers.
- **[I]** "Session Module Type" is accounting (the TACACS+ menu's "Session
  Management Module" is). Whether the unit sends accounting at all without
  it, and what the records hold, is not documented.
- Not documented for RADIUS, known for TACACS+ from the tested unit and
  **[I]** likely to apply: the unit's IP Tables must let the server's replies
  in (for RADIUS, UDP from the server's authentication and accounting
  ports; a rule accepting `ESTABLISHED,RELATED` covers them), SSH logins
  need Default User Access enabled, and the Invalid Access Lockout arms on
  repeated failures.

## Loading a vendor dictionary into tacctl's instance (built)

The way chosen is the third below (`-D`, a dictionary of tacctl's own);
"Vendor attributes and tacctl's dictionary" above has what was verified
with it on all three versions, a started daemon and decoded replies.
tacctl's file is written from the numbers WTI publishes (vendor 24496,
attribute 41, integer) with the value names of the user's guide; it is not
a copy of WTI's file.

- **[C]** A users entry with `WTI-Super = 3` fails the daemon's check without
  a dictionary (`Unknown name "WTI-Super"`, FreeRADIUS 3.0.20).
- **[C]** FreeRADIUS reads `<confdir>/dictionary` after its own: with the
  four lines (VENDOR, BEGIN-VENDOR, ATTRIBUTE WTI-Super, END-VENDOR) in a
  file of that name in the directory given with `-d`, the same check passes.
  In the real raddb that file is the package's (`/etc/raddb/dictionary`,
  `/etc/freeradius/3.0/dictionary`: a configuration file of `freeradius` /
  `freeradius-config`), which tacctl does not edit.
- **[C]** `-D <dir>` makes the daemon read `<dir>/dictionary` instead of
  `/usr/share/freeradius/dictionary`: a file there that includes the
  package's main dictionary by absolute path and then defines the vendor
  passes the check too (3.0.20). This is the way that leaves every package
  file alone; it changes the unit's command line (the drop-in) and the
  command of the config check.
- **[C]** Since: the `-D` way on 3.0.27 and 3.2.5 as well, with a started
  daemon, Access-Accepts that carry the attribute, and `radclient -D`
  decoding it (the cases above). The `<confdir>/dictionary` way was not
  pursued: that file is the package's.
