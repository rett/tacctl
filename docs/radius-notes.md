# RADIUS backend: what was checked against real FreeRADIUS

The design is in the header of `lib/backends/radius.sh`. This file records
what that design rests on: what was run against real FreeRADIUS, on which
versions, with what result, and what was not verified. It replaces the
assumptions marked [A] in `docs/plans/pluggable-backends.md` §5 and answers
§9 items 1-3 and (partly) 7.

Everything below was run on 2026-10-02 in rootless podman 4.9.3 containers
with `tests/containers/radius/run.sh` (procedure: `tests/README.md`, "RADIUS
in containers"), against the renderer as it is in this tree.

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
   `attr_filter.access_reject`). tacctl's policy removes its three.
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

Store: `tests/containers/radius/make-store.py`. 23 cases, all pass on all
three. Sources are told apart by address (`Packet-Src-IP-Address` in the
radclient request file; the container's own address for scope `prod`).

| Case | Result |
|---|---|
| right password, user in the client's scope | Access-Accept, `Service-Type = Administrative-User`, `Cisco-AVPair = "shell:priv-lvl=15"`, `Juniper-Local-User-Name = "RW-CLASS"` |
| operator / custom group (priv 10) / readonly | Accept with `NAS-Prompt-User`, `priv-lvl=7` / `10` / `1`, the group's class |
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

With systemd (Ubuntu noble, AlmaLinux 9; `flow.sh`, 47 and 45 checks, all passing):
package install by `backend enable`, daemon running as the service account
under the distro unit with the drop-in, artifacts 0640 `root:<group>` and
unreadable to others, package files unmodified (`dpkg --verify` /
`rpm -V`), `user disable|enable` and `scope protocols` reaching the daemon,
an unrenderable secret refused with the store unchanged, a udp6 listener
added and removed, an unbindable listener address rolled back, drift
refusal and `config render --force`, `systemctl reload`, `backend disable`
(unit stopped, disabled, drop-in gone, package unit as shipped), re-enable
without the package manager, the uninstall phases. On Ubuntu also: after
`disable` the package's own configuration starts under the unit, and
`enable` is then refused and leaves it running.

## Not verified

- **Real devices.** That Cisco IOS/IOS-XE honours `Cisco-AVPair =
  "shell:priv-lvl=N"` with `Service-Type` 6/7 for exec authorization and that
  Junos maps `Juniper-Local-User-Name` to a template user is documented
  vendor behaviour, not tested here. `Service-Type = Administrative-User`
  for priv 15 and `NAS-Prompt-User` otherwise is a choice.
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
