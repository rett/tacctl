# Login for Linux hosts

[Documentation](../README.md)

Linux hosts log in against this server by one of two methods. Accounts, tiers, sudo and the fallback to local passwords are the same for both; the PAM module differs:

| Method | PAM module | Backend | Where the module comes from |
|---|---|---|---|
| `tacplus` (default) | `pam_tacplus` | TACACS+ | Built by tacctl from the pinned v1.7.0 source (verified by commit hash; no distribution packages a usable build and upstream is archived): in a container on the server for `tacctl host enroll`, on the host when the install script is run by hand |
| `radius` | `pam_radius_auth` | RADIUS (`tacctl backend enable radius` first) | The host's distribution package: `libpam-radius-auth` on Debian/Ubuntu; `pam_radius` from EPEL on the RHEL family, enabling EPEL (`epel-release`) when the host does not have it |

```
tacctl config linux build                                  # once, on the server: prepare the
                                                           # pam_tacplus source tarball
tacctl config linux script --scope prod -o enroll.sh       # install script for hosts in a scope
tacctl config linux script --scope prod --method radius -o enroll.sh
tacctl config linux remove-script -o unenroll.sh           # removal script (no secrets; removes
                                                           # either method)
```
The server's port in the script is the configured listener's (`tacctl server listen`; the default listener's, 49, for `tacplus`, and the `auth` listener's, 1812, for `radius`, whose accounting port is the `acct` listener's, 1813): the `server=<address>:<port>` of `pam_tacplus` and the port of `pam_radius_auth`'s server file are written from it, and `config linux script` prints it (`Server: <address> port <n>`). `host enroll` (`--local` for this server) writes the same value. A host keeps the port it was enrolled with until its install script is run again in full: `--accounts-only` and `host sync` sync accounts and leave the PAM configuration alone.

Copy the install script to the host and run it as root from a session you keep open. It:
- installs the PAM module before creating any account (`tacplus`: builds and installs `pam_tacplus`, installing `gcc`, `make` and `libpam0g-dev` with apt if missing, and leaving a host that already has the module from the same source alone; `radius`: installs the package, and stops before any account or PAM change when it cannot);
- creates a local account for each user in the scope, with a locked password, a UID that is the same on every host (80000-89999), `tac-users` as primary group and a 0700 home; superusers are also in `tac-superuser` (see [tacctl's groups](ids-and-groups.md#tacctls-groups));
- deletes the accounts it created for users who are no longer in the scope (see [Account lifecycle on a host](account-lifecycle.md#account-lifecycle-on-a-host));
- sends `sshd`, `sudo` (including `sudo -i`), console `login` and the graphical logins `sddm` and `gdm-password` (where present) to the server for members of `tac-users` only (the shared `common-*` files, or `system-auth`/`password-auth` on the RHEL family, and every other local account are untouched);
- grants `%tac-superuser` full sudo, authenticated with the network password.

A reject from the server is final. If the server is unreachable, login falls through to the local password, which tacctl's accounts do not have; local administrators and every other local account (not in `tac-users`) are never sent to the server and see no delay. With the server silent, a tacctl user is refused after 5-6 s (`tacplus`) or 8-9 s (`radius`; see [RADIUS notes](../radius-notes.md)). A wrong shared secret on the host behaves like a silent server. The script refuses to run unless a local administrator with a usable password exists outside the user list, and restores the PAM files if any step fails. Re-run it with `--accounts-only` after adding, removing or moving users.

The install script contains the scope's shared secret, and so do the root-only files it writes (`/etc/pam.d/tacctl-*` for `tacplus`; `/etc/tacctl-pam_radius.conf`, 0600, for `radius`): use a dedicated scope per host or host group, and keep TACACS+ and RADIUS traffic on a management network or tunnel (no Linux PAM client supports TACACS+ over TLS). `passwd` does not work for these users; they change passwords with `tacctl passwd` on the server.

`radius` specifics: PAP only; the host reads no vendor attribute, so a scope of Linux hosts needs none enabled. The module is given `client_id=<the host's fully qualified name>` (`hostname -f`), so its NAS-Identifier names the host; without it pam_radius_auth sends the PAM service's name (`sshd`, `sudo`) and `device scan` sees the host change name with every service. A host enrolled before 0.2.1 keeps sending the service's name until it is enrolled again (its `name-mismatch` notice says so). A host enrolled with pam_tacplus sends no NAS-Identifier, and a name recorded from an earlier RADIUS enrolment raises no notice. Session accounting is sent only where the module gets it right: it always goes to the authentication port plus one, so the RADIUS `acct` listener must be on that port (the configured `acct` listener's; 1813 by default), and it is left out on Ubuntu 24.04, whose pam_radius_auth 2.0.1 sends malformed accounting records. Logins are in the server's auth log either way. **BlastRADIUS (CVE-2024-3596):** pam_radius_auth 2.0.x on **Ubuntu 24.04 and Debian 12** neither sends nor checks Message-Authenticator; Debian 13 and the RHEL family (EL8/9 backported, EL10) do, and tacctl adds `require_message_authenticator` where the installed module has the option. Treat RADIUS from Ubuntu 24.04 and Debian 12 hosts as forgeable on an untrusted path; FreeRADIUS logs a "BlastRADIUS check" block for such clients.

Graphical login: SDDM and GDM authenticate these users, and GNOME's lock screen unlocks through GDM. The user's keyring or wallet is not unlocked automatically. KDE Plasma's lock screen checks passwords as the logged-in user and so cannot read the root-only secret; on a Plasma host the install script switches screen locking off for the accounts it created (automatic lock, lock on resume and the Lock action), from their next login. Local accounts keep theirs. The settings live in `/etc/xdg/tacctl` and `/etc/xdg/plasma-workspace/env/tacctl-nolock.sh`, and unenrolling removes them. A session that gets locked anyway (`loginctl lock-session`) is unlocked from another login with `loginctl unlock-sessions`. Accounts are created with the full name `<login> (TACACS+)` or `<login> (RADIUS)`, which is what login screens list.

Debian, Ubuntu and their derivatives are supported, and so is the RHEL family (RHEL, AlmaLinux, Rocky, CentOS Stream, Oracle Linux). Both methods are tested on Ubuntu 24.04, Debian 12 and 13, and AlmaLinux and Rocky 8, 9 and 10. On RHEL-family hosts the script adds an `include` line in front of the service's `password-auth`/`system-auth` line instead of replacing a Debian `@include`, leaves the authselect-managed files alone, uses `dnf`, and, when SELinux is enabled, installs a small policy module (`tacctl_pam`, which labels the TACACS+ port and lets `sshd`, `login` and `sudo` connect to it; `tacctl_pam_radius` for RADIUS). SELinux in enforcing mode is not verified for either method.

The removal script undoes the PAM edits and deletes the secret, module, SELinux policy module, sudoers drop-in and sshd's lockdown drop-in (below) of either method (packages stay installed). Accounts, home directories and the `tac-*` groups stay; it lists any account left with neither a local password nor an SSH key.

**Emergency lockdown on a host.** While the host's scope is locked down
(`emergency lockdown`), `host enroll` and `host sync` write one sshd drop-in,
`/etc/ssh/sshd_config.d/00-tacctl-0-lockdown.conf`, and remove it when the
scope is not locked down. It holds `Match Group tac-users,!tac-superuser` with
`PubkeyAuthentication no`, `AllowTcpForwarding no`,
`AllowStreamLocalForwarding no`, `X11Forwarding no` and
`AllowAgentForwarding no`: no account of a tier that is not a superuser's logs
in with a key or forwards a port, whichever groups the lockdown names (the
host knows tiers, not the store's groups). Superusers, root and the
provisioning login, which is in no `tac-*` group, are not matched. The name
sorts before `00-tacctl-engineer.conf` and the console's drop-in, so its
values are the first sshd takes.

The script checks the file before sshd reads it: `sshd -t`, then `sshd -T -C
user=<account>,...,laddr=127.0.0.1,lport=22` for an account the file matches
(the five keywords must be `no`) and for one it does not (sshd's answer must be
what it was before). A check that fails puts the old file back and fails the
run, and so does a `sshd -T` that fails itself (its first line is shown). sshd
is reloaded (`systemctl reload`, or a SIGHUP to the process in
`/run/sshd.pid` where there is no systemd), never restarted, and `restorecon`
runs on the file. `/var/lib/tacctl-client/lockdown` says what the running sshd
may enforce (`on` once the file is loaded, `off` while a lift is under way): a
reload that fails fails the run and the next sync tries it again, even when the
file is already gone. A host whose `/etc/ssh/sshd_config` does not include
`sshd_config.d` (RHEL 8, OpenSSH before 8.2) is refused before anything
changes: the file would be ignored and the host would only look locked down.
A host provisioned through a tacctl account that is not a superuser's is
refused too, with the account named: the lockdown would close its key (the
check is made again right before the file is written, since the sync in between
can make the account a member, and not for the server's own script, which runs
locally and loses no login). At the step that begins a lockdown the
script also ends the live sessions of the accounts the file matches
(`loginctl terminate-user`, else their processes), never root, a superuser,
the provisioning login, the account the script runs from or any account under
UID 1000. The script's
header says which state the host gets in `TAC_LOCKDOWN` (client script
protocol 7).

`emergency lockdown enable|disable` offers the sync that does this for the
scope's hosts, and a host that is unreachable, held or refused stays on the
lockdown's `pending` list until a later `host sync` completes it (see
[Emergency commands](../cli/emergency.md)). A host enrolled or synced while the
lockdown stands gets the file; one synced after the lockdown is lifted loses
it.

## Pages

- [Enrolling hosts over SSH](enrolling.md): Enrolling, syncing and removing hosts.
- [Where the module is built (`tacplus`)](module-build.md): Where the pam_tacplus module is built.
- [UIDs, GIDs and groups](ids-and-groups.md): Consistent UIDs and GIDs and the groups tacctl creates.
- [Account lifecycle on a host](account-lifecycle.md): Account creation, change and removal on a host.
