# UIDs, GIDs and groups

[Documentation](../README.md) › [Linux hosts](README.md)

## Consistent UIDs and GIDs
Each user gets one number, its UID on every host this server enrolls (its primary group is `tac-users`). It is assigned the first time the user is sent to a host, from the server's range only, **80000-89999** unless changed (after the highest one given so far, never into a gap), and stored in `/etc/tacctl/linux-uids`. The default range is clear of what else hands out numbers on a Linux host: above the distributions' `useradd` range (`UID_MAX 60000` on Debian, Ubuntu and the RHEL family) and systemd's reserved numbers (60001-60513, 61184-65519, 65534/65535), inside the range systemd leaves unused (65536-524287), and below the usual start of `/etc/subuid` (100000). A number is never reused: a removed user's entry stays in the file, so a later user never inherits its files on a host. The file is keyed by name: a renamed user (`user rename`, also `Alice` to `alice`) gets a number of its own at its first sync, and the old name keeps its number. When the range is used up, the next user is refused with `No UID left for '<user>'` until it is given a free number of the range by hand.
```
tacctl config linux uid                  # list assignments
tacctl config linux uid jsmith           # print one
tacctl config linux uid jsmith 80500     # change it (within the range only)
tacctl config linux uid-range            # show the range
tacctl config linux uid-range 100000-109999   # change it, for all hosts
```
An entry outside the range is listed as `outside 80000-89999: not used on hosts`, and its user gets no account on any host until it is given a number in the range.

**Another range.** `config linux uid-range <min>-<max>` sets `linux.uid_min` and `linux.uid_max` in `tacctl.yaml`; one range serves all hosts. A range must hold at least 1000 numbers, start at 1000 or above, and stay clear of systemd's reserved numbers (60001-60513, 61184-65519, 65534-65535, and 524288 and up); one that overlaps `useradd`'s default 1000-60000 is accepted with a warning, since every host's `/etc/login.defs` must then keep clear of it. A change moves every entry of `linux-uids` by the offset between the two starts (80005 becomes 100005), as the move from 20000-29999 does, and the next enroll or sync moves each host's accounts the same way. It is refused, nothing changed, when the new range overlaps one the file was numbered for (hosts may still have accounts there), when an entry would land past its end, or when a number is already another name's. A range grown or shrunk at the same start moves nothing. The file records its range on its first line (`# range 80000-89999`) and the earlier ones (`# previous 20000-29999`), so a backup or a copy to another server carries its numbers and their range together; a range set by hand in `tacctl.yaml` is applied, the same way, by the next command that reads the file.

**Hosts that cannot hold the range.** An unprivileged container (rootless podman, an LXC/LXD container) sees only the IDs its user namespace maps, usually 0-65535: `useradd` there accepts a larger UID, but the account cannot log in. Before anything runs on a host, `host enroll` and `host sync` read its `/proc/self/uid_map` and `gid_map` (this server's own for `--local`) and refuse a host that cannot hold the whole range: `'<host>' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535 (an unprivileged container).` Give the container an ID map that covers the range, run it privileged, or choose a range all hosts can hold. `host target` warns about such a host.

**Numbers in 20000-29999** (the range of 0.2.0 and earlier) move once to the same offset in the range (20005 becomes 80005). On the server, the first `config linux uid`, `config linux script`, `host enroll` or `host sync` that finds such entries in `linux-uids` rewrites them all (users and removed users), keeps the old file as `linux-uids.pre-renumber-<UTC time>` and logs `uid-map renumbered <n> entries`; it refuses, changing nothing, when a new number is already another name's (`config linux uid <other> <uid>` resolves it). On each host, the next enroll or sync renumbers the accounts tacctl created there with a UID in 20000-29999: the UID (`usermod -u`, which re-owns the home directory tree), reported as `'<user>': renumbered <old> -> <new> (home re-owned)` and counted in the summary (`web1: synced (3 users; 1 renumbered).`). Files outside the home that still carry the old number (under `/home`, `/tmp`, `/var/tmp`, `/var/spool/cron`, `/var/mail`; at most 20 listed) are reported and left as they are. An account whose user is logged in, or whose new UID is taken on the host, is left exactly as it is and named as refused until a later sync can renumber it. Accounts in 20000-29999 that tacctl did not create are not touched.

If the number is already taken on a host by another account, the install or sync **stops before changing anything** and lists the options (GIDs do not matter: tacctl's accounts have no group of their own):
1. free the number on the host by renumbering the account that holds it (`usermod -u`, then `chown` its files);
2. assign the tacctl user another free number of the range (`tacctl config linux uid <user> <uid>`) and re-run;
3. accept a different number on that host only: `tacctl host enroll|sync ... --allow-uid-mismatch`, which takes the highest number of the range that is free there.

An account tacctl created whose UID on a host differs from the assignment (but is in the range) is kept as it is; every sync reports the difference and how to fix it. Changing an assignment does not renumber accounts already created on hosts. Two tacctl servers assign independently, so copy `linux-uids` between them if their hosts must agree.

## tacctl's groups
Each of tacctl's groups has a fixed GID, the same on every host: the first numbers of the UID range (80000-89999 by default; they follow `config linux uid-range`). A host has only the groups it uses:

| Group | GID | Where | Used for |
|---|---|---|---|
| `tac-users` | 80000 | every host | primary group of every account tacctl manages; PAM sends only its members to the server; the server's tier check |
| `tac-console` | 80001 | the tacctl server | sshd's login-console drop-in |
| `tac-superuser` | 80002 | every host | `%tac-superuser` sudo (and the tiers sudoers on the server) |
| `tac-operator` | 80003 | the tacctl server | its tiers sudoers |
| `tac-readonly` | 80004 | the tacctl server | its tiers sudoers |
| `tac-engineer` | 80005 | every host | `%tac-engineer` sudo on hosts other than the tacctl server (`config linux engineer-sudo`); on the server, its tiers sudoers only |

Accounts have no group of their own; with a shared primary group, each home is made 0700 when the account is created or moved. The first enroll or sync of an existing host moves what an earlier release made, once: each managed account's primary group becomes `tac-users` (`usermod -g` re-groups the files in its home) and its own group is removed when it has no members; each group moves to its fixed GID (`groupmod -g`; files in the managed homes that carried `tac-users`' old number follow it); on a host other than the tacctl server, `tac-readonly`, `tac-operator` and `tac-console` are removed when only tacctl's accounts are in them (otherwise kept, and said). A fixed GID that another group already holds on the host is left to it: tacctl's group keeps or gets another number, with a warning (`Group 'tac-users' keeps GID 1001, not 80000: GID 80000 belongs to group '<other>' here.`).
