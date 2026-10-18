# Account lifecycle on a host

[Documentation](../README.md) › [Linux hosts](README.md)

tacctl manages an account on a host only when it created it (the host's `/var/lib/tacctl-client/created`) **and** its UID there is in the server's range. Every other account, whatever its name, is never created, expired, deleted or otherwise changed. The one exception is its membership of tacctl's groups (`tac-users`, `tac-readonly`, `tac-operator`, `tac-engineer`, `tac-superuser`, `tac-console`): it is taken out of them, so it is a plain local account that is never sent to the server. Nothing else on it changes (UID, home, password, shell, expiry, full name). The host reports each one: `'<user>': removed from tacctl's groups (tac-users, tac-<tier>); it is a plain local account again.`

- **New user in the scope:** the install or sync creates the account.
- **Local account with the same name:** if the host already has an account named like a tacctl user that tacctl did not create, that user gets no account on that host, with a warning; the local account stays exactly as it is (an emergency login that does not depend on this server), and the rest of the install or sync goes on. A matching name does not prove it is the same person: rename the tacctl user, keep it off that host, or remove or rename the local account. The sync summary names such users: `web1: synced (4 users; 1 refused: carl).`
- **Disabled user** (`tacctl user disable`): the account is expired (no login, SSH keys included) and its files are kept; `tacctl user enable` and the next sync restore it.
- **Removed user** (no longer in the scope, or no longer a tacctl user): the account is deleted (`userdel`), and so is its own group, if an earlier release made one and it is now empty; its UID stays reserved on the server. Its home directory is deleted only when asked for: on a terminal, `host sync` and `host enroll` ask `Delete /home/<user> of removed user '<user>'? [y/N]` for each removed user (the list is read from the host's `getent passwd` over the same ssh connection before anything runs there); `--remove-home` deletes them without asking; with no terminal and no flag every home is kept. A kept home is moved out of reach of a later local account that gets the same UID: to `/home/.tacctl-removed/<user>-<YYYYmmdd-HHMMSS>` (`/home/.tacctl-removed` is root's, 0700; the moved tree is made `root:root` with `chown -hR`, never following a link, its top 0700), and the host prints `home kept: /home/.tacctl-removed/<user>-<time>`. A home is never deleted or moved when it is not a directory directly under `/home`, is or sits behind a symbolic link, is not owned by the account, or is also another account's home (`home kept in place: <home> (<reason>)`); one on another file system than `/home` stays in place too. A removed user who is still logged in cannot be deleted: the account is expired and deleted at the next sync.
- **Renamed user** (`tacctl user rename`): the ledger line `linux-uids`
  moves to the new name, so the user keeps its UID. The next `host sync`
  renames the account on each host by that UID alone, with nothing stored:
  a listed or disabled user with no account whose UID belongs to an
  account tacctl created under a name no longer listed is that account
  renamed (`usermod -l`, the login name only). The home directory keeps its
  path (`/home/Alice` stays), the full name becomes `alice (TACACS+)`, and
  the `created` and `expired` lists follow; a disabled user's account stays
  expired. The host prints `'Alice' is now 'alice' (renamed; UID 80001; home
  kept at /home/Alice)`, `host show` lists the account under Updated, and
  `host sync` does not ask whether to delete the home of `Alice`. A host
  that was offline, synced later or saw two renames ends the same, and so
  does a host still on an earlier UID range (renamed at the number the user
  had there, renumbered by the same run). Files elsewhere (`/var/mail/Alice`,
  cron spools) stay under the old name. A user who is logged in (a process
  runs under the UID) is not renamed: `'Alice': not renamed to 'alice':
  processes run as UID 80001 (logged in?); tried again at the next sync`,
  both names are left untouched and the user is named as refused in the
  summary. A local account `alice` that tacctl did not create keeps `Alice`
  as it is (`'Alice' keeps its account: 'alice' is a local account here`).
  If `alice` was already created by tacctl with another UID, nothing is
  renamed and neither account is removed (`'Alice' keeps its account: its
  UID 80001 is assigned to 'alice' by the server; it is not removed here.`);
  the UID check reports the difference. Two users that swap names are not
  renamed either. After a rename, do not give the old name to a new user
  (`user add Alice`) before every host has synced the rename: the host's
  account `Alice` still holds the renamed user's number, so the UID check
  refuses the sync of that host; sync all hosts first. A script written with
  `config linux script` before 0.2.14 has no rename: it stops at the UID
  check (the number belongs to `Alice`) until it is written again; do not
  pass `--allow-uid-mismatch` to it, which would create `alice` at a free
  number and delete `Alice`.
- **Local accounts and tacctl's UID range:** local `useradd` on a host must not give out UIDs of the server's range, or a local account could take a number tacctl has given out. `host enroll` and `host sync` read the host's `/etc/login.defs` and warn when its `UID_MIN`-`UID_MAX` overlaps the range (the default `UID_MAX` 60000 does not overlap 80000-89999); keep it clear of the range there. tacctl never edits the file.
- **Accounts an earlier release adopted:** reported once (`Accounts an earlier tacctl adopted are no longer tracked`), taken out of tacctl's groups in that run, and not tracked after that.

`host unenroll` does not touch any account.
