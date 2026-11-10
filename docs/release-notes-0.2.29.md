# tacctl 0.2.29

0.2.29 is a small release. A file uploaded through the console keeps its owner's execute bit,
a new user name is at most 32 characters and `config validate` warns of the longer names an
earlier release stored, and `tacctl ssh <device> --login <local-user>` opens a session as one
of a device's own accounts, which is the way in from the console while break-glass is held.
`tacctl rollback 0.2.28` is a target. The numbered list in `CHANGELOG.md` (0.2.29) is
everything that differs from 0.2.28.

## File transfer: a script keeps its execute bit

In 0.2.28 the console gave every new file the mode 0644 and ignored the mode the client asked
for, so a script copied with the `scp` of OpenSSH 9 or later lost its execute bit.

- **The mode of the open.** A new file now gets the mode the client asks for in the request
  that opens it, when that request carries the permissions alone, which is what the OpenSSH
  `sftp` and `scp` send. Only the permission bits count (set-user-ID, set-group-ID and sticky
  are ignored), reduced by the console's umask, 077: the owner's bits survive and the group
  and other bits go. A script asked at 0755 is 0700, a file asked at 0644 is 0600.
- **No mode asked.** A request without permissions, or that asks for no permission bits,
  still gives 0644, 0600 after the umask. A file that already exists keeps its mode, and a
  download changes nothing.
- **A read-only source.** A file asked at a mode without the owner's write bit (0444, or 0555,
  which `scp` sends for a read-only source) is created writable by its owner and gets the mode
  asked for, reduced by the umask, when the client closes the handle, since `scp` ends an
  upload by setting the size of the file. A change of the permissions before the close (by the
  client, a `chmod` in a shell, another session) is kept. An interrupted upload of a read-only
  source ends read-only (0400, say), and resuming it with `put -a` or `reput` is refused with
  permission denied, as it is by the OpenSSH server.
- **`scp -p`.** It sends the times together with the permissions in the open request, which is
  read as carrying none, so the file is created at 0644 (0600). `scp -p` then sets the
  permissions and times after the upload, which are applied as given, with no umask, so a
  script ends with the mode of its source, 0755.
- **Directories are unchanged.** The library does not deliver the mode of a request to make a
  directory, so a new directory is 0755, 0700 after the umask, whatever the client asks; a
  client that wants another mode sets it afterwards.

```bash
scp deploy.sh alice@tacacs.example.net:     # 0755 at the source, 0700 in the home
scp -p deploy.sh alice@tacacs.example.net:  # the mode of the source, 0755
```

The pages are `docs/cli/console.md` (The root is the home) and the manual page.

## User names of at most 32 characters

**A new user name is at most 32 characters**, the longest a Linux account name can be. Before,
`user add` took any length, so a longer name became a tacctl user with no account on the
tacctl server or on a host. `user add` and the new name of `user rename` now refuse a longer
name, change nothing and exit 1:

```text
Username 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' is 33 characters; a user name is at most 32 (the longest a Linux account name can be).
```

A name of exactly 32 is accepted. Only a new name is checked: a user an earlier release
stored with a longer name keeps working (it is shown, changed, renamed away to a shorter name
and removed as before), and `backup restore` and `tacctl upgrade` carry it unchanged. It still
has no Linux account, so it gets none at a sync. `store import` loads it as it is and prints
one line that counts such names. Rename it with `tacctl user rename <name> <shorter name>`.

**`config validate` warns of such a user** under `Names:`, as it does of a name with upper
case, and names the rename that fixes it. It is a warning, never an error; `config validate
--json` has it under `names`, and `--fix-names` does not offer it, since there is no name to
propose. A user whose name is also in upper case gets this one warning only. It is the
superuser's view only.

The length is not the only reason a user has no account: a name with upper case letters, and a
name that starts with a digit or `-` (`1alice`), which `user add` still accepts, have none
either. The pages are `docs/cli/user.md`, `docs/cli/config.md` and `docs/install/upgrading.md`.

## A session as a device's local account

In the console the words after `--` are the remote command and ssh's `-l admin` is refused, and
while break-glass is held on a device only its local accounts work, so there was no way to
open a session as `admin` from the console. `tacctl ssh` (and `tacctl device ssh`, the same
command) now takes `--login <local-user>`:

```bash
tacctl ssh sw1 --login admin
```

- It runs ssh as you, as before, with `-l <local-user>` in place of your name, for registered
  devices of any vendor. An enrolled host is refused (hosts are reached as you) and nothing is
  started.
- The device must have a pinned host key, since a local password goes only to a device whose
  key was verified: without one the line is refused and names `tacctl device hostkey <name>
  accept`. With one, ssh checks the key strictly against the pin.
- It needs the engineer tier or above, as the other `--login` verbs do, and the device must be
  in one of your scopes. A session as you stays every tier's. The name is letters, digits,
  `.`, `_` and `-`.
- The device asks for the account's password at its own prompt. tacctl never asks for it,
  caches it or stores it, and the password cache of the shell and the console is not used for
  the line.
- The session's `ssh` and `ssh end` audit lines carry `login=<local-user>` after the device and
  address fields and have no `password=` field; a plain session's lines are unchanged. On a
  device with break-glass held the warning says `you log in as its local account
  '<local-user>'` and the session goes on.

The pages are `docs/devices/connecting.md`, `docs/devices/break-glass.md`, `docs/cli/device.md`,
`docs/cli/console.md` and the manual page.

## Rollback

**`tacctl rollback 0.2.28`, the release before this one, is a target.** No change of 0.2.29
writes a stored file in a form 0.2.28 does not read, so the rollback converts no file, removes
no key and no field, takes no snapshot and needs no `--yes`. The file transfer settings of
`console.yaml` stay, as do the report limits, the chassis members of the pull records, the
reports in the users' homes and the per-tier sudoers drop-in. It is refused only while a
device's apply is not settled, and it ends with `tacctl upgrade --branch 0.2.28`, with no
closing note. After that upgrade a new uploaded file is 0644 (0600) again whatever the client
asks; the files uploaded in between keep their mode. `rollback 0.2.27` and older behave as
before, and `tacctl rollback` now takes fifteen targets.

```bash
tacctl rollback 0.2.28          # the dry run: steps, writes nothing
tacctl rollback 0.2.28 --apply
tacctl upgrade --branch 0.2.28
```

## Upgrading

`tacctl upgrade` converts nothing in this release. A user whose name is longer than 32
characters is carried unchanged; `tacctl config validate` lists it.
