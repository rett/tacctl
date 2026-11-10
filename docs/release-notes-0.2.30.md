# tacctl 0.2.30

0.2.30 is a small release. A new user name now starts with a lower-case letter, so that every
new user has a Linux account; the commands that write a file as you check its path as you, which
makes them work in a home on an NFS `root_squash` export; and a file uploaded with `scp -p` is
created with the mode of its source. `tacctl rollback 0.2.29` is a target. The numbered list in
`CHANGELOG.md` (0.2.30) is everything that differs from 0.2.29.

## User names start with a letter

Every new user gets a Linux account, on the tacctl server and on the enrolled hosts, and a name
that starts with a digit or `-` is no account name. `user add` and the new name of `user rename`
now refuse a first character that is not a lower-case letter, a to z, change nothing and exit
1:

```text
Username '1alice' must start with a letter (a to z): every new user gets a Linux account, and a name that starts with a digit or '-' is no account name (a new name does not start with '_' either).
```

A new name is now a lower-case letter, then lower-case letters, digits, `_` and `-`, at most 32
characters. A leading `_` is refused too, although Linux would take it, so that every new name
is an account name everywhere.

- **The first check that fails is the answer.** The checks run in a fixed order: the shape (no
  period), the reserved names, upper case, the length, the first character. A name with upper
  case is told its lower-case spelling (`Names are lower case: use 'alice'.`) only when that
  spelling passes every other check, so the suggestion is always a name the command takes. For
  a name such as `1Alice` or `_Alice` the answer is the check its lower-case spelling fails,
  said with the name as typed and with the lower case among what to fix (`Username '1Alice'
  must be lower case and start with a letter (a to z): ...`).
- **Existing users are unaffected.** Only a new name is checked. A user that exists as `9dave`,
  `_svc` or `-x` keeps working: it is shown, changed, renamed away, removed and restored as
  before, and `tacctl upgrade` and `backup restore` carry it unchanged. A user stored as `-x`
  is reached by the verbs as a bare word (`tacctl user show -x`).
- **`config validate` warns once per user whose name has no Linux account.** Under `Names:` it
  warns of a user whose name starts with a digit or `-` and names `tacctl user rename <name>
  <new-name>`. A name that starts with `_` has an account and gets no warning, unless it is
  also longer than 32 characters. A user gets one warning, whatever else is wrong with the name.
- **`--fix-names` never offers a refused rename.** `config validate --fix-names` offers the
  rename to the lower-case spelling of a name with upper case only when that spelling would
  pass every rule of a new name. For `1Alice` or a name over 32 characters it offers nothing,
  the warning names the rename to a name of your choice, and the run counts nothing as not
  offered or failed for it and exits 0.

```bash
tacctl user add alice ops-rw
tacctl user rename 9dave dave
tacctl config validate
```

The pages are `docs/cli/user.md` (`user add`, `user rename`, A new name starts with a letter),
`docs/cli/config.md`, `docs/install/upgrading.md` and the manual page.

## Writing a file from a home on an NFS `root_squash` export

On an NFS export with `root_squash`, root is mapped to an unprivileged account, and a home that
others may not search (0700, 0750) is out of its reach. This release documents what that does to
the commands that write a file, and fixes it for three of them.

- **The three commands that write as you check the path as you.** `device config plan
  --out|--out-dir`, `device reports export --out` and `device support-bundle` write as the
  person who ran `sudo`, but their check of the path (inside the home, links resolved) ran as
  root, so in such a home it refused the path with `cannot be resolved (Permission denied)`
  although the write, as you, would work. The check now runs as you, and the other rules are
  unchanged.
- **A path that cannot be resolved is not told to be spelled differently.** A refusal that says
  `cannot be resolved (<cause>)` (permission denied, a link that leads nowhere) now gives the
  cause and the path and no longer ends with `tacctl does not expand ~ or variables; name a
  path inside your home, relative to the current directory`. That sentence is about the
  spelling of the path and stays on the other refusals: an empty path, a NUL, a `$` or
  backtick, a `~`, a path outside the home.
- **The two commands that write as root are unchanged.** `config render --dry-run` and `config
  linux script|remove-script` still check the path as root. A home that others may not search
  is refused by the check (`cannot be resolved (Permission denied)`); in one that others may
  search they write nothing, leave no half-made file and say `Permission denied` with the path.
  Write the file on the local disk of the host and copy it to the home as yourself. Tests pin
  both cases.

The pages are `docs/cli/conventions.md` (Paths you name to write) and the manual page.

## File transfer: `scp -p` creates the file with its mode

In 0.2.29 a script uploaded with `scp -p` was created 0644 (0600 after the console's umask,
077) and got its mode only from the permissions that follow the data. The `scp` of OpenSSH 9 or
later sends the permissions together with the times in the request that opens the file (twelve
bytes of attributes), and the console read only four bytes of them. The console now reads the
attribute flags of the open request itself, so the permissions are found whatever else the
request carries (the times, a size, an owner), and a size is never read as a mode.

- **The mode at creation.** A new file is created with the permission bits asked for, reduced
  by the umask as before: a script asked at 0755 is 0700 from the start, and an upload of
  `scp -p` that is interrupted leaves that mode and not 0600.
- **Unchanged.** A request without permissions, or that asks for no permission bit, still gives
  0644 (0600). A file that exists keeps its mode, and the mode and the times the client sets at
  the end are applied as given, with no umask, so `scp -p` still ends with the mode of its
  source.

```bash
scp -p deploy.sh alice@tacacs.example.net:  # created 0700, ends 0755
```

The pages are `docs/cli/console.md` (file transfer) and the manual page.

## Rollback

**`tacctl rollback 0.2.29`, the release before this one, is a target.** This release changed no
stored file 0.2.29 reads strictly, so the rollback converts no file, removes no key and no
field, takes no snapshot and needs no `--yes`. The file transfer settings of `console.yaml`
stay, as do the report limits, the chassis members of the pull records, the reports in the
users' homes and the per-tier sudoers drop-in, and so does every user, whatever the name. It is
refused only while a device's apply is not settled, and it ends with `tacctl upgrade --branch
0.2.29`, with no closing note. After that upgrade `user add` and `user rename` take a new name
that starts with a digit, `-` or `_` again, the three commands above check the path as root
again, and a file uploaded with `scp -p` is created 0644 (0600) again; what was done in between
keeps its name and its mode. `rollback 0.2.28` and older behave as before, and `tacctl
rollback` now takes sixteen targets.

```bash
tacctl rollback 0.2.29          # the dry run: steps, writes nothing
tacctl rollback 0.2.29 --apply
tacctl upgrade --branch 0.2.29
```

The pages are `docs/cli/conventions.md`, `docs/install/upgrading.md` (Rolling back, To 0.2.29)
and the manual page.

## Upgrading

`tacctl upgrade` converts nothing in this release. A user whose name starts with a digit or `-`
is carried unchanged; `tacctl config validate` lists it.
