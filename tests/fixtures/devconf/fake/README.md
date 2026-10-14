# Fake device transcripts

Directories for `tacctl _fake-device <dir>` (a test build's hidden verb,
`internal/devssh/fakedev`): the files a fake device answers from, in the
layout `internal/devssh/fakedev/transcript.go` describes. The bats files
(`tests/integration/device_config_*.bats`) copy one, add the read command's
output (`<command>.out`: the configuration tacctl renders for the device,
taken from `tacctl config <vendor>`, so the pull agrees with it, or edited to
differ) and, with `TACCTL_TEST_DEVICE_DIAL`, point `device config pull` at it.

- `junos/`: the prompt of a Junos CLI. Its read command is
  `show configuration | display inheritance no-comments | display set`; the
  plain view that `device config plan` compares it with (the same statements
  with the groups' inheritance not applied) is `show configuration | display
  set` (a device with no file for it is pulled all the same, with no plain
  view; `tests/helpers/fakedev.bash` `fakedev_serve` writes one that equals
  the inheritance view). `show chassis hardware.out` is the inventory a pull
  reads the model and serial number from, and `show version.out` the
  running release (a pull reads it before the configuration's `set version`
  statement); a device with neither file is pulled all the same, with no
  model or serial number, and the release of its `set version` statement.
- `ios/`: the prompt of an IOS CLI. Its read command is `show running-config`
  (`terminal length 0` needs no file); `show version | include Version.out` is
  the image's version line, which a pull keeps on the record and derives the
  configuration syntax from (a 15.x line: the modern syntax; remove the file for
  a device that answers none, or put an IOS 12.4 line in it for the IOS 12.x
  syntax; `tests/helpers/fakedev.bash` `fakedev_serve` does that for
  `FAKEDEV_IOS_SYNTAX=ios12` and `FAKEDEV_IOS_VERSION`). `show
  inventory.out` is the inventory a pull reads the model and serial number
  from (remove it for a device that refuses the command).

The login is the user who runs the verb (`SUDO_USER`) with the password of
`TACCTL_TEST_DEVICE_PASSWORD`: `_fake-device <dir> --user <name> --password
<text>` sets what it accepts.

## The Junos configure model (`junos-rollout/`)

A directory with a `config.set` is a Junos device with a configure model
(`internal/devssh/fakedev/junos_config*.go`, plan D142): the committed
configuration, a shared candidate, `configure`, `configure exclusive` and
`configure private`, `set`, `delete` and `insert`, `show | compare`, `commit
check`, `commit [confirmed N] [comment "..."]` with a timer, `rollback N`,
`show system commit`, `show system rollback compare A B`, `show cli
authorization`, `show version`. The model answers the read commands (`show
configuration [| display inheritance no-comments] | display set`) from the
committed configuration, over any `.out` file of the directory; every other
command is still answered from the directory's `<command>.out` files, so a
fixture adds `show chassis hardware.out` as above. `junos/` has no
`config.set` and is the 0.2.4 pull's device; `junos-rollout/` is the copy to
start a rollout test from (`tests/helpers/fakedev.bash` `fakedev_dir
junos-rollout`).

The files, all optional but `config.set`, and read when they are needed
(`config.set` and `dirty.shared` once, at the first session). A line that
starts with `#` is a comment. A *knob* is on when its file exists; the
fixture directory ships none, a test writes the ones it needs.

| File | Format and effect |
|---|---|
| `config.set` | the committed configuration, `set` lines (a bracket list is expanded) |
| `device` | `hostname <h>`, `model <m>`, `junos <release>`: `show version` when there is no `show version.out`; the committed `system host-name` names the prompt |
| `class` | `<class>` for every login, or `<user> <class>`; default `super-user`. `read-only`, `operator` and `unauthorized` cannot `configure` (`unknown command.`) |
| `local` | `<user> <password> [<class>]` per line: local accounts beside the server's login |
| `root` | the password of `root`, whose shell is a csh (`root@<host>% `): `cli` starts the CLI, and an exec of `sh -c '...; exec cli'` starts it at once; any other csh word is `<word>: Command not found.` |
| `switch` | the `{master:0}` line before every prompt of a virtual chassis: absent or empty is `{master:0}`, `off` none, `<role>:<n>` that |
| `banner` | text before the first prompt (it may look like a prompt) |
| `echo.plain` | the CLI echoes a command as typed, without the trailing space the device adds |
| `load.errors` | `<prefix> => <message>` (or a tab): a statement that begins with the prefix (verb and absolute path, `set system login idle-timeout`) prints the message and is not applied |
| `version-gate` | `<prefix>`: the statement answers a syntax error; `<prefix> => check`: it is accepted and `commit check` refuses it |
| `check.errors` | `<message>`: `commit check` and `commit` fail with it always; `<prefix> => <message>`: when the candidate adds a statement with the prefix |
| `exclusive.held-by` | a user that holds the exclusive lock (read at each command): `configure` and `configure exclusive` answer `error: configuration database locked by:` |
| `dirty.shared` | `set` lines staged in the shared candidate by a stranger (an optional first line `user <name>`): `configure` lists him, `configure exclusive` answers `error: configuration database modified` |
| `private.no-confirmed` | `commit confirmed` in a private session is refused (`commit confirmed not supported for private`) |
| `verify.fail` | while a confirmed commit is pending a new login is refused: `deny` (the default; authentication fails), `close` (accepted, then closed) or `hang` |
| `commit.drop` | the connection of the session that typed `commit confirmed` closes once the commit is applied and the timer runs: unanswered by default, `after-output` prints the answer first |
| `drop` | `<command prefix>` per line: that command closes the connection unanswered, before it is applied |
| `slow` | `<command prefix> => <seconds>` per line (`*` is every command): the answer waits that long on the server's clock |
| `timer.minute` | seconds one minute of `commit confirmed` lasts (default 60): a bats test sets `1` to see the expiry |

Behaviour a test relies on:

- The device keeps one shared candidate. A shared session's staged change
  stays when it exits; an exclusive session's goes with its lock (`exit` or a
  closed connection). A private session commits only its own difference.
- `commit confirmed N` starts a timer that restores the configuration it
  replaced when it expires, whether or not any session is open. Any `commit`
  confirms (`commit complete`), and so does a `commit check` from a session
  that can run it (the exclusive lock keeps every other session out). A
  `rollback 1` and `commit` cancel at once. Expiry is a commit of the device's
  own (`by root via other`).
- A confirmed commit's history entry says `commit confirmed, rollback in
  Nmins` for good; entry 0 with that text is a pending commit.
- A commit gives every login user without a `uid` the next one from 2000, so
  `show system rollback compare 1 0` has a `uid` line that the candidate's
  `show | compare` had not.
- A `secret` is stored as a deterministic `$9$` string and `show` marks it
  `## SECRET-DATA`; the same text set twice is no change.
- `committed.set` is written to the directory (or `WithStateDir`) when the
  model starts and after every commit and expiry: the observable
  configuration of the device. A bats test copies the fixture directory
  first, as `fakedev_dir` does.
- Time is the server's clock: `fakedev.WithClock(fakedev.NewFakeClock(t))` in
  a Go test, `Advance` moves it and runs the expiry; the verb uses the real
  time, with `timer.minute` to shorten a minute.
- Every text the model prints is a constant in `junos_config_texts.go`, marked
  `[S]` (plan), `[A]` (the helper's observed phrase), `[L]` (not yet seen on a
  device) or `[C]` (captured), so that the lab spike can correct them in one
  place.
