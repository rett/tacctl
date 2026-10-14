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

## The Junos configure model (`junos-apply/`)

A directory with a `config.set` is a Junos device with a configure model
(`internal/devssh/fakedev/junos_config*.go`, plan D142): the committed
configuration, a shared candidate, `configure`, `configure exclusive` and
`configure private`, `set`, `delete` and `insert`, `show | compare`, `commit
check`, `commit [confirmed N] [comment "..."]` with a timer, `rollback N`,
`show system commit`, `show configuration | compare rollback N`, `show cli
authorization`, `show version`. The model answers the read commands (`show
configuration [| display inheritance no-comments] | display set`) from the
committed configuration, over any `.out` file of the directory; every other
command is still answered from the directory's `<command>.out` files, so a
fixture adds `show chassis hardware.out` as above. `junos/` has no
`config.set` and is the 0.2.4 pull's device; `junos-apply/` is the copy to
start an apply test from (`tests/helpers/fakedev.bash` `fakedev_dir
junos-apply`). `junos-blank/` is a device with no TACACS+ or RADIUS server,
a local account (`local`: `admin`), a root login (`root`) and alice's
TACACS+ template user (`template`), for `device onboard`, `device collect`
and `--login` (`tests/integration/device_onboard.bats`, `device_collect.bats`,
`device_sync.bats`, `device_config_login.bats`);
`TACCTL_TEST_LOCAL_PASSWORD` is the password tacctl logs in with as the
local account.

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
| `template` | `<user> <template> <class>` per line: that login is a TACACS+ one mapped to a local template user; `show cli authorization` prints `Current user: '<template>' login: '<user>' class '<class>'` |
| `root` | the password of `root`, whose shell is a csh (`root@<host>% `): `cli` starts the CLI, and an exec of `sh -c '...; exec cli'` starts it at once; any other csh word is `<word>: Command not found.` |
| `switch` | the `{master:0}` line before every prompt of a virtual chassis: absent or empty is `{master:0}`, `off` none, `<role>:<n>` that |
| `banner` | text before the first prompt (it may look like a prompt) |
| `echo.plain` | the CLI echoes a command as typed, without the trailing space the device adds; an empty line echoes nothing either way |
| `load.errors` | `<prefix> => <message>` (or a tab): a statement that begins with the prefix (verb and absolute path, `set system login idle-timeout`) prints the message and is not applied |
| `version-gate` | `<prefix>`: the statement answers a syntax error; `<prefix> => check`: it is accepted and `commit check` refuses it |
| `check.errors` | `<message>`: `commit check` and `commit` fail with it always; `<prefix> => <message>`: when the candidate adds a statement with the prefix |
| `exclusive.held-by` | a user that holds the exclusive lock (read at each command): `configure exclusive` answers `error: configuration database locked by:` and the holder's lines; `configure` enters and lists him as an exclusive editor |
| `dirty.shared` | `set` lines staged in the shared candidate by a stranger (an optional first line `user <name>`): `configure` lists him, `configure exclusive` answers `error: configuration database modified` |
| `verify.fail` | while a confirmed commit is pending a new login is refused: `deny` (the default; authentication fails), `close` (accepted, then closed) or `hang` |
| `commit.drop` | the connection of the session that typed `commit confirmed` closes once the commit is applied and the timer runs: unanswered by default, `after-output` prints the answer first |
| `drop` | `<command prefix>` per line: that command closes the connection unanswered, before it is applied |
| `slow` | `<command prefix> => <seconds>` per line (`*` is every command): the answer waits that long on the server's clock |
| `rescue` | a saved rescue configuration: `show system commit` ends with the line `rescue  <time> <zone> by root via cli`, which is no entry |
| `timer.minute` | seconds one minute of `commit confirmed` lasts (default 60): a bats test sets `1` to see the expiry |

Behaviour a test relies on:

- The device keeps one shared candidate. A shared session's staged change
  stays when it exits; an exclusive session's goes with its lock (`exit` or a
  closed connection). A private session commits only its own difference and
  refuses `commit confirmed` (`error: commit confirmed not supported for
  private configuration`). Under another session's exclusive lock `configure
  exclusive` is refused, `configure` and `configure private` enter (the
  latter with a warning), and neither can change or commit.
- `configure exclusive` answers `warning: uncommitted changes will be
  discarded on exit` before `Entering configuration mode`; every commit
  prints `configuration check succeeds` first, and `commit confirmed N` then
  `commit confirmed will be automatically rolled back in N minutes unless
  confirmed` (`1 minutes` for 1) and `commit complete`.
- `commit confirmed N` starts a timer that restores the configuration it
  replaced when it expires, whether or not any session is open. While it is
  pending, every session's prompt has the line `# commit confirmed will be
  rolled back in N minutes` (`1 minute`; the minutes left, rounded up)
  before its `{master:0}` / `[edit]` line: that line is the pending marker.
  Any `commit` confirms; a `commit check` from a session that can run it
  confirms too and leaves no history entry (the exclusive lock keeps every
  other session out). A `rollback 1` (`load complete`) and `commit` cancel
  at once with a normal entry. Expiry is a commit of the device's own (`by
  root via other`).
- A confirmed commit's history entry says `commit confirmed, rollback in
  Nmins` for good, also after a check confirmed it: it is not a pending
  marker.
- A commit gives every login user without a `uid` the next one from 2000, so
  `show configuration | compare rollback 1` has a `uid` line that the
  candidate's `show | compare` had not. `show system rollback compare` is
  not a command.
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
  device) or `[C]` (captured, `tests/fixtures/devconf/juniper/apply/
  texts.txt`), so that a capture corrects them in one place.
