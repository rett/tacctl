# tacctl 0.2.13

0.2.13 is a release for the people who work on tacctl: the `internal/cli`
tests run in parallel, and one setting, `TMPDIR`, is now read from the
environment a command is given. There is no change of state format, no new
setting beyond that and no new way of writing to a device. The numbered list
in `CHANGELOG.md` (0.2.13, items 1 to 3) is everything that differs from
0.2.12.

## The temporary directory

tacctl stages private copies (a dry-run render, a sudoers candidate, the
check of a store import) in a temporary directory. It is now the `TMPDIR` of
the environment the command was given, else the system's, and no part of
tacctl asks the process for it any other way. Nothing changes where `TMPDIR`
is unset or is what the process has. `man/tacctl.1` (ENVIRONMENT) and
`docs/cli/exit-status.md` name it, and say that `sudo` may replace it with
its own.

## The tests

The `internal/cli` tests took 24 minutes in one run. What a test replaced for
the whole process (a dial, a prompt, a terminal check, a timeout, the login
records) is now a field of the command's invocation, so the tests run side by
side in one process: about six minutes on eight cores, also under the race
detector, in a shuffled order and with 32 in parallel. The tests that set
the process environment, signal the process or write a registry stay serial.
`make lint` fails on any read of the process's temporary directory outside
`internal/paths`.

CI runs `internal/cli` in two shards instead of four, the ones without build
tags with the race detector; a run takes about four minutes.

## Upgrading from 0.2.12

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no file is added or converted.

## Known limits

- The tests of the break-glass hold and of the password cache that share
  the process stay serial.
- The bats suite, the diff corpus and the container matrix are not run in CI.

## Rolling back

No state changed, so there is no conversion: `tacctl upgrade --branch
0.2.12` installs 0.2.12 over it.
