# Login console: security review (0.2.1, WP7.4)

The record of how each way out of the login console was closed and tested.
The "Automated" column is filled in from the test suite; the "Live (WP7.4)"
column from the run on the dev server (2026-10-05; OpenSSH 9.6p1 on Ubuntu
24.04, a `feature/0.2.1` build, the acceptance script kept outside the repo,
steps in brackets as in `operator-console-wp-console.md` §5.5). Nothing here
was done against the production host.

Status: **automated tests done; live acceptance done (51 checks passed); the
interactive checks of the last section are left to be done by hand.**

| Avenue (design §6.5) | How it is closed | Automated | Live (WP7.4) |
|---|---|---|---|
| Shell escapes | The console starts only `sudo [-n] TACCTL_CONSOLE=<id> /usr/local/bin/tacctl <words>`, `logger`, `id`, and (for its tiers) the system shell; the login environment is scrubbed (`console.Scrub`) and the console re-executes itself with the clean one; the tokenizer knows quotes only | `internal/console` (Scrub, Guard, tokenizer fuzz), `internal/cli/console_mode_test.go` (scrub and re-exec), `console.bats` | [3] passed: one tacctl line per session for each tier, a batch on stdin; [4] `bash`, `sh -c id`, `id` refused (126); `system-shell` gives a shell without `TACCTL_*` |
| `-c` (remote commands, scp, sftp, rsync) | One tacctl line or `help` only (`console.Guard`); everything else exit 126 and `console DENY` | `console.bats` (`-c` cases), `TestConsoleMainForcedCommand` | [4], [5] passed: remote commands refused with 126; `console DENY` lines logged |
| sftp subsystem, `internal-sftp`, programs named by the client | sshd's drop-in `ForceCommand /usr/local/bin/tacctl-console`: every session, command and subsystem of a `tac-console` member reaches the console, which reads `SSH_ORIGINAL_COMMAND` (`console.Forced`) and applies the `-c` guard | `TestForced`, `TestConsoleMainForcedCommand`, `console.bats` (ForceCommand case) | [5] passed: `scp`, `scp -O` and `sftp` refused; `sshd -T` shows `forcecommand /usr/local/bin/tacctl-console` |
| Port forwarding, X11, tunnels, stream-local | Drop-in: `DisableForwarding yes`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `PermitTunnel no`; `console show`/`console check` read `sshd -T -C user=<u>` and warn in red | `TestDropInText`, `TestSSHDCheck`, `TestConsoleInstallRemoveCheck`, `console_cli.bats` | [2] `sshd -T`: `disableforwarding yes`, `allowtcpforwarding no`, `allowstreamlocalforwarding no`, `x11forwarding no`, `permittunnel no`; [5] passed: `-L` (no SSH banner through it), `-R` (request turned down), `-D` (curl rc 97/7) |
| Agent forwarding | `AllowAgentForwarding no` (and `DisableForwarding`) unless `console agent-forwarding enable` | `TestDropInText` | [2] `allowagentforwarding no`; [4] passed: no forwarded agent inside `system-shell` with `ssh -A` |
| Key logins bypassing TACACS+ | Drop-in: `PubkeyAuthentication no`; the check flags `pubkeyauthentication yes` | `TestDropInText`, `TestSSHDCheck` | [2] `pubkeyauthentication no`; [5] passed: a key in `authorized_keys` does not log in |
| What `ssh` may reach | Registered devices and enrolled hosts of the user's scopes only; in a console session `-F /dev/null`, no forwardings, no agent, `EscapeChar=none`, target after `--`, unpinned entries refused | `ssh_cli.bats` (console case), `internal/cli/ssh_test.go` | By hand (below) |
| ssh client escapes (`~C`) | `-o EscapeChar=none` unless `console ssh-escape enable` | `ssh_cli.bats` | By hand (below) |
| `system-shell` | Superusers only by default; refused through `-c` and in a batch (126); logged start, end, DENY | `TestConsoleSystemShell*`, `console.bats` | [4] passed: refused for readonly at the prompt, refused through `-c` (126), works for the superuser |
| Local privilege | Each line is `sudo` with the tiers rules; readonly and operator `sudo -n`; the tier gate on every run | `tiers.bats`, `TestConsoleLineArgv` | [3] passed: readonly `user show` works and `log failures` is refused; operator `log failures` and superuser `user list` work |
| Resource abuse | Line cap 4 KiB, one child at a time, idle timeout at the prompt, `ClientAliveInterval 300` / `ClientAliveCountMax 2` | `internal/shell` tests, pty tests | [2] `clientaliveinterval 300`, `clientalivecountmax 2`; [6] with `console idle-timeout 1` the session printed `idle timeout after 1 min` and ended (the script's elapsed time, 100 s, measured its own `sleep 100` feeding the session, not the console) |
| Information leakage | Output is what tacctl prints for the tier; `device list`/`ssh-config` scope-filtered | `tiers.bats`, `device_cli.bats` | [3] passed (as local privilege) |
| Drop-in integrity | Every change checked with `sshd -t` and undone on refusal; reload `ssh.service`, else `sshd.service`; `Include sshd_config.d/*.conf` checked; upgrade refreshes an installed drop-in | `TestDropInInstallRemove`, `TestUpgradeRefreshesConsoleDropIn`, `TestConsoleInstallRefusals` | [1] passed: upgrade made the `tacctl-console` symlink and refreshed the tiers sudoers rows; [2] `sshd -t` accepts, `console check` exits 0; [8] `console remove` and `install` keep `sshd -t` accepting |
| Break-glass | Accounts that are not tacctl users are never touched; `console user <u> disable` + `host sync` gives bash back; `console remove` refused while an account has the console; uninstall and unenroll restore `/bin/bash` first | `TestHostLocalConsole`, `TestUninstallRestoresConsoleShells`, `config_linux.bats` (shell field, remove script) | [2] the operator's own shell unchanged; [8] passed: opt-out gives `/bin/bash` and leaves `tac-console`, opt back in, `console remove` refused while accounts have the console and succeeds once none has it (drop-in and `/etc/shells` line removed), `console install` puts them back |

## Observations recorded live

- sudo logs the command-line assignment on its `COMMAND=` lines: `ENV=TACCTL_CONSOLE=<session id> ; COMMAND=/usr/local/bin/tacctl <words>` (design §9 item 10). Every console line is therefore in sudo's log with its session id, next to the console's own `start`/`end`/`DENY` lines.
- `sshd -T -C user=<console user>,host=localhost,addr=127.0.0.1` prints `forcecommand /usr/local/bin/tacctl-console`, `disableforwarding yes`, `pubkeyauthentication no`.
- OpenSSH 9.6p1 (Ubuntu 24.04) accepts `DisableForwarding` (`sshd -t`).
- New accounts get UIDs in 80000-89999. Removed accounts' homes are kept under `/home/.tacctl-removed` when the sync has no terminal to ask.

## Left to do by hand (interactive)

From a workstation, with a test user that has the console:

- `ssh <user>@<server>`: the prompt `<host>> `, the banner, Tab twice, `?`, `history`, `help`, `exit`.
- In the console, `ssh <device>`: `~C` does nothing; after `exit` the journal has `ssh end ... status=0`.
- As a superuser, a write (for example `user passwd ...`) asks the network password once, then uses sudo's cache.

## Residual risks

A bug in the tokenizer or the `-c` guard is a shell escape; it lands in an
unprivileged account with its tier's sudo rules, the same account that had
`/bin/bash` before 0.2.1. A host reached by `ssh` is a full shell on that
host, as intended. Without the drop-in (sshd's `Include` missing, or the
drop-in removed by hand), forwarding and sftp are open again: `console show`
and `console check` say so in red.
