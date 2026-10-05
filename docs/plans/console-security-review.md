# Login console: security review (0.2.1, WP7.4)

The record of how each way out of the login console was closed and tested.
The "Automated" column is filled in from the test suite; the "Live (WP7.4)"
column is filled in on the dev server, following
`operator-console-wp-console.md` §5.5 (steps in brackets). Nothing here is
done against the production host.

Status: **automated tests done; live acceptance pending.**

| Avenue (design §6.5) | How it is closed | Automated | Live (WP7.4) |
|---|---|---|---|
| Shell escapes | The console starts only `sudo [-n] TACCTL_CONSOLE=<id> /usr/local/bin/tacctl <words>`, `logger`, `id`, and (for its tiers) the system shell; the login environment is scrubbed (`console.Scrub`) and the console re-executes itself with the clean one; the tokenizer knows quotes only | `internal/console` (Scrub, Guard, tokenizer fuzz), `internal/cli/console_mode_test.go` (scrub and re-exec), `console.bats` | [3], [7]: pending |
| `-c` (remote commands, scp, sftp, rsync) | One tacctl line or `help` only (`console.Guard`); everything else exit 126 and `console DENY` | `console.bats` (`-c` cases), `TestConsoleMainForcedCommand` | [5]: pending |
| sftp subsystem, `internal-sftp`, programs named by the client | sshd's drop-in `ForceCommand /usr/local/bin/tacctl-console`: every session, command and subsystem of a `tac-console` member reaches the console, which reads `SSH_ORIGINAL_COMMAND` (`console.Forced`) and applies the `-c` guard | `TestForced`, `TestConsoleMainForcedCommand`, `console.bats` (ForceCommand case) | [5] `sftp`, `scp`: pending |
| Port forwarding, X11, tunnels, stream-local | Drop-in: `DisableForwarding yes`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `PermitTunnel no`; `console show`/`console check` read `sshd -T -C user=<u>` and warn in red | `TestDropInText`, `TestSSHDCheck`, `TestConsoleInstallRemoveCheck`, `console_cli.bats` | [2] `sshd -T`, [5] `-L/-R/-D/-w`: pending |
| Agent forwarding | `AllowAgentForwarding no` (and `DisableForwarding`) unless `console agent-forwarding enable` | `TestDropInText` | [5] `ssh -A`: pending |
| Key logins bypassing TACACS+ | Drop-in: `PubkeyAuthentication no`; the check flags `pubkeyauthentication yes` | `TestDropInText`, `TestSSHDCheck` | [5] key in `authorized_keys`: pending |
| What `ssh` may reach | Registered devices and enrolled hosts of the user's scopes only; in a console session `-F /dev/null`, no forwardings, no agent, `EscapeChar=none`, target after `--`, unpinned entries refused | `ssh_cli.bats` (console case), `internal/cli/ssh_test.go` | [3]: pending |
| ssh client escapes (`~C`) | `-o EscapeChar=none` unless `console ssh-escape enable` | `ssh_cli.bats` | [3] `~C`: pending |
| `system-shell` | Superusers only by default; refused through `-c` and in a batch (126); logged start, end, DENY | `TestConsoleSystemShell*`, `console.bats` | [4]: pending |
| Local privilege | Each line is `sudo` with the tiers rules; readonly and operator `sudo -n`; the tier gate on every run | `tiers.bats`, `TestConsoleLineArgv` | [3]: pending |
| Resource abuse | Line cap 4 KiB, one child at a time, idle timeout at the prompt, `ClientAliveInterval 300` / `ClientAliveCountMax 2` | `internal/shell` tests, pty tests | [6]: pending |
| Information leakage | Output is what tacctl prints for the tier; `device list`/`ssh-config` scope-filtered | `tiers.bats`, `device_cli.bats` | [3]: pending |
| Drop-in integrity | Every change checked with `sshd -t` and undone on refusal; reload `ssh.service`, else `sshd.service`; `Include sshd_config.d/*.conf` checked; upgrade refreshes an installed drop-in | `TestDropInInstallRemove`, `TestUpgradeRefreshesConsoleDropIn`, `TestConsoleInstallRefusals` | [1], [2], [8]: pending |
| Break-glass | Accounts that are not tacctl users are never touched; `console user <u> disable` + `host sync` gives bash back; `console remove` refused while an account has the console; uninstall and unenroll restore `/bin/bash` first | `TestHostLocalConsole`, `TestUninstallRestoresConsoleShells`, `config_linux.bats` (shell field, remove script) | [8], [9]: pending |

## Observations to record live

- Does sudo log the command-line assignment as `ENV=TACCTL_CONSOLE=…` on the
  `COMMAND=` line (design §9 item 10)? If not, the console's `start`/`end`
  lines and tacctl's `console=` fields are the per-session record.
- `sshd -T -C user=<console user>,host=localhost,addr=127.0.0.1` prints
  `forcecommand /usr/local/bin/tacctl-console`, `disableforwarding yes`,
  `pubkeyauthentication no`.
- The OpenSSH version of the dev server, and whether `DisableForwarding` is
  accepted by `sshd -t` there (OpenSSH 7.4 and later).

## Residual risks

A bug in the tokenizer or the `-c` guard is a shell escape; it lands in an
unprivileged account with its tier's sudo rules, the same account that had
`/bin/bash` before 0.2.1. A host reached by `ssh` is a full shell on that
host, as intended. Without the drop-in (sshd's `Include` missing, or the
drop-in removed by hand), forwarding and sftp are open again: `console show`
and `console check` say so in red.
