# Login console: security review (0.2.1, WP7.4)

The record of how each way out of the login console was closed and tested.
The "Automated" column is filled in from the test suite; the "Live (WP7.4)"
column from the run on the dev server (2026-10-05; OpenSSH 9.6p1 on Ubuntu
24.04, a `feature/0.2.1` build, the acceptance script kept outside the repo,
steps in brackets as in `operator-console-wp-console.md` §5.5). Nothing here
was done against the production host.

Status: **automated tests done; live acceptance done (51 checks passed); the
interactive checks done by hand on 2026-10-06 (below). The forwarding tiers
(CHANGELOG 60) came after the live run: their live check is recorded under
the observations.**

| Avenue (design §6.5) | How it is closed | Automated | Live (WP7.4) |
|---|---|---|---|
| Shell escapes | The console starts only `sudo [-n] TACCTL_CONSOLE=<id> /usr/local/bin/tacctl <words>`, `logger`, `id`, and (for its tiers) the system shell; the login environment is scrubbed (`console.Scrub`) and the console re-executes itself with the clean one; the tokenizer knows quotes only | `internal/console` (Scrub, Guard, tokenizer fuzz), `internal/cli/console_mode_test.go` (scrub and re-exec), `console.bats` | [3] passed: one tacctl line per session for each tier, a batch on stdin; [4] `bash`, `sh -c id`, `id` refused (126); `system-shell` gives a shell without `TACCTL_*` |
| `-c` (remote commands, scp, sftp, rsync) | One tacctl line or `help` only (`console.Guard`); everything else exit 126 and `console DENY` | `console.bats` (`-c` cases), `TestConsoleMainForcedCommand` | [4], [5] passed: remote commands refused with 126; `console DENY` lines logged |
| sftp subsystem, `internal-sftp`, programs named by the client | sshd's drop-in `ForceCommand /usr/local/bin/tacctl-console`: every session, command and subsystem of a `tac-console` member reaches the console, which reads `SSH_ORIGINAL_COMMAND` (`console.Forced`) and applies the `-c` guard | `TestForced`, `TestConsoleMainForcedCommand`, `console.bats` (ForceCommand case) | [5] passed: `scp`, `scp -O` and `sftp` refused; `sshd -T` shows `forcecommand /usr/local/bin/tacctl-console` |
| Port forwarding, X11, tunnels, stream-local | Drop-in: `DisableForwarding yes`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `PermitTunnel no`; `console show`/`console check` read `sshd -T -C user=<u>` and warn in red. Exception (CHANGELOG 60): the tiers of `console forwarding tiers` (default superuser) get `X11Forwarding yes` and `AllowTcpForwarding yes` in a `Match Group tac-console Group tac-<tier>` block before the console's; the console's `ssh` takes `-X/-Y/-L/-R/-D` for them only (others: `ssh DENY ... reason=forward`). Gateway ports (CHANGELOG 73): `GatewayPorts no` in the console's block; `-g` and an `-L`/`-D` bind address other than loopback refused in the console (`reason=gateway`) unless `console forwarding gateway-ports enable`, which adds `GatewayPorts clientspecified` to the tier blocks | `TestDropInText`, `TestSSHDCheck`, `TestConsoleInstallRemoveCheck`, `console_cli.bats` | [2] `sshd -T`: `disableforwarding yes`, `allowtcpforwarding no`, `allowstreamlocalforwarding no`, `x11forwarding no`, `permittunnel no`; [5] passed: `-L` (no SSH banner through it), `-R` (request turned down), `-D` (curl rc 97/7) |
| Agent forwarding | `AllowAgentForwarding no` (and `DisableForwarding`) unless `console agent-forwarding enable` | `TestDropInText` | [2] `allowagentforwarding no`; [4] passed: no forwarded agent inside `system-shell` with `ssh -A` |
| Key logins bypassing TACACS+ | Drop-in: `PubkeyAuthentication no`; the check flags `pubkeyauthentication yes` | `TestDropInText`, `TestSSHDCheck` | [2] `pubkeyauthentication no`; [5] passed: a key in `authorized_keys` does not log in |
| What `ssh` may reach | Registered devices and enrolled hosts of the user's scopes only; in a console session `-F /dev/null`, no forwardings, no agent, `EscapeChar=none`, target after `--`, unpinned entries refused | `ssh_cli.bats` (console case), `internal/cli/ssh_test.go` | By hand (below) |
| ssh client escapes (`~C`) | `-o EscapeChar=none` unless `console ssh-escape enable` | `ssh_cli.bats` | Passed by hand (2026-10-06): `~C` in the console's `ssh <device>` did nothing |
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

- Forwarding tiers (CHANGELOG 60, 71), 2026-10-06 on the dev server: `sshd -T` gives the superuser `x11forwarding yes`, `allowtcpforwarding yes`, `disableforwarding no` and the operator `no`, `no`, `yes`, both with `forcecommand /usr/local/bin/tacctl-console`; `ssh -L` through the server worked for the superuser and was refused for the operator (`channel 3: open failed: administratively prohibited`); `console check` asks about both and reports the settings in effect. A superuser's write in the console (`user passwd …`) asked sudo's password once.

## Checked by hand (interactive), 2026-10-06 on the dev server

With a tacctl superuser that has the console, from a workstation and from a
Junos switch (`ssh` from the switch's CLI to the server):

- `ssh <user>@<server>`: the banner (`tacctl console on <host> — type 'help'. Devices: device list. This session is logged.`), the prompt `<host>> `; Tab twice, `?`, `history`, `help`, `log tail -f` (until Ctrl-C), Ctrl-C at the prompt (a new prompt), `exit` (`Connection to <server> closed.`). Passed.
- In the console, `ssh <device>` to the switch: logged in as the user; `~C` did nothing; after `exit` the journal has `ssh end user=<user> device=<device> status=0 duration=40 console=<session id>`. Passed.
- As a superuser, a write (`user passwd ...`) asked sudo's password once, then used sudo's cache (recorded with the forwarding tiers above). Passed.
- Gateway ports (CHANGELOG 73): enabled and synced, `sshd -T` gives the superuser `gatewayports clientspecified` and the operator `no`, and `console check` reports the settings in effect; `ssh -R 0.0.0.0:18080:localhost:22` from a workstation listened on `0.0.0.0:18080`. Disabled and synced, the same `-R` listened on `127.0.0.1:18080` only, and the console refused `ssh <device> -L 0.0.0.0:8443:localhost:443` before connecting (`forwarded ports listen on loopback only`). Passed; left disabled.

## Residual risks

A user of a forwarding tier (superusers by default) can open TCP
forwardings through the server to anything the server reaches, past the
device registry and its scopes, and X11 to their own display; that is the
same reach as their `system-shell`, and sshd logs each forwarding. Close it
with `tacctl console forwarding tiers none` and a sync of the server.

A bug in the tokenizer or the `-c` guard is a shell escape; it lands in an
unprivileged account with its tier's sudo rules, the same account that had
`/bin/bash` before 0.2.1. A host reached by `ssh` is a full shell on that
host, as intended. Without the drop-in (sshd's `Include` missing, or the
drop-in removed by hand), forwarding and sftp are open again: `console show`
and `console check` say so in red.
