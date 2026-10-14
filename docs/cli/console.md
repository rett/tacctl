# Console Commands — `tacctl console`

[Documentation](../README.md) › [CLI reference](README.md)

The login console is the login shell of tacctl users on the tacctl server: tacctl commands and ssh to registered devices, nothing else. Its model is `/etc/tacctl/console.yaml` (0600, snapshotted, in `backup diff` and `restore`; absent means the defaults): the console is on for every tier, a user override wins over the tier's switch, and local accounts that are not tacctl users are never touched. The settings commands change that file only (after a snapshot); they never change an account or sshd. The accounts' login shells and sshd's drop-in follow it when this server's accounts are synced (`tacctl host sync <name of the host enrolled with --local>`), which every change to a tier switch, a user override or agent forwarding prints. The idle timeout, the ssh escape, the space completion and the system shell are read by each console session when it starts.

```yaml
version: 1
tiers: {readonly: enable, operator: enable, engineer: enable, superuser: enable}
users: {jdoe: disable}            # per-user override: enable or disable
settings:
  idle_timeout: 30                # minutes at the prompt; 0 = never
  agent_forwarding: false
  ssh_escape: false
  system_shell: /bin/bash
  system_shell_tiers: [superuser]
  forwarding_tiers: [superuser]
  gateway_ports: false
  list_max: 40                    # completions the shell lists without asking
  # space_completion: false       # written only when off (the default is on, see console space-completion)
  # password_cache:               # written only when something is set (see Password cache)
  #   tiers: [operator, superuser]
  #   idle: 15                    # minutes
  #   max: 8                      # hours
```

The keys: `tiers.<tier>` (`console tiers`; `engineer` is always on), `users.<name>` (`console user`), `settings.idle_timeout` (`console idle-timeout`), `settings.agent_forwarding` (`console agent-forwarding`), `settings.ssh_escape` (`console ssh-escape`), `settings.system_shell` and `settings.system_shell_tiers` (`console system-shell path|tiers`; the tiers are never `engineer`), `settings.forwarding_tiers` and `settings.gateway_ports` (`console forwarding tiers|gateway-ports`; the tiers are never `engineer`), `settings.list_max` (edit the file), `settings.space_completion` (`console space-completion`; written only when off) and `settings.password_cache` (`console password-cache tiers|idle|max`; written only when set).

```
console show                                      Tiers, settings, each user of this server's scope with its effective shell and why, and the server's pieces (operator tier and up)
console tiers [<tier> enable|disable]             Show or switch the console for readonly, operator, engineer or superuser (the engineer tier is always on)
console user <name> [enable|disable|clear]        Show or set one user's override (clear: the tier decides; never disabled for an engineer)
console idle-timeout [<min>]                      Minutes idle before the session ends, 0-1440 (default 30, 0 = never)
console agent-forwarding [enable|disable]         Opt in to agent forwarding for console users (default disabled)
console ssh-escape [enable|disable]               Opt in to ssh's ~. and ~C in the console's ssh (default disabled)
console space-completion [on|off]                 Whether a typed space at the console's prompt completes a fixed word and is never doubled; off turns off the refusal of repeated spaces and the completion (default on; server-wide); pastes are unchanged
console forwarding tiers [<csv>|none]             Tiers that may forward X11 and TCP ports: sshd, and ssh -X/-Y/-L/-R/-D to a device in the console (default superuser)
console forwarding gateway-ports [enable|disable] Let those tiers' forwarded ports listen on other addresses than loopback: sshd's GatewayPorts clientspecified for ssh -R, the console's ssh -g and -L/-D bind addresses (default disabled)
console password-cache tiers [<csv>|none]         Tiers whose shell and console sessions keep your network password in memory for the session (operator, engineer, superuser; default none)
console password-cache idle [<min>]               Minutes without a use before it is forgotten, 1-120 (default 15)
console password-cache max [<hours>]              Hours from the moment it was cached before it is forgotten, 1-24 (default 8)
console forget                                    Forget the cached password of this session now (a word of the shell and the console)
console system-shell tiers [<csv>|none]           Tiers that may start their system shell from the console (default superuser)
console system-shell path [<path>]                The system shell (default /bin/bash; absolute, executable, listed in /etc/shells)
console install                                   Put the /etc/shells line and sshd's drop-ins (console users, engineers) in place (host sync of this server does too), then check
console remove                                    Take the console's pieces away (refused while an account has the console as its shell; the engineers' drop-in stays)
console check                                     Whether sshd applies the console's and the engineers' settings to their users, and whether a tacctl account that is not a superuser is still in tac-superuser; exit 1 and a red warning when not (a local administrator in the group is only listed) (operator tier and up)
```

`console show` lists the users of the scope of the host enrolled with `--local` with `console (user override)`, `console (tier readonly)` or `bash (tier readonly disabled)`, then the server's pieces: the `/usr/local/bin/tacctl-console` symlink, the `/etc/shells` line, sshd's drop-in and what `sshd -T -C user=<user>` reports for a console user (`allowtcpforwarding`, `allowagentforwarding`, `forcecommand`, `pubkeyauthentication`). It warns in red when the drop-in is missing, sshd does not force the console, still allows forwarding, or allows key logins, because a console user could then forward ports past the device registry, run programs or sftp, or log in without TACACS+. A server that is not enrolled with `--local` says so.

## The console session — `tacctl-console`

`/usr/local/bin/tacctl-console` is a symlink to the tacctl binary; started under that name (sshd starts a login shell as `-tacctl-console`, and with the drop-in's `ForceCommand` every login as `tacctl-console -c /usr/local/bin/tacctl-console`, the client's command in `SSH_ORIGINAL_COMMAND`) it is the console: `tacctl shell` with the prompt `<host>> ` and the banner `tacctl console on <host> — type 'help'. Devices: device list. This session is logged.`, running every line as `sudo [-n] TACCTL_CONSOLE=<session> /usr/local/bin/tacctl <words>` (`-n` by the shell's rule: readonly and operator; superusers are asked for their network password) and starting nothing else. Its Tab, `?`, typed spaces and `help` list only what the caller's tier can run (the console asks the root side for the tier with the rest of its policy; see [Interactive Shell](shell.md#interactive-shell--tacctl-shell)). The login environment is discarded except `TERM`, `LANG`, `LC_*`, `HOME`, `USER`, `LOGNAME`, `SSH_CONNECTION`, `SSH_CLIENT` and `SSH_TTY`; `PATH` is `/usr/local/bin:/usr/bin:/bin`. The session asks the server for its settings once (`sudo -n tacctl _console-policy`; without an answer: 30 minutes idle, no system shell) and ends after the idle timeout at the prompt (not while a line runs).

```
ssh carol@authsrv                 # The console: prompt 'authsrv> ', Tab, ?, history, help
ssh carol@authsrv 'user list'     # One tacctl line (sshd passes it as -c), logged; no terminal needed
ssh carol@authsrv < lines.txt     # The lines as a batch; stops at the first failure
```

`-c` accepts one line that starts with a tacctl command or `help`. Everything else — `scp`, `sftp`, `rsync`, any program, the shell's own words, an empty string — is refused with `the tacctl console does not run programs; file transfer is not available` (exit 126) and nothing runs; so is any other argument (`the tacctl console takes no options`).

`system-shell` (the console's own word, at the prompt only) starts the user's system shell (`console system-shell path`, default `/bin/bash`) as the user, without arguments, with the console's environment and `SHELL=<path>`; the idle timer does not run meanwhile and sshd's drop-in still applies; `exit` returns to the console (`back in the tacctl console`). It is open to the tiers of `console system-shell tiers` (default: superusers only); for anyone else it is refused with `system-shell is not available for the <tier> tier on this console. An administrator enables it with: tacctl console system-shell tiers …` (status 1), and through `-c` or in a batch with status 126. The same tiers may open an editor from the console (`scope block ... edit|adopt`, `device block ... edit|adopt`: an editor can start a shell); for anyone else those verbs say so and change nothing.

Logged to syslog with the tag `tacctl-console`: `console start session= user= from= tty= mode=interactive|command|batch`, `console end session= user= reason=exit|eof|idle|hangup|signal|command|failed lines= status=`, `console DENY session= user= reason=command first=<word>` (auth.warning), `console system-shell start|end|DENY` (with `status=` and `duration=` at the end). Every line is in sudo's own log too, and `tacctl ssh` logs `console=<session>`.
