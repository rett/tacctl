# Console Commands — `tacctl console`

[Documentation](../README.md) › [CLI reference](README.md)

The login console is the login shell of every tacctl user, of every tier, on the tacctl server: tacctl commands and ssh to registered devices, nothing else. There is no switch for it, and local accounts that are not tacctl users are never touched. Its settings are in `/etc/tacctl/console.yaml` (0600, snapshotted, in `backup diff` and `restore`; absent means the defaults). The settings commands change that file only (after a snapshot); they never change an account or sshd. The accounts' login shells and sshd's drop-in follow the sync of this server's accounts (`tacctl host sync <name of the host enrolled with --local>`), which every change to agent forwarding or the forwarding settings prints. The idle timeout, the ssh escape, the space completion, the colour, the list threshold and the system shell are read by each console session when it starts.

```yaml
version: 1
settings:
  idle_timeout: 30                # minutes at the prompt; 0 = never
  agent_forwarding: false
  ssh_escape: false
  system_shell: /bin/bash
  system_shell_tiers: [superuser]   # the tiers that have the system shell; superuser always
  forwarding_tiers: [superuser]
  gateway_ports: false
  list_max: 40                    # completions listed without asking; -1: never ask
                                  (console list-max)
  # space_completion: false       # written only when off (the default is on, see console
                                  space-completion)
  # color: true                   # written only when set: true (on) or false (off); absent
                                  is auto (console color)
  # system_shell_users:           # written only when a user has a setting of their own
  #   jdoe: true                  # true gives the system shell, false takes it (console
                                  system-shell user)
  # password_cache_users:         # written only when a user turned the cache on (see
  #                               Password cache); a map of user name to true
  #   jdoe: true
  # password_cache:               # written only when something is set (see Password cache)
  #                               tiers: [operator, superuser]
  #   idle: 15                    # minutes
  #   max: 8                      # hours
```

The keys: `settings.idle_timeout` (`console idle-timeout`), `settings.agent_forwarding` (`console agent-forwarding`), `settings.ssh_escape` (`console ssh-escape`), `settings.system_shell` (`console system-shell path`), `settings.system_shell_tiers` (`console system-shell <tier> enable|disable`; always holds `superuser`, never `engineer`), `settings.system_shell_users` (`console system-shell user`; written only when a user has a setting), `settings.forwarding_tiers` and `settings.gateway_ports` (`console forwarding tiers|gateway-ports`; the tiers are never `engineer`), `settings.list_max` (`console list-max`; 1 to 1000, or -1 to never ask), `settings.space_completion` (`console space-completion`; written only when off), `settings.color` (`console color`; written only when `on` or `off`) `settings.password_cache` (`console password-cache tiers|idle|max`; written only when set) and `settings.password_cache_users` (`console password-cache on|off` by each user, `console password-cache user`; written only when a user has turned it on).

```
console show

    Settings, each user of this server's scope with its effective shell and why, and the server's
    pieces (operator tier and up)

console idle-timeout [<min>]

    Minutes idle before the session ends, 0-1440 (default 30, 0 = never)

console agent-forwarding [enable|disable]

    Opt in to agent forwarding for console users (default disabled)

console ssh-escape [enable|disable]

    Opt in to ssh's ~. and ~C in the console's ssh (default disabled)

console space-completion [on|off]

    Whether a typed space at the console's prompt completes a fixed word and is never doubled; off
    turns off the refusal of repeated spaces and the completion (default on; server-wide); pastes
    are unchanged

console color [auto|on|off]

    Whether the console's lists (Tab, ?, -h and --help) are in colour: auto, the terminal decides
    (the default); on, always; off, never. The console's environment is scrubbed of NO_COLOR and
    TACCTL_COLOR, so this is how the operator chooses (server-wide)

console list-max [<n>]

    The longest list the console shows without asking "Show all N?" (default 40, at most 1000;
    0: the default; a negative number never asks, and is shown as "never ask"; server-wide)

console forwarding tiers [<csv>|none]

    Tiers that may forward X11 and TCP ports: sshd, and ssh -X/-Y/-L/-R/-D to a device in the
    console (default superuser)

console forwarding gateway-ports [enable|disable]

    Let those tiers' forwarded ports listen on other addresses than loopback: sshd's GatewayPorts
    clientspecified for ssh -R, the console's ssh -g and -L/-D bind addresses (default disabled)

console password-cache [on|off]

    Your own choice of keeping your network password in memory for the session, off until you
    turn it on (operator tier and up, and the tier must be allowed by the line below). With no
    argument it prints the permission, your setting and the limits. At the prompt of the shell
    and the console it is a word: on saves the choice and starts the cache in that session at
    once, off saves it, forgets a cached password and stops caching. It sets only your own value

console password-cache tiers [<csv>|none]

    Tiers that are allowed to use the password cache (the permission; operator, engineer,
    superuser; default none). A listed tier's users still turn it on themselves

console password-cache user [<name> [clear]]

    The users who turned the cache on, one user's setting, or clear it (the user is back to off)
    (superuser only)

console password-cache idle [<min>]

    Minutes without a use before it is forgotten, 1-120 (default 15)

console password-cache max [<hours>]

    Hours from the moment it was cached before it is forgotten, 1-24 (default 8)

console forget

    Forget the cached password of this session now (a word of the shell and the console)

console system-shell [<tier> enable|disable]

    Without arguments, whether each tier has the system shell and the users with a setting of their
    own, with their tier. A tier alone prints its state (operator tier and up); with enable or
    disable it sets it (superuser only). The superuser tier always has it and cannot be disabled;
    readonly and operator are disabled by default; the engineer tier never has it and enable is
    refused

console system-shell user <name> [enable|disable|clear]

    Show or set the system shell for one user, over the tier's setting in both directions (clear:
    the tier decides; without a word it prints the user's access and why, operator tier and up).
    Disabling a superuser and enabling an engineer are refused. An enable is for the tier the user
    has when it is set: after a move to another tier it does nothing and is listed as "stale: set
    for operator, now readonly" until it is set again (it counts again if the user returns to that
    tier). A disable holds in any tier. `user rename` moves the setting to the new name and `user
    remove` drops it; an entry for a name that is no user is not honoured and is listed as "no
    such user"

console system-shell path [<path>]

    The system shell (default /bin/bash; absolute, executable, listed in /etc/shells); showing it is
    open to the operator tier and up, setting it is the superuser's

console install

    Put the /etc/shells line and sshd's drop-ins (console users, engineers) in place (host sync of
    this server does too), then check

console remove

    Take the console's pieces away (refused while an account has the console as its shell; the
    engineers' drop-in stays)

console check

    Whether sshd applies the console's and the engineers' settings to their users, and whether a
    tacctl account that is not a superuser is still in tac-superuser; exit 1 and a red warning when
    not (a local administrator in the group is only listed) (operator tier and up)
```

`console show` lists the users of the scope of the host enrolled with `--local` with their effective shell (the console) and why, then the server's pieces: the `/usr/local/bin/tacctl-console` symlink, the `/etc/shells` line, sshd's drop-in and what `sshd -T -C user=<user>` reports for a console user (`allowtcpforwarding`, `allowagentforwarding`, `forcecommand`, `pubkeyauthentication`). It warns in red when the drop-in is missing, sshd does not force the console, still allows forwarding, or allows key logins, because a console user could then forward ports past the device registry, run programs or sftp, or log in without TACACS+. A server that is not enrolled with `--local` says so.

## The console session — `tacctl-console`

`/usr/local/bin/tacctl-console` is a symlink to the tacctl binary; started under that name (sshd starts a login shell as `-tacctl-console`, and with the drop-in's `ForceCommand` every login as `tacctl-console -c /usr/local/bin/tacctl-console`, the client's command in `SSH_ORIGINAL_COMMAND`) it is the console: `tacctl shell` with the prompt `<host>> ` and the banner `tacctl console on <host> — type 'help'. Devices: device list. This session is logged.`, running every line as `sudo [-n] TACCTL_CONSOLE=<session> /usr/local/bin/tacctl <words>` (`-n` by the shell's rule: readonly and operator; superusers are asked for their network password) and starting nothing else. Its Tab, `?`, typed spaces and `help` list only what the caller's tier can run (the console asks the root side for the tier with the rest of its policy; see [Interactive Shell](shell.md#interactive-shell--tacctl-shell)). The login environment is discarded except `TERM`, `LANG`, `LC_*`, `HOME`, `USER`, `LOGNAME`, `SSH_CONNECTION`, `SSH_CLIENT` and `SSH_TTY`; `PATH` is `/usr/local/bin:/usr/bin:/bin`. The session asks the server for its settings once (`sudo -n tacctl _console-policy`; without an answer: 30 minutes idle, no system shell) and ends after the idle timeout at the prompt (not while a line runs).

```
ssh carol@authsrv

    The console: prompt 'authsrv> ', Tab, ?, history, help

ssh carol@authsrv 'user list'

    One tacctl line (sshd passes it as -c), logged; no terminal needed

ssh carol@authsrv < lines.txt

    The lines as a batch; stops at the first failure
```

`-c` accepts one line that starts with a tacctl command or `help`. Everything else — `scp`, `sftp`, `rsync`, any program, the shell's own words, an empty string — is refused with `the tacctl console does not run programs; file transfer is not available` (exit 126) and nothing runs; so is any other argument (`the tacctl console takes no options`).

A word that starts with an underscore (`__help`, `__complete`, `_console-policy`: the entry points of the scripts, the key and the console itself) is no command at the prompt or in a batch: it is answered as any word that is no command (`Unknown command: '__help'`), and nothing runs.

**A required password change.** A user who must change the password (`user require-password-change`; never a
superuser) gets, at the start of the console, a notice (`A password change is required of your account.`: no
device accepts the login, and nothing here runs until then but the change itself) and the password change
dialog, the line `passwd`, straight away. Until the password is changed nothing else runs: every other line, the
console's own words (`help`, `history`, `system-shell`, `console forget`) included, is refused with `A password
change is required: nothing runs here until it is made but 'passwd' (and 'exit').` and status 1, and Tab and `?`
list the change only (`exit` and `quit` end the session). A line typed while the session is locked is not
entered in the history file. The root side tells the console in its policy line
(`password_change=yes`, for a caller who is held to it, decided from the group's tier at that moment). When the
password is changed the root side is asked once more and the session goes on as any other. Each line a locked session would refuse asks the root side again first, so a session left locked by a
password changed in another one, or held because the answer could not be read, goes on as soon as
the requirement is gone. The dialog is held to the console's idle time like a prompt: one nobody answers is ended and the
session ends as an idle one. Ctrl-C in the dialog
declines it and ends the session (status 130); any other failure (a wrong current password, a new one that is
too weak or differs from its confirmation) leaves a prompt that is still locked, where `passwd` tries again.
Whether a change is required is one of three answers: required, not required, and unknown. When the policy
line cannot be read (sudo refuses, the answer is not a policy, `console.yaml` or the store cannot be read) the
root side's `password_change=unknown` or the missing answer holds a caller who is no superuser the same way,
with `It could not be read whether a password change is required of your account` instead of the dialog, and
the next line asks again; a superuser is never held by a read error (the console knows one by the system group
`tac-superuser`, which needs no store).
A `-c` line and a batch are held the same way, with no dialog: a `passwd` line runs, any other is refused with
status 1. The command line holds the caller to the change too, so a plain shell or `ssh <server> tacctl ...`
runs nothing but `passwd`, `version` and `help` (see [User Commands](user.md)).

`system-shell` (the console's own word, at the prompt only) starts the user's system shell (`console system-shell path`, default `/bin/bash`) as the user, without arguments, with the console's environment and `SHELL=<path>`; the idle timer does not run meanwhile and sshd's drop-in still applies; `exit` returns to the console (`back in the tacctl console`). Superusers always have it; the other tiers have it when a superuser has enabled it for the tier (`console system-shell <tier> enable`) or for the user (`console system-shell user <name> enable`, which wins over the tier's setting, and so does `disable`). For anyone else it is refused with `system-shell is not available for the <tier> tier on this console. An administrator enables it with: tacctl console system-shell user <name> enable …` (status 1), and through `-c` or in a batch with status 126. The same people may open an editor from the console (`scope block ... edit|adopt`, `device block ... edit|adopt`: an editor can start a shell); for anyone else those verbs say so and change nothing. Only a superuser sets the system shell (a tier, a user or the path). An operator or an engineer may read each form (`console system-shell`, `console system-shell <tier>`, `console system-shell user <name>`, `console system-shell path`); every form that sets something is refused for them (`'tacctl console system-shell' is not permitted for the operator tier.`, logged as a tier denial), and a readonly user is refused all of it.

Logged to syslog with the tag `tacctl-console`: `console start session= user= from= tty= mode=interactive|command|batch`, `console end session= user= reason=exit|eof|idle|hangup|signal|command|failed|locked lines= status=`, `console DENY session= user= reason=command first=<verb>|- [len=<n>]` (auth.warning; the first word is named only when it is a verb of tacctl or a console word, else `first=- len=<n>`, the length of the string, so a password typed at the prompt is not logged), `console password-change required|unknown|done|failed session= user= [status=]` and `console DENY session= user= reason=password-change first=<verb>|- [len=<n>]` for a line refused while a password change is required (the first word under the same rule), `console system-shell start|end|DENY` (with `status=` and `duration=` at the end). Every line is in sudo's own log too, and `tacctl ssh` logs `console=<session>`.

Each change of the console's settings also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `console set key= item= from= to=`, at `auth.notice` for `system-shell` (`item` is the tier, `user:<name>` or `path`); `console install` and `console remove` end their `console provision` and `console deprovision` lines in `result=ok` or `result=failed reason=` ([Audit log](../security/audit.md#detail-lines)).
