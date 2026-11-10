# Console Commands — `tacctl console`

[Documentation](../README.md) › [CLI reference](README.md)

The login console is the login shell of every tacctl user, of every tier, on the tacctl server: tacctl commands and ssh to registered devices, nothing else. There is no switch for it, and local accounts that are not tacctl users are never touched. Its settings are in `/etc/tacctl/console.yaml` (0600, snapshotted, in `backup diff` and `restore`; absent means the defaults). The settings commands change that file only (after a snapshot); they never change an account or sshd. The accounts' login shells and sshd's drop-in follow the sync of this server's accounts (`tacctl host sync <name of the host enrolled with --local>`), which every change to agent forwarding or the forwarding settings prints. The idle timeout, the ssh escape, the space completion, the colour, the list threshold, the system shell and the file transfer settings are read by each console session when it starts.

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
  # file_transfer:                # written only when something is set (see File transfer)
  #   tiers: [superuser]          # the tiers that have it; superuser always
  #   users: {alice: 'enable:operator', bob: disable}
  #   quota: {operator: 1G}       # bytes the whole home may hold; unlimited = no limit
  #   quota_users: {alice: unlimited}
  #   rate: {operator: 1M}        # bytes a second; a tier with none has no limit
  #   rate_users: {bob: 'off'}
  # password_cache_users:         # written only when a user turned the cache on (see
  #                               Password cache); a map of user name to true
  #   jdoe: true
  # password_cache:               # written only when something is set (see Password cache)
  #                               tiers: [operator, superuser]
  #   idle: 15                    # minutes
  #   max: 8                      # hours
```

The keys: `settings.idle_timeout` (`console idle-timeout`), `settings.agent_forwarding` (`console agent-forwarding`), `settings.ssh_escape` (`console ssh-escape`), `settings.system_shell` (`console system-shell path`), `settings.system_shell_tiers` (`console system-shell <tier> enable|disable`; always holds `superuser`, never `engineer`), `settings.system_shell_users` (`console system-shell user`; written only when a user has a setting), `settings.file_transfer` (`console file-transfer`; written only when something in it is not the built-in setting), `settings.forwarding_tiers` and `settings.gateway_ports` (`console forwarding tiers|gateway-ports`; the tiers are never `engineer`), `settings.list_max` (`console list-max`; 1 to 1000, or -1 to never ask), `settings.space_completion` (`console space-completion`; written only when off), `settings.color` (`console color`; written only when `on` or `off`) `settings.password_cache` (`console password-cache tiers|idle|max`; written only when set) and `settings.password_cache_users` (`console password-cache on|off` by each user, `console password-cache user`; written only when a user has turned it on).

```
console show

    Settings, each user of this server's scope with its effective shell, system shell and file
    transfer (state, quota and rate) and why, and the server's pieces, sshd's sftp subsystem
    included (operator tier and up)

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
    console (default superuser). A forwarding opens no session and never reaches the console, so
    sshd's drop-in lists the users who must change the password in a block that closes every
    forwarding for them before the tier blocks: their new connections forward nothing through the
    server in any tier until the password is changed (a connection already open keeps what it had
    until it closes; the server's sync, console install, and every verb that changes who is held
    rewrite the list: user require-password-change, user add, remove, rename and move, user
    passwd, their own passwd, a group command that lowers a tier, store import, backup restore
    and store rollback; see Login and Console Security)

console forwarding gateway-ports [enable|disable]

    Let those tiers' forwarded ports listen on other addresses than loopback: sshd's GatewayPorts
    clientspecified for ssh -R, the console's ssh -g and -L/-D bind addresses (default disabled)

console password-cache [on|off]

    Your own choice of keeping your network password in memory for the session, off until you
    turn it on (operator tier and up, and the tier must be allowed by the line below). With no
    argument it prints the permission, your setting and the limits. At the prompt of the shell
    and the console it is a word: on saves the choice and starts the cache in that session at
    once, off saves it, forgets a cached password and stops caching. It sets only your own value.
    With the cache on, ssh and device ssh ask for your password themselves the first time,
    before they connect, and keep it; the logins tacctl makes itself (device config pull,
    diff --pull, plan --pull, block ... adopt, device config apply, device onboard, device
    collect, device enroll) keep the password a device accepted, and every one of these lines
    uses a cached password, except a line with --login (a local account's password never
    comes from or goes into the cache; details: shell.md, Password cache)

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

console file-transfer [<tier> enable|disable]

    Without arguments, whether each tier has file transfer and the users with a setting of their
    own, with their tier. A tier alone prints its state; with enable or disable it sets it. Every
    form of the verb is the superuser's, the reads included (`console show` has the state of every
    user, for the operator tier and up). Off for every tier by default; the superuser tier always
    has it and cannot be disabled; the engineer tier can be given it (see File transfer)

console file-transfer user <name> [enable|disable|clear]

    Show or set file transfer for one user, over the tier's setting in both directions (clear: the
    tier decides; without a word it prints the user's access and why). Disabling a superuser is
    refused and enabling one stores nothing. An enable is for the tier the user has when it is
    set: after a move to another tier it does nothing and is listed as "stale: set for operator,
    now readonly" until it is set again. A disable holds in any tier. `user rename` moves the
    user's settings (the switch, the quota and the rate) to the new name and `user remove` drops
    them; an entry for a name that is no user is not honoured and is listed as "no such user"

console file-transfer quota [<tier> <size>|unlimited|default]

    Without arguments, the quota of each tier (the bytes the whole home may hold) and the users
    with one of their own; a tier alone prints its quota; with a size, unlimited or default it sets
    it (default returns the tier to the built-in value)

console file-transfer quota user <name> [<size>|unlimited|clear]

    Show or set the quota of one user, over the tier's (clear: the tier decides)

console file-transfer rate [<tier> <size>|off]

    Without arguments, the rate of each tier (the bytes a second a transfer may go at) and the
    users with one of their own; a tier alone prints its rate; with a size or off it sets it

console file-transfer rate user <name> [<size>|off|clear]

    Show or set the rate of one user, over the tier's (off: no limit whatever their tier has;
    clear: the tier decides)

console install

    Put the /etc/shells line and sshd's drop-ins (console users, engineers) in place (host sync of
    this server does too), then check

console remove

    Take the console's pieces away (refused while an account has the console as its shell; the
    engineers' drop-in stays)

console check

    Whether sshd applies the console's and the engineers' settings to their users, and whether a
    tacctl account that is not a superuser is still in tac-superuser; exit 1 and a red warning when
    not (a local administrator in the group is only listed). The drop-in's list of users held to a
    password change is part of it: a list that is not the users held now is drift, shown with
    both lists (operator tier and up)
```

`console show` lists the users of the scope of the host enrolled with `--local` with their effective shell (the console) and why, then the server's pieces: the `/usr/local/bin/tacctl-console` symlink, the `/etc/shells` line, sshd's drop-in and what `sshd -T -C user=<user>` reports for a console user (`allowtcpforwarding`, `allowagentforwarding`, `forcecommand`, `pubkeyauthentication`). It warns in red when the drop-in is missing, sshd does not force the console, still allows forwarding, or allows key logins, because a console user could then forward ports past the device registry, run programs or sftp, or log in without TACACS+. The table has each user's file transfer (state, quota and rate, with the reason) next to the system shell's, and the server section says whether sshd defines an sftp subsystem (`sshd sftp subsystem: /usr/lib/openssh/sftp-server`, or `none`), with a red warning when file transfer is on for someone and sshd defines none (see File transfer). A server that is not enrolled with `--local` says so.

## File transfer — `console file-transfer`

The console serves one kind of file transfer, SFTP, to the accounts that have it. It is off for every tier but the superuser tier, which always has it, until a superuser opens it for a tier (`tacctl console file-transfer operator enable`) or for one user (`tacctl console file-transfer user alice enable`). It is settled like the system shell: a user's own setting wins over the tier's, in both directions; an enable lasts only while the user stays in the tier they had when it was set; and `console show` lists each tier's state and each user's access with the reason (and the quota and rate). Unlike the system shell and forwarding, the engineer tier is not closed to it: a transfer reaches the user's home only, where a shell or a forwarded port would reach the server's secrets. A caller with no tier is never given it.

Every form of `console file-transfer` is the superuser's, the reads included (`console file-transfer`, `... <tier>`, `... user <name>`, `... quota`, `... rate`): the verb has no row for the lower tiers. What each user has, the state, the quota and the rate, is in `console show`, which the operator tier and up can run; the read-only tier cannot.

**What a user can do.** `sftp alice@tacacs.example.net` and the `scp` of OpenSSH 9 or later (which speaks SFTP unless it is given `-O`) work for an account that has file transfer. `scp -O` (the old protocol), `rsync`, any program and the shell's words are refused, as before, with `the tacctl console does not run programs or shell commands; file transfer is SFTP only (sftp, scp of OpenSSH 9 or later)` (exit 126). For an account that does not have file transfer the subsystem is refused with `file transfer is not enabled for this account; an administrator can switch it on (tacctl console file-transfer)` (exit 126), and so is the subsystem of a user held to a required password change. The console serves the protocol as the logged-in user, with no change of privilege, so the file system's permissions apply as they do in the user's shell. An account that does not have file transfer sees only `Connection closed` from `sftp` and `scp` (sshd does not show the error text of a subsystem; `ssh <host> id`, a command request, does): the reason, `reason=file-transfer` with status 126, is in the console's audit log, and `console show` lists who has file transfer.

**The root is the home.** The user's home directory, as the account database names it and never `$HOME`, is `/` for the client: a relative path starts there, and `..` does not climb out of it. `.ssh` is invisible (a listing does not show it) and every request for it, by any spelling, is refused; so is the request that would change the home directory itself. A symbolic link is never followed, and neither a symbolic link nor a hard link can be created through the console (the request is refused). A file that already has more than one name (a hard link made outside SFTP, for example in a shell with `ln`) cannot be opened, downloaded or written, and its mode and times cannot be changed (refused, reason `link`); it can still be listed, renamed and removed, since that acts on the name and not on the data. Setting the mode of a directory without the owner's read and search bits is refused too. The size of a regular file can be set (cut, or extended with zeros), which is what `scp` does after an upload to give the file its final size; it counts against the quota like a write (see below). The owner cannot be changed, and a request that asks for it is refused whole. A new directory gets the mode 0755, which is 0700 after the umask of the console, whatever the client asks (the library does not hand the server the attributes of a request to make a directory); a client that wants another mode sets it afterwards. A new file gets the mode the client asks for in the request that opens it, when that request carries the permissions alone (which is what the `sftp` and the `scp` of OpenSSH send), and 0644 otherwise (a request that carries other attributes with the permissions is read as carrying none, and so is one that asks for no permission bits (the mode 0, with or without file type bits), which cannot be told from a request with no attributes but the extended ones); a file that already exists keeps its mode, whatever the open asks. A new file asked at a mode without the owner's write bit (0444, which `scp` sends for a read-only source) is created writable by its owner and gets the mode asked for, reduced the same way, when the client closes the handle, so that the size step an upload ends with works; a change of the permissions before the close, by the client or by anything else (a `chmod` in a shell, another session), is kept, and a session that ends with the handle open closes it, so an upload of a read-only source that is interrupted ends read-only (0400, say) and resuming it with `put -a` or `reput` is refused with permission denied, as it is by the OpenSSH server. The mode of a new file is reduced by the umask of the console, 077: the owner's bits survive and the group and other bits go, so a script uploaded with mode 0755 is 0700 and one with 0644 is 0600. The set-user-ID, set-group-ID and sticky bits are ignored. A mode that a client sets afterwards (a `chmod` in `sftp`, or the permissions sent for a handle) is applied as given, with no umask. Without `-p`, `scp` sets nothing but the size of the file after an upload, so the mode is the one of the open. With `-p` (preserve) it sends the times together with the permissions in the open request, which is read as carrying none, so the file is created with 0644 (0600 after the umask), and then sets the permissions and the times of the handle after the upload, which are applied as given: a script ends with the mode of its source, 0755. Changing the mode or the times of a file goes through `/proc/self/fd`, so file transfer needs `/proc` mounted on the server. A listing comes in the order of the file system, not sorted (the `sftp` client of OpenSSH sorts what its `ls` prints itself). A session has at most 256 files and directory listings open at once; an open past that fails and is audited (reason `too-many-open-files`). The reports (`device reports`) and the support bundles of the user are in the home, so a user can fetch them with `scp alice@tacacs.example.net:reports/devices/inventory-20261106.csv .`.

**The quota and the rate.** The quota is the bytes the home may hold. It counts the sizes of the regular files in it, each inode once (a file with two names counts once): the reports and support bundles tacctl wrote there, `.ssh` and the files the user uploads. Directories, links and inodes do not count, and a sparse file counts its length. A write that would take the home over it is refused whole (`disk quota exceeded`) and audited, and so is a size that would grow a file over it; a smaller size gives the room back. An upload that is refused part way leaves what was written before the refusal in the home (the client does not remove it), and the `sftp` and `scp` of OpenSSH show only `Failure` for it: the reason, `reason=quota`, is in the console's audit log. A file that was deleted while a handle of the session still holds it stays counted until the handle is closed. The home is measured when the session starts and again, when a file is opened for writing, if the last measure is a few seconds old, so the quota is per session: N sessions of one user at once can each use the room that was free when they measured, and bring the home to about N times the quota. A directory in the home that the session cannot read or search (for example one owned by root with mode 0700) makes the home count as full: every upload that grows the home is refused with `disk quota exceeded` until the directory is readable, while reading, deleting and writes that do not grow the home go on. The rate is the bytes a second one session may move, reads and writes together, with a burst of one second; a transfer at its rate waits, it is not refused. Both are read when the session starts.

**The audit.** A transfer is in the console's own log, under the tag `tacctl-console`: the session's start (`mode=sftp`), `console sftp start` (the tier, the home, the quota and the rate in effect), one line for each upload, download, delete, rename, mkdir and setstat (`console sftp upload ... tier=operator path="/reports/a.csv" bytes=431`; each of these lines names the caller's tier), `console sftp DENY` for each refused request (reason `.ssh`, `outside-the-home`, `symlink`, `link`, `quota`, `unsupported`, `bad-path` or `too-many-open-files`), `console sftp end` (the bytes up and down, the requests, the refusals) and the session's end. Refusals of every kind are logged, a refused `readlink` or `realpath` included; the successful `stat`, listing, `readlink` and `realpath` are not. A refused subsystem is `console DENY ... reason=file-transfer|password-change|policy|home|stream subsystem=sftp`. The paths are file names and are logged, but escaped like a Go string in double quotes (a newline or an escape sequence in a name is `\n` or `\x1b`, never itself) and cut at 200 bytes of the escaped text (a name that was cut ends with `...` after the closing quote); the error text of a request that failed is cut the same way and does not repeat the path, so a line stays short enough for `logger` to keep it whole. When `logger` cannot write a line, the warning `The audit line was not written (logger: <reason>); the command continues.` can appear on standard error during a transfer, and the transfer goes on, unaudited, with standard output still the protocol's alone. See [Audit logging](../security/audit.md).

**Ending.** The console's idle timeout does not apply to a transfer: the session lasts as long as the connection, as an sshd subsystem does, and ends with status 0 when the client closes it. A protocol error ends it with status 1 and one line on standard error (`tacctl-console: sftp: ...`). Nothing but protocol is written to standard output.

**sshd must start the subsystem.** sshd starts the sftp subsystem only if its configuration defines `Subsystem sftp ...` (the stock `sshd_config` of Debian and Ubuntu has `Subsystem sftp /usr/lib/openssh/sftp-server`), and a `Match` block cannot define one: the line is global, and tacctl adds nothing global (the console's drop-in forces the console for every login and subsystem, which then hands the subsystem's command to it). `console file-transfer` with no argument and `console show` print `sshd sftp subsystem: <program>` or `none`, read from `sshd -T`, and warn in red when file transfer is on for a tier other than the superuser tier, or for a user, and sshd defines none: ``sshd defines no sftp subsystem: file transfer cannot start; add `Subsystem sftp ...` to sshd_config``.

The quota is the bytes the whole home may hold. Nothing set means 256M for the readonly, operator and engineer tiers and unlimited for the superuser tier; a tier is set with `console file-transfer quota <tier> <size>|unlimited|default` and one user with `quota user <name> <size>|unlimited|clear`. The rate is the bytes a second a transfer may go at, off (no limit) by default: `rate <tier> <size>|off` and `rate user <name> <size>|off|clear`. A size is a number of bytes or a number with `K`, `M`, `G` or `T` (powers of 1024), such as `512K`, `256M` or `2G`, and is printed back in the largest unit that holds it exactly. Zero, a negative number, a fraction, a number that overflows and more than `1T` are refused. A user's quota or rate wins over the tier's, `unlimited` and `off` included; `clear` returns the user to the tier's value.

The settings are kept in `settings.file_transfer` of `console.yaml` (`tiers`, `users`, `quota`, `quota_users`, `rate`, `rate_users`), written only when something in it is not the built-in setting. They apply from the next console login, are logged as `console set key=file-transfer item=<tier>|user:<name>|quota:<tier>|quota-user:<name>|rate:<tier>|rate-user:<name>` at `auth.notice`, and reach the console through `tacctl _console-policy`, which carries `file_transfer=yes ft_quota=<bytes> ft_rate=<bytes>` for a caller who has it. The console fails closed: a policy it cannot read, or one that does not name file transfer, is no file transfer.

```bash
tacctl console file-transfer operator enable
tacctl console file-transfer quota operator 1G
tacctl console file-transfer rate operator 1M
tacctl console file-transfer user alice enable
tacctl console file-transfer quota user alice unlimited
tacctl console file-transfer user alice clear
```

From a client:

```bash
sftp alice@tacacs.example.net
scp alice@tacacs.example.net:reports/devices/inventory-20261106.csv .
```


## The console session — `tacctl-console`

`/usr/local/bin/tacctl-console` is a symlink to the tacctl binary; started under that name (sshd starts a login shell as `-tacctl-console`, and with the drop-in's `ForceCommand` every login as `tacctl-console -c /usr/local/bin/tacctl-console`, the client's command in `SSH_ORIGINAL_COMMAND`) it is the console: `tacctl shell` with the prompt `<host>> ` and the banner `tacctl console on <host> — type 'help'. Devices: device list. This session is logged.`, where `<host>` is the host name, or the name `tacctl server name` set, running every line as `sudo [-n] TACCTL_CONSOLE=<session> /usr/local/bin/tacctl <words>` (`-n` by the shell's rule: readonly and operator; superusers are asked for their network password) and starting nothing else. Its Tab, `?`, typed spaces and `help` list only what the caller's tier can run (the console asks the root side for the tier with the rest of its policy; see [Interactive Shell](shell.md#interactive-shell--tacctl-shell)). The login environment is discarded except `TERM`, `LANG`, `LC_*`, `HOME`, `USER`, `LOGNAME`, `SSH_CONNECTION`, `SSH_CLIENT` and `SSH_TTY`; `PATH` is `/usr/local/bin:/usr/bin:/bin`. The session asks the server for its settings once (`sudo -n tacctl _console-policy`; without an answer: 30 minutes idle, no system shell) and ends after the idle timeout at the prompt (not while a line runs). `man` opens the manual page in a pager that cannot start a program (no shell escape, no editor, no pipe; see [Manual page](shell.md#manual-page--tacctl-man)), for every tier.

```
ssh carol@authsrv

    The console: prompt 'authsrv> ', Tab, ?, history, help

ssh carol@authsrv 'user list'

    One tacctl line (sshd passes it as -c), logged; no terminal needed

ssh carol@authsrv < lines.txt

    The lines as a batch; stops at the first failure
```

`-c` accepts one line that starts with a tacctl command or `help`, and the sftp subsystem (`/usr/lib/openssh/sftp-server`, `internal-sftp`, which sshd's `ForceCommand` hands over in `SSH_ORIGINAL_COMMAND`) for the accounts that have file transfer (see File transfer): it is refused with `file transfer is not enabled for this account; an administrator can switch it on (tacctl console file-transfer)` for the others. Everything else — `scp -O`, `rsync`, any program, the shell's own words, an empty string — is refused with `the tacctl console does not run programs or shell commands; file transfer is SFTP only (sftp, scp of OpenSSH 9 or later)` (exit 126) and nothing runs; so is any other argument (`the tacctl console takes no options`).

A word that starts with an underscore (`__help`, `__complete`, `_console-policy`: the entry points of the scripts, the key and the console itself) is no command at the prompt or in a batch: it is answered as any word that is no command (`Unknown command: '__help'`), and nothing runs.

**A required password change.** A user who must change the password (`user require-password-change`; never a
superuser) gets, at the start of the console, a notice (`A password change is required of your account.`: no
device accepts the login, and nothing here runs until then but the change itself) and the password change
dialog, the line `passwd`, straight away. Until the password is changed nothing else runs: every other line, the
console's own words (`help`, `history`, `system-shell`, `console forget`) included, is refused with `A password
change is required: nothing runs here until it is made but 'passwd' (and 'exit').` and status 1, and Tab and `?`
list the change only (`exit` and `quit` end the session). A line typed while the session is locked is not
entered in the history file, and Up, Down and Ctrl-R recall no earlier line until the lock lifts. The root side tells the console in its policy line
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
