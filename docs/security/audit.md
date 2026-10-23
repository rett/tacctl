# Audit log

[Documentation](../README.md) › [Security](README.md)

Every line tacctl writes to the log goes to syslog through `logger(1)`: facility `auth`, tag `tacctl` (the login console's own lines: `tacctl-console`). tacctl keeps no log of its own; where the lines go from there is the site's concern. `man tacctl`, AUDIT LOG, has the same content and the list of commands by class.

## What is recorded

A command that changes state, or logs in somewhere every time it runs, writes two central lines, whatever else it logs:

```
cmd start v=1 user=alice uid=1001 origin=sudo tier=superuser tty=pts/3 console=-
    cmd="user add" args="dave ops --hash <redacted>" sid=k3x9a0bq
cmd end v=1 user=alice cmd="user add" result=ok status=0 duration=0.312s
    snapshot=20261021_093015_412 sid=k3x9a0bq
```

(Each line is one line in the log; the examples here are wrapped.)

`grep 'cmd end'` lists every transaction. A refusal inside a verb writes a third line (see [Refusals](#refusals)). Commands that only read (lists, shows, checks, scans, the completion helpers, `hash`, `shell`, which runs each line as its own tacctl process) write none of these.

Every command has a class in a table in the code:

- **action**: it changes state or logs in somewhere every time it runs (`user add`, `host sync`, `ssh`, `log clear`, ...). The start line is written before the command does anything, after the tier gate and the preflight; the end line where the exit status is decided.
- **mixed**: it is a read or a write by its later arguments (`scope secret` shows or sets, `device port <name>` shows and `device port <name> 2222` sets, `config loglevel`, `console tiers`, ...). The start line is written just before the first thing the command changes, so a mixed command that only read writes nothing.
- **read**: no central line.

A command that is not in the table is treated as an action, and the test suite fails until its row is added. The lines of a verb that logs more (`ssh start`/`ssh end`, the console session, `breakglass hold`, `host enroll`, `device config apply`, ...) are kept; the pair is written for those verbs too.

## Fields

| Key | Meaning |
|---|---|
| `v` | Format version of the central lines (`1`); a collector pins itself to it. The older per-verb lines carry no `v` |
| `user`, `uid`, `origin` | Who ran the command: `SUDO_USER` and `SUDO_UID`, checked against the passwd database before any command runs, with `origin=sudo`. A process with no `SUDO_USER` (a root shell, a script run as root) is `user=root uid=0 origin=root`: the one case where the log holds no login identity, as sudo's own log holds none |
| `tier` | The tier the gate held the caller to (`superuser`, `engineer`, ..., `unrestricted` for root and a local administrator who is no tacctl user) |
| `tty`, `console` | The terminal the command runs on (`-` for none), and the login-console session it was typed in (`-` for none) |
| `cmd`, `args` | The command's words as the tier gate sees them (`user add`, `scope secret`, `device config`), and the arguments after them, each word quoted and cut at 64 bytes, the whole at 512 |
| `result`, `status` | How the command ended and its exit status (see below) |
| `duration` | Seconds with millisecond precision, from the start line to the end line |
| `snapshot` | The id of the pre-change snapshot or snapshots the command took (`-` when none was taken or the newest was current) |
| `reason` | On a `cmd DENY` line: `superuser` or `scope` |
| `sid` | The session id, last on every line (see [Correlating](#correlating)) |
| `class` | `class=unexpected` on a start line means a command classified as a read reached a write: a fault in the class table, never expected |

A value is written as it is when it holds only letters, digits and `. _ : / @ + -`; otherwise it is double-quoted with Go's escapes, so a line is always one line and a collector can split on spaces outside quotes. An empty value is `-`.

`result` is one of:

| `result` | Exit status |
|---|---|
| `ok` | 0 |
| `failed` | 1, 2, 3 or any other status that is not one of the next three |
| `denied` | The verb refused the caller (`cmd DENY`). The tier gate's own refusal ends the command before it starts, so it has no end line |
| `interrupted` | 130: Ctrl-C, SIGTERM or a hangup ended it |
| `aborted` | 2, written when tacctl's own code panicked |

Priorities: `auth.info` for an action, `auth.notice` for the weighty ones (`install`, `upgrade`, `uninstall`, `rollback`, `log clear`, the whole-state replacements `store import`, `store rollback`, `backup restore` and `config restore`, `group edit <group> tier|priv-lvl`, `config sudoers`, `console system-shell|tiers|user`), `auth.warning` for every refusal and for an end line whose result is not `ok`.

## Refusals

The tier gate's refusals keep their words and carry the session id:

```
tier DENY user=carol tier=readonly cmd=user remove sid=k3x9a0bq
```

A verb the gate lets through can still refuse: an engineer naming a scope's secret to change, or another scope's device. That is the third central line, at `auth.warning`:

```
cmd DENY v=1 user=bob uid=1002 tier=engineer cmd="scope secret"
    args="lab set <redacted>" reason=superuser sid=k3x9a0bq
```

with `reason=superuser` (the verb is the superuser's) or `reason=scope` (the thing named is not in the caller's scopes). The message and the exit status are the verb's own. If the command had written its start line, `cmd end` follows with `result=denied`. A collector matches `DENY` for both kinds.

## Secrets on the command line

`args=` writes `<redacted>` for:

- the value of a flag that carries a secret or a password hash (`--hash` of `user add` and `user passwd`, `--secret` of `scope add`), as `--hash <redacted>` or `--hash=<redacted>`;
- the value in `scope secret <scope> set <value>`, and every word of `scope secret` after the scope but the sub-command (`show`, `set`, `generate`), and a lone word after `scope secret` that is none of them;
- every word of `hash` and of `passwd`, and every word of `user add`, `user passwd`, `scope add` and the `community` and `v3-user` verbs of `scope snmp`, `device snmp` and `config snmp` that no flag or argument of the verb takes, a word that starts with `-` and is no flag of the verb included. These verbs ask for the password, the community or the SNMPv3 keys at a prompt (or on standard input with `--stdin`) and refuse a line that carries one. `user add`, `user passwd`, `scope add` and `passwd` are actions and write the start line before they refuse it. The SNMP verbs and `scope secret` are mixed and refuse at parse without a line, but an engineer's refusal inside the verb (`scope snmp prod community ...` for a scope that is not theirs) writes `cmd DENY` with the same `args=`; the redaction matters there. A word starting with `-` or a switch given a value (`--stdin=x`) is redacted too.

Nothing else is redacted: free text such as `breakglass hold --reason` is why a device was taken out of AAA, and it is logged as typed, as are the arguments of `ssh` after `--`. A secret typed in the place of a name (`user passwd <password>`) is logged as the name; only the words after the verb's own arguments are redacted. Whatever is typed on a command line is also in sudo's own log, which records the whole line.

The login console's refusal of a `-c` string (`scp`, a program, a shell) is not a `cmd` line but `console DENY ... reason=command first=<word>` under the tag `tacctl-console`. `first=` is a verb of tacctl or one of the console's own words (`help`, `history`, `exit`, `quit`, `system-shell`); any other first word, a program or a password typed at the prompt, is not logged: the line reads `first=- len=<n>`, `n` the length of the string.

The test suite runs every verb that takes a secret with a marker in each position it can be typed in and fails when the marker is in any `logger` argument.

## Correlating

Every line of one command, the detail lines of the verb and the tier gate's included, ends in the same `sid=<8 characters of a-z0-9>`, made for each run. `grep sid=k3x9a0bq` finds a command's lines; `tacctl ssh` and the login console keep their own `session=` beside it. The `snapshot=` of the end line names the snapshot taken before the change (`tacctl backup diff <id>` shows it against the live state). The id is for searching, not a key: two commands may share one, and the timestamps and process ids tell them apart.

A start line with no end line means the command did not finish: SIGKILL, a power loss, a crash of the process. The snapshot named by the command's lines holds the state before it, and `tacctl config validate` says what the files are now.

An `upgrade` that replaces tacctl with the new version and runs again ends its first pair at the hand-over; the second run writes its own pair, with its own `sid`.

## When `logger` fails

If `logger` cannot be started (not installed) or exits with an error (the syslog socket refused), the command prints once on standard error

```
[WARN] The audit line was not written (logger: <reason>); the command continues.
```

and goes on with its own status; the lines it could not write are lost. `logger` is in `util-linux`; `tacctl install` and `tacctl upgrade` warn when it is missing. A signal that ends a command does not drop its lines: they are written after Ctrl-C, SIGTERM and a hangup too.

## Forwarding

The facility is `auth`; the program names are `tacctl` and `tacctl-console`. A collector matches the program name. With rsyslog, in `/etc/rsyslog.d/tacctl.conf`:

```
if $programname == 'tacctl' or $programname == 'tacctl-console' then @@loghost.example.net:514
```

With journald, `journalctl -t tacctl -t tacctl-console` reads them, and `systemd-journal-upload` with `URL=https://loghost.example.net:19532` sends the journal to a `systemd-journal-remote` collector. Keep the log where an operator who runs tacctl cannot rewrite it: that is what makes it an audit trail.
