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
| `snapshot` | The id of the pre-change snapshot or snapshots the command took, comma-separated when it took more than one (`-` when none was taken or the newest was current) |
| `reason` | On a `cmd DENY` line: `superuser` or `scope` |
| `sid` | The session id, last on every line (see [Correlating](#correlating)) |
| `class` | `class=unexpected` on a start line means a command classified as a read reached a write: a fault in the class table, never expected |
| `mode` | On the review, approval and apply lines of `device config apply` and the approval line of `device onboard`: `attended` when the device's name was typed back, `scripted` when `--confirmed --yes` answered the review |

A value is written as it is when it holds only letters, digits and `. _ : / @ + , -` (a comma, so that a list of scopes or snapshot ids stays one word); otherwise it is double-quoted with Go's escapes, so a line is always one line and a collector can split on spaces outside quotes. An empty value is `-`.

`result` is one of:

| `result` | Exit status |
|---|---|
| `ok` | 0 |
| `failed` | 1, 2, 3 or any other status that is not one of the next three |
| `denied` | The verb refused the caller (`cmd DENY`). The tier gate's own refusal ends the command before it starts, so it has no end line |
| `interrupted` | 130: Ctrl-C, SIGTERM or a hangup ended it |
| `aborted` | 2, written when tacctl's own code panicked |

Priorities: `auth.info` for an action, `auth.notice` for the weighty ones (`install`, `upgrade`, `uninstall`, `rollback`, `log clear`, the whole-state replacements `store import`, `store rollback`, `backup restore` and `config restore`, `group edit <group> tier|priv-lvl`, `config sudoers`, `config audit-strict`, `console system-shell|tiers|user`), `auth.warning` for every refusal and for an end line whose result is not `ok`.

## Detail lines

The central pair says who ran which command and how it ended. A verb that
changes something also writes a line of its own beside it, saying what it
changed: the object, and for a setting the value before and after. A detail
line is written once the change is made, so it sits between `cmd start` and
`cmd end`; except for the verbs named after the table, a change that failed
has no detail line and the end line says `result=failed`. It is written at the priority of the command's class
(`auth.notice` for the weighty ones, `auth.info` otherwise), ends in
`by=<user>` and the `sid`, and holds a name or a count, never a secret, a hash
or a password. `from=` and `to=` are the value before and after (`-` for
none); a list is comma-separated.

```
user add name=dave group=ops scopes=core,lab by=alice sid=k3x9a0bq
config loglevel from=info to=debug by=alice sid=k3x9a0bq
```

| Event | Keys after the event words |
|---|---|
| `user add` | `name` `group` `scopes` |
| `user remove`, `user disable`, `user enable` | `name` |
| `user passwd` | `name` `source=prompt\|hash\|generated` |
| `user rename` | `from` `to` `uid=carried\|-` |
| `user move` | `name` `from` `to` (groups) |
| `user scope` | `name` `op=add\|remove\|replace` `scopes` |
| `group add` | `name` `priv-lvl` `tier` |
| `group remove` | `name` |
| `group edit` | `name` `key=priv-lvl\|tier\|wti-level\|junos-class` `from` `to`; one line per setting changed, so a `priv-lvl` change that also records or drops the tier writes a `tier` line too; `priv-lvl` and `tier` at `auth.notice` |
| `group commands` | `name` `op=default\|add\|remove\|seed` `rule` `action` `count` |
| `group privilege` | `name` `op=add\|remove\|seed` `count` |
| `group preset` | `name` `preset=roles` `changes`; one line per group changed |
| `config sudoers`, `config sudoers tiers` | `op=install\|remove` `file`, and `group` for the first |
| `console set` | `key` `item` `from` `to`: `key` is the setting (`tiers`, `user`, `system-shell`, `forwarding`, `agent-forwarding`, `ssh-escape`, `password-cache`, `idle-timeout`, `space-completion`) and `item` the tier, user or part of it; `auth.notice` for `tiers`, `user` and `system-shell` |
| `backup restore` | `id` `pre` (the snapshot taken first) `keep-uids` `legacy`; `auth.notice` |
| `store import` | `source` `replace` `force`; `auth.notice` |
| `store rollback` | `pre`; `auth.notice` |
| `install` | `branch`; `auth.notice` |
| `upgrade` | `from` `to` (commits) `branch`; `auth.notice` |
| `uninstall` | `backups=kept\|removed` `logs=kept\|removed`; `auth.notice` |
| `scope add` | `name` `prefixes` `default` |
| `scope remove` | `name` `users` |
| `scope rename` | `from` `to` `users` `hosts` |
| `scope default` | `from` `to` |
| `scope prefixes` | `op=add\|remove\|move\|remove-all` `scope` `cidr`, and `to` for a move |
| `scope protocols`, `scope vendor-attrs`, `scope auth-method`, `scope aaa-order`, `scope exec-timeout`, `scope tacacs-group`, `scope radius-group`, `scope netconf` | `scope` `from` `to` |
| `scope devices` | `scope` `cidr` `from` `to` (the vendor tag) |
| `scope mgmt-acl` | `scope` `op=add\|remove\|clear\|cisco-name\|juniper-name` `value` |
| `scope secret set` | `scope` `source=set\|generate` |
| `snmp set` | `kind=community\|v3-user\|clear\|version\|port\|timeout\|clients\|contact`, and `scope` or `device`; `from` `to` for `config snmp port\|timeout` |
| `secret-read` | `kind` `name`: a secret shown (`scope`, `snmp`, `snmp-device`, `snmp-default`, `block`, `block-adopt`, `store`, `config`, `snapshot`, `backup`); written for every caller, a superuser's too |
| `secret-export` | `scope` `file`: `config linux script` writes a file that holds the scope's secret (the line comes before the file) |
| `config allow`, `config deny`, `config mgmt-acl` | `op=add\|remove\|clear\|cisco-name\|juniper-name` `value` |
| `config password-age`, `config bcrypt-cost`, `config password-min-length`, `config secret-min-length`, `config loglevel`, `config metrics`, `config branch` | `from` `to` |
| `config listen` | `backend` `listener` `from` `to` |
| `config devices` | `key` `from` `to` |
| `config audit-strict` | `from` `to` (`on` or `off`); `auth.notice` |
| `config cisco source-interface` | `scope` `from` `to` |
| `config render` | `backends` `force` |
| `config linux uid` | `user` `uid` |
| `backend enable`, `backend disable` | `id` |
| `host sync` | `name` `target` `created` `updated` `renamed` `removed` `remove-home` `result`, and `reason` when it failed; one line per host |
| `host move` | `scope` `moved` `failed` (for a move of every drifted host) |
| `device add` | `name` `address` `vendor` `count` |
| `device remove` | `names` (the first 20, then `+n`) `count` |
| `device rename` | `from` `to` `count`, and `reason=device-name` when `device enroll` took over the name the device is configured with |
| `device enroll hostkey`, `device collect hostkey`, `device onboard hostkey` | `user` `addr` `device` `alg` `fp` `result=accepted\|skipped\|refused` `source=confirmed\|flag`; every answer to a host key's question, before the key is pinned or used; `auth.notice` |
| `device enroll` | `user` `addr` `device` `vendor` `source=snmp\|given\|asked` `result`; one line per address at the end of the run |
| `device import` | `source` `added` `updated` `removed` `count` |
| `device set` | `name` `field` `from` `to`: `address`, `hostname`, `vendor`, `port`, `description`, `location`, `legacy-ssh`, `config-syntax`, `netconf`, `stale-days` (no `name`) and `notice:<kind>` |

The verbs that logged before 0.2.17 keep their lines (`host enroll`, `host
unenroll`, `host rename`, `host forget`, `host target`, `breakglass hold`,
`release`, `remove-record` and `hold-move`, `rollback`, `device sync`,
`block-set`, `block-edit`, `block-adopt` and `block-remove`, `scope breakglass`, `scope staging`, `group
reset`, `device hostkey`, `device config forget`, `linux engineer-sudo`,
`console provision` and `deprovision`) and gain `result=ok` at the end of a
change that was made. A change that failed is written too, at
`auth.warning`, with `result=failed reason=<word>` in place: the word is the
class of the error, never its text (`script`: the client script failed on the
host; `store`: the snapshot or the write of the store, the registry or
`tacctl.yaml` failed; `race`: another command changed the name or the record
meanwhile; `lock`: another command holds the host; `write`: a file could not
be written; `ssh` and `sshd`: the connection or sshd's check failed;
`interrupted`). `host unenroll` also says `force=yes|no`. The failed
`breakglass hold` line does not repeat the text typed after `--reason`:
`reason=` there is the word. `device sync` gains `names` (the first 20
devices written, then `+n`) and `result`. `passwd` says `source=self`, and
the lines that had no actor (`uid-map renumbered`, `uid-range set`, the two
`hostkey-mismatch` lines, `console policy ... unusable`) end in `by=<user>`;
`scope staging done` stays without an actor, as the sweep that writes it has
none.

`device config apply` writes, at `auth.notice`, a review line for each device
asked, then, when any device was approved, the approval line, and each applied
device's line:

```
device config apply review user=alice device=sw-lab-1 shape=3f2a1b9c0d4e
    answer=approved mode=attended sid=k3x9a0bq
device config apply user=alice approved=1 shapes=3f2a1b9c0d4e
    canary=sw-lab-1 mode=attended sid=k3x9a0bq
device config apply user=alice device=sw-lab-1 id=tacctl-20261013T141201Z-3f2a
    shape=3f2a1b9c0d4e sections=aaa,snmp result=applied commit=0 until=-
    mode=attended sid=k3x9a0bq
```

`answer=declined` for a device whose name was not typed back. `mode` is
`attended` for the names typed back and `scripted` for `--confirmed --yes`;
nothing typed at the review is written. A Ctrl-C at a question, or after the
last answer and before the first commit, applies nothing: the answers already
given keep their lines, no approval line follows, and one line says the review
was cut short:

```
device config apply review user=alice result=interrupted applied=0
    mode=attended sid=k3x9a0bq
```
 `device onboard` says `mode=attended`
on its approval line.

`device enroll` writes, at `auth.notice`, a line for every answer to a host
key's question, before the key is pinned or used, and at the end one line per
address at `auth.info`:

```
device enroll hostkey user=alice addr=192.0.2.10 device=sw1 alg=ssh-ed25519
    fp=SHA256:... result=accepted source=confirmed sid=k3x9a0bq
device enroll user=alice addr=192.0.2.10 device=sw1 vendor=juniper
    source=snmp result=planned sid=k3x9a0bq
```

`result=` of the key is `accepted`, `skipped` (Enter, or the end of input) or
`refused` (an answer that is not the device's name, a name the rules refuse,
a `--host-key` the device does not offer); `source=confirmed` for the name
typed at the terminal, `flag` for `--host-key`. `device=` is the name shown
or given, `-` before one is known; what was typed is never written. A
fingerprint is a public value. The address's `source=` is where the vendor
came from (`snmp`, `given` by `--vendor`, `asked` at the terminal) and its
`result=` how far the address went: `refused`, `skipped`, `failed`,
`not-tried`, `registered`, `registered-other`, `pull-failed`, `planned`,
`applied` or `declined`. Between them the run writes the `device add` line
of each registration, the pull's and the plan's lines, a `device rename`
line with `reason=device-name`, and the apply's lines with `mode=attended`
when the review is run.

`device collect` and `device onboard` ask the same question before their
login and write the same line, as `device collect hostkey` and `device
onboard hostkey`, with the same keys. For `collect`, `device=` is the name
the device gives by SNMP when it is the answer (`--register`), on a refusal
too, and `-` when the answer is the address or the address was skipped; for
`onboard`, the name given or read, or the name typed when it was accepted,
and `-` on a skip. What was typed is never written.

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

- the value of a flag that carries a secret or a password hash (`--hash` of `user add` and `user passwd`, `--secret` of `scope add`), as `--hash <redacted>` or `--hash=<redacted>`; the `-` of `--hash -` is written as `<redacted>` too;
- the value in `scope secret <scope> set <value>`, and every word of `scope secret` after the scope but the sub-command (`show`, `set`, `generate`) and the flag `--stdin`, and a lone word after `scope secret` that is none of them;
- every word of `hash` and of `passwd`, and every word of `user add`, `user passwd`, `scope add` and the `community` and `v3-user` verbs of `scope snmp`, `device snmp` and `config snmp` that no flag or argument of the verb takes, a word that starts with `-` and is no flag of the verb included. These verbs ask for the password, the community or the SNMPv3 keys at a prompt (or on standard input with `--stdin`) and refuse a line that carries one. `user add`, `user passwd`, `scope add` and `passwd` are actions and write the start line before they refuse it. The SNMP verbs and `scope secret` are mixed and refuse at parse without a line, but an engineer's refusal inside the verb (`scope snmp prod community ...` for a scope that is not theirs) writes `cmd DENY` with the same `args=`; the redaction matters there. A word starting with `-` or a switch given a value (`--stdin=x`) is redacted too.

Nothing else is redacted: free text such as `breakglass hold --reason` is why a device was taken out of AAA, and it is logged as typed, as are the arguments of `ssh` after `--`. A secret typed in the place of a name (`user passwd <password>`) is logged as the name; only the words after the verb's own arguments are redacted. Whatever is typed on a command line is also in sudo's own log, which records the whole line, and `ps` shows it while the command runs. The forms that keep a value off the command line are `scope secret <scope> set` (a hidden prompt, or `--stdin`), `user add|passwd --hash -` (the hash on standard input), and the `community` and `v3-user` verbs (a prompt or `--stdin`).

The login console's refusal of a `-c` string (`scp`, a program, a shell) is not a `cmd` line but `console DENY ... reason=command first=<word>` under the tag `tacctl-console`. `first=` is a verb of tacctl or one of the console's own words (`help`, `history`, `exit`, `quit`, `system-shell`); any other first word, a program or a password typed at the prompt, is not logged: the line reads `first=- len=<n>`, `n` the length of the string.

The test suite runs every verb that takes a secret with a marker in each position it can be typed in and fails when the marker is in any `logger` argument.

## Correlating

Every line of one command, the detail lines of the verb and the tier gate's included, ends in the same `sid=<8 characters of a-z0-9>`, made for each run. `grep sid=k3x9a0bq` finds a command's lines; `tacctl ssh` and the login console keep their own `session=` beside it. The `snapshot=` of the end line names the snapshot taken before the change (`tacctl backup diff <id>` shows it against the live state). The id is for searching, not a key: two commands may share one, and the timestamps and process ids tell them apart.

A start line with no end line means the command did not finish: SIGKILL, a power loss, a crash of the process. The snapshot named by the command's lines holds the state before it, and `tacctl config validate` says what the files are now.

One `sid=` holds a whole `device enroll`: the acceptance of each key, the
registration, the pull, the rename, the plan and, when the review was run,
the apply of each device; the end line names the run's one snapshot.

An `upgrade` that replaces tacctl with the new version and runs again ends its first pair at the hand-over; the second run writes its own pair, with its own `sid`.

## When `logger` fails

If `logger` cannot be started (not installed) or exits with an error (the syslog socket refused), the command prints once on standard error

```
[WARN] The audit line was not written (logger: <reason>); the command continues.
```

and goes on with its own status; the lines it could not write are lost. `logger` is in `util-linux`; `tacctl install` and `tacctl upgrade` warn when it is missing. A signal that ends a command does not drop its lines: they are written after Ctrl-C, SIGTERM and a hangup too.

## Refusing a command whose line cannot be written

By default a failed `logger` is the warning above and the command goes on.
With

```yaml
audit:
  strict: true
```

in `/etc/tacctl/tacctl.yaml` (default `false`; `tacctl config audit-strict
on` writes it, `off` removes it, and with no argument it shows the value and
where it comes from) a command that changes state is refused when its `cmd
start` line cannot be written, before it changes anything:

```
[ERROR] The audit line cannot be written (logger: <reason>) and audit.strict
    is set; nothing was changed.
```

The status is 1. This holds for an action command and, for a mixed command, at
the first thing it would change; a command that only reads runs as before. The
warning of the previous section is not printed beside the refusal. An end line
that cannot be written is that warning and nothing more: the command has
already run.

The refusal comes before the first write, which for a few commands is after a
prompt or a read: `device collect` refuses after its first login, and `device
config apply` after the choice of devices and the password prompt. `device
config apply --check` writes the central pair too. `device enroll` is an
action, refused before anything is scanned; an acceptance whose `device
enroll hostkey` line cannot be written refuses that device before its key is
pinned, and the run goes on to the next address; so does a `device collect
hostkey` line, before anything is sent to that address, and a `device onboard
hostkey` line refuses the run before anything is sent.

A command that shows a secret writes its `secret-read` line before it prints
anything. When that line cannot be written the command is refused, whatever
the caller's tier, before any secret is printed:

```
[ERROR] The audit line cannot be written (logger: <reason>) and audit.strict
    is set; nothing was shown.
```

The status is 1. These are the commands that show a secret: `scope secret
<scope> show`, `config cisco`, `juniper` and `wti`, `device config show`,
`device config plan` (unless `--no-secrets`), `scope snmp`, `device snmp` and
`config snmp show --reveal`, `scope block` and `device block show --reveal`,
their `edit` (the editor opens on the block in force) and `adopt`, `store
show`, `config dump`, `backup diff`, and the diff of `backup restore` and
`config restore`. `config linux script`, which writes the scope's secret into
the script it hands over, writes its `secret-export` line before the file and
is refused the same way before the file is written. The `device config` verbs
that build a device's expected configuration only to compare it or with the
secrets elided (`pull`, `diff`, `apply`, `list`, `plan --no-secrets`; `device
collect` and `onboard` too) write a `secret-read` line for the secrets it
carries, but are not refused for it: a line that cannot be written is the
warning. Those that change something are refused by their `cmd start` line as
above; `scope secret <scope> generate` writes its start line before it prints
the value it generated.

`config audit-strict` itself is never refused by the setting. When `logger`
is down and every change is refused, `tacctl config audit-strict off` still
turns it off; it prints the warning of the previous section, as its own lines
are lost.

Leave the key off where a server whose `journald` is restarting must still be
able to run the command that fixes it; turn it on where "every transaction is
recorded" must hold.

## Forwarding

The facility is `auth`; the program names are `tacctl` and `tacctl-console`. A collector matches the program name. With rsyslog, in `/etc/rsyslog.d/tacctl.conf`:

```
if $programname == 'tacctl' or $programname == 'tacctl-console' then @@loghost.example.net:514
```

With journald, `journalctl -t tacctl -t tacctl-console` reads them, and `systemd-journal-upload` with `URL=https://loghost.example.net:19532` sends the journal to a `systemd-journal-remote` collector. Keep the log where an operator who runs tacctl cannot rewrite it: that is what makes it an audit trail.
