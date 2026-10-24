# tacctl 0.2.17

0.2.17 is the audit release. Every line tacctl writes to syslog goes through
one writer and carries a session id, every state-changing command writes a
start and an end line, every change writes a line saying what it changed,
and a setting can refuse a command or a secret reveal whose line cannot be
written. The release also reads the vendor from the device by SNMP, adds
selectors and a pull step to the device configuration verbs, asks for each
device of an apply by its name, and adds `device enroll`, one attended
command from a new address to its plan, with an SSH host key accepted per
device in `enroll`, `collect` and `onboard`. The only new setting is
`audit.strict`, off by default. The numbered list in `CHANGELOG.md` (0.2.17,
items 1 to 14) is everything that differs from 0.2.16.

## The audit log

`docs/security/audit.md` and the AUDIT LOG section of the manual page
describe the lines, their keys and forwarding.

- **One writer, a session id.** Each line of a run ends in the same
  `sid=<id>` (8 characters of `a-z0-9`, made for each run; the tier gate's
  `DENY` lines and the login console's `tacctl-console` lines included), so
  `grep sid=<id>` finds every line of one command. The words and keys of the
  lines that existed are unchanged and `sid=` is the last key. A line is no
  longer dropped while Ctrl-C, SIGTERM or a hangup is ending the command:
  `ssh end` and `console end` were lost on a hangup. When `logger` cannot be
  started or exits non-zero, the command prints once on standard error that
  the audit line was not written and goes on with its own status; before,
  every such line was lost silently. `tacctl install` and `tacctl upgrade`
  warn when `logger` (package `util-linux`) is not installed.
- **`cmd start`, `cmd end`, `cmd DENY`.** A command that changes state or
  logs in somewhere every time it runs writes `cmd start` before it does
  anything and `cmd end` where its exit status is decided. `result` is `ok`,
  `failed`, `denied`, `interrupted` or `aborted`, and `snapshot` names the
  snapshot the command took. A command that is a read or a write by its
  later arguments (`scope secret`, `device port <name> [<n>]`, `config
  loglevel [<level>]`) writes the pair only when it writes. The commands that
  only read write none. A refusal inside a verb (an engineer naming a
  scope's secret to change, or another scope's device; the superuser's
  verbs) writes `cmd DENY` with `reason=superuser|scope`; its message and
  exit status are unchanged. A start line with no end line means the command
  did not finish. A person who runs tacctl as root with no `SUDO_USER` is
  `user=root origin=root`.
- **Detail lines.** A command that changes something writes a line of its
  own beside the pair, saying what it changed and, for a setting, the value
  before and after (`config loglevel from=info to=debug by=<user>`). A list
  is one word (`scopes=core,lab`). The lines that existed keep their words
  and gain `result=ok`; a failed change is written too, at `auth.warning`,
  as `result=failed reason=<word>`, never the text of an error. A value is a
  name or a count, never a secret, a hash or a password.
- **Secret reads.** Every `show` that prints a secret writes `secret-read
  kind= name=` for every caller (before, only for the restricted tiers), and
  so do `store show`, `config dump` and `backup diff`. `config linux script`
  writes `secret-export`.
- **Redaction.** `args=` shows `<redacted>` for the value of `--hash`, of
  `scope add --secret` and of `scope secret <scope> set`, for every word of
  `hash` and `passwd`, and for a word typed in the place of a prompt (`user
  passwd bob <password>`, `scope snmp <scope> community <value>`). The login
  console's refusal of a `-c` string names its first word only when it is a
  verb of tacctl or one of the console's own words; any other word reads
  `first=- len=<n>`. Free text such as `breakglass hold --reason` is logged
  as typed. The test suite fails when a marker typed in any of these places
  reaches a `logger` argument.
- **Snapshot manifest.** The `manifest` of a snapshot gains `sid`, `user`
  and `command`, so the `snapshot=` id of a `cmd end` line and the snapshot
  lead to each other. Snapshots of earlier releases have none of them.
- **Priorities.** `auth.info` for an action, `auth.notice` for the weighty
  ones (`install`, `upgrade`, `uninstall`, `rollback`, `log clear`, the
  whole-state replacements, `group edit <group> tier|priv-lvl`, `config
  sudoers`, `config audit-strict`), `auth.warning` for a refusal and for an
  end line whose result is not `ok`.

### `audit.strict`

`audit: {strict: false}` in `tacctl.yaml` is the new key (`true` or `false`;
anything else is a `config validate` error). With `strict: true`, a command
that changes state whose `cmd start` line `logger` did not write is refused
before it changes anything (status 1, no snapshot taken); a command that
only reads runs. An end line that cannot be written is still the warning.

`tacctl config audit-strict [on|off]` (superuser) shows the value and where
it comes from; `on` writes the key and `off` removes it. The command is
never refused by the setting, so `off` works while `logger` is down.

With the setting on, a command that shows a secret (`scope secret <scope>
show`, `config cisco|juniper|wti`, `device config show`, `device config plan`
unless `--no-secrets`, the `--reveal` forms of the SNMP and block verbs,
`store show`, `config dump`, `backup diff`, the diffs of `backup restore`
and `config restore`) is refused for every tier when its `secret-read` line
cannot be written, before any secret is printed (`nothing was shown.`,
status 1). `config linux script` writes its `secret-export` line before the
script and is refused the same way before the file is written. Without the
setting a line that cannot be written is the warning, and the secret is
shown.

### Secrets off the command line

`tacctl scope secret <scope> set` with no value asks twice at a terminal
without echo; `set --stdin` reads one line of standard input. `tacctl user
add` and `tacctl user passwd` take `--hash -` to read the hash from standard
input. The forms with the value on the command line work as before; sudo's
log records the whole line and `ps` shows it while the command runs, which
the new forms avoid.

## Vendor detection

`tacctl device add` reads the device's `sysObjectID.0` and `sysDescr.0` by
SNMP and says which vendor they name: `cisco` for an enterprise 9 answer
whose sysDescr starts `Cisco IOS Software` or `Cisco IOS XE Software`,
`juniper` for an enterprise 2636 answer whose sysDescr names Junos, and
`wti` for an enterprise 2634 answer. Any other answer names none. A
`--vendor` that disagrees is a warning; without `--vendor` a terminal is
asked one `y/N` to register with the vendor named, and `--pull` without
`--vendor` uses it.

`device check` has a `Vendor` row (`vendor_detected` in `--json`) and
`--all` ends with the devices registered as `other` that name a vendor.
`device vendor <name> --from-device [-y]` sets the vendor from the device.
`device discover --snmp` puts each address's sysName and vendor in its
`device add` line. A vendor read that is not the registered one is the
notice `vendor-differs` (not acknowledgeable). A vendor change marks the
last pull `needs pull (vendor changed)`, so `device config diff`, `plan`
and `sync` no longer read a record in the other vendor's shape. Nothing is
written to a device.

## Selecting devices

`device config pull`, `diff`, `plan` and `apply` take three new selectors
beside names, `--all`, `--scope`, `--vendor` and `--stale`:

- `--differs` keeps the devices whose last pull differs from what tacctl
  renders now (decided from the records, with no login). A device that
  needs a pull, was never read or failed is `--stale`, not `--differs`.
- `--name <text>` keeps the devices whose name contains the text.
- `--ip <addr|cidr|text>` keeps those whose address equals the address, lies
  in the prefix or contains the text.

`--name` and `--ip` take comma lists, as in `device list`, and `device config
list` takes them too. The filters combine; `--stale` and `--differs` together
are an AND on `pull`, `diff`, `plan` and `apply`. `--name` and `--ip` match
text, so select the devices of an `apply` by exact names, a full address or
a CIDR. A selector given with no value (`--scope=`, `--name ""`) is refused
with exit 2 instead of selecting every device.

`device config apply --pull` first reads the selected Junos devices as
`device config pull` does, with the one password of the run asked once for
the pull, the check and the apply. A device whose pull fails is a failed row
and is not checked; a pull that stops ends the run with nothing checked.
`--stale` and `--differs` are applied to the fresh records, so `apply --pull
--differs` reviews the devices that differ now. The summary names a device
that no longer differs, and one that cannot be compared, and neither is
checked. The review, `--check`, `--confirmed -y`, `--hold` and every refusal
are unchanged. The pull only reads.

## The apply review

The review shows the devices grouped by shape, then asks for each device in
turn: `Type the device name to apply to <name>:`. The name typed back
approves that device (spaces and tabs around it are ignored). Anything else
declines it with no second try, and the end of input declines it and every
device after it. The single answer for several devices, the number of
devices, is gone, and there is no default. All the questions are answered
before the first commit, so the canary, `--pause`, `--concurrency` and
`--hold` are unchanged.

A declined device is a skipped row and nothing is sent to it; the approved
ones are applied and the run exits 1 (`--json`: `"stop":"not-approved"`). A
Ctrl-C at a question, or after the last answer and before the first commit,
applies nothing and exits 130. The audit lines say how the review was
answered: a `device config apply review` line for each answer, and
`mode=attended` (names typed back) or `mode=scripted` (`--confirmed -y`) on
the approval line and on each device's apply line. `device onboard`'s
approval line says `mode=attended`. A script that typed the count must now
type each device's name, or use `--confirmed -y`.

## `device enroll`

`tacctl device enroll <address>... | --discovered` (superuser) takes a new
address to its plan in one attended command. Per address, in the order
given:

1. What is refused before any question (registered already, no scope, a
   scope you are not a member of, break-glass held, no ssh host key) is a
   row, and the run goes on.
2. The one host key that will be pinned (ed25519 first, then ECDSA, then
   RSA) is shown with the console command that shows it, and is accepted by
   typing the device's name: its SNMP sysName or, when SNMP gives none, the
   name to register it as. Enter skips the device; any other answer refuses
   it. There is no `-y`, no answer for several devices and no trust on first
   use. Without a terminal the one form is `--host-key SHA256:<fp>` for one
   address, with `--vendor` and `--name` where SNMP reads none.
3. The vendor SNMP names is taken, else asked (`other` registers the device
   and ends its chain). After one `y/N` the device is registered at once
   through `device add`, with that key alone pinned; the run takes one
   snapshot.
4. Your password once, then the pull of every device registered with a
   vendor tacctl reads.
5. The registry rename to the name the device is configured with, when a
   name was typed or given (Junos `host-name`, IOS `hostname`, a WTI Site
   ID). It is kept, with the reason and the `device rename` line, when the
   name is taken, generic or invalid, or the device is held. Nothing is
   written to the device.
6. The plan, printed as `device config plan --no-secrets` prints it
   (`device config plan <name>` prints the region to paste), and for Junos
   devices whose plan has a change one question that runs the apply review.

`--json` ends at the plan. A device registered stays registered when a later
stage fails; the table (`ADDRESS NAME VENDOR KEY PULL PLAN RESULT`) gives
each one's next step. Exit 0 when every address went as far as its vendor
allows, 1 when one was refused, skipped or failed, 2 for wrong arguments or
no terminal, 130 interrupted.

### Host keys in `collect` and `onboard`

`device collect` and `device onboard` accept a key per device the same way.
The one `Trust these keys ...? [y/N]` for every key of a run is gone. Before
any login, the one key that will be pinned is shown, the others as offered
and not pinned, and the key is accepted by typing back: for `collect`, the
address, or with `--register` the device's SNMP sysName when it gives one a
new device may take; for `onboard`, `--name`, else its SNMP sysName, else
the name to register it as. Enter skips the address (`onboard`: stops), any
other answer refuses it and nothing is sent to it. Only the key accepted is
pinned at registration (`device hostkey <name> accept` pins the others after
a check), and `collect --json` lists under `host_keys` only that key.
`--host-key SHA256:<fp>` is unchanged and remains the form without a
terminal; `collect --register -y` answers only the registration question,
never a key's.

Every answer is a `device enroll hostkey`, `device collect hostkey` or
`device onboard hostkey` line at `auth.notice` with the person, the device,
the algorithm, the fingerprint and the `sid`, written before the key is
pinned or used. With `audit.strict` an unwritten line refuses that address
(`onboard`: the run) before anything is sent.

## Upgrading from 0.2.16

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no file is converted. `audit.strict` is
off until `tacctl config audit-strict on` sets it. The upgrade rewrites the
tiers sudoers drop-in, and a group drop-in that is exactly 0.2.16's text, so
that `device enroll` keeps the password cache's variable.

- A log filter that anchors the end of a line (`$`) must allow the
  `sid=<id>` that now ends every line. A filter that matches the start of a
  line, or `by=` and `user=`, still matches.
- A script that answered the apply review with the number of devices must
  type each device's name, or use `--confirmed -y`.
- `logger` (package `util-linux`) must be installed for any audit line to be
  written; the upgrade warns when it is not.

## Known limits

- Detection does not name an IOS 12.x device: its sysDescr reads `Cisco
  Internetwork Operating System Software`, not `Cisco IOS Software`.
  Non-IOS Cisco devices (ASA, IOS XR) are not named either. Register them
  with `--vendor` or `device vendor`.
- The device name `device enroll` offers is the full SNMP sysName, not its
  first label.
- `--stale` and `--differs` together keep the devices that are both.
- `tacctl rollback 0.2.16` does not rewrite the group sudoers drop-ins; they
  stay as 0.2.17 wrote them.
- Junos is the only vendor tacctl writes to; `device enroll` pulls and plans
  the others and offers no apply for them.

## Rolling back

`tacctl rollback 0.2.16` prepares the state; `tacctl upgrade --branch
0.2.16` installs 0.2.16 over it. One key changed in the schema of
`tacctl.yaml`: 0.2.16 refuses `audit.strict` as an unknown key (its `config
validate` reports it and its `backup restore` refuses a snapshot that has
it). `rollback 0.2.16 --apply` removes the key, and asks for `--yes` when
its value was `true`, since 0.2.16 then runs a command whose audit line
cannot be written. The snapshot it takes first holds the 0.2.17 form of the
file: restore it with 0.2.17, not with 0.2.16.

No other file needs a conversion. The console, device, store and SNMP
files, the blocks, the apply state and the rendered backend files are in
formats 0.2.16 reads. The sudoers drop-ins are left as they are, since sudo
accepts them, and 0.2.16's own upgrade rewrites the tiers file. The snapshot
manifests gained keys that 0.2.16 ignores. Nothing is re-rendered or
restarted and no device or host is contacted.
