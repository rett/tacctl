# Changelog

All notable changes to tacctl. The README and the manual page describe only the
current behaviour; this file is where history lives.

## 0.2.17

1. **Audit lines: one writer, a session id, no line lost to a signal, a
   warning when `logger` fails.** Every line tacctl writes to syslog now goes
   through one writer. Each line of a run ends in the same `sid=<id>` (8
   characters of `a-z0-9`, made for each run; the tier gate's `DENY` lines and
   the login console's `tacctl-console` lines included), so `grep sid=k3x9a0bq`
   finds every line of one command. The words and keys of the lines are
   unchanged and `sid=` is the last key, so a filter that matches the start of
   a line, or `by=` and `user=`, still matches; a filter that anchors the end
   of a line (`$`) must allow the id. A line is no longer dropped when Ctrl-C,
   SIGTERM or a hangup is ending the command: `ssh end` and `console end` were
   lost on a hangup, because `logger` was not started on a cancelled context.
   When `logger` cannot be started or exits non-zero (not installed, the
   syslog socket refused, no answer in 10 seconds), the command prints once on standard error `[WARN]
   The audit line was not written (logger: <reason>); the command continues.`
   and goes on with its own status; before, every such line was lost
   silently. `tacctl install` and `tacctl upgrade` warn when `logger` (package
   `util-linux`) is not installed.

2. **Audit log: every state-changing command writes `cmd start` and `cmd end`,
   a refusal inside a verb writes `cmd DENY`.** A command that changes state
   or logs in somewhere every time it runs (`user add`, `host sync`, `ssh`,
   `log clear`, ...) writes `cmd start v=1 user= uid= origin= tier= tty=
   console= cmd= args=` before it does anything and `cmd end v=1 user= cmd=
   result= status= duration= snapshot=` where its exit status is decided, at
   `auth.info` (`auth.notice` for `install`, `upgrade`, `uninstall`,
   `rollback`, `log clear`, the whole-state replacements, `group edit <group>
   tier|priv-lvl`, `config sudoers` and the console's reach; `auth.warning`
   for an end line whose result is not `ok`). `result` is `ok`, `failed`,
   `denied`, `interrupted` (130) or `aborted` (a panic of tacctl's own code,
   status 2); `snapshot` names the snapshot the command took. A command that
   is a read or a write by its later arguments (`scope secret show|set`,
   `device port <name> [<n>]`, `config loglevel [<level>]`, ...) writes the
   pair only when it writes, from the first thing it changes; the commands
   that only read write none. `args=` shows the command line with the value of
   `--hash`, of `--secret` of `scope add` and of `scope secret <scope> set`
   as `<redacted>`. A refusal inside a verb (an engineer naming a scope's
   secret to change, or another scope's device; the superuser's verbs) writes
   `cmd DENY v=1 user= uid= tier= cmd= args= reason=superuser|scope` at
   `auth.warning`; its message and exit status are unchanged. A start line
   with no end line means the command did not finish. The new page
   `docs/security/audit.md` and the manual page's AUDIT LOG section describe
   the lines, their fields and forwarding; the manual page lists the commands
   by class. A person who runs tacctl as root with no `SUDO_USER` is
   `user=root origin=root`. The lines that existed keep their words.

3. **Audit log: no secret in `args=`, and the console's refusal names only a
   verb.** `args=` of the `cmd` lines now hides every place a secret can be
   typed: the value of `--hash` and of `scope add --secret`, the value of
   `scope secret <scope> set`, every word of `hash` and `passwd`, and a word
   typed in the place of a prompt, where the command refuses the line after
   its start line is written (`user passwd bob <password>`, `user add bob
   operator <password>`, `scope snmp <scope> community <value>` and the
   `v3-user` and `device snmp` and `config snmp` forms). A refused `-c` string
   of the login console logs `first=<word>` only when the word is a verb of
   tacctl or one of the console's words (`help`, `history`, `exit`, `quit`,
   `system-shell`); any other word, a program or a password typed at the
   prompt, reads `console DENY ... reason=command first=- len=<n>`, `n` the
   length of the string (the line used to carry any first word). Free text
   such as `breakglass hold --reason` and the arguments of `ssh` after `--`
   are logged as typed, as before; the docs say so.

4. **Audit log: detail lines for every change, `result=` on the lines that
   existed, a list is one word.** A command that changes something now says
   what it changed in a line of its own beside the `cmd start`/`cmd end` pair,
   at the priority of its class and ending in `by=<user>` and the `sid`: `user
   add name= group= scopes=`, `user passwd name= source=prompt|hash|generated`,
   `user rename from= to= uid=`, `user scope name= op= scopes=`, `group add`,
   `group edit name= key= from= to=` (one line for each setting changed),
   `group commands`, `group privilege`, `group preset`, `config sudoers op=
   file=`, `console set key= item= from= to=`, `backup restore id= pre=
   keep-uids= legacy=`, `store import`, `store rollback`, `install`, `upgrade
   from= to= branch=`, `uninstall`, `scope add|remove|rename|default`, `scope
   prefixes op= scope= cidr=`, `scope protocols|vendor-attrs|auth-method|
   aaa-order|exec-timeout|tacacs-group|radius-group|netconf scope= from= to=`,
   `scope devices`, `scope mgmt-acl`, `scope secret set scope= source=`, `snmp
   set kind=` (with `scope=` or `device=`), `config allow|deny|mgmt-acl op=
   value=`, `config <tunable> from= to=` (`password-age`, `bcrypt-cost`,
   `password-min-length`, `secret-min-length`, `loglevel`, `metrics`,
   `listen`, `branch`, `devices`, `cisco source-interface`), `config render
   backends=`, `config linux uid`, `backend enable|disable id=`, `host sync`
   for each host (`created= updated= renamed= removed= remove-home= result=`),
   `host move`, `device add|remove|rename|import` with counts and `device set
   name= field= from= to=` for every setter. A value is a name or a count,
   never a secret, a hash or a password. Every `show` that prints a secret is
   now `secret-read kind= name=` for every caller (before, only for the
   restricted tiers), and so are `store show`, `config dump` and `backup
   diff`; `config linux script` writes `secret-export scope= file=`. The lines
   that existed keep their words and gain `result=ok` when the change was made;
   a change that failed is written too, at `auth.warning`, as `result=failed
   reason=<word>` (`script`, `store`, `race`, `lock`, `write`, `ssh`, `sshd`,
   `interrupted`; never the text of an error): `host enroll|unenroll|rename|
   forget|target`, `breakglass hold|release|remove-record|hold-move`,
   `rollback`, `device sync`, `block-set|edit|adopt|remove`, `scope
   breakglass`, `scope staging`, `group reset` and its sections, `device
   hostkey`, `device config forget`, `linux engineer-sudo` and `console
   provision|deprovision`. `host unenroll` says `force=yes|no`, `device sync`
   `names=` (the first 20 devices) and `passwd` `source=self` where it said
   `(self-service)`; `uid-map renumbered`, `uid-range set`, the two
   `hostkey-mismatch` lines and `console policy ... unusable` end in
   `by=<user>`. A comma is now written as it is in a value, so a list reads
   `scopes=core,lab` and the `snapshot=` of a `cmd end` line that took two
   snapshots `snapshot=<id>,<id>`; a space, a quote or a control character is
   still quoted. The `secret-read` line of the walkthroughs and of `scope
   snmp|device snmp show --reveal` is also written for a superuser, and the
   `Reveal logged:` line of those two verbs is printed for every caller; a
   verb that shows no secret (`device config list`, the note after a setter)
   writes none. The
   page `docs/security/audit.md` and the manual page's AUDIT LOG section list
   the lines and their keys.

5. **A snapshot's manifest records who took it.** The `manifest` file of a
   snapshot gains `sid` (the session id of the audit lines), `user` (the
   person who ran the command) and `command` (its words, without arguments),
   so the `snapshot=` id of a `cmd end` line and the snapshot lead to each
   other. Snapshots of earlier releases have none of them; `backup restore`
   and `backup diff` do not read the manifest, and 0.2.16 ignores the new
   keys.

6. **`audit.strict`: refuse a command whose audit line cannot be written.** A
   new key of `tacctl.yaml`, `audit: {strict: false}` by default, valid values
   `true` and `false` (anything else is a `config validate` error). With
   `strict: true`, a command that changes state (an action command, or a mixed
   command at the first thing it would change) whose `cmd start` line `logger`
   did not write is refused before it changes anything: `[ERROR] The audit line
   cannot be written (logger: <reason>) and audit.strict is set; nothing was
   changed.`, status 1, with no snapshot taken and no `[WARN]` beside it; a
   command that only reads runs. An end line that cannot be written is still
   the warning of item 1. Edit the file to set it; it is listed under
   CONFIGURATION KEYS in the manual page and in `docs/cli/tunables.md`, and
   `docs/security/audit.md` describes it. `tacctl rollback 0.2.16` is a new
   target for the release before this one: it removes `audit.strict`, which a
   0.2.16 binary refuses as an unknown key (its `config validate` reports it
   and its `backup restore` refuses a snapshot that has it), and asks for
   `--yes` when the value was `true`; the rollbacks to 0.2.9 and 0.2.3 remove
   the key too.

7. **A shared secret and a password hash without the secret on the command
   line.** `tacctl scope secret <scope> set` with no value asks for the secret
   twice at a terminal, without echo, and `set --stdin` reads one line of
   standard input (a script); the minimum length and the single-class check
   apply to the value read, which is taken as it is (less its line end, a CR LF
   included) and refused when it holds a control character, whichever way it
   is given; `--stdin` at a terminal is typed without echo. `tacctl user add`
   and `tacctl user passwd` take `--hash -` to read the hash from one line of
   standard input (a control character in it is refused). The forms with
   the value on the command line (`set <value>`, `--hash <hash>`) work as
   before; sudo's log records the whole command line and `ps` shows it while
   the command runs, which the new forms avoid. The `args=` of the audit lines
   shows `--stdin` as typed and still writes `<redacted>` for the `-` of
   `--hash -` and for any value typed beside `--stdin`.

8. **The vendor from the device by SNMP.** `tacctl device add` reads the
   device's `sysObjectID.0` and `sysDescr.0` (the two in one request of their
   own, beside the name and location reads, with the credentials of the name
   hint) and says which vendor they name: `cisco` for
   an enterprise 9 answer whose sysDescr starts `Cisco IOS Software` or
   `Cisco IOS XE Software`; any other enterprise 9 sysDescr, an unknown
   enterprise, and a missing value name none, and Junos and WTI are
   recognised but not named yet. A `--vendor` that disagrees is a warning
   with the `device vendor` command; without `--vendor` a terminal is asked
   one `y/N` to register with the vendor named (`device add <address>` folds
   it into its question), and `--pull` without `--vendor` uses it. `device
   add <address>` asks a terminal for the name when the device gives none
   that can be offered, instead of refusing. `device check` has a `Vendor`
   row (`vendor_detected` in `--json`) and `--all` ends with the devices
   registered as `other` that name a vendor; `device vendor <name>
   --from-device [-y]` sets it from the device; `device discover --snmp`
   puts each address's sysName and vendor in its `device add` line. The
   vendor read last is kept in the seen cache, and one that is not the
   registered vendor is the notice `vendor-differs` (not acknowledgeable). A
   vendor change marks the last pull `needs pull (vendor changed)`, so
   `device config diff`, `plan` and `sync` no longer read a record in the
   new vendor's shape. Nothing is written to a device.

## 0.2.16 (2026-10-23)

1. **`config validate` takes no argument.** `config validate extra` ran the
   report and ignored the word. It now refuses it like the other verbs with a
   fixed number of arguments: `Unknown argument: 'extra'`, the usage, exit
   status 1, and no report. `--json`, `--fix-names` and `-y` are unchanged.

2. **`config validate --fix-names`: a host renamed whose own scope is refused
   counts as renamed.** `--fix-names` counted the host as failed and then
   offered its `linux-<name>` scope on its own, where the same refusal came
   again. The host now counts as renamed, and the scope is not offered in that
   run. One line takes the place of the question: `'linux-Web1' is not
   offered: its rename was refused with the host's (<reason>); retry: tacctl
   scope rename linux-Web1 linux-web1`. The scope counts under `not offered`
   and the run exits 1. The next `--fix-names` offers the scope again. `host
   rename` typed directly prints and exits as before.

3. **`host enroll` checks the device namespace again after the script has
   run.** The check of a new host name against the device registry ran only
   before the client script, which can take minutes. A `device add` that
   finished meanwhile left a host and a device with one name. The check is now
   repeated under the device registry's lock, right after the registry line is
   written. A conflict takes the line back, writes no record, pins or audit
   line, and exits 1 with `A device named '<name>' (<address>) was registered
   while the client script ran; a host and a device cannot share a name.` and
   the `host enroll ... --name <other>` command to run next. The script has
   already run on the host, and what the command did before it stays: if it
   opened the host's own `linux-<name>` scope to both protocols, or added the
   `--staging` bench address, a warning says so and names the command that
   undoes it (`Scope 'linux-web1' is still open to tacacs, radius; see
   'tacctl scope protocols linux-web1'.`, `Staging address 192.0.2.50/32
   stays in scope 'lab' for the host 'web1', which is not enrolled; remove
   it: tacctl scope staging remove 192.0.2.50/32`). The same warnings follow
   when another enrolment of the name finishes first. A re-enrolment or move
   of an enrolled host is not checked again.

4. **The comment of the rendered backend files names a held host as a host.**
   The comment block of `tacquito.yaml` and the RADIUS `clients.conf` now
   reads `(host <name>)` for a break-glass hold on an enrolled host instead of
   `(device <name>)`; a held device reads as before. The word comes from the
   host registry when the files are rendered, so `config validate` still reads
   them as up to date. `backup restore` words a hold by the registry it puts
   back: when the restore changes the enrolled names, the files are rendered
   again after the host files are in place, so a hold on a host the snapshot
   enrolls or forgets reads `(host <name>)` or `(device <name>)` to match.
   This adds no restart. If that second render fails, the restore stands and a
   warning says to run `tacctl config render`.

5. **The UID ledger has a lock; two concurrent `host sync` could give one UID
   to two users.** `linux-uids` was read and written by several commands with
   nothing between them. Two `host sync` runs that met a new user each took the
   same next number, so the user got two lines or two users shared a number.
   `config linux uid <user> <uid>` checked the holder and wrote in two steps,
   and `user rename`'s move ran beside a sync with no order. Every command that
   writes the ledger or decides from it now holds `/etc/tacctl/.linux-uids.lock`
   (0600) for its read-and-write window and nothing longer:

   - `host enroll`, `host sync` and `config linux script` hold it while they
     work out the users and their numbers, never while the script runs on a
     host.
   - `config linux uid <user> <uid>` holds it from the holder check to the
     write.
   - `config linux uid-range` and the renumbering of an old file, `user
     rename`'s move, and `backup restore`'s put of the ledger hold it for
     their own writes.
   - Every snapshot copies the ledger under it.

   `--keep-uids` takes none. The commands that only show the ledger (`config
   linux uid` with no number, `user list`, `user show`, `host show`, `host
   check`, `backup diff`) take no lock; every write replaces the file whole,
   so they see it before or after a change. A command that finds the lock held
   waits up to 30 seconds, then stops with nothing changed: `the UID ledger
   (linux-uids) is locked by another tacctl command; try again in a moment
   (waited 30s)`. A `host sync` building its script now sends the names as they
   were before a concurrent `user rename` or after it, never a mix. No state
   format changes.

6. **`host enroll` refuses a new name that a break-glass hold is recorded
   under.** `host rename` already did. `host enroll --name web9` for a name
   that a hold (without a host) is recorded under was accepted, and the files
   kept saying `(device web9)` until the hold was released. It now exits 1
   before any ssh with `A break-glass hold is recorded under the name 'web9'
   (<address>) ...` and `A hold is removed only by 'tacctl breakglass release
   web9'. Nothing was changed.` The check applies to a name no host has;
   a host that is enrolled is not affected by it.

## 0.2.15 (2026-10-19)

1. **Small fixes.** The client script's UID check no longer says `Nothing was
   changed.` when an account may have been renamed earlier in the same run: it
   says `No account was created or removed (an account renamed above keeps its
   new name).` The line for a renamed account shows the account's own UID, and
   on a host still on an earlier UID range adds `, to be renumbered to <uid> later
   in this run`. The `host sync` help line and the documentation now say that
   a sync pushes renames as well (a renamed user's account is renamed, keeping
   its UID and home). `host list` counts the `Names:` findings about hosts in
   its footer, and `host list --json` lists them under the host's `findings`.

2. **`device config apply --hold` takes an answer typed ahead.** An answer
   typed before the first question is now taken as that device's answer, and
   an answer that comes after a device's window is still dropped, not given to
   the next device. Each line is matched to the question it was read under.
   This also closes an occasional wrong rollback when the review's answer and
   the hold's answer were typed together (a pasted `name`/`OK`).

3. **`backup restore` refuses while a host is locked.** The restore now tries
   the per-host lock that `host provisioner rotate`, `host rename` and `host
   forget` hold, for every host in the live registry and in the snapshot's,
   without waiting. If another command holds one, it stops before the
   snapshot of the current state with nothing changed, names the host and
   says to run it again when that command has finished; the locks are
   released when the host files are back, and a snapshot that does not know
   the hosts takes none. The restore can no longer interleave with a running
   rotation, which removes the known limit of 0.2.14. The three refusals for
   a busy host lock (`host provisioner rotate`, `host rename`, `host forget`)
   now read `'<name>' is locked by another tacctl command (a rotation,
   rename, forget or restore of it is running); nothing was changed. Run
   this again when it has finished.`

4. **A `host sync` no longer makes the next snapshot new.** When tacctl
   decides whether the state equals the newest snapshot, it now ignores what
   `host enroll` and `host sync` write into each host record on every run
   (`last_sync` and `facts`) and compares only the `provisioner` entry, so a
   command that changes nothing else no longer uses up one of the 30 kept
   snapshots after a sync. A record present on one side only counts as equal
   when it has no `provisioner` entry; a snapshot that is taken still holds
   the records whole. The snapshot that `backup restore` takes first still
   compares everything, records included, so the undo puts back the sync
   information as it was.

5. **`host sync` takes several names.** `tacctl host sync <name>...` syncs the
   hosts named in one run, in the order typed, each as `--all` would sync it;
   the UID numbering is done once, a host that fails does not stop the others,
   and the exit status is 1 when any failed. Every name is checked before the
   first host is touched: an unknown name refuses the run, a name given twice
   counts once, a host with a break-glass hold among the names refuses the
   whole run (nothing is attempted over ssh; `--all` still skips a held host
   and says so), and names together with `--all` are a usage error. The names
   complete at every position.

6. **`backup restore <timestamp> --keep-uids` leaves the UID ledger as it
   is.** The flag (also on `config restore`) restores a snapshot's registry,
   host records and staging but not `linux-uids`. Use it when the snapshot is
   wanted for its users, groups, scopes or devices and the hosts have synced
   since: the live ledger is the one the hosts agree with. In place of the
   list of users whose number would be dropped or changed, the note before
   the question and after the restore is one line saying the ledger is kept.
   A restored user with no line gets one at the next `host sync`. A snapshot
   that does not know the hosts never touches the ledger, and the flag says
   so. `--keep-uids` with `--legacy`, or without a store, is a usage error.

7. **`host check <name>... | --all [--json]` compares hosts and changes
   nothing.** It runs, for each host named or for every enrolled host with
   `--all`, the read-only comparison that `host show <name> --check` makes,
   and changes nothing here or on any host. Every name is checked first: an
   unknown name refuses the run, a name given twice counts once, and names
   with `--all` are a usage error. Each host gets one result: `as tacctl
   would make it`, its differences with the command that fixes each,
   `skipped` for a host with a break-glass hold (typed or not), or `could not
   be checked` with the reason. With more than one host a last line counts
   them by state. The exit status is 1 when a host has a difference or could
   not be checked, and a skipped host is not a failure. `--json` prints an
   array (`[]` for no host) and nothing else on standard output, with `name`,
   `target`, `state` (`ok`, `differences`, `failed`, `held`), `differences`,
   `notes`, `error` and `breakglass`. It is the superuser's, like `host show
   --check`.

8. **`config validate --json` prints the findings as one JSON object.** The
   object has `valid`, `errors`, `warnings`, `mode` (`store` or `legacy`),
   `counts` (users, groups and scopes; `null` when the model cannot be read),
   `backends`, and `findings` in the order the text report lists them. Each
   finding has `section` (a fixed token for each label of the text report),
   `level` (`error` or `warning`), `text`, `fix` (the command that puts it
   right, `""` when none), and `backend` or `hosts` where they apply. Nothing
   else is printed on standard output (the complaint of an unreadable store
   goes to standard error), and the exit status is the text report's: 1 when
   `errors` is not 0, with the object printed either way. An option other
   than `--json` is now refused with the usage line. The verb stays the
   operator's: the per-tier sudoers rules gain the exact `config validate
   --json` row, `tacctl upgrade` rewrites an installed drop-in, and `tacctl
   rollback` recognises the 0.2.14 text. A finding the text report colours
   red but does not count (a break-glass hold with no registered device) is a
   `warning` in the object.

9. **`config validate --fix-names [-y]` renames the names the report flags.**
   After the report it offers each device, host, user and scope with upper
   case in its name, one question each (`Rename user 'Alice' to 'alice'?
   [y/N]:`; a piped `y` answers, and `-y` answers yes to all). Each rename is
   the existing verb (`device rename`, `host rename`, `user rename`, `scope
   rename`) with its own snapshot, and the findings are read again after each
   one, so a scope that a host rename carried is not offered twice. A name
   whose lower-case spelling is taken is not offered, and its line names the
   verb that picks another name. A rename the verb refuses is printed and
   counted, and the rest go on. The run ends with `Names: renamed N, declined
   N, not offered N, failed N.` and exits 1 when the report had errors, a
   rename failed or a name was not offered; a decline does not fail it. It is
   the superuser's, needs the store, and is a usage error with `--json`.

## 0.2.14 (2026-10-18)

1. **`device address` moves a break-glass hold with its device.** On a
   device that is held, changing the address used to be refused until the
   hold was released, which answered the old address again. It now moves the
   hold: the new address must pass what a new hold passes (not a loopback
   address, not one a listener of either backend binds, not an enrolled
   host's address, not held by another record, covered by a scope), and one
   line names both addresses and asks to confirm (`-y` skips it). The
   registry and the record are written together, rendered once, and each
   backend whose file changed is restarted once; a restart that fails is
   reported as `NOT restarted` and exits 1, with both left on the new
   address. A refused address changes nothing. The superuser moves a hold
   (an engineer is refused), `--apply` is refused for a held device, and
   `device remove` and `device import` of a held device are still refused.
   The log line is `breakglass hold-move device= from= to= by=`.

2. **A break-glass hold can be placed on an enrolled Linux host.**
   `tacctl breakglass hold|release|list` now name hosts and devices alike,
   with the same record (`breakglass_hold.<name>` in `tacctl.yaml`: since,
   by, reason, address) and the same carve-out: the host's address, the one
   `host enroll` or `host sync` recorded (else its ssh target's, when that is
   an address), is taken out of every scope's prefixes at render time, so
   the server answers no login and no sudo check for it while the host's
   local administrator and its console keep working. The hold report, the
   prompt and the way in are the host's own; `list` has a KIND column and
   `--json` a `kind` field. The refusals stay for this server's own host
   (`--local`), loopback addresses, listener addresses, a host with no
   address, an address no scope covers and a name that is both an enrolled
   host and a registered device (ambiguous: both are named, nothing is
   changed); a device is still not held, nor moved by `device address`, at
   an enrolled host's address, and a host is not held at a registered
   device's address. A host is held by its name: an address that is only its
   ssh target's is refused, naming the host. `host sync`, `host show --check`, `host
   enroll` of a registered host (and so `host move`), `host target <name>
   <target>`, `host provisioner <name> rotate` and `host unenroll` (also
   with `--force`) are refused for a held host, naming the hold and
   `tacctl breakglass release <name>`, before anything is attempted over
   ssh (also when the device registry, which records the host's address,
   cannot be read: nothing is attempted); `host sync --all` skips a held host
   and says so; `tacctl ssh` of a
   held host warns. `host list` marks a held host (`BREAK-GLASS` in a STATE
   column and a footer), `host show` has a Break-glass section (`breakglass`
   in `--json`), `status`, `scope` and `config validate` name the hold, and a
   record whose host is no longer enrolled at the record's address is an
   orphan, as for a device. Holds and releases are the superuser's; an
   engineer sees the holds of the hosts of their own scopes. The log lines
   are `breakglass hold|release host=<name> addr=<ip>`. The state format is
   unchanged.

3. **`host enroll` holds a new host name to the device name rules, and a
   missing option value is a usage error.** A name no enrolled host has with
   exactly that spelling (`--name`, or the one worked out from the target)
   must now be no tacctl word, as for a device: a host can no longer be
   called `all`, `scope`, `local` and the like. Names are not
   case-sensitive: `Web1` is refused while `web1` is enrolled (`'web1' is
   enrolled; names are not case-sensitive.`), where both could be enrolled
   before and shared one pin record in the device registry; a registered
   device of that name, in any case, is refused as before and now says
   `Nothing was changed.` A refusal changes nothing and attempts nothing over
   ssh. Enrolling a registered host again under its registered spelling is
   allowed, as before, so a host already named with a reserved word or
   enrolled twice in two cases keeps working. `host enroll --scope`,
   `--server`, `--name`, `--port` or `--identity` with no value (or an empty
   one) used to exit 1 without a word; it now prints `<option> needs a
   value.` and the usage line, as `--method` does. No other `host` verb
   exited silently on a missing value.

4. **Snapshots hold the host state, and a restore puts it back.** A
   snapshot now also holds `linux-hosts` (the registry of enrolled Linux
   hosts), `hosts/` (the per-host records), `staging` (the staging addresses)
   and `linux-uids` (the UID ledger), 0600 in a 0700 directory. `linux-hosts`
   is in every new snapshot, empty when there is no registry, so a snapshot
   that has it is one that knows the hosts; the provisioner's lock files and
   the caches are not kept. A snapshot is skipped only when all of it equals
   the newest one, so a change of the registry alone makes a new snapshot,
   and the first one after the upgrade is taken once even when nothing else
   changed. `host enroll` (so `host move`) and `host unenroll` take a
   snapshot just before the registry changes, after the script on the host
   has succeeded; if the snapshot cannot be taken the registry is left and
   the command says so. `host sync` takes none. `backup restore` of a
   snapshot that knows the hosts puts `linux-hosts` back whole, makes
   `hosts/` match (a record the snapshot lacks goes), puts `staging` back or
   removes it and puts `linux-uids` back as it was, after the render and the
   other files, under the apply lock; the snapshot of the current state it
   takes first holds the live host files, so the restore can be undone. A
   snapshot without `linux-hosts` (0.2.13 and older) leaves all four alone.
   No host is touched and nothing is reconciled: before the question, and
   again after the restore, a note names the hosts that come back, go or are
   registered differently, what to do about a host whose state no longer
   matches (`host sync`, `host show --check`, `host unenroll` again, `host
   enroll` again), and every user whose UID the restored ledger drops or
   changes, since a host may already hold that number. `backup diff` adds
   `linux-hosts`, `staging`, `linux-uids` and each host record where either
   side has one; `backup list` is unchanged. The state format does not
   change and 0.2.13 ignores the new entries. `host move --all` takes one
   snapshot before the first move and none per host, so a batch of more than
   30 hosts does not push the state before it out of the 30 snapshots kept.
   The restore takes the host registry's lock before it changes anything: a
   registry another command holds for 30 seconds stops it with nothing
   changed. If putting the host files back fails after the render, the
   backends are still restarted and the failure is a warning that names the
   snapshot of the state from before the restore. A host file that cannot be
   read is named in a red line before the question (`could not compare the
   host files`), and the restore still puts the files back. When the snapshot
   fails after `host unenroll` ran the removal, the message says to add
   `--force` if the removal cannot run again.

5. **`host rename <old> <new>` gives an enrolled host another name, and
   `host enroll` can no longer register a name twice.** The rename is the
   superuser's and local: nothing is sent to the host, so a host with a
   break-glass hold may be renamed, and a running `host provisioner rotate`
   of the host refuses it. The new name follows the rules of a new host name
   with no way round them: no tacctl word, no generic name, no other host or
   registered device equal to it in any case; changing only the spelling
   to lower case (`Web1` to `web1`) is allowed and the same name says
   `already has that name`. What an earlier host of the new name left (a pin, a record,
   staging addresses) is listed and replaced after a confirmation (`--yes`
   skips it); a break-glass hold under the new name is always refused. After
   a snapshot the registry line is renamed where it is, one write of the
   device registry renames the pinned keys, the address, its history and the
   acknowledged notices (`known_hosts` follows; if that write fails the
   registry line is renamed back and nothing is changed), then the record,
   the staging addresses, the hold (same address) and the host-key scan
   result follow, each a warning with the fix when it cannot. The log line
   is `host rename old= new= by=`. When the host's scope is `linux-<old>`,
   no other host uses it and `scope rename` would accept `linux-<new>`, the
   command also asks `Scope 'linux-<old>' is this host's own (no other host
   uses it). Rename it to 'linux-<new>' too? [y/N]` (`--yes` answers yes);
   the scope is then renamed after the host, with its own snapshot, and the
   host's registry line and staging addresses follow it. A scope left alone
   gets one line saying why, or the `tacctl scope rename` line to run; if the
   scope step fails the host stays renamed in its old scope and the command
   says `Host renamed. Scope 'linux-<old>' was NOT renamed` with the retry
   and exits 1. `scope rename` itself is unchanged. The registry write of
   `host enroll` for a new name is now checked again under the registry's
   lock: two enrolments of `Web1` and `web1` started together can no longer
   both be written, the second says the name is taken and writes nothing
   (the client script has already run on its host). `backup diff` against a
   snapshot of 0.2.13 or older no longer lists the live host files as only in
   the current state, which a restore of it would not change; it prints
   `host files: not in this snapshot (it predates 0.2.14)` when the server
   has host files.

6. **`host forget <name>` repairs duplicate and orphaned hosts, and
   `config validate` and `host list` report them.** `config validate`
   (under `Linux hosts:`, warnings only) and `host list` (one last line,
   `N finding(s): see tacctl config validate`) now name, for the superuser,
   two enrolled names equal ignoring case, a host named like a registered
   device, two hosts with the same recorded address and ssh port (one
   address on another port is another machine, as `host enroll` judges it),
   and a pin, record or staging entry that no registry line has, each with
   the verb that fixes it (a break-glass hold with no host is the hold's own
   orphan line). Nothing is repaired where it is reported. `tacctl host
   forget <name> [--yes]` is the repair: superuser only, local, with no ssh
   and nothing sent to the host. After a snapshot it drops the registry
   line, the pinned keys, address and history (the generated `known_hosts`
   follows), the record, the host's staging entries and the host-key scan
   result, after listing what it would drop and asking (`--yes` skips the
   question). The host itself is not touched: its accounts, secrets and PAM
   setup stay (`host unenroll` cleans a host that can be reached). For this
   server's own host (`--local`) it says before it asks that this server's
   PAM setup and console accounts still use the scope, points to `host
   unenroll <name>`, and does not suggest `scope remove`. It is refused for
   a held host (release it first), a name a hold is recorded under, and
   while a rotation of the host runs. The name is the registered spelling;
   the leftovers of a name with no registry line are named by their spelling
   and forgotten the same way (when a pin cannot be removed, the retry
   hint names the pin's own spelling); a name that matches one enrolled host
   ignoring case is that host, several are refused; pins shared by names
   equal ignoring case stay while another host has such a name. `host
   unenroll` now also drops the host's staging entries, so a routine
   unenroll of a host enrolled with `--staging` leaves no orphan; the /32
   stays a prefix of the scope, and both commands print the `scope prefixes
   <scope> remove` line for it. The log line is `host forget name= by=`. The
   state format does not change. Also, in `host rename`: the device
   registry is checked for the new name under its lock when the pins are
   written, so a device registered at that moment can no longer share a name
   with the renamed host (the registry line goes back and nothing is
   changed), and `device add|rename` refuse a name an enrolled host has
   taken since their checks. That closes the window between `host rename`
   and `device add|rename` only: `host enroll` checks the device name before
   its script runs on the host, which can take minutes, and does not check
   again, so a host and a device can still end up with one name that way;
   the new findings report it. The messages for an undo that cannot restore
   the pins, or that replaced a leftover pin, say what was left; a scope
   another host was enrolled into since the question keeps its name; a
   record that cannot be moved stays under the old name, which `host
   forget` drops.

7. **`host list --json`, an ADDRESS column, and `host show` words a missing
   record neutrally.** `tacctl host list --json` prints a JSON array, `[]`
   when there is no host, with no table, footer or warning. Each host has
   `name`, `local`, `target`, `port` (22 unless the registry gives one; 0 for
   this server's own host), `scope`, `server`, `method`, `identity` (the path
   only), `address` (the address recorded at the last enroll or sync, empty
   when unknown), `users`, `drift` (the scope warning the table prints,
   empty when none), `breakglass` (the hold, as in `host show --json`, only
   while the host is held) and `findings` (the `config validate` findings
   that name the host, each with `text` and `fix`; always empty for an
   engineer). An engineer lists the hosts of their own scopes in both forms;
   the engineer sudoers rule gains `host list --json` (`tacctl upgrade`
   rewrites the drop-in). The table has an ADDRESS column
   after TARGET: the recorded address, or `-` when none. `host list` takes
   no other argument (it ignored them before). The model is read once for
   all rows. `host show` prints `no record under this name` where it printed
   `not recorded (before 0.2.2)` for the last sync and the host facts of
   a host with no record under its name: nothing tells a host enrolled
   before the records from one whose record was lost or forgotten.

8. **New device, host, user and scope names are lower case.** `device add`
   and `rename`, `host enroll` and `host rename`, `user add` and `user rename`, and
   `scope add` and `scope rename` (also the scope that `host rename` offers
   to rename) refuse a name with an upper-case letter: `Names are lower
   case: use 'alice'. Nothing was changed.` For a device or a host, a name
   taken in another case or a generic one is refused for that reason first.
   The name derived from the target's host name (`host enroll
   admin@Web1.example.net`, `--local`) is lowercased silently, because host
   names are not case-sensitive; a host already enrolled in another spelling
   keeps that spelling; a name given with `--name` is not changed. The name a device reports to `device onboard` and `device collect
   --register`, and the name `device discover` suggests, are lowercased the
   same way. A name that exists with upper case keeps working as it is:
   nothing is migrated or folded, no login changes, and the verbs that read
   names match them as before. A rename that changes only the spelling to
   lower case (`user rename Alice alice`, `device rename Core-SW1 core-sw1`,
   `scope rename Lab lab`, `host rename Web1 web1`) is how an old name is
   fixed; what follows the name (the users' scope lists, the keys and files
   of a scope or device, the registration of a host) follows it as in any
   rename. A user rename carries the Linux UID (item 10): on an enrolled
   host the next sync renames the account `Alice` to `alice`, with its UID
   and home.
   `device import` (a registry file or a CSV, so a server can be rebuilt
   from `device export --csv`) and `store import` load names with upper case
   as they are and say in one line how many. `config validate`
   warns of each such device, host, user and scope with the verb that
   renames it (`Names:`); the warning for a user says that devices match the
   typed login name exactly, so the rename changes what the person types at
   the device. The superuser sees the warnings; an engineer none.

9. **Host verbs: `-y`, one prompt shape, and the scope line of `host
   rename`.** `host enroll`, `host move`, `host rename` and `host forget`
   take `-y` as well as `--yes`, as the `device` verbs do. Their questions
   have the shape of the device questions, an indented `  <Question>?
   [y/N]: `; the words of the questions and the answers that count (`y` or
   `Y` alone) do not change. When `host rename` does not rename the
   scope `linux-<old>` (it is not offered, or another host has taken it
   since the question), the line `Scope 'linux-<old>' keeps its name: ...`
   is a warning, so `--yes` does not hide it. `host unenroll` removes the
   login method from the host and the registration, `host unenroll --force`
   removes the registration even when the host cannot be cleaned, and `host
   forget` only drops this server's record of the host.

10. **`user rename` carries the user's Linux UID.** The line of the old name
    in `linux-uids` becomes the new name's, in place (comments, the range
    lines and the order stay), inside the apply lock after the pre-change
    snapshot, which holds the ledger. The command says `UID <uid> follows
    the rename (linux-uids).` and, with enrolled hosts whose scope lists the
    user, how many hosts rename the account at their next sync (`tacctl
    host sync --all`). A user with no line is renamed as before. A new name
    that already has a line keeps its number, the ledger is left alone, and
    a warning says that hosts remove the old account and create the new one
    with that number. If the ledger cannot be written after the rename, the
    command says so, names the snapshot to restore and exits 1. The client
    script, run by `host sync`, renames the account: a listed user with no
    account here whose UID belongs to an account tacctl created under
    another name, no longer listed, is that account renamed (`usermod -l`:
    the login name only; the home keeps its path, the full name and the
    `created` and `expired` lists follow). It works from the UID alone, so a
    host that was offline, synced later, or saw the user renamed twice or
    back ends the same, and so does a host still on an earlier UID range
    (the account is found at the number the user had there, renamed, then
    renumbered). A disabled user, or one kept without a login (its group
    has no priv-lvl), is renamed too: the server writes the numbers of the
    scope's disabled and kept users that have one in a new header line,
    `TAC_INACTIVE_UIDS` (`name:uid` lines, left out when there is none; a
    header without it still works), and the account stays expired under
    its new name. A user who is logged in (processes under the UID)
    defers the rename to the next sync, with both names left untouched; a
    local account of the new name keeps the old account and says so; two
    users that swapped names are no rename, and the UID check reports the
    differences. The script never removes an account of tacctl's whose UID
    the server has given to a listed or disabled user: it keeps it and says
    so, which includes a new name that tacctl already created with another
    UID (no rename: both accounts stay and the UID check reports the
    difference). If the lists of created and expired accounts cannot be
    rewritten, nothing is renamed. `host sync` no longer asks whether to
    delete the home of the renamed user's old name, and `host show` lists
    the account under Updated. The script protocol stays 6; a script written
    by an earlier release with `config linux script` has no rename and
    stops at the UID check until it is written again (do not pass
    `--allow-uid-mismatch` to such a script: it would create the new name
    at a free number and delete the old account). Until every host has
    synced the rename, do not give the old name to a new user: that host's
    UID check refuses the sync. The ledger has no lock of its own: a `host
    sync` that reads it at the moment of the rename sees the file before or
    after it. `config validate` says that the next sync renames the
    account.

## 0.2.13 (2026-10-16)

1. **The `test` workflow no longer runs on a push to `master`.** After a
   release `master` and `develop` hold the same files, so the second run
   tested nothing new. The release procedure pushes the release branch and
   opens a pull request to `master`, so the Go tests run on the release
   commit before the tag exists (`docs/releasing.md`).

2. **The temporary directory is read from the invocation's environment.**
   Where tacctl stages private copies while it works (rendered trees, a
   candidate sudoers file, a script for a host, an import check) is the
   `TMPDIR` of the environment the command was given, now documented in the
   manual page (ENVIRONMENT, FILES) and in `docs/cli/exit-status.md`; unset,
   it is the system temporary directory as before, and sudo's environment
   policy may replace it. For developers: the Go tests no longer set `TMPDIR`
   for the process, and `tests/tools/no-os-tempdir.sh` (in `make lint`)
   keeps the code from reading the process's temporary directory.

3. **The `internal/cli` tests run in parallel.** The package took 24
   minutes in one run. What a test replaced for the whole process (a dial,
   a prompt, a terminal check, a timeout, the login records, the temporary
   directory) is now a field of the invocation, so the sandbox tests run
   side by side in one process: about six minutes on eight cores, also
   under the race detector, in a shuffled order and with `-parallel 32`.
   The tests that set the process environment, signal the process or write
   a registry stay serial. CI runs `internal/cli` in two shards instead of
   four. Nothing in tacctl changes.

## 0.2.12 (2026-10-16)

1. **`config get` and `config get-list` complete every key of the schema.**
   Tab used to offer a short fixed list of top-level keys. It now offers
   every key the schema holds (`device.apply.transport`,
   `backends.tacacs.level`, `linux.uid_min` ...) and the start of each family
   of keys that carries a name (`tier.`, `privileges.`, `snmp_scope.`,
   `blocks.`) with no space after it; once the prefix is typed the groups
   or the scopes of the store follow (`tier.ops`, `snmp_scope.lab.`). The
   list is built from the schema, and a test fails for a family that is
   not decided, so a key added to the schema is completed with no second
   list to keep.

2. **`config validate` warns of keys that name a group or scope the store
   does not have.** `tier`, `wti_level` and `junos` settings of a missing
   group were reported already; the same check now covers
   `privileges.<group>` and `commands.<group>` and every per-scope key
   (`snmp_scope`, `breakglass_scope`, `blocks`, `netconf_scope`,
   `exec_timeout`, `aaa.order`, `tacacs_group`, `radius_group`,
   `scope_auth_method`, `scope_mgmt_acl.*`, `cisco.source_interface`). One
   `Orphan settings:` line names each key; the built-in groups are never
   named, the exit code does not change, and the line says the key is
   removed from `tacctl.yaml` by hand (a group or scope added later under
   the name would take it over). They come from a store import, a restore
   or a hand edit; `group remove` and `scope remove` drop what they own.

3. **The tier notes are a field of the tier table.** The sentences that say
   what a family's help adds to the tier a verb needs (`scope secret`,
   `scope snmp`, `host show`, `device config` ...) were a second list in
   the shell code next to the table; each is now the `Note` of the row it
   explains, and the manual page's TIERS block reads it from there. No help
   text changes.

4. **A re-run of `tacctl install` takes the apply lock.** Over a live
   store it renders and restarts the services as an upgrade does, and
   took no lock, so another command's change could be put back or lost
   between its steps. It now holds the lock from the seed (the store
   check, the configuration step of each backend, the render) to the end of
   the start phase, and waits as the other commands do while another one
   holds it. The builds, the clone, the packages and the service accounts
   before it do not hold it; a fresh install has nothing to wait for.
   Ctrl-C while it waits, there or in `upgrade` after its pull, now says that
   the store, `tacctl.yaml` and the services were not changed and to run
   the command again, not "Nothing was changed.", which was not true of the
   builds and the clone before it.

5. **`config validate` warns of files that belong to a device or scope that is
   not registered.** The records and files of a device's last pull
   (`device-config`), the SNMP credentials of a device (`snmp/devices`) and
   of a scope (`snmp/<scope>.yaml`) are taken away by `device remove` and
   `scope remove`, but not by an import or a restore of the registry or by
   a hand edit; a device or scope added later under that name picks them up,
   or is refused for them. One `Orphan files:` line names each, with the
   command that removes it where there is one. A warning; the exit code does
   not change; an engineer's run, which has no scopes of the leftovers, does
   not print them.

6. **`breakglass hold` and `release` take a list of devices.**
   `tacctl breakglass hold sw1=<reason>,sw2 --reason "<text>"` holds
   several devices in one command (the list is one argument; quote it when a
   reason holds a space), each with its own reason after `=` or
   the `--reason` default (a device with neither is a usage error naming
   it), and `tacctl breakglass release sw1,sw2` releases several. The list
   is best effort: each device is checked as a single one is, the ones that
   pass are held together in one write, one render and one restart of each
   backend, and each refused or already-held device is named with why on a
   `Not held: <name>: <why>` line, in the confirmation and in the report;
   the exit code is 1 when any was not held. The names of the devices that
   pass are typed back, as printed, comma separated. A release names what is
   not held under `Not released:`, releases the rest and exits 1. One device
   is held, asked and reported exactly as before.

7. **A source interface typed inside the server group is named as an older
   form.** `ip tacacs source-interface` under `aaa group server tacacs+ <G>`
   (or the RADIUS equivalent) was listed with the group's other leaves as a
   statement nobody explained. The plan and the diff now say that the group
   has its own source interface, an older per-group form, and that the
   standard sets one for the device. Nothing is rendered or removed
   differently.

8. **The Go tests run in CI.** A `test` workflow runs on a pull request and
   on a push to `develop` or `master`: gofmt, `go vet`, every package but
   `internal/cli` with the race detector, and `internal/cli` (which takes
   over twenty minutes in one run) in four shards, each with and without
   the test knobs. `tests/tools/go-test-shard.sh <index> <count>` runs one
   shard and `--check <count>` fails unless every test is in exactly one.
   The bats suite, the diff corpus and the container matrix stay on the
   maintainer's machine. The actions of both workflows (the release
   rebuild too) run on Node 24 and are pinned by commit.

## 0.2.11 (2026-10-15)

1. **`tacctl group preset roles` shows what each setting changes.** Under every
   setting that is not unchanged, `--dry-run` (and the confirmation of a real
   run) prints the value now and the preset's, the Cisco rules and the Junos
   deny-set patterns removed and added, in the form `group reset` uses; a
   setting that is written without changing what applies says so (the WTI
   level or tier that follows the priv-lvl and is now set explicitly). A step
   that is unchanged prints nothing more. Before, the line said only `set`,
   `kept (pass --force)` or `replaced`.

2. **A session start brings the seen data up to date in the background.** A
   login used to show in LAST SEEN only after someone ran `device scan`.
   An interactive session of the console or of `tacctl shell` (operator tier
   and up) now starts `device scan --if-stale --quiet` as it opens, detached,
   with its output thrown away, under the same sudo rules as the session's
   own lines; nothing a person types waits for it, and `list` and `show` still
   read the cache only. `--if-stale` does nothing when the cache is younger
   than five minutes or another scan holds it (sessions that start together
   run one scan, the others leave at once), and re-scans a device's host keys
   only when its last scan is a day old, so a session start does not touch
   every device; `--quiet` prints nothing. Both are options of `device scan`
   for use by hand too; `--if-stale` refuses `--full` and `--since`. When the
   seen data is an hour old or more (no session has started since), the
   footer of `device list` and the `Last seen` line of `device show` say how
   old it is and to run `tacctl device scan` (a read-only caller is told that
   an operator can).

3. **`tacctl group list` says when no group has the engineer tier.** The
   engineer tier exists only through a tier setting, so an install without
   the role looked the same as one that had decided against it. When the
   table has no group at the engineer tier, one `[INFO]` line follows it
   (for every caller tier) naming the two ways to give it: `group preset
   roles` and `group edit <group> tier engineer`. The line is not printed
   once any group has the tier, nor while a `tier.<group>` setting of
   `tacctl.yaml` is not a tier (`config validate` and the other warnings
   own that).

4. **`config validate` warns about an empty `privileges.<group>` on a
   built-in group that ships a list.** An empty list in `tacctl.yaml`
   (what removing the last mapping once stored) hides the shipped default
   of `readonly` (`show running-config`) and `operator` (`undebug all`). The
   warning is a `Group settings:` line naming the shipped mappings and
   `group privilege reset <group>`, which removes it; the exit code is
   unchanged. `group privilege list` of such a group no longer reads as if
   the group had never been given a list: a second line says that
   `tacctl.yaml` stores an empty list that hides the shipped default.

5. **`config devices` help names the apply transport default as `cli`.**
   The one-line help of `tacctl config devices` said the apply transport
   defaults to `auto`; it is `cli` (`config devices apply-transport`), as
   the manual and the documentation already said.

6. **Tab completion offers the values of `--tier`, `--wti-level`, `--priv`
   and `group edit <group> tier`.** `group add --tier` and `--wti-level`
   and `group edit <group> tier` (with `auto`) take their words from the
   lists the commands validate against, and `--priv` of `config snmp v3-user`
   and `scope snmp v3-user` offers `aes128`, as `--auth` of the same
   verbs offers `sha` and `sha256`.

7. **Every release is rebuilt and compared by a published check.** The
   repository gains its first workflow, `release-reproducible`: when a
   release is published it checks out the tag on a clean runner, installs the
   Go version that tag's `bin/tacctl.sh` names, rebuilds both binaries and
   compares the sums with the published `SHA256SUMS`, whose signature it
   verifies with the tag's own `release/allowed_signers` (no key and no
   secret are involved). It also checks that the rebuilt binaries have the
   test knobs off and the tag's commit stamped in, and it can be run by hand
   for an older tag. The logic is one script,
   `tests/tools/release-reproduce.sh` (`make release-reproduce TAG=<tag>`
   runs it locally), which replaces the second build of `docs/releasing.md`.
   Around it, `make release-verify` also checks both binaries for test knobs
   and commit without running them, and `make release-assets` first checks
   that the release metadata is in place (the dated CHANGELOG heading, the
   man page's `.TH` line, the release notes file). No change to the binary
   or the commands.

8. **The NETCONF limits are documented as the service port's.** A lab run
   showed that `--connection-limit` and `--rate-limit` bound the NETCONF
   service on TCP 830 and not the SSH subsystem that `device config apply`
   and the pull use (seven simultaneous sessions and four applies inside a
   minute were not refused on Junos 25.4 with the limits at 5 and 10). The
   manual page and `docs/cli/scope.md` say so; nothing else changes.

9. **Commands that change the configuration wait for each other.** A
   command that failed put back the whole of `store.yaml`, `tacctl.yaml` and
   `rendered.json` from the copies it took at its start, and with them what
   another command had written in between, which printed success. The next
   change then found the rendered file recorded as hand-edited and was
   refused. Every command that changes the store or `tacctl.yaml` now takes
   one lock, `.store-apply.lock` in the state directory, from before it
   copies the files it may put back to after its last restart: a second
   command prints `Waiting for another tacctl command that is changing the
   configuration...` once and runs when the first is done, and Ctrl-C ends
   the wait with `Nothing was changed.` and exit 1. It covers the store commands, `config render`,
   `config listen|loglevel|metrics`, the RADIUS listener changes,
   `backend enable|disable`, `store import` and `store rollback`, `backup
   restore`, every write of `tacctl.yaml`, and `upgrade` after its
   self-update. A file that was edited by hand while a command ran is saved
   as `<file>.overwritten-<stamp>` in the state directory (and named in a
   warning) before the command puts its own copy back. A read command takes
   no lock.

10. **`config validate` names what an interrupted command left behind.** A
    command that is killed while it changes the configuration leaves a
    private copy of `tacctl.yaml`, usually with `store.yaml` (secrets
    included), in the state directory: `.apply.*`, `.restore.*`, `.enable.*`,
    `.units.*` or `.disable.*`. When one is older than ten minutes and no
    command holds the apply lock, `config validate` prints a `Leftovers:`
    warning naming it and what to check before removing it. The exit code is
    unchanged.

## 0.2.10 (2026-10-15)

1. **`tacctl scope netconf` and `tacctl device netconf`: the NETCONF service
   of the Junos devices, per scope with a per-device override.** Three states:
   `enable` (`set system services netconf ssh`, with `--connection-limit <n>`
   and `--rate-limit <n>`, 1 to 250 each, `none` to remove one), `disable`
   (`delete system services netconf`) and `leave`, the default, which plans and
   compares nothing of the service, as before. `scope netconf <scope>` with
   `leave` removes the scope's setting and with `disable` drops its limits.
   `device netconf <name>` takes the device's own word over its scope's: `leave`
   leaves the device alone whatever its scope says, `clear` gives the decision
   back to the scope, and the state and each limit layer on their own, the
   device's value over the scope's. `show` (or no word) prints the setting and
   where each value comes from, `device netconf --apply` runs `device config
   apply` for the device as the other setters do, and `device show` has a
   `NETCONF` row (and `--json` a `netconf` object) for a Junos device whose
   setting is not the default. Both verbs are the superuser's. The scope's
   values are `netconf_scope.<scope>.state`, `.connection_limit` and
   `.rate_limit` in `tacctl.yaml`, and follow the scope on rename and removal;
   a device's own is the optional `netconf:` map of its entry in
   `devices.yaml`, refused for a device of another vendor, and removed with a
   warning when `device vendor` makes the device one. A 0.2.9 binary does not
   know the keys and its `devices.yaml` reader refuses the map.

2. **The walkthrough, `device config pull`, `diff` and `list` follow the
   setting.** For `enable` the Junos walkthrough's NETCONF step is live: the
   statement, or the limits' statements when a limit is set (a limit's
   statement creates `ssh` and the device prints no bare `ssh` beside it), and
   `netconf` is a section like the others: compared by statement, with what
   the device holds under `system services netconf` beside them (a trace
   option, the SSH port, a limit the setting states none of) shown as
   unmanaged and kept, and a limit with another value a difference. For
   `disable` the step is a live `delete system services netconf` and the
   section expects nothing under the hierarchy: every statement the device has
   there is a difference. `leave` is the commented step and no section, byte
   for byte as in 0.2.9.

3. **`device config plan` and `device config apply` write the setting.** The
   `netconf` section is planned where the setting is `enable` or `disable`
   (`--section netconf` names it; it is refused with the setting to make where
   the scope leaves the service alone): `set system services netconf ssh` and
   the limits, or the one statement `delete system services netconf`, and
   nothing else under `system services`, the delete of a limit included. The
   statements are held against the rendering before the first is typed, as
   every other statement is: `set` of what the section renders and `delete` of
   the service only when the setting disables it; the rest of `system
   services`, the SSH service among it, stays on the list of what is never
   written. The plan warns that disabling the service ends it for every NETCONF
   client of the device, and its back-out types the service again.

4. **`device config apply` writes over NETCONF where the device offers it
   (`--transport auto|cli|netconf`, `config devices apply-transport`).** The
   check and the apply of a Junos device go over the NETCONF subsystem when
   the device's last read found it answering and the login may commit, and
   over the command line otherwise, when asked for: NETCONF is opt-in and
   `cli`, the default, is what 0.2.9 did. `auto` says why a device was not
   taken over NETCONF (`[via cli: NETCONF port closed at the last read]`; a
   device never read says nothing);
   `netconf` never falls back, and a device that does not answer or cannot
   confirm is failed. `--transport` of one run replaces the setting
   (`device.apply.transport`, a superuser's, written only when set). Over
   NETCONF the change is loaded under the candidate's lock (a Junos device
   refuses a confirmed commit in a private session, and a locked candidate
   that holds another editor's staged change is refused), checked, committed
   under a confirmed commit and confirmed by the session that made it; a
   session that closes or dies without confirming leaves the commit pending
   until the window ends, as over the command line (a failed verification
   is cancelled at once while tacctl runs), and the fresh login proves the
   device through NETCONF as before. A change to the NETCONF service itself (`scope netconf`, `device
   netconf`) is always made over the command line, because its verification
   depends on the service: `auto` takes the command line and says so,
   `--transport netconf` refuses it. The device's line, the JSON (`via`,
   `via_reason`) and the record (`applied.via`) say which transport ran; a
   read through NETCONF also records the hello. A 0.2.9 binary does not know
   `device.apply.transport`.

5. **A change to the NETCONF service is proved by a NETCONF probe before it
   is confirmed.** After the fresh login and before the confirming commit,
   an apply that enables the service must be answered by a NETCONF hello as
   you, and one that disables it must find the hello no longer answered
   (`port closed` or `no hello`); a probe that cannot tell is a failed
   proof, and a failed proof rolls the change back. The line says
   `[NETCONF verified: hello ok]` or `[NETCONF verified: not answering]`
   (the JSON has `service_proof`), and the record's NETCONF probe becomes
   what was proved, so `device config list` and the next apply see it at
   once; a rolled-back change leaves the record's probe as it was and the
   reason says so. A NETCONF fresh login that sees no pending confirmed
   commit names the history it read, not a prompt.

6. **`tacctl rollback 0.2.9` prepares the state for the release before this
   one.** It is the dry run it always was until `--apply`, which takes a
   snapshot and then removes `device.apply.transport` and the
   `netconf_scope` keys from `tacctl.yaml` (the dry run warns with their
   values and `--apply` refuses without `--yes` while one is set) and the
   `netconf:` map of every device from `devices.yaml`, so a 0.2.9 binary's
   `config validate`, `backup restore` and device registry read the files.
   What 0.2.9 ignores is left and listed: the `via` field of the apply
   records. 0.2.10 changed no sudoers text, so no drop-in is rewritten.
   `rollback 0.2.3` removes the same settings on its way, and the refusal of a
   rollback while an apply is not settled stands for both targets. `0.2.8` is
   no longer a target: the way is this rollback, the install of 0.2.9, then
   0.2.9's own `tacctl rollback 0.2.8`, and the refusal of `0.2.4` to `0.2.8`
   says so.

7. **`tacctl version --long` is laid out as a title card and a list of
   facts.** The first line is the version, as `tacctl version` prints it; the
   project's name, the address and licence, and the copyright follow on
   their own lines, and the facts (commit, build date, Go version, test
   knobs) come after a blank line with their values aligned; no line is wider
   than 62 columns, where the old copyright line wrapped on an 80-column
   terminal. The build date is the commit's date shown as `2026-10-14 15:34
   AKDT` in the local time zone. The field labels (`commit:`) and the short
   `tacctl version` are as before.

## 0.2.9 (2026-10-14)

1. **`config devices apply-confirm-timeout` and `apply-pause`.** The two
   settings of `device config apply`: `device.apply.confirm_timeout`, the
   minutes of its `commit confirmed` (3 to 60, default 10: a window under three
   minutes cannot hold the verification), and `device.apply.pause`, the seconds
   it waits between the devices of a batch after the canary (0 to 3600, default
   60; 0 is none). Both are the superuser's, are written to `tacctl.yaml` only
   when set, are checked by the schema (`config validate` reports a hand-edited
   value out of range) and appear in `config devices` with the others. A 0.2.8
   binary does not know the keys; `tacctl rollback 0.2.3` removes them with the
   other keys the older release lacks and says so.

2. **The sudoers drop-ins keep `TACCTL_ASKPASS` for `device config apply`,
   `device onboard` and `device collect`.** The password cache's alias in the
   per-tier drop-in and in the group drop-in gains the three command lines, so
   the shell's cache answers the logins they make (`device config shapes` logs
   in to nothing and is not among them). The cache answers a `device collect`
   line for your own login and is left shut for one with `--login`, which never
   has it. The drop-ins' bytes change: `upgrade` rewrites a tiers file that
   differs from this release's rules and a group drop-in that is exactly
   0.2.8's text, as for every earlier change, and `rollback` knows 0.2.8's
   texts as older ones. The rows are unchanged: `device config apply` and
   `device config shapes` are the superuser's (the engineer's `device config`
   rows name `show`, `pull`, `diff` and `plan` only, and the verb holds every
   lower tier back as well), so no sudoers line is added for a lower tier.

3. **`device add --pull` reads the device's configuration as it registers it.**
   `tacctl device add <name> <address> --vendor cisco|juniper|wti --pull`
   registers the device as before and then runs `device config pull` for it, as
   the invoking user, in the same command; the pull's output follows the add's
   report. The flag is off by default and asks nothing. It is refused before
   anything is registered when the caller's tier may not run `device config
   pull`, when run as root, or when the vendor is not one the pull reads. A
   device no scope's prefixes cover is registered and not pulled, with one line
   that names `tacctl scope prefixes <scope> add <cidr>` and the pull command.
   A pull that fails leaves the device registered and the command exits with
   the pull's status. The manual page, `docs/cli/device.md` and
   `docs/devices/connecting.md` describe it.

4. **`device config apply`: the plan, typed into Junos devices by tacctl.**
   `tacctl device config apply <name>[,<name>...] | --all | --scope <scope> |
   --vendor juniper` is the superuser's step after `plan`: it writes the same
   statements itself instead of a paste. It logs in as you (the password is
   asked once and never stored), reads each device, loads the plan in an
   exclusive configure session, runs the device's own `commit check` and
   discards the candidate; `--check` ends there and commits nothing. The
   devices that need a change are then shown grouped by shape and by what the
   review shows of each (the same change under one heading, every secret
   elided, a per-device value printed for each device, what the plan keeps and
   what it leaves out; two devices whose warnings, sections left out, kept
   statements or not-found deletes differ are two headings) and ONE question is
   asked, answered by typing the device's name (one device) or the number of
   devices back; there is no answer without a terminal except `--confirmed
   --yes`. A device whose plan refuses a section (what makes `device config
   plan` exit 1) is not applied and is a failure, with the reason. At the start
   of each device's apply the break-glass hold, the registry entry and the
   scope that covers it are read again: a device held, changed or no longer
   yours since the review fails and nothing is sent. Each device is committed
   under `commit confirmed` (`config devices apply-confirm-timeout`), proven by
   a fresh login as you, by what landed being the change the check showed and
   by a read of the planned sections, and then confirmed; a failed proof rolls
   the change back, and a device whose state could not be read is reported
   `PENDING until <time>`: nothing may be typed on it before then, and the next
   `apply` of it reads its commit history before anything else. The record says
   `pending` from the moment the confirmed commit is typed, so a tacctl killed
   during the verification leaves a record the next run settles; a record that
   cannot be written then is said at once in red on standard error. Never
   written: `breakglass`, `netconf`, the root account and yours, `system
   services`, `interfaces`, groups; the statements are held against the
   planner's own ownership tables before the first one is typed. `--section`,
   `--hold` (keep the change only when you type `OK` after logging in with one
   account of each class; it needs a terminal and is refused with `--json`,
   exit 2), `--server`, `--source`, `--concurrency`, `--timeout`,
   `--max-failures` and `--json` (one object per device and phase, then the
   summary) are the options. Exit status: 0 every device applied, was checked
   or had no change, 1 a device failed, was rolled back or is pending (or the
   run applied none of its devices and found none already applied: `--confirmed
   --yes` that skipped them all), 2 wrong arguments (with `--check
   --exit-code`, a device that needs a change), 130 interrupted (the first
   Ctrl-C starts no more devices, the second cancels the running ones: a
   candidate is discarded, a pending commit is cancelled where the window
   allows). A Cisco device or a WTI unit named is refused with the reason and a
   selector leaves them out. Audit lines carry the user, device, change
   identifier, shape and result, never a value; the approval's line names the
   canary of each shape (`none` with `--no-canary`). The manual page,
   `docs/devices/planning.md` and `docs/cli/device.md` describe it.

5. **Shapes, `--confirmed`, `--max` and `device config shapes`.** Two devices
   that need the same change have the same shape (a hash of the statements with
   each secret elided and each per-device value, such as a location, masked).
   The first device of every shape is applied alone and the rest of its shape
   follow only when it applied (`--no-canary` starts them together; `--pause`
   or `config devices apply-pause` waits between devices). `--confirmed`
   applies only shapes an earlier apply confirmed and skips the others
   (`unknown shape <hash>: review and apply it by hand first`), and is the one
   form `--yes` answers the review of, so a script runs a batch without a
   terminal; `--max <n>` (default 5) caps the devices of every apply run.
   `tacctl device config shapes [list [--show <hash>] [--json]]` lists the
   shapes seen, which are confirmed, on which devices, and for a new one the
   nearest confirmed shape; `shapes seed <name>[,<name>...] [-y]` files the
   shape of a device's last check or apply as confirmed on your word (one
   question), for a device applied and verified by hand. They are the
   superuser's and contact no device; the store is
   `/var/lib/tacctl/device-apply/shapes.json` (0600: statements with values
   elided).

6. **What an apply leaves in the record.** The `applied` part of a device's
   record in `devices-config.json` (version 1, fields added) holds the last
   check or apply: when, by whom, the change identifier, the result (`checked`,
   `applied`, `rolled-back`, `pending`, `failed`, `unknown`), the reason, the
   end of a pending window, the shape, the planned sections, the statement
   counts, the confirming commit and the fingerprint of each planned section
   before the change; never raw device output and never a secret. Every read an
   apply makes refreshes the pull part of the record (the read after a
   confirmed apply is the picture `device config diff` then shows). `device
   config list` gains an `APPLIED` column once a listed device was checked or
   applied (`checked`, `applied <time>`, `PENDING <time>`, `rolled-back`,
   `failed`), its `--json` and `device show --json` gain `applied`, and the
   Configuration row of `device show` ends with `apply: ...`, in red and with
   what must not be typed for a pending commit. `device config forget` removes
   it with the pull record.

7. **The Junos plan's region types `configure exclusive`.** A private session
   cannot `commit confirmed` on Junos 25.4 (`error: commit confirmed not
   supported for private configuration`), so a pasted plan never reached its
   confirmed commit and nothing was committed. The plan, cleanup (`--converge`)
   and `--backout` regions now open with `configure exclusive`, which takes
   `commit confirmed` and is refused with `error: configuration database
   modified` when another session has uncommitted changes, or `error:
   configuration database locked by: <name>` when another session holds the
   lock. The region's report and follow-up say that the session holds the
   configuration lock until `exit` (typed after `commit`), and what to do when
   it is refused; the whole-paste check refuses a region that starts with
   `configure private`. The manual page and `docs/devices/planning.md` describe
   it.

8. **A setting that changes the rendered configuration says so.** After `device
   location`, `description`, `address`, `config-syntax` or `vendor` stores a
   value that is rendered, and the device has a stored pull that `device config
   plan` would now change, the verb prints one line: `The configuration of
   <name> would change: tacctl device config apply <name> --check` (`device
   config plan <name>` for a device that is not Junos, or for a caller who is
   not a superuser). The line is made from the stored pull alone: no login, no
   network, and nothing for a device that was never pulled, whose pull is
   stale, or that cannot be planned. `device rename` says the device's own host
   name is unchanged and not planned by tacctl; `port`, `legacy-ssh` and
   `hostname` say nothing about the configuration. A change that writes what a
   scope's devices are rendered from (`scope prefixes`, `secret`, `mgmt-acl`,
   `snmp`, `block`, and the protocol, AAA order, timeout and group settings)
   prints the same line for the scope (`tacctl device config apply --scope
   <name> --check`) when at least one of its devices has a stored pull that
   would change.

9. **`--apply` on `device address`, `description`, `location` and
   `config-syntax`.** After the value is stored, `--apply` runs `device config
   apply` for that one device in the same command: the same review, answered by
   typing the device's name back and never skipped, and the confirmed commit.
   It is the superuser's, for a Junos device and at a terminal; otherwise it is
   a usage error before anything is changed. A value that is already set
   changes nothing and applies nothing, and the exit status is the apply's.
   `--apply` with no value, or with `location --from-device`, is refused.

10. **`device onboard`: a blank Junos device brought in with one of its local
    accounts.** `tacctl device onboard <address> --login <local-user>` is the
    superuser's. Any local account may be named, a break-glass account
    included; only `root` is handled apart (its csh wrapper). The host keys the
    address offers are shown and one question is asked before any login
    (`--host-key SHA256:<fp>` answers it; without a terminal and without it the
    run is refused, and without a terminal only `--check` runs). `--login` may
    not name your own login, and `--section` must include `aaa`. As the local
    account (its password asked once on the terminal, never kept or cached) the
    pre-flight reads the release, a pending commit, the login's class, whether
    a TACACS+ or RADIUS server is there already (`system tacplus-server`,
    `radius-server` or `accounting destination tacplus|radius server`, also in
    a group: then refused, such a device is reached by the normal flow) and
    whether a local account of your own name is there (then refused: a login as
    you could be that account's). The device is registered through `device add`
    with the keys shown (`--name`, else the name it reports, else asked), its
    own location and description fill the empty fields (its host name never
    fills the registry's `hostname`, which ssh would dial instead of the
    address), its read is recorded as a pull made as the local account, and the
    ordinary planner's first-time plan is checked on the device; `--check`
    stops there. After the review (the device's name typed back) your own
    password is asked and the change is committed as the local account under
    `commit confirmed`; every session after the commit, every read included, is
    your own TACACS+ login, which proves the change before it is confirmed in
    the held session: its `show cli authorization` must name the template user
    your group's class renders, with that class, never a local account. A
    refused or wrong fresh login rolls it back and leaves the local account as
    it was. Afterwards the local account is never tried again, `root`
    included (a login would send its password to the TACACS+ server): the
    run says it was not probed, and `--json` has `probe` with `not-probed`. What the device reports is shown with its control characters
    replaced. The plan never holds the break-glass accounts, root or the local
    account. `--legacy-ssh` (also taken by itself when the handshake needs the
    legacy algorithms), `--section` and `--json` (one object at the end).
    Logged: `device onboard user= device= addr= login=local:<account> result=`,
    never a password.

11. **`--login <local-user>` on `device config pull`, `diff --pull` and `plan
    --pull`.** A superuser reads one registered Junos device with a pinned host
    key, whose address a scope answers, as one of its local accounts instead of
    their own login: for a device the server does not answer yet. Any local
    account may be named, a break-glass account included; only `root` is
    handled apart. One device by name only (a list, `--all`, `--scope`,
    `--vendor` or `--stale` is a usage error); an engineer with the flag is
    refused by the tier gate, and a device on which break-glass is held is
    refused (release it first), as for every pull and for `device onboard`. The
    password is asked once on the terminal, sent to the one connection and
    never stored in, asked of or forgotten by the password cache. `root` is
    accepted only for a device never read as the invoking user (a pull record
    file that cannot be read refuses it), through the remote command `sh -c
    'PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin; exec cli'` (root's shell is a
    csh), over the ssh command line only. The record says
    `login=local:<account>` (the pull records' file gains `login` and
    `user_pulled`, which 0.2.8 ignores), and the pull is logged as `device
    config pull user= device= login=local:<account>`.

12. **`device collect`: what an address nobody registered is, with one login.**
    `tacctl device collect <address>... | --discovered` (a superuser, Junos
    devices) is the login before the registration, which the registry forbids
    today (no pinned key, no entry). For each address no registry entry holds
    it reads the host keys (nothing is authenticated), shows them with their
    fingerprints and asks ONE question before any login (`--host-key
    SHA256:<fp>` names the key of one address instead; without a terminal one
    of the two is needed); then, in one session per address, `show version` and
    the pull's read command, and nothing else. The login is yours (the password
    cache may answer it) or, with `--login <local-user>`, one local account for
    the run (the one-shot password of item 11: asked once, never kept or
    cached, sent to each address once; `root` through its csh wrapper). The
    first refusal of the password ends the run, and an address whose `show
    version` is not a Junos answer is listed `not-junos`, its session closed
    and never registered. The result is one table (address, host name, model,
    release, authentication order, servers, `EN-CLASS`, NETCONF, `lo0` filter,
    legacy ssh, result) and the `device add` line each device would run;
    `--json` prints one object. `--register` asks one question and then
    registers each device through `device add` (the same code as every
    registration) with the keys shown pinned and `--legacy-ssh` where the
    handshake needed it, and keeps the read as the device's first pull record,
    as a pull makes it (`login=local:<account>` for a local login), so `device
    sync` and `device config plan` have a record at once (`-y` answers the
    question; without a terminal it is needed). Refused before anything is
    sent: an address a registry entry holds, one no scope answers, one with
    break-glass held, and (for your own login) a caller who is not an active
    member of the scope. `--discovered` takes the addresses `device discover`
    lists from the seen cache. Logged: `device collect user= addr= login=
    result=` per address, never a password or a device's text.

13. **`device sync`: the registry's empty fields from the pull records.**
    `tacctl device sync <name>[,<name>...] | --all | --scope <scope> | --vendor
    <vendor> [--apply] [--overwrite]` (a superuser; no login) fills a Junos
    device's empty `hostname`, `location` and `description` from what its last
    pull record says the device holds (`system host-name` with its
    `domain-name`, `snmp location`, `snmp description`). The preview is one
    table of the fields (what the registry has, what the device says, the
    action: `fill`, `same`, `keep`, `replace`, `none`, `refused`) and one of
    the record's facts (login, model, release, serial number, which are the
    record's and not written). `--apply` writes after one question (`-y`;
    without a terminal it is needed) in ONE registry write under the registry's
    lock, each field checked again against the live file so a value set since
    the preview is kept, and never as an import of a re-serialised file.
    `--overwrite` replaces a field that is set and shows the old value; the
    name, address, vendor and scope are never touched. A value with control
    characters (a newline, a terminal escape), one the registry would not
    accept from a person, and a host name that is not a DNS name (no
    `domain-name`: a bare label is not an address tacctl can connect to) are
    listed `refused` and never written; text a device reports is shown with
    control characters as `?`, cut at 64 characters. A host name is filled only
    when the system resolver answers it with the device's registered address
    and no other (the registry's `hostname` is where tacctl connects, so a name
    the device merely reports must not redirect later logins): a failed lookup,
    a different address or extra addresses are listed `refused: does not
    resolve: not filled`, and `--overwrite` never replaces a hostname with such
    a name. Logged: `device sync user= devices= fields=` when fields were
    written.

14. **A pull record keeps the device's host name.** The record of a Junos
    device gains `hostname` (`system host-name`, with `domain-name` appended
    when the name has no dot), read from the configuration the pull already
    has, for `device sync`; 0.2.8 ignores the field, and a record made before
    this release has none until the next pull.

15. **`tacctl rollback 0.2.8`.** The rollback takes the release before this one
    as a target as well as `0.2.3` (which works as before). A dry run unless
    `--apply [--yes]`: it removes `device.apply.confirm_timeout` and
    `device.apply.pause` from `tacctl.yaml` (a 0.2.8 binary refuses them; the
    dry run warns with the values and `--apply` needs `--yes` while one is
    set), rewrites the per-tier and group sudoers drop-ins that are exactly
    this release's text with 0.2.8's, after `visudo -cf` (an edited one is left
    and named), and lists, without deleting, what 0.2.9 left that 0.2.8
    ignores: the `applied` parts and the `login`, `user_pulled` and `hostname`
    fields of `devices-config.json`, and the apply state directory
    (`device-apply/`: the shape store and the device locks). Both targets are
    refused, the dry run too, while a record says a confirmed commit is
    `pending` or `unknown`: the refusal names each device and time and the
    command that settles it (`device config apply <name> --check`, or `device
    config forget <name>`). `0.2.4` to `0.2.7` are refused with the
    one-release-at-a-time rule. The output ends with `tacctl upgrade --branch
    0.2.8`, and the audit line is `rollback target=0.2.8 keys=<n> by=<user>`.
    `rollback 0.2.3` also lists the apply state it leaves. The manual page and
    `docs/install/upgrading.md` describe it.

16. **A leading `tacctl` is dropped in the shell and the console.** A line
    pasted from the help or the documentation, `tacctl device list`,
    `sudo tacctl device list` or `/usr/local/bin/tacctl device list`, runs
    as `device list`; Tab, `?`, a typed space, `help` and the `-c` guard of
    the console see the same words, so they cannot disagree. Only the first
    word (and `sudo` before it) is dropped, once: `tacctl` later in the line
    is an argument. A line that is only `tacctl` prints the top-level usage
    exactly as `tacctl` with no arguments does, and ends with status 1. The
    history keeps the line as typed and redacts what follows it as before.
    The manual page, `docs/cli/shell.md` and `docs/security/login-console.md`
    describe it.

17. **A device that answers a login slowly no longer fails the pull.** The
    ssh client types an empty line to learn the device's prompt and, when
    nothing comes back in a quiet period, types it once more. A device that
    answered both lines late was refused with "the prompt cannot be told from
    the banner"; the answers are now counted against the lines sent, and a
    device that stays silent is given ten quiet periods before the login
    fails.

18. **A Junos device with a saved rescue configuration can be checked and
    applied.** The `rescue <time> by <user> via <how>` line that `show system
    commit` ends with in that case was refused as an unknown line; it is now
    read as a marker that is no history entry, and any other unknown line is
    still refused.

19. **`device config apply` reads a compare that adds an entry beside existing
    ones.** A Junos compare prints the unchanged neighbours of an added name
    server, NTP server, community, trap target or filter term as context
    (`<entry> { ... }`), which failed every check of such a change and named
    the wrong reason at the staged-changes gate; context lines are now skipped
    inside a hunk and are never a change, and any other unknown line is still
    refused.

20. **A pending apply is settled from the device's own rollbacks.** When the
    commit after tacctl's is the device's rollback (`by root via other`) or
    someone else's, `show configuration | compare rollback N` against
    tacctl's commit and the one before it decides `applied` or `rolled-back`,
    and anything else is `unknown`; a rendering changed since the commit no
    longer turns a rollback into `applied`. The settled result is printed
    above the device's line and logged (`device config apply settle`).

21. **The help title no longer names the backends.** The first line of
    `tacctl --help` and the manual's NAME line describe tacctl as pluggable
    network-device AAA management; the backends are interchangeable and are
    no longer named in the title.

22. **`device config apply` reads a change of one element of a Junos list.**
    Junos prints a change of one element of a bracket list (`system
    accounting events [ ... ]`, `system domain-search [ ... ]`) as the whole
    list removed and added, so the elements on both sides were taken as
    changes outside the delta and every check of such a change failed. An
    element shown both removed and added at the same path is now no change;
    only the net elements are held against the delta, in the check and in the
    landed compare. An element added or removed by someone else, a list whose
    kept elements change order, a hidden secret and an annotation are still
    changes.

## 0.2.8 (2026-10-13)

1. **The documentation is a tree of topic pages.** `README.md` holds the
   quick start and an index; the reference is under `docs/` by topic
   (`install`, `server`, `security`, `hosts`, `devices`, `cli`,
   `development`), each folder with its own README. The pages are in the
   project clone (`/opt/tacctl/docs/`).

2. **tacquito's authentication lines carry the client's address and port.**
   Patch `0003` (now `0003-authen-log-addresses.patch`) appends what the
   authentication start packet holds to the `accepting user` and `failed to
   validate the user` lines: `... from [<device or host>] using a bcrypt
   password; client [<address>] port [<port>]`. A device fills in the address
   of the person logging in, and `sshd` on a host does through PAM; a `sudo`
   prompt on the server itself gives none, and the fields are left out. The
   `from [...]` part and its readers (`device scan`, `log`) are unchanged.

3. **`ssh` audit lines say where the caller logged in from.** The `auth.info`
   and `auth.warning` lines of `tacctl ssh` and `device ssh`, and the block
   editor's refusals, gain `from=<address>`: the first field of
   `SSH_CONNECTION` when the environment has it, else the host of the login
   record of the terminal (sudo removes `SSH_CONNECTION`; sshd records the
   client there). The field is omitted when it cannot be told.

4. **The restore point is marked as unchecked only in its `archive config`
   form.** The copy form (`--restore-point=<fs>`) and the back-out's
   `configure replace <file> force` ran on IOS 12.4(15)SW, IOS 15.6(2)T and
   IOS-XE 16.7 without `archive` configured: the file was written, the pasted
   region converged, and the replace returned the access list to its first
   state. The report's "not lab-tested" note and the "tried only on devices
   with `archive`" caveat are gone for that form; the bare form keeps its
   note, and `copy <file> running-config` is still described as a merge.

5. **`install` and `upgrade` no longer put a copy of the README into
   `/etc/tacquito`.** That directory is the daemon's; tacctl's documentation is
   in the project clone (`/opt/tacctl/docs/`). The first upgrade removes the
   copy an earlier release left there (`Removed: README.md`).

6. **A pull records the release, model and serial number of the device.** What
   a device reports about itself is kept with the last-pull record (replaced by
   every good pull, never in `devices.yaml`): the release (a Junos device's
   `show version` `Junos:` line, else the configuration's `set version`; the
   `Cisco IOS Software ... Version X,` line of the version output a Cisco pull
   already reads; a WTI unit's command menu version), and the model and serial
   number from more commands in the same session (`show chassis hardware` and
   `show version` on Junos, `show inventory` on IOS and IOS-XE). A device that
   refuses one is pulled all the same with the field empty, and a command that
   stalls takes the pull at most 15 seconds more; no extra login. `device show`
   has `Release:`, `Model:` and `Serial:` rows after the Configuration row,
   `device config list` a `RELEASE` column, and `--json` of both (and `device
   list`) the fields `release`, `model` and `serial` (`release` in `device
   config list`); the operator tier and up see them, as the Configuration row.

7. **A Junos walkthrough follows the device's recorded release for the idle
   timeout.** `set system login idle-timeout` exists from Junos 16.1; the
   walkthrough of a registered device (`device config show`) whose last pull
   recorded an older release sets the timeout on each login class instead. A
   device with no recorded release gets the global statement, as before. The
   statements a release lacks are kept as rows of one table
   (`internal/devices/gates.go`), added when a device refuses one. The compare
   and the plan leave the idle timeout out in both forms.

8. **IOS block lines were run on three releases; the compare reads IOS's
   default zone.** The system and snmp block lines (banner, domain name and
   list, name servers, NTP servers, community, trap host, `enable traps`, trap
   source) were pasted and read back on IOS 12.4(15)SW, 15.6(2)T and IOS-XE
   16.7.1. `clock timezone UTC 0` is the default zone and no release prints
   it: the rendered line now reads as present on a device with no `clock
   timezone` statement (it read `differs` for good). The report's "not
   checked on a device" note for the blocks is now only for a system block
   with NTP key lines. IOS 12.4 stores an `ntp server <host> version 3`
   without the option: for a device in the IOS 12.x syntax the walkthrough,
   the managed `system` section and the plan type and compare the line
   without `version 3`, and every other option and version stays; the block's
   text, `show`, `check` and `adopt` are unchanged, and other devices get the
   line as typed. The restore point's caveat says that a 12.4 `configure
   replace` can stop at an `ntp server` with options.

9. **The IOS `system` and `snmp` blocks take the VRF forms and the `informs`
   host kind.** `ntp server vrf <name> <host> ...`, `ip name-server vrf <name>
   <address> ...`, `ip domain name vrf <name> <name>` and `ip domain list vrf
   <name> <name>` in a system block, and `snmp-server host <address> [vrf
   <name>] [informs|traps] [version 1|2c] <community> ...` in an snmp block,
   are statements of the block (SNMPv3 stays refused, and `informs` needs
   `version 2c`, which `check` enforces). The vrf is part of the object: a
   line with it is satisfied by no line without it and the other way round,
   `ip domain name` is one per vrf, and a `no` line names the vrf it takes
   out. A trap host is the entry IOS keeps: one object per address, vrf,
   kind, `udp-port` (162 is the default) and community. One address as traps
   and as informs, or on two ports, is several hosts, which a block states one
   line each, `adopt` takes as they are and a device's own beside the block's
   stay kept and listed; the version and the notification types are
   attributes, replaced in place when they differ (this also holds for a
   0.2.7 block: a host the block states on another port than the device's is
   typed beside it, no longer in its place). The compare reads the stored
   forms of IOS 15.6 (a vrf's name servers one line each) and IOS-XE 16.7
   (one line), and the two blanks IOS prints before `config` in `udp-port
   1162  config`. The plan's undo of a trap host is `no` and its line up to
   its `udp-port`, without the types (`no snmp-server host <address> C` does
   not take away an informs host or one with a `udp-port`); a vrf statement
   is undone as `no ntp server vrf <name> <host>`, `no ip name-server vrf
   <name> <address>`, `no ip domain name vrf <name>` or `no ip domain list vrf
   <name> <name>`. A device's own `ip domain name` is kept when the block
   states only a vrf's. `check` notes each vrf a block names: tacctl does not
   create one, and the device refuses a line that names one it lacks. The
   report words name the vrf (`the NTP server <host> in vrf <name>`), and a
   device's host of another vrf, kind or port is reported as its own entry.

10. **Colour appears only on a terminal, and `NO_COLOR` and `TACCTL_COLOR`
    decide it.** Output was coloured whatever it went to; a pipe or a file
    held escape sequences. Now each of standard output and standard error is
    styled only when it is a terminal and `TERM` is neither empty nor `dumb`.
    `TACCTL_COLOR=always` styles both even into a pipe, `TACCTL_COLOR=never`
    neither, and either wins; otherwise a non-empty `NO_COLOR` means never.
    The `[INFO]`, `[WARN]` and `[ERROR]` lines (they carry their word) and the
    bold titles of the listings follow the rule; the decision is made once
    per process, and a program tacctl starts keeps the terminal it is
    attached to. The sudoers drop-ins (per-tier and group) keep the two
    variables through sudo: their `env_keep` line is now `SSH_AUTH_SOCK
    TACCTL_CONSOLE DISPLAY NO_COLOR TACCTL_COLOR`, and `tacctl upgrade`
    rewrites a group drop-in that is exactly the text 0.2.7 or an earlier
    release wrote (an edited one is left, with the warning that names
    `config sudoers install <group>`) and the per-tier drop-in as before.
    Without a drop-in, a user's `NO_COLOR` is not seen under sudo and the
    terminal decides; the login console decides by its terminal only.
    `rollback` to 0.2.3 puts 0.2.3's text back over both forms.

11. **`tacctl help` says what tacctl is and where it lives.** The title line
   reads "Network-device AAA from one store: TACACS+ (tacquito) and RADIUS
   (FreeRADIUS)", a second line names the copyright holder, the licence and
   the project address, and the last line points to the manual page and
   `/opt/tacctl/docs/`. `version --long` ends with the copyright, licence and
   address line; `version` is unchanged.

12. **`version --long` no longer asks for a password.** The per-tier sudoers
   drop-in listed `tacctl version` and not `tacctl version --long`, so a
   caller through `sudo` (the shell, the console) was asked for a password for
   the longer form. The drop-in lists both; the first upgrade rewrites an
   unedited drop-in.

13. **Help text and the shell's `?` listing are highlighted on a colour
   terminal.** Verbs and listing labels are bold, option names and
   placeholders cyan; the plain text is the same bytes. The same colour rule
   as the `[INFO]` and `[WARN]` lines applies.

14. **Go 1.27.2.** The toolchain `install` and `upgrade` fetch and verify, and
   the one tacctl is built with, is Go 1.27.2 (`go.mod` says `go 1.27.0`). The
   Python 3.12 `repr` that the configuration reader reproduces now uses
   CPython's own printable-character table (Unicode 15.0) instead of the Go
   toolchain's, so what tacctl prints no longer moves with a Go release.
   An upgrade that has to build tacctl from source on a host whose Go is
   older than the tree needs (a branch, or a release binary that cannot be
   verified) installs the toolchain first; before, the build stopped at
   `go.mod requires go >= 1.27.0`.

## 0.2.7 (2026-10-12)

1. **The break-glass section compares login names without regard to case, and says so.**
   A scope's break-glass user `NetEngineer` and a device whose account is
   `netengineer` were reported as one missing and one extra user. They are now
   one account for the section's state, which reads ok, with a note under the
   section: `login user 'netengineer' on the device is 'NetEngineer' in the
   scope: the names differ only in case, and they are case-sensitive on the
   device, so a login by the scope's spelling is refused there`. Junos and IOS
   login names are case-sensitive, so the note stays until the record or the
   device is changed (`tacctl scope breakglass <scope> add <name>`). A device
   that has the rendered spelling as well keeps the other spelling as an extra,
   and only the break-glass section is affected (IOS `username` lines and Junos
   `system login user` statements).

2. **SNMP community and trap-group names are told apart in the compared form,
   not all elided to `<secret>`.** Every community name read from a device was
   one mark, so another community's `authorization` looked like tacctl's own,
   and a leaf under a community could not be attributed to one. A name is now
   elided to a label that says whose it is and never holds the string:
   `<secret:N>` for the N-th community of the scope's rendering (in the order
   of the rendering) and `<other:N>` for the N-th other string on the device
   (by first appearance). One string has one label throughout a pull, a Junos
   `trap-group` name (the community its traps are sent with) and the community
   word of an IOS `snmp-server host` included. `device config diff`,
   `pull --diff`, the plan's report and its `--json`, and the stored sections
   show the labels (`+ set snmp community <other:1> authorization read-only
   (present, not compared)`, `- snmp-server community <secret:1> RO
   TACCTL-SNMP`). The labels are relative to the rendering the pull was
   compared with: after a scope's community is changed, pull the device again.
   A record made by an older tacctl (the bare `<secret>` for every name) still
   loads and compares: its communities are compared by presence, a note under
   the section says so, and `device config plan` leaves every statement under
   a community of that record alone (`the community's name is not visible`),
   with a line that says to pull the device again to plan them.

3. **The Junos plan no longer types a delete for another community's
   statements, and another community's `authorization` no longer satisfies
   tacctl's.** A `clients` leaf of a community that was not tacctl's was
   answered with `delete snmp community <tacctl's community> clients <addr>`,
   which the device refuses (`statement not found`) and which the report
   excused in a note; an `authorization` of another community made tacctl's
   own read as present. Both are gone: a statement under another community is
   kept (`Left alone`), the note is gone, and a rendered community the device
   lacks is set whole (`set snmp community <name> authorization read-only` and
   its `client-list-name`), with a back-out that deletes the community. A stray
   leaf of tacctl's own community (a `clients` entry) is still deleted, under
   the community's real name, and a rendered leaf that the device holds with
   another value is replaced in place by its set. The report and the back-out
   show the label, `<secret:N>` (`<SECRET>` with `--no-secrets`); the line to
   paste holds the name.

4. **A section that holds only the device's own statements beside what tacctl
   renders reads `ok (+N unmanaged)`.** The `snmp` section is a hierarchy
   the device shares with its monitoring, and every extra made it `differs`,
   so a device that was brought to the standard and kept its other community,
   its trap groups or its `snmp name` could never read `ok`: it stayed in
   `--stale` and `--differs` and made `device config diff --exit-code` exit 2.
   A section whose rendered statements are all present and unchanged, and
   whose every extra is one the plan keeps by rule, is now `ok`, with the
   number of those extras: another community and its client lists and leaves,
   a client list, view or SNMPv3 object tacctl does not render, a location,
   contact or description when tacctl renders none, and the statements that
   have no row at all (`snmp name`, `engine-id`, trap groups and options, on
   IOS `snmp-server host`, `enable traps` and the rest of `snmp-server`).
   Text shows `ok (+N unmanaged)` in `device config diff`, `pull --diff` and
   the Configuration row of `device show`; `diff` and `pull --diff` list the
   statements as `+` lines with the note `N statements of the device's own,
   kept on purpose`; `device config list` keeps the state `ok` and its DETAIL
   reads `snmp +N unmanaged`. These devices are not in `--differs` or `--stale`
   and do not make `--exit-code` of `diff` or `plan` exit 2 (the plan still
   lists the extras, as left alone). In `--json` the `state` strings are
   unchanged (`ok` stays `ok`) and a section has the integer `unmanaged`
   (omitted when 0) in `pull` and `diff`, `device config list` has the map
   `unmanaged` (section to count, for the sections that are ok), and
   `devices-config.json` has `sections.<name>.unmanaged`. Only `snmp` can
   read this way: the extras of `aaa`, `roles` and `mgmt-acl` (another
   server, a login class, a filter, a user nobody recorded) are findings about
   who can log in and stay `differs`, as does any deactivated statement.
   In a record made by an older tacctl, whose communities are not told apart
   (item 2), an extra statement under a community is a difference until the
   device is pulled again.

5. **Configuration blocks have a home: `/etc/tacctl/blocks` and the lists in
   `tacctl.yaml` that put them in force.** A block is vendor syntax that a
   scope or a device owns beside the structured settings, written in the
   device's own language and never translated (the Junos `snmp` and `system`
   blocks are the first). A scope's blocks are the files
   `/etc/tacctl/blocks/<scope>/<vendor>/<block>` and a device's
   `/etc/tacctl/blocks/_devices/<device>/<vendor>/<block>` (the device's name in
   lower case; `_devices` cannot be a scope's name), 0600 in 0700 directories,
   written atomically; `<vendor>` is `juniper` or `cisco`, `<block>` is `snmp`
   or `system`. A block is in force only while `tacctl.yaml` names it:
   `blocks.<scope>.<vendor>` and `blocks_device.<device>.<vendor>` are lists of
   block names (the device's dots written `~`, as `breakglass_hold` does); a
   file that no list names is not used. Snapshots hold the directory and
   `backup restore` puts it back; `scope rename` and `scope remove` carry a
   scope's blocks, `device rename` and `device remove` a device's (`device
   remove` and `device import --replace` say so before they ask, because a block
   holds community strings); a scope or device name that has blocks left on
   disk or in `tacctl.yaml` is refused for a new scope, device or rename, with
   the path. `rollback 0.2.3` removes the lists and leaves the files. A scope
   called `devices` is an ordinary scope name.

6. **A scope's Junos `snmp` block is rendered, compared and planned.** The
   block's communities (`authorization`, `clients`, `client-list-name`), trap
   groups (`version`, `categories`, `targets`) and trap options are appended
   to the SNMP step of `device config show` and `config juniper`, and to the
   managed `snmp` section, as live lines under a comment that names the
   scope's block (never a string); they are rendered even when the scope's own
   SNMP settings are not configured. Each community and trap group of the
   block is an object tacctl owns whole: the plan sets what the device lacks
   and deletes a `clients` entry, a leaf or a trap-group target the block does
   not state, under the object's real name, and the back-out deletes what the
   plan created. The device's other communities stay `<other:N>`: kept, listed
   and counted as unmanaged. The management filter's `permit-snmp` term also
   permits the block's unrestricted IPv4 clients (a `restrict` entry is no
   permit; a community that uses a `client-list-name` gets a comment, because
   the list's addresses are on the device), so the filter's `deny-snmp` term
   does not refuse a community the block grants. A block with an error is never
   rendered in part: every Junos device of the scope is refused, with the line
   numbers and the verb that checks the block, and a block community that is
   the scope's own community is refused without printing it. A scope with no
   block renders exactly what it did.

7. **A scope's Junos `system` block is a seventh managed section.** The login
   message, domain name, domain search list, time zone, name servers and NTP
   servers (with `prefer`, `version`, `key`, `routing-instance`), boot server,
   source address, authentication keys and trusted keys that the block states
   are rendered as the last lines of the SNMP step, compared and planned
   additively: a statement the device lacks is set, a single value that
   differs (the login message, domain name, time zone, boot server, source
   address) is replaced in place, a list entry is added, and nothing the
   device holds is ever deleted (the extras are listed as unmanaged; `ok (+N
   unmanaged)` applies). An NTP key is typed only where its number is missing
   (the device keeps ciphertext, so presence is all that is compared), and a
   login message is kept in the record, the diff and the report as its size and
   a digest, never as text; the plan's pasted statement is the whole message,
   with a warning when the one-line statement is over 1,000 characters (a line
   over 1,023 pasted into an interactive terminal is truncated: use `device
   config plan <name> --plain`). The section exists only for a scope that has
   the block, so no other device gains `~` lines for its own NTP; `--section
   system` selects it in `device config diff` and `plan`. An older record has
   no such section and is not compared until the next pull; the plan says to
   pull again. The back-out types a replaced value back and deletes what the
   plan added; for a replaced message it names the rollback, because only a
   digest is kept.

8. **`tacctl scope block <scope> juniper` and `tacctl device block <name>`
   keep the configuration blocks: `list`, `show`, `check`, `set`, `remove`.**
   `list` names each block of the scope (or device) with its state (in force,
   named in `tacctl.yaml` with no file, or a file `tacctl.yaml` does not name,
   which is ignored), its size, what it states (communities and trap groups,
   or statements and the login message's lines, or the number of errors) and
   the findings of the store against `tacctl.yaml`; for a device it also names
   the scope's blocks beneath, and the device's orphans (a vendor directory
   that is not the device's vendor). `show <block>` prints the block elided:
   `<secret:N>` for a community string, `<group:N>` for a trap group's name,
   `<secret>` for an NTP key, `<message: N lines, M characters>` for the
   login message, and never a comment line (a comment may hold anything);
   `--reveal` prints the file as stored. `device block <name> show <block>
   --effective` prints the block as it is rendered for the device, the scope's
   with the device's laid over it, with a comment before each object saying
   which layer it comes from. `check <block> [--file <path>|-]` lints the file
   in force, a file (read as the caller, at most 256 KiB) or standard input:
   every finding with its line, the objects that become owned, the number of
   statements that carry a secret, the diff against the file in force (elided;
   a changed string shows as the same mark removed and added), and a block
   community that is the scope's own community (refused, by its place and
   without printing it); the exit status is 1 on an error. `check --against
   <device>` (at the device level `--against`) plans that Junos device with the
   text in force and prints the statements of the block's section from its last
   pull, every secret as a mark: nothing is written, no back-out is kept and no
   device is reached; a device that was not pulled is told to be pulled first.
   `set <block> (--file <path>|-) [-y]` runs the check (an error refuses it and
   writes nothing; a text that states nothing is refused, use `remove`),
   shows the owned objects and the diff, asks, takes the configuration
   snapshot, writes the file (0600, atomically) and names it in `tacctl.yaml`
   (blocks.<scope>.juniper or blocks_device.<device>.juniper); a block read
   from standard input needs `-y` unless standard input is a terminal, and the
   same text as the file in force is no change. `remove <block> [-y]` takes
   the entry and the file away after a snapshot (a file no list names is
   removable too) and says that nothing is deleted from a device: what the
   block set is no longer rendered, and the next compare lists those
   statements as the device's own, kept. Nothing is restarted by either.
   `set` and `remove` are the superuser's and are logged `block-set` and
   `block-remove` (name `<scope>/juniper/<block>`, or `_devices/<device>/
   juniper/<block>`, with the size and counts, never a value); an engineer
   reads (`list`, `show`, `check`) the blocks of their own scopes and of the
   devices there, another scope or device is not found, and an engineer's
   `show --reveal` is logged as `secret-read kind=block name=<that name>`. A
   write is refused, before anything is changed, when `tacctl.yaml` cannot be
   read or written. `cisco` is refused (`IOS blocks come in the release
   after`), and so is a device that is not a Junos device, an enrolled host and
   a device in no scope (its blocks can still be removed). The two verbs are in
   the engineer's rows of the tier table and the sudoers drop-in
   (`scope block *`, `device block *`), in the shell's and the console's lists
   and in tab completion (scope and device names, `juniper`, the block names,
   `--file` paths).

9. **A device's own blocks are rendered, compared and planned over its scope's,
   and `config validate` reports the blocks.** The walkthrough of a registered
   Junos device (`device config show <name>`, `config juniper --name <name>`)
   and the managed `snmp` and `system` sections of `device config
   pull|diff|plan` are made from the scope's block with the device's laid over
   it per object: a community (by its string), a trap group (by its name) or a
   trap-options leaf the device states replaces the scope's of the same key
   whole, one it adds is added, and the scope's others stay; in the system
   block a single value is the device's and a list entry is added, or replaced
   when it has the same value; the device's `delete` line takes the scope's
   object out for that device. The management filter's `permit-snmp` term
   permits the resolved block's clients. The comment above the block's
   statements says which layers it is made of and the verb that shows it
   (`tacctl device block <name> show snmp --effective`), and a refusal names
   the layer: a device block with an error refuses that device alone, with
   `tacctl device block <name> check <block>`; a block community that is the
   scope's own community is refused naming the device's block when it holds it.
   A batch resolves the device level once per device that has blocks of its
   own, before its workers start; an engineer's pull logs the read of a
   device's block under its own name. `config validate` gains a `Config
   blocks:` line when there are blocks: a name in `tacctl.yaml` with no file and
   a block in force that does not parse are errors (exit 1), a file no list
   names and a device's orphans (not registered, another vendor) are warnings;
   an installation with no blocks prints nothing new.

10. **`tacctl scope block <scope> juniper edit <block>` and `tacctl device
    block <name> edit <block>` open a block in your editor.** Superuser only,
    and refused without a terminal on standard input and output. The editor is
    yours, as `visudo` and `sudoedit` take it: `VISUAL`, else `EDITOR`, else
    `editor` (the system's alternative), else `vi`; a value may carry
    arguments (`emacs -nw`) and a name is looked up in `PATH`, a path must be
    absolute. It runs as the invoking user, never as root, on a private copy
    (mode 0600, named for the block: `scope-lab-juniper-snmp.txt`) in a
    directory of its own (0700, made under `/var/tmp` and handed to that user),
    with the user's `HOME`, `TERM`, `LANG` and `LC_*`, `PATH`, and `VISUAL` and
    `EDITOR` as given, and nothing of sudo's or tacctl's; the directory, with
    whatever swap or backup files the editor wrote there, is removed afterwards
    on every path, a stop signal included. The seed is the file in force; for a
    block that does not exist, the block's grammar and an example as `#`
    lines, and for a device's new block also the scope's objects as `# set ...`
    lines to uncomment where the device differs (a device's object replaces
    the scope's of the same key whole). What the editor leaves is read as the
    user (a regular file of at most 256 KiB that is theirs; a link or anything
    else is ignored and nothing is written), checked as `set` checks it, and
    installed as `set` installs it: the owned objects and the elided diff, the
    question (`-y` answers it), the snapshot, one atomic write, the entry in
    `tacctl.yaml`, logged `block-edit name=<scope>/juniper/<block>` (or
    `_devices/<device>/juniper/<block>`) with the size and counts. A text that
    fails the check is offered back to the editor (up to five rounds) with the
    errors as `# tacctl:` lines at the top, numbered as the editor's window is;
    those lines are removed before any text is read and never reach the file.
    An editor that exits non-zero, a text that is empty or states nothing, and
    an edit that changes nothing write nothing. In the login console the rule
    of the system shell applies, since an editor can start a shell: an edit is
    open to the tiers of `console system-shell tiers` (default `superuser`,
    never the engineer), and a refusal is logged `block edit DENY`.
    **The sudoers drop-ins change.** sudo's `env_reset` drops `VISUAL` and
    `EDITOR`, so both drop-ins (`/etc/sudoers.d/tacctl-tiers` and the group
    drop-in of `config sudoers install`) gain a `Cmnd_Alias` of the four command
    lines that open an editor (`scope block * edit *`, `scope block * adopt *`,
    `device block * edit *`, `device block * adopt *`) and a `Defaults!` line
    that keeps those two variables for them, the way `TACCTL_ASKPASS` is kept,
    and for nothing else; no `SETENV` tag is added. tacctl takes both variables
    out of its own environment at start on the sudo side, so no program it runs
    (git, a pager) inherits an editor the caller named. `tacctl upgrade`
    rewrites an installed tiers drop-in and a group drop-in that is exactly the
    text 0.2.4 to 0.2.6 wrote; `tacctl rollback` puts 0.2.3's text back over
    either. Without the refreshed drop-in, `VISUAL` and `EDITOR` do not reach
    tacctl (unless the caller's own sudoers rule allows the assignments tacctl
    puts on those four lines) and the editor is `editor`, else `vi`. The editor
    has to stay in the foreground until the text is saved (`code --wait`,
    `gvim -f`). An editor may write swap or backup files beside its working
    copy, which is why that directory is private; a block holds community
    strings, a poller's credential, on this host and in the snapshots.

11. **`tacctl scope block <scope> juniper adopt <device> <block>` and `tacctl
    device block <name> adopt <block>` read a Junos device's own statements and
    open them as the draft to prune.** Superuser only, with the same terminal,
    console and editor rules as `edit`. The device is read live with your login
    as `device config pull` reads it: the password from the cache or the
    terminal (the shell keeps the line's `TACCTL_ASKPASS` for `adopt` too), the
    transport of `device.config.transport` (NETCONF, the command line as the
    fallback under `auto`), `device.config.timeout`, the pinned host key and the
    pull's words for a failure (`Cannot read <device>: authentication failed.`,
    `no host key is pinned for the device` with the command that pins it); one
    device, one login, one command (`show configuration snmp | display set` or
    `show configuration system | display set`). Nothing of the device's text is
    stored: it exists in memory and in the editor's private copy, which is
    removed. The read is logged as a reveal is, `secret-read
    kind=block-adopt name=<scope>/juniper/<block>` (or `_devices/<device>/...`;
    never a value), whoever reads, and `block adopt-read user= device=
    transport= result=`. The draft holds the statements the block's grammar
    takes minus what tacctl renders itself (the scope's own community and its
    client list, the v3 settings, a location or contact it renders) and the
    device's identity (`snmp name`, `engine-id`); for a device's block also
    minus what the scope's block states with the same statements (an object that
    differs is the device's exception, whole). A community string or trap group
    name the login sees masked (`/* SECRET-DATA */`, `<masked>`, asterisks) or
    only as the device's ciphertext cannot be adopted: each such statement is
    named as a `# left out:` line with its shape and no value, and an NTP
    authentication key, always ciphertext, is left out the same way. The
    system block's draft converts the device's `\n`-escaped login message to the
    heredoc form (`blocks.FromDeviceMessage`) and takes `domain-name`,
    `domain-search`, `time-zone`, `name-server` and `ntp server`, `boot-server`,
    `source-address` and `trusted-key`. An existing block of that name is not
    merged: its text is opened first, whole, and the adopted statements follow
    under a `# adopted from <device> at <time>` comment with the counts; an
    object the file already has with other statements is left as it is and
    counted. A draft with nothing adoptable opens no editor and says why; one
    pruned to nothing writes nothing (`No statement was adopted`); the rest is
    `edit`'s: check, diff, question, snapshot, write, logged `block-adopt`.

12. **`config wti`'s IP Tables step gives the list as one paste, adds ICMP
    and warns at 48 entries.** Step 5 follows the numbered list with the same
    rules as one `<iptables>` ... `</iptables>` block for the unit's IP Tables
    prompt (the unit takes the whole list in one paste, replacing every entry,
    and applies it at once), and the list gains one `-i eth0 -s <net> -p icmp
    -j ACCEPT` line per network of the server, the management permits and the
    SNMP clients (the unit's own Ping Access item is separate). Step 11 gives
    the whole list, the DROP, `iptables -A OUTPUT -j ACCEPT` and the three
    `-P INPUT|OUTPUT|FORWARD DROP` policies (last, the order a lab unit took
    without cutting the pasting session off) as one block, with the revert
    (clear the slots, or paste Step 5's block again). A list that would exceed
    the unit's 48 entries says so in Step 5, in Step 11 and at the end of the
    output, and is not cut. From a lab test on a WTI 8.10 unit; the walkthrough
    no longer says that when the unit applies a changed list is unknown (it
    applies a paste at once, and any session leaving a top-level menu saves
    it).

13. **`config snmp test <address|device>` follows a registered device.** The
    test used the default's settings only, so a device with an SNMP community
    of its own (or in a scope with its own) answered "no answer" to it. It now
    reads a registered device with the settings the device is read with
    everywhere else (its own, else its scope's, else the default's) and says
    which it tried (`(tried with the settings of device 'sw1' (tacctl device
    snmp sw1 show))`, also in the "no answer" report); an address that is no
    device is read with the default's as before, and `scope snmp <scope> test`
    is still the scope's.

14. **`device list` is sorted by name and can be narrowed.** The rows were in
    registry order, devices before hosts. They are now sorted by name (case
    ignored, then address), in the table and in `--json`. `--name <text>` keeps
    the names that contain the text, `--ip <addr|cidr|text>` the addresses
    equal to an address, inside a CIDR (`10.20.0.0/16`, `2001:db8::/32`) or
    containing a text (`10.20.1.`), `--vendor <vendor>` and `--scope <scope>`
    those exact values; each takes one value or a comma list (any of them
    matches) and different options must all match. A bare word
    (`device list sw1`, `device list lab`) keeps the entries whose name or
    address contains it or whose vendor or scope it is. The heading then reads
    `Registered devices (N) and enrolled hosts (M), of T`, an empty selection
    says `None match.`, and `--stale`, `--unconfigured`, `--scan`, `--probe`
    and `--json` combine with all of it.

15. **`config wti`'s SNMP step uses the item names of a WTI 8.10 unit.** The
    step said its menu names were from WTI's documents and sent you to "the
    entry labelled SNMP". It now names the page (`/N`, item 25, SNMP Access)
    and its items as the unit prints them: Enable, Version (`V1/V2 Only` for
    v2c), Read Only, Read-Only Community, Contact and SNMP Location, with the
    note that other firmware may number them differently. The statements a
    pull compares for a unit (`snmp enable on`, `snmp version v1-v2-only`,
    `snmp read-only yes`, ...) are the ones this step tells it.

16. **`device config pull`, `diff` and `list` read WTI units.** A WTI console
    server has no command that prints its configuration, so a pull walks the
    unit's menus over ssh as you (the pages of command menu version 8.10 the
    tables name: the login's help, the network status, the Site ID, and under
    `/N` the SNMP, TACACS+, RADIUS and IP tables pages), typing only the keys a
    page lists and never the final ESC that makes a unit save its
    configuration. The user directory is read in a second connection with the
    same password. The pages are never kept: the extraction is, compared with
    what tacctl renders as for any device, with a community the unit prints in
    clear kept as a label (`<secret:N>`, `<other:N>`). A unit has four
    sections, `aaa`, `mgmt-acl`, `snmp` and `breakglass`; `roles`, `netconf`
    and `system` are not listed for it. Units are selected by `--all`,
    `--scope`, `--vendor wti` and `--stale` like any device, the record has the
    command menu version (`os`), the unit's Site ID and the number of other
    sessions it had, and the line of a pull says `1 other session on the unit`
    (a count; no name is read into any output).
    The results are new for a unit: **`denied`** (the login's WTI level cannot
    configure it: `the login's WTI level is User; SuperUser or Administrator
    is needed`, with `tacctl group edit <group> wti-level superuser`), a failed
    pull that exits 1 and does not stop a batch; **`unsupported`** (`command
    menu version 7.4; tables are verified for 8.10`, before any page); and
    **`parse-failed`** (a page the tables do not know: its path and title line
    only). A user directory that cannot be read is a warning on the line, the
    pull is `ok`, and `breakglass` reads `n/a` with a note. `device config
    list --failed` includes `denied` and `unsupported`, `device list` shows the
    state in its CONFIG column instead of `-`, and `device show` replaces `not
    read (WTI units are not read in this release)` with the last pull.
    `--transport netconf` is refused for a unit as for a Cisco device. In
    `--json`, a pull has `unit` (`version`, `level`, `site_id`,
    `other_sessions`, `users_read`) and `warning`, `device config list --json`
    has `unit` for a unit (`version`, `site_id`, `other_sessions`,
    `users_read`), and a record made before 0.2.7 is unchanged.

17. **`device config plan` plans a WTI unit.** A unit has nothing to paste:
    its settings are the items of numbered menu pages, a value is live as soon
    as its Enter is accepted, and it has no commit-confirm and no rollback. Its
    plan is the report, the version check (`/H` must show `Version 8.10`, `/J`
    the Site ID the pull read), what to have ready (a serial console or a
    second session that stays open, `/SN` for other administrators, the
    other sessions the pull saw), **a numbered checklist of menu steps**
    between `DO THESE STEPS ON: <unit>` and `END OF STEPS` (the keys typed from
    the prompt, the item as the unit prints it, what to enter, and `was:` the
    pulled value), the `ESC ESC` that saves and a `CHECK` step, and **one
    `<iptables>` block** between `IP TABLES (replaces every entry; see the
    notes)` and `END OF IP TABLES`. The steps are ordered so that none takes
    away the way in before the one that needs it (the SNMP page, then the
    protocol's page with its secret word first and its Enable last); a step on
    the AAA page carries the warning that a wrong secret word, host, port or
    service name returns every login to the Default User Access level. The
    block is the whole rendered list followed by the unit's own tail exactly as
    the pull showed it, is presented and never applied, and its lines are the
    only lines of the output that are not comments. The IP tables section is
    refused, the rest still planned and the report saying why, when the list
    would hold more than 48 entries or an entry the page does not take, does
    not permit the tacctl server's address to reach the unit's ssh, or does not
    permit the `--from` address; without `--from`, a list that ends in the
    final DROP and other sessions on the unit are warnings. A secret step names
    the command that shows the value (`tacctl scope secret show <scope>`,
    `tacctl scope snmp <scope> show --reveal`) and a unit's plan types none
    unless `--secrets` is given. A second host, a read/write community, the
    other protocol's page switched on and a local account the scope does not
    record are findings with the step that removes them; `breakglass` is
    reported and never planned (walkthrough Step 10). `--backout` prints the
    steps with the pulled values (a secret as "re-enter the one you keep") and
    the old list as a block, or the slots to clear; `--converge` offers only
    the read/write community and the other protocol's Enable. `--plain` and
    `--section roles|system` are refused for a unit (exit 2), `--out-dir`
    writes `<name>.txt` and `<name>.backout.txt`, never a `.set`, and `plan
    --pull` and `--all`, `--scope` and `--vendor wti` select units.

18. **A WTI pull reads the whole SNMP system name, contact and location.** The
    SNMP access page prints these three texts cut at about 16 characters and
    ending in `...`, so a pull kept `wti.site.exam...` and compared it by its
    beginning, with a note that it was taken as equal. A pull now opens the
    item's text prompt for each of the three that the page shows cut that way:
    the item's number and a CR print the whole value, and ESC leaves the
    prompt with the value as it was. Nothing is typed at a prompt (no text, no
    CR and no `<SPACE><CR>`, which would clear the field), a value the page
    shows whole is not opened, and the prompts of the communities and secret
    words are never visited. The whole values are extracted, shown by `device
    config diff` and compared exactly: a contact that merely begins as the
    rendered one is now a difference, and the note `the unit shows a truncated
    value` is gone for a value read that way. The prompt pages are three more
    screens of the pull, and the document is not kept. A record made by an
    earlier pull holds the cut value and is still compared by its beginning,
    with the note, until the unit is pulled again. The prompt pages print
    values and nothing else; the SNMP access page itself prints the read-only
    and read/write communities in clear on this firmware, and they are turned
    into labels in memory and never stored or logged, as before.

19. **`config wti`'s IP Tables list no longer opens tcp 443.** The list gave
    the server and each permitted range ssh (22) and https (443). Web access
    is off on the units and the REST API is not used, so the list now permits
    ssh only: the numbered list, the `<iptables>` blocks of Step 5 and Step 11
    and the managed `mgmt-acl` statements lose their `--dport 443` lines, and
    the 48-entry count falls with them (a scope with ten permits is 25
    entries, 30 with the last step's tail). A unit whose list still has the
    443 lines reads `differs` in `mgmt-acl` until its list is replaced. To
    allow https, telnet or http, add the same line with `--dport 443`, `23`
    or `80` by hand, as the step's notes say.

20. **A management ACL entry can list the services it permits.** The lists
    `mgmt_acl.permits` and `scope_mgmt_acl.permits.<scope>` (`tacctl config
    mgmt-acl` and `tacctl scope mgmt-acl <scope> add|remove|list|clear`) took
    a CIDR and nothing else. An entry is now `<cidr>[:<service>[,<service>...]]`
    with `<service>` one of `tcp/<ports>`, `udp/<ports>` and `icmp`, and
    `<ports>` one of `N`, `N-M` and `*`:
    `tacctl scope mgmt-acl lab add 172.16.100.0/23:tcp/22,udp/161,udp/162`.
    A token that starts with `tcp/`, `udp/` or `icmp` belongs to the entry
    before it in a comma-separated `add` or `remove` (a service before any
    CIDR is refused), and the CIDR is split from its services at the first `:`
    that is followed by `tcp/`, `udp/`, `icmp` or `*`, so an IPv6 CIDR is
    written as it is. An entry is stored in one form: the canonical CIDR, then
    the services lower-cased, without repeats, in the order tcp, udp, icmp and
    ports ascending (`tcp/*` takes the other tcp services; `<cidr>:*` and
    `<cidr>:tcp/*,udp/*,icmp` are the plain CIDR); ports are 1 to 65535, a
    range has its low port first, `icmp` takes no port, and an entry holds at
    most 8 services. The same CIDR may be listed twice with different
    services; an exact duplicate is still a no-op; entries sort by the CIDR as
    before, then by services. `remove <entry>` removes that exact entry, and
    `remove <cidr>` with no services removes every entry of that CIDR and says
    how many; `list` prints the services after the CIDR. `config validate`
    and the schema check each element and name the services problem.

    **Behaviour change for WTI units: a plain `<cidr>` now permits every
    protocol and port from that source.** A plain entry of an existing list
    renders as `iptables -A INPUT -s <cidr> -j ACCEPT` in the unit's IP Tables
    list, where 0.2.6 and before rendered ssh and ICMP for it, so a list of
    plain permits is wider on the unit than the same list was: the unit's
    telnet and web pages are reachable from those sources. A network with a
    plain entry has no separate ICMP line. To keep what the list permitted,
    replace each plain entry with `<cidr>:tcp/22` (`tacctl scope mgmt-acl
    <scope> remove <cidr>`, then `add <cidr>:tcp/22`). The notes of Step 5
    name the plain entries and say so, and `device config plan` of a unit
    whose paste carries one reports `N plain permit(s) of the rendered list
    allow every protocol and port from the source`. An entry that lists
    services renders one rule for each, in order: `-p tcp -s <cidr> --dport
    22`, `--dport 161:162` for a range, no `--dport` for `tcp/*` or `udp/*`,
    and `-i eth0 -s <cidr> -p icmp` for `icmp`; the ICMP line of a network is
    still added unless its entry lists `icmp`, and the SNMP client lines are
    unchanged. An entry equal to the tacctl server's own /32 adds its services
    after the server's lines; it is not a permitted range for the lock-out
    guard, which now also needs at least one entry that permits ssh (plain, or
    with `tcp/22`), else the DROP stays a comment. The 48-entry count and the
    plan's check that the server and `--from` reach the unit's ssh follow the
    new rules (the check reads tcp 22, a range that holds it, every tcp port
    and every protocol).

    **Cisco and Junos list a source only when its entry permits ssh.** A
    standard access list and the `permit-mgmt` term match a source and
    nothing else, so a plain entry, and an entry whose services include
    `tcp/22` (alone, in a range, or as `tcp/*`), are listed by their source as
    before and every other entry is not listed, with a comment above the list
    that names it (`entry 10.0.0.0/8:udp/161 permits udp/161 only: not in the
    VTY access list VTY-ACL ...`). The managed `mgmt-acl` sections use the
    same list, so `device config diff` and `plan` agree with the walkthrough.
    Output for lists of plain entries is unchanged.

    **`tacctl rollback 0.2.3` is refused while any entry carries services**
    (the dry run too): 0.2.3 reads these lists as plain CIDRs and refuses the
    file, and a rewrite to the CIDR would permit every protocol and port. The
    refusal lists each entry with its key and the command that removes it
    (`tacctl config mgmt-acl remove <entry>`, `tacctl scope mgmt-acl <scope>
    remove <entry>`) and changes nothing. Remove them, or replace each with
    the plain CIDR you mean it to be, then run the rollback again.

21. **A scope's and a device's IOS `snmp` block (checked on one IOS 15.6(2)T
    router).** `tacctl
    scope block <scope> cisco list|show|check|set|remove|edit|adopt <block>`
    and `tacctl device block <name> ...` for an IOS or IOS-XE device keep an
    `snmp` block of IOS configuration lines (the verbs, the files under
    `blocks/<scope>/cisco/`, the lists `blocks.<scope>.cisco` and
    `blocks_device.<device>.cisco`, the tiers, the snapshot and the elided
    reads are those of the Junos block). Grammar, one statement per line, `#`
    and `!` comment lines:

        snmp-server community <string> RO|RW [<acl-name>]
        snmp-server host <address> [version 1|2c] <community> [udp-port <n>] [<type> ...]
        snmp-server enable traps [<type> [<subtype> ...]]
        ip access-list standard <NAME>
         permit <address> [<wildcard>] | permit host <address> | permit any
        no snmp-server community <string>      (also: host, enable traps, ip access-list standard)

    `check` refuses, with the line and never a string: tacctl's own names
    (the scope's community, `TACCTL-SNMP`, `TACCTL-VIEW`, `TACCTL-GROUP` and
    the scope's management access list), a numbered access list, a read-write
    community with no access list or whose list permits `any`, an access list
    with no entry, a `deny` or `remark` entry, an address with bits set under
    its wildcard, `snmp-server contact|location|trap-source|engineID|user|
    group|view`, a trap host in a `vrf` or with `informs` or SNMPv3, a
    placeholder, a tab and any token off the grammar. A `no` line means "not
    managed on this device" and is kept, never rendered. Resolution is per
    object (a community by its string, a list by its name, a host by its
    address and community, an `enable traps` line by its words): a device's
    object replaces the scope's of the same key whole, and its `no` line takes
    the scope's out.

    The block's lines follow the structured SNMP step of the walkthrough
    (also when the scope's SNMP is not configured), under a comment that names
    the block and never a string, and are the last lines of the managed `snmp`
    section. The plan owns a community (retyped in place when its access or
    list differs, never removed) and a list the block defines (whole: an entry
    it does not state is removed with a `no` line, and a list it only names is
    the device's own); a trap host (compared by address, community and the
    set of its options, because IOS leaves out the default version, kind and
    port and keeps its own order of types) and an `enable traps` line (present
    when the device enables it in the expanded form it prints, a line with no
    type present when the device has any) are only ever added. The device's
    other communities, hosts, lines and lists stay and are listed (`ok (+N
    unmanaged)`), and `--converge` removes none of them. IOS has no confirmed
    commit, so the plan is pasted line by line and undone by its `no` lines; a
    community or host the plan replaced is typed again by value. A block
    community equal to the scope's own, and a list named as the management
    list, are refused by `check` and by every render without printing the
    string. The report says, among its notes, that the block's lines (list
    entries, trap hosts, `enable traps` lines) were written from the vendor's
    references and have not been checked on a device; it says so for every
    release, because it cannot know which one a device runs. A lab IOS
    15.6(2)T router took a block's communities with their lists, list
    entries, a trap host and the trap types, read them back as `ok`, and took
    the `no` line that removes a stray list entry. Other releases and IOS-XE
    have not been checked. The IOS `system` block and `trap-source` are
    item 22.

    `adopt` reads `show running-config | include ^snmp-server` and, for each
    standard list a community names, `show running-config | section ip
    access-list standard <NAME>` (the whole configuration once when the image
    does not know `| section`), as the caller, over the ssh command line; it
    drops tacctl's own community and list, v3 and the device's identity and
    names what a block cannot hold (a numbered list, a view or IPv6 list, a
    deny entry, a string shown as ciphertext) as `# left out:` lines. Limits:
    VRF forms (`snmp-server host ... vrf <v>`, management VRFs on IOS-XE) are
    refused in a block, and the device's own such lines stay unmanaged.

    **Every `show --reveal` of a block is logged**, the superuser's too, as
    `secret-read kind=block name=<scope>/<vendor>/<block>` (or
    `_devices/<device>/<vendor>/<block>`), never a value; an elided read is
    not.

22. **The IOS `system` block, and `trap-source` in the IOS and Junos `snmp`
    blocks (IOS checked on one 15.6(2)T router).** `tacctl scope block
    <scope> cisco list|show|check|set|remove|edit|adopt` and the device level
    (`tacctl
    device block <name> ...`) now take the block name `system` for IOS and
    IOS-XE, as they take it for Junos; the refusal `The IOS system block is
    not built` is gone. The block is IOS configuration lines, `#` and `!`
    comments, and the login banner as a heredoc so that its text is easy to
    read and edit:

        banner login <<'EOF'
        <text lines>
        EOF
        ip domain name <name>
        ip domain list <name>
        clock timezone <zone> <hours> [<minutes>]
        ip name-server <address> [<address> ...]
        ntp server <address-or-name> [prefer] [version <1-4>] [key <n>] [source <interface>]
        ntp authentication-key <n> md5 <string>
        ntp trusted-key <n>
        ntp authenticate
        no <statement>

    The block is additive, as the Junos system block is: a statement is set
    when the device lacks it, a single value that differs (banner, domain
    name, time zone, an NTP server's options) is replaced in place, a list
    entry is only added, and what the device holds beside is its own, listed
    and kept (`ok (+N unmanaged)`); a `no` line says "not managed here" and is
    never rendered. A device's block is laid over its scope's per object (a
    server by its host, a key by its number, a single value whole), and its
    `no` line takes the scope's object out for that device. The banner is
    rendered as IOS's multi-line banner, `banner login <d>`, the text, `<d>`
    alone on a line, where `<d>` is the first of `^ ~ % # @ $ &` that the text
    does not contain; a text of at most 20 lines of 80 characters of ASCII
    with no tab or control character is accepted, and one that holds every
    candidate is refused. An `ntp authentication-key` string is typed only
    where the device has no key of that number (a pulled device shows
    ciphertext, so a key is compared by its number alone), and `ntp
    authenticate` is one boolean; the plan pastes the NTP lines in the order
    IOS needs (keys, trusted keys, servers, `ntp authenticate` last) and says
    so. Refused by `check`, without the line's words: a placeholder
    (`<secret>`, `<message: ...>`), a key with no key number or of another
    algorithm, an abbreviated interface (`Lo0` for `Loopback0`), an IPv6 NTP
    server, and every VRF form (`ntp server vrf`, `ip name-server vrf`, `ip
    domain name vrf`): a device's own lines of those forms stay unmanaged. `ip
    domain-name` and `ip domain-list`, the legacy spellings, are accepted and
    read as the current ones.

    The comparison puts both sides in one form: the banner is `banner login
    <message: N lines, M characters, id xxxxxxxx>` (its size and a short
    digest; no text of it is stored, shown in a report or kept in a record,
    and `show`, `check` and the plan's report print the mark), `clock timezone
    CET 1` (12.4) and `CET 1 0` (15.x) are one statement, `ip name-server A B`
    is a statement per address, an NTP server's keywords are compared as a set
    whatever order the device stored them in, a host name and an interface are
    compared without case, and the banner a device prints with `^C` or any
    single delimiter is read as its text between the delimiters. The
    walkthrough puts the block's lines after the SNMP step under a comment
    that names the block (and the delimiter chosen), and the Step 0 comment
    `ip domain name <DOMAIN>` names the block's value for a scope that has
    one; with no block every walkthrough, section and golden is as it was. The
    plan has a section `system` (after `snmp`, before `mgmt-acl`), `--section
    system`, the rows `ios.system.*` of the ownership table, a back-out that
    types a replaced single value again, takes an added statement away as the
    device takes it (`no banner login`, `no ntp authentication-key 5`, `no ntp
    server <host>`) and, for a replaced banner (only its digest is kept),
    names the way back (`configure replace` with the archived or the startup
    configuration), and a warning when a banner line is longer than the 255
    characters IOS takes on a typed line. The whole-paste check understands a
    banner: its text is any text up to the closing delimiter (a line that
    starts with `!` is no comment there), and no label or comment may stand
    inside it. `--converge` removes none of the device's own lines. The report
    says, among its notes, that the system block's lines (banner, domain, time
    zone, name servers, NTP) were written from the vendor's references and
    have not been checked on a device; it says so for every release. On a lab
    IOS 15.6(2)T router a block with a banner (typed with the `^` delimiter),
    `ip domain name`, `ip domain list`, `clock timezone`, `ip name-server`
    and `ntp server ... prefer` was pasted and read back as `ok` (the device
    stores the time zone as `AKST -9 0`, which compares equal to `-9`); a
    changed banner, an added list entry and name server, and `ntp server`
    typed again without `prefer` came out as the planned lines and replaced
    the server line in place; `adopt` drafted the block from the device and
    left the other banners out; and `snmp-server trap-source` was pasted and
    read back. Not checked on a device: the NTP key lines
    (`ntp authentication-key`, `ntp trusted-key`, `ntp authenticate`, the
    `key` option), a delimiter other than `^`, IOS-XE and IOS 12.4, and the
    Junos `trap-options source-address`.

    `adopt` reads `show running-config | include ^(banner|ip domain|ip
    name-server|clock timezone|ntp )` and the banner's own lines with `show
    running-config | section ^banner login` (the whole configuration once when
    the image does not know `| section`), as the caller, over the ssh command
    line; the draft holds the device's banner as the heredoc and its
    statements minus what the block or the scope's block states already, and
    leaves each `ntp authentication-key` out with a `# left out:` line (the
    string is never adopted).

    `snmp-server trap-source <interface>` (IOS) and `set snmp trap-options
    source-address <address>|lo0` (Junos) are accepted in the `snmp` blocks,
    which refused them until this release. One is in force at most, the
    interface is written in full (`Loopback0`, which is how the device stores
    it) and compared without case, and the address is canonical IPv4 or IPv6
    or the keyword `lo0`. A scope's block that states one gets a note that the
    same source interface or address is stated for every device of the scope
    (a device's own block can state another; the default layer refuses it).
    The plan sets it when the device's differs, in place (a `set` over the old
    value, never a delete), and the device's own is kept while the block
    states none; on IOS `no snmp-server trap-source` and on Junos `delete snmp
    trap-options source-address` say "not managed", and the report names the
    leaf as the block's. `adopt` takes the device's own trap source into the
    draft.

23. **`device config plan --restore-point[=<fs>]` adds a restore point to an
    IOS or IOS-XE plan (the copy form checked on one 15.6(2)T router).** The
    plan's region can only be
    undone with the back-out's `no` lines; the flag puts a file of the
    running configuration beside it first. The output gets a block of its
    own before the region, outside the `PASTE FROM HERE` banners, between a
    banner pair of its own:

        !!!!! RESTORE POINT FROM HERE: <device> !!!!!
        copy running-config <fs>tacctl-<device>-<yyyymmdd-hhmm>.cfg

        !!!!! RESTORE POINT TO HERE: <device> !!!!!

    The comments above it say to paste the block first and on its own at the
    privileged prompt, to check that `dir <fs>` lists the file, that the file
    holds the device's secrets in their own forms (protect it, delete it when
    done), that it needs free space on the file system, and that it is a
    file, not a rollback timer: IOS has no commit-confirm for a pasted plan.
    The one empty line answers the `Destination filename` prompt; a paste
    tool that drops blank lines turns the closing banner into the file name,
    and `file prompt quiet` turns the prompt off. `<device>` in the file name
    is the device's name up to its first dot (IOS limits a file name to about
    63 characters), the time is the plan's, in UTC.

    The file system comes from the flag or from the pull. `--restore-point=
    <fs>` names it (`flash:`, `bootflash:`, `disk0:`: lower case letters and
    digits, then a colon; a network file system such as `tftp:` is refused,
    since its copy asks for more than the one empty line answers) and makes
    the named copy above. The bare flag uses the device's own archive path:
    the pull now keeps the file system of the `archive` / `path` statement
    in its record (the word up to the colon only, never the host or user of a
    remote path), and the block is then the one line `archive config`,
    which asks for no name. A bare flag for a device whose last pull read no
    archive path is a usage error (exit 2) that says to name a file system
    or to pull again.

    The back-out gains an alternative after its `no` lines (the plan's
    after-steps say so too): `configure replace <file> force` for the named
    copy, or for the newest entry of `show archive` after `archive config`,
    as comments, with the caveats: it was tried only on devices with
    `archive` and a `path` configured, `copy <file> running-config` only
    merges, the removal of `aaa new-model` was skipped in one pass on IOS
    12.4 (use the `no` lines for AAA), and the file and the copies the
    replace leaves are to be deleted. The file name in the back-out is the
    block's, and the kept back-out records it (a `restore:` line of its
    stamp, and `its restore point is <file>` in the line `--backout` prints
    first). `--json` gains `restore_point` (`mode`, `file`, `command`,
    `file_system`, `note`) when the plan has a region to paste with the
    flag; the report's notes say the block and the alternative have not been
    checked on a device, for every release. The `copy` form was typed on a lab
    IOS 15.6(2)T router: the single empty line answered the `Destination
    filename` prompt and `dir flash:` listed the file. `archive config` and
    `configure replace` were not tried. Off by default: without the flag
    every IOS output, JSON and back-out is as it was. The flag is refused for
    another vendor
    (naming the devices), and with `--plain` (a plain file is the region's
    statements and has no room for a block of its own) and with `--backout`
    (the kept back-out names the file its plan made). The region's own
    whole-paste check is unchanged and still refuses a `copy`; the restore
    block has an allowlist of its own (exactly `archive config`, or one
    `copy running-config <fs>tacctl-<name>-<time>.cfg` and one empty line).
    Completion offers `--restore-point` and, after the `=`, the file
    systems.

24. **A WTI unit's Multiple Logins setting must be On, and the standard, the
    comparison and the plan say so.** A unit's `Multiple Logins` (`/N`, item
    31; Off or On) decides whether a second session may log in while one is
    open. `device config pull` opens a second session to read the user
    directory, and the walkthrough and every plan tell you to keep a session
    open as the way back and to check from a second login: with the setting
    Off a unit refuses all of them. The standard now has one statement for
    it, `unit multiple-logins on`, in the `aaa` section of every WTI
    rendering (`device config show`, `config wti` Step 3 for both protocols,
    the managed sections). A pull reads the item from the `/N` page it
    already opens, with no extra navigation, and a unit that prints it Off
    differs in `aaa` (`- unit multiple-logins on`, `+ unit multiple-logins
    off`, severity ACCESS). `device config plan` fixes it with one step,
    `/N 31 -> 2 (On)   was: 1 (Off)`, which is **the first step of the
    checklist**, ahead of the SNMP page and the AAA pages: it cannot lock
    anybody out, the checks of the steps after it and the pull that confirms
    them need a second session, and the report's item for it says so. Its
    back-out puts it Off again, last. A unit whose `/N` page does not print
    item 31 has no statement for it, and the standard's is then reported
    missing.

25. **Plain management ACL entries on WTI units are named by the upgrade and
    at the top of the plan.** Item 20 made an entry with no `:service` mean
    every protocol and port; on a WTI unit that differs from 0.2.6, which
    rendered such an entry as ssh (tcp/22) and ICMP. The meaning is kept, and
    two things say where it applies before anything is pasted. The first
    `tacctl upgrade` onto this release prints, once, for every scope that has
    a registered WTI unit and a plain IPv4 entry in the list that applies to
    it (its own permit list, else the global one): `Management ACL: plain
    entries now permit every protocol and port on WTI units.`, then one line
    per scope with the entries and up to five unit names, what a WTI plan
    renders for them (`iptables -A INPUT -s <cidr> -j ACCEPT`, where 0.2.6
    rendered ssh and ICMP) and how to keep ssh only (`tacctl scope mgmt-acl
    <scope> remove <cidr>`, then `add <cidr>:tcp/22`). A marker in the state
    directory (`wti-plain-acl-noted`, beside the other notice markers; a fresh
    install writes it too) records that it was said: a later upgrade prints
    nothing of it, `config validate` does not repeat it, and a plain entry
    added afterwards is not announced by an upgrade. The plan says the same at
    the top of its report: when a WTI plan pastes a list that holds plain
    entries, a `# WARNING:` line follows the box and the basis of the pull,
    ahead of the irregularities, and names the entries. It replaces the note
    that stood among the notes at the bottom, and `--json` carries it first in
    `warnings`. `--backout` prints the same line when the list it puts back
    (the unit's own, as the pull showed it) holds plain entries.

## 0.2.6 (2026-10-12)

A hotfix for 0.2.5, started from `master`. The items below are everything that
differs from 0.2.5. The server, the store and the rendered TACACS+ and RADIUS
files are untouched; what changes is the standard Cisco block that
`config cisco` and `device config show` print and the managed `aaa` section
that `device config pull`, `diff`, `list` and `plan` compare.

### What changed

1. **The standard Cisco block has no `aaa authentication enable` list.**
   0.2.5 rendered `aaa authentication enable default group <G> enable` for
   TACACS+ (and carried the RADIUS form commented out) on the reading that
   the server would refuse an `enable` it did not know. It does not: tacquito
   answers a TACACS+ enable request as a login with the user's own password,
   so an operator at privilege 7 who typed `enable` and their own password
   reached privilege 15 and could `show running-config` (the TACACS+ key, the
   enable secret's hash and the local users' hashes). This was tested on lab
   devices running IOS 15.6 and IOS-XE 16.7; command authorization at level 15
   still denied `configure`, `debug` and `clear`. The line is gone from the
   three templates (`cisco`, `cisco-legacy`, `cisco-radius`), from the managed
   `aaa` section, from the walkthrough's Step 1 and from the RADIUS
   walkthrough, where the commented line and its "not verified (lab item E2)"
   note are replaced by one comment: there is no enable list, and `enable`
   uses the local enable secret and nothing else (0.2.3's behaviour). The Step
   0 note about the enable secret says the same. The cost, stated in the
   README and the manual page: the local enable secret is again the one
   shared secret of the way up, on the vty and on the console alike, while
   the server is up, and who holds it is site policy (Step 0). Command
   authorization at level 15 still asks the server with the user's group
   rules, so an operator who knows the secret cannot configure, debug or
   clear, and can read the running configuration. `pull`, `diff`, `list` and
   `plan` treat the line as an extra of the standard, for TACACS+ and RADIUS
   alike: `aaa authentication enable default group <G> enable`,
   `default group tacacs+ ...`, `default enable group <G>`, `default line`,
   `default none` or any other `default` list is `+`, severity ACCESS, and
   `device config plan` removes it with one `no <the statement>` line in the
   `aaa` region (after the added lines; the back-out types it again).
   `aaa authentication enable default enable`, which is what IOS does with no
   list, is tolerated and left; a list of another name is an extra of that
   name and is kept, as before. A pulled Cisco device that has the list reads `differs` in
   `device config list` after the upgrade without a new pull, because the
   rendering changed; `device config plan <device>` prints the one line.
   Items 30, 31 and 76 of 0.2.5 say what 0.2.5 shipped and stand as written.

2. **The break-glass texts no longer make the console depend on a silent
   server.** The README, the manual page, the `breakglass hold` report and
   the Cisco walkthrough said that the console's local login and `enable`
   work only while no server answers, because `enable` asked the server
   first. With no enable list the `CONSOLE` login list is local and `enable`
   uses the local secret, so on a Cisco console a local account logs in and
   reaches privilege 15 while the server is up. The text now says so: the hold
   is for a vty local login (a server's FAIL for a local name is final) and
   for the local accounts of a Junos or WTI device. The Cisco way in in the
   hold report reads: ssh as a local account; on the console, the local
   account, then `enable` with the local enable secret.

## 0.2.5 (2026-10-11)

The items below are everything that differs from 0.2.3. Items 1 to 29 were
drafted under the working name 0.2.4 (the diff corpus and a few comments in the
code call them `0.2.4 item N`); items 30 and later were drafted as 0.2.5, and
all of them ship together as this release. The numbers 62 to 69 are not used.

### What changed

1. **`tacctl device config pull` reads what the devices run and compares the
   sections tacctl manages with what tacctl renders for each device.** Nothing
   is written to a device. It logs in to each device as the user who invoked
   tacctl (`SUDO_USER`; root is refused, and so is a caller who is not an active
   tacctl user with the device's scope, as for `tacctl ssh`) with that user's
   tacctl password, asked for once on the terminal without echo and never
   stored, put in an argument or the environment, written to a file or logged
   (the session's password cache, below, can hold it). The devices are named
   (`<name>[,<name>...]`) or selected with `--all` (every device of yours) or
   with `--scope`, `--vendor` and `--stale`, which combine; names and `--all`
   stand alone. An engineer's selection is their own scopes' devices. A device
   of vendor `other`, one in no scope and one in a scope you are not in are
   refused when named and left out, with a note that names them, by a selection;
   so is a WTI unit, which is not read: named, it is recorded `unsupported` and
   the run exits 1. A device needs a pinned host key (`device hostkey <name>
   accept`): an unpinned device is refused with that command, a key that is not
   the pinned one is `host-key-mismatch` and raises the `hostkey-changed`
   notice, and nothing is trusted on first use. Junos is read over NETCONF (the
   ssh subsystem, a `<command>` RPC) where the device answers and over an ssh
   exec channel otherwise (`--transport auto`, the default; `netconf` and `ssh`
   never fall back); IOS and IOS-XE are read with `terminal length 0` and `show
   running-config` over the ssh command line (not lab-tested; a Cisco device is
   never read over NETCONF, and `--transport netconf` refuses it before any
   login, leaving its record alone, or as wrong arguments when every selected
   device is Cisco). From the text six sections are extracted (`aaa`, `roles`,
   `mgmt-acl`, `snmp`, `netconf`, `breakglass`), compared with what tacctl
   renders for that device (the same builders as the walkthroughs; a Cisco
   device with `legacy-ssh` against the IOS 12.x syntax; `--server` and
   `--source` as for `config <vendor>`) and recorded. A secret (a server key, a
   community, a hash) is compared by presence only: no output, record or file
   holds a device's secret value. One line per device (`ok via netconf`, `ok,
   differs in aaa,snmp via ssh (netconf: port closed)`, `failed: <reason>`),
   rewritten in place on a terminal and appended otherwise; then `12 ok, 2
   differ, 1 failed`. `--diff` prints the differences, `--json` one JSON line
   per device and a summary line, `--timeout <seconds>` bounds one device
   (10-600, default 90, connect included), `--max-failures <n>` stops starting
   devices after n failures. At most `device.config.max_concurrency` devices are
   read at once (default 8; `--concurrency` lowers it, never raises it). The
   first rejected password stops the batch, so one wrong password is not tried
   on every device; the first Ctrl-C stops starting devices and lets the running
   ones finish (the rest are `not started`), a second cuts them off. Exit status
   0 (differences are not failures), 1 (a device failed or was refused), 2
   (wrong arguments), 130 (interrupted). Every device is logged (`auth.info
   device config pull user= device= transport= result= duration=`, never a
   credential) and an engineer's pull logs the `secret-read` lines the
   walkthrough logs.

2. **`tacctl device config diff` shows the last pull against what tacctl renders
   now, per section.** `-` is a rendered statement the device lacks, `+` one it
   has in a managed hierarchy that tacctl does not render, `!` the same
   statements in another order (a Junos authentication order or filter terms, a
   Cisco ACL), `?` a secret the login could not see (a Junos class without the
   secret permission masks its secrets and omits a server's `secret`: a masked
   one is present, an omitted one is never `-`), `=` a secret that is present. A
   section tacctl renders nothing for is `n/a`, with the device's statements
   listed. `--pull` reads the devices first (with the options of `pull`),
   `--section <list>` limits the output, `--json` prints an array and
   `--exit-code` makes a difference exit 2 (a device that could not be compared
   exits 1). A device never pulled is said so, with the command that reads it.
   With `--pull` the status follows the pull: a device whose pull failed, or was
   not started, counts as failed (1) even when the last good pull's diff is
   printed for it, and an interrupt is 130.

3. **`tacctl device config list` and `forget`, and the records.** A pull keeps,
   per device, `/var/lib/tacctl/devices-config.json` (when, by whom, over which
   transport, what the NETCONF probe found, the result, the state of each
   section; 0600, derived, never snapshotted) and
   `/var/lib/tacctl/device-config/<name>.yaml` (the managed sections of the last
   successful pull, secret values elided). `device config list` shows each
   device's state (`ok`, `differs`, `never`, `failed`) computed against today's
   rendering, so a change of the store makes a device `differs` without a new
   pull; `--stale` is `--never`, `--failed` and `--differs` together,
   `--transport netconf|ssh|none`, `--scope`, `--vendor` and `--json` narrow it.
   `device config forget <name>[,...]|--all` deletes records (they are derived:
   a pull makes them again). A failed pull changes the record's result and keeps
   the sections of the last good one, which `diff` still compares. `device
   rename` carries a record along; `device remove` and `device import --replace`
   drop the record and the sections file of the devices they remove.

4. **`device list` has a CONFIG column and `device show` a Configuration row.**
   The column is the state the last pull recorded (`ok`, `differs`, `never`,
   `failed`; `-` for a host, a vendor `other`, a WTI unit and a device in no
   scope) and is `config` in `--json`; the row says when, by whom and over what
   the device was read, the result and the state of each section (`pulled
   2026-10-09 14:02 by alice over netconf (hello ok), ok; sections: aaa ok,
   roles ok, ...`). Both are the operator tier's: a read-only user's `device
   list` and `device show` (and their JSON) have neither the column nor the row.
   `device list --stale` keeps its meaning (not seen in the logs for
   `stale-days`); the configuration's staleness is `device config list --stale`.

5. **`device check` shows a NETCONF row for a Junos device.** What the probe of
   the device's last pull found (`hello ok`, `port closed`, `no hello`, with the
   time), or `not probed` and the command that probes it; the check logs in to
   nothing. It is `netconf` in `--json`. A Cisco device is not read over NETCONF
   and has no row.

6. **`tacctl config devices` sets how pulls read the devices.**
   `max-concurrency` (1-64, default 8), `transport` (`auto`, `netconf`, `ssh`)
   and `timeout` (10-600 seconds, default 90) are the schema's
   `device.config.max_concurrency`, `.transport` and `.timeout`; with no word it
   shows them and whether each is set. Superuser only. `--concurrency` above the
   cap is refused, naming the cap and the verb that raises it.

7. **Tiers: `device config list` and the shell word `console forget` are the
   operator's, `device config show|pull|diff` and `device snmp` the engineer's,
   `device config forget` the superuser's.** The gate sees `device config`, so
   the verb holds each to its tier (`'tacctl device config pull' is not
   permitted for the operator tier.`, logged as a tier denial; the operator
   tier's `device config show` refusal now names the verb too). The tiers
   sudoers drop-in grants the operator `device config list` and `console forget`
   and the engineer `device config show|pull|diff` and `device snmp *`, and
   keeps `TACCTL_ASKPASS` for five command lines only: a `Cmnd_Alias` of `device
   config pull|diff|plan`, `ssh` and `device ssh` (named differently in the group
   drop-in, since sudoers refuses an alias defined twice) with its own
   `env_keep` line, so the variable is in the environment of the sudo process
   and never on sudo's command line (argv is world-readable). The rules are
   re-rendered by `config sudoers tiers install`, and `upgrade` rewrites an
   installed drop-in. An engineer's `device config list`, `pull` and `diff`
   cover the devices of their own scopes; another scope's device is not found.

8. **The shell and the login console can keep your network password in memory
   for the session, so a pull, a diff and the `ssh` lines after it ask once.**
   It is off for every tier until `tacctl console password-cache tiers
   <operator,engineer,superuser|none>` opens it (a read-only user has no pull
   and is not offered it); the console then has it for those tiers, and a plain
   `tacctl shell --password-cache` asks the same policy (a caller outside
   `tac-users` asks for it themselves). `console password-cache idle` is 1-120
   minutes without a use (default 15; each use restarts it) and `max` 1-24 hours
   from the moment the password was cached (default 8; use does not extend it);
   `tiers`, `idle` and `max` are superuser verbs. The settings are
   `settings.password_cache` in `console.yaml`, written only when one is not the
   default, and `console show` lists them; the policy line `_console-policy`
   carries `password_cache=yes pc_idle= pc_max=` for a tier that has the cache
   (an older console ignores them). The shell says `password cached for this
   session (console password-cache)` when it keeps a password and `password
   forgotten (<why>)` when it lets go: after the idle time, the maximum
   lifetime, `passwd` (or `user passwd`), the shell word `console forget`
   (operator and up; handled in the session's own process, without sudo), a
   device's refusal, a clock that went backwards, and the end of the session. It
   is for the interactive session only: `-c` and batch lines keep no process
   around and use no cache, and the plain CLI from bash asks per run. When the
   cache cannot start (memory cannot be locked, a debugger is attached, no
   private directory is available for its socket, or the policy cannot be read
   or does not allow the tier) one line says `password cache unavailable:
   <why>`.

9. **The cache lives in the session's own process and is opened only for the
   lines that use it, each with a token of its own.** The password is in a
   locked page of the shell's (or console's) process, which is marked not
   dumpable before it checks for a tracer, and is zeroed when it is forgotten;
   no file, log, argument or environment holds it. The process listens on a
   socket in a private directory (`$XDG_RUNTIME_DIR/tacctl`, else
   `/run/user/<uid>/tacctl`, else `~/.local/state/tacctl/run`) and is shut
   between lines. For a line that runs `device config pull`, `device config
   diff --pull`, `ssh` or `device ssh` (and no other) it makes a token for that line,
   puts `TACCTL_ASKPASS=<socket>:<token>` in the environment of that line's sudo
   process and answers the same user or root with that token once, until the
   line ends, when the token is dead: after the line's one get the token can do
   nothing but forget, a value read out of an earlier line, or by another
   process of the user after the line, opens nothing, and a request that was
   waiting when its line ended is refused. What remains is a process of the same
   user that reads the line's environment and reaches the socket before that one
   get. The root side marks its process not dumpable and, as the first thing any
   verb does, takes `TACCTL_ASKPASS` out of its environment, so no program it
   starts inherits it.

10. **A pull stores only a password it prompted for, after a device accepted it,
    and forgets it when one refuses it.** `device config pull` and `diff --pull`
    ask the session's cache first and prompt on the terminal only when nothing
    is cached; a password that came from the cache is never stored again, so the
    maximum lifetime cannot be stretched by use, and a device that refuses a
    cached password makes it forgotten at once and stops the run. A store never
    lands after a forget in one run.

11. **`tacctl ssh` uses a cached password for a device with pinned host keys.**
    ssh is started as the user directly, without sudo, so the token is never a
    sudo variable or argument and reaches no log, and runs `SSH_ASKPASS` (the
    tacctl binary; it answers a password prompt and nothing else) with
    `SSH_ASKPASS_REQUIRE=force`, one password prompt, no configuration file (no
    `SendEnv`, `ProxyJump` or `Match exec` of the user's) and strict checking of
    the pinned host key; an option word after `--`, an unpinned device or an
    account that is not in the local account database keeps the prompt as
    before. An ssh that ends with status 255 makes the cache forget the
    password, since a refusal cannot be told from other failures. The audit line
    says `password=cached` when the cache was used.

12. **`tacctl upgrade` rewrites the drop-in `config sudoers install <group>`
    wrote with an earlier release.** When the file is exactly the text 0.1.x to
    0.2.3 wrote for the group its header names, it is replaced by this release's
    (after `visudo -cf`), so a host that installed it before the password cache
    keeps `TACCTL_ASKPASS` through sudo: `Updated: sudoers for group <name>`, or
    a warning and the old file when `visudo` refuses. A file an administrator
    edited (a rule, a host restriction, extra lines) or that only has a tacctl
    header is left as it is with `customised`, naming `tacctl config sudoers
    install <group>`; one that says tacctl wrote it but names no group
    `config sudoers install` accepts (`[a-zA-Z_][a-zA-Z0-9_-]*`) gets one
    line, `<file>: not written by tacctl for a group it knows; left alone`; a
    file that is not tacctl's, a current one and an absent one are left alone
    and not mentioned.

13. **`tacctl device snmp <name>` gives one device SNMP settings of its own.**
    `device snmp <name> [show [--reveal] | version v2c|v3 | port <n> | timeout
    <seconds> | clients list|add|remove <cidr> | community [--stdin] | v3-user
    <user> [--stdin] | clear]`: a device that its scope's (or the default's)
    settings do not fit has its own version, agent port, wait, list of allowed
    clients and credentials. The order is the device's value, then its scope's,
    then the default's, then the built-in, one setting at a time (the v3 user
    and both passphrases come from one level, so a user is never joined to
    passphrases nobody paired with it); a device's list of allowed clients
    replaces its scope's for that device (the tacctl server's /32 stays first,
    `0.0.0.0/0` refused last). `community` and `v3-user` make the device's
    version `v2c` or `v3`, as the scope's verbs do. The non-secret settings are
    an optional `snmp:` map of the device in `devices.yaml` (`version`, `port`,
    `timeout`, `clients`), written only when something is set, so a registry
    that sets none is byte for byte what it was; the credentials are
    `/etc/tacctl/snmp/devices/<name>.yaml` (the lowercased name, 0600 in a 0700
    directory, the format of `snmp.yaml`, atomic writes; 0.2.3 never opens the
    subdirectory). `device remove` and `device import --replace` delete the file
    and `device rename` moves it; a new device, or a rename onto a name whose
    file is already there (an earlier device's, kept by a rollback), is refused
    with the file's path. `device import` and `device export` carry the map: a
    file without one never drops a device's own, and `device export --json` has
    it as `snmp`. 0.2.3 refuses a registry that has the map, so a rollback to
    0.2.3 has to remove it first.

14. **`device show`, `device check`, `scope snmp show`, `device config show` and
    the walkthrough say which value a device is read with and where it comes
    from, and every read uses it.** `device show` has an `SNMP` row (`version
    v2c (scope lab), port 2161 (device), timeout 4 s (scope lab)`, then the
    credentials as set or not, and the clients), `device check` an `SNMP` and an
    `SNMP creds` row before the sysName, and both put an `snmp` object (values,
    `*_from`, never a secret) in `--json`; `device config show` has the same
    rows in its data block, and the SNMP step of `config <vendor> --name
    <device>` says `Credentials: this device's own (tacctl device snmp <name>
    show --reveal).` and `this device's own ranges` when they are. `scope snmp
    <scope> show` prints the order of resolution and which of the scope's
    devices have settings of their own (what they set, never a value). The
    labels are `(device)`, `(scope <scope>)`, `(default)`, `(built-in)` and
    `(not set)`. `device add`, `device check` and `device location
    --from-device` read a registered device with its own version, port, timeout
    and credentials when it has them (`scope snmp <scope> test` and `config snmp
    test` still try the scope's and the default's), and `device config pull`,
    `diff` and `list` compare the `snmp` section (and the management filter's
    SNMP terms) with what tacctl renders for that device with its own values
    over its scope's; a device whose own credentials file cannot be read fails
    on its line instead of being compared with its scope's.

15. **Tiers, logging and snapshots for a device's own SNMP settings.** Setting
    and clearing are the superuser's; an engineer reads `device snmp <name>
    [show [--reveal]]`, the plain reads of version, port, timeout and `clients
    list` for the devices of their own scopes, and each `--reveal` (or
    walkthrough that prints the device's own credentials) is logged as
    `secret-read kind=snmp-device name=<device> by=<user>`, never the value; an
    engineer's `--reveal` logs one such line for each level a printed secret
    comes from (`kind=snmp-device name=<device>`, `kind=snmp name=<scope>`,
    `kind=snmp-default name=default`). The SNMPv3 user's name is the engineer
    tier's: `device show` and `device check`, and their `--json`, print `v3 user
    set` and `v3_user_set` below the engineer tier and the name (`v3_user`) from
    engineer up. An engineer's `device import` neither sets nor drops a device's
    own settings (a file that carries a map that differs is refused). Snapshots
    hold `snmp/devices/` in its modes, and `device snmp <name> community`,
    `v3-user` and `clear` take the snapshot before the credentials file is
    written or removed, so it holds the old credential (also for a clear of a
    file that has no map). `backup restore` makes `snmp/devices/` match the
    registry it restores, also when the snapshot has no `snmp/` directory
    (absent means none), so no device file is left that the restored registry
    has no map for; a snapshot without a registry (0.2.0) leaves them alone. A
    file that cannot be read can be repaired: `clear` removes the file without
    parsing it, `community` and `v3-user` replace a file that cannot be parsed
    and say so, every read that meets one names it and the way out, and `scope
    snmp <scope> show` lists the device as unreadable instead of skipping it.

16. **`tacctl rollback 0.2.3` prepares the state for 0.2.3, and 0.2.2 is two
    steps away.** The tool of 0.2.3 (target 0.2.2) is replaced: each release's
    rollback converts what that release changed, so this one takes `0.2.3` only,
    as a dry run unless `--apply` (a snapshot first; `--yes` while a setting is
    dropped). It removes `device.config.max_concurrency`, `.transport` and
    `.timeout` from `tacctl.yaml` (and any key a 0.2.3 binary does not know),
    `settings.password_cache` from `console.yaml` (the cache is off again;
    `tiers.engineer` and `space_completion` are 0.2.3's own and stay) and the
    `snmp:` map of every device from `devices.yaml` (0.2.3's parser answers
    `unknown key 'snmp'` and cannot read the registry); it rewrites the tiers
    sudoers drop-in and the `config sudoers install <group>` drop-in with
    0.2.3's text, after `visudo -cf`, when the file is exactly this release's
    text (an edited file, or one `visudo` refuses, is left and named; 0.2.3's
    upgrade rewrites the tiers file itself). It leaves, and lists,
    `snmp/devices/` (0.2.3 never opens the subdirectory), the records of the
    pulls in `/var/lib/tacctl` (`devices-config.json`, `device-config/`:
    derived, never snapshotted; `device config forget --all` before the rollback
    deletes them), `store.yaml` and the rendered backend files, and re-renders
    and restarts nothing. `--hosts` is accepted and says no host needs anything.
    `rollback 0.2.2` is refused with the way there: this rollback, `tacctl
    upgrade --branch 0.2.3`, then 0.2.3's own `rollback 0.2.2` (so the 0.2.2
    conversions, the tier marker, the SNMP credentials directory and the
    `--hosts` sync of the engineers' sudo are that release's tool). The snapshot
    holds the 0.2.5 form: restore it with 0.2.5, not with 0.2.3. Rolling back,
    then: dry run `tacctl rollback 0.2.3`, `tacctl rollback 0.2.3 --apply
    --yes`, `tacctl upgrade --branch 0.2.3`; until the install, a command that
    writes the console's settings, a device's SNMP settings or `config devices`
    writes the 0.2.5 form again, and a second `--apply` converts it. (The real
    0.2.3 release, built from its tag, is run against the state before and after
    in the test suite.)

17. **Test builds only: `tacctl _fake-device` and two knobs.** A `-tags
    testknobs` build (`make build`) has a hidden verb that runs the fake device
    of `internal/devssh/fakedev` on loopback, and `TACCTL_TEST_DEVICE_DIAL` (a
    loopback `host:port` every device is dialled at) and
    `TACCTL_TEST_DEVICE_PASSWORD` (the password a pull logs in with); the bats
    files of the device configuration verbs run against them. The installed
    binary has neither the verb, the fake device nor the variables' names.

18. **A device's own SNMP credentials count only while the device has an `snmp:`
    map.** The map gates the file `snmp/devices/<name>.yaml`: a file with no map
    beside it (what a rollback to 0.2.3 leaves, or a stray) is ignored by the
    lookups, the walkthroughs, `device show`, `device check`, the pull's
    expected configuration and `scope snmp show`, and is not parsed. `device show`
    and `device snmp <name> show` say once that it is present and ignored, with
    `clear` as the way out; giving the device settings brings it into force
    again and the verb says so, and `community` and `v3-user` replace it
    instead of carrying its other half. A device that has a v3 user in an ignored
    file under a v2c scope is therefore read with the scope's settings, not with
    its own credentials under the scope's version.

19. **`tacctl uninstall` removes the device records of `/var/lib/tacctl`.** The
    seen cache (`devices-seen.json`), the records of the configuration pulls
    (`devices-config.json`, `device-config/`) and their lock files go with the
    rest, so the directory itself is removed when nothing of anyone else's is in
    it; they held excerpts of each device's configuration (secret values elided).

20. **The Junos walkthrough writes the management filter's deny terms as plain
    `set` statements.** The terms that log and drop (`deny-mgmt`, and
    `deny-snmp` under SNMPv3) were printed as `then { log; discard; }`, which
    is the brace form of a hierarchy, not a `set` line a device takes. They are
    now `set firewall family inet filter <name> term deny-mgmt then log` and
    `... then discard` (and the same for `deny-snmp`). The pull's expected
    configuration is built from the same lines.

21. **A `legacy-ssh` device also gets the CBC ciphers old IOS offers.** Old IOS
    (12.4) offers only `aes128-cbc`, `aes192-cbc`, `aes256-cbc` and `3des-cbc`,
    which neither OpenSSH nor the built-in client has by default, so `tacctl
    ssh` and a pull failed with `no matching cipher found` after the key
    exchange and the host key had been accepted. `legacy-ssh` now appends
    `Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc` to the options of
    `tacctl ssh` and to the `Host` blocks of `device ssh-config`, and the
    built-in client of the device reader appends `aes128-cbc` and `3des-cbc`
    (the CBC ciphers it implements) to its own list. The strong ciphers stay
    first, so a modern device still negotiates them.

22. **`device add` and the host-key re-scans read the key of a `legacy-ssh`
    device with the built-in client.** OpenSSH 9's `ssh-keyscan` cannot do the
    `diffie-hellman-group1-sha1` key exchange or the CBC ciphers an old IOS
    unit offers, so it printed no key and `device add --legacy-ssh` was
    refused (`No ssh host key could be read`) until `--no-host-key` or `device
    hostkey <name> set SHA256:<fp>` was used. When `ssh-keyscan` reads no key
    from a `legacy-ssh` device, tacctl now tries its own ssh client, which
    negotiates the legacy algorithms and stops at the host key, before
    authentication: no password is ever sent. It asks for each key type the
    device offers and pins them like `ssh-keyscan`'s, with the same `SHA256:`
    fingerprints. It applies to `device add`, `device hostkey <name> accept`,
    the re-scans of `device scan` and `device check`, and the mismatch report of
    `tacctl ssh`. The refusal still appears when both reads fail, and now says
    so.

23. **A pull of a legacy IOS router compares what IOS stores with what was
    typed.** Read from a lab router (IOS 12.4(15)SW), `show running-config`
    prints the typed lines of tacctl's configuration in forms the first
    comparison listed as differences. The `privilege exec level N <words>` line
    IOS stores for the words it knows, when it does not know the last ones
    (`privilege exec all level 7 monitor capture` is stored as `privilege exec
    level 7 monitor`: the image has no `capture`), is no longer an extra line
    of `roles`, and `snmp-server queue-length 100`, which the image prints
    beside the first community, is no longer an extra line of `snmp` when
    tacctl renders a community. A line of another level or mode, a different
    queue length and a device-side `all` are still extra, and the command the
    image did not store (`monitor capture`) is still missing, so `roles` of
    such a device stays `differs`.

24. **The Cisco comparison reads how the console and VTY lines log in, and
    whether the device has an `enable` secret.** The `aaa` section of a Cisco
    device now holds the login method of `line con 0` and of every `line vty`
    range, which the walkthrough prints as `login authentication default`
    (the rendered `aaa` of every Cisco variant, IOS-XE, IOS 12.x and RADIUS,
    ends with those lines). A router whose VTY lines still say `login local`
    shows `+ line vty 0 4 > login local` and `- line vty 0 15 > login
    authentication default`. IOS does not print `login authentication
    default` under a line (the lab router, IOS 12.4(15), has `aaa new-model`
    on and only the access class under its VTY lines), so with `aaa new-model`
    on the device a line that has no `login` statement counts as `login
    authentication default`, as does one that prints it; a rendered `line vty
    0 15` is satisfied when the device's ranges (`line vty 0 4`, `line vty 5
    15`) with that method cover it, and the ranges that are in order are not
    listed. A router without `aaa new-model` has no method on a line with no
    `login` statement, and one that has nothing of AAA but `login local` on
    its lines is `missing`, the lines listed all the same. The extraction also
    records whether the device sets an `enable` secret or password for level
    15 (by presence, never the value, as one statement of `aaa` in the
    sections file), and a device with none gets one note under `aaa` when the
    rendering turns AAA on: with the server unreachable a local user of
    privilege 15 is then the only way to level 15. A record made by an older
    tacctl says nothing about the lines or the secret: it is not compared on
    the lines (a note says so) and gets no note about the secret until the
    next pull. A rendered `privilege exec [all] level N ...` line that the
    device stores shortened (`monitor capture` as `monitor`) stays missing,
    now with a note that names the line the device holds instead; it is not
    read as equal, since a device on which the line was removed and its
    parent left looks the same.

25. **A Cisco device's configuration syntax is a setting of its own:
    `tacctl device config-syntax <name> [auto|ios12|modern]`.** Two lab
    devices that need `legacy-ssh` (IOSv 15.6, CSR1000v IOS-XE 16.7) speak the
    modern `tacacs server NAME` syntax, but the comparison rendered the IOS 12.x
    syntax for every device with the flag, so `device config pull --diff` read
    both as `aaa differs`, while `device config show` printed the modern syntax;
    one flag carried two facts. The syntax is now a per-device fact, written to
    `devices.yaml` as `config_syntax: ios12|modern` only when set (`auto`, the
    default, is the absence of the key). The verb prints the setting with no
    word, and is an Engineer verb for the devices of the engineer's own scopes
    (sudoers `device config-syntax *`, the tier tables and the completion
    lists); it refuses a device that is not a Cisco device. `device add
    --config-syntax auto|ios12|modern` sets it on registering (with `--vendor
    cisco`). `device show` has a `Config syntax` row for a Cisco device
    (`auto (modern, from the pull of 2026-10-10)`, `ios12`; the resolution is
    part of the configuration state the read-only tier is not shown), and
    `device show --json`, `device list --json` and `device export` carry
    `config_syntax` (and, for `show` and `list`, `syntax` and `syntax_source`).
    `device import` of the registry's YAML carries the key; a CSV row, and a
    YAML file that has none (a registry exported by an earlier tacctl), say
    nothing of it, so a merge keeps the registered one. One resolution decides
    the syntax for the comparison (`device config pull`, `diff` and `list`) and
    for the walkthroughs (`device config show`, and `config cisco --name` of a
    registered device): the explicit `ios12` or `modern`, else the syntax the
    last pull derived from the device's version line, else (walkthrough only)
    the modern syntax with one line, `# syntax: modern (no pull yet; set
    'tacctl device config-syntax <name> ios12' for IOS 12.x, or pull the device
    once)`, after the data block of `device config show` and on standard error
    of `config cisco --name`. `--legacy` of `config cisco` and `device config
    show` stays an explicit IOS 12.x override for that run. A scope served over
    RADIUS has one syntax, as before. The setting is a Cisco setting
    everywhere: a registry file, an import and a save refuse `config_syntax` on
    a device of another vendor, and `device vendor <name> <other>` removes the
    setting and says so. A setting that contradicts the image the last pull
    read (`modern` on a device whose pull read `Version 12.4`: the lock-out
    direction) is not refused (the setting wins) and is no longer silent:
    `device config pull` ends the device's line with `warning: config-syntax is
    modern but the device says IOS 12.4(15)T14 (ios12 syntax)` and `--json`
    carries `syntax_conflict`, `image_syntax` and `os`; `device show` and
    `device config-syntax <name>` say `modern (the pull of 2026-10-10 read IOS
    12.4(15)T14, which is ios12 syntax, not modern: check the setting)`
    (`syntax_conflict` and `image_syntax` in `--json`); `device config list`
    names it in the DETAIL column and `--json`; the walkthrough prints one
    `# warning:` line; and `device config-syntax <name> <word>` says it when
    the setting is made. For a device that was pulled by a build that kept no
    image line, `device config show` says `the last pull holds no image line:
    run device config pull <name>` instead of `no pull yet`.

26. **`legacy-ssh` is the ssh algorithms and nothing else.** The flag adds the
    SHA-1 key exchange, the CBC ciphers and `ssh-rsa` to the ssh login, the
    host-key scan and `tacctl ssh`; it no longer decides which syntax a
    device is rendered or compared in (item 25). The help of `device
    legacy-ssh` and `device add --legacy-ssh`, the README and the manual page
    no longer say "old IOS" or "rendering" for it, and the hint a failed
    handshake prints names the algorithms.

27. **`device config pull` of a Cisco device records the image and the syntax
    it says.** The Cisco read gains `show version | include Version` after
    `terminal length 0` and before `show running-config`; the first line that
    names the image (`Cisco IOS Software, ... Version 15.6(2)T`, `Cisco IOS XE
    Software, Version 16.07.01`) is kept on the record as `os`, and the syntax
    derived from it as `syntax`: `Version 12.` is `ios12`; `Version 15.2` to
    `15.9`, `16.`, `17.` and `IOS-XE` or `IOS XE` are `modern`; **any other
    line has no syntax and is never guessed modern**: IOS 11.x, IOS 15.0 and
    15.1 (the `tacacs server NAME` syntax is believed to start at 15.2, which
    is not verified for those, so they take the setting), an ASA registered as
    cisco and IOS XR. The loader's `ROM:` and `BOOTLDR:` lines name no image
    and are ignored, so a device that answers only those has no version line.
    The comparison of the pull is made in the syntax the device says now unless
    the setting says otherwise (an upgraded device is not compared in the
    syntax it had), and `pull --json` carries `syntax` and `os`. A device
    that answers no image line, or one that maps to no syntax, is not an error
    of the read; if it has no setting (and, for no line at all, its record has
    no syntax either), the pull is refused with `tacctl device config-syntax
    <name> ios12|modern`, and nothing is recorded: the pull's own output is
    where the reason is, and `device config list` is unchanged. Under a
    setting the pull is compared as set and a record that read no line keeps
    no image.

28. **A Cisco device whose syntax is unknown is `pull`, not guessed either
    way.** Nothing in the registry is rewritten by the upgrade, and a record
    made before item 27 (by a build that did not read the version line) has no
    version line: a Cisco device whose setting is `auto`
    and whose last good pull recorded no syntax is `needs pull (syntax
    unknown)` in `device config list`, `pull` in its state column and in the
    CONFIG column of `device list`, and `--stale` selects it (so does `device
    config pull --stale`). `device config diff` of it says `needs pull
    (syntax unknown)`. One `tacctl device config pull --vendor cisco` after the
    upgrade makes every such device known; an operator who knows a device sets
    `ios12` or `modern` and compares it without that pull (the 12.4 router is
    one `device config-syntax <name> ios12`). A record whose version line maps
    to no syntax is in the same state. A device of a RADIUS scope is never in
    this state.

29. **`tacctl rollback` removes the `config_syntax` key.** A release before
    0.2.5 refuses a `devices.yaml` with a device key it does not know
    (`device 'x': unknown key 'config_syntax'`), so the rollback plan lists
    each device that has one under the devices step, warns that the older
    release compares a `legacy-ssh` Cisco device as IOS 12.x again, and
    `--apply` removes the keys in the one write that removes the SNMP maps,
    after the snapshot. The records' `os` and `syntax` fields stay: the older
    release ignores them.

30. **`config cisco` and `device config show` print the standard Cisco block,
    and the managed `aaa` section is that block.** One set of lines, in one
    order, for every Cisco device (the three templates `cisco`,
    `cisco-legacy` and `cisco-radius`, rewritten, and the managed sections
    built from the same builders): `aaa new-model` first (nothing under
    `aaa` exists on IOS until it is set, so a group and its `server` leaf
    typed before it are rejected); the server block and its group;
    `ip tacacs source-interface <interface>` when the scope sets one (item
    33); `aaa authentication login default <methods>` and
    `aaa authentication login CONSOLE local`; `aaa authorization exec default
    <methods>`; `aaa authentication enable default group <G> enable`;
    `aaa accounting exec ...` and `aaa accounting commands <level> ...` per
    level in use; `aaa session-id common`; the `privilege exec level` lines;
    SNMP; the VTY access list; the NETCONF step (commented); `line con 0` with
    `login authentication CONSOLE` and `line vty 0 15` with `login
    authentication default`. The command authorization (`aaa authorization
    commands <level> ...` per level in use and `aaa authorization
    config-commands`) is a Step 2 of its own, after a check: the session
    that pastes is a local user the server does not know, and a server that
    answers `fail` for such a name is final and never falls through to
    `local`, so a device whose TACACS+ path is not proven could end with no
    session able to run a command. The walkthrough says to open a new
    session with your own account, run `show privilege`, and only then type
    Step 2. From `aaa new-model` until the login lists are typed a new
    TACACS+ login would fail (a local user still gets in): the walkthrough
    says to paste the block in one go from a session that stays open. RADIUS gets the same where RADIUS has it (no command
    authorization; `ip radius source-interface`); its `aaa authentication
    enable default group <G> enable` is not rendered or compared (item 31).
    `--legacy` (the IOS 12.x syntax) differs from the modern output in the
    server block (the global `tacacs-server host ... single-connection
    timeout 5 key ...` line and `server <ip>` under the group), the local
    enable secret line (`enable secret <PASSWORD>`, not `enable
    algorithm-type scrypt secret <PASSWORD>`), the hashes of the break-glass
    accounts (type 5, not type 9), the NETCONF step (a comment: IOS 12.x has
    none) and the Type 6 note (not available on 12.x); the `aaa` lines, the
    `privilege exec level` lines, SNMP and the access list are the same.
    Everything the walkthrough pastes is ASCII (the remark of the access list
    and the privilege headings had a dash that was not).

31. **The console has a login list of its own, `CONSOLE`, and `enable` asks
    the server first.** `aaa authentication login CONSOLE local` and
    `login authentication CONSOLE` under `line con 0`: a local user can
    always log in on the console, since the `default` list asks the server
    first and a reject from the server does not fall through to local. With
    the server up that user lands at privilege 1: the standard does not set
    `aaa authorization console` and must not (it would put the console under
    the `default` lists, server first, and defeat `CONSOLE`; the walkthrough
    says so where it used to suggest uncommenting it), and `enable` asks the
    server first, which refuses a name it does not know and does not fall
    through, so the local console is a way to privilege 15 only while no
    server answers. `aaa authentication enable default group <G> enable`
    makes `enable` ask the server first: a TACACS+ user lands at the level
    the server's `priv-lvl` gives, so nobody types `enable` while the server
    is up (an operator who does is refused by the server, by design: levels
    come from groups, not from a shared password), and only when no server
    answers does the keyword fall through to the local enable secret. There
    is no enable password in the login path. For RADIUS what a server answers
    to IOS's enable request is not verified: with a reachable server that
    does not answer enable requests positively `enable` fails, and the local
    enable secret is used only when no server answers, so the RADIUS
    walkthrough carries the line commented out with that note and neither
    renders nor compares it (a device that has it is not told it is extra).
    The comparison reads the console's leaf as any other: a console that
    prints no `login authentication` leaf is on the default list, which is
    not `CONSOLE`, so it shows `- line con 0 > login authentication CONSOLE`
    and `+ line con 0 > login authentication default` (the vty lines on the
    default list with no leaf stay what they were).

32. **`aaa session-id common` is rendered and compared.** It was only
    tolerated (never an extra, never missing); it is now a statement of the
    `aaa` section like the others, and where a rendering has none (an
    operator's own template, an old record) a device's line is still no
    extra.

33. **`tacctl config cisco source-interface <scope> <interface>|none`
    sets the interface a scope's Cisco devices take their server requests'
    source address from.** Stored as `cisco.source_interface.<scope>` in
    `tacctl.yaml` (the full interface name as IOS prints it, with its capitals:
    `Loopback0`, `GigabitEthernet0/0/1`, `TenGigabitEthernet`,
    `FortyGigabitEthernet`, `FastEthernet`, `Ethernet`, `Serial`, `Vlan`,
    `Port-channel`, `Tunnel`, `BVI`, `Management` and the other long type
    names the verb's help lists; an abbreviation such as `lo0` or `gi0/1` is
    refused, because IOS stores the long form and the device would compare
    different for ever; checked by the schema; unset by default; moved by
    `scope rename`, dropped with the scope, removed by `rollback 0.2.3`),
    rendered as `ip tacacs source-interface <interface>` (`ip radius
    source-interface` for RADIUS), compared like any statement, and listed
    by `config show` when a scope sets one. Without arguments the verb lists
    every scope's setting, with a scope it shows it; setting or unsetting is
    the superuser's, an engineer reads their own scopes' (the tier gate sees
    `config cisco`, which an engineer may run for the walkthrough, so the
    verb decides). **Unset, nothing is rendered or compared** (never a
    placeholder in a statement): the walkthrough prints the line commented
    with the command, and a source interface a device already has is left
    alone, not an extra.

34. **The names are the ones tacctl has always rendered; nothing is renamed
    and nothing migrates.** The server block `TACACS`, its group
    `TACACS-GROUP` (`scope tacacs-group` sets another), `VTY-ACL`,
    `TACCTL-SNMP`; the one new name is the console's list `CONSOLE`. A device
    configured by an earlier walkthrough needs no rename. The forms it may
    still carry (a global `tacacs-server host` on a modern image, a
    `radius-server host` beside a `radius server` block, a server group of
    another name) are listed by `device config pull --diff` and `device
    config diff` as extras (`+` lines), never as satisfied lines, and the
    standard's lines as missing (`-` lines); the walkthrough removes none of
    them (`device config plan` replaces or removes them, items 39 and 50).
    The README gives the steps to replace an old `tacacs-server host` entry
    from the console (the old entry out, the named block in, each group
    that held its address pointed at the named block, then a check): the
    groups keep their names, so the method lists that name them keep
    resolving (when no group holds the old address, because the lists use
    `group tacacs+`, the standard group is created and the lists keep using
    `group tacacs+`), and with command authorization on a TACACS+ session
    must not be the one that removes the entry. A device that also has
    `aaa authorization console` cannot take the four steps as they are (the
    group has no server after the old entry goes, command authorization
    falls to `local`, and a TACACS+ user is not in the local database): the
    README and the manual page put a step 0 first, `no aaa authorization
    console`, typed while the TACACS+ user's commands still pass (the
    standard never sets it and it is not put back).

35. **The walkthrough starts with Step 0, a commented hardening checklist and
    the local enable secret.** `hostname`, `ip domain name`, `no ip domain
    lookup`, `service password-encryption`, `service timestamps debug|log
    datetime msec localtime`, `no service pad`, `no ip source-route`, `no ip
    http server`, `no ip http secure-server`, `ip ssh version 2`, `ip ssh
    time-out 60`, `ip ssh authentication-retries 3`, `transport input ssh`,
    `exec-timeout` and `logging synchronous` on the lines, then `no enable
    password` and `enable algorithm-type scrypt secret <PASSWORD>` (`enable
    secret <PASSWORD>` for IOS 12.x), followed by the scope's break-glass
    accounts, which moved there from the end so that the local user exists
    before AAA is turned on. Everything in it is comments: site policy, never
    compared, never part of the managed sections.

36. **A Cisco device configured from an earlier walkthrough.** It reads as
    missing the lines of items 30 and 31 and, for its console, as `login
    authentication default` where the standard has `CONSOLE`; nothing is
    rewritten by the upgrade and a pull of the device shows exactly that. A
    record pulled before this release holds no `aaa session-id common` in its
    `aaa` section (it was not read then), so it shows as missing until the
    next pull. The break-glass step of the walkthrough is now Step 0 and says
    the CONSOLE list takes the same accounts. `rollback 0.2.3` removes the
    `cisco.source_interface.<scope>` keys (a 0.2.3 binary refuses a key it does
    not know).

37. **`tacctl device config plan` prints what to paste to make a device match
    what tacctl renders.** Per device, from the last pull: a box naming the
    device, the irregularity report in plain words, ONE region between `PASTE
    FROM HERE` and `PASTE TO HERE`, the check and the one line to type
    yourself afterwards, and the back-out as comments. Nothing is written to a
    device, and nothing is read from one unless `--pull` says so (it is the
    pull of `device config diff --pull`, with the pull's options; its progress
    goes to standard error). The devices are named (`<name>[,<name>...]`) or
    selected with `--all`, `--scope`, `--vendor` and `--stale`, as for `pull`
    and `diff`; `--section aaa,roles,mgmt-acl,snmp` limits the plan (the
    report still names the others; `netconf` and `breakglass` are never
    planned and are a wrong argument). The report has one numbered item per
    finding of the comparison (missing, different, out of order, extra, a
    secret not visible, not plannable for this login), its section, the
    statement in words with the line (a secret's value elided), its severity
    (`ACCESS`, `MONITORING`, `COSMETIC`) and what the paste does about it
    (`Fixed by region line 3`, `Left alone`, `Not fixable by this login`).
    The region holds only statements the device takes as they stand, the
    wrapper lines and one label comment per section; the report, the check,
    the follow-up and the back-out are comment lines outside it. A device that
    was never pulled, was pulled more than `stale-days` ago, whose last pull
    failed, whose Cisco syntax is not known (`needs pull`), a WTI unit, or one
    whose plan has nothing to paste because a section was refused (a
    statement a Junos group applies, the lock-out guards of the Cisco `aaa`
    unit) cannot be planned: exit 1, one line on standard error and, with
    several devices, the cover page. Exit status 0 (the outputs were made, a
    consistent device included), 1, 2 (wrong arguments; with `--exit-code` also
    a device that needs a change and none that could not be planned), 130.
    Every device is logged (`auth.info device config plan user= device=
    status= sections= converge= secrets= out=`, never a value).

38. **A plan is safe when pasted whole, and its follow-up is never in it.** On
    Junos the region is `configure private`, the statements, `show | compare
    | no-more`, `commit check` and the confirmed commit `commit confirmed N
    comment "tacctl plan <device> <time> by <user>"`: without the one word
    `commit`, typed by hand after the check, the switch undoes the paste by
    itself in N minutes. A `configure private` that another session's
    uncommitted work refuses leaves every later line an unknown command, and
    the report says so. On IOS the region is `configure terminal`, the lines
    and `end`: the change is live at `end` and nothing rolls it back by itself
    (the report says so twice and asks for a second privilege-15 session until
    the end); there is no revert timer, because on IOS 15.x it reverts only
    while the session that armed it stays open, which is not the case that
    matters, a paste that cuts the technician's own session. `write memory`
    is typed by hand after the check. The region never holds a plain
    `commit`, `exit`, `rollback`, `write memory`, `configure confirm`, `copy`,
    `delete /force` or `reload`, nor `breakglass`, `netconf`, the application
    of the management filter on `lo0`, the `access-class` binding, `system
    root-authentication`, `system services ssh`, groups, `username`, `enable
    secret` or a `line` header; every region is checked to be printable ASCII
    and of an owned shape before it is printed. **`tacctl config devices
    confirm-timeout [<minutes>]`** sets N (1-60, default 5; the key
    `device.config.confirm_timeout` of `tacctl.yaml`, which `rollback`
    removes).

39. **`--converge` adds a cleanup region for the extras.** A statement in a
    standard hierarchy that the standard does not have is reported with its
    severity and the exact line that removes it, and left alone by the plan's
    region. `--converge` makes the region that removes the old servers and the
    like, between `CLEANUP FROM HERE` and `CLEANUP TO HERE`, for a device that
    has nothing else to paste (item 46): on IOS another `tacacs server` block
    or `tacacs-server host` line of the scope's protocol, an old `aaa group
    server` (its entries first, the group before the server it names), another
    `snmp-server community`; on Junos another `system tacplus-server` (a
    `system radius-server` on a RADIUS scope: only the scope's own protocol,
    item 53), another `snmp community`, the entries of another `snmp
    client-list`, a login class no user uses. Never a login, a line, the enable
    secret, a method list, another ACL, the other protocol's servers and
    groups, a server or group that a statement which stays names (item 47);
    never a line that holds the address given with `--from` (the address you
    are logged in from), and without `--from` no client-list entry; the whole
    cleanup is refused while the standard's server is missing and the plan does
    not put it there; a section the pull's login could not see completely is
    not cleaned. The cleanup ends as the plan does (`commit confirmed`, or
    `end`), has its own follow-up, and each item of the report says which
    cleanup line removes it.

40. **`--backout` prints the back-out region alone.** From the last pull: the
    statements that put back what the pull showed, for the sections the plan
    changed, between `BACK-OUT FROM HERE` and `BACK-OUT TO HERE`, with the
    same wrapper as the plan's region. On IOS the `no` lines in reverse
    order, with the console and VTY login leaves typed again and never a `no
    line`; a secret tacctl does not hold is a comment that says to type it
    again. A pull made after the paste replaces what the back-out is computed
    from: the plan keeps its back-out beside the record, and `--backout` prints
    that one then (item 48); `--out-dir` also writes it beside the plan, at
    plan time, as `<name>.backout.txt`.

41. **`--plain`, `--json`, `--out`, `--out-dir`, `--force` and the cover
    page.** `--plain` is the statements of one device, no wrapper line, no
    comment, no banner (for `load set <file>` on Junos; with `--converge` a
    device that has a cleanup makes two files, `--out` and
    `<name>.cleanup.set`); `--plain` of several devices
    needs `--out-dir`, and `--plain --no-secrets` is refused. `--json` is an
    array with one object per device (`name`, `address`, `scope`, `vendor`,
    `based_on`, `status` `consistent`, `needs-change`, `left-alone` or
    `cannot-plan`, `reason`, `irregularities`, `region`, `after`, `backout`,
    `extras`, `skipped`, `withheld`, `warnings`, `confirm_timeout`, and with
    `--converge` `cleanup`, `cleanup_after`, `cleanup_deferred`,
    `cleanup_refused`, `cleanup_left`); a secret's value is never in it. `--out <file>` writes one
    device's output; `--out-dir <dir>` one file per device (`<name>.txt`,
    `.set` with `--plain`, `.json` with `--json`), each plan's
    `<name>.backout.txt` and, for several devices, `COVER.txt`. The files are
    0600 in a 0700 directory (an existing directory open to others is
    refused), written as the user who ran sudo (the verb runs as root, and a
    path a lower tier names is never written with root's rights), and an
    existing file is refused, all of them before any is written, unless
    `--force`. Several devices print the cover page first: one line per
    device (`consistent`, `needs change: 2 irregularities fixed by the paste,
    1 left (1 ACCESS), 1 extra`, `NOT consistent, nothing to paste`, `cannot
    be planned: <why>`) and the totals, then the outputs separated by a rule.

42. **A plan types a secret only where the device lacks it.** A server key or
    community the device lacks is typed in its line, and the output says so:
    `THIS OUTPUT HOLDS THE TACACS+ KEY OF SCOPE lab` is the first line of the
    report and is repeated on standard error, so a redirected output carries
    it. A secret the device has, or one the pull's login could not see, is
    neither printed nor changed unless `--secrets`, which types every secret
    statement of the planned sections again (the way to rotate a key).
    `--no-secrets` leaves each as a comment line, `# VALUE NEEDED, then remove
    this mark: ...`, so a paste as it stands cannot set the literal
    `<SECRET>`. The values are the ones `device config show` prints for the
    same caller; an engineer's print logs `secret-read`.

43. **A Cisco plan follows the standard block, and holds command
    authorization back until the server is proven.** The region is the
    standard's order: `aaa new-model`, the server block or host line, the
    group, the method lists with `aaa authorization exec` directly after the
    login list, accounting, `roles`, `snmp`, `mgmt-acl`, then the console and
    VTY login leaves. The `aaa authorization commands <level>` and
    `config-commands` lines are in the paste only when the pulled
    configuration already uses the scope's server (its address in a server
    block or host line and a login or exec list that names the group);
    otherwise the report says `command authorization is not in this paste: log
    in on a new session with your own account and check 'show privilege', then
    plan again; it is the one group of lines left`, and the first plan puts
    everything else (once the commands list names the server every further
    command of the pasting session and of its back-out is asked of it, and
    the server answers FAIL for a user it does not know and never falls
    through). A device that has no local user at privilege 15 and no `aaa
    new-model` is refused for `aaa`. The syntax is the one resolution of
    `device config-syntax` and the pull's version line (item 25), never the
    ssh flag. The unset `cisco.source_interface.<scope>` is a warning of the
    report, never a line. The report says `Checked on a device: IOS 12.4(15) (a
    7200 emulator), IOS 15.6(2)T and IOS-XE 16.7.1; other trains are written
    from the references`.

44. **Who may plan, and what a login's class cannot commit.** `device config
    plan` is an Engineer verb for the devices of the engineer's own scopes (the
    tier tables, the completion lists and the sudoers rule `device config plan
    *`; a superuser sees all; an operator is refused). The Junos login class of
    the caller's group, as the rendering gives it, decides what is planned: a
    section it cannot commit (for `EN-CLASS`: the server, accounting, `login`,
    `snmp`) is not in the region and the report says `Not fixable by this
    login: EN-CLASS cannot change 'system tacplus-server' (ask a superuser)`,
    in one line. `plan --pull` shares the pull's password handling, so the
    shell's and the console's password cache serve it too (the
    `TACCTL_ASKPASS` alias names it).

45. **A Junos pull also reads the plain view.** After the inheritance view,
    the same session reads `show configuration | display set` (best effort: a
    device that does not answer it is still pulled) and keeps it, in the form
    of the sections file, as `/var/lib/tacctl/device-config/<name>.plain`
    (0600, stamped with the time of the pull it belongs to, so a view of
    another pull is ignored; `device config forget` and `device rename` carry
    it). The plan
    compares the two to tell a statement of the device's own from one a group
    supplies: a statement that a group applies is never changed, its section is
    refused. A record without a plain view says so in the report (`pull the
    device again to read it`).

46. **A device with something to paste gets no cleanup beside it.** A
    technician who copies a whole output runs every region in it: the old
    server would go in the paste that adds the new one, and on Junos the second
    `commit check` would confirm the first region's pending `commit confirmed`
    unverified. `--converge` therefore makes the cleanup region only for a
    device whose first region is empty (the plan after the paste and the
    verifying pull, `tacctl device config pull <name> --diff`); the cleanup is
    then the whole output, between `CLEANUP FROM HERE` and `CLEANUP TO HERE`
    (never the first region's `PASTE TO HERE`). A device with a first region
    gets that region and one line in the report: `cleanup comes after this
    region is pasted and verified: pull the device, then plan --converge
    again` (`cleanup_deferred` in `--json`); `--plain --converge` makes the
    cleanup file only for a device that has one.

47. **The cleanup never removes what a statement that stays names.** An IOS
    cleanup removes only the scope's own protocol's servers and groups (a
    TACACS+ scope never touches `radius server`, `radius-server host` or `aaa
    group server radius`, which may serve 802.1X or another list; a RADIUS
    scope never touches TACACS+); never a group that an `aaa ... group <name>`
    line which stays names, nor the servers that group names (the report says
    which statement names it); no server at all while a staying list uses
    every server of the protocol (`group tacacs+`, `group radius`); and no
    named `aaa authorization commands` list, because the pull does not say
    which line uses a named list: it is left, with its `no` line in the report
    to type when you know it is not in use. The order is the group entries,
    then the groups, then the servers, so an entry is gone before its group
    and a group before the server it names, and a RADIUS group's `server name
    X` names a RADIUS block.

48. **A plan keeps its back-out, and `--backout` prints it after the check
    pull.** The check the after-steps ask for is `device config pull <name>
    --diff`, and that pull is the new baseline: a back-out computed from it
    would be "nothing to back out". Every plan that has changes now saves its
    back-out beside the device's record (`/var/lib/tacctl/device-config/<name>.backout`,
    0600, stamped with the pull it was computed from, carried by `device config
    forget` and `device rename`): the text the plan printed, with a line that
    holds a secret's value turned into a note to type it with its own value.
    `plan <name> --backout` prints the kept one, with a first comment line
    that says which plan and pull it undoes (the latest plan with changes
    replaces it, item 51); with none kept it computes it from the pull, and
    with no plan to undo it says `nothing to back out: no plan was made from an
    earlier pull of <name>` (exit 0). `--backout --pull` is refused (exit 2): a
    pull replaces the picture a back-out is computed from.

49. **The files of a plan are named and checked more strictly.** The name of a
    device's cleanup file (`<name>.cleanup.set`) is reserved in a run, so the
    plain file of a device called `<name>.cleanup` is not the same file and
    `--force` cannot let one replace the other; `COVER.txt` is reserved only
    when a cover is written; `--plain --out` of a device that cannot be planned
    writes no file, as `--out-dir` already did, and says so on standard error;
    the `out=` of the audit line is quoted when a path holds a space. Writing
    as the user who ran sudo proves each change of the thread's file-system
    identity (a refused change is an error, never a write as root), and a
    directory that only a supplementary group of the user may write is
    refused. A plan reads the record, its sections and its plain view under
    the store's lock, so a pull running at the same time cannot mix two pulls.

50. **A server entry of another name at the standard's address is replaced,
    in an order that keeps the session.** IOS silently refuses a second
    server entry with the same address and key, so a device that already
    holds the standard's server under another form (a named `tacacs server
    <OTHER>` block, the shape every earlier walkthrough produced, or the
    legacy `tacacs-server host` line on a modern image) could not take
    `tacacs server TACACS` beside it: the plan as first built typed the
    standard block (refused), then `server name TACACS` into the group and
    removed the old entry, and the group named a block that did not exist
    (TACACS+ dead, local fallback only). Now the region (a) takes the
    command-authorization lists that name the group off first, typed while
    the server still answers (`no aaa authorization config-commands`, then
    each `no aaa authorization commands <level> ...`), (b) removes the
    group's `server name <OTHER>` or `server <address>` entry and then the
    old block or `no tacacs-server host`, (c) adds the standard block, the
    group's `server name TACACS` and the rest in the standard's order, and
    (d) types the lists again last. A group of another name that held the old
    entry is pointed at the standard block by its own name, so the method
    lists that name it keep resolving. The back-out is the inverse (the old
    block and entry back, the old key a note to type yourself, the lists
    last) and starts by taking command authorization off. The report says
    which entry is replaced and why. A `radius server <OTHER>` block at the
    standard's address and ports is replaced the same way (RADIUS has no
    command authorization). The refusal with the steps by hand
    (`this device runs the legacy server form with command authorization`)
    remains only for a device that authorizes commands and shows no server in
    use (no login or exec list names a group): nothing then proves that the
    pasting session is a TACACS+ user. On `ios12` the host line is the
    standard and nothing of this applies. The old entry is removed by the
    region only when the plan types the standard block's address or key; a
    block that has both leaves the old one an extra for `--converge`.

51. **The kept back-out is the device's and says what it covers.** It is
    stamped with the pull, the device's address and the sections it undoes.
    A narrower plan from the same pull (`plan <name>` of `aaa` and `snmp`,
    then `plan <name> --section snmp`) no longer replaces it: the narrower one
    would be labelled as undoing the plan of that pull. A later plan with
    changes replaces it and the report says so (`this plan replaces the kept
    back-out of the plan from the pull of <time> (UTC); print it first with
    'tacctl device config plan <name> --backout'`); a plan with changes and no
    line tacctl can type to undo them removes it (an earlier plan's back-out
    would be printed for it) and says so. `--backout` prints the kept one
    whenever one exists, whatever pull it was made from (it is what was
    pasted), with a first comment line that names the sections and the pull;
    it prints it even when the plan itself cannot be made (a stale record, a
    rendering that fails), with one line on standard error; and for a name
    whose address changed since the plan it says `nothing to back out: the
    kept back-out is for another device address` (exit 0). The after-steps
    say it is kept `until the next plan with changes`.

52. **A file of an earlier plan is not left beside a new one.** A plain plan
    after the verifying pull writes `<name>.set` and `<name>.cleanup.set`; when
    the device changed and `--force` wrote the new `<name>.set`, the old
    cleanup file stayed and could be loaded beside the new statements. A
    `--plain` run that writes a device's file now removes that device's cleanup
    file (`<out>.cleanup.set` for `--out`) when it does not write one itself,
    and a text `--out-dir` run removes `<name>.backout.txt` when the plan has
    no back-out to write; each says so on standard error (`Removed <path> (a
    file of an earlier plan that this plan does not make)`). `--plain --converge`
    says on standard error why a device has no cleanup file: the cleanup is
    deferred to after the first region, refused as a whole, or there is
    nothing to remove.

53. **The Junos cleanup follows the scope's protocol.** On a TACACS+ scope it
    removed `system radius-server <X>` too, which may serve accounting or
    another login method; on a RADIUS scope it removed `system tacplus-server`.
    It now removes only other servers of the scope's own protocol, as the IOS
    cleanup does, and keeps one that a statement staying on the device names
    (`system accounting destination <protocol> server <address>`). Items 39
    and 47 read that way, and the order of an IOS cleanup is the group
    entries first, then the groups, then the servers. The README and the
    manual page list `snmp-server community` and `snmp community` among what
    the cleanup removes.

54. **The report agrees with the region it prints, and the Junos cleanup
    asks for the pending commit.** A device with an empty first region, a
    refused section (a management ACL the `--from` address is not permitted
    by) and a cleanup said `CANNOT BE PLANNED ... Nothing is pasted for this
    device` and then printed the cleanup region; it now says the cleanup
    region is the only paste and names the refused section as left alone. The
    check pull of a Junos plan is taken before its `commit`, so a plan made
    from it reads as applied while the `commit confirmed` may still be
    pending: the report of a Junos cleanup and its follow-up now say to check
    that `show system commit` shows no pending `commit confirmed` (type the
    plan's `commit` first).

55. **Smaller corrections of the plan.** A kept back-out turns a line that
    holds a value into a note whether or not its elided form is known. A group
    entry `server 192.0.2.5` names the `radius-server host 192.0.2.5 auth-port
    ... acct-port ...` the device stores, so the cleanup that removes the host
    removes the entry with it and a host a staying entry names stays.
56. **An operator can no longer interrupt service, even intermittently.**
    The rule the shipped `operator` rules and privileges are now written to:
    nothing an operator (or the `readonly` viewer) may run can drop or reset a
    connection, a session or an adjacency, change forwarding, or load a device
    enough to degrade forwarding or management, with any arguments the server
    permits. The engineer is the escalation. Out of the operator's command
    rules (`commands.operator`) and out of `privileges.operator`: `monitor
    capture ...` (the control plane takes the matched packets and `export`
    writes or sends them off the box), and the `clear` forms `counters` (it
    erases the evidence of an escalation; no service impact, but the operator
    reads counters, the engineer resets them), `line <n>` (ends another
    session at once), `ip arp <address>` and `arp-cache <name>` (a
    re-resolution, a brief interruption for the host, a whole interface or
    table with the arguments the device accepts) and `mac address-table
    dynamic ...` (every frame to an unlearned address floods, a port or a
    VLAN with it). The operator has no `clear` or `monitor` rule at all
    afterwards (the catch-all denies them). `ping` and `traceroute` stay, as
    the one-line extended forms with every number inside a bound the rule
    checks (one rule per command, in front of it a deny of the interactive
    forms): `ping [vrf <name>] [ip|ipv6] <host>` and, in any order, `source
    <addr|if>`, `size 1-9999`, `df-bit`, `repeat 1-1000`, `timeout 1-10`,
    `data <hex>`, `validate`; `traceroute [vrf <name>] [ip|ipv6] <host>` and,
    in any order, `source <addr|if>`, `numeric`, `probe 1-10`, `ttl 1-255
    [1-255]`, `timeout 1-10`; `mpls ipv4|pseudowire <target> [<vc-id>]` for
    both. A value past a bound (`repeat 1001`, `repeat 2147483647`, `timeout
    0`, `size 10000`, `probe 11`, `ttl 256`), `sweep` (its one-line syntax is
    not verified here: a lab item; MTU testing is `size` with `df-bit`),
    another keyword and anything after the options are denied. The
    interactive dialog is denied: a bare `ping` or `traceroute`, or a
    protocol keyword with no host (`ping ip`, `ping ipv6`, `ping vrf MGMT
    ip`, `ping mpls`, `ping clns`, `traceroute ip`, ...), makes IOS ask its
    questions (repeat count, timeout, sweep range) at the device, where the
    server neither authorizes nor accounts what is typed, while the one-line
    forms carry the same choices as arguments the rule checks and the
    accounting records. A broadcast or multicast address as the host is a
    residual risk no regex can close; the engineer runs every form,
    unbounded. `privileges.operator` is `undebug all` alone: `exec all:
    ping`, `exec all: traceroute` and `exec all: monitor capture` are gone,
    so on a device the level-1 `ping` and `traceroute` are what a user below
    level 15 runs, and with the server unreachable (the `local` fallback) or
    over RADIUS, which carries no command rules, an operator has IOS's own
    basic `ping` and `traceroute` and nothing beyond them: lowering them would
    hand every form to every user whenever the server does not answer, which
    the user ruled out (the strict side of the trade-off, decided). The `vrf`
    and `mpls` forms, which `exec all:` lowered, are expected to be level 15
    again, the engineer's, however the server rule reads (a lab item);
    whether an image accepts `repeat` or `timeout` at level 1 is not
    something tacctl can change, and the README says so. `undebug all` (it
    only stops a debug, which relieves load) and `terminal` (a session's own
    settings) stay. The invariant is stricter and has no exception left:
    every shipped privilege entry is permitted by the group's rules bare and
    with any arguments its own keywords leave to it (a keyword child with a
    level of its own, `show running-config view full`, keeps it;
    `TestPrivilegesArePermitted`, whose `localFallbackExceptions` is gone).
    The role preset's operator and viewer rules follow the shipped ones, and
    its operator `show` deny gains `tech-support` (the level already stopped
    it). `config cisco` and `device config show` render `privilege exec
    level 1 show running-config` and `privilege exec level 7 undebug all` and
    nothing else; the engineer permits every removed command (rules and level
    15), which `tests/tools/permcheck-baseline.txt` proves live. An operator
    on a WTI unit keeps the `User` level: it can end a console session on a
    port the Default User Access list grants (`/D`), which is the point of
    it, and the README says so. `rollback 0.2.3` leaves the rendered files as
    they are, and the shipped rules of 0.2.3 permit the commands again, so an
    installation on the shipped rules is told by `config validate` of 0.2.3
    that its rendered configuration is out of date until `tacctl config
    render` there brings the permits back.

57. **A Junos operator has no `clear` bit, and the preset's deny sets are
    narrower for it.** `OP-CLASS` is `network trace view view-configuration`
    (no `clear`): the bit reached every `clear` family that needs only it
    (`clear bgp|ospf|isis|... neighbor`, `clear security flow session`,
    `clear arp`, `clear ethernet-switching table`, the counter resets), which
    the preset's deny set could not list within 241 bytes, so this holds with
    no preset, over RADIUS and whatever the server sends. The `config
    juniper` summary says `local: network/trace/view + view-configuration`
    for the operator and `operator bits + clear, reset, ...` for the engineer
    (whose `EN-CLASS` bits are unchanged, `clear` among them; `engineer` may
    run every removed command). The role preset's `deny-commands` follow: the
    operator denies `clear` whole in place of the family list and `monitor
    traffic` whole in place of `monitor traffic ... write-file` (a capture on
    the routing engine, unbounded without a `count`; `monitor start|stop|list`
    and `monitor interface` stay), and the viewer's and the operator's both
    deny `ping ... rapid` and `ping ... interval` (they send at the reply
    rate or at a chosen one; `count`, `size` and the default pace stay).
    The sets are 136, 133 and 219 of 241 bytes (viewer, operator, engineer).
    A device configured from an earlier Step 1 keeps `clear` in `OP-CLASS`
    until Step 1 is pasted again: `device config plan` for a pulled device
    prints `delete system login class OP-CLASS permissions clear`. Stored
    deny sets of the 0.2.3 preset keep working as before until `tacctl group
    reset operator --preset` and `tacctl group reset readonly --preset` bring
    the new ones (item 58 names them). A shipped Junos deny set that applies
    to every install, without the preset, is a mechanism of its own and is
    not part of this change: without the preset (or sets of your own, or
    the RADIUS `Juniper-Deny-Commands` attribute) nothing denies `ping
    ... rapid`, `ping ... interval` or an unbounded `monitor traffic`; the
    bit removal is the protection every install has, and those three are
    denied only where the deny sets are sent. Which bit `test interface
    restart-auto-negotiation` needs is an open lab item.

58. **Moving from 0.2.3's operator rules to this release.** A stored value
    is a choice, so `tacctl upgrade` drops only the one that is not: a
    `privileges.operator`, `commands.operator` or `commands.readonly` in
    `tacctl.yaml` that is exactly what 0.2.3 shipped (`group privilege add`
    seeds the shipped list into the override first, so an installation that
    ever added an entry holds the nine lines) is removed, with an info line
    each, and the shipped values of this release apply, on every install
    whichever backend is enabled (a RADIUS-only one included); the same exact
    match is dropped when `tacquito.yaml` of an installation without a store
    is migrated. Any other stored value is kept, and the upgrade ends with a
    red notice that names each setting with the removed entries
    (`privileges.operator (exec all: ping, clear line)`, `commands.operator
    (clear, monitor, ping, traceroute)`, `commands.readonly (ping,
    traceroute)`, `junos operator deny-commands` for the 0.2.3 preset's
    value) and the command that replaces each: `tacctl group privilege reset
    operator` and `tacctl group commands reset <group>` for a list somebody
    stored (the shipped value), and, for what 0.2.3's `group preset roles`
    stored (its `show` deny and the Junos deny sets, which the shipped
    rules do not carry), `tacctl group reset <group> --preset --only
    commands,junos` (`--only junos` for the Junos set alone), which puts the
    preset's current value back and loses no deny (each takes `--dry-run`).
    `tacctl config validate` prints the same as a warning, `Operator
    policy:`, which does not fail the validation. Devices pasted earlier
    keep their `privilege exec level 7 ...` lines (and, on Junos, `clear`
    in `OP-CLASS`) whatever `tacctl.yaml` holds, so until a device is
    re-pasted its operators keep the old reach when the server does not
    answer, and always over RADIUS. The first upgrade onto this release says
    so, on every install, with the lines to remove (on Cisco `no privilege
    exec all level 7 ping`, `no privilege exec all level 7 traceroute`, `no
    privilege exec all level 7 monitor capture`, `no privilege exec level 7
    clear counters`, `clear line`, `clear ip arp`, `clear arp-cache`, `clear
    mac address-table dynamic`; on Junos `delete system login class
    OP-CLASS permissions clear`) and the way to get exactly the lines a
    device needs: `tacctl device config pull <device>` and `tacctl device
    config plan <device>`, which prints them, parents included, in its
    paste region. It says so once (the marker `operator-policy-noted` in
    `/var/lib/tacctl`, which a fresh install writes at once and `tacctl
    uninstall` removes) and again at each upgrade while a stored setting
    still carries a removed entry. `tacctl group privilege reset operator`
    prints the removal lines only for entries a stored list holds that the
    shipped one does not; for an install on the shipped list it says the
    group is already canonical and prints none.

59. **`group commands seed` writes the shipped rules.** The recovery verb
    wrote a broader legacy set that gave the operator `clear`, `test`,
    `monitor` and `enable`, and `ping` and `traceroute` with any arguments;
    it now writes the shipped rules of the built-in groups (what `group
    commands reset` writes), so it cannot hand an operator what item 56
    removed. Its verb description says so.

60. **A privilege line IOS added for a command that is gone is extra too.**
    `device config pull` and `device config plan` took the `privilege exec
    level N <words>` lines IOS adds for the words leading to a command
    ('privilege exec level 7 clear' for 'privilege exec level 7 clear
    counters') as part of that command even when nothing rendered was left
    beneath them, so a device pasted with a removed command kept the parents
    after the plan's `no` lines and a second plan was needed. A parent is the
    image's own line only while a rendered command is beneath it; otherwise
    it is extra and the plan removes it with the command (whenever a
    rendering is given, a rendered `privilege` line or none).

61. **The privilege lines IOS 15.x leaves behind are the image's own and are
    not reported.** On IOS 15.x and IOS-XE, `no privilege exec level N
    <command>` does not remove the line: the image keeps `privilege exec
    level <the command's own level> <command>` (`level 15 clear counters`,
    `level 15 monitor capture`, `level 1 ping`, and the words leading to
    them: `level 15 clear ip`, `level 15 monitor`, `level 1 clear`, `level 1
    show`). Nobody can remove such a line, so a device that ever had one
    removed read `roles differs` forever, `device config pull --diff` showed
    the lines as `+`, and `device config plan` listed them as irregularities
    it could not fix. A line `privilege exec level L <words>` is now the
    image's own, and neither compared nor reported, when `<words>` is one of
    the commands tacctl lowers or has lowered (`ping`, `traceroute`, `monitor
    capture`, `clear counters`, `clear line`, `clear ip arp`, `clear
    arp-cache`, `clear mac address-table dynamic`, `undebug all`, `show
    running-config`, and the words leading to them), `L` is that command's
    own level, it has no `all`, and the rendering has no line for that
    command. A line at any other level is still an extra, a rendered line the
    device lacks is still missing, and the back-out's comment about the
    lines is unchanged.

70. **`tacctl breakglass hold <device> --reason "<text>"` makes the server
    stop answering one device, so its local accounts can be used while the
    server is up; `release <device>` answers it again.** The standard Cisco
    block (items 30 and 31) and the Junos `authentication-order` use a
    device's local accounts only while no server answers it, so the way in
    for a locked-out technician was a cable or a hand-edited firewall on the
    server. A hold is the superuser's, for one registered device, for an
    exceptional case, and is shown until it is released: there is no timer and
    no automatic release, and no whole-scope form. It asks for the device's
    name typed back at a terminal (no `--yes`), says in a paragraph that the
    act is for one device in exceptional circumstances and which local
    accounts (`scope breakglass <scope> list`) are the only way in, and
    prints one report: the record, what was rendered (`192.0.2.0/24 of scope
    'lab' answers as 8 prefixes without 192.0.2.21`), the backends that
    restarted, the way in for the device's vendor (Cisco: ssh as a local
    account, the console's local `CONSOLE` login and `enable` with the local
    secret; Junos: a local `system login user`; WTI: Fallback Local), that its
    accounting goes to a server that does not answer it, `Held now:` with every
    hold that stands and `When done: tacctl breakglass release <device>`. It
    is refused, with nothing changed, for a device that is not registered (an
    enrolled Linux host is not one), has no address, is held already, is at a
    loopback address, an address a listener of either backend binds or the
    recorded address of an enrolled host (the server's own logins come from
    `127.0.0.1`), or that no scope covers (`already unanswered`). `--reason`
    is required, 1 to 256 characters. The record is
    `breakglass_hold.<device>.address|since|by|reason` in `tacctl.yaml` (a
    device name's dots are written `~` in the key), so every snapshot holds
    it and `backup diff` shows it; `release` removes it from the record alone,
    so a device removed from `devices.yaml` by hand is still released.

71. **A hold is carved out at render time; the store is never changed.** Both
    renderers replace every prefix of every scope, and every tagged address of
    `scope devices` for RADIUS, by itself minus the held addresses: a `/24`
    that holds the address becomes the eight prefixes `/25` to `/32` that do
    not, a prefix equal to the address is gone, an IPv6 `/64` is sixty-four
    prefixes, several holes in one prefix are taken out in turn, and a prefix
    that holds none is written as it was. A piece sorts where the prefix it
    came from did (and, in `clients.conf`, falls on the longest stored
    prefix's client), so every address that is not held is answered by the scope
    that answered it before. The read-back of the rendered `tacquito.yaml`
    compares the file with the same carved model, so it keeps passing while a
    hold stands. `tacquito.yaml` and `clients.conf` get a comment block that
    names each held address, its device and the prefixes it was carved from
    (only where something was carved), never the reason. `hold` then `release`
    renders the original bytes, byte for byte; each is one restart of each
    backend whose file changed, and a release that changes nothing (the device
    was uncovered meanwhile: `breakglass list` says `no scope covers it now`)
    restarts nothing. `scope rename`, `scope prefixes` and `scope remove` are
    neither refused nor changed: the record names no scope, the carve-out
    applies to every scope that covers the address.

72. **A held device is shown as held wherever it is shown.** `breakglass list
    [--json]` (device, address, scope, since, how long, by whom, why);
    `status` (`Break-glass:        none held`, or one red line per hold);
    `device show` (a `Break-glass` row: `HELD since 2026-10-10 14:02 (2 h 14
    min) by alice: <reason>; the server does not answer 192.0.2.21`) and `device
    list` (`BREAK-GLASS` in the STATE column and a footer) and `device show
    --json`, `device list --json` and `device check --json` (a `breakglass`
    object with `held`, `address`, `since`, `by` and `reason`); `device check`
    (a note on the Scope row); `device scan` (a refusal of the address reads
    `(break-glass held)` in place of `(no scope)`); `scope routing` (one line
    per hold under the stored rows), `scope show` (`Break-glass held:` under
    the prefixes), `scope list` (`(1 break-glass hold)`) and `scope lookup`
    (`NOT ANSWERED: break-glass held on <device> since ...`, and a note for a
    range that holds a held address); `config validate` (a warning per hold,
    red when the device is not registered). `device list --unconfigured` does
    not list a held device. An engineer sees the holds of the devices of their
    own scopes only.

73. **What a hold changes for other verbs.** `device address` and `device
    remove` (and `device import` that would move or remove it) of a held device
    are refused (`break-glass is held on <name>: release it first`), because
    the hold is on the address the server sees; `device rename` moves the
    record with the device and renders the comment again, restarting nothing.
    `device config pull`, `diff --pull` and `plan --pull` of a held device are
    refused up front, and a batch (`--all`, `--scope`, `--vendor`, `--stale`)
    skips it with that line instead of failing on it, because the device does
    not authenticate your login; `device config plan` of the last pull works,
    puts `BREAK-GLASS HELD on this device since ... by ...: the server does not
    answer it, so the check below ("a NEW ssh session as yourself") cannot pass
    until it is released` before its items and marks the device on the cover
    page (`[break-glass held]`; `breakglass_held` in `--json`). `tacctl ssh` of
    a held device warns and connects. The three after-steps comment lines of a
    plan (`Locked out ... A superuser runs: tacctl breakglass hold <name>
    --reason "..."`, the local login, `... tacctl breakglass release <name>`)
    end every Cisco and Junos region's after-steps, the cleanup's and the
    back-out's, whether or not the device is held, and Step 0 of the Cisco
    walkthrough has one commented line after the accounts: `To use these
    accounts while the server is up: tacctl breakglass hold <device> --reason
    "..." (a superuser); release when done`. `tacctl backup restore` is a
    render like any other: a hold comes back with a snapshot of a
    `tacctl.yaml` that has it and goes with one that lacks it, and the
    restore says which devices are held now and which will be held after
    (before the question, and again at the end) whenever that set changes.

74. **Tiers and the log.** `hold` and `release` are the superuser's (the tier
    table has no row for them, as for every change of what the scopes
    answer); `list` is an engineer row with its sudoers line (`breakglass
    list`, read-only, the devices of the engineer's own scopes). Both verbs
    log `auth.info breakglass hold device=<name> addr=<ip> reason="<text>"
    by=<user>` and `breakglass release device=<name> addr=<ip> held=<duration>
    by=<user>` (the reason is logged: it is where the why outlives the
    release) and take the snapshot every change takes first. `tacctl.yaml`
    carries no credential and the reason never reaches a backend file.

75. **`tacctl rollback` is refused while a hold stands.** In the dry run and
    with `--apply` alike: the older release has no such record, so the device
    would stay unanswered until the older release's first render and then be
    answered without anyone releasing the hold. The refusal names each held
    device with its address, who held it and since when, and
    `tacctl breakglass release <device>`; nothing is changed.
    `breakglass_hold.*` is in the keys a rollback strips when none stands.

76. **The break-glass texts say how to use the local console while the server
    is up.** The README and the manual page already said the console's local
    login and `enable` work only while no server answers; they now add that
    `tacctl breakglass hold <device>` is how to make that happen on purpose for
    one device (a "Holding break-glass" subsection with the procedure per
    vendor, the `enable` design paragraph's last sentence, and the
    `scope breakglass` verb's description: the accounts a hold makes usable).

77. **The hold report says plainly what is carved, and warns when the server
    has not seen that address.** A hold takes out the one address the device
    is registered at (its management address). A device that sends its AAA
    from another address (a Cisco `ip tacacs source-interface`, which
    `cisco.source_interface.<scope>` sets, a NAT, an IPv6 address) is still
    answered, and the report said HELD all the same. It now has a `Carved:`
    line after `Rendered:` that says so (`only 192.0.2.21, the address
    registered for sw-lab-1. A device that sends its AAA from another address
    (a source interface, a NAT) is still answered.`), and, when the seen data
    (`device scan`) hold no request from the registered address, a
    `Warning:` line: either that the server has seen the device from no
    address at all (no request from it, none that identifies as its name), or
    that another address identifies as the device's name and is most likely
    where it sends from, and in both that it is still answered, with where to
    learn the address: `tacctl device config pull <device>` (its source
    interface) or `show tacacs` and the device's own log. With no seen data
    nothing is added. The hold itself does not change: it still carves the
    registered address only.

78. **A hand-written key with a dot in it is released from where it is
    stored, and `config validate` names every entry that is not a usable
    hold.** `breakglass_hold: {sw.lab: {address: ...}}` is read, listed and
    carved (the schema's own check of the leaf path does not accept a name
    with a dot, which `config validate` already reported), but `release` and
    the rename carry removed the key tacctl would have written (`sw~lab`), so
    the report said RELEASED while the record stayed and the device stayed
    unanswered. A release now removes every entry of the device under the key
    it is stored under, whichever spelling, and renders again. `config
    validate` names, in red, `breakglass_hold.<key>` for a key with a dot in
    it (still carved: `release` removes it), an entry with no address, an
    address that is not one IPv4 or IPv6 address (a prefix included: it is
    not carved, so a hand-written `10.0.0.0/8` silences nothing) and an entry
    that is not a record; the last three carve nothing and are not listed by
    `breakglass list`, `tacctl breakglass release <name>` removes them (`Break-glass
    record REMOVED for <name>: the entry ...`, nothing restarts), and an entry
    with no address makes `config validate` exit 1.

79. **A restart that failed is reported as not restarted, and the hold or
    release exits 1.** A service restart that failed printed its warning and
    the report said `tacacs restarted`, so a hold that was not in force looked
    as if it was. The report now says `tacacs NOT restarted: the running server
    still answers 192.0.2.21 until it is restarted (run: sudo systemctl restart
    tacquito)` for a hold, and `still does not answer` for a release, naming
    the command the warning names, and exits 1 after the whole report with
    the line `The hold is recorded and the rendered files are kept, but it is
    not in force until the backend named under Rendered is restarted` (a
    release: `The record is removed and the rendered files are kept, ...`).
    Nothing is undone: the record and the files are what the next restart
    serves, and `release` takes the hold back. The backends' restart now
    returns that failure to its caller, which `StoreApply` carries in its
    result; every other caller still goes on as it did, except `backend
    enable`, which now takes a restart that failed as the backend not having
    come up (it undoes the change, as for a service that is not active).

80. **Two superusers cannot both hold one device.** The check for a hold that
    was made while the name was typed ran before `tacctl.yaml` was locked, so
    two holds could both pass it and the second overwrote the first one's
    `since`, `by` and `reason`. The check is now made under the file's lock,
    on the file as it is, in the same step as the write; the second hold is
    refused as `already held` (`Break-glass is already held on '<device>'
    (<address>) since ... by ...: another hold was made while the name was
    typed. Nothing was changed.`) and the first record is as it was.

81. **A hold applies to a device only while the device is registered at the
    record's address; any other record is an orphan.** Holds were matched to
    devices by name, so a device removed from `devices.yaml` by hand and
    another registered under the same name took over the old record: it
    showed as held, `device address` was refused and the pulls skipped it,
    while the address that was carved was the old one. A record now holds the
    device of its name only while that device's registered address is the
    record's. Any other record (no device of that name is registered, or the
    one that is stands at another address) is an orphan: `breakglass list`
    shows `<device> (orphan)` with its address, since, by and reason and says
    why, `--json` has `orphan: true`, `status` says `ORPHAN record <device>
    ...`, and `config validate` says `<device> is an orphan record: ...; it
    still silences <address>` (red, as it was for a device that is not
    registered). The address stays carved until `tacctl breakglass release
    <device>` removes it. The device itself is not shown as held, is not
    refused `device address`, `device remove` or `device import`, is pulled,
    and `device rename` leaves the record under the old name; `breakglass hold
    <device>` of such a device is refused (`A break-glass record named
    '<device>' stands at <address>, not at the address the device is
    registered at ...`) until the record is released, rather than written
    over. An engineer sees only the records that hold a device of their own
    scopes. A rename of a device that is held still carries the record.


## 0.2.3 (2026-10-09)

### What changed

1. **A fourth tacctl tier, `engineer`, between operator and superuser.** A
   group's tier is the one set on it in `tacctl.yaml` (`tier.<group>`), else
   its priv-lvl band as before (below 7 readonly, 7-14 operator, 15
   superuser), so a group at priv-lvl 15 on the devices can be engineers in
   tacctl. An engineer may do what an operator may, and for the
   devices of their own scopes also: `device add`, `remove`, `rename`,
   `address`, `hostname`, `vendor`, `port`, `description`, `legacy-ssh`,
   `hostkey` and `import`, `scope devices`, `config cisco|juniper|wti`
   (with `--staging`, never at an address another scope answers). Another
   scope's device is not found; a change that would touch one, or a device
   at an address no scope of theirs answers, is refused (`Scope '<name>' is
   not one of yours`, exit 1), and `device remove --all` removes their own
   devices only. Beyond those an engineer reads the secret of a scope of
   their own (`scope secret <scope> show`; `scope show <scope>` shows the
   scope and the secret's length only) and
   lists and shows the hosts and the staging addresses of their scopes
   (`host list`, `host show`, `scope staging list`; item 20) and the SNMP
   settings of those scopes (item 21); the rules that keep the tier away
   from root and from the global settings are items 3 to 19. Linux
   host deployment (`host enroll`, `sync`, `move`, `target`, `provisioner`,
   `unenroll`, `default-method`) is the superuser's (item 26). Users,
   groups, scopes and the change of any secret, backends, backups,
   upgrades and every global setting (the default host method, the
   console's settings, `tacctl.yaml` in general) stay the superuser's.
   The tiers sudoers drop-in gains the
   engineer rows (`TACCTL_EN`) and `%tac-engineer ALL=(root) NOPASSWD:
   TACCTL_RO, TACCTL_OP, TACCTL_EN` (superusers get `TACCTL_EN` without a
   password too); engineers never get more than tacctl through sudo on the
   tacctl server. `console tiers` and `console show` list the `engineer`
   tier (always on, item 5), and `console system-shell tiers` and `console
   forwarding tiers` refuse `engineer`. `console check` asks sudo (`sudo -l -U`) what each member of
   `tac-engineer` may run and warns in red, exit 1, when it is anything but
   tacctl. On Linux hosts engineers are in a new group `tac-engineer` (GID
   80005, the range's first number + 5, on every host) instead of
   `tac-superuser`; a host's first sync after the group's tier is set to
   `engineer` moves them (`'<user>': moved from tac-superuser to tac-engineer`). On a host other
   than the tacctl server, its sudoers drop-in gives `tac-engineer` every
   command with their own password (`%tac-engineer ALL=(ALL:ALL) ALL`), or
   the commands `tacctl config linux engineer-sudo
   all|<command>[,<command>...]` names (absolute paths, checked with
   `visudo`, kept as `linux.engineer_sudo`); a sync now rewrites an
   installed drop-in when it differs, so the setting reaches each host at
   its next sync. The client script speaks protocol 6 (`TAC_ENGINEER_SUDO`
   in its header); a script of protocol 5 and this body refuse each other
   before changing anything.

2. **`group show` prints the Junos patterns to every tier.** Under its
   `Junos rules` row it lists the `deny-commands` and `deny-configuration`
   patterns themselves, one per line, beside the byte counts it printed
   before, so the read-only tier can see them. `group junos` stays the
   superuser's, and the `tacctl group junos <group> list` hint is printed
   only to a tier that may run it.

3. **A `tacctl.yaml` that cannot be read no longer makes an engineer a
   superuser.** The tier of a group comes from `tier.<group>` in
   `tacctl.yaml`; when the file could not be read the setting was lost and a
   group at priv-lvl 15 was a superuser, who could then sync this server
   and join `tac-superuser`. Now, while the file cannot be read, no tacctl
   user is trusted above the operator tier (a priv-lvl 15 user becomes an
   operator for the time; `config validate` and `console check` stay open
   to diagnose it), and the denial says why: `'tacctl host sync' is not
   permitted: /etc/tacctl/tacctl.yaml cannot be read (<problem>), so no
   tacctl user is trusted above the operator tier until it is fixed
   (tacctl config validate).` (logged `reason=conf-problem`; root and
   callers outside `tac-users` are not affected). `host enroll` and `host
   sync` refuse for everyone, and `group edit <group> tier` when the file
   cannot be read (it could not write it), with
   `/etc/tacctl/tacctl.yaml cannot be read (<problem>); accounts and tiers
   are not synced until it is fixed.` The same holds, with the same
   messages, when the file reads but a tier setting is not a tier: a
   `tier.<group>` that is a mapping, a list, null, empty or a number, or a
   `tier` that is not a mapping at all (`'tier.<group>' must be one of
   readonly, operator, engineer, superuser`). Such a group counts as
   readonly, never as its priv-lvl band (a name that is a string but not a
   tier, such as `Engineer`, also counts as readonly). A missing or empty
   file, or one that lost its `tier` section, is not a problem of the file
   but of the groups it should describe: item 7. For a file that reads
   but holds a setting that is not a tier, `group edit <group> tier <tier>`
   run by root writes the setting that repairs it (a managed superuser is
   held at the operator tier meanwhile, so it is root's verb then), and
   `group show` says when a group's setting is not a tier (`invalid setting
   '<x>'; treated as readonly`). The warning that
   tells root the file could not be parsed no longer suggests removing it
   (`fix the file; 'tacctl config validate' checks it`).

4. **An engineer keeps the console's lockdown even when `tacctl.yaml` cannot be
   read.** The console asks the server for its policy with the hidden
   `_console-policy`. With the file unreadable (item 3) the gate's cap makes
   an engineer an operator, and `console system-shell tiers operator` or
   `console forwarding tiers operator` would then have given that engineer a
   system shell (a bash on the server) and forwarding. The policy line now
   treats a caller as the engineer tier whenever its tier without the cap is
   engineer or the account is in `tac-engineer`: `tier=engineer
   system_shell=no forward=no`, and the console login, whatever the settings
   and the cap. The gate itself still permits what the capped tier permits.

5. **An engineer has the console or no login on the tacctl server.** The
   engineer tier's console switch is always on: `console tiers engineer
   disable` and `console user <engineer> disable` are refused (`The
   engineer tier has the console or no login on this server; it cannot be
   disabled. To keep a user off this server, remove its scope from the
   user.`), a stored `disable` for the tier or for a user is ignored and
   `console tiers` and `console show` say so, and an engineer whose
   console cannot be provisioned (the `tacctl-console` link is missing)
   gets `/usr/sbin/nologin`, with a warning, instead of `/bin/bash`. An
   account whose tier is none gets `/usr/sbin/nologin` too, no longer a
   real shell. sshd gets a drop-in of its own for the engineers,
   `/etc/ssh/sshd_config.d/00-tacctl-engineer.conf`, with a `Match Group
   tac-engineer` block that closes forwarding and tunnels for engineers
   whatever shell they have (agent forwarding follows `console
   agent-forwarding`). The name sorts before `tacctl-console.conf`: sshd
   reads the drop-ins in name order and takes the first value of a keyword
   across all `Match` blocks, so an engineer who is also in a group that
   `console forwarding tiers` lets forward (a stale `tac-superuser`) keeps
   forwarding closed (item 6). It is written at every `host sync` and `host
   enroll --local` of this server and by `console install`, with or
   without the console installed (so `ssh -N -D` fails for an engineer
   even when the `tacctl-console` link is missing), refreshed or created by
   `tacctl upgrade` for an install that has the console's drop-in, left in
   place by `console remove` and removed by `tacctl uninstall`; the
   console's own drop-in `tacctl-console.conf` no longer holds an engineer
   block, so there is one source. `console check` checks the file on its
   own (`sshd drop-in <path>: missing | present, differs from this release's
   | present, current`, red and exit 1 unless current). The file has no
   `ForceCommand`: the console's drop-in sets one for the members of
   `tac-console`, which engineers with the console are, and an engineer
   without it has `/usr/sbin/nologin`; authentication is left alone. `console
   check` also checks the engineers: each member of `tac-engineer` has the
   console or a nologin shell (red, exit 1, otherwise), and sshd closes
   forwarding for the first of them.

6. **The engineer's sshd drop-in sorts before the console's.** The file was
   `tacctl-engineer.conf`, which sshd reads after `tacctl-console.conf`; the
   first value of a keyword wins across `Match` blocks, so with `console
   forwarding tiers superuser` an engineer who was also in `tac-console`
   and, through a failed `gpasswd -d` or an NSS group, still in
   `tac-superuser`, got `DisableForwarding no` and `AllowTcpForwarding yes`
   from the console's tier block. It is `00-tacctl-engineer.conf` now.
   `console install`, `host sync` of the server and `console remove` write
   the new file and then remove the old one; `tacctl upgrade` renames an
   installed one (`Removed: sshd drop-in <old> (renamed to ...)`, checked
   with `sshd -t`); `uninstall` removes both; `console check` flags the old
   file and a name that sorts after the console's. A test builds both
   drop-ins and checks the order, and runs `sshd -T` on them where sshd is
   installed.

7. **A custom group at priv-lvl 15 always has an explicit tier, and one
   that lost it holds back only its own members.** The band cannot say
   whether a group at priv-lvl 15 other than the built-in `superuser` is a
   superuser group or an engineer group whose `tier.<group>` was lost (an emptied or
   restored `tacctl.yaml`; item 3 had made a missing file cap every managed
   caller, which locked a superuser out of `group edit <g> tier` and every
   other verb until root acted, and missed an empty file or one without a
   `tier` section). Now: `group add <name> 15 <class>` without `--tier`
   writes `tier.<name>: superuser` (and says so), `group edit <name>
   priv-lvl <n>` does the same when it raises a group into the band, removes
   a `superuser` setting that only recorded the band when it lowers the
   group out of it (an `engineer` setting stays), and `group edit <name>
   tier auto` at priv-lvl 15 records `superuser`; the first `tacctl
   upgrade` to 0.2.3 writes `tier.<group>: superuser` for every such group
   that has no setting, which is what 0.2.2 treated them as, one line each
   (`Group '<g>' (priv-lvl 15): tier recorded as superuser in <file> (what
   0.2.2 treated it as; change it with: tacctl group edit <g> tier
   <tier>)`), after a snapshot, and then never again (item 13); `store
   import` (and a `backup restore --legacy`) do the same for the groups the
   import brought, not for the ones the store already had. A group at
   priv-lvl 15 that has no setting anyway is ambiguous: its members are held
   at the operator tier (`'tacctl <cmd> <sub>' is not permitted: your group
   '<g>' is at priv-lvl 15 or more and has no tier setting in <file> (it was
   lost) ...`, logged `reason=group-ambiguous`), a `host enroll` or `host
   sync` gives them the operator tier on the hosts and prints one red line
   per such group naming `tacctl group edit <g> tier <tier>` (item 9), and
   `group show` says `NOT SET`. The members of the built-in `superuser`
   group and everyone else are not affected, so a managed superuser who is
   not a member repairs it. The special case of a missing file is gone.

8. **A built-in `readonly` or `operator` group at priv-lvl 15 is ambiguous
   too.** Item 7 exempted every built-in group from the rule that a group
   at priv-lvl 15 has an explicit tier, so `group edit operator tier
   engineer` and `group edit operator priv-lvl 15` followed by a lost
   `tacctl.yaml` made the members of `operator` superusers again. Only the
   built-in `superuser` group is exempt now: `group edit operator priv-lvl
   15` records `tier.operator: superuser` when the group has no setting and
   lowering it takes that record away again, a lost setting holds the
   members at the operator tier (item 9), and the upgrade records
   `readonly` or `operator` at 15 as `superuser`, what 0.2.2 treated them as.

9. **A sync is not refused because a group lost its tier.** While a group at
   priv-lvl 15 had no setting every `host sync` and `host enroll` was
   refused, including the sync that `user remove`, `user move` and `group
   edit ... priv-lvl` run to take rights away, so a removed user kept
   `tac-superuser`. They run now: the members of an ambiguous group get the
   operator tier on the hosts (the cap the gate applies to the same users;
   no `tac-superuser`, no `tac-engineer`), and one red line per group says
   `Group '<g>' (priv-lvl 15) has no tier setting in <file>, so its members
   are synced as operators (no tac-superuser, no tac-engineer) until:
   tacctl group edit <g> tier <tier>`. A `tacctl.yaml` that cannot be read
   still stops them (item 3). `host show` and `console show` list such a
   member as an operator.

10. **A legacy install has no ambiguous groups.** An install without a store
    keeps no tier settings, so none can have been lost, and `group edit ...
    tier` needs a store: its groups at priv-lvl 15 are superusers as in 0.2.2
    (the gate no longer holds their members at the operator tier) until
    `tacctl store import`.

11. **Lowering a group's priv-lvl below 15 removes its `superuser` setting.**
    The setting written for a group at 15 (item 7) is the same word as one
    chosen with `--tier superuser`, and lowering the group out of the band
    removes either, so the lower band decides again (`engineer`, `operator`
    and `readonly` settings stay). The usage of `group edit` and the README
    say so; set the tier again after lowering when a superuser group below 15
    is wanted.

12. **`group show` words a tier that is not one.** A `tier.<group>` that is a
    string but not a tier (`Engineer`, say) was shown as `Engineer (set;
    auto would be ...)` although the group counts as readonly. It is
    `readonly (invalid setting 'Engineer'; treated as readonly; fix: tacctl
    group edit <g> tier <tier>)`.

13. **The tier migration of the upgrade runs once.** `tacctl upgrade` used to
    write `tier.<group>: superuser` for every group at priv-lvl 15 without a
    setting on every run, so an `engineer` group whose setting was lost
    later (an old `tacctl.yaml` copied back, a hand edit) became a superuser
    group at the next routine upgrade. The migration now runs at the first
    upgrade only and leaves the marker `/var/lib/tacctl/tier-pinned` (outside
    `tacctl.yaml`, which is what gets lost); a fresh install writes it at
    once, and `tacctl uninstall` removes it. When `tacctl.yaml` cannot be
    read or written, or the snapshot fails, nothing is written and no marker
    is left, so the next upgrade tries again. `store import` and `backup
    restore --legacy` pin only the groups that were not in the store before
    the import.

14. **Lowering a tier syncs this server's accounts at once.** `group edit
    <group> tier <tier>|auto`, `group edit <group> priv-lvl <n>`, `user move
    <user> <group>`, `user rename <old> <new>` (the old account goes), `user
    disable`, `user remove`, `user scope <user>
    remove|replace|remove --all` (a user who is no longer in the server's
    scope is none), `group remove` and `group preset roles --force` take the
    tier of every user with an account on the tacctl server (the users of
    the scope it is enrolled in; every user when it is not enrolled) before
    they write and after, and when any is lower (for example superuser to
    engineer) run the
    sync of the enrolled server (`tacctl host sync <server>`, local) and say
    so, so the user does not keep the old tier's groups, `tac-superuser`
    among them, until somebody syncs. When the sync fails, or no server is
    enrolled, a red line says `Members of '<group>' keep their old groups on
    this server until: tacctl host sync <server>` (`'<user>' keeps the groups
    of the old tier ...` for `user move`; exit 1 for a failed sync). A raise,
    or a change that leaves every tier, syncs nothing. `store import`,
    `store rollback` and `backup restore` replace the state wholesale and
    cannot say whose tier fell: when the server is enrolled they print the
    red line `Users whose tier is lower now keep their old groups on this
    server until: tacctl host sync <server>`, and a model that cannot be read
    before or after a change prints its red line too. `console check` reports
    every member of `tac-superuser` that is a tacctl account and not a
    superuser-tier tacctl user (`<user> is an engineer but is still in
    tac-superuser here (stale membership ...)`, `<user> is operator, not a
    superuser, but ...`, or `<user> is no tacctl user (removed?) but ...` for
    an account whose UID is in tacctl's range; root is not named); an account
    outside that range, a local administrator added by hand, is only
    mentioned (item 15).

15. **`console check` does not flag a local administrator.** A member of
    `tac-superuser` that is not a tacctl account (its UID is outside
    `linux.uid_min`..`linux.uid_max`, for example an administrator added by
    hand) made the check exit 1 for good. It is listed now as `<user>: in
    tac-superuser, not a tacctl account (a local administrator?); tacctl host
    sync <server> takes it out of tacctl's groups` and the check stays green;
    a tacctl user who is not a superuser, and an account in the range whose
    user was removed, are still red.

16. **`console check` asks sudo in the C locale.** The `sudo -l -U` that
    checks what the engineers may run is run with `LC_ALL=C`, `LANGUAGE=C`
    and `COLUMNS=4096`, and a rule sudo wrapped onto continuation lines is
    read as one rule, so a translated or wrapped answer can no longer hide
    a command.

17. **An engineer imports devices from standard input only.** `device
    import` by an engineer must be `tacctl device import - [--check|
    --replace] < file`; a file name (or a flag before `-`) is refused (`The
    engineer tier imports from standard input only: tacctl device import -
    [--check|--replace] < file`), and the tiers sudoers rows for it are
    `device import -` and `device import - *`, so sudo refuses a file name
    before tacctl runs; until now `device import /some/file` read any file
    as root for an engineer.

18. **`config cisco|juniper|wti --staging --name <device>` refuses a device
    of another scope.** An engineer naming a registered device of a scope
    that is not theirs is told `Device '<name>' not found.` and nothing
    is staged; a device registry that cannot be read refuses the command
    instead of skipping the check.

19. **A host is not a device to an engineer, and nothing an engineer runs
    can make a host sync necessary.** The device verbs that write the
    registry (`rename`, `remove`, `address`, `hostname`, `vendor`, `port`,
    `description`, `location`, `legacy-ssh`, `import`) and `device hostkey`
    (which pins a host's ssh keys) answer `Device '<name>' not found.` for
    an enrolled host, one of their own scope's included; `config
    cisco|juniper|wti --staging <address>` refuses an address an enrolled
    host holds (`--staging: <address> is not available for staging.`) and
    `--name` of a host; `scope devices <scope> set|unset` refuses an address
    or range that contains an enrolled host's address (`<range> is not
    available for tagging.`); and the sweep that ends a staging address
    after a device moved leaves the staging address of a host alone for an
    engineer. A test now runs every command line an Engineer row opens and
    compares, before and after, everything a sync is built from (the script
    it would send for each registered host: users, tiers, UIDs, shells, the
    console policy of this server's own entry, `TAC_ENGINEER_SUDO`, the
    server address, the scope's secret and method; the host registry, the
    host pins and recorded addresses of `devices.yaml`, the `linux.*`,
    `host.*` and `tier.*` settings, and the scope and prefix that answer
    each host's address); any difference fails with the command line and the
    field.

20. **Engineers read the secrets of their own scopes and see their hosts.**
    An engineer may run `scope secret <scope> show` (the read of the value,
    logged) and `scope show <scope>` (the scope and the secret's length only,
    no read of the value and nothing logged) for the scopes they are a member
    of (another scope is `Scope '<name>' does not exist.`); `scope secret <scope> set`, `generate` and
    the usage are refused (`The engineer tier reads a scope's secret:
    tacctl scope secret <scope> show. Changing it is the superuser's.
    Nothing was changed.`). Every read of a secret by an engineer, the
    walkthroughs `config cisco|juniper|wti` included, is logged `secret-read
    kind=scope name=<scope> by=<user>` (auth.info, never the value). The
    engineer also gets `host list` and `host show` (their scopes' hosts
    only; `host show --check` logs in to the host over ssh and is refused:
    `'host show --check' logs in to the host over ssh, which is the
    superuser's`) and `scope staging list` (their scopes' addresses;
    `remove` stays the superuser's and a restricted list does not sweep).
    The tiers sudoers drop-in has the matching rows (`host list`, `host
    show *`, `scope staging`, `scope staging list`, `scope secret *`, `scope
    show *`). Nothing an engineer can run
    changes a global setting: `tacctl.yaml`, `console.yaml` and the SNMP
    files stay as they are (a test walks the whole tier table).

21. **Engineers read the SNMP settings of the scopes of their own.**
    `scope snmp <scope> show [--reveal]` (with the plain reads of version,
    port, timeout, contact and `clients list`) is open to the engineer tier
    for the scopes they are a member of, and says whether each value is the
    scope's or the default's; another scope is `Scope '<name>' does not
    exist.`. Every setter, `clear` and `test` is refused (`The engineer tier
    reads a scope's SNMP settings ... Changing them is the superuser's.
    Nothing was changed.`), and so is `config snmp show --reveal`: the
    default is the superuser's. A `--reveal` by an engineer, and a
    walkthrough that prints the credentials, is logged `secret-read
    kind=snmp name=<scope> by=<user>` (auth.info, never the value). The tiers
    sudoers drop-in gains the rows `scope snmp *` and `device location *`.

22. **`host show` and `host show --check` know the engineer tier.** `host
    show` lists an engineer's account in `tac-users` and `tac-engineer` on a
    host (a superuser's in `tac-users` and `tac-superuser`), and takes the
    tier from the group's `tier` setting as the sync does, not from the
    priv-lvl band alone. `--check` expects `tac-engineer` on every host (GID
    the range's first number + 5; `group tac-engineer is missing` until a
    sync makes it), reads who is in `tac-superuser` and `tac-engineer`, and
    reports an engineer still in `tac-superuser` (`<user> is an engineer but
    is still in tac-superuser`, fixed by `tacctl host sync <name>`). A host
    that ran client script protocol 5 is still reported by the existing
    difference.

23. **`config linux engineer-sudo` warns about commands that give root a
    shell, and the client script checks each command.** A shell, an
    interpreter, an editor, `su`, `sudo`, `find`, `env` and the like is
    accepted with `<command> gives root a shell; engineers on those hosts
    are then superusers in all but name.` The client script refuses a
    `TAC_ENGINEER_SUDO` command that `engineer-sudo` would refuse (`..`,
    `.`, `//` or a trailing `/`, more than 255 characters) with `is not a
    clean command path`, before anything changes.

24. **A machine that runs tacctl gets no engineer sudo line, and this
    server is enrolled with `--local` only.** The script a host runs is now
    told whether it is the server (`TAC_LOCAL`) by the registry entry, not
    by the accounts' shells, and its sudoers step writes no `%tac-engineer`
    line, with a warning, on a machine that has `/usr/local/bin/tacctl` or
    the tiers drop-in but was not enrolled as the server. The address
    `0.0.0.0` (and `0`, which resolves to it) counts as this machine, and
    `host enroll` of an address of this machine without `--local` is
    refused, for everyone, with `'<target>' is this server; enroll it with
    --local`, so no entry that is not the server's own reaches the script
    without `TAC_LOCAL`.

25. **`tacctl host` no longer forwards your ssh agent or any port to a
    host.** Every ssh of `host enroll`, `sync`, `move`, `target`, `show
    --check` and `unenroll` carries `-o ForwardAgent=no -o
    ClearAllForwardings=yes`, which beat the ssh config of the person who
    runs it.

26. **Linux host deployment is the superuser's; engineers read hosts.** `host
    enroll`, `host sync`, `host move`, `host target`, `host provisioner`,
    `host unenroll` and `host default-method` have no engineer row (and no
    row in the tiers sudoers drop-in): an engineer is refused at the gate
    (`'tacctl host sync' is not permitted for the engineer tier.`), in the
    shell and the console too, and nothing is written. An engineer keeps
    `host list` and `host show`, which show the hosts of their own scopes
    only (another scope's host is `No enrolled host named '<name>'`).
    Engineers still get their accounts and their sudo on the hosts of their
    scopes through a superuser's sync (`tac-engineer`, `linux.engineer_sudo`,
    client script protocol 6 and `TAC_REVOKE_ENGINEER` are as before).
    Every ssh of
    `tacctl host` still carries `-o ForwardAgent=no -o
    ClearAllForwardings=yes`.

27. **`host show <name> --check` is the superuser's.** It opens an ssh
    session as the invoking user, so an engineer, who may read `host show`,
    is refused with `'host show --check' logs in to the host over ssh, which
    is the superuser's; 'tacctl host show <name>' shows what tacctl
    recorded of it.` before anything runs. The family's help lists the
    note under `host`.

28. **`tacctl host provisioner <name> rotate <user> (--key <file>|--password)
    [--remove-old [--remove-home]] [--dry-run] [--yes]` switches the account
    tacctl logs in to a host with, without ever locking tacctl out.** In this
    order: the arguments are checked locally and nothing has changed (the
    host is enrolled and not this server's own `--local` entry; the new
    account is not `root`, the login in use or a tacctl user; exactly one of
    `--key` and `--password`, the latter on a terminal; `--remove-old` only
    for a registry target of the form `user@host`, because without a user
    the "old account" would be your own username); the new account is
    created over the login in use by a small script of its own, never the
    client script; a fresh ssh login in a NEW connection (no shared
    connection, the new account's credentials only) must run `sudo id -u`
    and get `0`, with ssh trusting the host's pinned keys and no others
    (item 35; the probe's `sudo-password` answer, which a login that
    cannot sudo gives too, is not enough);
    only then does the registry change, as `host target` does it (after a
    snapshot; scope, server and method kept; `Target` becomes
    `<user>@<host>`; the identity is the key file, or cleared for
    `--password`); the old login is recorded in the host's record. With
    `--remove-old` the old account is removed last, over the new one
    (item 30). A new `host provisioner` line in the usage, the completion,
    the README and the manual page.

29. **The new account, and where its secrets are.** It is created below
    tacctl's UID range from the start (`useradd -K UID_MAX=<first of the
    range - 1>`, out of the ranges the server used before and out of
    20000-29999; a system-range number when none is free), with `useradd -m
    -U -s /bin/bash -c 'tacctl provisioning account'`; that comment is not
    the one `host sync` gives and manages, and is for display only: a
    re-run adopts an account only when root's record says tacctl made it
    (item 31), any other existing account of that name is refused, and so
    is an adopted one whose UID is inside tacctl's range. Its sudoers line is
    in its own file, `/etc/sudoers.d/tacctl-provisioner` (one line per
    provisioning account, checked with `visudo -cf`; never `tacctl-host`,
    which each sync rewrites). With `--key` the account has a locked
    password, `NOPASSWD: ALL` and only the public key in
    `~/.ssh/authorized_keys` (modes 0700 and 0600, `restorecon` where
    SELinux is on); a missing key file is made by `ssh-keygen -t ed25519`
    (it asks for the passphrase, empty is your choice) and its path becomes
    the registry identity, as `host target --identity` does; every access to
    the key file (existence, owner and mode, the public key, the
    fingerprint) runs as the invoking user, never as root. With `--password`
    the account has `ALL` with a password that you type into the host's own
    `passwd` over the ssh terminal; it never passes through tacctl, an
    argument, the environment, a file, a log or the audit line (the proof
    types it into ssh and sudo on your terminal the same way). A host whose
    sshd has `PasswordAuthentication no` always fails a `--password` proof;
    `--dry-run` says so.

30. **Failures, `--remove-old`, `--dry-run` and the audit line.** If creating
    the account fails the script takes back its own steps: the account it
    made, the sudoers line it wrote (item 36 states what can remain). If
    the proof fails, what the run did is taken back over the login in use
    (an account this run created is removed with its sudoers line, an
    adopted one is never deleted, item 33), the registry is left alone and
    `auth.warning host provisioner rotate name= old= new= auth= step=prove
    by=` is logged; if that removal fails too the output names what is
    left. A run interrupted before the
    registry changed is repeated with the same command, which adopts the
    account; one interrupted after it is finished by the same command with
    `--remove-old`, which reads the old login from the host's record.
    `--remove-old` runs last, as the new account: `pkill -u <old>`,
    `userdel`, the old account's line in the provisioner sudoers file, taken
    out first (other sudoers files that name it, and the groups it was in,
    are reported and left), and its home moved to `/home/.tacctl-removed/<name>-<time>`, root
    owned and 0700, or deleted with `--remove-home` (a terminal is asked when
    neither is given), by the rules of `host sync` for removed users. It is
    refused when the old and new accounts are the same, the old one is
    `root` or a tacctl user, an account with a number in tacctl's UID range,
    or when the registry does not point at the new account yet. `--dry-run`
    prints the plan (the `useradd` line, the sudoers line, the key's
    fingerprint, the registry line before and after) and runs only a test
    login to the current target, a look at whether the account exists there
    and the host's `sshd -T` value of `passwordauthentication`; it changes
    nothing. Every completed rotation logs `host provisioner rotate name=
    old= new= auth=key|password by=` and every removal of the old account
    `host provisioner remove-old name= old= new= by=`, never a secret.

31. **Adoption trusts root's record, not the account's comment.** A re-run of
    `host provisioner ... rotate` adopts an existing account only when it is
    in `/etc/passwd` itself (not an sssd or LDAP account) and a record the
    create script wrote under `/var/lib/tacctl-provisioner/<account>`
    (a directory of root's alone, 0700, file 0600; the account name, its UID,
    whether `~/.ssh` was made by the script) agrees with it, written at once
    after `useradd`. The comment field (`tacctl provisioning account`) is the
    account's own to change where `CHFN_RESTRICT` lets it, and a directory
    supplies it, so it decides nothing and is kept for display. Any other
    account of that name is refused with nothing changed.

32. **The sudoers line is written last, and the key is written by the
    account.** The create script sets the key (or runs `passwd`) first and
    gives the account its `NOPASSWD: ALL` or `ALL` line only after every other
    step has succeeded; a failure after the line takes that line out again
    (an adopted account that had another line gets it back), an account the
    run created is removed with it. `authorized_keys` is written as the
    account (`runuser`, else `sudo -u`) with `umask 077` instead of by root in
    a directory the account owns, so a link planted in `~/.ssh` cannot make
    root write elsewhere, and `~/.ssh` is refused when it is a link, belongs to
    somebody else or is writable by its group or others. An adopted account
    is adopted only when its `~/.ssh` was made by the script, and that
    directory is emptied first (`rc`, `authorized_keys2` and anything else a
    former user of the account left); the rest of its home (dotfiles, cron,
    user units) is not scanned, so an account that has been in use is better
    removed and made again.

33. **A failed proof never deletes an account it did not create.** The
    create script says on a status line whether it created or adopted the
    account, and whether it added, changed or left its sudoers line. After a
    failed proof the command removes (with the home) only an account the run
    created; for an adopted account it takes out only the line this run
    added, leaves the account, and says what is left; when the script said
    nothing, nothing is deleted and the output names what may be there.
    Two operators rotating to the same name no longer leave the registry
    pointing at a deleted account.

34. **One rotation of a host at a time.** The command holds an exclusive lock
    for the host (`/etc/tacctl/locks/host-provisioner-<name>.lock`) from its
    first check to its last step, and a second run fails at once with
    `Another rotation of '<name>' is running` and changes nothing (`--dry-run`
    changes nothing and takes no lock). The host's record is changed under a
    lock too, and the registry entry is read again just before it is
    rewritten: a `host move` that ran during the proof is kept, a change of
    how the host is reached (`host target`) stops the rotation. On the host,
    both scripts change the shared sudoers file under `flock` on
    `/etc/sudoers.d/.tacctl-provisioner.lock` (a lock directory where `flock`
    is missing), so two scripts at once lose no line.

35. **The proof's ssh trusts the pinned keys, not whoever answers.** The keys
    the new login prints were never proof of the host: a machine that answers
    can print the pinned ones. The proof now runs ssh with a temporary
    known_hosts made from the host's pinned keys and `UserKnownHostsFile=<it>`,
    `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`,
    `HostKeyAlias=<name>` and `UpdateHostKeys=no`, so ssh itself refuses
    another machine; the keys the login reads are still compared with the
    pins (the comparison `host target` uses, which also logs `auth.warning
    host provisioner hostkey-mismatch name=`). A host with no pinned keys has
    nothing to trust: `--password` is refused (the password would be typed to
    an unauthenticated peer) and `--key` goes on only after the keys the host
    answered with are listed and confirmed (`--yes` confirms); ssh then goes
    by your own known_hosts. The proof's options are a stricter set than a
    later login's (`IdentitiesOnly`, `PreferredAuthentications=publickey`, no
    GSSAPI or host-based logins), so a proof that holds is not undone by what
    `host sync` adds. The temporary known_hosts is readable by the user whose
    ssh runs the proof whatever umask tacctl runs with (it was closed to that
    user under a restrictive umask, and the proof then failed with "No ED25519
    host key is known").

36. **Creating the account takes back what it did.** A `useradd` that fails
    after it made part of the account no longer leaves it: what it made is
    removed. The scripts run on a terminal on the host even when tacctl has
    none (`ssh -tt`), so an interrupted or dropped connection hangs the script
    up and its rollback runs; they also end on a closed pipe. What can still
    remain: a host that loses power or whose shell is killed outright during
    the run, a removal that itself fails (the output names it), and an
    adopted account's emptied `~/.ssh`, which is not brought back.

37. **Removal details.** The remove script takes the account's sudoers line
    out first, before ending processes and `userdel` (a `userdel` that fails
    leaves the account expired and without sudo); its group is removed only
    when it is the account's own (its number is the account's UID or primary
    group, as `host sync` checks), and the account's record goes with it. The
    account's group is created below tacctl's range too (`-K GID_MAX`), and
    a group number inside the range is refused like an account number.

38. **`--dry-run` reads root's record.** It reports whether the host's record
    names the existing account and agrees with its UID ("the rotation adopts
    it and empties its `~/.ssh`"), or that nothing shows tacctl made it and the
    rotation would refuse it.

39. **A space at the prompt of the shell and the console works as on a
    Junos device.** This changes how typing behaves for existing console
    users at the upgrade; `tacctl console space-completion off` brings the
    old typing back for everyone: it turns off the refusal of repeated
    blanks and the completion. A
    space is refused (nothing is inserted) where it would be a second one: at the start of
    the line, right after a space and right before one. At the end of a word
    that is a command, a sub-command, a fixed choice (such as
    `enable|disable`) or a flag name, a space completes the word when
    exactly one such word starts with what is typed and adds the blank (`de`
    and a space give `device `).
    When several do, they are listed once, as `?` lists them but without the
    question for a long list and without paging, and nothing is inserted;
    more candidates than `list_max` print nothing. A word that is complete
    already (`user` while `user-x` exists), a name of the store (a user, a
    group, a scope, a host, a device, a backup, a file), free text, a typo,
    a space inside a word and a space inside quotes or after a backslash get
    the space as typed. Tab, `?` and the Ctrl-R search keep their meaning,
    and `-c` and batch input are not affected. Pastes are unchanged from
    0.2.2, with the setting on or off, with one addition: a paste that
    reaches the editor while the long-list question (`Show all <n> ...?`)
    or the pager is waiting for a key ends it (it counts as `q`) and is then
    read as a paste.

40. **`tacctl console space-completion [on|off]` and `tacctl shell
    --space-completion on|off`.** The console setting is server-wide and on
    by default; without an argument the verb prints the current value, and
    `console show` has a `space-completion` row. It is stored in
    `console.yaml` as `settings.space_completion`, and only while it is off;
    a `console.yaml` without the key reads as on. Each console
    session reads it when it starts, from a new `space_completion=yes|no`
    field on the `_console-policy` line (an older tacctl ignores a field it
    does not know). Plain `tacctl shell` takes `--space-completion on|off`,
    default on. A `console.yaml` written by 0.2.3 is not read by a 0.2.2
    binary even when the setting was never turned off, because the engineer
    tier's switch is written with it too: `tacctl rollback 0.2.2 --apply`
    (item 84) removes both keys before the older release is installed.

41. **The shell and the console list only what the caller's tier can run.**
    In `tacctl shell` and the login console, Tab, `?`, a typed space and the
    top-level `help` no longer name the commands and sub-commands that the
    caller's tier would be refused: a readonly user does not see `store`,
    `install` or `user add`, an operator does not see `host`, an engineer does
    not see `group junos`, and a superuser and a caller outside `tac-users`
    see everything as before. The lists are read from the same table as the
    sudoers drop-in (`tier.Rules`), so they cannot differ from what the gate
    allows, and a test walks every verb of the completion tree for every tier.
    This is display only: the gate and sudo are still the check, and a
    command typed by hand is refused as before. The usage stays complete:
    `help <command>` describes every verb and now ends with the tier each
    needs, with a note for the verbs whose sub-verbs the code splits (`scope
    secret`, `scope staging`, `scope snmp`, `host show`, `device import`), and
    `?` after a verb the tier cannot run shows its usage with `Needs the
    <tier> tier.`, after a family it cannot run at all (`store ?` for a
    readonly user) `Needs the <tier> tier. help <family> describes it.` The
    top-level `help` ends its command list with `Shown: the commands the
    <tier> tier can run` and leaves out the examples it would not let you run.
    A caller whose tier cannot be learned (the root side does not answer, or
    has not yet) sees the read-only commands only, never more; a caller the
    root side answered has no tier (item 45) sees none. The rows that are
    listed keep their full description, which can name a verb of the family
    that is not listed (`user <subcommand>` ends with its list of verbs).
    `tacctl` with no arguments, `tacctl <command>`, the man page and the
    README are not filtered.

42. **`tacctl shell` learns the caller's tier from the root side, and
    `_console-policy` can name the gate's tier.** A `tac-users` member's
    shell asks `sudo -n tacctl _console-policy` (as the console does) when it
    starts, in the background (item 43); a caller outside `tac-users` is not
    asked and sees everything. The answer already
    carried `tier=`, the console's own view of the caller (an engineer stays
    an engineer there, item 4). When the tier the gate enforces differs, as
    for an engineer that an unreadable `tacctl.yaml` caps to operator, the
    line also carries `gate=<tier>`, and the lists follow it, so they show
    what the gate will run. An older tacctl ignores the field, and a shell
    that finds none uses `tier=`.

43. **`tacctl shell` never waits for the root side to learn the tier.** The
    question to `sudo -n tacctl _console-policy` ran on the editor's own
    thread, with no limit, the first time Tab, `?` or a typed space needed
    the tier; if sudo's PAM step waited out a server timeout, typing stalled
    (Ctrl-C does not reach a raw terminal), and one failure was kept for the
    session. The interactive shell now asks when it starts, in the
    background, giving up after 3 seconds. Until the answer is in, or when
    there was none, the lists show the read-only commands. After a failure
    the next Tab, `?` or space asks again once 30 seconds have passed. A
    shell without a terminal (`-c`, a script) asks on first use and waits for
    the answer, for at most 3 seconds.

44. **`?` after a command the tier cannot run says what it needs.** `store ?`
    for a readonly user, `config ?` for a readonly one and `host ?` for an
    operator printed `No valid completions`; they now print `Needs the
    <tier> tier. help <family> describes it.` The note for `scope staging`
    joins those of `scope secret` and `scope snmp` in `help scope` (those of
    `host show` and `device import` are in `help host` and `help device`): an engineer's `scope staging` runs `list` only, but the
    sudoers rows grant only that, and the shell used to offer `remove`
    without a word. A test compares the notes with the sudoers rows
    narrower than `<verb> *`, so a new split verb fails until it has its
    note. `?` after `scope staging` no longer prints `Next: [list`.

45. **A disabled tacctl user's shell lists no command.** When the root side
    answers that the caller has no tier (`tier=none`: the account is
    disabled), the shell used to list the read-only commands, `passwd` and
    `user list` among them, though the gate refuses them. It now lists none
    and its top-level `help` says that the account has no tier; `help`,
    `exit` and `quit` remain. An answer that cannot be read, or has no tier
    field, still lists the read-only commands.

46. **The plain shell's tier lookup is logged as `shell policy`.** It was
    logged as `console policy ... session=` like a console login; a lookup
    without the console's `TACCTL_CONSOLE` marker is now `auth.info shell
    policy user=<user> tier=<tier>`.

47. **`help scope` for an engineer notes `scope snmp`.** The verbs of a
    family that the gate cannot tell apart carry a note in the shell's and the
    console's help of the family; `scope snmp` had
    none, so an engineer saw it listed without being told that only the reads
    of a scope of their own are theirs: `scope snmp: an engineer may read the
    settings of a scope of their own (show [--reveal], version, port, timeout,
    contact, clients list); every setter, clear and test needs the superuser
    tier.` The manual's TIERS section prints the same note, from the same
    place.

48. **Every command-rule regex is rendered whole, `^(?:regex)$`; a rule with a
    bare alternation now matches what it says.** tacquito adds `^` and `$`
    only where they are missing, so a stored `crypto|trace` was tested as
    `^crypto|trace$`: a prefix match on the first branch and a suffix match
    on the last (`show ip trace` and `show foo trace` matched, `show crypto
    pki` did not). tacctl now wraps each stored regex when it writes
    `tacquito.yaml`, so the regex has to match the whole arguments string and
    its alternation stays together. A rule with a top-level `|` and no
    anchors, or one that ended in a prefix form tacquito closed with `$`,
    matches differently after the upgrade: what it was meant to match now
    matches, and what only the old reading matched no longer does. Review
    `tacctl group commands list <group>` for such rules; `tacctl upgrade`
    re-renders and restarts tacquito. A rule without a `match`, the shipped
    rules before this release and any regex with one pair of anchors and no
    top-level `|` mean what they meant. The read-back and the legacy importer
    undo the wrapper, so a rendered file imports back to the same rules.

49. **`group commands add` and `config validate` check the rules they write
    and hold.** `--match` is now also refused when it is empty (tacquito
    skips an empty regex, so the rule would match nothing); an invalid regex
    (Go's RE2, as tacquito), a comma and a regex that begins with the
    command word (it can never match: the arguments are tested without it)
    were refused already. After the rule is added, a warning follows for a prefix form without
    `( .*)?` and without a closing `$` (`^crypto` matches the exact argument
    `crypto` only: write `^crypto( .*)?$`), and for a rule that can never be
    reached because an earlier rule of the same name has no `--match`, or the
    `*` catchall comes first. `config validate` prints the same findings for
    the stored rules as `Command rules:` warnings; they do not make the
    validation fail.

50. **The baseline command rules and privileges of the four roles.** Shipped,
    for every install and every group without an override of its own, and
    permit-only (nothing that denies what a role could do before): `readonly`
    is the account for monitoring and backup systems (SolarWinds NCM) and
    keeps `show`, `ping`, `traceroute`, and gains `dir`, `terminal length|width`
    (so a screen-scraper's `terminal length 0` is no longer denied), `exit`
    and `logout`; `operator` gains `dir`, `ssh`, `telnet`, `undebug`, `exit`,
    `logout`, `monitor capture`, and the `clear` forms `counters`, `line`,
    `ip arp <address>`, `arp-cache <name>` and `mac address-table dynamic
    <argument>` (single entries; never the whole table, `clear ip route`, a
    hard `clear ip bgp`, `debug`, `copy`, `test`). Roles nest: what readonly
    may run, operator may run. Privileges (`privilege exec ...` on the
    device): `readonly` lowers `show running-config` to level 1, so a
    monitoring account backs up the configuration its level may see (IOS
    filters it to what level 1 could enter; `show running-config view full`
    is unfiltered, shows every key and is not lowered, and `show startup-config`
    is not lowered pending a lab check); `operator`'s list is now `exec all:
    ping`, `exec all: traceroute`, `exec all: monitor capture`, `clear
    counters`, `clear line`, `clear ip arp`, `clear arp-cache`, `clear mac
    address-table dynamic` and `undebug all` (IOS levels are cumulative, so
    operator inherits readonly's line). The old list (`show running-config`,
    `show startup-config`, `show tech-support`, `show archive`, `show
    access-list`, `show ip route`) gave an operator little or nothing useful
    (a level-7 `show running-config` is almost empty) and `show access-list`
    and `show ip route` are level 1 already; the new list moves nothing up.
    **On the devices:** the rules reach the server at the upgrade's re-render,
    but the new `privilege` lines reach a device only when you paste the
    output of `tacctl config cisco` again, and the old lines stay until you
    remove them: for each of `show running-config`, `show startup-config`,
    `show tech-support`, `show archive`, `show access-list` and `show ip route`
    that a device carries at level 7, enter `no privilege exec level 7 <command>`
    (`show running-config` needs none: the new `privilege exec level 1 show
    running-config` replaces its mapping). Until the re-paste an operator cannot yet `clear
    counters` or `clear line` (the device's level gate), and a readonly user
    reads the unfiltered level-1 output only. A SolarWinds backup of a Cisco
    device is therefore a **filtered** configuration; before pointing NCM at
    a fleet check what it stores. Pre-existing overrides are untouched.

51. **The role preset's Cisco content, rewritten.** `tacctl group preset roles`
    now also writes, for the viewer (`readonly`) and the operator, a `show`
    deny in front of their shipped rules for the secret-bearing, unfiltered
    sub-trees (viewer: `running-config view full`, `tech-support`,
    `startup-config`, `derived-config`, `key chain`, `snmp community|user`,
    `crypto`, `archive log`; operator: the same without `tech-support` and
    with `crypto isakmp key|key`); every other `show` falls through to the
    shipped permit. The engineer's Cisco rules are 34 rules, written whole
    (item 48), and **Cisco configuration mode is not restricted for
    engineers**: an engineer can change AAA, the TACACS+ and RADIUS servers
    and keys, lines, privilege levels, SNMP, logging and the management ACL,
    so a mistake can lock a device out (tacctl's own push, 0.2.5, protects
    itself with its revert timer; a site that wants a boundary adds rules with
    `tacctl group commands add`). What stays denied is exec-level only and
    hides nothing: `reload`, `delete`/`erase`/`format`/`fsck`/`rename`/`mkdir`/
    `rmdir`, `request`/`install`/`software`/`upgrade`/`issu`, `write erase`,
    `archive` other than `archive config`, `copy` into running-config or
    flash (saving to startup-config, flash or a URL and exporting a file are
    permitted), `configure network|memory` and `configure replace <url>`,
    `tclsh`/`guestshell`/`app-hosting`/`iox`/`scripting`, `hw-module`,
    `redundancy`, `switch`, `test aaa`, `debug all|aaa|tacacs|radius`, `clear
    aaa|logging|archive`, and the matching `do` forms. The preset no longer
    takes the management ACL's name into account.

52. **The role preset's Junos deny sets, and no `deny-configuration`.**
    `deny-commands` per role: viewer (112 of 241 bytes) denies `ssh`,
    `telnet`, `file`, `request`, `restart`, `start`, `load`, `op`, `test`,
    `monitor`, `configure`, `edit`, `clear` and `show system rollback`;
    operator (226) denies `file`, `request`, `restart`, `start`, `load`, `op`,
    `test`, `configure`, `edit`, the hard protocol clears (`clear bgp|ospf|
    ospf3|isis|ldp|rsvp|mpls|pim|igmp|msdp|bfd|vrrp|lacp|dhcp`), `clear
    system|security|network-access|log`, `monitor traffic ... write-file` and
    `show system rollback`; engineer (219) denies `request system|chassis
    routing-engine|vmhost|security`, `start`, `op`, `file copy|delete|
    delete-directory|rename|archive|show|change-owner|change-permission`,
    `clear system login|log` and `restart chassis|management`. `load` is not
    denied for the engineer: Junos tests a pattern against a command's
    keywords with each argument replaced by a placeholder, so no pattern can
    allow `load set terminal` (pasting set-lists) and refuse `load set
    <file>`; an engineer has no shell and cannot `file copy`, so the files a
    load reads are the ones the box holds. The dead `show configuration .*(...)`
    clauses of 0.2.2 are gone (the lab showed they never matched). **No role
    has a `deny-configuration`**: the viewer and the operator read the whole
    configuration with secrets redacted (`SECRET-DATA`; their classes have no
    `secret` bit), the engineer must not hide what they can see, and the
    engineer's set, which 0.2.2 wrote and which contained `snmp`, is no longer
    part of the preset (engineers may configure SNMP). With the canonical
    settings **a Junos engineer's `EN-CLASS` bits are the only limit on
    configuration**: an engineer can edit `system login`, `tacplus-server` and
    the management filter, where on Cisco the rules (item 51) are the only
    limit; that asymmetry is accepted. A site that wants a Junos boundary sets
    `group junos engineer deny-configuration` itself (README, Default
    Groups). `group preset roles` clears an engineer `deny-configuration` left
    by 0.2.2 only with `--force` (otherwise it reports it as kept), and its
    `--mgmt-filter` option is gone, since there is no `deny-configuration`
    left to put the filter in. The deny sets are sent by the server and take
    effect at the next login; the classes' permission bits are the ceiling
    on the device (item 107).

53. **Lab check of per-command authorization: `tests/tools/permcheck.py`.** A
    small RFC 8907 client that asks a lab TACACS+ server for the decision on
    every `user|cmd|args|expected` line of a file and reports the differences
    (no server is started by the repository; it takes a host, port and secret
    and fake secrets only in its examples). `tests/tools/permcheck-baseline.txt`
    holds the baseline's sample corpus as the preset decides it. See
    `tests/README.md`.

54. **The engineer role preset of 0.2.2 did not hold, and `tacctl upgrade`
    says so.** Of the Cisco denies that `tacctl group preset roles` wrote on
    0.2.2, most did not work: the regexes were prefix forms (`^config-key`,
    `^(http|ssh|...)`, `trustBoundary`, the `do` list), and tacquito matches
    the whole arguments string, so only the exact one-word argument was
    denied. `no aaa new-model`, `no tacacs server X`, `no username x`,
    `no line vty 0 4`, `enable secret ...`, `ip ssh ...`, `ip http server`,
    `key config-key ...`, `test aaa ...`, `clear aaa ...`, `do copy tftp:
    running-config` and `do reload in 5` were permitted, and the `copy`
    permit let `copy running-config bootflash:packages.conf` through while it
    denied `copy running-config tftp://...`. The test of that preset passed
    because it did not anchor the regexes the way tacquito does; the tests
    now decide with an emulator of tacquito's authorizer. The
    preset's values are overrides, which an upgrade never touches, so an
    install that ran it keeps them: `tacctl upgrade` compares
    `commands.engineer` and the two Junos sets of `engineer` with the text of
    0.2.2's preset and, when they are identical, ends with a red notice that
    names `tacctl group reset engineer` (look first with `--dry-run`; item 55).
    Nothing in the shipped defaults was affected.

55. **The upgrade notice names the new verb.** An install that still carries
    0.2.2's engineer role preset is told to run `tacctl group reset engineer
    --dry-run` and then `tacctl group reset engineer`, in place of `group
    preset roles --force`, which also rewrote every other role.

56. **`tacctl group reset <group> [--preset] [--only settings,commands,privileges,junos]
    [--dry-run] [--yes]` puts a group back to its canonical state.** It shows
    the difference first and asks `Apply these changes to group '<group>'?
    [y/N]` (`--yes` answers for you; without a terminal and without `--yes`
    it changes nothing and exits 1; `--dry-run` prints the difference and
    stops; a group that already is canonical says so and exits 0 without
    asking). Superuser only: the gate, the tiers sudoers and the shell's and
    the console's lists give a lower tier, the engineer included, no `group
    reset` (an engineer changes no global setting). `--only` limits the reset
    to the sections named; it never changes the group's name, users or
    built-in flag. Where `group commands reset <group>` drops only the
    command overrides, this reverts everything a group carries in one
    reviewed step.

57. **What canonical means.** For `readonly`, `operator` and `superuser`: what
    a fresh install gives them, read from the same sources the install uses
    (the shipped command rules and Cisco privileges, priv-lvl 1, 7 and 15,
    Junos class `RO-CLASS`, `OP-CLASS` and `RW-CLASS`), with no setting of
    their own for the tier, the WTI level or the Junos sets. With `--preset`:
    the role preset's values (items 51, 52), so a built-in group can be set
    back to its role. For `engineer`, which is not built-in until 0.3.0: the
    preset's engineer (priv-lvl 15, `EN-CLASS`, tier `engineer`, WTI
    `superuser`, its Junos `deny-commands`, no `deny-configuration`, its Cisco
    rules), written through the same setters as `group preset roles`, so
    `group reset engineer` equals `group preset roles --force` for that one
    group (and creates the group when it is absent). Any other group is
    refused: `Group 'x' is not a built-in or role group, so it has no
    canonical defaults; group commands reset x drops its command overrides.`

58. **The difference.** Four sections, each `unchanged` or the lines that
    change: `settings` (priv-lvl, Junos class, tier and WTI level as
    `current -> canonical`, the tier and level saying whether the current
    value is set or automatic), `commands` (rules removed `-`, added `+`,
    moved `~`, and the default action), `privileges` (lines `-` and `+`) and
    `junos` (each deny set with its size in bytes, its patterns `-` and
    `+`). It is computed before anything is written. A priv-lvl change warns
    `Cisco logins and the per-level authorization lines change; re-paste
    tacctl config cisco`, a class change `re-paste tacctl config juniper Step
    1`, and a tier that falls names the users whose tier falls. When the
    group ends with command rules, the groups at its priv-lvl that have none
    get a `*` permit rule first, as `group commands add` does (the lockout
    guard of `aaa authorization commands <level>`), and the diff says which.

59. **Writes, the audit line and the server's accounts.** The reset takes the
    usual pre-change snapshot, writes in one apply, renders and restarts the
    backends once, and logs `group reset name=<group> sections=<changed
    sections> by=<user>`. Every group at priv-lvl 15 other than `superuser`
    keeps an explicit tier setting (a reset to the preset's `engineer` writes
    `tier.engineer: engineer`). A reset that lowers a tier syncs this
    server's accounts at once, or says `Members of '<group>' keep their old
    groups on this server until: tacctl host sync <server>`, as `group edit
    tier` does (item 14).

60. **Removed: `tacctl group privilege clear <group>` and `tacctl group
    commands clear <group>`.** Both answer like any unknown subcommand
    (`Unknown subcommand: 'clear'` and the usage, exit 1) and are gone from
    the usage, the completion, the README and the manual page; item 61
    replaces them. `group privilege clear` wrote an empty list
    (`privileges.<group>: []`), which hid the shipped default instead of
    removing the override, so a built-in group that was cleared lost its
    shipped mappings (`readonly`'s `show running-config`, `operator`'s
    `ping` and `clear` entries) without saying so; `group commands clear`
    dropped the rules after a bare confirmation, with no look at what would
    change. A `privileges.<group>: []` that a `clear` left in
    `tacctl.yaml` is not touched by the upgrade; `group privilege reset
    <group>` shows it as a change to the shipped default and removes it.

61. **New: `tacctl group privilege reset <group> [--dry-run] [--yes]` and
    `tacctl group commands reset <group> [--dry-run] [--yes]`.** Each puts
    one group's Cisco priv-exec mappings (`privileges.<group>`) or command
    rules (`commands.<group>`) back to the shipped default, with the
    difference and the confirmation of `group reset`, and gives the same
    difference and result as `tacctl group reset <group> --only privileges`
    or `--only commands` for a built-in group. The shipped default is
    `defaults.yaml`'s list for `readonly`, `operator` and `superuser`; any
    other group, a custom group or `engineer`, has none shipped, so the reset
    removes its override (a true removal: the group has none afterwards, and
    an empty list is never stored). Neither takes `--preset`: the role
    preset's values come with `group reset <group> --preset`. The difference
    lists the entries or rules removed (`-`), added (`+`) and moved (`~`), and
    for the rules the default action; `already canonical` exits 0 without
    asking. It then asks `Apply these changes to the privileges of group
    '<group>'? [y/N]` (`... to the command rules of group ...`); `--yes`
    answers for you, without a terminal and without `--yes` it changes
    nothing and exits 1, `--dry-run` stops after the difference. A snapshot is
    taken first, the backends render and restart once, and the audit line is
    `group privilege reset name=<group> by=<user>` (`group commands reset
    ...`). `group privilege reset` warns that devices keep the `privilege
    exec level N ...` lines they were pasted with, and lists the exact `no
    privilege <mode> level N <command>` lines for the entries it removes, to
    paste before re-pasting `tacctl config cisco`. `group commands reset`
    keeps the lockout guard of `group reset`: a group at the same priv-lvl
    without rules gets a `*` permit rule first, and a group left without any
    rules is warned about (`tacctl config cisco` leaves its `aaa
    authorization commands` line commented out). Both are superuser only, the
    engineer included, like the other `group privilege` and `group commands`
    verbs. `group privilege list|add|remove|seed` and `group commands
    list|default|add|remove|seed` are unchanged.

62. **New: `tacctl scope snmp <scope> show [--reveal] | version | community
    | v3-user | clients | contact | port | timeout | clear | test`.** SNMP
    is now a setting of the scope; `tacctl config snmp` keeps meaning the
    default beneath it. A value comes from the scope, else the default
    (`snmp.*` and `snmp.yaml`), else the built-in, and `show` labels each
    one `(scope)`, `(default)` or `(built-in)`; the v3 user and its two
    passphrases are taken together from one level. The scope's non-secret
    settings are `snmp_scope.<scope>.{version,port,timeout,v3.auth,v3.priv,
    contact,clients}` in `tacctl.yaml`, written only when set; its community
    or v3 passphrases are the file `/etc/tacctl/snmp/<scope>.yaml` (0600 in
    a 0700 directory, the format of `snmp.yaml`, which is unchanged: a
    `snmp.yaml` of 0.2.2 loads as it did, and 0.2.2 ignores the new
    directory). `community` and `v3-user` ask twice without echo (`--stdin`
    reads them) and make the scope's version v2c or v3. A scope's rename
    moves its settings and file; its removal (also `scope prefixes remove
    --all`) deletes them. The sysName lookup of `device add` and `device
    check` now uses the credentials of the device's scope, the one that
    answers its address (a device in no scope uses the default);
    `scope snmp <scope> test <address|device>` tries the scope's,
    `config snmp test` the default's. A message that says SNMP is not
    configured names `tacctl config snmp` for a scope that has set nothing
    of its own and `tacctl scope snmp <scope>` for one that has begun. A
    credentials file that cannot be read leaves the SNMP step out of a
    walkthrough with a warning and fails the lookup with its reason.

63. **The allowed SNMP clients and the contact of a scope:
    `scope snmp <scope> clients list|add|remove <cidr>[,<cidr>...]` and
    `contact [<text>|--clear]`.** The ranges are IPv4 networks in canonical
    form, kept in the order given (the order of the access list), at most
    32, none twice, and never `0.0.0.0/0` (`would allow every address:
    0.0.0.0/0 is the restrict tacctl always renders last, and is never
    stored`); IPv6 is refused. An overlap of two ranges is a note, not an
    error (`10.0.0.0/8 already contains 10.1.0.0/16 (both stay)`). A scope
    with no ranges allows the tacctl server only, and the walkthrough says
    so. The contact is up to 120 characters, with no control character and
    no `?` (a device CLI reads a pasted `?` as a request for help).
    `tacctl.yaml` is held to the same rules: `config validate` reports a
    hand-edited list or contact that breaks them.

64. **`config snmp show --reveal` prints the default's credentials.** Plain
    `show` still says only whether they are set.

65. **New: `tacctl device location <name> [<text>|clear]` and `device add
    --snmp-location <text>`.** A device may have a location, the SNMP
    location its walkthrough renders (120 characters, no control character,
    no `?`). `devices.yaml` gets a `location:` line only for a device that
    has one, so a registry without any is the bytes it was; `device show`
    prints it and `device export --json` carries it (the CSV columns do not).
    A CSV import keeps the location of a device it updates. An empty text
    clears it. An engineer may set it for the devices of their own scopes.

66. **`config cisco`, `config juniper` and `config wti` end with an SNMP
    step.** Every walkthrough (the TACACS+ and RADIUS forms, and Cisco's
    legacy IOS 12.x form) gains a `${SNMP_BLOCK}` step that lets the device
    answer the tacctl server's reads and nobody else's. The allowed clients
    are, in this order, the tacctl server's own address as a /32 (always;
    the address its route to the devices uses, or `--source`, item 68),
    the scope's ranges in the order given (item 63), then `0.0.0.0/0`
    refused, which is always rendered and never stored. Cisco gets the
    standard access list `TACCTL-SNMP` (a /32 as `permit host`, wildcard
    masks for the rest, ending in `deny any`) bound to `snmp-server
    community <community> RO TACCTL-SNMP`, or for v3 a view, the group
    `TACCTL-GROUP` (`v3 priv read ... access TACCTL-SNMP`) and `snmp-server
    user ... v3 auth sha|sha256 ... priv aes 128 ...`, with `snmp-server
    location` and `contact`. Junos gets `set snmp client-list TACCTL-SNMP`
    with the ranges and `0.0.0.0/0 restrict`, the community `authorization
    read-only` with `client-list-name`, or the v3 `usm local-engine` user
    with its `vacm` group and view, and `set snmp location|contact|
    description`. WTI gets the unit's SNMP menu in the walkthrough's style
    (version, community or v3 user, location, contact) as Step 6, with the
    client restriction written as the list of clients for the unit's IP
    Tables (Step 5 is the unit's firewall check). The
    values are the scope's effective ones (item 62), the credentials are
    printed for superusers and for engineers of the scope (item 21), and a
    line says whether they are the scope's own or inherited from the
    default. A value that is not set (the scope's contact, a device's
    location) is a commented placeholder, never text a paste would apply,
    and the output ends with `Unfilled SNMP values: contact (tacctl scope
    snmp <scope> contact '<text>'), location (tacctl device location <name>
    '<text>')`; with no SNMP version in the scope or the default the step is
    a comment saying SNMP is not configured in tacctl, and nothing is
    listed. The step is built by one function per vendor over one input
    value (version, credentials, clients, contact, location, sysName,
    description) that reads no terminal, file or clock, so the text can be
    rendered per device later and reused by a push. **The Cisco and Junos
    lines are live, not comments:** pasted on a device that already has SNMP
    they bind an existing community to a list that allows only the server and
    the scope's ranges and overwrite the location and contact, so pollers and
    NCM using that community lose access; add them first with `tacctl scope
    snmp <scope> clients add <cidr>`, or leave the step out. **Not verified
    on a device:** the SNMP syntax of the three vendors, the SHA-256 keywords on
    Cisco and Junos, that a Junos client list does not restrict a v3 user
    (the output says so), and the WTI menu names and client restriction
    (the unit may have an SNMP access menu of its own). An operator's copy
    of a template without `${SNMP_BLOCK}` renders as before, without the
    step and without the `Unfilled` line. The shipped templates, their
    golden files and `.shipped.sha256` change.

67. **The WTI walkthrough has one more step.** The SNMP step is Step 6, so
    Save is Step 7, the test from a second session Step 8 and the debug
    step Step 9, in the TACACS+ and RADIUS forms; the notes and the verify
    lines name the new numbers. A template of your own keeps its numbers.

68. **`config cisco|juniper|wti` take `--name`, `--server`, `--source` and
    `--snmp-location`.** `--server <address|name>` is the address the
    devices are told to authenticate against (the TACACS+ or RADIUS server
    lines, the ping step), for devices that reach this server through a
    translating firewall; a host name must resolve to an IPv4 address, and
    it replaces the address a RADIUS listener is bound to too.
    `--source <address>` is the address tacctl itself reaches the devices
    from: the first SNMP client, and the address the ssh permit of the Cisco
    VTY-ACL and of the Junos management filter and the server's /32 of the
    WTI IP Tables list allow in addition to the scope's ranges, so a paste
    from behind the firewall does not lock tacctl out. When they differ
    the output says which address plays which role (`Two server addresses:`).
    Neither is stored, and both combine with `--staging`. `--name <device>`
    now also names a registered device without `--staging` (it was refused
    with `--name goes with --staging`): its location, description and sysName
    fill the SNMP step, and a device of another scope is refused;
    `--snmp-location <text>` gives the location for one paste. The usage
    line names the new flags.

69. **A commented NETCONF step in the Junos and Cisco walkthroughs.**
    Junos: `set system services netconf ssh` with the optional
    `connection-limit` and `rate-limit`, the check `ssh -p 830 -s
    <user>@<device> netconf` (expect a `<hello>`) and `show system
    connections | match "\.830 "`; the management filter, whenever it is
    rendered, says that it permits tcp port 830 next to ssh (it did), and
    without a filter the step says to permit it when one is added. Cisco: a
    commented `netconf-yang` with its prerequisite (exec authorization),
    for superusers; an engineer's walkthrough says to ask a superuser (the
    engineer's command rules no longer deny `netconf-yang`, but this step
    stays a superuser's); the legacy IOS 12.x walkthrough says there is no
    NETCONF. The WTI notes say the unit has none. Nothing is enabled by
    tacctl. **Not verified on a device.**

70. **`config wti` renders the unit's IP Tables list for the scope.** Step 5
    (both protocols) keeps its caution about loopback and replies and now
    follows it with the whole list, numbered in the unit's order, from data
    tacctl already holds: the scope's management permit list (`scope
    mgmt-acl`, else the global `config mgmt-acl`, the list the Cisco
    VTY-ACL and the Junos filter read), the tacctl server's address (the
    route to the devices, or `--source`; never `--server`) and the scope's
    SNMP clients. The rules: `-i lo`; `-m conntrack --ctstate
    ESTABLISHED,RELATED` (older builds: `-m state --state
    ESTABLISHED,RELATED`; it covers the replies of the unit's own TACACS+,
    RADIUS, DNS and NTP queries); `-p tcp -s <cidr> --dport 22` and `--dport
    443` for the server's /32 and each permitted range; `-p udp -s <cidr>
    --dport 161` for the SNMP clients (the server first, then the scope's
    ranges in order). Telnet and http are not rendered; the notes say how to
    add them. IPv4 only: an IPv6 or malformed entry is skipped with a note.
    Nothing new is stored and there is no new verb, so rolling back to
    0.2.2 has nothing to clear.

71. **The final DROP is a separate last step, never applied by the
    walkthrough.** `iptables -A INPUT -j DROP` is not in the Step 5 list;
    Step 11 gives it as the next numbered line, says plainly that the
    walkthrough does not apply it, and tells you to keep the serial session
    open, to paste it yourself as the last line and to test a login from a
    permitted address before saving. A scope with no management permit list
    (none of its own, none global, or only IPv6 entries) gets the loopback,
    established and server rules and a commented DROP with the reason: the
    DROP would lock out every administrator but tacctl. An unknown server
    address also leaves it commented, and the output ends with `Unfilled
    SNMP values: tacctl server address (pass --source <address>)`.

72. **The WTI walkthroughs end with two more steps.** Break-glass local
    accounts, which shared Step 9 with the debug step, are Step 10, and the
    final DROP is Step 11; Step 1 says to keep the serial session open until
    Step 11 is done when the DROP is added. The templates gain the
    variables `IPTABLES_BLOCK` and `IPTABLES_DROP_BLOCK`; a template of your
    own keeps its numbers and lacks the list until you add them.

73. **The WTI SNMP step points at the IP Tables list.** Its client
    restriction (the server, the scope's ranges, everything else refused) is
    now the udp port 161 lines of Step 5, unless the unit has an SNMP access
    menu of its own, where the same clients go; the text no longer says the
    restriction depends on a list not yet written.

74. **The mgmt-acl usage and the README name WTI.** `config mgmt-acl` and
    `scope mgmt-acl` describe the permits as those of the Cisco VTY-ACL, the
    Junos lo0 filter and the WTI IP Tables; the README's "Management ACL"
    section and the manual page describe the list, the guards and the final
    DROP.

75. **Not lab-verified.** The list is built from WTI's documents and the
    user's description of the unit. How the real unit takes the lines (the
    menu under `/N`, whether a changed list applies on entry or on save,
    whether `-m conntrack` or the older `-m state` is accepted, and that the
    TACACS+ login and the `sysName` read still work with the DROP in place)
    is for the user to confirm on the lab unit; the output says "Not
    verified on a unit".

76. **`tacctl scope breakglass <scope> list | add <name> [--role
    admin|operator|readonly] | remove <name>` records a scope's break-glass
    local users.** These are the accounts a scope's devices keep for the day
    the server cannot be reached; until now the walkthroughs only advised
    keeping one. Only the name and the role are recorded (`admin` by
    default), in `tacctl.yaml` as `breakglass_scope.<scope>.users`, a list
    of `name:role`, written only when set, moved by `scope rename` and
    removed with the scope. **tacctl never stores a password or a hash for
    them.** A name must be a device-safe user name (a letter, then up to 31
    letters, digits, `_` and `-`), is refused when it is a tacctl user of the
    scope (the device's local account would shadow the server's), when it is
    `root`, `tacquito` or the Junos account `remote` (item 80), or when it
    collides with a template-user or class
    name of the Juniper walkthrough (`RW-CLASS`, `OP-CLASS`, `RO-CLASS`, any
    other group's class, `super-user`, `operator`, `read-only`,
    `unauthorized`), and a scope records at most 16. Each change is logged
    (`auth.info scope breakglass add|remove`). It is superuser-only, as the
    other settings of a scope are: an engineer's `scope breakglass` is
    refused, while the walkthroughs of their own scopes show the accounts
    (item 77). The tier table has no row for it and `permits.psv` pins that.

77. **`config cisco|juniper|wti` render the scope's break-glass accounts,
    with a placeholder where the credential goes.** A new last step of every
    template (`${BREAKGLASS_BLOCK}`: the end of the Cisco configs, Step 7 of
    the Juniper ones, with Commit as Step 8, and Step 10 of
    the WTI walkthroughs, for TACACS+ and RADIUS) holds one line per account. Cisco: `username <name> privilege <15|7|1>
    secret 9 <TYPE9-HASH>` (the type 9 hash itself, as `show
    running-config` prints it; `--legacy`, IOS 12.x, has no type 9 and gets
    `secret 5 <HASH>`; item 79), next to the `aaa authentication login`
    line that follows the scope's `aaa-order`. Junos: `set system
    login user <name> class <class> authentication encrypted-password
    '<HASH>'`, the class being the local class of the built-in `superuser`,
    `operator` or `readonly` group for the roles `admin`, `operator` and
    `readonly`, never a template user. WTI: a local account of the matching
    access level (`admin` is Administrator, or the level the group's
    `wti-level` sets; item 82) in a menu step. The lines are
    commented out, so a paste cannot create an account with the placeholder
    as its password, and the output ends with an `Unfilled break-glass
    credentials` line naming every recorded account (tacctl cannot see
    whether you put in a credential, so the line stays while the account is
    recorded). A scope without break-glass users gets the existing advice and
    a notice with the command that records one. An operator's own copy of a
    template does not get the step (`tacctl upgrade` leaves the new template
    beside it as `<name>.template.new`); the `Unfilled` line is printed
    anyway. Creating, rotating and removing the account on the device stays
    with the operator.

78. **`config validate` warns about a scope with no break-glass user, and
    `scope show` says so.** `config validate` prints one `Break-glass:`
    warning naming the scopes with none (a lockout risk when the server is
    unreachable; the exit status is unchanged) and one for each recorded name that is also a
    tacctl user of the scope, and reports a `breakglass_scope.*` key that was
    hand edited into a shape the setter refuses. `scope show` has a
    `Break-glass:` line with the accounts and roles, or `none`.

79. **The Cisco break-glass line carries the hash, in the form IOS takes.**
    The line had the hash after `algorithm-type scrypt secret`, but that
    keyword takes a plaintext password and hashes it: a pasted `$9$...` hash
    would have become the password, literally. It is now `username <name> privilege <N> secret 9
    <TYPE9-HASH>` (`secret 5 <HASH>` with `--legacy`), and the comment above
    it says the hash is meant, not the password. Output of the walkthroughs,
    the README and the man page change with it.

80. **Break-glass names: `remote` is reserved and case does not count.**
    `remote` is the Junos template account every remote user without a
    local-user-name is mapped to; a local `remote` of the `admin` role would
    have put them all in the superuser class, so `scope breakglass add`
    refuses it (as `root`). Duplicate, member and reserved-name checks, and
    `remove <name>`, compare without regard to case, as the template names
    always did; `config validate` reports two entries that differ only in
    case.

81. **`user add`, `user scope add|replace` and `user rename` refuse a name
    that is a break-glass account.** The check ran only from the break-glass
    side. A tacctl user named like a break-glass account of a scope they are
    in (or would be in) gets the local account's class on Junos, and on
    Cisco with `aaa-order local-first`. The verbs now refuse it, naming
    `tacctl scope breakglass <scope> remove <name>` as the way out.

82. **The WTI break-glass level follows the group's `wti-level`.** The
    account line used the group's priv-lvl band and ignored a `wti-level`
    set on the group, so it could disagree with the mapping table of the same
    walkthrough. The placeholder in the WTI step is `<PASSWORD>` (it is
    typed on the unit, not a hash). The comments above the Cisco and Junos
    accounts now say what the scope's `aaa-order` does: the local accounts
    are tried first with `local-first`, otherwise only when no server
    answers.

83. **Smaller changes in `scope breakglass`.** `scope breakglass <scope>
    remove <name>` completes the recorded names. `config validate` prints
    one warning line naming the scopes without a break-glass user instead of
    one per scope. `add` no longer says the account is unfilled "until you
    put in your own", which tacctl cannot tell.

84. **New: `tacctl rollback <version> [--apply] [--yes] [--hosts]` prepares
    the state for the release before this one.** Run on 0.2.3, before the
    older release is installed (item 88 described the manual steps; this
    does them). It is a dry run unless `--apply` is given: the dry run lists
    every step and every warning and changes nothing (not a byte, not a
    snapshot). The one target is `0.2.2`; `0.2.1` and older are refused
    with the reason (0.2.2's own changes, the per-group `junos`, `wti_level`
    and `tier` settings, the SNMP name hint and the host facts, are not
    covered: restore a snapshot with `tacctl backup restore`), and so is
    `0.2.3`, a newer release or any other word. Superuser only: the tier
    table has no row for it (`permits.psv` pins that), so an engineer, an
    operator and a readonly user are refused by the gate. The command ends
    with the exact next step, `tacctl upgrade --branch 0.2.2` (which
    switches the clone to the tag, builds it and re-executes it), and the
    fallback that needs no tool: `tacctl backup restore <id>` of the entry
    you noted in `tacctl backup list` before the upgrade to 0.2.3 (snapshots
    are taken before every change; the upgrade adds one only when it records
    a tier). A new
    `rollback` entry in the usage, the completion (`--apply`, `--yes`,
    `--hosts`, and `0.2.2`), the README (Rolling back, under Upgrading) and
    the manual page.

85. **What `rollback --apply` converts, in this order, after a snapshot.**
    `tacctl.yaml`: removes `linux.engineer_sudo`, `snmp_scope.*` and
    `breakglass_scope.*`, the key families 0.2.3 added, and any other key a
    0.2.2 binary does not know (0.2.2's `config validate` reports them and
    its `backup restore` refuses a snapshot that has one; every
    `tier.<group>` setting stays, 0.2.2 has the key and the value
    `engineer`). The families are one table, `conf.Known022` and
    `conf.Added023`, and a test fails when `schema.go` gains a key family
    that is in neither (and, where the 0.2.2 tag is in the repository, when
    `Known022` is not that tag's schema). `console.yaml`: removes
    `tiers.engineer` and `settings.space_completion`, which 0.2.2's parser
    rejects, and writes the file the way 0.2.2 reads it; every other setting
    stays. `devices.yaml`: removes the `location` of every device (0.2.2's
    parser answers `unknown key 'location'` and the registry cannot be
    read). Each file is written once, atomically; a file this release
    cannot read stops the rollback before anything is changed. It moves the
    `snmp/` directory (the scopes' credential files, which 0.2.2 never looks
    at; the snapshot holds them too) aside, and removes the marker
    `/var/lib/tacctl/tier-pinned`, so that a later upgrade to 0.2.3 records
    the tiers again. It leaves, and lists, the host records (the
    `provisioner` entry is ignored by 0.2.2's JSON
    decoder) and the engineer sshd drop-in `00-tacctl-engineer.conf` (a
    `Match Group tac-engineer` block that only closes forwarding; 0.2.2
    neither knows nor removes it, and removing it means an sshd reload in
    the middle of a rollback).
    `store.yaml` is not touched (0.2.3 did not change its format; a test
    compares the bytes). It then re-renders the enabled backends through
    `config render`: nothing it removed reaches `tacquito.yaml`, so this is a
    check, and the file stays as 0.2.3 renders it (the shipped command rules
    of item 50, every regex wrapped as `^(?:regex)$`), which tacquito reads;
    0.2.2's `config validate` says `Rendered config ... is out of date`
    until the upgrade (or its `config render`) renders 0.2.2's form. A
    second `--apply` changes nothing and takes no snapshot.

86. **Warnings that need a human, and `--yes`.** The dry run lists them and
    `--apply` refuses, changing nothing, while one applies and `--yes` is
    missing. *Engineers become superusers under 0.2.2*: 0.2.2 takes a user's
    tier from the priv-lvl of the group alone, so a group at priv-lvl 15
    (an engineer group, or one given a lower tier, or one whose setting was
    lost) makes its users superusers; the users are named, for this server
    (the scope of its `--local` entry: superusers of tacctl there, and
    members of `tac-superuser`) and for each other host (they join
    `tac-superuser` at the next 0.2.2 sync, `--hosts` or not). *Groups
    change tier*: every group whose `tier.<group>` differs from its priv-lvl
    band, with its tier now and under 0.2.2. *Settings 0.2.2 cannot use are
    dropped*: the engineer sudo list, the per-scope SNMP settings (the
    credential files are moved aside, mode 0600, and named; the snapshot
    holds them), the
    break-glass users (no longer rendered; they exist only in the snapshot),
    the device locations. An install without a store has no snapshot to
    take, which is a warning too. A note (no `--yes`) lists the command
    rules with a top-level `|` in a regex, which match differently again
    when 0.2.2 renders them unwrapped (item 48). A model that cannot be
    read is a warning of its own.

87. **`rollback --hosts` takes the engineers' sudo off the enrolled Linux
    hosts: the client script's `TAC_REVOKE_ENGINEER=1`.** 0.2.2's sync never
    removes the `%tac-engineer` line from a host's sudoers drop-in, nor
    the engineers from `tac-engineer`, and gives an engineer at priv-lvl 15
    `tac-superuser`. After the files are converted, `--hosts` syncs every
    enrolled host but this server's own entry (listed as not synced) through
    `host sync` (the scope rules, the prompt for removed users' homes, the
    host's record) with a new header field, `TAC_REVOKE_ENGINEER=1`, added
    only for this run (the protocol stays 6; an ordinary sync has no such
    line). The script then writes no `%tac-engineer` line in the sudoers
    drop-in and takes the accounts of the engineer tier out of
    `tac-superuser` and `tac-engineer` (`'<user>': engineer sudo revoked
    (removed from tac-engineer).`), so the engineers have no sudo on the
    host until the next 0.2.2 sync, which puts an engineer at priv-lvl 15 in
    `tac-superuser` again (item 86): take engineer groups out of those scopes
    or lower their priv-lvl first. Every other account, and the groups
    themselves, are left alone.
    The tacctl server's own script ignores the field (engineers there have
    tacctl's sudo rows only, which the older release replaces). A host that
    fails is named, the others are still synced and the exit status is 1;
    run the same command again once the cause is fixed.

88. **Rolling back to 0.2.2 by hand.** `tacctl rollback 0.2.2 --apply`
    (item 84) does what follows. A `tacctl.yaml` that carries `snmp_scope.*`
    is reported as `unknown config key` by 0.2.2 and makes its `backup
    restore` refuse a snapshot, and a `devices.yaml` with `location:` is
    refused by its parser (`unknown key 'location'`). Without the tool,
    clear them before going back: `tacctl scope snmp <scope> clear` for every scope (it
    removes the settings, the ranges, the contact and the credentials
    file), and `tacctl device location <name> clear` for every device that
    has one (`tacctl device export` shows them); `tacctl scope breakglass
    <scope> remove <name>` for every recorded break-glass name; `tacctl
    config linux engineer-sudo all`, which unsets `linux.engineer_sudo`; and
    remove `tiers.engineer` and `settings.space_completion` from
    `console.yaml` by hand (`console tiers engineer disable` is refused: the
    engineer tier is always on). The directory
    `/etc/tacctl/snmp/` is ignored by 0.2.2 and may stay.

89. **The manual page is checked against the code.** `man/tacctl.1` is still
    written by hand and still shows everything, whatever the caller's tier,
    but `make lint` now runs the Man tests of `internal/cli` and `groff -k -ww`
    on it (`make lint-man`), so no change passes with a stale page. The tests
    fail naming the missing item and the part of the page to edit: every
    command of the tree has an entry and none that is gone is named (also the
    removed `group privilege clear` and `group commands clear`); every flag of
    every command, in every spelling, is in its command's entry; every key of
    `tacctl.yaml` and `console.yaml` is under CONFIGURATION KEYS with its type
    and default; every path of `internal/paths` is under FILES (or in a short
    list of directories whose files are listed, each with the reason); every
    environment variable the code reads is under ENVIRONMENT (the variables
    that move paths or set the clock for the test suite are listed with the
    reason in `manEnvExempt`); every exit status the tests pin is under EXIT
    STATUS; every row of the tier table is under TIERS in the tier it is open
    to. Whatever can be derived from the code is generated, so it cannot
    drift: `make man` rewrites the blocks between `.\" BEGIN GENERATED:
    <name>` and `.\" END GENERATED: <name>` (the TIERS table, the two key
    lists, and for each command its tier line and flag list, with the flags
    described as the usage describes them), and a test compares them byte for
    byte. The prose around them stays hand-written. See `tests/README.md`.

90. **Four new sections of the manual page, and a tier line in every entry.**
    TIERS says who is held to a tier and how it is decided, and lists, from
    the same table the gate and the sudoers drop-in use, the verbs each tier is
    the lowest for, with the notes for the verbs the code splits further
    (`scope staging`, `scope secret`, `scope snmp`, `host show`, `device
    import -`). CONFIGURATION KEYS lists every key of `tacctl.yaml` (the
    families `privileges.<group>`, `snmp_scope.<scope>.*`,
    `breakglass_scope.<scope>.users`, `tier.<group>` and the rest included)
    and every setting of `console.yaml`, each with its type, default, what it
    is for and the verb that sets it. EXIT STATUS documents 0, 1, 2, 3, 126,
    127 and 130. ENVIRONMENT documents the variables tacctl reads
    (`SUDO_USER`, `SUDO_UID`, `SUDO_GID`, `HOME`, `USER`, `LOGNAME`,
    `SSH_CLIENT`, `SSH_TTY`, `SSH_CONNECTION`, `SSH_AUTH_SOCK`, `DISPLAY`,
    `TACCTL_CONSOLE`, `TACQUITO_SRC`). Every command's entry ends with a
    `Requires: <tier>` line and, when the command has flags, an `Options:`
    list of them.

91. **Gaps the new tests found, filled.** Flags that no entry named:
    `backend enable|disable --yes`, `config juniper|wti --staging`,
    `config linux script|remove-script -o`, `device hostkey|import|remove
    --yes`, `device ssh -X -Y -g -L -R -D`, `host enroll --staging`,
    `log tail|search|failures|accounting|clear --backend` and `log clear
    --yes`. Paths FILES did not list: `/etc/tacctl/hosts/` (the per-host
    records), `/usr/local/go/`, `/etc/login.defs`, `/etc/ssh/ssh_host_*_key.pub`,
    the archives `uninstall` leaves in `/root/` and the FreeRADIUS package's
    daemon, module directory, system dictionary and pid file.
92. **The completion helper no longer names what a verb of the caller's tier
    would not list.** `_completion-names breakglass-users <scope>` answered any
    tier with the break-glass account names of any scope; it now answers
    nothing to a caller below the superuser (the verb it completes, `scope
    breakglass`, is the superuser's). `_completion-names backups` answers
    nothing to the readonly tier, whose verbs do not list backups (`backup
    list` is an operator row). The other kinds (users, groups, scopes,
    backends, listeners, hosts, devices) are what `user list`, `group list`,
    `scope list`, `backend list|status`, `ssh` and `device list` already show
    that tier.
93. **A setting left behind by a group is not taken over by a new group of the
    same name.** `tier.<group>`, `wti_level.<group>` and `junos.<group>` stay
    in `tacctl.yaml` when a store import, a restore or a hand edit drops the
    group, and `group add` used to let a leftover `tier: superuser` raise a
    new group at priv-lvl 5 above its band. `group add` now clears those three
    settings of the name (it says which) unless `--tier` or `--wti-level` sets
    them again; `commands` and `privileges` overrides are not touched.
    `config validate` warns, never errors, of a tier, WTI level or Junos
    setting for a group that does not exist, and so do `store import` and
    `backup restore --legacy`, which replace the store and keep `tacctl.yaml`.
94. **The upgrade says when accounts on the tacctl server still hold root.**
    On an install where 0.2.2's `group preset roles` wrote `tier.engineer:
    engineer`, the group is engineer-tier from the upgrade while its accounts
    on this server stay in `tac-superuser` until a sync. When this server is
    enrolled, the last lines of `tacctl upgrade` now name the members of
    `tac-superuser` that are tacctl users below the superuser tier, in red,
    with `tacctl host sync <server>`. The upgrade does not run the sync itself
    (it prompts and rewrites accounts), as `console check` does not.
95. **`rollback --apply` removes the tier-pin marker and moves the SNMP
    credentials aside.** The marker `/var/lib/tacctl/tier-pinned` left in
    place made the upgrade to 0.2.3 that follows 0.2.2 skip the pin, so a
    group at priv-lvl 15 made or raised under 0.2.2 stayed at the operator
    tier; it is removed (the dry run lists it: "remove the tier-pin marker so
    the next upgrade pins again"). `snmp/` is moved to
    `snmp.rolled-back-<timestamp>/` beside it (mode 0600 kept), not left live
    for a new scope of the same name to pick up. The rollback's next steps no
    longer say the upgrade took a snapshot: they say to note the newest entry
    of `tacctl backup list` before upgrading.
96. **Snapshots hold the SNMP credentials.** `snmp.yaml` and the per-scope
    files of `snmp/` (0600, the directory 0700) are part of a snapshot, and
    `backup restore` brings them back (a snapshot with a credentials
    directory makes the live one match it; one without leaves the live files
    alone). A scope removed with its credentials can be recovered.
97. **`scope add` and `scope rename` do not take over a credentials file.** A
    new scope, or a scope renamed to the name, whose SNMP credentials file
    already exists (kept by a rollback, restored by hand) is refused with the
    file's path; `snmpcred.RenameScope` no longer overwrites it.
98. **The Junos walkthroughs number break-glass before the commit.** Step 7 is
    the break-glass users and Step 8 the commit, in both Junos templates (it
    was Step 7 Commit, then a second Step 6 after the `commit`); the step no
    longer says "commit again". The WTI break-glass step (Step 10) ends with
    "Save as in Step 7."
99. **SNMP credentials are checked against device syntax.** A community, v3
     user or passphrase with a blank, `?`, `"` or a control or non-ASCII
     character, or longer than 32 (community, user) or 64 (passphrase)
     characters, is refused when it is set. A value already stored that a CLI
     would misread is rendered as a commented NOT SET line with the command
     that sets it again. `device description` and `--description` refuse `?`
     the way the location does (a description is pasted into `set snmp
     description`); one stored with a `?` is rendered commented.
100. **The Junos management filter restricts udp port 161.** When a
     management ACL is rendered and SNMP is configured, the filter gets a
     `permit-snmp` term (the server's /32, then the scope's SNMP client
     ranges) and a `deny-snmp` term, for udp port 161 only, ahead of the
     `default-accept`. The Step 5 text promised a source restriction under
     SNMPv3 that the client list does not give; the filter is it, once applied
     to lo0, and the text says so (and says v3 is unrestricted when no filter
     is rendered).
101. **The server's own address is the first permit of the Cisco access list
     and of the Junos filter.** `--source` (else the detected address) heads
     the VTY ACL and the management filter as a /32 whenever the block is
     rendered, once, so `access-class` cannot cut off tacctl's own ssh; the
     note under "Two server addresses" is now true for the three vendors.
102. **`show running-config view full` is denied by the shipped readonly and
     operator rules.** A `show` deny with `^(running-config view full)( .*)?$`
     stands in front of the `show` permit (it was only the role preset's).
     The three operator `clear` privilege lines (`ip arp`, `arp-cache`, `mac
     address-table dynamic`) are documented as the one exception to "the
     `local` fallback gives no more than the server": the device lowers the
     verb with any arguments, the server permits the single-entry forms only;
     a test names the three. The engineer preset's note says what tacquito
     cannot do: tell exec from configuration mode, so `archive`, `switch`,
     `redundancy`, `hw-module`, `iox`, `app-hosting`, `scripting`, `software`
     and a bare `configure` are refused there too.
103. **A typed space after `-` or `--` is a space.** At the shell's prompt `device
     import -` followed by a space listed the flags, and `log search --` became
     `log search --backend`; a word of dashes only now keeps the blank as
     typed. The setting's usage says space completion assumes bracketed paste.
104. **The legacy importer reads back what 0.2.3 writes.** A command rule with
     an escaped quote, a `\uNNNN` escape or a `]` in its regex was scraped by
     pattern and came back wrong or not at all; the `match:` list is read by
     the YAML loader. `^(?:...)$` is taken off a regex only where what remains
     has its parentheses paired and compiles, so a pre-0.2.3 `^(?:a)|(?:b)$` is
     left alone instead of becoming `a)|(?:b`.
105. **The console policy line logs only a session id.** `session=` in the log
     line of `_console-policy` was the caller-controlled `TACCTL_CONSOLE`
     (passed through `env_keep`); anything that is not a session id is logged
     as `-`.
106. **The rotation scripts do not read a test switch from the environment.**
     The scripts the provisioner runs as root took `TACCTL_ROTATE_TEST=1` from
     the environment of the ssh session, which moved the sudoers and passwd
     paths and skipped the root check. The script now sets `ROTATE_TEST=0` on a
     line of its own; the test suite rewrites that line in its copy.

107. **The role preset's engineer class is `EN-CLASS`.** `tacctl group preset
     roles` creates `engineer` with the Junos class `EN-CLASS`, `tacctl config
     juniper` writes its template user and the engineer permission bits for
     any group that uses it, and `group reset engineer` restores it. The other
     classes are unchanged (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`). A group
     created earlier keeps the class it holds; set it with `tacctl group edit
     <group> juniper-class EN-CLASS` after the devices have the template user.
     The permission bits of the classes are final: the
     viewer's `RO-CLASS` gains `network` (ping and traceroute; `ssh` and
     `telnet` stay denied by its server-sent set) and `OP-CLASS` loses `reset`
     (the operator's set already denied `restart` and `request`). Paste Step 1
     of `tacctl config juniper` again to bring a device up to date. What an
     engineer or operator may do beyond the bits is decided by the server-sent
     deny sets, which need no change on the devices.

108. **`tacctl device show` always names the location, and the walkthroughs do
     not list it as unfilled.** The Location row is `-` when none is set. The
     location belongs to one device, so a walkthrough no longer ends with an
     `Unfilled SNMP values: location (...)` line for it; the commented
     placeholder in the SNMP step still names `tacctl device location <name>
     '<text>'`. The contact, the credentials and the server address are listed
     as before.

109. **`tacctl device config show <name>` prints a registered device's
     walkthrough.** It prints the device's data (name, address, hostname,
     vendor, the scope that covers it and the prefix, description, location),
     then the walkthrough `tacctl config <vendor> --scope <its scope> --name
     <name>` prints, from the same code, with the device's location,
     description and name in the SNMP step. `--protocol tacacs|radius`,
     `--legacy` (Cisco only), `--server` and `--source` are those of `config
     <vendor>`. Only a cisco, juniper or wti device has one: a vendor `other`
     is refused with `tacctl device vendor <name> cisco|juniper|wti`, an
     enrolled Linux host with `tacctl host show <name>`, and a device no
     scope's prefixes cover with `tacctl scope prefixes <scope> add <cidr>`; a
     refusal prints no data block. `tacctl device config` alone prints the
     usage. The row is the engineer's, like `config cisco|juniper|wti`: an
     engineer gets the devices of their own scopes (another scope's device is
     "not found"), an operator is refused, and completion offers the device
     names after `device config show`.
110. **The device's own location is read by SNMP.** `tacctl device add` reads
     the device's `sysLocation.0` next to its `sysName.0` (same credentials,
     timeout and retry) unless `--snmp-location` or `--no-lookup` is given,
     and stores a non-empty answer as the device's location: `Location: <text>
     (read from the device)`. A value the registry does not accept is shown and
     not stored. A device that reports none gets the line `Location not set:
     tacctl device location <name> '<text>'`; at a terminal the add offers to
     enter one instead (blank skips). The add never fails because of it, and a
     device that does not answer says nothing more than the name hint did.
     `tacctl device check` gains a `Location` row (match, differs with both
     values, registry only, device only, or why there is no reading) and
     `syslocation`, `syslocation_match` and `syslocation_error` in `--json`; it
     writes nothing and stays the operator's. `tacctl device location <name>
     --from-device [-y]` reads it now and stores it: an empty answer is
     refused with the reason, and a different registered location is shown
     beside the device's and replaced after a `y` at a terminal, or with `-y`
     (without either it is refused).

## 0.2.2 (2026-10-07)

### What changed

1. **A release install leaves nothing in root's home.** The bootstrap shim
   downloads Go and the release binaries with `wget --no-hsts`, so wget no
   longer writes its HSTS cache (`/root/.wget-hsts`) on the server; found
   by the 0.2.1 release check (`tests/containers/fresh/run.sh --release`).

2. **A device name may be a fully qualified host name of up to 253
   characters.** `tacctl device add sw1.site-a.example <address>` was
   already accepted; the limit was 63 characters for the whole name, and is
   now 253, each dotted part 1 to 63 characters (no empty part, no trailing
   dot): `Invalid device name '<name>'. Use letters, digits, '.', '_' or '-',
   starting with a letter or digit; at most 253 characters, each dotted part
   at most 63.` The `name-mismatch` notice no longer fires when a device
   registered as `sw1.site-a.example` sends `sw1` as its NAS-Identifier (the
   registry name's first label). The `ambiguous-nas-id` notice's remedy says
   that a fully qualified host name tells the devices apart. Enrolled host
   names are unchanged, because a host's name also names its scope
   (`linux-<name>`).

3. **An account whose primary group is `tac-users` is no longer listed in
   it a second time.** 0.2.0 put every account tacctl manages in
   `tac-users` as a supplementary group, and 0.2.1 made `tac-users` the
   primary group but kept the old entry, so `getent group tac-users` still
   listed them. A sync now takes each managed account whose primary group
   is `tac-users` out of the group's member list (`gpasswd -d`) and says so
   once per account; it no longer adds `tac-users` as a supplementary group
   either, except to an account whose primary group could not be changed
   yet. Other accounts in the group are left to the existing cleanup.
   `client-remove.sh` now finds tacctl's accounts by their primary group as
   well when it reports those left without a way to log in.

4. **`group commands remove` no longer drops several rules of a name at
   once, and `group commands add` can place a rule.** When more rules than
   one share the name, `remove` refuses (`[ERROR] Group 'operator' has 2
   rules named 'show'; select one with --match/--action (see 'tacctl group
   commands list operator'), or pass --all.`, exit 1) unless `--match` (the
   rule's regexes, all of them, in order) and `--action` narrow them to one;
   `--all` removes them all, as `remove` did before. A removal names the
   rule it took: `Removed rule #3 'show' (deny, match=[^crypto( .*)?]) from
   group 'operator'.` The name is now compared literally, so `remove
   operator 'sh.w'` warns that there is no such rule. `add --before <name>`
   puts the rule before the first rule of that name (`No rule named 'x' in
   group 'operator'.`, exit 1, when there is none) and `add --first` puts it
   first; without them it goes before the catchall as before. `group
   commands list` gains a `#` column with each rule's position, and the
   `group commands` usage says how tacquito tests a `--match` (anchored at
   both ends, against the arguments joined by spaces).

5. **`config cisco`, `config juniper` and `config wti` say what the server
   now sends and what stays on the device.**
   - **Cisco:** `aaa accounting commands <level>` is printed for every
     privilege level a group uses, not for 1, 7 and 15 only. Once any group
     has command rules, `aaa authorization commands <level>` follows for
     every level in use, with `aaa authorization config-commands` and a
     commented `aaa authorization console` to uncomment for the console
     line. A level where a group has no rules gets its line commented out,
     naming the group and the fix (`tacctl group commands default <group>
     permit`), since the server would deny that group every command. The
     notes say that a group at priv-lvl 15 is kept apart from the
     superusers only by the server's rules, so the `local` fallback lets it
     run everything while the server is unreachable. The shipped
     `cisco.template` and `cisco-legacy.template` take the accounting lines
     from the new `${ACCT_COMMANDS_BLOCK}`; a template copied to
     `/etc/tacctl/templates` before 0.2.2 keeps the 1/7/15 lines it has
     (`tacctl upgrade` writes this release's version beside it as
     `<name>.template.new`). Re-paste the AAA block on Cisco devices.
   - **Junos:** Step 3 no longer turns the `group commands` rules, which
     are Cisco's, into class `allow-commands`/`deny-commands` lines. It is
     a read-only summary of what the server sends per class at login: the
     group's `deny-commands` and `deny-configuration` values with their
     sizes against the 241 and 236 byte limits, or `none`, over TACACS+ and
     over RADIUS (`Juniper-Deny-Commands`, `Juniper-Deny-Configuration`).
     The classes keep their permission bits, and Step 3 lists the `delete
     system login class <class> allow-commands` lines that remove what an
     earlier walkthrough put there. A group whose class is `ENG-CLASS` gets
     the engineer permission bits and its template user. The verify list
     gains `show cli authorization`, and the group summary shows each set's
     size.
   - **WTI:** the Service Name is the factory `wti` again, which per-group
     WTI levels need. A unit set to `shell` by an earlier walkthrough still
     logs every group in at its priv-lvl band but ignores the WTI levels set
     on groups until its Service Name is set back to `wti`. The summary
     shows a group's level set with `wti-level` next to its band
     (`priv-lvl 15 → SuperUser (wti-level override; auto: Administrator)`),
     over TACACS+ and RADIUS, and the hint for an empty SuperUser band
     points at `tacctl group edit <group> wti-level superuser`.
   - The `group commands` usage says that Junos devices do not use these
     rules.

6. **`tacctl group privilege` entries may name a mode.** An entry may start
   with `exec:` (the default when there is none), `exec all:`, `configure:`
   or `configure all:` (`tacctl group privilege add operator 'configure:
   router bgp','exec all: show ip'`); `config cisco` renders it as
   `privilege <mode> [all] level <N> <command>`. `group privilege list`
   shows each mapping's mode in a column, and an unknown mode is refused
   (`Unknown privilege mode 'config' in 'config: router bgp'.`). Entries
   stay in `privileges.<group>` of `tacctl.yaml`. A 0.2.1 binary reports an
   entry with a mode as invalid in `config validate` and prints it after
   `privilege exec level <N>` as it is, so remove such entries before
   rolling back.

7. **`tacctl host show <name> [--all] [--json] [--check]` shows one
   enrolled host in full.** Its connection, its scope and the scope that
   answers its address today (with the drift warning of `host list` and a
   pending staging /32), its address history, pinned keys, sightings,
   notices, the accounts the next sync makes there, and two new records:
   the last enroll or sync (when, by whom, the result or why it failed, the
   client script protocol, the accounts created, updated and removed) and
   the host's facts read over that run's session (OS, sshd version, PAM
   module and version, `useradd`'s UID range). They are kept in
   `/etc/tacctl/hosts/<name>.json`, written by every `host enroll` and
   `host sync` (a failed sync too) and removed by `host unenroll`, and are
   only ever shown; a host not synced since this release shows `not
   recorded (before 0.2.2)`. `--check` logs in read-only and compares the
   host with what tacctl would make it (groups and GIDs, each account's
   UID, primary group and home mode, the PAM files, the client script
   protocol, the host keys against the pins), one line per difference with
   the command that fixes it, exit 1 when there is one. For it the client
   script now records on the host the protocol it ran and the checksums of
   the PAM files it writes (`/var/lib/tacctl-client/protocol` and
   `pam.sha256`; the removal script deletes them). Same tier as `host list`.

8. **`tacctl device add` says what the device calls itself.** With SNMP set
   up, it reads the device's `sysName.0` next to the host-key scan and prints
   `The device calls itself '<sysName>' (SNMP sysName).`; when that is not the
   name given, its `--hostname`, or the first label of either, a warning
   names the fixes (`add --hostname <sysName>, or register it as <name>`) and
   the add goes ahead. A device that does not answer within the timeout (2 s
   by default, one retry), an empty sysName, or no SNMP set up is one info
   line (`No SNMP answer from <address>; no name hint.`), and a NAS-Identifier
   a scan recorded for the address is shown in its place, labelled as such;
   `--no-lookup` skips it. `tacctl device add <address>` with no name offers
   the sysName, lowercased, and takes it after a `y` at a terminal; without a
   terminal or an answer, or for a generic sysName such as a WTI unit's `WTI`,
   it is refused with the usage line. `device check` gains an `SNMP name` row
   (`match` or `differs`) and a `--json` option with a `sysname` field.
   SNMP is v2c or v3 at authPriv (SHA or SHA-256, AES-128), spoken by tacctl
   itself: `tacctl config snmp community|v3-user <user>` asks for the secrets
   without echo (or reads them with `--stdin`) and keeps them in
   `/etc/tacctl/snmp.yaml` (0600, never printed); `config snmp show`, `port`,
   `timeout`, `clear` and `test <address>` complete it, with `snmp.version`,
   `snmp.port`, `snmp.timeout`, `snmp.v3.auth` and `snmp.v3.priv` in
   `tacctl.yaml`. `config snmp` is for administrators only. Nothing of the
   hint is stored.

9. **Each group carries its own device settings, sent by the server at
   login.** `tacctl group junos <group> deny-commands|deny-configuration
   list|add|remove|clear` keeps a group's Junos deny patterns; the server
   sends them, joined into one value, with the group's login class over
   TACACS+ (`junos-exec`) and RADIUS (`Juniper-Deny-Commands`,
   `Juniper-Deny-Configuration`, only where `Juniper-Local-User-Name` is
   sent). A set may not exceed 241 bytes (deny-commands) or 236
   (deny-configuration), the TACACS+ argument limit: `add` refuses a
   pattern that would make it longer, and the render refuses a hand-edited
   one. `tacctl group edit <group> wti-level viewonly|user|superuser|
   administrator|auto` gives a group its own WTI access level instead of
   its priv-lvl band, sent as a `wti` service over TACACS+ (WTI units need
   their factory Service Name `wti`) and as `WTI-Super` over RADIUS.
   `group add` takes `--wti-level`; `group show <group>` prints every
   setting of a group and where it comes from, and is open to the
   read-only tier; `group remove` drops the group's settings. `tacctl
   group preset roles [--dry-run] [--force] [--mgmt-filter <name>]` writes
   starting values for viewer (`readonly`), operator, engineer (created at
   priv-lvl 15 with class `ENG-CLASS` when absent) and superuser: their WTI
   levels, the Junos deny sets of the first three and engineer's Cisco
   command rules; a value already there and different is kept unless
   `--force`, and no user is moved. The settings live in `tacctl.yaml`
   (`junos.<group>`, `wti_level.<group>`). A model without them renders
   `tacquito.yaml` as 0.2.1 did; the RADIUS configuration gains the
   post-auth and reject lines for the new attributes on every install.
   Until the engineer tier (0.2.3), a group's tacctl tier still comes from
   its priv-lvl, so an engineer group at 15 is a superuser on the tacctl
   server: keep engineers out of the server's own scope.

## 0.2.1 (2026-10-07)

### What changed

1. **`tacctl config linux uid` and `config linux uid <user>` only read.** The
   listing and the lookup leave `/etc/tacctl/linux-uids` as it is (a missing
   file stays missing); only `config linux uid <user> <uid>` writes it.
2. **`help`, `-h` and `--help` are open to the read-only and operator tiers.**
   A tier user gets the usage (exit 1, as for everyone) instead of a denial;
   the tiers sudoers rules grant `tacctl help`, `tacctl -h` and
   `tacctl --help`. A word after them is still denied.
3. **`install`, `upgrade` and `uninstall` refuse an argument they do not
   know**, and a `--branch` with no value, before doing anything:
   `Unknown argument: '<x>'` and the usage line (`Usage: tacctl install
   [--branch <name>] [-y|--yes]`, `Usage: tacctl upgrade [--branch <name>]`,
   `Usage: tacctl uninstall [-y|--yes]`), exit 1. `upgrade` has no `-y`
   (it does not ask).
4. **`tacctl upgrade` refreshes the tiers sudoers rules** when
   `/etc/sudoers.d/tacctl-tiers` is installed and differs from this
   release's rules: the file is rewritten after `visudo -cf` accepts the new
   rules (`  Updated: tiers sudoers`, else `  Unchanged: tiers sudoers`).
   The file is never created by an upgrade; when `visudo` refuses the new
   rules the old file stays, a warning names it, and the upgrade goes on.
5. **The `tacctl config` usage lists `mgmt-acl cisco-name [name]` and
   `mgmt-acl juniper-name [name]`.**
6. **The top-level usage lists `device`, `ssh`, `shell` and `completion`.**
   `tacctl` with no command (and `tacctl help`) now shows the verbs a user
   types every day next to `host` and `hash`: `device <subcommand>`, `ssh
   <name|address> [-p <port>]`, `shell [--idle <min>] [-c <line>]` and
   `completion bash|zsh|fish`. They were reachable only from the README and
   the manual page.
7. **`group commands add … --match` refuses a regex with a comma**: `A comma
   cannot be used in --match (the rule line form splits on it); use \x2c`,
   exit 1. A comma used to be split into two matches the next time the rules
   were written.
8. **`user verify` refuses a stored hash with a bcrypt cost above 16**, before
   asking for the password: `bcrypt cost 31 exceeds the verify limit (16);
   tacquito still authenticates it`, exit 1. Such a hash (tacctl writes 10 to
   14) made the check run for hours or days.
9. **`config linux script` and `host enroll` report what stopped them.**
   `config linux script -o <file>` that cannot write the file prints
   `[ERROR] Cannot write <file>: <reason>` and exits 1 (it said `Wrote …` and
   exited 0); without `--server`, a failing `ip route` lookup prints `[ERROR]
   Could not determine this server's address (ip route failed); pass --server
   <address>`, exit 1. `host enroll <host>` prints `[ERROR] Cannot resolve
   '<host>'` for a name that does not resolve and `[ERROR] Could not determine
   this server's address for <host> (ip route failed); pass --server
   <address>` when the route lookup fails, exit 1; both used to end silently
   with the tool's status.
10. **The store migration's stop message no longer names `timeout`**: `the
   daemon load-smoke cannot run (<tacquito binary> is missing), so the
   rendered config cannot be proven to load`.
11. **`tacctl install` over an existing store names a backend whose
    configuration step failed**: `[WARN] <backend>: configuration step failed
    (see above); run 'tacctl upgrade' after the install`, and the install
    goes on.
12. **The upgrade summary keeps the TACACS+ unit note**: `Units: NOT updated —
    the previous unit files are in place (see 'Unit update stopped' above)`
    when the unit update stopped.
13. **`tacctl install --branch <bash release>` stops before building** with
    `[ERROR] '<branch>' is a release of the bash era; install it with its own
    installer: sudo /opt/tacctl/bin/tacctl.sh install`, exit 1, instead of a
    build failure.
14. **The sudoers drop-ins keep the agent socket, and the tiers rules gain
    rows for `ssh` and `device`.** Both files (`config sudoers install` and
    `config sudoers tiers install`) carry `Defaults!/usr/local/bin/tacctl
    env_keep += "SSH_AUTH_SOCK"`, so a `SSH_AUTH_SOCK=… tacctl host …` line
    keeps the agent socket through sudo; the grants stay plain `NOPASSWD:`, so
    a caller cannot hand tacctl another `SUDO_USER`, and tacctl also refuses
    a `SUDO_USER` that is not the account of `SUDO_UID` (`getent passwd
    <uid>`): `SUDO_USER '<name>' is not the account of SUDO_UID <uid>, so
    tacctl access is denied.`, exit 1, logged as `tier DENY user=<name>
    uid=<uid> reason=sudo-user-mismatch`. The read-only tier gets `ssh
    <name>`, `device ssh <name>`, `device list`, `device show`, `device
    notices` and `device ssh-config`; the operator tier also `device check`,
    `scan`, `discover` and `export`. `tacctl upgrade` rewrites an installed tiers file that
    differs (item 4), which is how an installed host picks the rows up.
15. **`host sync <TAB>` and `host unenroll <TAB>` complete the enrolled host
    names** (a read-only or operator user is offered the hosts of its own
    scopes).
16. **Release binaries.** A release tag publishes `tacctl-<tag>-linux-amd64`,
    `tacctl-<tag>-linux-arm64`, `SHA256SUMS` and `SHA256SUMS.sig` (an
    `ssh-keygen -Y` signature by the release key, whose public half is
    `release/allowed_signers`). When the clone is exactly at a release tag,
    the bootstrap shim, `tacctl install` and `tacctl upgrade` download the
    binary for the host, verify the signature, the checksum and the commit
    the binary was built from, and install it (`Installing the <tag> release
    binary (linux/<arch>, verified)`); when any of that fails they print
    `Release binary for <tag> not used (<reason>); building from source.` and
    build as before. A branch never downloads. `docs/releasing.md` is the
    release procedure (`make release-assets`, `make release-verify`).
17. **arm64 hosts.** The bootstrap shim installs the Go toolchain for the
    host's architecture (`go<version>.linux-arm64.tar.gz` on aarch64, amd64
    on x86_64); on any other architecture it cannot download Go, and says so
    naming the architecture.
    `bin/tacctl.sh --build <out> --goarch <arch>` cross-builds.
18. **The tacquito authentication lines name the device.** A new source patch
    (`patches/0003-authen-log-conn-remote-addr.patch`, applied by `install`
    and `upgrade`) makes tacquito log `accepting user [<user>] from [<address>]
    using a bcrypt password` and `failed to validate the user [<user>] from
    [<address>] using a bcrypt password`; `tacctl log search <user>` and
    `tacctl log failures` lines gain `from [address]`, the address the device
    connected from (`unknown` when the server has none).
19. **`tacctl completion zsh` and `tacctl completion fish`** print the zsh and
    fish completion scripts (`tacctl completion bash|zsh|fish`; other shells
    are refused with that usage line). They are print-only: `install` and
    `upgrade` still write only the bash script. The words and the live names
    are the same as bash's.
20. **New: `tacctl device`, the device registry.** It names the network devices
    that authenticate against the server (`device list|show|add|remove|rename`,
    the field getter/setters `address|hostname|vendor|port|description`,
    `legacy-ssh`, `stale-days`, `notice`, `notices`, `import`, `export`) in
    `/etc/tacctl/devices.yaml` (0600, `version: 1`, own lock, atomic write). It
    never touches `store.yaml`: scope, state (`configured`/`unconfigured`) and
    vendor tag are looked up per display. A device is found by name or by its
    registered address; enrolled Linux hosts appear read-only as `linux`
    entries in one namespace. Writes are administrator-only and take a
    snapshot first; snapshots, `backup diff` and `backup restore` include the
    file. `list` and `show` (read-only tier and up) and `export` (operator
    tier and up) show a tier user only the entries of its own scopes.
21. **Device and host names are checked for duplicates and generic names.**
    `device add` and `device rename` refuse a name already taken (compared
    without regard to case, across the registry and the enrolled hosts) or an
    address already registered, and a generic name (`switch`, `router`,
    `cisco`, `ubuntu`, `ip-10-0-0-1`, ...) with the command that names the
    device and the same `device add` line with `--allow-generic` (every other
    flag as given); `--allow-generic` registers it anyway and the device
    carries a `generic-name` notice (`device notices`, `device notice <name> ack|unack
    <kind>`). `host enroll` refuses a name that is a registered device or a
    generic name (give another `--name`); a host enrolled under a generic name
    earlier is not refused and carries the notice.
22. **New: `tacctl shell [--no-history] [--idle <min>] [-c <line>]`**, an
    interactive prompt (`tacctl> `) where each line is a tacctl command
    without the `tacctl`. It runs as the invoking user and runs each line as
    `sudo [-n] tacctl <words>` with the terminal attached (`-n` for tier
    users), so sudo's policy and log and the tier gate apply per line. Lines
    are split with quotes and backslash only (no pipes, redirections,
    variables or separators); `help [<command>]`, `history`, `exit`/`quit`
    are the shell's own words. `help` prints the usage of `tacctl` (with a
    Shell section for the keys), `help <command>` the block `tacctl <command>`
    prints. Tab completes commands, flags and live names; a second Tab lists the
    matching words alone, alphabetical, in columns that fit the terminal
    (as bash does), without the shell's own words; `shell` is not offered
    inside the shell, and typing it says so. `?` inserts nothing and shows
    help for the cursor's position (Junos style): where words can come,
    `Possible completions:` with one row per word, alphabetical, with its
    argument column and description (commands as the rows of `help`, a
    family's verbs as its usage rows, flags with their description from the
    usage, device and host names with `<vendor> <address> <scope>` from
    `_completion-names <kind> --desc`, filtered to the caller's scopes as
    the names are); after a command that takes arguments, its usage lines,
    its options not yet on the line, and what comes next (`Next: <username>
    <group>`, `Next: <Enter> to run`). Inside quotes, or after a backslash
    (`\?`), `?` is typed as a character. A list of more than 40 entries (Tab's or `?`'s) asks first, as bash
    does: `Show all 45 devices? [y/N]` (the kind of the entries: devices,
    hosts, users, scopes, commands, options, choices, ...); `y` shows it,
    any other key or Ctrl-C prints how to narrow it (`type more letters to
    narrow it (e.g. core0…<Tab>)`) and gives the line back. Help from `?`
    taller than the terminal is paged inside the shell (no external pager):
    a screenful, then `-- more (Space: page, Enter: line, q: quit) --`;
    `q` or Ctrl-C stops and gives the prompt and the line back. Tab's
    column lists are not paged. Lists and help start below the
    line typed (the line stays, as in bash) and the prompt comes back with
    it; flags are completed only after a `-`. When a tier user's line is
    refused by the tier, the shell prints the tier denial without sudo's
    own `a password is required` line. Ctrl-R
    searches the history,
    Esc-b/Esc-f move by word, Ctrl-C cancels the line or the running command,
    Ctrl-Z is ignored. The history is `~/.local/state/tacctl/history` (0600,
    1000 lines), with secrets redacted (`scope secret lab set …(redacted)`).
    With stdin not a terminal (`tacctl shell < file`) the lines run in order
    and the first non-zero status stops the run and is the exit status.
23. **Host keys are pinned.** `device add` reads the device's ssh host keys
    (`ssh-keyscan -T 5 -p <port> -t ed25519,ecdsa,rsa <address>`, as root),
    pins them in `devices.yaml` (`host_keys:`) and prints each `SHA256:`
    fingerprint with the console command that shows it on the device. A
    device that does not answer is refused (`No ssh host key could be read
    from <address> port <port> (ssh-keyscan); nothing was changed.`) unless
    `--no-host-key` is given, which registers it unpinned with a
    `hostkey-unpinned` notice. `--host-key SHA256:<fp>` registers only when
    the device offers a key with that fingerprint, and pins that key alone.
    `host enroll` and `host sync` pin an enrolled host's keys once, from the
    keys both the host's own `/etc/ssh/ssh_host_*_key.pub` (read over the
    enrolment's authenticated ssh connection) and an `ssh-keyscan` of the
    target hold; a key type the two disagree on pins nothing (both sets
    printed, `host hostkey-mismatch` logged), a type only one has is
    reported, unreadable key files or a host that does not answer pin
    nothing (with a warning; the enrolment succeeds); `--local` is not
    pinned. A later sync compares the key files with the pin: a difference
    is reported and the pin stays.
    `host unenroll` drops the host's pins. An import never changes an
    existing pin.
24. **New: `tacctl device hostkey <name> [show|accept [-y]|set SHA256:<fp>]`**
    (administrators only) shows the pinned fingerprints, or re-pins: `accept`
    re-scans and pins every offered key after confirmation, `set` pins only
    the key with that fingerprint. Both work for devices and enrolled hosts,
    and log `device hostkey accept|set name=<name> keys=<n> by=<user>` to
    syslog. Nothing else changes a pin.
25. **`/var/lib/tacctl/ssh/known_hosts` is generated** (root, 0644, in a
    0755 directory) from the pinned keys on every registry write and after
    `backup restore`: one `<name> <type> <key>` line per key, for ssh's
    `HostKeyAlias` lookup. `/var/lib/tacctl` is 0711 (every user may pass
    through it, only root may list it): `install`, `upgrade`, the first
    write of `known_hosts` and the Linux build cache set it. `uninstall`
    removes the file and its directory.
26. **New: `tacctl ssh <name|address> [-p <port>] [-- <ssh args>]`** (`device
    ssh` is the same) opens an ssh session to a registered device or an
    enrolled host as the invoking user, never root. Only an active tacctl
    user (in the store, not disabled) whose scopes include the entry's may
    connect, at every tier, superusers included; a local account that is not
    a tacctl user (`'<user>' is not a tacctl user; …`), a caller outside the
    scope (`'<user>' has no access to scope '<scope>' (device <name>)`) and
    an entry in no configured scope are refused, each logged as `ssh DENY
    user= device= scope= reason=` (auth.warning). A disabled user has no
    tier, so the tier gate refuses it first (`'<user>' has no active tacctl
    user, so tacctl access is denied.`, logged as `tier DENY user=<user>
    tier=none cmd=ssh <name>`); a disabled superuser, whom no tier gate
    stops, is refused by `tacctl ssh` itself (`ssh DENY … reason=disabled`). The
    session is logged (`ssh user=<user> device=<name> addr=<address>`,
    auth.info), and ssh runs through `sudo -u <user> -H` with the terminal,
    logging in as the invoking user, by password only: no agent socket, no
    key, no identity, no other login, and no way to name one; an enrolled
    host's enrolment account is never used. Its exit status is tacctl's. Every
    session gets `-o ConnectTimeout=10 -o PubkeyAuthentication=no -o
    PreferredAuthentications=keyboard-interactive,password` (`wti`:
    `PreferredAuthentications=password`); `legacy-ssh` devices the SHA-1 key
    exchanges and `ssh-rsa`; pinned devices `-o
    UserKnownHostsFile=/var/lib/tacctl/ssh/known_hosts -o
    GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o
    HostKeyAlias=<name> -o UpdateHostKeys=no`. An unpinned device prints its
    `hostkey-unpinned` notice first. Run by root itself it refuses (`tacctl
    ssh runs ssh as the user who invoked it; run it from your own account,
    not as root`), without a terminal too (`a terminal is required`); an
    unregistered address is refused with the `device add` command. After an
    ssh exit 255 on a pinned device whose key changed, tacctl prints the
    pinned and offered fingerprints, the vendor's console command and
    `tacctl device hostkey <name> accept|set`. `tacctl ssh <TAB>` completes
    the device names of the caller's scopes.
27. **New: `tacctl device ssh-config`** prints an `ssh_config` fragment (one
    `Host` block per device and enrolled host the caller may see, with
    `PubkeyAuthentication no`, the password methods, the legacy algorithms
    and, for a pinned entry, the same `UserKnownHostsFile`,
    `GlobalKnownHostsFile none`, `StrictHostKeyChecking yes`, `HostKeyAlias`
    and `UpdateHostKeys no` lines; no `User` line, so ssh logs in with the
    local username) and on stderr how to Include it from `~/.ssh/config`.
    Print-only; open to the read-only and operator tiers, filtered to their
    scopes.
28. **The host provisioning account must not be a tacctl user.** `host
    enroll` refuses a target whose ssh login (the `user@` of the target, else
    the invoking user's name) is a tacctl user: enrolment uses a local
    account that does not authenticate through tacctl. `host sync` warns
    about an existing enrolment that uses one.
29. **New: `tacctl device scan [--full] [--since <dur>] [--backend <id>]`**
    (operator tier and up) reads which devices talked to the server into the
    seen cache `/var/lib/tacctl/devices-seen.json` (0600, derived, not
    snapshotted): the tacquito journal (`journalctl <units> -o json
    --output-fields=MESSAGE`, resuming after its cursor; the patched
    `accepting user`/`failed to validate the user … from [address]` lines,
    `bad secret detected for ip`, `has no secret providers` (no scope covers
    the address), and at log level 30 `prefix secret provider matches
    remote`) and FreeRADIUS's `tacctl-auth.log` with
    its rotations (resuming by inode and offset, following copytruncate and
    gzip). The first scan reads the last `stale-days` days, `--full`
    everything the logs hold, `--since` that stretch. It prints each
    backend's window, re-scans the pinned host keys (never re-pinning), and
    lists the open notices. Records unseen for twice `stale-days` are dropped.
30. **New: `tacctl device discover [--all] [--backend <id>]`** scans, then
    lists the addresses that authenticated without being registered (scope,
    vendor tag, first/last seen, count, last user, outcome, NAS-Identifier)
    with a ready `tacctl device add <name> <address>` line each; `--all`
    adds the addresses only ever refused.
31. **New: `tacctl device check <name>|--all`**: scope, vendor tag, last seen,
    reachability (a 3-second TCP connect to the ssh port) and the offered host
    keys against the pin, then the notices.
32. **`device list` and `device show` print the seen data**: LAST SEEN (`<time>`,
    `rejected <time> (bad secret)`, `never`), BY, VIA, `stale` after
    `stale-days`, and `seen data as of <time> (tacctl device scan to refresh)`;
    `--json` gains a `seen` object. `list --scan` scans first, `list --probe`
    adds a REACH column (operator tier and up).
33. **Scan-time device notices**: `ambiguous-nas-id`, `generic-nas-id`,
    `name-mismatch`, `duplicate-address`, `identity-changed`, and from the
    host-key re-scan `hostkey-changed` (not acknowledgeable; only `device
    hostkey accept|set` clears it), `hostkey-added` and `hostkey-unreachable`.
    They appear in the scan output, `device list|notices|show` and a new
    `Device notices: <n> (tacctl device notices)` section of `tacctl status`
    (the first five; `none` when every notice is acknowledged; no section
    without registered devices or enrolled hosts).
34. **No `login failure` lines after a successful Linux login.** tacquito no
    longer sends a server message with a failed TACACS+ authentication (source
    patch 0004). sshd could not show it during password login and printed one
    `login failure` per wrong password after the next successful login.
35. **Linux UIDs come from 80000-89999 only** (they were given out from
    20000 up, inside local `useradd`'s default range). 80000-89999 is above
    the distributions' `useradd` range (`UID_MAX 60000` on Debian, Ubuntu
    and the RHEL family) and systemd's reserved numbers (60001-60513,
    61184-65519, 65534/65535), inside the range systemd leaves unused
    (65536-524287) and below the usual `/etc/subuid` start (100000). tacctl
    gives out UIDs (and the matching primary GIDs) from that range, after
    the highest one given so far; a removed user's number stays reserved and
    is never reused. Existing numbers are moved once (item 52). Past 89999
    the script is refused: `[ERROR] No UID left for '<user>': every number
    of 80000-89999 has been given out (UIDs are never reused).` and `Give it
    a free number of the range by hand: tacctl config linux uid <user>
    <uid>`, exit 1. `config linux uid <user> <uid>` refuses any other value:
    `UID must be a number from 80000 to 89999: tacctl gives out UIDs (and
    the matching GIDs) in that range only.` (it took 1000 and up). An entry
    of `/etc/tacctl/linux-uids` outside the range is listed as `outside
    80000-89999: not used on hosts`, and its user is left out of the scripts
    with `Skipping '<user>': its UID <uid> is outside 80000-89999, so no host
    gets an account for it.` `--allow-uid-mismatch` takes the highest number
    of the range that is free on the host (it took the host's next free UID,
    outside any range).
36. **The client script manages an account only when it created it and its
    UID is in 80000-89999.** Before any change it reads the account's UID on
    the host. Any other account (one tacctl did not create, or one it created
    whose UID is outside the range) is never created, expired, deleted or
    otherwise changed, with one exception: it is taken out of tacctl's own
    groups (`tac-users`, `tac-readonly`, `tac-operator`, `tac-superuser`,
    `tac-console`) with `gpasswd -d`, and nothing else on it changes (UID,
    home, password, shell, expiry, full name): `'<user>': removed from
    tacctl's groups (tac-users, tac-<tier>); it is a plain local account
    again.` An out-of-range account tacctl created is reported (`'<user>' has
    UID <uid>, outside 80000-89999: tacctl changes nothing on it but its
    membership in tacctl's groups, although it created it.`); one it created
    in 20000-29999 is renumbered first (item 52).
37. **`--adopt` is gone** (`host enroll`, `host sync` and the client script:
    `Unknown option: '--adopt'`). A local account named like a tacctl user
    that tacctl did not create no longer stops the install or sync: that user
    gets no account on that host (`'<user>': this host has a local account of
    that name that tacctl did not create, so '<user>' gets no TACACS+
    account here. The local account is left as it is.`), and the rest goes
    on. Accounts an earlier release adopted are reported once (`Accounts an
    earlier tacctl adopted are no longer tracked: <names>. Only their
    membership in tacctl's groups is removed.`) and, in that same run, taken
    out of tacctl's groups (item 36); they are not tracked after that. The
    summary counts the accounts tacctl manages on the host and names the
    users it refused there: `<host>: synced (4 users; 1 refused: carl).` and
    `Host '<host>' enrolled (4 users; 1 refused: carl).` (with none refused,
    `synced (<n> users).`, and `1 user` for one), read from the script's last line `[INFO]
    Accounts: <n> managed by tacctl here[; refused: <names>].`
38. **Removed users' accounts are deleted.** `host sync`, `host enroll` and
    the client script delete (`userdel`) the accounts tacctl created for
    users no longer in the host's scope or no longer tacctl users, and their
    per-user group when it is now empty: `Deleted account '<user>': no longer
    a TACACS+ user here (its UID <uid> stays reserved on the tacctl server,
    never reused).` (they were expired). Accounts expired that way by an
    earlier release are deleted at the first sync. A disabled user's account
    is still only expired (`'<user>' has no TACACS+ login here now
    (disabled): account expired, files kept.`) and re-activated when the
    user is enabled; so are the accounting sink's. A user still logged in is
    expired and deleted at the next sync (`Could not delete '<user>' (userdel
    failed; still logged in?): …`).
39. **Home directories of removed users: asked, forced or kept.** On a
    terminal, `host sync` and `host enroll` read the host's `getent passwd`
    over the same ssh connection before anything runs there (read-only, no
    sudo), print `<host>: removed users with an account there (deleted by
    this run): <users>` and ask `Delete /home/<user> of removed user
    '<user>'? [y/N] ` for each; `--remove-home` (both verbs, and the client
    script) deletes them without asking; with no terminal and no flag
    nothing is asked. A home that is kept is moved out of reach of a later
    local account with the same UID: to `/home/.tacctl-removed/<user>-<YYYYmmdd-HHMMSS>`
    (`/home/.tacctl-removed` is root's, 0700; the moved tree is made
    root:root with `chown -hR`, never following a link, its top 0700), and
    the host prints `home kept: /home/.tacctl-removed/<user>-<time>`. The
    host deletes or moves a home only when it is a directory directly under
    `/home`, not a symbolic link, owned by the account and no other account's
    home (else `home kept in place: <home> (<reason>)`), and never follows a
    link inside it; a home on another file system than `/home`, or a
    `/home/.tacctl-removed` that is not a real directory, keeps it in place
    with a warning.
40. **The install script's header has a protocol.** After `TAC_USERS` it sets
    `TAC_INACTIVE` (the scope's disabled users and the accounting sink),
    `TAC_REMOVE_HOMES` (names, or `*`), the UID range (item 53) and
    `TAC_PROTOCOL=4`; the script body refuses a header of another protocol
    before changing anything (`This script's header speaks protocol <n> and
    its body protocol 4: they were not written by the same tacctl. …`).
    `TAC_USERS` lines are `name:tier:uid` for every host, and
    `name:tier:uid:shell` for the tacctl server's own accounts (item 55).
41. **Enrolled hosts have a recorded address.** `host enroll` and `host
    sync` record the address the enrolment's ssh connection reached (the
    host's side of sshd's `SSH_CONNECTION`, read over the same connection
    after the script) in `devices.yaml`'s `hosts:` section (`address:`),
    cross-checked with what the target's name resolves to (`<host>: the
    enrolment session reached <a>, but '<name>' resolves to <b>; recorded <a>
    …` when they differ; the resolution is recorded when sshd reports
    nothing); `--local` records `127.0.0.1`, the address its own logins
    reach the server from. The device registry uses it: `device add` and
    `device address` refuse it (`<address> belongs to the enrolled host
    '<name>'.`), `device show <address>` and `tacctl ssh <address>` find the
    host, sightings (TACACS+ `from [address]`, RADIUS clients) are attributed
    to it, and `device discover` no longer lists it as unregistered. A sync
    that finds another address records it, logs `host address-changed name=
    old= new=` (auth.warning), says `<host>: its address changed from <old>
    to <new>; …` and raises the `address-changed` notice (with the scope
    prefix to add when the host's scope does not cover the new address),
    which `device notice <host> ack address-changed` acknowledges.
    `host unenroll` forgets the address with the pins.
42. **`host enroll` and `host sync` warn when the host's local `useradd` can
    give out tacctl's UIDs**: they read `/etc/login.defs` (`UID_MIN`,
    `UID_MAX`; read-only, over the same connection) and, when the range
    overlaps 80000-89999 (the default `UID_MAX 60000` does not; one raised
    to 80000 or more does), print `<host>: local useradd there gives out
    UIDs <min>-<max> (/etc/login.defs UID_MIN/UID_MAX), which overlaps
    tacctl's 80000-89999:` and suggest keeping `UID_MAX` below 80000, once
    per host and run. tacctl never edits the file.
43. **An upgrade that changed nothing says so**: when no file was updated,
    no unit, binary or config changed and no backend has a note, the summary
    head is `Already Up to Date (source unchanged at <commit>)` instead of
    `Scripts Updated (source unchanged at <commit>)`.
44. **`host enroll` and `host sync` on a terminal no longer end each host
    with ssh's `Shared connection to <host> closed.`** (the script run uses
    `-o LogLevel=ERROR`; ssh's errors still show).
45. **New: `tacctl host target <name> [<[user@]host>] [--port <n>]
    [--identity <file>|--no-identity]`** (administrators only). With only a
    name it shows how the enrolled host is reached: target, port, identity,
    server address, recorded address, scope and method. A change is tested
    before anything is written: tacctl logs in to the new target as `host
    enroll` and `host sync` do (the invoking user's ssh, agent, port and
    key), checks that the login is root or may use sudo (sudo that asks for
    a password is refused without a terminal, and warned about with one),
    reads the host's ssh keys over that session and compares them with the
    pinned ones (`The host reached is not '<name>' as pinned: its ssh keys
    differ; nothing was changed.`, with both fingerprint sets), and records
    the address it reached (item 41). A login that is a tacctl user is
    refused as at enrollment, and a host enrolled with `--local` has no
    target (`'<name>' is this server (enrolled with --local); …`). Then the
    registry line is rewritten in place (scope, server and method kept)
    after a snapshot, and `host target name= target= port= by=` is logged
    (auth.info). No script runs on the host. `host target <TAB>` completes
    the enrolled names.
46. **New: `tacctl console show|tiers|user|idle-timeout|agent-forwarding|
    ssh-escape|system-shell`** with `/etc/tacctl/console.yaml` (0600,
    snapshotted, in `backup diff` and `restore`; absent means the defaults:
    the console on for every tier, `system-shell` for superusers only,
    `/bin/bash`, idle timeout 30 minutes, agent forwarding and ssh escape
    off). `show` (operator tier and up) prints the switch per tier, the
    settings, a table of each user of this server's scope with its tier,
    effective shell and why (`user override`, `tier readonly disabled`), and
    the server's pieces: the `tacctl-console` symlink, the `/etc/shells`
    line, sshd's drop-in and what `sshd -T -C user=<user>` reports, with a
    red warning when the drop-in is missing or sshd still allows TCP
    forwarding for a console user. Changes to the tier switches, a user
    override and agent forwarding print `Apply to the accounts: tacctl host
    sync <name>`; the commands change `console.yaml` only. The top-level
    usage lists `console`. New paths:
    `TACCTL_SSHD_DROPIN` (default
    `/etc/ssh/sshd_config.d/tacctl-console.conf`) and `TACCTL_SHELLS_FILE`
    (default `/etc/shells`).
47. **Tiers sudoers:** rows `_console-policy` (every tier: the console
    reads its settings with it), `console show` and `console check`
    (operator); the `Defaults!` line is now `env_keep += "SSH_AUTH_SOCK
    TACCTL_CONSOLE"` in both generated sudoers files (the console's
    session marker). Picked up by `tacctl upgrade` (item 4);
    administrators using the opt-in drop-in re-run `tacctl config sudoers
    install`.
48. **New: the login console `tacctl-console`.** Started under that name
    (a symlink to `tacctl`; as a login shell, `-tacctl-console`) tacctl is
    `tacctl shell` with a `<host>> ` prompt and a banner, runs each line as
    `sudo [-n] TACCTL_CONSOLE=<session> /usr/local/bin/tacctl <words>`,
    starts nothing else, and discards the login environment but `TERM`,
    `LANG`/`LC_*`, `HOME`, `USER`, `LOGNAME` and `SSH_CONNECTION`,
    `SSH_CLIENT`, `SSH_TTY` (`PATH=/usr/local/bin:/usr/bin:/bin`). It asks
    the server for its settings once per session (`_console-policy`).
    `-c '<line>'` (sshd's remote command: `ssh <server> 'user list'`) runs
    one tacctl line; `scp`, `sftp`, `rsync` and every other program are
    refused with `the tacctl console does not run programs; file transfer
    is not available`, exit 126, and any other argument with `the tacctl
    console takes no options`. Standard input that is not a terminal runs
    as a batch. The session ends after the idle timeout at the prompt
    (`tacctl console idle-timeout`, default 30 minutes). Sessions and
    refusals are logged to syslog (tag `tacctl-console`: `console start`,
    `console end … reason= lines= status=`, `console DENY … first=`), each
    line in sudo's log as well. The test knob `TACCTL_TEST_CONSOLE_ENV=1`
    (`-tags testknobs` builds) keeps `TACCTL_*` and `PATH` for the test
    sandbox.
49. **New console word `system-shell`:** starts the user's system shell
    (`/bin/bash`, `console system-shell path`) as themselves, without
    arguments, with the console's environment and `SHELL=<path>`, logged
    with start, end, status and duration (`console system-shell
    start|end`); superusers only by default (`console system-shell tiers
    <csv>|none`); refused for other tiers with the command that enables it
    (`console system-shell DENY`); not available through `-c` or in a
    batch (exit 126); the idle timer does not run while it does; `help`
    and Tab name it only in the console.
50. **`tacctl ssh` inside a console session** runs ssh with `-F /dev/null`
    (no `~/.ssh/config` or `/etc/ssh/ssh_config`), `-o
    PermitLocalCommand=no -o ControlMaster=no -o ClearAllForwardings=yes -o
    ForwardAgent=no`, `-o EscapeChar=none` (`console ssh-escape enable`
    keeps `~.`/`~C`), and the target after `--`, so words after the name's
    `--` are only the remote command (one starting with `-` is refused); it
    refuses a device or host with no pinned host key (`'<name>' has no
    pinned host key, so the console does not connect to it; an
    administrator pins it: tacctl device hostkey <name> accept`, logged
    `reason=unpinned`). Every `tacctl ssh` now also logs `ssh end user=
    device= status= duration=` when the session ends; from a console
    session its log lines end with `console=<session>`.
51. **`tacctl shell`: a superuser's lines run `sudo` without `-n`**, so
    sudo asks for the network password on the terminal when a line needs
    it (once; sudo's cache applies) and superusers' write verbs work from
    the shell and the console; readonly and operator lines (and those of a
    `tac-users` member in no tier group) keep `-n`.
52. **UIDs given out from 20000 up are renumbered once to 80000-89999**, at
    the same offset (20005 becomes 80005). On the server, the first `config
    linux uid`, `config linux script`, `host enroll` or `host sync` rewrites
    every entry of `/etc/tacctl/linux-uids` in 20000-29999 (users and
    removed users alike), keeps the old file as
    `linux-uids.pre-renumber-<UTC time>`, replaces it by a rename, prints
    `Renumbered <n> entries of /etc/tacctl/linux-uids from 20000-29999 to
    80000-89999 (the same offset; the old file is kept as …).` and logs
    `uid-map renumbered <n> entries from=20000-29999 to=80000-89999
    backup=<file>` (auth.info); after that there is nothing left to do and
    nothing is said. A number that is already another name's refuses it,
    nothing changed: `Cannot renumber /etc/tacctl/linux-uids from
    20000-29999 to 80000-89999: '<user>' (<old>) would become <new>, which
    is already assigned to '<other>'. Nothing was changed.` and `Give
    '<other>' another number first: tacctl config linux uid <other> <uid>`
    (exit 1 for the commands that write a script; a warning for `config
    linux uid`, so it can make that change). On a host, the next enroll or
    sync renumbers each account tacctl created there with a UID in
    20000-29999, listed, disabled or removed (a removed user's account is
    then deleted as before): `usermod -u <new>` (which re-owns the home
    directory tree), `groupmod -g <new>` for its own group (named like it,
    GID the old UID, no other member), `usermod -g <new>` when the primary
    GID still is the old one, and the home's files that kept only the old
    group follow it: `'<user>': renumbered <old> -> <new> (home re-owned)`
    (`(home not fully re-owned)`, with the `chown -hR --from=<old> <new>
    <home>` to finish it, when usermod changed the UID but failed on the
    home).
    Files outside the home that keep the old UID or GID are listed, never
    changed (a scan of `/home`, `/tmp`, `/var/tmp`, `/var/spool/cron` and
    `/var/mail`, at most 20 paths): `'<user>': these files still carry its
    old number <old> and were left as they are (chown -h <new>:tac-users <file>
    gives them back):`. The account is left exactly as it is for that run,
    and named as refused in the summary, when the new UID or GID belongs to
    another account or group there (`'<user>': not renumbered from <old> to
    <new>: UID <new> belongs to '<other>' here. …`) or the user has
    processes (`… processes run as UID <old> (still logged in?). The account
    is left as it is until the next sync.`; `pgrep -u`, or `/proc` without
    pgrep). Accounts in 20000-29999 that tacctl did not create are never
    touched. The summaries count them: `<host>: synced (3 users; 1
    renumbered).`, from the script's `[INFO] Accounts: <n> managed by tacctl
    here; <k> renumbered[; refused: <names>].` Kept homes under
    `/home/.tacctl-removed` are root's already and stay as they are.
53. **New: `tacctl config linux uid-range [<min>-<max>]`**, and hosts that
    cannot hold the range are refused. The UID range is `linux.uid_min` and
    `linux.uid_max` in `tacctl.yaml` (default 80000-89999, one range for all
    hosts). `uid-range` with no argument prints `Linux UID range:
    <min>-<max> (default|tacctl.yaml; one range for all hosts)` and the
    range `linux-uids` is numbered for. A new range is refused, nothing
    changed, when it holds fewer than 1000 numbers, starts below 1000, ends
    above 4294967293, or overlaps systemd's reserved numbers (60001-60513,
    61184-65519, 65534-65535, 524288 and up): `Cannot use UID range
    <range>: <reason>.`, exit 1; one that overlaps `useradd`'s default
    1000-60000 is accepted with a warning. A change moves every entry of
    `linux-uids` by the offset between the two starts (the old file kept as
    `linux-uids.pre-renumber-<UTC time>`, `uid-map renumbered <n> entries
    from= to= backup=` logged as in item 52) and logs `uid-range set
    from=<old> to=<new>` (auth.info); it is refused, nothing changed, when
    the new range overlaps one the file was numbered for (`… it overlaps
    <range>, a range the file was numbered for (hosts may still have
    accounts there). Nothing was changed.`), when an entry would land past
    its end, or when a number is another name's. A range grown or shrunk at
    the same start moves nothing. `linux-uids` records its range in a first
    line `# range <min>-<max>` and the earlier ones in `# previous <min>-<max>
    …`; a file without the record is taken as numbered for 20000-29999 when
    it has entries there, else for 80000-89999 when it has entries there.
    A range set by hand in `tacctl.yaml` is applied by the next command
    that reads the file, and one that cannot be used stops those commands:
    `The Linux UID range in tacctl.yaml (<range>) cannot be used: <reason>.`
    The script header carries the range (`TAC_UID_FIRST`, `TAC_UID_LAST`)
    and the earlier ones (`TAC_UID_PREVIOUS`); the script refuses a header
    without a valid range (`The header has no valid UID range …`) and
    moves accounts it created in any earlier range by offset (item 52's
    rules), an account whose new number would fall outside the range being
    left as it is and refused. Before anything runs on a host, `host
    enroll` and `host sync` read its `/proc/self/uid_map` and `gid_map`
    (this server's for `--local`) and refuse a host whose user namespace
    cannot hold the range: `'<host>' cannot hold UIDs <range>: its user
    namespace maps only <ranges> (an unprivileged container). Give it an
    ID map that covers <range>, run it privileged, or choose a range it can
    hold: tacctl config linux uid-range <min>-<max> (one range for all
    hosts).` (`Enrollment of <host> refused; nothing was changed.`; a sync
    leaves that host alone and exits 1). `host target` warns about such a
    host. The test knob `TACCTL_TEST_PROC` (`-tags testknobs` builds)
    stands for `/proc/self`.
54. **List tables: rules as wide as the table; `user list` shows the UID.**
    Every list (`user`, `group`, `scope`, `backend`, `backup`, `host`,
    `device` lists, `device discover`, `console show`'s users,
    `config linux uid` and `builds`, `group commands list`, `scope devices`)
    is one table: the title, a rule as wide as the table, the column header,
    a rule as wide as the table, the rows. Column widths follow the content;
    no line ends in a space. `user list` has a UID column after USERNAME, read
    from `/etc/tacctl/linux-uids` (`-` for a user with none; a listing never
    assigns one), and `user show <user>` has a `UID:` line. A detail view's
    underline is 44 dashes, or the width of its title when that is longer.
55. **The login console is provisioned on the tacctl server.** `host
    enroll --local` and `host sync` of that host give each tacctl user of
    its scope the login shell `console.yaml` decides (`useradd -s`, `usermod
    -s`: `'<user>': login shell is now the tacctl console.` or `… now
    /bin/bash.`) and put console users in `tac-console` (taken out of it
    when they get bash); the summary counts them (`authsrv: synced (3 users;
    2 with the console).`). Before the script runs, when any user gets the
    console, `/etc/shells` gets the line `/usr/local/bin/tacctl-console` and
    sshd gets the drop-in `/etc/ssh/sshd_config.d/tacctl-console.conf`
    (`Match Group tac-console`: `ForceCommand /usr/local/bin/tacctl-console`,
    `DisableForwarding yes` (left out, with `AllowAgentForwarding yes`, under
    `console agent-forwarding enable`), `AllowTcpForwarding no`,
    `AllowStreamLocalForwarding no`, `X11Forwarding no`, `PermitTunnel no`,
    `PermitTTY yes`, `PubkeyAuthentication no`, `ClientAliveInterval 300`,
    `ClientAliveCountMax 2`), each reported `Installed:`, `Updated:` or
    `Unchanged:`. Every change of the drop-in is checked with `sshd -t`;
    when sshd refuses it the previous file comes back (`sshd refused the
    console's drop-in; … was put back as it was:` and sshd's words), else
    sshd is reloaded (`systemctl reload ssh.service`, or `sshd.service`).
    After the script the check of `console check` runs. Without
    `/usr/local/bin/tacctl-console` nobody gets the console (`… is missing,
    so no account gets the login console now`). Every other host, and
    `config linux script`, keep three fields and never touch a shell.
    `host unenroll` of the server gives tacctl's accounts `/bin/bash` back
    (the remove script, for every account it created with the console
    shell; any other account with that shell is named and left) and removes
    the drop-in and the `/etc/shells` line. With `ForceCommand` every login,
    remote command and subsystem of a console user (sftp and
    `internal-sftp` included) reaches the console as `tacctl-console -c
    /usr/local/bin/tacctl-console`; the console takes the client's command
    from `SSH_ORIGINAL_COMMAND` (none: a login) and the `-c` guard decides
    it as before. New: `tacctl console install` (the pieces, then the
    check), `console remove` (refused while an account has the console:
    `These accounts still have the console as their login shell: … Nothing
    was removed.`) and `console check` (operator tier and up: the drop-in
    present and current, `/etc/ssh/sshd_config` including
    `sshd_config.d/*.conf`, and `sshd -T` for a console user; exit 1 with
    the red warning). `console show` and `console check` also report
    `forcecommand` and `pubkeyauthentication` and warn when sshd does not
    force the console or allows key logins. `install` makes the symlink
    `/usr/local/bin/tacctl-console`, `upgrade` refreshes it (`Updated:
    /usr/local/bin/tacctl-console -> /usr/local/bin/tacctl`) and rewrites an
    installed drop-in that differs from the release's (`Updated:|Unchanged:
    sshd drop-in`; never creates one), and `uninstall` first gives every
    account whose shell is the console `/bin/bash` (`Login shell /bin/bash
    restored for: …`), then removes the drop-in, the `/etc/shells` line and
    the symlink. Nothing changes for anyone at the upgrade itself: the
    accounts follow at the next `host sync` of the server.
56. **Usage: one line per option, and `?` describes every flag.** The usage
    blocks that named a command's flags only in its row or in running text
    (`install`, `upgrade`, `uninstall`, `ssh`, `shell`, `version`, `config
    render|restore|listen|cisco|juniper|wti`, `config linux script|remove-script`,
    `scope add|remove|prefixes`, `group commands add|seed`, `group privilege
    seed`, `host sync|unenroll`, `backend enable|disable`, `store show|import`,
    `log`, `backup restore`, and `device`'s verbs) have an indented line per
    option with its description. In `tacctl shell` (and the console), `?`
    after a dash now shows a description for every flag: option lines
    indented deeper than a row were not read, and a line naming two flags
    (`--port <n>, --identity <file>`) described only the first.
57. **`host enroll` checks that the scope answers the host.** tacquito and
    FreeRADIUS pick a scope by the address a request comes from; this
    server's own logins come from 127.0.0.1. `host enroll --local --scope
    <scope>` with a scope that does not cover 127.0.0.1 is refused before
    anything changes: `Scope '<scope>' does not cover 127.0.0.1, the address
    this server's own logins reach TACACS+ and RADIUS from (<scope '<other>'
    answers it (prefix …)|no scope covers it>), so every login of '<host>'
    would be refused.`, with `tacctl scope prefixes <scope> add
    127.0.0.1/32` and the alternative of enrolling without `--scope`, exit
    1. For another host the same finding for the address its name resolves
    to is a warning (`If its requests come from that address, its logins are
    refused.`); `host sync` of this server warns when its scope no longer
    covers 127.0.0.1. The install script passes the server's UID range to
    `useradd` for that call (`-K UID_MIN=<first> -K UID_MAX=<last>`), so a
    host whose `/etc/login.defs` stops at 60000 prints no `useradd warning:
    … outside of the UID_MIN … range` line; `login.defs` is not changed.
58. **`scope aaa-order|exec-timeout|tacacs-group|radius-group <scope>`
    print the scope on a line of its own** (`  Scope 'lab'`, then `  Cisco
    aaa-group-server name: TACACS-GROUP`, then `  Source: …`) instead of
    one line `  Scope 'lab' Cisco aaa-group-server name: …`.
59. **`config wti` says which ports User- and ViewOnly-level logins
    reach.** A WTI unit lets those logins reach only the serial ports (and,
    on a power unit, the plugs and plug groups) turned On under Default User
    Access, and none from the factory: an operator (priv-lvl 7, User) logged
    in and saw no ports. Step 3 of both walkthroughs (TACACS+ and RADIUS) now
    sets Port Access, Plug Access and Plug Group Access with the rest of
    Default User Access, and a new "Port access" section names the groups
    those lists apply to (or says no group needs them). Administrator and
    SuperUser logins reach every port, as before.
60. **Superusers may forward X11 and TCP ports through the login console.**
    A new setting, `tacctl console forwarding tiers [<csv>|none]`
    (`forwarding_tiers` in console.yaml, default `superuser`), names the
    tiers that may:
    - sshd's drop-in gives the console users of those tiers (`Match Group
      tac-console Group tac-<tier>`, before the console's own block)
      `X11Forwarding yes` and `AllowTcpForwarding yes`, so `ssh -X`, `-L`,
      `-R`, `-D` and `-J` through the server work for them, still into the
      console and by password only; everyone else stays closed, and agent,
      stream-local and tunnel forwarding are unchanged. `console check` and
      `console show` expect TCP forwarding for those users only. An
      installed drop-in is refreshed by `upgrade` or the next sync.
    - `tacctl ssh` (and `device ssh`) take `-X`, `-Y`, `-L`, `-R` and `-D`;
      the log line names them (`forward=x11,local,...`). `-X` uses the
      display of an `ssh -X` login to the server: the console hands
      `DISPLAY` on, and both sudoers files keep it for tacctl
      (`env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"`). In a console
      session other tiers are refused (`ssh DENY ... reason=forward`).
    - `_console-policy` reports `forward=yes|no`; `console show` lists the
      forwarding tiers.
61. **A RADIUS Linux host names itself, not the PAM service.**
    pam_radius_auth sends the PAM service's name (`sshd`, `sudo`) as its
    NAS-Identifier unless it is given `client_id=`, so `device scan` saw an
    enrolled host as `sshd`, then `sudo` (`identity-changed`,
    `name-mismatch`). The client script now passes `client_id=<the host's
    fully qualified name>` (`hostname -f`; left out when the name cannot be
    one PAM argument) on the auth and session lines. A RADIUS host still
    sending a service's name gets one `name-mismatch` notice that says to
    enrol it again; a host enrolled with pam_tacplus sends no
    NAS-Identifier, so a name recorded from an earlier RADIUS enrolment no
    longer raises notices for it.
62. **Fixed tacctl groups; `tac-users` is every account's primary group.**
    tacctl's groups now have the same GID on every host, the first numbers
    of the UID range: `tac-users` 80000, `tac-console` 80001,
    `tac-superuser` 80002, `tac-operator` 80003, `tac-readonly` 80004 (they
    follow `config linux uid-range`). A host has only the groups it uses:
    every host `tac-users` (the PAM gate) and `tac-superuser` (sudo); the
    tacctl server itself also `tac-readonly`, `tac-operator` (its tiers
    sudoers) and `tac-console` (sshd's console drop-in). New accounts get
    `tac-users` as primary group instead of a group of their own, and their
    home is made 0700. The next enroll or sync of a host moves what an
    earlier release made: each managed account's primary group becomes
    `tac-users` (`usermod -g`, which re-groups the files in its home) and
    its own group goes when it is empty; the groups move to their fixed
    GIDs (`groupmod -g`; files in the managed homes that carried
    `tac-users`' old number follow it); the tier and console groups of a
    host other than the server go when only tacctl's accounts are in them.
    A fixed GID that another group holds is left to it, with a warning.
    UID checks no longer look at GIDs. The script header gains
    `TAC_LOCAL=1` for the server's own script; `TAC_PROTOCOL` is 5.
63. **`host enroll` uses the host's scope; it no longer makes one.**
    Without `--scope`, enroll created a `linux-<name>` scope for the host's
    address as a `/32`, even when a scope already covered the address, and
    on a re-enroll even when the host was registered in another scope. The
    `/32` answered first, so the host left its scope, and its users' accounts
    there were deleted as removed users. Now, without `--scope`: a
    registered host stays in the scope it is registered in; any other host
    goes into the scope that answers its address, named with the prefix
    (`192.0.2.22 (dev.example.net) is answered by scope 'lab' (prefix
    10.0.0.0/8); enrolling dev there`); a host whose address no scope covers
    is refused before anything changes, with the commands that add the
    address to a scope or make the host a scope of its own (`tacctl scope
    add linux-<name> --prefixes <address>/32 --secret generate`). A host's
    own scope from an earlier release is still opened to both protocols
    for a method switch and narrowed afterwards.
64. **A host whose scope no longer answers it is reported, never moved.**
    `host sync` (each host), `host list` and `config validate` compare an
    enrolled host's registered scope with the scope that answers the
    address recorded at its last enroll or sync, and warn when they differ
    (a prefix change, a new address, the wrong scope at enroll): its logins
    are checked against the other scope's users and secret and refused. The
    warning gives the enroll that moves it. Re-enrolling without `--scope`
    says the same, with `--scope <the answering scope>`. An enroll naming
    another scope for a registered host is a move: it says so, names the
    users whose accounts the move deletes, and asks on a terminal (`[y/N]`);
    without one it stops, nothing changed, unless given the new `--yes`.
65. **`log tail -f` follows the logs.** `-f` was taken for the line count:
    the TACACS+ section passed it to `journalctl -n` and the RADIUS one
    stopped with `tail: invalid number of lines: '-f'`. `log tail [-f|
    --follow] [n]` now prints each backend's tail, then follows every
    enabled backend at once (`journalctl -f` for tacquito's units, `tail -F`
    on the RADIUS auth and daemon logs), each line behind its backend's id
    when more than one is enabled, until Ctrl-C, which ends it normally.
66. **Moving hosts and prefixes between scopes.** `host move <name>
    [<scope>]` moves an enrolled host to another scope: an enroll with its
    registered target, port, identity, server and method, into the scope
    named or, without one, the scope that answers its address; it names the
    users whose accounts the move deletes and asks first (`--yes` without a
    terminal). `host move --all` moves every host another scope answers.
    `scope prefixes <scope> move <cidr>[,<cidr>...] <other>` moves prefixes
    in one change (the same checks as remove and add) and names the
    enrolled hosts that then belong elsewhere, with `host move`; none is
    moved. `scope remove` (and `scope prefixes <scope> remove --all`) refuse
    a scope that enrolled hosts use, `--force` or not, since they hold its
    secret. The warnings of item 64 now give `tacctl host move <name>`.
67. **Off-site provisioning (`--staging`).** `host enroll ... --scope
    <scope> --staging` and `config cisco|juniper|wti --scope <scope>
    --staging <bench-ip> [--name <device>]` provision a host or device at a
    bench address its scope does not cover: the address joins the scope as
    a `/32`, so the scope's own secret and users answer it there and nothing
    changes on the device once it is installed in the scope's prefixes. The
    staging addresses are recorded (`StateDir/staging`; `tacctl scope
    staging` lists them) and each is removed once its host (enroll, sync,
    `host target`) or registered device (`device add`, `device address`) is
    seen at another address the scope covers; `scope staging remove
    <address>` removes one by hand. A device configuration's own output
    stays clean: the staging lines go to stderr.
68. **One machine, one registration.** `host enroll` checked only the
    name, so a host enrolled as `rett@dev.example.net` could be enrolled again
    by its address (as `h192-0-2-22`): two registrations, two scopes'
    secrets and users fighting over one machine. Enroll now refuses a new
    name whose address another enrolled host reaches (its recorded address
    or its target's resolution, on the same ssh port; for this server, any
    of its own addresses), naming the host and the two ways out
    (re-enroll under its registered name, or `host target`). `host target`
    refuses to point a host at another's address.
69. **Accounting from accounts tacctl does not know is recorded (tacquito
    patch 0005).** tacquito refused accounting for a user the device's
    scope does not know, so a device's local account (a Junos `admin`
    logging in or committing) or a daemon got an error reply and the device
    discarded the record (Junos: `AUDITD_TACPLUS_START_NO_RESPONSE:
    Discarded Accounting-Request message; no positive response from
    TACACS+ servers`). The patch records it through the scope's accounter
    (`root`, the accounting sink, when the scope has it, else any of its
    users: they share one), keeping the user the device sent, and replies
    success. Authentication and authorization of unknown users are
    unchanged. `tacctl upgrade` rebuilds tacquito with it. Verified live
    on a Junos device: a local `admin` login and commit are recorded and
    answered with success, as are a tacctl user's.
70. **`scope rename` carries enrolled hosts.** A rename updated the users of
    the scope but left the host registry (and staging addresses) naming the
    old one, so the hosts kept working on the unchanged secret but were
    reported against a scope that no longer existed. The rename now updates
    them and says how many; a host still registered in a scope that is gone
    is reported as such (`registered in scope 'x', which no longer exists`)
    with the `host move` that fixes it. The client script's GID messages
    after a reorder name the GID a group had (`now GID 80002 (was 80003)`),
    not the spare one it waited on.
71. **`console show` and `console check` ask sshd about a user of each
    kind.** They asked only about the first console user, often a superuser
    who may forward, and compared TCP forwarding only: a setting read before
    the drop-in (sshd keeps the first value, so a global `X11Forwarding yes`
    or `AllowTcpForwarding yes` there beats every tier block) left the other
    tiers open unnoticed. Now the first user of a tier that may not forward
    and the first of one that may are both checked, `x11forwarding` too
    (`disableforwarding yes` closes all), and an open non-forwarding tier is
    warned with the likely cause and where to look. Verified on the dev
    server: the operator's `ssh -L` is refused, the superuser's works.
72. **Acknowledged notices are out of the way, and `--all` shows them.**
    `device show` listed acknowledged notices with their full text, including
    the check to make and the `tacctl device notice … ack …` command already
    run. It now lists only the open notices and counts the acknowledged ones
    (`1 acknowledged notice not shown: tacctl device show dev --all`).
    `--all` on `device show` and on `device notices` lists them too, marked
    `(acknowledged)`, with only what happened (`address-changed
    (acknowledged): the address of 'dev' changed from 10.0.0.1 to 10.0.0.2
    (<time>, seen by host enroll or sync)`). `--json` is unchanged.
73. **Gateway ports for the forwarding tiers, and loopback for everyone
    else.** `tacctl console forwarding gateway-ports enable` (default
    disabled) lets the tiers of `console forwarding tiers` open forwarded
    ports on other addresses than loopback: their blocks in sshd's drop-in
    set `GatewayPorts clientspecified`, so an `ssh -R 0.0.0.0:8080:host:80`
    to the server listens on every address, and the console's `tacctl ssh`
    takes `-g` (new) and a bind address on `-L` and `-D`. Disabled, the
    console's `tacctl ssh` now refuses `-g` and an `-L` or `-D` bind address
    other than loopback (`0.0.0.0:…`, `*:…` or an empty one, which ssh binds
    on every address even without `-g`; `ssh DENY … reason=gateway`): until
    now a superuser could open a port on every address of the server that
    way. The console's block of the drop-in sets `GatewayPorts no`, `console
    show` lists the setting, and `console show`/`console check` print
    sshd's `gatewayports` for each user they probe and warn when it is
    anything but `no` for a user it is not meant for.
74. **Completion lists what each flag does.** `tacctl <verb> -<Tab><Tab>`
    listed bare flag names (`-c  --idle  --no-history`); bash, zsh and fish
    now show each with the value it takes and its description, the text the
    shell's `?` shows (`--idle  (<min>: End the session after this many idle
    minutes at the prompt)`). `tacctl shell -c <Tab>` offers the commands.
    The `user` usage lists `scope <user> remove --all`, and `device show
    --all` is described as what it does there.
75. **A device's own `root` sessions stay out of the accounting log
    (tacquito patch 0005).** Junos opens short `root` CLI and junoscript
    sessions with no terminal for its process and health checks, several a
    minute, and every login and logout of them filled the accounting log.
    tacquito now answers a `root` record with no terminal (port `non-tty`,
    which Junos sends for them, `unknown`, or empty) with success and does
    not record it; a `root` login on the console or over ssh (port `0` or a
    tty name) is recorded as before, its commands included. Verified live on
    a Junos device: its `non-tty` root sessions are no longer recorded, and
    a `root` ssh login and its commands are. The device still logs
    `AUDITD_TACPLUS_MSG_SENT` for each record it sends; only its syslog
    configuration can drop that line. `tacctl upgrade` rebuilds tacquito.

## 0.2.0 (2026-10-04)

tacctl is now a single Go program, `/usr/local/bin/tacctl`, built on the server
from the repository clone in `/opt/tacctl` (dependencies are vendored there;
nothing is downloaded to build it). The command line, the output, the exit
codes, the files tacctl writes and every state format are unchanged: users,
groups, scopes, `store.yaml`, `tacctl.yaml`, snapshots, the registry of Linux
hosts and every generated file are byte-for-byte what 0.1.18 reads and writes,
so going back to 0.1.18 needs nothing to be converted. What differs is listed
here, and nothing else.

### What changed

1. **`tacctl version --long`** prints the commit, build date and Go version of the
   installed binary, and `test knobs: off`. `tacctl version` prints the same
   first line as before (`tacctl 0.2.0`).
2. **tacctl runs no helper programs for its own work any more**: not `python3`,
   `openssl`, `date`, `sha256sum`, `envsubst`, `awk`/`sed`/`grep`, `curl`,
   `timeout`, `gzip`, `sleep`, and not `chown`, `chmod`, `cp`, `mv` or `install`
   (except `install` for the sudoers drop-ins). Hashing, YAML, rendering, file
   handling and checksums are done by the binary itself.
3. **Device configs name the built-in template** when `/etc/tacctl/templates/`
   has no copy of it: the `Notes:` line of `config cisco|juniper|wti` then reads
   `  - Using template: built-in cisco.template` instead of a path under
   `/opt/tacctl/config/templates/`. `install` and `upgrade` put the shipped
   templates in `/etc/tacctl/templates/`, so on an installed server the line
   names that copy, as before.
4. **Python is not needed.** The preflight no longer checks that Python's
   `bcrypt` module imports.
5. **`user move` usage line** now reads `Usage: tacctl user move <user> <group>`;
   the word `user` was missing.
6. **Install dependencies.** `python3`, `python3-yaml` and `python3-bcrypt` are
   no longer installed or required (`git` and `wget` stay: the repository and the
   Go toolchain download). Nothing is uninstalled from hosts that have them.
   `tacctl hash commands` still prints the Python recipe, for operators who
   generate a hash on their own machine.
7. **Shell completion is generated by the binary.** `tacctl completion bash`
   prints the script; `install` and `upgrade` write the bash script to
   `/etc/bash_completion.d/tacctl` (the upgrade says `Updated:` or `Unchanged:
   bash completion`, and rewrites the file only when it differs). The words are
   the same as before and live names still come from `sudo -n tacctl
   _completion-names`. `completion` and `__complete` run without sudo. Only bash
   is supported; zsh and fish are not offered.
8. **New options for non-interactive use.**
   `tacctl config render --dry-run --out <dir>` renders every enabled backend
   into a new, empty directory at the files' live paths and touches nothing
   else (no render record, no restart); `tacctl install -y|--yes` and
   `tacctl uninstall -y|--yes` skip the confirmation (the prompts stay the
   default). `uninstall -y` answers *no* to the two "preserve" questions, so
   nothing is archived.
9. **The `tacctl.yaml` write path takes the store's precautions** (the file and
   its directory are synced, and a lock is held while it is rewritten); the
   bytes written are unchanged.
10. **Passwords longer than 72 bytes are refused** with a message. Before, the
    bcrypt library silently used only the first 72 bytes.
11. **`tacctl upgrade` rebuilds the binary** whenever the Go sources of the
    clone changed, and `tacctl upgrade --branch <name>` onto a release of the
    bash era hands the host over to that release's own upgrade (see "Rolling
    back").
12. **Test knobs.** The `TACCTL_TEST_NOW`, `TACCTL_TEST_RANDOM`, `TACCTL_FAULT`
    and `TACCTL_TEST_ROOT` variables used by the test suite work only in a binary
    built with `-tags testknobs`; the installed binary ignores them.
13. **A stored value that is not valid UTF-8 is refused** (for example a secret
    passed as raw bytes): `tacctl store: cannot write scopes.<s>.secret: the value
    is not valid UTF-8 or contains control characters; nothing was written`.
    Such a value was stored in a form tacquito could not reproduce, so no working
    configuration changes.
14. **Command-rule regexes are checked with Go's RE2**, the engine tacquito uses,
    not Python's `re`. Python-only syntax (lookarounds, backreferences) is
    refused when you enter it, and the `invalid regex (<reason>)` text is Go's.
    This applies to `group commands add --match` and to `commands.<group>[].match`
    in `tacctl.yaml`.
15. **YAML constructs tacctl never writes are refused in `store.yaml` and
    `tacctl.yaml`**: anchors and aliases, merge keys, non-string keys,
    `!!set`/`!!omap`/`!!pairs`/`!!binary`, timestamps with a time of day and
    integers beyond 64 bits. The message is `line L, column C: ... is not supported
    in this file`; setters refuse, readers warn and use the defaults, as for any
    `tacctl.yaml` that does not parse.
16. **Inputs that used to end in a Python traceback** (invalid tagged scalars such
    as `!!int abc`, impossible dates, out-of-range `\U` escapes, a date value in
    `tacctl.yaml`) are reported as a parse problem with its position, or read
    normally (the date).
17. **A store that cannot be loaded is reported once** and the command stops
    there; before, the error could print several times and be followed by a
    misleading "does not exist". `status` and `config validate` print it once and
    carry on with zero counts.
18. **`config validate` with a `tacquito.yaml` that does not parse** (legacy
    mode) prints the first lines of the YAML error, finishes the report and
    exits 1; it died with exit 120 and a traceback fragment. A failed `config
    sudoers [tiers] install` no longer leaves a temporary file behind.
19. **`group commands add <group> <name> --match` with no value** exits 1
    silently instead of dying with bash's `unbound variable`, and `group commands
    remove <group> 'sh['` ends without stray `grep`/`python` messages.
20. **WTI secret warnings** classify characters the same way whatever your locale
    (C.UTF-8 rules). Under a locale such as `en_US.UTF-8`, an accented letter used
    to suppress the punctuation warning.
21. **`host enroll x --scope`** (a value flag at the end of the line) exits 1
    instead of looping forever, and `config linux uid <user> 09999` no longer
    prints a `value too great for base` line (the value is accepted as before).
22. **A `tacquito.yaml` that is not valid YAML** is reported in the YAML library's
    words (for example by `store rollback` with a broken pre-store file), and one
    that is not UTF-8 makes the migrations skip it silently instead of ending in a
    Python traceback.
23. **`tacctl install` no longer downloads Go.** The bootstrap script
    (`bin/tacctl.sh`) installs it when it is missing; `install` needs
    `/usr/local/go/bin/go` and says `Go <version> already installed, skipping.`.
24. **The upgrade's `tacquito.bak` keeps the binary's mode**, so a binary restored
    after a failed build or restart can be started by the `tacquito` user. (This
    is the 0.1.17 fix, listed because it is part of the baseline.)
25. **`/usr/local/bin/tacctl` is a real binary**, built from the clone, not a link
    to `bin/tacctl.sh`. `install` and `upgrade` print `Building /usr/local/bin/tacctl
    from /opt/tacctl...`, and `upgrade` no longer relinks the command. `uninstall`
    lists the Go build cache (`/root/.cache/go-build`) among what it does not
    remove, instead of the `python3-bcrypt` package.
26. **Go is installed only after its download is verified.** `bin/tacctl.sh` fetches
    Go 1.26.2 from `https://dl.google.com/go/` with its published SHA-256 and
    refuses to install it if the checksum cannot be fetched or does not match.
    (The same rule shipped in 0.1.18.)
27. **`upgrade` rebuilds and re-executes whenever the installed binary was not built
    from the clone's current commit**, so a pull that changes only documentation
    also causes one (cached, so quick) rebuild. The version the binary reports
    therefore always matches the clone. 0.1.x re-executed only when `bin/` or `lib/`
    changed.
28. **`config defaults` and `config dump` headers** say the defaults are built into
    tacctl (`it is generated by tacctl config defaults`, `Defaults:  built into tacctl`)
    instead of naming `lib/conf.sh`, which no longer exists. Comment lines only; the
    data is unchanged.

29. **Completion candidates differ in form from the hand-written script's.** Words
    come in command order rather than hand-ordered, a lone candidate is shell-quoted
    (`lab\,prod` is the word `lab,prod`), `scope prefixes <scope> remove` offers
    `--force` beside `--all`, and `config get` completes only the shipped top-level
    keys.
30. **The usage text shows the current options**: `install [--branch <name>]
    [-y|--yes]`, `uninstall [-y|--yes]`, `version [--long]`, and `config render
    --dry-run --out <dir>`.
31. **A restart is no longer refused by systemd's start limit.** Before every
    start or restart of tacquito (and its listener instances) or FreeRADIUS,
    tacctl runs `systemctl reset-failed` on the unit. systemd refuses a sixth
    start within ten seconds, so a quick series of changes, each ending in a
    restart, could leave the service stopped (`start-limit-hit`) until someone
    ran `systemctl reset-failed` by hand. The units themselves are unchanged.
32. **Going back to a bash release installs the packages it needs first.**
    `tacctl upgrade --branch <bash release>` checks for `python3`,
    `python3-yaml` and `python3-bcrypt` (0.1.x cannot start without them, and a
    server installed with 0.2.0 does not have them) and installs any that are
    missing before it hands over (`Installing packages the bash release needs:
    ...`). If they cannot be installed it does not hand over: the installed
    command stays as it was, the clone goes back to the branch it was on, and
    the message gives the command to run:
    `sudo apt-get install -y python3 python3-yaml python3-bcrypt && sudo tacctl upgrade --branch <name>`.

### Upgrading from 0.1.18

Run `sudo tacctl upgrade` as always. Servers on 0.1.16 and 0.1.17 cross over the same
way; for anything older, upgrade to 0.1.18 first. On a 0.1.18 server this happens:

1. The 0.1.18 `tacctl upgrade` rebuilds tacquito if its sources or the patch
   overlay changed, pulls the new tree and, because `bin/` and `lib/` changed,
   re-executes `bin/tacctl.sh upgrade`, which is now the bootstrap script.
2. The bootstrap checks for a Go toolchain at `/usr/local/go/bin/go` that is new
   enough for the tree. A 0.1.x server has one, since tacquito is built with it;
   if it is missing or older it installs Go 1.26.2, after verifying the published
   checksum, and never replaces a newer one.
3. It builds the binary from the vendored sources with `GOTOOLCHAIN=local` and no
   network, prints `Building /usr/local/bin/tacctl from /opt/tacctl...`, replaces
   the old link `/usr/local/bin/tacctl` in one rename and runs `tacctl upgrade` with
   the new binary.
4. The Go upgrade continues where the bash one stopped: state migration, tacquito
   "up to date" (a tacquito rebuilt just before is restarted, and can be rolled
   back, exactly as in 0.1.18), packages, the config phase, then system files: the
   completion is regenerated (`Updated: bash completion`, once), the manual page,
   templates you have not customised, logrotate, and finally one restart of what
   changed. Running `tacctl upgrade` again afterwards changes nothing.

If the build fails (full disk, no usable Go), the installed command is left as it
was and the bootstrap prints

    [ERROR] tacctl could not be built (see above). The installed command is unchanged.
    [ERROR] Fix the cause and run the command again, or go back to the bash release:
    [ERROR]   sudo git -C /opt/tacctl checkout 0.1.18 && sudo tacctl config branch <previous branch>

Every later `tacctl` command runs the bootstrap again and repeats the message until
the cause is fixed or the way back is taken.

### Rolling back to 0.1.18

Nothing in `/etc/tacctl` has to change: the files 0.2.0 writes are the files 0.1.18
reads. Either let `tacctl` do it:

    sudo tacctl upgrade --branch 0.1.18

(the Go upgrade checks out the tag, installs `python3`, `python3-yaml` and
`python3-bcrypt` if they are missing, which is the case on a server installed
with 0.2.0, prints `Target branch is a bash release of tacctl; handing over.`,
turns `/usr/local/bin/tacctl` back into a link to `/opt/tacctl/bin/tacctl.sh` and
runs that release's `upgrade`). The clone then stays on the tag: `sudo tacctl
upgrade` keeps it there, and `sudo tacctl upgrade --branch master` makes the
server follow `master` again. Or by hand, which works without a working binary
(on a server installed with 0.2.0, first
`sudo apt-get install -y python3 python3-yaml python3-bcrypt`):

    sudo git -C /opt/tacctl fetch --tags --force origin
    sudo git -C /opt/tacctl checkout 0.1.18
    sudo ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl
    sudo tacctl upgrade

The 0.1.18 upgrade reinstalls its own completion and manual page. The Go build cache
(`/root/.cache/go-build`) stays behind, as the tacquito build cache does.

### Cost of building on the host

A first build compiles the standard library and the vendored dependencies: about 13
seconds of wall time (54 s of CPU) on an eight-core development machine, leaving about 129 MB
in the Go build cache; the binary is 10.9 MB. An unchanged tree builds again in under a
second.

## 0.1.18 (2026-10-03)

- **Installing on a server without Go works again.** `tacctl install` downloads Go and its published checksum from `dl.google.com`, and installs Go only after the download is verified: a checksum that cannot be fetched, or a failed download, stops the install with an error.

## 0.1.17 (2026-10-03)

- **Upgrade rollback works again for the tacquito binary.** The backup `tacctl upgrade` takes before rebuilding tacquito keeps the binary's permissions, so a binary restored after a failed build or a failed restart can be started by the `tacquito` service user.

## 0.1.16 (2026-10-03)

- **Membership lists use `replace` and `remove --all`.** `tacctl user scope <user> replace <scopes>` replaces a user's scopes and `user scope <user> remove --all` removes them all; `tacctl scope prefixes <scope> remove --all [--force]` removes every prefix (and with them the scope). `set` and `clear` on these two lists now fail with a message naming the new verb; update any scripts that call them.
- **`scope show` no longer prints the scope secret**; it shows whether one is set and its length. `tacctl scope secret <scope> show` prints it.
- **Customised templates survive upgrades.** A template you edited in `/etc/tacctl/templates/` is kept and the shipped version is written beside it as `<name>.template.new`; see the README section "Custom Templates".
- **Upgrades restart a service only when it has something new to read**, and a failed restart rolls tacquito back to the previous binary. `tacctl upgrade --branch <name>` runs the new branch's own upgrade when tacctl's code differs.
- **A `tacctl.yaml` that does not parse is never overwritten**: settings changes refuse with the parse error, and other commands warn and use the defaults.
- RADIUS-only installs no longer need `tacquito.yaml`.

## 0.1.15 (2026-10-02)

This is a large release; read the notes below before running `tacctl upgrade` on an existing server.

- **A canonical store.** Users, groups, scopes and connection filters live in `/etc/tacctl/store.yaml`; `tacquito.yaml` is generated from it on every change and is no longer the source of truth. Hand edits of a generated file are detected (drift) and never silently overwritten. See the README section "The store and generated configs".
- **`/etc/tacctl`** holds everything tacctl owns (store, `tacctl.yaml`, snapshots, templates, the Linux host registry). `/etc/tacquito` is the TACACS+ daemon's directory again.
- **Backups are snapshots** of `store.yaml` and `tacctl.yaml`, taken before every change; `backup restore` re-renders every backend.
- **Backends.** TACACS+ (tacquito) and RADIUS (FreeRADIUS) behind one contract: `tacctl backend list|status|enable|disable`; `status`, `log` and `config validate` report per backend. See the README section "Backends".
- **RADIUS**, opt-in: `tacctl backend enable radius`. PAP against the same bcrypt hashes, the same scopes and secrets, `config cisco|juniper|wti --protocol radius`, per-scope vendor attributes. See the README section "RADIUS".
- **Listeners** in `tacctl.yaml` (`listeners.<backend>.<name>`), from which the systemd drop-ins are rendered; further TACACS+ listeners run as `tacquito@<name>` instances.
- **Linux hosts over RADIUS**: `tacctl host enroll --method radius` (pam_radius_auth), `host default-method`, switching a host between methods; Rocky Linux joins the tested hosts.
- **Per-scope settings**: `scope protocols`, `scope auth-method`, `scope vendor-attrs`, `scope devices`, `scope radius-group`; every per-scope `tacctl.yaml` key now follows `scope rename` and is removed by `scope remove`.
- Confirmation prompts no longer exit silently when standard input is closed; `config validate` exits 1 when it finds structure or scope errors.

### Upgrading to 0.1.15

The first `tacctl upgrade` from 0.1.14 or earlier runs the old release's upgrade, which pulls 0.1.15 and re-executes it; 0.1.15 then does the following on its own. Nothing needs to be prepared, and RADIUS stays off (`tacctl backend enable radius` afterwards, if wanted).

1. **State directory.** `tacctl.yaml`, `linux-hosts`, `linux-uids`, `backups/` and `templates/` move from `/etc/tacquito` to `/etc/tacctl` (0700 root). Each old path becomes a symlink to the new one, for one release, so the previous release still finds its files after a rollback. This runs on every upgrade: if older code has meanwhile replaced a symlink with a regular file, the newer content wins and the other copy is kept under `/etc/tacctl/backups/legacy/`.
2. **Units.** `tacquito.service` and the template `tacquito@.service` are installed. The listen address, log level and metrics address of the old hand-managed drop-in `tacquito.service.d/tacctl-overrides.conf` are imported once into `tacctl.yaml` (`listeners.tacacs.default`, `backends.tacacs.level`, `backends.tacacs.metrics_address`), the drop-in is replaced by the rendered `tacctl.conf`, and the old file is kept under `backups/legacy/`. The running daemon is not touched until the one restart at the end; if the unit does not come up then, the unit files, drop-ins, `tacctl.yaml` and the binary are restored together.
3. **The store, behind a gate.** The legacy migrations of `tacquito.yaml` run as in every upgrade, then `tacctl store import --check` with the newly built binary: import (nothing unrepresentable), render, equivalence of what tacquito would load from the two files, and a load test of the rendered file on a loopback port. Only when all of that passes is `/etc/tacctl/store.yaml` written, the old file kept as `/etc/tacctl/backups/legacy/tacquito.yaml.pre-store.<timestamp>`, `tacquito.yaml` rendered from the store (and compared once more with the file it replaced), and tacquito restarted. The summary says `Store: migrated from tacquito.yaml`.

**When the gate stops**, the upgrade still completes: the code is installed, `tacquito.yaml` and the running daemon are left exactly as they were, and tacctl runs in **legacy read-only mode** (read commands work, changes are refused). The report says why: content the store cannot hold (another service on a group, a non-bcrypt authenticator, an unknown top-level key, …), a render that is not equivalent (the differences are printed), the tacquito binary or `timeout` missing. The upgrade **never forces either through**. To proceed, either fix what `tacctl store import --check` lists in `tacquito.yaml` and run `tacctl upgrade` again, or accept the difference yourself: `tacctl store import` (`--force` drops what the store cannot hold, listing each item), then `tacctl config render --force`.

**Rollback.** `tacctl store rollback` returns to the kept pre-store `tacquito.yaml` and legacy read-only mode under 0.1.15 (refused while RADIUS is enabled: `tacctl backend disable radius` first). Run it before putting the previous release's code back (`git -C /opt/tacctl checkout 0.1.14`): that release edits `tacquito.yaml` directly, and with the store still in place its edits would be drift to 0.1.15. It finds `tacctl.yaml`, `linux-*`, `backups` and `templates` through the symlinks in `/etc/tacquito`, and a later upgrade moves whatever it wrote and runs the gate again. Its `config listen|loglevel|metrics` write the old `tacctl-overrides.conf` drop-in, which the rendered `tacctl.conf` beside it overrides (systemd reads drop-ins in name order); remove `tacctl.conf` from `tacquito.service.d` after going back if you change those settings there.

After the upgrade: `tacctl status`, `tacctl config validate` (store, rendered config, drift), and `tacctl backup list` (the pre-store file is under the old-style backups).

---
