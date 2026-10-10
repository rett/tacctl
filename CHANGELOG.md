# Changelog

All notable changes to tacctl. The README and the manual page describe only the
current behaviour; this file is where history lives.

## 0.2.4 (unreleased)

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
   keeps `TACCTL_ASKPASS` for four command lines only: a `Cmnd_Alias` of `device
   config pull|diff`, `ssh` and `device ssh` (named differently in the group
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
    holds the 0.2.4 form: restore it with 0.2.4, not with 0.2.3. Rolling back,
    then: dry run `tacctl rollback 0.2.3`, `tacctl rollback 0.2.3 --apply
    --yes`, `tacctl upgrade --branch 0.2.3`; until the install, a command that
    writes the console's settings, a device's SNMP settings or `config devices`
    writes the 0.2.4 form again, and a second `--apply` converts it. (The real
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
    image did not store (`monitor capture`, and `clear mac address-table
    dynamic`, which it accepts and does not store) is still missing, so
    `roles` of such a device stays `differs`.


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
