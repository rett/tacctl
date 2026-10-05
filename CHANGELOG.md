# Changelog

All notable changes to tacctl. The README and the manual page describe only the
current behaviour; this file is where history lives.

## 0.2.1 (unreleased)

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
    (`10.125.0.222 (dev.example.net) is answered by scope 'lab' (prefix
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
