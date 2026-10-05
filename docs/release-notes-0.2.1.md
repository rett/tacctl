# tacctl 0.2.1

0.2.1 adds a device registry and ssh by name: `tacctl device` names the network
devices that authenticate against the server, shows which of them have been
seen and which addresses authenticate without being registered, and pins their
ssh host keys; `tacctl ssh <name>` opens a session to one as the invoking user,
by password. It also adds `tacctl shell` (an interactive prompt with completion
and history), zsh and fish completion, signed release binaries (amd64 and
arm64), and a stricter account lifecycle for Linux hosts. The numbered list
below is everything that differs from 0.2.0, and nothing else.

## Upgrading from 0.2.0

Upgrade with `sudo tacctl upgrade` as always. A new server needs only `git` and
`wget`; the installer brings Go and builds tacctl on the server:

    sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && /opt/tacctl/bin/tacctl.sh install'

What to expect:

- **tacquito is rebuilt once** and restarted, with two new source patches
  (`patches/0003` logs the address a device connected from, `patches/0004`
  stops the server message after a failed authentication); items 18 and 34.
- **The tiers sudoers file is refreshed by the upgrade** when
  `/etc/sudoers.d/tacctl-tiers` is installed and differs (`Updated: tiers
  sudoers`), so read-only and operator users get the new `ssh`, `device` and
  `help` rows; the upgrade never creates the file, and a file `visudo`
  refuses is left as it is, with a warning. The opt-in drop-in of `config
  sudoers install` is not touched by an upgrade: run `tacctl config sudoers
  install <group>` again to give it the `env_keep` line for the agent socket
  (item 14).
- **The first `host sync` (or `host enroll`) of each host after the upgrade
  deletes the accounts of removed users.** Accounts that earlier releases only
  expired for users no longer in the host's scope are deleted (`userdel`, their
  group too); their UIDs stay reserved on the server. Home directories are
  kept unless you say otherwise: on a terminal each is asked about, and
  `--remove-home` deletes them without asking (items 38 and 39). Accounts
  tacctl did not create (including ones an earlier release adopted) are never
  deleted or changed, except that they are taken out of tacctl's own groups
  (item 36); `--adopt` is gone (item 37). A kept home is moved to
  `/home/.tacctl-removed/` and made root's, so a local account that later
  gets the same UID does not inherit it (item 39). The same run records the
  host's address in the device registry (item 41) and warns when the host's
  `/etc/login.defs` lets local `useradd` give out UIDs of 80000-89999
  (item 42; keep `UID_MAX` below 80000 there, as the default 60000 is).
- **UIDs move to 80000-89999, once** (items 35 and 52). The first `config
  linux uid`, `config linux script`, `host enroll` or `host sync` after the
  upgrade renumbers `/etc/tacctl/linux-uids` from 20000-29999 to the same
  offset in 80000-89999 (20005 becomes 80005), keeps the old file as
  `linux-uids.pre-renumber-<time>` and logs `uid-map renumbered <n>
  entries`. **The first sync (or enroll) of each host then renumbers the
  accounts tacctl created there**: UID, own group and primary GID, the home
  directory re-owned (`'<user>': renumbered <old> -> <new> (home re-owned)`;
  the summary says `synced (<n> users; <k> renumbered)`). Files outside the
  home that keep the old number (in `/home`, `/tmp`, `/var/tmp`,
  `/var/spool/cron`, `/var/mail`) are listed, never changed: give them back
  with `chown -h <new>:<new> <file>`. A user who is logged in, or whose new
  number is taken on the host, keeps the account as it is and is named as
  refused; log the user out (or free the number) and sync again. Accounts in
  20000-29999 that tacctl did not create are not touched. New users get
  80000-89999 only; a user whose recorded UID is outside it gets no account
  on hosts until it is given a number in the range.
- **Release binaries.** When a clone is at a release tag, `install` and
  `upgrade` download the binary for the host, verify its signature against the
  public key committed in the clone (`release/allowed_signers`), its checksum
  and the commit it was built from, and install it; otherwise they build from
  source as before. To check the assets by hand:

      ssh-keygen -Y verify -f /opt/tacctl/release/allowed_signers -I tacctl-release \
          -n tacctl-release -s SHA256SUMS.sig < SHA256SUMS
      sha256sum -c --ignore-missing SHA256SUMS

## What changed

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
    are the shell's own words. Tab completes commands, flags and live names; a second Tab lists the
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
    `TAC_REMOVE_HOMES` (names, or `*`) and `TAC_PROTOCOL=3`; the script body
    refuses a header of another protocol before changing anything (`This
    script's header speaks protocol <n> and its body protocol 3: they were
    not written by the same tacctl. …`).
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
    old number <old> and were left as they are (chown -h <new>:<new> <file>
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
