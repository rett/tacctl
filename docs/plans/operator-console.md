# tacctl operator console — design proposal (for decision)

> **Status: proposal, not a plan of record.** Written 2026-10-03 against the `feature/go-rewrite` working tree (`ebb3102`, WP2.1 done, Phase 2 in progress) and the 0.1.16 bash code in `lib/`. It supersedes the device-registry draft of the same day and folds it in. Nothing here is scheduled: §12 lists the decisions for the user, each with a recommendation; the size estimates assume every recommendation is accepted. It changes no file, no state and no host; log formats and sshd settings were read on the dev server read-only, and every log line, name and address below is **made up** (documentation ranges, invented names).

Markers as in the other plans: **[V]** verified by reading code or a read-only command on the dev server; **[I]** inferred from code; **[A]** assumption about external software to confirm before relying on it.

The proposal has four parts that build on each other:

| Part | What | Depends on |
|---|---|---|
| **A. Device registry** | names for the devices and hosts that authenticate here; *configured* / *seen* / *reachable* facts; `device discover` | the store, the backends' logs, `internal/hosts` (WP3.2) |
| **B. Shell mode** | `tacctl shell`: a prompt where lines are tacctl commands, with completion, help and history from the cobra tree | the cobra tree (Decision 2), in-process `cli.Run` |
| **C. `ssh <name>`** | `tacctl ssh <name>` and, in the shell, `ssh <name>`: an ssh session to a registered device or enrolled host, as the invoking user, with name completion | A (names), B (prompt), the `host` ssh runner (WP3.2) |
| **D. Login console** | the shell as the **login shell** of TACACS+ users on the server: a jump host / console with no shell escape | A, B, C; the Linux-host enrolment scripts; sshd configuration |

---


> **Status 2026-10-03 — decided.** The user accepted the recommended placement (option (b): **0.2.1** = registry, shell, `ssh`; **0.2.2** = console), asked the in-progress rewrite to make all §9.3 door-openers now, and accepted every recommendation in §12. This document is the plan of record for 0.2.1/0.2.2, to be revisited (and split into work packages) when that work starts after 0.2.0. **Requirement (user, 2026-10-03): `ssh <name>` must reach every kind of device tacctl serves — Cisco IOS/IOS-XE, Juniper Junos, WTI and enrolled Linux hosts (plus `other`) — through the vendor profiles of §5.2; the acceptance of the 0.2.1 `ssh` package includes a live session to each vendor available in the lab, and the legacy-IOS option names [A] are verified there.**

## 0. Summary of the recommendation

1. **Do all four, in two 0.2.x releases after 0.2.0 ships** — A+B+C in 0.2.1, D in 0.2.2 — and keep 0.2.0 the parity release it is (§9, placement option (b)). Putting any of it into 0.2.0 costs three to six weeks on a release whose gate is "behaves like 0.1.16", and the login console in particular deserves its own release notes and its own live acceptance.
2. **Registry: a separate additive file `/etc/tacctl/devices.yaml`** (root 0600, own `version: 1`, `yamlpy`/`pyyaml`, lock + tempfile + fsync + rename), **not** a store section: the store is what renders the daemons' configs and the registry renders nothing. Scope is derived from the store at display time, never stored. Enrolled Linux hosts appear in the registry read-only from `linux-hosts`. Rollback to 0.1.16 stays a checkout (§3.5).
3. **"Seen" for TACACS+ needs a ~10-line tacquito patch** (`0003`): the accounting log records the *user's* source address, not the device's [V]; the journal names the device only at debug level or in error lines [V]. tacctl already carries two patches. FreeRADIUS already logs everything needed in `tacctl-auth.log` [V] (§3.3).
4. **Shell mode runs unprivileged and spawns `sudo tacctl <line>` per command** — not, as go-rewrite §8 sketched, one sudo re-exec with a root session. The same loop then serves as the login console: the process holding the terminal never holds privilege, every line passes sudoers *and* the in-tacctl tier gate, sudo logs every command, `ssh` runs as the user without any `SSH_AUTH_SOCK` plumbing, and Ctrl-C goes to the child (§4).
5. **`ssh <name>` is the one external process the shell may start.** Names only (registered devices and enrolled hosts in the caller's scopes), the user's own ssh, agent and `known_hosts`, a fixed option set per vendor, no secret on argv, never root. Outside the shell `tacctl ssh <name>` goes through the normal sudo re-exec and drops back to the invoking user the way `host enroll` does today. `tacctl device ssh-config` prints an `~/.ssh/config` Include so plain `ssh <name>` works too (§5).
6. **The login console is an opt-in per tier with a per-user override** (`console tiers enable readonly,operator`, `console user <u> enable|disable`), provisioned by the existing `host enroll --local`/`host sync` path on the tacctl server only, registered in `/etc/shells`, and **paired with an sshd `Match Group tac-console` drop-in** that disables TCP/stream/X11 forwarding and agent forwarding — the shell cannot prevent those by itself. The console refuses `-c` except for a single tacctl line (so `ssh devserver "user list"` works and scp/sftp fail cleanly), starts nothing but `tacctl` and `ssh -F <generated config>`, redacts history, logs every line (sudo's log plus its own), and can optionally send per-line TACACS+ accounting to the local tacquito using the library's own client (`client.go` [V]). Superusers keep bash unless opted in; local administrators and root are never touched; that is the break-glass (§6).
7. **Keep the door open now, cheaply:** the in-process `cli.Run(ctx, args, stdio)` already in the plan; a data-driven tier table and sudoers emitter; `_completion-names` extensible by kind (add `hosts` in WP3.2); the ssh runner of WP3.2 as a reusable `AsUser` + tty primitive; `sudoArgv`'s first-word list as a table; `hosts.Registry` as a package API. None of these changes 0.2.0 behaviour (§9.3).
8. **Size:** A ≈ 5–6 sessions, B ≈ 3–4, C ≈ 1 (on top of A/B), D ≈ 5–6, total **≈ 14–17 sessions, ≈ 8,000–9,000 lines of Go incl. tests** plus a tacquito patch, client-script changes and two live acceptance rounds (§10).

---

## 1. Use cases and non-goals

### 1.1 Use cases

| # | Use case | Part |
|---|---|---|
| U1 | Connect to a device by name with the right login, port and vendor options: `tacctl ssh core-sw1`, or `ssh core-sw1` after installing the generated Include | A, C |
| U2 | Tab completion of device and host names, in tacctl, in the shell, and in plain `ssh` | A, B, C |
| U3 | See which registered devices are *configured* (inside a scope) and which are not | A |
| U4 | See which devices have actually authenticated recently, and which went quiet | A |
| U5 | Discover devices that authenticate but are not registered, and devices with a wrong secret | A |
| U6 | An operator does twenty tacctl commands in a row without retyping `tacctl` and with completion that needs no bash-completion file | B |
| U7 | A TACACS+ user SSHes to the tacctl server and gets a console: `ssh core-sw1`, `user show jdoe`, `log failures`, `exit` — and nothing else; the server is their jump host | D |
| U8 | Batch: `tacctl shell < provisioning.txt` stops at the first failing line and returns its code | B |
| U9 | Audit: who ran what in the console, and when; which device sessions were opened from it | D |

### 1.2 Non-goals

- Not an inventory/IPAM/CMDB (one `description` field is the ceiling); not a source of truth for anything that renders; no config push, remote execution or device-config backup; no credential handling by tacctl, ever.
- Not a general-purpose restricted shell: the console runs tacctl verbs and `ssh <name>`; no file transfer, no editors, no pipes, no shell builtins.
- Not a replacement for the device's own AAA: command accounting *on* a device stays the device's job; the console accounts for its own lines.
- Not a NetBox client (CSV/YAML import/export only, §3.1).
- No bidirectional device-context mode in the shell (`scope lab` then `show`): every tacctl verb names its scope explicitly; a mode would duplicate every argument parser and invite "which scope am I in" mistakes with secrets involved (go-rewrite §8, unchanged).

---

## 2. What exists today [V]

### 2.1 Vendor tags, the host registry, the ssh runner

- `store.yaml` `scopes.<s>.devices: {<cidr>: cisco|juniper|wti}` (`lib/store.sh:108`, `vendor_map`) is **RADIUS reply behaviour keyed by address** (`scope devices <s> set|unset`, `lib/scopes.sh:1363-1470`; FreeRADIUS `client` blocks with `tacctl_device`, `radius.sh:540-600`), validated inside the scope's prefixes (`device_problems`, `store.sh:175-215`; Go `internal/store/cidrs.go:179-230`), shown by `scope lookup` (`internal/model/views.go:547-558`). No name, port or login; TACACS+ ignores it.
- `/etc/tacctl/linux-hosts`: `name|target|port|scope|server|identity[|method]` (`lib/linux_hosts.sh:641-671`, 0600; two hosts on the dev server: the dev server itself via `--local`, and the test client). `target` is the ssh target — the file already holds what an `ssh <host>` needs. It does not hold the host's IP (the scope does). Go port: WP3.2, not started.
- `_host_ssh` (`linux_hosts.sh:684-705`): as root with `SUDO_USER` set, runs `sudo -u $SUDO_USER -H [env SSH_AUTH_SOCK=…] ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 [-o BatchMode=yes when no tty] [-p] [-i] …`, tty inherited, `-t` when stdin is a terminal. `SSH_AUTH_SOCK` reaches root only because `bin/tacctl.sh:43-44` passes it as a sudo command-line assignment for `host`; the dev server's sudoers has `env_reset` and no `env_keep` for it, and the opt-in `NOPASSWD: /usr/local/bin/tacctl` rule has no `SETENV`, so `host` through that rule is refused by sudo (go-rewrite §1.1).
- Accounts on enrolled hosts are created by `config/linux/client-install.sh:616-618` with `useradd -m [-u uid -g name] -s /bin/bash -c "<name> (TACACS+)"`, then `usermod -aG tac-users,tac-<tier>` (`:628`); the server passes `TAC_USERS` as `name:tier:uid` lines (`linux_hosts.sh:127,287`; parsed with `IFS=: read -r name tier uid`, `client-install.sh:587`). The script insists that a local administrator with a usable password exists outside the user list and restores PAM on failure (README). On the dev server the PAM stack is `tacctl-auth|account|session` included from `/etc/pam.d/sshd` [V].

### 2.2 What the logs record about the device

| Source | Written by | Device (NAS) address? | User / outcome? | Level | Retention on the dev server | Read today by |
|---|---|---|---|---|---|---|
| `/var/log/tacquito/accounting.log` (+ one per extra listener) | tacquito `accounters/local/local.go:105`, `json.Marshal` of the accounting **request body** | **No.** `RemAddr` is the body's `rem_addr`: the address the client reports **for the user** (a workstation, `localhost`, `Unknown host - non-tty` on Junos daemons) [V sample]. The connection address lives in the request context (`ContextConnRemoteAddr`, set in `server.go:164`) and is not written [V] | user; `cmd=login`/`cmd=logout` | always | daily × 90, compressed [V `/etc/logrotate.d/tacquito`]; ~52k lines/day on the dev server, mostly the Junos `root` sink | `_tacacs_last_login` (`tacacs.sh:942-960`), `log accounting` |
| tacquito journal INFO | `bcrypt.go:143` `accepting user [u] using a bcrypt password`; `:152` `failed to validate the user [u] …` (ERROR) | **No** | user, outcome | 20 = default `backends.tacacs.level` (`conf.sh:537`) [V] | journald: the dev server holds tacquito entries back to 2026-05-31, 3.3 GB for all units [V] | `log tail|search|failures` (`journalctl -u …` + grep, `tacacs.sh:3463-3483`) |
| tacquito journal ERROR | `server.go:159` `closing connection, unable to read, bad secret detected for ip [A.B.C.D:port]` [V 95 lines in 3 days] | **Yes** (wrong secret) | none (undecryptable) | always | as above | `log failures` greps `bad secret` |
| tacquito journal ERROR | same wrapper for an address no scope covers (`no matching prefix secret provider found`, `prefix/provider.go:110`) | [I] likely through the same `for ip` text — to confirm | none | always | as above | — |
| tacquito journal DEBUG | `prefix/provider.go:105` `prefix secret provider matches remote [A.B.C.D] against prefix [10.99.0.0/24]`, per packet [V 305 lines in 3 days]; `log.go:56` `Record` maps with `conn-remote-addr:` (3 lines in 3 days) | **Yes** | no user on the provider line | 30 only (the dev server runs 30 via its drop-in [V]; a fresh install runs 20) | as above | — |
| `/var/log/freeradius/tacctl-auth.log` | FreeRADIUS `linelog` from tacctl's config (`radius.sh:524-530`) | **Yes**: `client=<Packet-Src-IP>`, `nas=<NAS-Identifier|NAS-IP-Address|->`, `scope=`, `device=<tag|generic>` | user, Access-Accept/Reject, reason | always | weekly × 12, `copytruncate` [V] | `_radius_last_login`, `_radius_status_activity` (`radius.sh:1423-1472`) |
| `/var/log/freeradius/tacctl-accounting.log` | FreeRADIUS `detail` | [I] yes (every request attribute) | user | always | as above | `log accounting` |

Made-up examples of the shapes that matter:

```
# tacquito accounting.log — RemAddr is the user's workstation, not the switch
2026/10/02 14:03:11 …/local.go:105: {"Flags":2,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"jdoe","Port":"tty1","RemAddr":"192.0.2.44","Args":["task_id=7","service=shell","cmd=login"]}
# tacquito journal, level 30 — the switch, no user
DEBUG: 2026/10/02 14:03:10 …/prefix/provider.go:105: prefix secret provider matches remote [10.99.0.1] against prefix [10.99.0.0/24]
# tacquito journal, any level — a device with the wrong secret
ERROR: 2026/10/02 14:05:02 …/server.go:159: closing connection, unable to read, bad secret detected for ip [10.99.0.77:51234]
# FreeRADIUS tacctl-auth.log — everything in one line
2026-10-02 14:07:40 Access-Accept scope=prod device=wti client=10.99.0.9 nas=oob-con1 reason='-' user=jdoe
```

tacctl builds tacquito from source and applies `patches/0001-stringy-default-service-permit.patch` and `0002-acct-success-empty-server-msg.patch` on install/upgrade, with a test (`tests/integration/tacquito_patches.bats`) [V]. The tacquito library also ships a TACACS+ **client** (`/opt/tacquito-src/client.go`: `NewClient`, `SetClientDialer(network, address, secret)`, `Send`, `SendOnly`) [V] — relevant for console accounting (§6.7).

### 2.3 Completion, tier gate, privilege model

- Completion runs in the user's shell; live names come through `sudo -n tacctl _completion-names <kind>` (`config/tacctl.bash-completion:49-51`; kinds `scopes users groups backups backends enabled-backends listeners`, `bin/tacctl.sh:235-262`). It works for root, for the opt-in `NOPASSWD` rule, and for tier users because `TACCTL_RO` lists `_completion-names *` (`dispatch.sh:271`) [V]. Host names are not completed today [V]. 0.2.0 generates completion from the cobra tree with `ValidArgsFunction` calling the same bridge (Decision 3); `__complete` runs without sudo and never opens `/etc/tacctl` (`internal/cli/reexec.go` `noSudo`).
- Tier gate: `caller_tier` from `SUDO_USER`, `id -nG`, model priv-lvl (`dispatch.sh:38-61`); `tier_permits` fixed allow-list (`:70-90`): readonly gets `passwd status version hash _completion-names user list|show group list scope list backend list|status`; operator adds `log tail|search|failures|accounting`, `config validate`, `backup list`. The sudoers tiers file mirrors it (`emit_tier_sudoers`, `:262-280`: `%tac-superuser ALL=(ALL:ALL) ALL`, lower tiers `NOPASSWD` on the aliases) and is not refreshed on upgrade (parity, go-rewrite §3.9).
- Every command but `hash` (and 0.2.0's `completion`/`__complete`) re-execs under sudo and runs as root; `cli.Run(ctx, app, build) error` is already the in-process entry (`internal/cli/cli.go`), with `signal.NotifyContext` at the top.

### 2.4 The server as an enrolled host; sshd on the dev server

The dev server is enrolled with `--local` on scope `lab` [V registry]; TACACS+ users log in to it over SSH with their TACACS+ password through pam_tacplus, which also sends session START/STOP accounting [V memory]. `/etc/shells` on the dev server lists `sh`, `bash`, `rbash`, `dash`, `tmux` [V]. Effective sshd settings [V `sshd -T`]: `usepam yes`, `permittty yes`, `allowtcpforwarding yes`, `allowstreamlocalforwarding yes`, `allowagentforwarding yes`, `x11forwarding yes`, `permittunnel no`, `forcecommand none`, `clientaliveinterval 0`, `subsystem sftp /usr/lib/openssh/sftp-server`; no `sshd_config.d` drop-ins. OpenSSH 9.6p1, bash-completion 2.11 [V `dpkg-query`].

---

## 3. Part A — device registry

### 3.1 Data model

| Field | Type | Rules | Stored |
|---|---|---|---|
| `name` | string | `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`; unique across the registry **and** enrolled-host names (one namespace for `ssh` and completion); not `local`, `all`, a tacctl verb | key |
| `address` | IPv4/IPv6 address | required, canonical, unique; **the AAA identity** (scope matching, log matching) | yes |
| `hostname` | DNS name | optional; display, and the ssh target when set | yes |
| `vendor` | `cisco|juniper|wti|linux|other` | default `other`; the first three are the store's `KNOWN_VENDORS`; drives the ssh profile (§5.2) | yes |
| `port` | 1–65535 | default 22 | yes |
| `login` | string | optional `-l` override; default none, so ssh uses the local username = the TACACS+ username for tier-managed users | yes |
| `legacy-ssh` | bool | opt-in (`enable|disable`), off: legacy IOS key-exchange/host-key algorithms | yes |
| `description` | ≤ 120 chars | optional | yes |
| `scope`, `tag` | — | **derived** per display via `model.ScopeLookup` and the vendor tag covering the address; `device show` warns when tag and vendor disagree | no |
| `state`, `last seen`, `by`, `via` | — | derived from the seen cache (§3.4) | no |

Scope is derived, not stored: the store is the authority on which scope answers an address; storing it would need cascades on `scope rename|remove|prefixes` and a second `device_problems`. Deriving costs one in-memory lookup per device. Vendor tags stay independent of the registry (`device add --vendor` never touches the store; a `device add` must not trigger a `store_apply` with a FreeRADIUS restart); `device show` prints the tag or the `scope devices … set` hint when the scope is served over RADIUS.

Enrolled Linux hosts appear in `device list|show`, `ssh` and `ssh-config` as `vendor=linux` entries built from `linux-hosts` (`hostname`/`login`/`port`/identity from `target|port|identity`; `address` = the scope's single `/32`/`/128` when it has one). They are read-only through `device`; `device add` refuses a host's name and `host enroll --name` refuses a device's name. Nothing is written to `linux-hosts` (Decision 10). Merging the two files is a 0.3.0 option.

Import/export: `device import [--check] [--replace] <file|->` (CSV `name,address[,vendor[,port[,login[,description]]]]` or the registry's YAML; merge by default; the `store import` switches operators know [V `store.sh:1128`]) and `device export [--csv|--json]`. No NetBox API client: a `curl … | jq | tacctl device import --csv -` script is the right shape for that [I].

### 3.2 The file

`/etc/tacctl/devices.yaml`, root 0600, own `.devices.lock`, tempfile + fsync + rename with the parse-back self-check of `store.Write`; `yamlpy` in the store's style, read with `pyyaml`:

```yaml
# tacctl device registry: names for the devices and hosts that authenticate here.
# Edit with 'tacctl device ...'. Scope and activity are not stored; they are looked up.
version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, description: 'DC1 core'}
  lab-rtr2: {address: 192.0.2.7, vendor: juniper, hostname: lab-rtr2.lab.example.net}
  oob-con1: {address: 10.99.0.9, vendor: wti}
```

Absent file = empty registry. `settings` keeps the registry's tunables out of `tacctl.yaml` (whose 0.1.16 reader tolerates unknown keys on read — `load_overrides`, `conf.sh:129-147` [V] — but `config validate` may flag them [I]; a separate file avoids the question). Snapshots copy `store.yaml` and `tacctl.yaml` by name (`service.sh:113-115`) [V]; adding `devices.yaml` is additive (an old `backup restore` would not look at it [I: confirm in the WP]).

### 3.3 Verification: configured, seen, reachable

| Fact | Values | Computed how |
|---|---|---|
| **configured** | `configured` (scope lookup exit 0, with the scope and `shadowed by …`) · `unconfigured` | `model.ScopeLookup` over the store already loaded; µs |
| **seen** | `seen <when> by <user> via tacacs|radius` · `rejected <when>` (last exchange a reject / bad secret) · `stale` (older than `stale_days`) · `never` | the seen cache (§3.4), refreshed by `device scan` |
| **reachable** (optional) | `open` · `closed` · `timeout` · `-` | TCP connect to `hostname-or-address:port`, 3 s, parallel, **only** on `device check` or `device list --probe` |

**RADIUS** sightings come from `tacctl-auth.log` (`client=` is the device; `.1` and `.N.gz` readable natively; resume by inode + offset, a shrink means re-read).

**TACACS+** sightings — three options:

| Option | Gives | Caveat |
|---|---|---|
| T1. Journal at **debug** (`prefix secret provider matches remote […]`) | address + time per packet | only at `level: 30`, which a fresh install does not run; noisy; no user |
| T2. **ERROR lines** (`bad secret detected for ip […]`, `no matching prefix …`) | wrong-secret / unknown-client discovery at any level | failures only |
| **T3. tacquito patch `0003`** | address, user, outcome, time at the default level, one line per authentication: in `bcrypt.go` include `tq.ContextConnRemoteAddr` from the request context on the `:143`/`:152` lines, e.g. `accepting user [jdoe] from [10.99.0.1] using a bcrypt password` | a third patch to carry against upstream [A: upstream activity is low]; `log search` output gains three words (release-notes line); no new volume |

**Recommendation: T3 + T2, with T1 understood as a fallback** (the scanner recognises all three shapes, so an unpatched install at level 30 still gets address-only sightings). The accounting log is not a source (wrong address). Journal access: `journalctl -u <units> -o json --since … [--after-cursor …]` through the runner (exec per the rewrite's §3.6 policy), units from the existing `_tacacs_journal_units`; the JSON gives `__CURSOR`, `__REALTIME_TIMESTAMP`, `MESSAGE`. journald retention bounds a `--full` rebuild (the dev server: four months [V]); `rotate 12` bounds RADIUS to 12 weeks; `device scan` prints the window it saw.

### 3.4 Seen cache, scan, discover, staleness

- `/var/lib/tacctl/devices-seen.json` (root 0600; **derived, rebuildable, never snapshotted** — a cache, so Decision 10 does not apply): per address `first`, `last`, `count`, `last_user`, `last_outcome`, `via`; per source a resume point; pruned after `2 × stale_days`; keeps addresses no scope covers (they are what `discover` shows).
- `device scan [--full] [--since <dur>] [--backend <id>]` refreshes incrementally and reports what it read. `device discover [--all]` scans, then lists unregistered addresses with scope, tag, first/last seen, count, last user/outcome and a ready `tacctl device add <nas-identifier-if-valid> <address>` line; `--all` includes addresses that only ever failed.
- `device list|show` **read the cache only** and print `seen data as of <time> (tacctl device scan to refresh)`; `list --scan` does both. Explicit beats a hidden `journalctl` inside a list command.
- `settings.stale_days` (default 30; `device stale-days [n]`) marks `stale`, bounds the default scan window and the pruning.
- Reachable: include **on demand only** (~60 lines); the AAA server often has no path to management ports, so a timeout is routinely a false alarm and the help text says so. Dropping it loses little.

### 3.5 Storage options and rollback

| Option | 0.1.16 rollback | Writes through | Verdict |
|---|---|---|---|
| **A. separate `devices.yaml`** + cache in `/var/lib/tacctl` | **unaffected** (0.1.16 never opens either) | own lock/atomic write; no render, no restart | **recommended, also for 0.3.0** |
| B. `store.yaml` section, `version: 2` | **blocked** (`store_validate` refuses unknown top keys/version, `store.sh:292-330` [V]); fails 0.2.0's own "no state-format change" gate | `store_apply`: snapshot, render all, restart — for data no backend reads | 0.3.0 at the earliest and only with a reason; none visible |
| C. keys in `tacctl.yaml` | tolerated on read [V]; `config validate` may complain [I] | `conf.Set` | no: a flat tunables file, not a record store |
| D. extend `linux-hosts` lines | 0.1.16 parses fields positionally (`:665-671`) — breaks `host sync` on rollback | `host_remember` | no; the 0.3.0 merge goes the other way (hosts into `devices.yaml`) |

---

### 3.6 Name notices: generic and duplicate names (decided 2026-10-03)

Requirement (user): when a device or host with a generic or duplicate name is registered, enrolled, or seen authenticating, tacctl shows a notice **with remediation steps**.

**Detection.**
1. *Duplicate registry name or address* — `device add`/`rename` refuse a name already taken, compared case-insensitively (`Core-SW1` vs `core-sw1`), and an address already registered under another name: `[ERROR] 'core-sw1' is already registered (10.1.2.3); choose another name, or see 'tacctl device show core-sw1'` / `[ERROR] 10.1.2.3 is already registered as 'core-sw1'; rename it with 'tacctl device rename core-sw1 <new>'`. Registry and enrolled-host names share one namespace for this check.
2. *Generic name at registration/enrolment* — `device add`, `device rename`, `device discover --add` and `host enroll` **refuse** a name matching the generic list (factory and image defaults, case-insensitive: `switch`, `router`, `switch\d*`, `router\d*`, `cisco`, `juniper`, `wti`, `default`, `localhost`, `localhost.localdomain`, `ubuntu`, `debian`, `raspberrypi`, `ip-\d+-\d+-\d+-\d+`, …; the list is data in the package, extensible in `devices.yaml` `generic_names:`) with the remediation steps below; `--allow-generic` registers it anyway, and the device then carries a standing `generic-name` notice. Hosts already enrolled under a generic name before 0.2.1 are not refused retroactively; they get the notice.
3. *Seen at authentication* (by `device scan`/`discover`, from the seen cache of §3.4):
   - `ambiguous-nas-id` — one RADIUS NAS-Identifier sent from more than one client address;
   - `generic-nas-id` — a NAS-Identifier on the generic list (e.g. a device still called `Router` sending that as its identity);
   - `name-mismatch` — a registered device whose NAS-Identifier differs from its registry name (informational);
   - `duplicate-address` — one address answering for two registry entries' identities (TACACS+ carries no device name, so this — via patch 0003's NAS address — is the only TACACS+-side name notice).

**Where notices appear.** The output of `device scan`/`discover` (after the scan), a `Device notices` section in `tacctl status` (beside "Password Age Warnings"; counts plus the first five, `tacctl device notices` for all), a `NOTICES` column in `device list`, and `device show <name>` (which also lists acknowledged ones). Notices are computed, not stored, except acknowledgements.

**Remediation text** (per vendor profile; exact device syntax verified in the 0.2.1 lab acceptance, [A] until then):
- Cisco IOS/IOS-XE: `hostname <name>`, and so RADIUS carries it, `radius-server attribute 32 include-in-access-req format %h`;
- Junos: `set system host-name <name>` (NAS-Identifier follows the host name [A]);
- WTI: set the Site ID / unit name in the `/N` network menu [A: menu item varies by firmware];
- Linux hosts: `hostnamectl set-hostname <name>`, then `tacctl host sync <host>`;
- then align the registry: `tacctl device rename <old> <new>` (new verb), or `--allow-generic` to keep a lab name deliberately.
Every notice line ends with the one command that fixes or acknowledges it.

**Acknowledgement.** `tacctl device notice <name> ack <kind>` records an accepted notice in `devices.yaml` (`ack: [<kind>, …]` on the device); `unack <kind>` removes it. Acknowledged notices disappear from `status` and `device list` but stay visible, marked, in `device show`. `ack` is per device and per kind (two units deliberately sharing a NAS-Identifier are acknowledged on each). Superuser only, like other registry writes.

### 3.7 Identity by IP; host-key pinning and change detection (decided 2026-10-03)

Requirement (user): identify devices by IP, with detection of host and fingerprint changes.

**IP as identity.** An address is registered at most once (§3.6). Everywhere a device name is accepted, its registered address is too: `tacctl ssh 10.1.2.3`, `device show 10.1.2.3`, notices and scans resolve an address to its device. An unregistered address stays refused, because the registry is the allow-list of §5.1/§6.5. Scans keep, per address, the last NAS-Identifier seen in the seen cache (§3.4). When it changes, they raise `identity-changed` (`10.1.2.3 now identifies as 'Router' (was 'core-sw1') — replaced or reset? verify, then 'tacctl device notice core-sw1 ack identity-changed'`), which catches a swapped or factory-reset unit before any ssh.

**Host-key pinning (decided: scan-and-pin at registration).**
- `device add` runs `ssh-keyscan -T 5 -p <port> -t ed25519,ecdsa,rsa <address>` (through the runner, as root; outbound only, no authentication). It pins every key returned in `devices.yaml` (`host_keys: [<type> <base64>, …]`; public keys are not secret) and prints each `SHA256:` fingerprint with "compare with the device console before first use", plus the per-vendor command below.
- `--host-key SHA256:<fp>` registers only if a scanned key matches that fingerprint, otherwise it refuses.
- `--no-host-key` registers unpinned and leaves a standing `hostkey-unpinned` notice. A device that does not answer at registration is refused unless `--no-host-key` is given.
- Legacy IOS (`legacy-ssh`) is scanned with `ssh-rsa` allowed.
- Enrolled Linux hosts get their keys pinned at `host enroll`/`sync`, which already connect to the host.

**Enforcement (decided: refuse until re-pinned).**
- `tacctl ssh` (and the console) connects with `-o UserKnownHostsFile=<tacctl-generated known_hosts> -o StrictHostKeyChecking=yes -o HostKeyAlias=<name> -o UpdateHostKeys=no`. The known_hosts file is root-owned, 0644, regenerated from `devices.yaml` on every registry write, and lists only the pinned keys.
- A mismatch is refused by ssh itself. tacctl recognises the failure and prints the pinned and offered fingerprints, the verification command for the vendor, and the fix: `tacctl device hostkey <name> accept` (superuser; re-scans and re-pins after the operator has verified on the console) or `… hostkey <name> set SHA256:<fp>`.
- No in-session override exists, inside or outside the console.
- `device ssh-config` emits the same `UserKnownHostsFile`/`HostKeyAlias`/`StrictHostKeyChecking yes` lines, so plain `ssh <name>` is protected the same way.

**Change detection at scan time.** `device scan`/`check` re-scan each registered device's keys and compare:
- `hostkey-changed`: the pinned key is not among the offered ones. This notice **cannot be acknowledged**; only `hostkey accept|set` clears it, and the pin is never updated silently.
- `hostkey-added`: an additional key type appeared, pinned keys unchanged. Informational, ackable, `hostkey accept` pins it.
- `hostkey-unpinned`.
- `hostkey-unreachable`: no answer, carrying the last good scan time.

They appear with the other device notices (§3.6: scan output, `status`, `device list|show`).

**Verification commands in the remediation text** ([A] until the 0.2.1 lab acceptance):
- Cisco IOS/IOS-XE: `show ip ssh`, `show crypto key mypubkey rsa` (fingerprint form varies by release)
- Junos: `show system ssh host-key` [A], or `file show /etc/ssh/ssh_host_ed25519_key.pub` from the shell
- WTI: per firmware [A]
- Linux: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`

**Permissions.**
- `device hostkey … accept|set` and `--no-host-key`: superuser.
- Scans: operator+, as in §8.
- Every tier sees the notices for its own scopes.

## 4. Part B — shell mode (go-rewrite §8 and Decision 13, revisited)

### 4.1 What it is

`tacctl shell` (never bare `tacctl` on a TTY: that prints usage and exits 1, and scripts depend on it) opens `tacctl> ` where each line is a tacctl command without the prefix. Sub-commands, flags and live names complete from the cobra tree and the `_completion-names` bridge; `help [verb]` prints the family's usage block (the same text as `tacctl <family>`); `exit`, `quit`, Ctrl-D leave; `history` lists; `!` and shell metacharacters mean nothing. Lines are tokenised by the shell's own splitter (POSIX-style quotes, no expansion, no globbing, no pipes); the tokens go to the same `args.Parse` specs as the CLI, so messages and exit codes are identical, and `[exit 3]` is shown after a non-zero command.

### 4.2 Privilege: the shell never holds it

go-rewrite §8 sketched "one sudo re-exec at `tacctl shell` start, the session runs as root, tier re-evaluated per command". This proposal **inverts it**: the shell runs as the invoking user and executes each line as `sudo [-n] /usr/local/bin/tacctl <tokens>` (through the runner, tty inherited). Consequences:

| | root session (§8 sketch) | **unprivileged shell (recommended)** |
|---|---|---|
| Who holds privilege | the long-lived shell process (root) | nobody; each line is a short root child under sudo's own policy |
| Tier gate | re-evaluated per line inside the shell | sudoers globs **and** the in-tacctl gate on every line, exactly as from bash |
| Audit | shell adds `logger` lines | sudo's own `COMMAND=` log line per command for free, plus tacctl's existing `logger` lines |
| `ssh <name>` | needs `sudo -u $SUDO_USER -H env SSH_AUTH_SOCK=…` (the `host` plumbing, `SETENV` caveat) | plain `ssh` as the user; agent socket already in the environment |
| History file | must be written as `SUDO_USER` from a root process | the user's own file, naturally |
| Ctrl-C | must be forwarded to the child's process group | child in the foreground process group gets it; the shell survives |
| Prompts, masked passwords | child owns the tty: fine either way | fine |
| Cost | none per line beyond the fork | one `sudo` per line: ~10 ms, and a password prompt for admins when sudo's timestamp has expired (sudo caches it, default 15 min); tier users have `NOPASSWD` rules |
| Reuse | shell only | **the same loop is the login console** (§6) |

The user's sudo rights decide what the shell can do, as they do at a bash prompt. For a tier-managed user the shell can pre-check the tier table and print the denial itself (saves a `sudo: a password is required` from `-n`), with the in-tacctl gate as the real control. The one thing `tacctl shell` needs in sudoers for tier users is nothing new: it runs as the user; only the lines it issues go through sudo. (If the user later prefers the root-session design for the *interactive* shell, the login console must still be the unprivileged one — §6.2.)

### 4.3 Details

- **Completion:** sub-commands, flags and values from the cobra tree + `args.Parse` specs (one source of truth with the CLI, Decision 2); live names (`users`, `groups`, `scopes`, `hosts`, `devices`, `backups`, `backends`, `listeners`) via `sudo -n tacctl _completion-names <kind>` in-process-cached for a few seconds per kind; a caller without a rule gets words-only completion, as with the bash file.
- **Help:** `help` → the top-level usage; `help scope` → the scope block; `help scope prefixes` → that nested block — the `SetHelpFunc` texts of §3.2.
- **History:** `~/.local/state/tacctl/history` (0600, 1,000 lines) of the invoking user; **redaction:** a line whose tokens contain `--secret`, `--hash`, `secret set`, `secret <s> set`, `import` with a value, or whose family is `passwd` is stored as `<family> <verb> …(redacted)`; `tacctl shell --no-history`.
- **Ctrl-C:** cancels the running line's child, redraws the prompt; at an empty prompt prints `^C` (does not exit — `exit`/Ctrl-D do). Ctrl-Z is ignored (no job control).
- **Prompts and passwords:** the child owns the tty, so `[y/N]` prompts and `read_password_masked`-style input work unchanged; the shell does not pre-read stdin.
- **`SSH_AUTH_SOCK`:** untouched — the shell is the user, `ssh` inherits it.
- **Non-TTY / batch:** `tacctl shell < file` and `tacctl shell -c "<line>"`: run lines in order, no prompt, no history, stop at the first non-zero status and return it; prompt-feeding (`echo y |`) is not possible inside a batch (stdin is the script) — documented; use `-y` flags where they exist.
- **Libraries:** `reeflective/console` + `reeflective/readline` derive menus and completion from a cobra tree [V web search, go-rewrite §8]; lighter readlines (`chzyer`, `peterh/liner`) need hand-wired completion and have uncertain maintenance [A]. The console mode (§6) adds requirements — no job control, no editor spawning, bounded line length, idle timer — that any choice must satisfy; a pty test (`creack/pty`) drives prompt, completion, Ctrl-C and timeout in CI.
- **Idle timeout:** `--idle <min>` (default from `console idle-timeout`, §6.8); a timer on input ends the shell with `idle timeout` when no child is running.

### 4.4 Pros and cons (interactive shell alone)

Pros: faster operator loop; completion without the bash file; batch mode; one implementation that §6 reuses. Cons: a second entry point to document (README, man, completion), one more dependency cluster to vendor and patch, a pty test harness, and sudo's per-line prompt for admins without `NOPASSWD` (mitigated by sudo's timestamp). Not a security boundary by itself — admins have bash anyway.

---

## 5. Part C — `ssh <name>`

### 5.1 Verb and resolution

`tacctl ssh <name> [-l <login>] [-p <port>]` at top level (`device ssh` is an alias); in the shell, `ssh <name> …`. The name is a registered device or an enrolled host; a raw address is refused (`not a registered device; register it: tacctl device add <name> <address>`), because the registry is the allow-list the console relies on (§6.5) and the same rule everywhere avoids two behaviours. Resolution: `hostname` if set else `address` (a host's `target` as is), port, login, vendor profile, legacy-ssh. Tier-managed callers may only reach devices whose derived scope is in their `scopes` (`'jdoe' has no access to scope 'prod' (device core-sw1)`).

### 5.2 Vendor profiles

| vendor | options | Why |
|---|---|---|
| `wti` | `-o PreferredAuthentications=password -o PubkeyAuthentication=no` | the README's own advice for WTI units (a key attempt first can leave the unit closing the session when its lockout is armed; units hold no user keys) [V README] |
| `cisco` + `legacy-ssh` | `-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa` | old IOS offers only SHA-1 kex and `ssh-rsa`; `+` appends, so modern IOS-XE still negotiates the strong set [A: option names vary by OpenSSH version; untested on hardware, like every device config in this repo] — hence **opt-in per device** |
| `juniper`, `linux`, `other` | none | current OpenSSH on the far end |
| always | `-o ConnectTimeout=10` | as `_host_ssh` |

No stored free-form ssh options: that is `~/.ssh/config`'s job, and `device ssh-config` (§5.4) hands the user a `Host` block to extend. Outside the console, `tacctl ssh <name> -- <ssh args>` passes extra arguments for one session; **inside the console this passthrough does not exist** (§6.5).

### 5.3 Who runs ssh

- **In the shell and the console:** the shell process is the user; it execs `ssh` directly. No sudo, no `SSH_AUTH_SOCK` plumbing, nothing to drop.
- **`tacctl ssh <name>` from bash:** the first word is not `hash`, so the front door re-execs under sudo (the registry is root-only). `sudoArgv` adds `SSH_AUTH_SOCK=…` for `ssh`/`device` as it does for `host`; root resolves the name, applies the tier gate, writes `logger -t tacctl -p auth.info "ssh user=<caller> device=<name> addr=<address>"`, then runs `sudo -u <caller> -H env SSH_AUTH_SOCK=… ssh …` with the tty inherited and returns ssh's status (the `AsUser` runner of WP3.2; SIGINT ignored while the child owns the terminal, go-rewrite §3.5). `SUDO_USER` empty or `root` → `tacctl ssh runs ssh as the user who invoked it; run it from your own account, not as root` (no `--as-root`). The opt-in `NOPASSWD` rule's missing `SETENV` bites here as it does for `host`; `config sudoers install` could add `SETENV:` to its rule in the same release (one word; also fixes `host` for those users) — Decision 12.
- Alternative considered: a sudo-free `tacctl ssh` that fetches parameters through a hidden `sudo -n tacctl _device-resolve <name>` (like completion). Fewer prompts, a second privilege path to audit; not recommended while the `host` mechanism exists and the shell covers the no-sudo case.

What tacctl never does: pass a password, write into the user's `~/.ssh`, set `StrictHostKeyChecking=no` or `UserKnownHostsFile=/dev/null`, put a secret on argv (the Go argv-recorder test covers `ssh`), use `BatchMode` (a session without a tty is an error).

### 5.4 `tacctl device ssh-config`

Prints an `ssh_config` fragment for the caller's devices (tier-filtered) to stdout, and on stderr the two-line install hint (`> ~/.ssh/tacctl.conf`, then `Include ~/.ssh/tacctl.conf` at the **top** of `~/.ssh/config`, since an `Include` after a `Host` block belongs to that block):

```
# Generated by tacctl device ssh-config on the dev server, 2026-10-03. Re-run after registry changes.
Host core-sw1
    HostName 10.99.0.1
    KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
Host oob-con1
    HostName 10.99.0.9
    PreferredAuthentications password
    PubkeyAuthentication no
Host web1
    HostName web1.example.net
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_web1
```

Then `ssh core-sw1` works and bash-completion completes `ssh core<TAB>` from the `Host` lines (bash-completion 2.11 on the dev server follows `Include` [A: verify]). `User` only for a `login` override. Print-only: no root process writes into a user's home (a `--install` running as the invoking user is a later convenience). The same generator, written to a root-owned file, is the `-F` config the console uses (§6.5) — one piece of code, two consumers.

---

## 6. Part D — the console as a login shell

**Threat model.** The console's users are TACACS+ users of the readonly and operator tiers (and superusers if opted in) who authenticate to the tacctl server with their network password. Without the console they get `/bin/bash` on the server today (`client-install.sh:616-618`) with whatever sudo the tiers file grants — i.e. a full shell on the AAA server, read access to anything world-readable there, outbound connections anywhere the server can reach. The console's goal is to **shrink that**: tacctl verbs the tier allows, `ssh` to registered devices in the user's scopes, nothing else — while not weakening what superusers and local administrators have. The security analysis therefore asks, for each avenue, "can a console user get more than those two things?"

### 6.1 What a console user gets

```
$ ssh jdoe@devserver
Password:                      ← TACACS+ via pam_tacplus (as today)
tacctl console on the dev server — type 'help'. Devices: tacctl device list. Session is logged.
devserver> device list
devserver> ssh core-sw1
core-sw1 login: jdoe … (TACACS+ on the device) … exit
devserver> log failures            ← operator tier only; readonly gets the tier denial
devserver> exit
```

The console is `tacctl shell` (§4) started in **console mode**: same prompt, completion, help, history and batch rules, plus the restrictions of §6.5. Console mode is selected by the binary's name: `/usr/local/bin/tacctl-console` is a symlink to the real binary [I: `os.Executable()` resolves symlinks — the Go code reads `os.Args[0]` for this, including the login-shell form `-tacctl-console`]. A separate name keeps `tacctl` itself out of `/etc/shells` and makes `ps`/`last`/audit lines self-explanatory.

### 6.2 Privilege model

The console process is the user's login shell: unprivileged. Each line becomes `sudo -n /usr/local/bin/tacctl <tokens>`; `ssh <name>` becomes `ssh -F /etc/tacctl/console/ssh_config …` as the user. The sudoers tiers file (`%tac-readonly … NOPASSWD: TACCTL_RO`, etc. [V]) and the in-tacctl tier gate decide what each line may do, exactly as when the same user types `sudo tacctl …` at bash today; a line outside the user's alias is refused by sudo with `-n` (the console translates `sudo: a password is required` into the tier denial text after consulting the table itself). The console needs no privilege and no sudo rule of its own. The sudo re-exec inside tacctl is unaffected: the child *is* `sudo tacctl`, so `needsSudo` is false (EUID 0) and `SUDO_USER` is the console user — the gate sees exactly what it sees today.

This is the reason §4.2 recommends the unprivileged design for the interactive shell too: one loop, one set of tests, one audit trail.

### 6.3 How accounts get it

- **Where:** only on the tacctl server (the host enrolled with `host enroll --local`): the console runs `tacctl` against the local store. Other enrolled hosts have no store; a console there is meaningless, so the installer emits the shell field only for the local target.
- **Opt-in, following the convention:** `tacctl console tiers enable <csv>|disable <csv>` (tiers whose users get the console; nothing on until enabled; a new install has none), and `tacctl console user <u> enable|disable|clear` as the per-user override (`clear` returns the user to the tier rule). `console show` prints the effective shell per user. Stored in `/etc/tacctl/console.yaml` (same discipline as `devices.yaml`; additive, ignored by 0.1.16): `tiers: [readonly, operator]`, `users: {jdoe: disable}`, `settings: {idle_timeout: 30, agent_forwarding: false, accounting: journal}`. (A store field `users.<u>.console` would be a schema change — 0.3.0; `tacctl.yaml` keys are possible but mix tunables with per-user records.)
- **Provisioning:** `host enroll --local`/`host sync <server>` pass a fourth field in `TAC_USERS` (`name:tier:uid:shell`, shell = `/usr/local/bin/tacctl-console` or `/bin/bash`), and `client-install.sh` uses `-s "$shell"` on `useradd` and `usermod -s` on an existing account whose shell differs (both only for the tacctl-created or adopted accounts it already manages). Server and script ship together, so the field is a protocol change between two things of the same version, not a state format; the registry line is unchanged. `sync` applies a changed opt-in the same way account changes are pushed today (manually, no timer [V memory]). The installer adds `/usr/local/bin/tacctl-console` to `/etc/shells` when it writes the shell (and removes the line on unenroll when no account uses it) — listing is the convention for restricted shells and keeps `pam_shells`-style checks happy [A: nothing on the dev server uses `pam_shells`; sshd does not consult `/etc/shells`].
- **Which tiers may get it; may a tier keep a normal shell?** The console is a *restriction*, so it applies where restriction means something: readonly and operator. Superusers have `%tac-superuser ALL=(ALL:ALL) ALL` in the tiers file [V], so a console for them is cosmetic — recommended default `console tiers enable readonly,operator`, superusers excluded unless the user enables that tier too (then it is a convenience, not a boundary, and the help text says so). A tier can stay on bash by not being enabled; a single user can be excepted with `console user <u> disable` (e.g. an operator who maintains the server).
- **Break-glass:** local administrators (not in `tac-users`) are never touched by the installer (README) [V], root is untouched, the installer refuses to run when no local administrator with a usable password exists [V README], and `console user <u> disable` + `host sync` gives any one user bash back. A console user who needs bash temporarily does not get it from the console: that is the point.

### 6.4 Login shell vs `ForceCommand`

| | login shell `tacctl-console` (recommended) | sshd `Match Group tac-console` + `ForceCommand tacctl-console` |
|---|---|---|
| Applies to | every login path: sshd, console `login`, `su`, graphical logins (they all exec the account's shell) | sshd only; a tty login on the server's console, `su jdoe` or a display manager still gives bash |
| Requires | `/etc/shells` entry; `useradd -s`; handling `-c` (§6.5) | an sshd drop-in; nothing on the account |
| sftp/scp | both end up in the shell with `-c` (sshd runs `$SHELL -c '<command>'` for commands and for the sftp subsystem [V `sshd -T`: `subsystem sftp /usr/lib/openssh/sftp-server`]) → refused by the console either way | same |
| Port forwarding, X11, agent | **neither** form controls these: they are sshd channel features, independent of what the shell is → the sshd drop-in is needed in both cases | same |

**Recommendation: the login shell, plus an sshd drop-in `/etc/ssh/sshd_config.d/tacctl-console.conf` written by the installer** (`Match Group tac-console` → `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `AllowAgentForwarding no` unless `settings.agent_forwarding`, `PermitTunnel no`, `PermitTTY yes`, `ClientAliveInterval 300`, `ClientAliveCountMax 2`; no `ForceCommand` — the shell is already the command). The group `tac-console` is added by the installer to accounts that get the console (so the `Match` follows the opt-in exactly). sshd is reloaded after `sshd -t` validates the drop-in, the same pattern as `visudo -cf` for sudoers; a failed validation removes the drop-in and reports. Debian's `sshd_config` includes `sshd_config.d/*.conf` by default; the RHEL family too [A: confirm the include line exists on each supported family, as the client script already probes families].

### 6.5 Restricting the console

| Avenue | How it is closed |
|---|---|
| **Shell escapes** | The console starts exactly two programs: `sudo -n /usr/local/bin/tacctl …` and `ssh -F <root-owned config> …` (absolute paths, fixed environment: `PATH=/usr/bin:/bin`, no `ENV`/`BASH_ENV`/`LD_*`; the login environment is discarded except `TERM`, `LANG`, `SSH_*`). No pipes, redirections, globbing, variables, backticks: the tokenizer knows quotes and nothing else; unknown first words are `unknown command`; `!` is not history expansion. No `$EDITOR`, no pager (`log tail` output is streamed; `less` is never spawned). |
| **`-c` (sshd commands, scp, sftp, rsync)** | `tacctl-console -c '<string>'` is accepted **only** when the string tokenises to one console line (`ssh devserver 'user list'` works and is logged as such); anything else — `scp -t`, `sftp-server`, `rsync --server`, chained commands — is refused with `the tacctl console does not run programs; file transfer is not available` and exit 126. So console accounts cannot move files in or out of the server. |
| **What `ssh` may reach** | Names from the registry/hosts **in the user's scopes** only; no raw addresses, no `-o`, no `--` passthrough, no `-J`, no `-W`, no `-L/-R/-D`; the only user-supplied values are the name, `-l <login>` and `-p <port>`, each validated. The client config is a **root-owned `-F /etc/tacctl/console/ssh_config`** generated from the registry (the §5.4 generator), so the user's `~/.ssh/config` (which they cannot write anyway — no shell, no scp — but an administrator might have left one) is never read: no `ProxyCommand`, no `LocalCommand`, no `Match exec`. The generated file sets `PermitLocalCommand no`, `ProxyCommand none`, `ControlMaster no`, `ForwardAgent` per setting, `UserKnownHostsFile ~/.ssh/known_hosts` (so the user's first connection still asks and pins the key), `StrictHostKeyChecking ask` — the one interactive question that is not a tacctl prompt. |
| **ssh client escapes (`~C`, `~.`)** | `~C` can request `-L/-R/-D` forwardings from the *client* side; with `PermitLocalCommand no`, `!cmd` is unavailable [V OpenSSH ssh(1) semantics; version on the dev server 9.6]. Those forwardings would originate from the server to the device network — the ssh client enforces nothing here, so the console passes `-o EscapeChar=none` by default (`settings.ssh_escape` to re-enable `~.` for hung sessions, at the cost of `~C`). |
| **Agent forwarding** | Default off in the sshd drop-in (`AllowAgentForwarding no`), so a forwarded agent never appears in the console session and `ssh` to devices is password-only (which is what TACACS+/RADIUS logins are). `console agent-forwarding enable` turns it on for sites that want key logins to Linux hosts — knowing that a key login on an enrolled host bypasses TACACS+ (pam_tacplus's account phase cannot run for key logins [V memory]). |
| **Port forwarding, X11, tunnels, sftp subsystem** | sshd drop-in (§6.4). The console cannot do this itself; without the drop-in a console user could `ssh -L 2222:core-sw1:22 jdoe@devserver` and bypass the registry entirely — **this is the single most important line of the design**, and `console show` warns loudly when the drop-in is missing or sshd's effective `allowtcpforwarding` for the group is still `yes` (`sshd -T -C user=<u>` through the runner). |
| **Local privilege** | The console's sudo lines are the tiers aliases; `sudo -n` never prompts; nothing in the console exposes `sudo` itself or any other binary. A superuser on the console has `(ALL:ALL) ALL` by tier policy and could `sudo -i` from bash — but the console has no `sudo` verb, so even a superuser gets only tacctl and `ssh` *while in the console*; their escape is to disable the console for themselves (or a local administrator does it). |
| **Resource abuse** | Line length cap (4 KiB), history cap, one child at a time, idle timeout (§6.8), sshd `ClientAlive*`; no background jobs. |
| **Information leakage** | The console prints only what `tacctl` prints for that tier (secrets/hashes are superuser-only today [V]) and ssh's own output; `device list`/`ssh-config` are scope-filtered; the generated `-F` config is readable by the console group but contains no secrets. |
| **Terminal injection** | Output of child processes goes to the user's terminal as today; the console does not interpret it. |

Residual risks (honest list): a bug in the tokenizer or in the `-c` filter is a shell escape — mitigated by a small, table-driven tokenizer with a fuzz test and by the fact that even an escape lands in an unprivileged account with the tier's sudo rights (the same account that has `/bin/bash` today). ssh itself is a large program run with user-controlled `-l`/`-p` values and a root-owned config: validation of those two values is strict (`-l` a username regex, `-p` 1–65535). A device reached by `ssh` is a full shell on *that* device, as intended.

### 6.6 sudo re-exec and tier gate for a login shell

Nothing changes in tacctl: every console line is `sudo -n tacctl …`; sudoers decides whether to start it (tiers aliases, `NOPASSWD`), tacctl's front door sees EUID 0 and does not re-exec, `enforce_tier` reads `SUDO_USER` and the model as today. Tier users have no local password [V memory], so `-n` is the only sensible mode and a non-matching line simply fails — the console reports it as a tier denial. The sudoers tiers aliases gain the §8 rows (`ssh *`, `device list|show|ssh-config`, …); the release notes say to re-run `tacctl config sudoers tiers install` (the file is not refreshed on upgrade — parity).

A disabled or removed user is denied at the next line (`none` tier) and, since pam_tacplus's account phase refuses them, at the next login; `host sync` expires the local account (`usermod -e 1`, `client-install.sh:646`) [V].

### 6.7 Session logging and accounting

| Layer | Exists today | With the console |
|---|---|---|
| Login/logout of the SSH session | pam_tacplus session START/STOP to tacquito (`accounting.log`, `User`, `cmd=login/logout`) [V memory]; sshd's own journal lines | unchanged |
| Each tacctl command | sudo's `COMMAND=/usr/local/bin/tacctl …` line in the auth log/journal; tacctl's `logger` lines for mutations and tier denials [V] | unchanged, and now **every** line of the session is one of these (there is nothing else to run) |
| `ssh <name>` sessions | — | `logger -t tacctl-console -p auth.info "ssh user=<u> device=<name> addr=<a> start"` and `… end status=<n> duration=<s>`; the device's own TACACS+ accounting records what was done there |
| Console session itself | — | `console start user=<u> from=<client ip> tty=<pts>` / `console end reason=exit|idle|hangup lines=<n>` |
| **Per-line TACACS+ accounting** (optional) | — | the console asks tacquito to account each line as the user: `Acct START/STOP` with `service=shell`, `cmd=<line>`, `rem_addr=<client ip>`, `port=console`, using the library client (`client.go` [V]) against the local listener with the server's own scope secret. The console runs as the user and cannot read the secret, so the privileged side does the sending: `sudo -n tacctl _console-acct <session-id> start|stop <line>` (hidden, in `TACCTL_RO`), or the root-side `tacctl` emits it when it is invoked from a console session (sudo passes no environment, so the marker must be an argument: `tacctl --console <session-id> user list`, stripped before dispatch). This puts console lines into the same `accounting.log` the devices write to, so `log accounting` shows them with everything else. Cost ≈ 400 lines incl. RFC 8907 framing via the vendored library [A: vendoring `github.com/facebookincubator/tacquito` as a module is possible; it is what tacctl builds anyway]. |

**Recommendation:** journal-based logging (sudo + console `logger` lines) in the first version; the TACACS+ accounting option as a `settings.accounting: journal|tacacs` switch in a follow-up once the console is in use. `tacctl log search <user>` covers both, since it already greps the journal.

### 6.8 Idle timeout

`console idle-timeout [min]` (default 30, `0` disables) — a timer in the readline loop that ends the session (`idle timeout after 30 min`, logged) when no line is running; during an `ssh` session the device's own timeout applies (the scope's `exec-timeout` renders it into device configs today [V README]) and the console's timer is paused. The sshd drop-in's `ClientAliveInterval 300 / CountMax 2` is the safety net for dead connections.

---

## 7. Command surface, output, completion

README conventions throughout: dispatcher with no sub prints usage and exits 0 (like `scope`/`host`); filters `set|clear`; opt-ins `enable|disable`; scalar getter/setters show the value with no argument and take `clear` to unset an optional one; destructive verbs confirm and cancel on closed stdin.

```
tacctl ssh <name> [-l <login>] [-p <port>] [-- <ssh args>]      Session to a registered device or enrolled host, as you (never root)
tacctl shell [--no-history] [--idle <min>] [-c <line>] [< file]  Interactive prompt; batch when stdin is not a terminal

tacctl device                                                     Usage, exit 0
  list [--stale] [--unconfigured] [--probe] [--scan] [--json]
  show <name> [--json]
  add <name> <address> [--vendor cisco|juniper|wti|other] [--hostname <dns>] [--port <n>] [--login <user>] [--description <text>]
  remove <name>[,<name>…] | --all                                  Confirms; never touches hosts or scopes
  rename <old> <new>
  address|hostname|vendor|port|login|description <name> [<value>|clear]   One scalar getter/setter per field
  legacy-ssh <name> [enable|disable]                               Opt-in: legacy IOS ssh algorithms
  stale-days [<n>]
  check <name>|--all                                               Checklist: scope, tag, seen, reachable (probes)
  scan [--full] [--since <dur>] [--backend <id>]                   Refresh the seen cache
  discover [--all] [--backend <id>]                                Scan, then list unregistered addresses that authenticated
  ssh-config                                                       ssh_config Include block for your devices
  import [--check] [--replace] <file|->  /  export [--csv|--json]
  ssh <name> …                                                     Alias of 'tacctl ssh'

tacctl console                                                    Usage, exit 0
  show                                                             Tiers enabled, per-user overrides, effective shell per user, sshd drop-in status, warnings
  tiers [enable|disable <csv>]                                     Opt-in per tier (readonly, operator, superuser); nothing on until enabled
  user <u> [enable|disable|clear]                                  Per-user override of the tier rule
  idle-timeout [<min>]  ·  agent-forwarding [enable|disable]  ·  ssh-escape [enable|disable]  ·  accounting [journal|tacacs]
  install | remove                                                 Write/remove the sshd drop-in and the /etc/shells line (also done by host enroll --local / sync)
```

Two new top-level words beyond `device`/`console`: `ssh` and `shell`; all four are words the 0.1.16 dispatcher answered with usage/exit 1, so nothing existing changes meaning. `_completion-names` gains `devices` (registry + hosts, tier-filtered) and `hosts`.

`device list` (fixed-width `printf`, the suite's style):

```
Registered devices (4) and enrolled hosts (2)
--------------------------------------------
  NAME        ADDRESS      VENDOR   SCOPE        STATE         LAST SEEN            BY       VIA
  core-sw1    10.99.0.1    cisco    prod         configured    2026-10-02 14:03     jdoe     tacacs
  oob-con1    10.99.0.9    wti      prod         configured    2026-09-01 09:12     asmith   radius   stale
  lab-rtr2    192.0.2.7    juniper  -            unconfigured  never                -        -
  edge-fw     10.99.3.1    other    prod         configured    rejected 2026-10-03  -        tacacs   bad secret
  web1        10.99.5.20   linux    linux-web1   configured    2026-10-03 08:11     jdoe     tacacs   host
  client      10.99.5.22   linux    lab          configured    2026-10-03 07:40     jdoe     tacacs   host

  seen data as of 2026-10-03 08:15 (tacctl device scan to refresh); stale after 30 days
```

Completion: `tacctl ssh <TAB>`, `device show|…|check <TAB>` and, in the shell, `ssh <TAB>` → `ValidArgsFunction` → `sudo -n tacctl _completion-names devices` (filtered to the caller's scopes under the tier gate, so completion never offers a name the caller could not list); `--vendor` the enum; `console user <TAB>` → `users`; plain `ssh <TAB>` outside tacctl → the shell's own completion over the Include file (§5.4).

---

## 8. Permissions

| Verb | unrestricted / superuser | operator | readonly | `none` |
|---|---|---|---|---|
| `ssh <name>`, `device list|show|ssh-config`, `_completion-names devices|hosts`, `shell` | all devices | **own scopes only** | own scopes only | denied |
| `device check|scan|discover|export`, `console show` | yes | yes (log reading is operator-level today) | no | denied |
| `device add|remove|rename|<setter>|stale-days|import`, `console tiers|user|<setting>|install|remove` | yes | no | no | denied |

"Own scopes only" reuses `model.User(caller).Scopes`. The device list is no more sensitive than `scope list`, which readonly users already have [V]; names and activity are new but modest, and the people who most need `ssh <name>` are exactly the readonly/operator users — denying them would defeat the console. `device discover` reveals every address talking to the server, including other scopes', hence operator-level like `log tail`.

`emit_tier_sudoers` gains, in `TACCTL_RO`: `${t} ssh *`, `${t} device list`, `${t} device list *`, `${t} device show *`, `${t} device ssh-config`, `${t} _console-acct *` (if §6.7's option is taken); in `TACCTL_OP`: `${t} device check *`, `${t} device scan`, `${t} device scan *`, `${t} device discover`, `${t} device discover *`, `${t} device export`, `${t} device export *`, `${t} console show`. `tiers.bats` keeps table and file in step. `shell` and `tacctl-console` themselves need no sudoers entry (they run as the user).

---

## 9. Release placement

Constraints: 0.2.0 is a parity release (go-rewrite Decision 10: no state-format change; §6.6 gate measures parity; risk 9 "scope creep"); the rewrite is mid-Phase 2 (WP2.1 done) with Phases 3–5 ahead (≈ 17 sessions remaining of ≈ 31); the user has accepted every Decision 13 recommendation so far ("shell mode deferred to 0.2.x").

What each part touches in parity terms: A/B/C/D add **files** (`devices.yaml`, `console.yaml`, a cache, an sshd drop-in, an `/etc/shells` line), **verbs** (four top-level words, three families), **one tacquito patch** (changes two journal lines), a **client-script protocol field** (`TAC_USERS` fourth field; `useradd -s`), **sudoers tiers rows** and **`_completion-names` kinds**. None changes an existing file's format, so Decision 10 holds in letter; in spirit, every one is a new behaviour the differential runner must exclude and the release gate must additionally test.

| Option | Content | Cost to the 0.2.0 date | Risk | Verdict |
|---|---|---|---|---|
| **(a) phases after the parity proof in 0.2.0** | WP4.3 (parity proof) → new Phase 4b: A, B, C, D → WP5.x live acceptance (now also covering shell, console, sshd drop-in on the dev server and the test client) → release | **+14–17 sessions ≈ +4–6 weeks** at the plan's pace; the gate gains ~10 items (shell completion/Ctrl-C/batch/history redaction; console `-c` filter, forwarding check, `/etc/shells`, break-glass; registry rollback test) | the release whose point is "same as 0.1.16" ships with its largest-ever feature and a new login-shell security surface; one gate for two unrelated kinds of risk; a parity regression found late competes with console bugs for the same release | not recommended |
| **(b) 0.2.x right after 0.2.0** | 0.2.0 as planned → `0.2.1`: A + B + C (registry, shell, `ssh`) → `0.2.2`: D (console) → optional `0.2.3`: TACACS+ accounting for console lines, `linux-hosts` merge deferred to 0.3.0 | **none** | the door must be kept open during Phases 2–4 (§9.3) — cheap and listed; the shell lands ~2–3 weeks after 0.2.0, the console ~3–4 weeks after that | **recommended** |
| (c) split: B + C in 0.2.0, A and D later | shell and `ssh <name>` with names from `linux-hosts` only (no registry yet) in 0.2.0; registry and console in 0.2.x | **+4–5 sessions ≈ +1–2 weeks**; `ssh` without the registry only reaches enrolled hosts, which makes the first version of `ssh <name>` underwhelming and the release notes awkward ("devices come later") | a readline dependency cluster enters the parity release; the shell's pty tests join the gate | possible if the user wants the shell in hand sooner; otherwise (b) |

**Recommendation: (b).** Nothing in A–D makes 0.2.0 better at being 0.1.16, and the console's security review deserves a release of its own. The practical difference between (a) and (b) for the user is *when 0.2.0 ships*, not when the console does — the console sessions are the same either way.

### 9.3 What the in-progress rewrite should do now (cheap, behaviour-neutral)

1. **In-process execution, no `os.Exit` outside `cmd/`** — already a §9.0 rule and `cli.Run(ctx, app, build) error` exists [V]. Keep it; the shell's batch mode and the `-c` path call it directly for `help` and for pure-local verbs, and spawn `sudo tacctl` for the rest.
2. **`sudoArgv` first-word list as a table** (`reexec.go` hardcodes `"host"` [V]) so adding `ssh`/`device` is one line; `noSudo` likewise (`shell` and `console` join `hash`).
3. **Tier gate as data** (WP2.4a): `tier.Permits` and `emit_tier_sudoers` generated from one table of `(tier, family, verb)` rows, with `tiers.bats`'s cross-check preserved; adding the §8 rows is then additive and the goldens change in one place.
4. **`_completion-names` kinds in a map** (`internal/cli`), and **add `hosts` in WP3.2** (new kind, harmless to the hand-written completion; the generated completion of 0.2.0 may use it for `host sync|unenroll <TAB>` — a one-line §3.9 note).
5. **`internal/hosts` exposes `Registry.Load/Entries`** as a package API with the parsed `target|port|identity`, not just `host list` text, so `devreg` can union it.
6. **The ssh runner of WP3.2 as a primitive:** `execx.Runner.Start` with `AsUser`, tty inheritance, the SIGINT-while-child-owns-the-tty discipline, exit-status passthrough — needed by `host` anyway and by `tacctl ssh` later. The option vector stays a parameter, not a constant.
7. **The `ssh_config` generator is not needed yet**; but keep device-template variable building (WP3.1) separate from any ssh knowledge so §5.4 does not grow into `internal/devices`.
8. **`args.Parse` specs carry completion data** (positional kinds, flag value kinds) — already the plan's "one source of truth" (§3.2); the shell's completer reads the same specs.
9. **Usage text per family as functions returning strings** (not direct prints), so `help <family>` in the shell reuses them.
10. **Cobra `Use`/`Short` strings accurate** on every verb (they become the shell's completion descriptions).
11. **Keep `backend.Backend` open for one more verb** (`Sightings`): nothing to do now beyond not sealing the interface with a compile-time list of exactly today's 19 verbs in a way that makes a 20th a parity failure (the registry table test should assert "at least these", or the test is updated with the verb).
12. **Do not** add the readline dependency, the registry file or any new top-level word to 0.2.0.

---

## 10. Implementation sketch and sizes

### 10.1 Packages

```
internal/devreg/           Part A: model.go (Device, validation via internal/cidr + internal/names), file.go (devices.yaml: pyyaml/yamlpy,
                           lock, atomic 0600, parse-back), resolve.go (registry ∪ hosts.Registry; namespace; ScopeLookup/tag derivation;
                           tier filtering), seen.go (cache), scan.go (Scan/Discover), probe.go, sshprofile.go (per-vendor options),
                           sshconfig.go (generator: user Include and the root-owned -F file), csv.go
internal/backend/          + Sightings(ctx, since, resume) ([]Sighting, string, error); tacacs/sightings.go (journalctl -o json via runner,
                           three line shapes), radius/sightings.go (auth log + rotations), faketest scripted sightings
internal/shell/            Part B: loop.go (readline, prompt, modes: interactive | batch | -c | console), tokenize.go (quotes only; fuzzed),
                           complete.go (cobra tree + args specs + _completion-names bridge with a short cache), history.go (0600, redaction),
                           exec.go (sudo -n tacctl … / ssh -F … as the user; tty; SIGINT; status), idle.go
internal/console/          Part D: config.go (console.yaml), policy.go (tiers/users → shell per account), sshd.go (drop-in text, sshd -t,
                           reload, sshd -T -C check), shells.go (/etc/shells line), guard.go (-c filter, environment scrubbing, limits),
                           acct.go (optional TACACS+ client via the vendored library)
internal/hosts/            (WP3.2) + the TAC_USERS fourth field; config/linux/client-install.sh: useradd -s / usermod -s for managed accounts,
                           tac-console group; client-remove.sh: restore /bin/bash on unenroll
internal/cli/              device.go, ssh.go, shell.go, console.go; reexec.go table; tier rows; _completion-names devices|hosts
cmd/tacctl/                argv[0] detection: tacctl-console / -tacctl-console → console mode
patches/0003-authen-log-conn-remote-addr.patch; tests/integration/tacquito_patches.bats +1
backups/<ts>/ gains devices.yaml and console.yaml when present
```

Rules of the rewrite apply unchanged: no `os/exec` outside `execx` (sudo, ssh, journalctl, logger, sshd all through the runner, so bats stubs and the Go fake work), no `os.Getenv` outside `paths`, every command returns `error`, `-tags testknobs` clock for deterministic "last seen"/timestamps in goldens.

### 10.2 Tests

- Go: registry round-trip and invalid-input corpus; scope derivation over the three store fixtures; sightings parsers over made-up journal JSON and auth-log fixtures (rotations, `copytruncate` shrink, the three tacquito shapes); cache apply/prune/resume; ssh argv builder table (vendor × legacy × overrides × root refusal); ssh-config golden; tier filtering; **tokenizer fuzz** and a table of escape attempts (`;`, `|`, `$(...)`, backticks, `>`, `\n`, `!`, unicode spaces) all yielding "unknown command"/"no such verb"; `-c` filter table (`user list` ok; `scp -t .`, `/usr/lib/openssh/sftp-server`, `bash`, `user list; id` refused); console environment scrubbing; sshd drop-in golden; policy (tiers/users → shell) table.
- bats (black-box, the suite's contract): `device_cli.bats`, `shell.bats` (batch mode through stdin, `-c`, exit codes, redaction via a stubbed `sudo`), `console.bats` (policy, `install`/`remove` with stubbed `sshd`/`systemctl`, `/etc/shells` under `TACCTL_*` roots, `host enroll --local` emitting the shell field), `tiers.bats` rows, `completion.bats` cases, `config_linux.bats` for the `useradd -s` path with the fake account database.
- pty tests (`creack/pty`): prompt, completion, Ctrl-C at prompt and during a child, idle timeout, history redaction, console `-c`.
- Live (the dev server and the test client only, snapshot first, throwaway accounts): register the dev server and the test client; `device scan` after a real TACACS+ login (patched tacquito); `tacctl ssh client` with the agent; `ssh-config` installed under the user's own `~/.ssh` and `ssh client` by name; `discover` after a deliberate wrong-secret attempt from a container; **console:** a throwaway readonly user enabled for the console on the dev server — SSH in, `device list`, `ssh client`, `exit`; `scp` and `sftp` refused; `ssh -L` refused by sshd; `ssh devserver 'user list'` works; idle timeout; `sudo` absent; break-glass (`console user <u> disable` + `host sync`, local admin unaffected); then remove the user. Nothing on production.

### 10.3 Size

| Part | Sessions | Lines (Go incl. tests) | Notes |
|---|---|---|---|
| **A** registry: model/file/resolve/csv + CRUD/import/export verbs + bats | 2 | 1,400 | |
| **A** sightings verb, two parsers, cache, scan/discover/check/probe, fake backend | 1.5–2 | 1,100 | |
| **A** tacquito patch 0003 + test; snapshot/diff/restore of the new files; docs; live check | 0.5–1 | 200 + docs | |
| **B** shell loop, tokenizer, completion, history, exec, batch/-c, pty tests, vendoring of the readline cluster | 3–4 | 2,000 | the dependency review is part of it |
| **C** `tacctl ssh` + shell `ssh`, profiles, `ssh-config`, re-exec table, tier rows + sudoers + goldens, completion kinds | 1 | 700 | |
| **D** console.yaml + policy + verbs; argv[0] mode; guard (`-c`, env, limits); sshd drop-in + check; `/etc/shells`; client-script changes (bash) + config_linux tests; docs | 3–4 | 1,800 + ~150 bash | |
| **D** live acceptance on the dev server (console user, scp/sftp/forwarding refusals, break-glass) + security review write-up | 1 | 0 | |
| **D (optional)** per-line TACACS+ accounting via the library client | 1 | 400 | follow-up |
| **Total** | **≈ 14–17** (A 4–5, B 3–4, C 1, D 5–6, optional +1) | **≈ 8,000–9,000** | at one to two sessions a day with review between: 0.2.1 ≈ 2–3 weeks after 0.2.0, 0.2.2 ≈ 3–4 weeks after that |

Executor suggestion: Opus for the shell loop/tokenizer, `ssh` plumbing and everything in D; Sonnet for registry CRUD, parsers and docs.

---

## 11. Pros, cons, risks

**Pros.** Connect-by-name and completion with zero new trust (the user's ssh, agent, `known_hosts`); the two facts only the AAA server knows (*configured*, *seen*) visible per device; `discover` answers "what is pointed at us?" after every secret rotation; one list for devices and hosts; a shell whose privilege model is *less* than today's (`sudo` per line, no root session); a console that turns "TACACS+ users get bash on the AAA server" into "they get tacctl and `ssh` to their devices" — a strict reduction of today's exposure for readonly/operator accounts; every console line audited by sudo without new code; all files additive and rollback-safe; placement that leaves 0.2.0 untouched.

**Cons.** Three new families (~35 verbs) to document and keep; a readline dependency cluster to vendor; a third tacquito patch; a cache to explain; the console's correctness rests on a small tokenizer and an sshd drop-in — two things that must both be right; superusers gain nothing security-wise from the console; `tacctl ssh` from bash inherits `host`'s `SETENV` limitation for users of the opt-in `NOPASSWD` rule; Debian/RHEL sshd include conventions to probe; the client script grows another concern (shells, a group, `/etc/shells`).

**Risks.**
1. *Forwarding bypass.* A console without the sshd drop-in is a jump host with the registry as decoration (`ssh -L`). Mitigation: the installer writes and validates the drop-in, `console show` checks `sshd -T -C` for a console user and warns in red, `console install` is idempotent, the live acceptance proves the refusal.
2. *Tokenizer/`-c` filter bug = shell escape.* Mitigation: table-driven tokenizer with fuzzing, allow-list of first words, the console starts only two absolute paths with a scrubbed environment; the blast radius is the same unprivileged account that has bash today.
3. *Locking people out.* An enabled tier whose users maintain the server; a broken drop-in; `/etc/shells` edits. Mitigation: opt-in per tier with per-user `disable`, local administrators never touched, the installer's existing "a local administrator must exist" refusal, `sshd -t` before reload with rollback, `console remove` restores bash for managed accounts.
4. *Patch drift* (0003 stops applying upstream). Mitigation: two-hunk change, loud test on install/upgrade like 0001/0002, scanner degrades to T1/T2.
5. *Journal volume.* `--full` scans at level 30 with months of journal; mitigation: cursors, `--since`, the scan reports its window and retention.
6. *Dependency.* `reeflective/console` maintenance and footprint [A]; mitigation: review in the B package, `go mod verify`, the lighter fallback evaluated in the same session.
7. *Legacy IOS ssh options* [A]: opt-in, visible in `ssh-config` output, correctable in the user's own config.
8. *Scope creep into inventory / into a general restricted shell.* §1.2 is the fence.
9. *Secrets.* None handled by A–D; argv-recorder test asserts no secret on any child argv; the `-F` config and `ssh-config` contain none; history redaction tested.

---

## 12. Decisions for the user (each with the recommendation)

**Placement**
1. **Release placement.** Recommend **(b): 0.2.0 unchanged; 0.2.1 = A + B + C; 0.2.2 = D** (§9). Alternatives: (a) everything in 0.2.0 (+4–6 weeks, two risk classes in one gate); (c) shell + `ssh` to hosts only in 0.2.0 (+1–2 weeks).
2. **Door-openers now** (§9.3, items 1–12). Recommend **yes, all**; they are behaviour-neutral and mostly already rules of the plan. The one visible change is the `hosts` completion kind in WP3.2 (a one-line §3.9 note).

**Part A — registry**
3. **Storage.** Recommend **separate `/etc/tacctl/devices.yaml`** (and `console.yaml`), own version, snapshotted; **not** a store section now or at 0.3.0. Alternative: store section at 0.3.0 (rollback blocked, render data and catalog mixed).
4. **Scope derived, never stored.** Recommend **derived**. Alternative: stored with cascades and consistency checks.
5. **Linux hosts read-only from `linux-hosts`**; merge into one file is a 0.3.0 candidate. Recommend **read-only union now**.
6. **TACACS+ "seen" source.** Recommend **tacquito patch 0003 + error lines, debug line as fallback**. Alternative: no patch (address-only at `loglevel debug`, or failures only).
7. **Reachable probe.** Recommend **include, on demand only** (`device check`, `list --probe`). Alternative: leave it out.
8. **Scan is explicit** (`device scan`; `list` shows the cache's age). Recommend **explicit**. Alternative: implicit refresh in `list` when older than N minutes.
9. **Vendor tags stay independent** of the registry's `vendor` (`show` reports mismatches). Recommend **independent**. Alternative: `device add --vendor` also tags for RADIUS (a registry write becomes a store apply + FreeRADIUS restart).
10. **Import/export** (CSV/YAML, `--check|--replace`), no NetBox client. Recommend **include in the first version**.

**Part B — shell**
11. **Shell privilege model.** Recommend **unprivileged shell, `sudo -n tacctl` per line** (§4.2), replacing §8's root-session sketch; it is also what the console needs. Alternative: §8's one re-exec + root session (fewer sudo prompts for admins; a long-lived root loop; the console would still need the unprivileged form).
12. **Readline library.** Recommend **`reeflective/console`+`readline`** evaluated and vendored in the B package with a lighter fallback decided in the same session [A]. Alternative: hand-rolled line editor (no dependency, no history/completion polish).
13. **History redaction rules** (`--secret`, `--hash`, `secret set`, `passwd`, `import` values) and `--no-history`. Recommend **as listed**; alternative: history opt-in only.

**Part C — `ssh <name>`**
14. **Verb name `ssh`** (top level and in the shell; `device ssh` alias), names only, no raw addresses. Recommend **yes**. Alternative: `connect`.
15. **`tacctl ssh` from bash via the `host` mechanism** (sudo re-exec, drop to the invoking user), refusing a root invoker; **add `SETENV:` to the opt-in `config sudoers install` rule** so `host` and `ssh` work through it. Recommend **yes to both**. Alternative: a sudo-free `tacctl ssh` with a hidden `_device-resolve` bridge.
16. **Vendor profiles:** WTI by vendor, legacy IOS as per-device opt-in `legacy-ssh`, nothing for Junos/Linux, no stored free-form options. Recommend **as listed**. Alternative: a per-device `ssh-options` field.
17. **`device ssh-config` print-only** (no root writes into `~/.ssh`). Recommend **print-only**; a `--install` as the invoking user later if asked.

**Part D — console**
18. **Build the login console at all.** Recommend **yes, in 0.2.2**, because it strictly reduces what readonly/operator accounts can do on the AAA server today. Alternative: stop after A–C (interactive shell only; TACACS+ users keep bash).
19. **Login shell + sshd drop-in, not `ForceCommand`.** Recommend **login shell `/usr/local/bin/tacctl-console` in `/etc/shells` plus the `Match Group tac-console` drop-in** (§6.4). Alternative: `ForceCommand` only (sshd-only coverage, bash on other login paths).
20. **Opt-in shape.** Recommend **`console tiers enable <csv>` with `console user <u> enable|disable|clear` override, default none enabled; recommended enablement `readonly,operator`**; superusers only if the user wants the convenience (not a boundary for them). Alternative: per-user only.
21. **Where the opt-in lives.** Recommend **`/etc/tacctl/console.yaml`** (additive). Alternatives: `tacctl.yaml` keys (tolerated by 0.1.16 on read [V], mixes records into tunables); a store field (0.3.0).
22. **Provisioning path.** Recommend **`host enroll --local` / `host sync` with a fourth `TAC_USERS` field and `useradd|usermod -s`**, the `tac-console` group, `/etc/shells` and the sshd drop-in written by the same run, `console install|remove` for the server-side pieces alone. Alternative: a separate `console` command that edits accounts directly (a second account-management path).
23. **Agent forwarding default off** for console users (`console agent-forwarding enable` to allow). Recommend **off**. Alternative: on (key logins to Linux hosts bypass TACACS+ [V memory]).
24. **ssh client escape character disabled** (`EscapeChar none`) in the console by default; `console ssh-escape enable` restores `~.`/`~C`. Recommend **disabled**.
25. **`-c` handling:** one tacctl line allowed (`ssh devserver 'user list'`), everything else refused — so no scp/sftp/rsync for console accounts. Recommend **yes**. Alternative: refuse every `-c` (simpler, loses the one-liner).
26. **Accounting of console lines.** Recommend **journal-based first (sudo + `logger` lines, session start/end, `ssh` start/end), TACACS+ per-line accounting via the library client as the optional 0.2.3 follow-up** (`console accounting journal|tacacs`). Alternative: build the TACACS+ client in 0.2.2 (+1 session).
27. **Idle timeout** default 30 min (`console idle-timeout`), paused during `ssh`, with sshd `ClientAlive*` as the safety net. Recommend **as listed**.
28. **Permissions table** (§8): `ssh`/`device list|show|ssh-config`/`shell` for every tier filtered to own scopes; `check|scan|discover|export|console show` operator+; all writes superuser; tiers sudoers extended with a release-notes reminder to re-run `config sudoers tiers install`. Recommend **as listed**. Alternative: readonly gets nothing from `device` (defeats the console's purpose).

29. **Generic names** (§3.6) — *decided by the user:* **refuse** at registration/enrolment with remediation steps; `--allow-generic` overrides and leaves a standing notice.
30. **Notice acknowledgement** (§3.6) — *decided by the user:* per device and kind, `tacctl device notice <name> ack|unack <kind>`, stored in `devices.yaml`, hidden from `status`/`device list`, shown marked in `device show`.
31. **Notice kinds and placement** (§3.6): duplicate name/address refused; generic name refused; `ambiguous-nas-id`, `generic-nas-id`, `name-mismatch`, `duplicate-address` from scans; shown in scan/discover output, `status`, `device list|show`, `device notices`. Recommend **as listed** (accepted with the rest of §12).
32. **Identity by IP** (§3.7): addresses accepted wherever names are; `identity-changed` notice when a device's NAS-Identifier changes. Accepted.
33. **First host key** (§3.7) — *decided by the user:* scan and pin at `device add`, fingerprints printed for console comparison; `--host-key SHA256:<fp>` to check against a known fingerprint, `--no-host-key` to register unpinned with a notice.
34. **Host-key change** (§3.7) — *decided by the user:* strict; `tacctl ssh` and the console refuse a mismatching key, with verification steps; only a superuser's `device hostkey <name> accept|set` re-pins; `hostkey-changed` cannot be acknowledged.
