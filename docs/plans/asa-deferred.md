# Cisco ASA 9.x: the deferred addendum (written 2026-10-10 for 0.2.5; deferred the same day)

> **Status: deferred, no release number.** The user decided on 2026-10-10: "Hold off on ASA until later release." This file keeps the ASA part of the 0.2.5 addendum intact (decision **D115**, the lab items A1-A3, the effects on the other decisions and the open questions), so a later release starts from it. **What that release starts from:** the staged scope of D115 (first the registry vendor `asa`, the ssh profile, the server-side check and the `config asa` walkthrough with its paste region in the D108/D109 layout; then the read, an `asa` family in `internal/devconf`, and the delta region); **the lab needs:** an ASAv in GNS3 at 9.14(3) or the nearest 9.x, and the target as the user pasted it: Cisco Adaptive Security Appliance Software 9.14(3)15 on an ASA5525 (a failover pair, active/standby). Nothing of this is in 0.2.5: no `asa` vendor, no `config asa`, no cover state, no lab item. D113's dialect setting stays `ios12 | modern` for vendor `cisco`; the ASA would be a vendor of its own.

## The decision as drafted

| # | Decision | Status |
|---|---|---|
| **D115** | **Cisco ASA 9.x is a vendor of its own, `asa`, staged: 0.2.5 ships the registry vendor, the ssh profile, the server-side check and the `config asa` walkthrough with its paste region; the read (`pull`/`diff`/`plan` from a device) waits for the ASAv lab and a later release.** *Why a vendor:* the ASA's syntax is not IOS's (`aaa-server <GROUP> protocol tacacs+` and `aaa-server <GROUP> (<ifc>) host <ip>` / ` key …`; `aaa authentication ssh\|http\|serial\|enable console <GROUP> LOCAL`; `aaa authorization exec authentication-server [auto-enable]`; `aaa authorization command <GROUP> LOCAL`; `aaa accounting ssh\|enable console <GROUP>` and `aaa accounting command <GROUP>`; `privilege show\|clear\|cmd level N mode exec\|configure command <word>`; `username <u> password <pbkdf2 hash> privilege N`; `enable password`; `ssh <net> <mask> <ifc>`, `http <net> <mask> <ifc>`, `ssh version 2`, `management-access <ifc>`; `snmp-server host <ifc> <ip> community <c> version 2c` beside `snmp-server community`, or `snmp-server group\|user` for v3; no candidate, no commit, each line live, `write memory` to save; a failover pair replicates the active unit's configuration to the standby). **(a) Server side first (0.2.5, lab):** an ASA is a TACACS+ client of the `shell` service with `priv-lvl` (the group bands of the Cisco model apply unchanged), per-command authorization with `cmd=`/`cmd-arg` as IOS sends them (tacquito's rules apply unchanged), and accounting; nothing new is built on the server: the lab check (§12.1) proves it with a `gotest*` user per tier against an ASAv. **(b) The walkthrough `tacctl config asa --scope <s> [--name <device>]` (0.2.5, WP13.2b):** a template `asa` with the managed sections' equivalents rendered from the same builders: `aaa` (the server group, the host with the scope's secret, timeout, the four `aaa authentication … console <GROUP> LOCAL` lines, `aaa authorization exec authentication-server auto-enable`, `aaa authorization command <GROUP> LOCAL`, the accounting lines); `roles` (`privilege show\|cmd level N …` lines from the groups' levels, the same command list the IOS `privilege exec` lines come from, written in the ASA's form); `mgmt-acl` (`ssh <net> <mask> <ifc>` and `http <net> <mask> <ifc>` lines from the management ACL's entries and the server's /32, with `<ifc>` a placeholder the person fills once: the ASA names interfaces, the registry does not know them); `snmp` (`snmp-server community`, `snmp-server host <ifc> <addr> …` for every /32 of the client list and a note for a prefix, since the ASA polls only from listed hosts; v3 user/group; `location`, `contact`); `breakglass` (`username … privilege 15` and `enable password`, commented as on IOS); no `netconf`. The walkthrough carries the ASA lock-out rules as comments outside its region: the `LOCAL` word on every `aaa authentication … console` line (without it a server outage locks the box), never remove `enable password` while `aaa authentication enable console` names the server, the `ssh`/`http` lines must contain the address the person is on, `management-access` untouched, and on a failover pair paste on the **active** unit only (`show failover`), then `write memory` (replicated; `write standby` only if the standby is out of sync). **Its paste region** (D108, D109 apply): `configure terminal` … `end`, the follow-up `write memory` outside, the back-out as `no` lines, a second ssh session held; the walkthrough's region is the standard rendering for a fresh ASA, not a delta (the ASA is not read in 0.2.5). **(c) Reading (deferred):** `terminal pager 0`, `show running-config` (keys shown as `*****`, users as `pbkdf2` hashes: by presence as everywhere; `more system:running-config` shows keys in clear and is never used), `show mode` and `changeto context` for multiple contexts, the active unit of a pair; an `asa` family in `internal/devconf` with its own section rules; `device config pull\|diff\|plan` for `asa` say `ASA units are not read in this release` and the cover page shows `not read (asa)`; D113's `config_syntax` stays a `cisco` setting (`asa` is a vendor, with one dialect). **(d) The delta region (deferred with the read).** **(e) Lab:** the user launches an ASAv in GNS3 (9.14 or the nearest 9.x); §12.1 lists the read-only probes first. *Rejected:* ASA as a `cisco` dialect (`config_syntax asa`): the sections, the privilege syntax, the management-access model and the read differ in kind; **the full read in 0.2.5**: a new extractor and comparison without a lab device yet, on top of a release that already carries D113; **nothing in 0.2.5**: the user manages these units now and the walkthrough plus the server-side check are what makes TACACS+ logins possible on them. | deferred (drafted as recommended, staged) |

## The lab items as drafted (an ASAv the user launches)

| # | Item | Test | Feeds |
|---|---|---|---|
| **A1** | ASAv read-only probes (coordinator, after the user launches it): `show version`, `show mode`, `show failover`, `show running-config` with `terminal pager 0` (the key masking, the `pbkdf2` form, the prompt), `show ssh`, `show run aaa-server`, `show run aaa`, `show run privilege`, `show run ssh`, `show run http`, `show run snmp-server`, `show curpriv` | read-only | D115 (c): the future extractor; the walkthrough's verify commands; the ssh profile |
| **A2** | The server side as a `gotest*` user per tier: `aaa-server` to the dev server, `aaa authentication ssh console <GROUP> LOCAL`, `aaa authorization exec authentication-server auto-enable`, `aaa authorization command <GROUP> LOCAL`, accounting; what the ASA sends (`show aaa-server` statistics, the dev server's log: `priv-lvl`, `cmd=`/`cmd-arg`), and that a level-15 user lands in enable while an operator does not | **write on the ASAv (a lab appliance; the user's go-ahead); a local user and a second session held; `LOCAL` on every line** | D115 (a), the walkthrough's lines |
| **A3** | The walkthrough's region pasted whole on the ASAv, then its back-out; `write memory` and the replication on a failover pair are not testable on a single ASAv (documented as untested) | write, go-ahead | D115 (b) |

## Effects on the 0.2.5 decisions, if the ASA is taken up

- **D113:** `asa` is a vendor, not a `cisco` dialect; `config_syntax` stays `ios12 | modern`.
- **D99/D110 (cover page and report):** a new cover state `not read (asa)` beside `cannot be planned`; the report vocabulary is unchanged (an ASA has no report in 0.2.5).
- **D104:** `config asa` is an Engineer row as `config cisco|juniper|wti`; `device add … --vendor asa` and `device vendor <name> asa` through the existing rows; the `--vendor` selectors accept `asa` and the pull records an `asa` unit `unsupported` with the sentence above (D71's pattern).
- **Size:** +1 session (WP13.2b and the ASAv items); ≈ 9-10 sessions. Cut order unchanged; WP13.2b is cut before `--converge` only if the ASAv cannot be had before the release (the walkthrough without a lab check would be written from the references, which the mission's "exactly the right config" does not allow).

## Open questions as drafted (with the recommendations of the time)

1. **ASA staged as D115** (vendor, ssh profile, the server-side check and the `config asa` walkthrough with its region in 0.2.5; the read, `diff` and the delta region later): **recommended yes**.
2. **An ASAv in GNS3 at 9.14(3) or the nearest 9.x**, read-only first (A1), then A2/A3 with a go-ahead each: **recommended yes, please launch it**; without it WP13.2b slips to the next release.
3. **The ASA's SNMP hosts:** the ASA polls only from listed `snmp-server host` entries; the walkthrough renders one per /32 of the scope's client list and a note for a prefix (`the ASA needs host entries: add the pollers' addresses as /32 entries, or list them by hand`): **recommended yes** (the alternative, rendering nothing for SNMP on ASA, leaves the unit unmonitored).
4. **`aaa authorization exec authentication-server auto-enable`** so that level-15 users land in enable at login and the ASA takes the server's `priv-lvl` for everyone: **recommended yes** (without `auto-enable` every superuser types `enable` and the enable password's authentication line must name the server too; the walkthrough carries both lines either way).

## Image shapes to anticipate (2026-10-10)

The version output of an ASA 9.14 image on a Firepower (FXOS) platform has
this shape:

```
<host>/act/sec# show version | include Version
Cisco Adaptive Security Appliance Software Version 9.14(3)15
SSP Operating System Version 2.8(1.172)
Device Manager Version 7.16(1)150
Baseboard Management Controller (revision 0x1) Firmware Version: 2.4
```

- **Prompt:** `<hostname>/<state>/<priority>#` (`act` active, `stby` standby;
  `pri` or `sec` is the configured failover priority, so an active unit can be
  the secondary). The CLI prompt detector of `internal/devssh` must accept the
  slashed form and must not assume `host#`. A read or a paste made on a unit
  shows which unit it was (`/act/` or `/stby/`): the walkthrough's pre-check
  refuses a paste on a `/stby/` prompt.
- **Platform family:** `SSP Operating System` and a baseboard management
  controller line mark a Firepower platform running the ASA image on FXOS, as
  opposed to a classic ASA 5500-X. FXOS-managed units keep some chassis-level
  settings (management access, users) outside the ASA CLI; whether that
  matters for a given unit is decided when the release starts, from a
  `show version` and `show mode` capture.
- **Version line:** `Cisco Adaptive Security Appliance Software Version
  9.14(3)15` is the shape the version derivation (D113) would need if the
  `asa` vendor reuses it.

## Lab A1 results: ASAv 9.12(4)18, single context (2026-10-11, read-only)

An ASAv with a local account, `aaa authentication ssh console LOCAL` and
`aaa authorization exec LOCAL auto-enable`, read through the ssh CLI with
`terminal pager 0`. A2 and A3 are not run (writes, after WP13.2).

- **Login and prompt:** the plain `<host>#` prompt (no `/act/sec` suffix on a
  single ASAv); the banner is three lines (`User <name> logged in to <host>`,
  `Logins over the last N days: ...`, `Failed logins since the last login: N.`)
  and a privilege-15 user lands at `#` through `auto-enable`.
- **ssh:** the stock client algorithms suffice (`ssh key-exchange group
  dh-group14-sha256`, an RSA host key, AES CTR and CBC ciphers, `ssh cipher
  encryption medium`, `ssh cipher integrity high`); no legacy profile is needed.
- **Version:** `show version | include Version` prints the three-line shape
  (software, `SSP Operating System`, `Device Manager`); the license state
  (`ASAv Platform License State: Unlicensed`) does not affect the CLI.
- **Running config:** starts with `: Saved`, a `: Serial Number:` and a
  `: Hardware:` line, then `ASA Version <v>`; secrets print masked
  (`username <u> password ***** pbkdf2 privilege 15`, `enable password *****
  pbkdf2`), so the comparison is by presence, as on IOS.
- **AAA shape:** no `aaa new-model`, no `line vty`, no `login authentication`
  leaves. `show running-config aaa` gives `aaa authentication ssh console LOCAL`
  (with a trailing blank), `aaa authorization exec LOCAL auto-enable`,
  `aaa authentication login-history`; `show running-config all aaa` adds
  `aaa proxy-limit 16`, `no aaa authentication secure-http-client`,
  `no aaa local authentication attempts max-fail` and
  `aaa authentication login-history duration 90` (the implicit lines the
  extractor must tolerate). `show aaa-server` lists the built-in `LOCAL`
  group with request counters.
- **Management access:** `ssh <network> <mask> <nameif>` lines (one per
  permitted network and interface) are the management ACL, with `ssh version 2`,
  `ssh timeout <minutes>`, `ssh stricthostkeycheck` and the key-exchange line.
- **Command differences from IOS:** `show curpriv` (not `show privilege`);
  `show mode` prints `Security context mode: single`; `show context` is invalid
  in single mode; errors read `ERROR: % Invalid input detected at '^' marker.`,
  `ERROR: % Unrecognized command`, `ERROR: % Incomplete command`; the `aaa ...`
  configuration commands are refused at the exec prompt (config mode needed),
  and `?` is not interactive through a non-tty exec.
