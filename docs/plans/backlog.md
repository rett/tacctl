# tacctl backlog: work filed for after 0.2.0

**Decision (user, 2026-10-03):** 0.2.0 is the Go rewrite with functional equivalence to 0.1.16 and nothing else. Everything below waits until 0.2.0 is released. Each item records where its design lives and why it was deferred. Nothing here may be started on `feature/go-rewrite`.

## 1. Operator console (0.2.1, 0.2.2)

The design and every decision are in `docs/plans/operator-console.md`.

- **0.2.1: device registry, shell mode, `ssh <name>`.**
  - Device registry: `/etc/tacctl/devices.yaml`, scope derived from the address, configured/seen/reachable states.
  - Name notices (§3.6): generic names refused unless `--allow-generic`, duplicates refused, scan-time notices with remediation for each vendor, acknowledgement per device.
  - Identity by IP and host-key pinning (§3.7): scan-and-pin at registration, strict enforcement through a known_hosts file tacctl generates, re-pin by a superuser only.
  - Unprivileged shell that runs `sudo -n tacctl <line>` for each line.
  - `ssh <name>` to Cisco IOS/IOS-XE, Junos, WTI and Linux hosts, with a live session to each vendor in the lab acceptance.
  - tacquito patch 0003, which logs the NAS address so TACACS+ devices can count as "seen".
- **0.2.2: login console.** `tacctl-console` as a login shell, an sshd `Match Group tac-console` drop-in with no forwarding, `-c` limited to one tacctl line, opt-in per tier, provisioning through `host enroll|sync`, journal accounting, idle timeout.
- **0.2.3 (optional):** TACACS+ accounting of each console line through the tacquito client library.
- **Door-openers still pending in 0.2.0** (from the console plan, §9.3):
  - Already done in WP2.4a: in-process `cli.Run`, sudo word tables, the tier rules table, the completion kinds map, argument specs with completion data, usage functions, accurate `Use`/`Short`.
  - Still to do in Phase 3, and only where it is pure code structure with no behaviour change:
    - `internal/hosts` exposes `Registry.Load/Entries` (item 5);
    - the ssh runner is a reusable primitive (item 6);
    - device-template variable building stays free of ssh knowledge (item 7).
  - **Deferred to 0.2.1:** the `hosts` completion kind (item 4), because it changes the completion behaviour.

## 2. Distribution

- **Release binaries (0.2.1, user 2026-10-04):** tagged releases publish linux/amd64 and linux/arm64 binaries; install and upgrade download the binary for the host's architecture and verify it, and build from source as today for branch builds or when the download fails or cannot be verified. Verification: a `SHA256SUMS` release asset signed with a key whose public half is committed in the repo (minisign or `ssh-keygen -Y`; chosen in the refresh), the private key held by the user, who signs at release time.

- **Release reproducibility check in CI** (candidate, filed by WP6.8): a GitHub Actions workflow that, on a release, rebuilds both `tacctl-<tag>-linux-<arch>` assets from the tag with `make release-assets` and compares their sums with the published `SHA256SUMS`. It only re-builds and compares; signing stays on the release manager's machine (no key in CI).

- **zsh and fish completion** (0.2.1, user 2026-10-04): `tacctl completion zsh|fish` from cobra's generators (0.2.0 ships bash only).

## 3. Behaviour kept for parity in 0.2.0, candidates to change later

**0.2.1 (user, 2026-10-04):** every recommendation of the plan refresh's accept/reject pass (`operator-console-wp.md` §7.2) was accepted. The fixed items are in 0.2.1 (CHANGELOG 0.2.1 items 1-12, plus the differential runner's `Using template:` normalisation and stub lint); what remains here is kept on purpose or deferred.

Kept, with the reason (not to be changed without a new decision):

- `log clear` is superuser-only while the other `log` verbs are operator-level: destroying the audit logs stays a superuser act.
- The no-subcommand and unknown-subcommand exit codes are inconsistent across families (pinned by the usage tests): scripts and the differential corpus depend on them, and they have no value for an operator.
- A failed legacy migration continues during install but aborts during upgrade (0.1.16's errexit difference; WP3.3a): the legacy path leaves in 0.3.0, so it is not reworked before then.

Deferred:

- `config render --dry-run` does not report the drop-ins a real render would remove (open question from WP2.4c): it needs a removal report from each backend's staging step, for little value.

## 3b. Juniper authorization from the server (0.2.2 candidate, filed 2026-10-05)

**Request (user, 2026-10-05):** send Juniper users' command and configuration permissions from the server, as attributes, instead of only the login class.

- **Today:** a Juniper login gets only its class: `local-user-name` in tacquito's `junos-exec` service (TACACS+), `Juniper-Local-User-Name` (RADIUS). `tacctl group commands` rules reach Junos only as the class's `allow-commands`/`deny-commands` lines that `tacctl config juniper` prints for each device (`internal/devices/juniper.go`).
- **Proposal:**
  - TACACS+: the same `junos-exec` service also carries `allow-commands`, `deny-commands`, `allow-configuration`, `deny-configuration` (or the `*-regexps` variants where Junos has them).
  - RADIUS: the matching Juniper VSAs (Juniper-Allow-Commands 2, Juniper-Deny-Commands 3, Juniper-Allow-Configuration 4, Juniper-Deny-Configuration 5), set in post-auth beside `Juniper-Local-User-Name`, only for scopes that send Juniper attributes.
  - Rendered from the group's command rules (the same regexes `config juniper` builds), and from a new per-group configuration rule set (`tacctl group config-access <group> allow|deny <regex>`, stored like the command rules), which tacctl does not have yet.
  - The device-side class lines stay as the fallback for logins when the server is unreachable; `config juniper` says which source is authoritative.
- **Open, to settle by a live check on the lab Juniper switch first** (run sheet kept outside the repo):
  1. How Junos combines server-sent values with the class's own: override or merge, for allow and deny, commands and configuration; what `show cli authorization` reports.
  2. Length: a TACACS+ value is at most 255 bytes, a RADIUS VSA 253; today's per-class regex joins every rule into one expression. Which Junos releases accept the `*-regexps` (list) variants.
  3. Behaviour over both protocols, and the Junos release on the lab switch.
- **Live check on the lab Juniper switch (2026-10-05; EX4300, Junos 25.4R1), TACACS+:**
  - Junos applies server-sent values: after a new login `show cli authorization` lists them under "Individual command authorization" (allow/deny regular expression, allow/deny configuration regular expression).
  - `deny-configuration "^system"` blocked system edits for a class with `permissions all`.
  - `allow-commands-regexps` (the list form) is accepted on 25.4.
  - **An argument longer than 255 bytes makes the login fail**: the limit is TACACS+'s for the whole `name=value` argument, so a `deny-commands` value may be at most 241 bytes and a `deny-configuration` value 236 (a 247-byte `deny-commands` value is a 261-byte argument; tacquito logs `unable to marshal packet; invalid arg length. valid range [2-255], found [261]` and Junos `PAM_TACPLUS_SEND_AUTHOR_FAIL`). An oversized value locks the group out of every Juniper device of the scope. tacctl must check each rendered argument's length and refuse the change (naming the group and the length), never send it.
  - The switch's classes carry only `permissions view` / `permissions all`, no local regexes: on such devices the server is the only source of command rules, and the permission bits decide which commands exist at all (an operator without `view-configuration` has no `show configuration`, whatever the regex says).
  - Still open: whether a server value replaces or joins a class's own allow/deny lines (the lab classes have none); whether Junos accepts the same attribute twice (splitting long rule sets); RADIUS (VSAs 2-5) not yet run.
- **Not in 0.2.1:** it changes what devices are told at login; 0.2.1 is at its release gate.

## 3c. Device authorization from the server: Cisco, Junos and WTI (0.2.2 candidate, filed 2026-10-05)

**Request (user, 2026-10-05):** one interface for command permissions across vendors, with no permissions hardcoded on devices; Cisco keeps its privilege levels. Extends §3b. A worked scheme for four roles (viewer, operator, engineer, superuser) on all three vendors, and the lab run sheet that tests it, are kept outside the repo.

- **How tacquito evaluates command rules** (read in its source, `cmds/server/config/authorizers/stringy/command.go`):
  - Rules are tried in order. A `*` rule decides at once, wherever it stands; a rule with another name is skipped; a rule without `match` decides; a rule whose regexes all miss falls through to the next rule, so a deny with `match` followed by a permit of the same name works.
  - Every `match` regex is anchored at both ends (`^` and `$` added when missing) and tested against the arguments joined by spaces, without the final `<cr>`. A regex therefore has to cover the trailing arguments itself: `--match '^crypto'` matches `show crypto` only, not `show crypto pki certificates`; write `--match '^crypto( .*)?'`.
- **Cisco (TACACS+): privilege levels stay; the server decides each command.**
  - IOS checks both: the privilege level decides which commands exist, `aaa authorization commands <level>` asks the server about each one. Configuration commands are sent as ordinary commands (`interface ...`, `hostname ...`), so one rule set covers both modes.
  - `config cisco` emits `aaa authorization commands` and `aaa accounting commands` for levels 1, 7 and 15 only, while `group add|edit` accepts 0-15: commands at any other level in use are never sent to the server. Emit one line per level in use.
  - Emit `aaa authorization config-commands` explicitly (IOS's default once `aaa authorization commands` is set, per Cisco's reference; the line makes it certain), and offer `aaa authorization console`.
  - A role that configures (engineer) has to be priv-lvl 15: configuration commands are level 15, and lowering them needs a `privilege configure` line per command and submode on every device. The server's rules are then the only thing separating it from superuser; the `local` fallback makes it a superuser while the server is unreachable (document it).
  - Over RADIUS Cisco IOS has no per-command authorization; nothing changes there.
- **Junos:** the classes keep permission bits only; the server sends `deny-commands` and `deny-configuration` (no `allow-*` values, so the question of how allow and deny combine never arises). Junos regexes are POSIX ERE over the whole command line, Cisco's rules are a command word plus RE2 over the arguments, and the deny sets of the two differ in content (Cisco `aaa`, `username`; Junos `system login`, `system tacplus-server`). So the attributes are a per-group Junos rule set of their own under the `group` verbs (for example `tacctl group junos <group> deny-commands|deny-configuration add|remove|list <regex>`), not a translation of `group commands`. Each value is checked when it is set: its `name=value` argument must fit TACACS+'s 255 bytes (RADIUS: 253 bytes for the value).
- **WTI:**
  - The unit has no per-command authorization; it takes one of four access levels from priv-lvl (bands 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator) or from `WTI-Super` (0-3) over RADIUS. WTI's documents: Administrator has all ports, features and configuration menus; SuperUser all ports and operating features and may view but not change the configuration; User only status and the ports enabled for it (over TACACS+: Default User Access); ViewOnly status only.
  - Because the WTI level comes from the Cisco priv-lvl, an engineer at 15 is an Administrator on WTI units and can change their users and AAA settings. Proposal: a per-group WTI level (`tacctl group edit <group> wti-level auto|viewonly|user|superuser|administrator`, `auto` = today's bands). RADIUS: set `Tacctl-WTI-Super` from it. TACACS+: a `wti_exec_<group>` service named `wti` with its own priv-lvl, and the walkthrough sets the unit's Service Name back to its factory `wti`; groups without an override keep working through patch 0001's fallback to the `shell` values.
  - Ports and outlets: TACACS+ carries no port lists. RADIUS has `WTI-Port-Access` (42), `WTI-Plug-Access` (43), `WTI-Group-Access` (44) in WTI's dictionary, one character per port or outlet, so the value depends on the model; not pursued (per-unit Default User Access lists instead).
- **tacctl gaps found on the way:**
  - `group commands remove <group> <name>` drops every rule of that name, so one rule of a deny/permit pair cannot be removed alone; it needs a selector (`--match`) or an index.
  - `group commands add` always appends before the catch-all; a rule cannot be placed before an existing one.
  - `group privilege add` emits `privilege exec level N <cmd>` only; `privilege exec all level N <cmd>` (a whole command tree) and `privilege configure level N <cmd>` cannot be expressed.
  - `--match` regexes cannot contain a comma (the rule line form splits on it).
- **To settle on lab devices before building:** that tacquito's denies hold for priv-lvl 15 commands and in configuration mode (IOS-XE); how IOS reports `do <cmd>` in configuration mode; the Junos deny sets with permission-only classes (including `set groups ... system login`); that a WTI unit with Service Name `wti` sends `service=wti` and takes the priv-lvl of a `wti` service (SuperUser from 12 while Cisco gets 15).

## 3d. Fully qualified device names (filed 2026-10-05)

**Request (user, 2026-10-05):** many sites have devices with the same short host name (`sw1.site-a.example`, `sw1.site-b.example`); the registry should name them by their full name.

- **Today:** a registry name may already contain dots (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`, `internal/devreg/model.go`), so `tacctl device add sw1.site-a.example <address>` works, and lookups are exact and case-insensitive.
- **Gaps:**
  - The limit is 63 characters, a DNS label's, not a full name's 253.
  - The name-mismatch notice (`nameMatches`, `internal/devreg/notices_scan.go`) accepts a NAS-Identifier equal to the registry name, the device's `hostname` or its first label, and a short registry name against a fully qualified NAS-Identifier, but not the reverse: a device registered as `sw1.site-a.example` that sends `sw1` raises "identifies itself as 'sw1'". It should also accept the registry name's first label.
  - Several devices sending the same short NAS-Identifier raise the ambiguous-NAS-ID notice; it is correct, and the remedy is a fully qualified host name on the device (or the notice acknowledged).
  - `host enroll` defaults `--name` to the short host name.

## 4. Linux hosts: considered, not pursued

- **nss_tacplus** (shared template accounts, no per-user local accounts) — considered 2026-10-04, not pursued; revisit if per-user accounts become a burden. 0.2.1 keeps one local account per user (UIDs 20000-29999, created, expired and deleted by `host enroll|sync`).

## 5. State-format changes (0.3.0 at the earliest)

- Drop the regex migrations of a legacy `tacquito.yaml` once no supported host can be older than the store release.

0.2.0 makes no state-format changes, so rolling back to 0.1.16 is a checkout (go-rewrite Decision 10). Format changes wait for 0.3.0, with their own migration and gate:

- merging the `linux-hosts` registry into the device registry;
- any device data inside `store.yaml`.
