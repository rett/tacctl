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
  - **A value longer than 255 bytes makes the login fail**: an oversized value locks the group out of every Juniper device of the scope. tacctl must check each rendered value's length and refuse the change (naming the group and the length), never send it.
  - The switch's classes carry only `permissions view` / `permissions all`, no local regexes: on such devices the server is the only source of command rules, and the permission bits decide which commands exist at all (an operator without `view-configuration` has no `show configuration`, whatever the regex says).
  - Still open: whether a server value replaces or joins a class's own allow/deny lines (the lab classes have none); whether Junos accepts the same attribute twice (splitting long rule sets); RADIUS (VSAs 2-5) not yet run.
- **Not in 0.2.1:** it changes what devices are told at login; 0.2.1 is at its release gate.

## 4. Linux hosts: considered, not pursued

- **nss_tacplus** (shared template accounts, no per-user local accounts) — considered 2026-10-04, not pursued; revisit if per-user accounts become a burden. 0.2.1 keeps one local account per user (UIDs 20000-29999, created, expired and deleted by `host enroll|sync`).

## 5. State-format changes (0.3.0 at the earliest)

- Drop the regex migrations of a legacy `tacquito.yaml` once no supported host can be older than the store release.

0.2.0 makes no state-format changes, so rolling back to 0.1.16 is a checkout (go-rewrite Decision 10). Format changes wait for 0.3.0, with their own migration and gate:

- merging the `linux-hosts` registry into the device registry;
- any device data inside `store.yaml`.
