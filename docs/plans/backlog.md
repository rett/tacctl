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

- **Release binaries:** GitHub release binaries with checksums. The bootstrap shim would then download instead of building (go-rewrite Decision 7, alternative (b)).

## 3. Behaviour kept for parity in 0.2.0, candidates to change later

These come from the go-rewrite plan's §3.9 "Not changed although tempting" list and the package reports. Each would be a deliberate behaviour change in a later release.

- `config linux uid` touches the UID file on a read.
- `log clear` is superuser-only while the other `log` verbs are operator-level.
- `help` is denied to tier users.
- `install|upgrade` silently ignore unknown arguments.
- The tiers sudoers file is not refreshed on upgrade.
- The no-subcommand and unknown-subcommand exit codes are inconsistent across families.
- The `mgmt-acl cisco-name|juniper-name` verbs are missing from the usage text.
- `group commands add … --match` with a comma in the regex is split on the next write (`name|action|matches` line form).
- `hash.Verify` honours a stored bcrypt cost up to 31, so a hand-edited `$2b$31$` hash makes `user verify` run for days. A cost cap could come later; tacquito verifies logins itself.
- `config render --dry-run` does not report the drop-ins a real render would remove (open question from WP2.4c).

## 4. State-format changes (0.3.0 at the earliest)

0.2.0 makes no state-format changes, so rolling back to 0.1.16 is a checkout (go-rewrite Decision 10). Format changes wait for 0.3.0, with their own migration and gate:

- merging the `linux-hosts` registry into the device registry;
- any device data inside `store.yaml`.
