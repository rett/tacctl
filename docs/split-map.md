# Split map: `bin/tacctl.sh` → `bin/tacctl.sh` + `lib/*.sh`

Work package WP0.1 of `docs/plans/pluggable-backends.md`. This document is the complete brief for WP0.2: with it and the repo, the split can be done mechanically with no behaviour change. Nothing in the repo was changed to produce it.

Markers: **[V]** verified by running something; **[R]** established by reading the code only; **[A]** assumed.

Source of truth for every line number below: `bin/tacctl.sh` at git blob `2a00219a9a127ca80050e4be024aebf8c83a924e` (HEAD `c27694f`, branch `develop`), 11,283 lines, sha256 `b5a59714f08d911ba2b66807a4fa3b2a1ae8d3a051f219801daa55150b08ef30`. If the file has changed since, stop: the ranges are no longer valid. The split script in §9 refuses to run on any other content.

---

## 1. Summary

- 11 lib files, the same names the plan proposes. The entrypoint keeps 148 original lines plus a 31-line load block.
- The split is a pure partition: 49 line ranges, each moved verbatim, none reordered inside a file except by ascending original line number. No function is split. No cut falls inside a heredoc or a multi-line string. **[V]** (§9.2 check).
- A prototype built with the §9.1 script was compared with the original: after sourcing, the set of 211 functions, the names and values of all 78 variables, the shell options, the umask and the traps are identical. **[V]** (§9.3 check).
- The full suite on the prototype: see §10. One test must be edited (it copies `bin/tacctl.sh` alone to another directory).
- Three things in the plan's WP0.2 text cannot be met as written; §8 lists them. The important one: `make lint` already fails on the unsplit file, so "lint green" is not an available acceptance criterion.

## 2. Baseline (before any change)

| Check | Result |
|---|---|
| `make test` | **524 / 524 pass** (143 unit, 368 integration, 13 e2e). Wall time **13 m 10 s** (user 10 m 40 s, sys 2 m 18 s) on the dev server. **[V]** |
| `make lint` | **Fails, exit 2**, at the first target (`shellcheck bin/tacctl.sh`, exit 1): 40 findings = 18 warnings + 22 notes. Takes about 16 s. `tests/helpers/*.bash` and `config/linux/*.sh` are clean when run separately. shellcheck 0.9.0. **[V]** |
| Shell | bash 5.2.21. Options after sourcing: `errexit nounset pipefail` (line 25, `set -euo pipefail`) plus defaults. No `trap`, `readonly`, `declare`, `typeset`, `export` or `shopt` at top level. `umask 077` at line 49. **[V]** |
| Functions | 211, all defined at column 0 at top level, no duplicates. One nested definition, `update_if_changed` inside `cmd_upgrade` (line 10823), which moves with its parent. **[V]** against `declare -F`. |

Baseline lint findings by code: SC2089 ×5, SC2090 ×5, SC1083 ×4, SC2034 ×3, SC1078 ×1 (warnings); SC2012 ×6, SC2016 ×5, SC2015 ×3, SC2006 ×2, SC2030 ×2, SC2031 ×2, SC1079 ×1, SC2086 ×1 (notes).

Line-number claims in the plan that are wrong or imprecise:

| Plan says | Actual |
|---|---|
| ~190 functions | 211 |
| top-level statements at `:109-193, 195-269, 279-503` | those are function bodies (`conf_emit_defaults`, cache helpers, `_conf_schema_py`); the only top-level statement in that span is line 199 |
| top-level statement at `:811` | 811–813 (three lines) |
| not listed | **778–804**: four source-time calls to `conf_get`, the only place the script runs its own functions while being sourced |
| dispatch gate at `:11188`, sudo re-exec `:38-48`, self-update `:10766-10786` | correct |

## 3. Target layout and line counts

Line counts include the header each lib file gets (4 lines; 5 for `core.sh` and `lifecycle.sh`, which carry one extra shellcheck directive, §7.2).

| File | Lines | Original lines | Functions | Contents |
|---|---|---|---|---|
| `bin/tacctl.sh` | 179 | 148 | 0 | shebang, shell options, sudo re-exec, umask, `PATCH_DIR`, `SCRIPT_DIR`, load block, dispatch gate and main `case` |
| `lib/core.sh` | 190 | 185 | 12 | base paths, constants, colours, `info/warn/error`, `get_version`, `preflight`, name and CIDR validators and helpers |
| `lib/conf.sh` | 845 | 841 | 21 | `tacctl.yaml` defaults, schema, read/write API, source-time tunables, tunable setter commands, `config dump` |
| `lib/policy.sh` | 460 | 456 | 16 | command rules and priv-exec mappings, their migrations, `regenerate_tacquito_commands`, `write_group_commands` |
| `lib/users.sh` | 1374 | 1370 | 30 | disabled-hash marker, password dates, hash helpers, user YAML helpers, password prompts, user commands, `user scope`, `hash` commands, `cmd_user` |
| `lib/groups.sh` | 1351 | 1347 | 21 | `list_all_groups`, `get_group_privlvl`, `get_config_value`, `cmd_config_show`, group commands |
| `lib/scopes.sh` | 2097 | 2093 | 37 | scope helpers, allow/deny prefix filters, scope commands |
| `lib/render_devices.sh` | 1234 | 1230 | 12 | template resolution, mgmt-ACL data and command, Cisco / Juniper / WTI renderers |
| `lib/linux_hosts.sh` | 885 | 881 | 26 | `config linux …`, `host …` |
| `lib/service.sh` | 1221 | 1217 | 15 | `restart_service`, last login, `backup_config`, listen-address validator, systemd drop-in helpers, status, validate, loglevel/listen/metrics, log, backup |
| `lib/lifecycle.sh` | 1082 | 1077 | 12 | patch overlay, deploy-repo helpers, man page, `config branch`, deps, install / upgrade / uninstall |
| `lib/dispatch.sh` | 442 | 438 | 9 | caller tiers, sudoers drop-ins, `cmd_config` dispatcher, `usage` |
| **Total** | **11,360** | **11,283** | **211** | 11,283 original + 46 header lines + 31 load-block lines |

### Departures from the plan's proposed list

The file names are unchanged. What differs from what the plan implies:

1. **The main `case` stays in `bin/tacctl.sh`, not `lib/dispatch.sh`.** Lines 11188–11283 are one top-level `if [[ "${BASH_SOURCE[0]}" == "$0" ]]` block. Moved verbatim into a lib file the test would be `lib/dispatch.sh == $0`, always false, and nothing would ever dispatch. Wrapping the body in a new function would work but adds a function (WP0.2's acceptance demands identical function sets) and is an edit, not a move. WP2.3's "Read first: `lib/dispatch.sh` (usage, main case)" should read "`lib/dispatch.sh` (usage) and `bin/tacctl.sh` (main case)".
2. **`lib/dispatch.sh` therefore holds the caller-tier gate and the sudoers commands** (1983–2080, 9544–9709) with `cmd_config` and `usage`. `enforce_tier` is the first thing the main `case` calls, and WP2.3 edits `tier_permits`, `emit_tier_sudoers` and `usage` together.
3. **`PATCH_DIR` (75–78) and `SCRIPT_DIR` (1429–1431) stay in the entrypoint** rather than going to `core.sh` and `render_devices.sh`. Both read `BASH_SOURCE[0]`; see §5. WP1.1's "`lib/core.sh` (paths, ex-`:29-83`)" is right except for line 78.
4. **`cmd_user` (11135–11185) goes to `users.sh`**, matching `cmd_group` in `groups.sh` and `cmd_scope` in `scopes.sh`.
5. **`cmd_hash*` (10065–10159) goes to `users.sh`** although it sits under the "SYSTEM LIFECYCLE COMMANDS" banner; it is the bcrypt helper for `user add --hash`. The banner itself (10061–10064) goes to `lifecycle.sh`.
6. **`get_config_value` and `cmd_config_show` (2910–3067) go to `groups.sh`** because WP1.4b (groups) is the package that rewrites them; this keeps 1.4a/b/c on disjoint files.
7. **`read_user_scopes` and `set_user_scopes` stay in `scopes.sh`** (inside 3068–3727), as WP1.4c expects, even though they act on users. WP1.4a and WP1.4c both touch user-scope code: `cmd_user_scope` is in `users.sh`, its helpers in `scopes.sh`.
8. **`cmd_status` and `cmd_config_validate` are in `service.sh`.** WP1.4c edits both while WP1.5 "owns the backup section" of the same file and WP1.3 adds to it. Those packages are planned as parallel worktrees; they will conflict in `lib/service.sh` unless coordinated. This is a planning note, not something the split can fix.

## 4. The map

### 4.1 Range table

Every line of the original, in order. `ENTRY` means it stays in `bin/tacctl.sh`. Each range ends on the blank line that separates it from the next block, so files concatenate cleanly.

| Lines | Target | What it is |
|---|---|---|
| 1–26 | ENTRY | shebang, header comment, `set -euo pipefail` |
| 27–33 | core | `: "${TACCTL_ETC:=…}"`, `TACCTL_LOG`, `TACCTL_BIN`, `TACCTL_CONFIG` |
| 34–50 | ENTRY | sudo re-exec, `umask 077` |
| 51–74 | core | `CONFIG` … `SERVICE_FILE`, `TACCTL_OVERRIDES_FILE`, `GO_VERSION`, `TACQUITO_REPO`, `TACQUITO_SRC` |
| 75–78 | ENTRY | `PATCH_DIR` and its comment |
| 79–84 | core | `TACQUITO_BIN`, `HASHGEN_BIN`, `DEPLOY_DIR`, `MANAGE_REPO`, `GO_BIN` |
| 85–805 | conf | conf framework (`conf_emit_defaults` … `conf_set_list`), then the source-time tunables 778–804 |
| 806–818 | users | `DISABLED_MARKER_HEX`, `is_disabled_hash` |
| 819–1238 | policy | `validate_regex` … `regenerate_tacquito_commands` |
| 1239–1274 | groups | `list_all_groups`, `get_group_privlvl` |
| 1275–1310 | policy | `write_group_commands` |
| 1311–1329 | core | colours, `info`, `warn`, `error`, `get_version` |
| 1330–1415 | lifecycle | `tacquito_patches_applied`, `apply_tacquito_patches`, `normalize_deploy_perms`, `ensure_safe_directory`, `install_man_page` |
| 1416–1427 | core | `preflight` |
| 1428 | render_devices | comment line heading the template block |
| 1429–1431 | ENTRY | `SCRIPT_DIR` and its two comment lines |
| 1432–1443 | render_devices | `TEMPLATE_DIR_LOCAL`, `TEMPLATE_DIR_REPO`, `resolve_template` |
| 1444–1449 | service | `restart_service` |
| 1450–1468 | users | `record_password_date`, `get_password_date` |
| 1469–1516 | service | `get_last_login`, `BACKUP_RETENTION`, `backup_config` |
| 1517–1596 | users | `generate_hash`, `normalize_bcrypt_hash`, `verify_hash` |
| 1597–1647 | core | `validate_class_name`, `validate_username`, `reject_reserved_username`, `validate_cidr` |
| 1648–1781 | render_devices | `cidr_to_cisco_wildcard`, mgmt-ACL readers/writers, `validate_acl_name` |
| 1782–1851 | service | `validate_listen_address`, `OVERRIDE_DIR`, `OVERRIDE_FILE`, drop-in helpers |
| 1852–1982 | users | `replace_user_hash`, `user_exists`, `get_user_hash`, `get_user_group`, password prompts |
| 1983–2080 | dispatch | `TIER_*`, `tier_for_privlvl`, `caller_tier`, `tier_permits`, `enforce_tier` |
| 2081–2909 | users | `cmd_list` … `cmd_move` |
| 2910–3067 | groups | `get_config_value`, `cmd_config_show` |
| 3068–3727 | scopes | scope helpers `read_default_scope` … `set_user_scopes` |
| 3728–3793 | core | `canonicalize_cidr`, `sort_cidrs_by_specificity`, `parse_cidr_list` |
| 3794–4700 | render_devices | `cmd_config_cisco`, `cmd_config_juniper`, `wti_access_level_for_privlvl`, `cmd_config_wti` |
| 4701–5581 | linux_hosts | `LINUX_*`, `PAM_TACPLUS_*`, `config linux` functions, `LINUX_HOSTS_FILE`, `host` functions |
| 5582–5633 | lifecycle | `cmd_config_branch` |
| 5634–5865 | scopes | `cmd_config_prefix_filter`, `read_prefix_list`, `write_prefix_list` |
| 5866–6041 | render_devices | `cmd_config_mgmt_acl` |
| 6042–7242 | scopes | `cmd_scope` … `cmd_scope_mgmt_acl` |
| 7243–7394 | users | `cmd_user_scope` |
| 7395–7528 | dispatch | `cmd_config` |
| 7529–8681 | groups | `cmd_group_list` … `cmd_group` |
| 8682–9543 | service | `cmd_status`, `cmd_config_validate`, `cmd_config_loglevel`, `cmd_config_listen`, `cmd_config_metrics` |
| 9544–9709 | dispatch | `SUDOERS_FILE`, `TIER_SUDOERS_FILE`, `emit_tier_sudoers`, `cmd_config_sudoers_tiers`, `cmd_config_sudoers` |
| 9710–9829 | conf | `cmd_config_password_age`, `cmd_config_bcrypt_cost`, `cmd_config_password_min_length`, `cmd_config_secret_min_length`, `cmd_config_dump` |
| 9830–10060 | service | `cmd_log_clear`, `cmd_log`, `cmd_backup` |
| 10061–10064 | lifecycle | "SYSTEM LIFECYCLE COMMANDS" banner |
| 10065–10159 | users | `cmd_hash`, `cmd_hash_usage`, `cmd_hash_generate`, `cmd_hash_commands` |
| 10160–11094 | lifecycle | `DEPS_*`, `_pkg_installed`, `_apt_install`, `ensure_dependencies`, `cmd_install`, `cmd_upgrade`, `cmd_uninstall` |
| 11095–11134 | dispatch | "MAIN" banner, `usage` |
| 11135–11185 | users | `cmd_user` |
| 11186–11283 | ENTRY | dispatch gate and main `case` |

### 4.2 Per-file composition

Within a file, ranges are concatenated in ascending original order, after the header.

| File | Ranges, in order |
|---|---|
| `bin/tacctl.sh` | 1–26, 34–50, 75–78, 1429–1431, *load block (new)*, 11186–11283 |
| `lib/core.sh` | 27–33, 51–74, 79–84, 1311–1329, 1416–1427, 1597–1647, 3728–3793 |
| `lib/conf.sh` | 85–805, 9710–9829 |
| `lib/policy.sh` | 819–1238, 1275–1310 |
| `lib/users.sh` | 806–818, 1450–1468, 1517–1596, 1852–1982, 2081–2909, 7243–7394, 10065–10159, 11135–11185 |
| `lib/groups.sh` | 1239–1274, 2910–3067, 7529–8681 |
| `lib/scopes.sh` | 3068–3727, 5634–5865, 6042–7242 |
| `lib/render_devices.sh` | 1428, 1432–1443, 1648–1781, 3794–4700, 5866–6041 |
| `lib/linux_hosts.sh` | 4701–5581 |
| `lib/service.sh` | 1444–1449, 1469–1516, 1782–1851, 8682–9543, 9830–10060 |
| `lib/lifecycle.sh` | 1330–1415, 5582–5633, 10061–10064, 10160–11094 |
| `lib/dispatch.sh` | 1983–2080, 7395–7528, 9544–9709, 11095–11134 |

### 4.3 Lib file header

Each lib file starts with this header, which ends at the first blank line. The files are not executable (mode 0644) and have no shebang; the first line tells shellcheck the dialect.

```
# shellcheck shell=bash
# tacctl lib/<name>.sh -- <one-line purpose>
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.
<blank>
```

`core.sh` and `lifecycle.sh` have one more line, directly after the first (reasons in §7.2):

```
# shellcheck disable=SC2034  # constants assigned here are read by the other lib files      (core.sh)
# shellcheck disable=SC2164  # errexit is set by bin/tacctl.sh before this file is sourced  (lifecycle.sh)
```

### 4.4 The load block (new text in `bin/tacctl.sh`)

Inserted after the `SCRIPT_DIR` line and before the dispatch gate: a blank line, the comment, eleven `source` lines each preceded by its shellcheck directive, a blank line. Explicit lines rather than a loop or a glob, for three reasons: the order is load-bearing, a loop variable would leak into the global namespace of a `set -u` script, and shellcheck can only follow constant paths.

```bash
# --- Load the library ---
# SCRIPT_DIR (above) is this file's real directory with symlinks resolved, so
# lib/ is found the same way through the /usr/local/bin/tacctl symlink, under
# the sudo re-exec, from a dev checkout, and when sourced by the test harness.
# Order: core.sh must come before conf.sh (conf.sh's source-time tunables
# overwrite the built-in defaults core.sh assigns and need
# TACCTL_OVERRIDES_FILE); render_devices.sh and linux_hosts.sh read SCRIPT_DIR.
# shellcheck source=lib/core.sh
source "${SCRIPT_DIR}/../lib/core.sh"
# shellcheck source=lib/conf.sh
source "${SCRIPT_DIR}/../lib/conf.sh"
# shellcheck source=lib/policy.sh
source "${SCRIPT_DIR}/../lib/policy.sh"
# shellcheck source=lib/users.sh
source "${SCRIPT_DIR}/../lib/users.sh"
# shellcheck source=lib/groups.sh
source "${SCRIPT_DIR}/../lib/groups.sh"
# shellcheck source=lib/scopes.sh
source "${SCRIPT_DIR}/../lib/scopes.sh"
# shellcheck source=lib/render_devices.sh
source "${SCRIPT_DIR}/../lib/render_devices.sh"
# shellcheck source=lib/linux_hosts.sh
source "${SCRIPT_DIR}/../lib/linux_hosts.sh"
# shellcheck source=lib/service.sh
source "${SCRIPT_DIR}/../lib/service.sh"
# shellcheck source=lib/lifecycle.sh
source "${SCRIPT_DIR}/../lib/lifecycle.sh"
# shellcheck source=lib/dispatch.sh
source "${SCRIPT_DIR}/../lib/dispatch.sh"
```

The `source=` paths are relative to the directory shellcheck runs in, which is the repo root under `make lint`.

## 5. Sourcing order and top-level statements

### 5.1 Order and the constraints behind it

`core → conf → policy → users → groups → scopes → render_devices → linux_hosts → service → lifecycle → dispatch`

Only three constraints are real; the rest of the order is the plan's and is free:

1. **`core.sh` before `conf.sh`.** Lines 55–58 (core) assign the built-in values of `PASSWORD_MAX_AGE_DAYS`, `BCRYPT_COST`, `PASSWORD_MIN_LENGTH`, `SECRET_MIN_LENGTH`. Lines 778–804 (conf) overwrite them from `tacctl.yaml`. Reversed, the built-ins would silently win and every operator override of those four tunables would be ignored. Lines 778–804 also need `TACCTL_OVERRIDES_FILE` (line 68, core). These are the only variables assigned twice at top level. **[V]**
2. **`SCRIPT_DIR` (entrypoint) before `render_devices.sh` and `linux_hosts.sh`.** Lines 1433 and 4712 expand it at source time; under `set -u` an unset `SCRIPT_DIR` aborts.
3. **Base paths (27–33, first lines of `core.sh`) before everything else in `core.sh` and before any other lib file.** Satisfied by `core.sh` being first and its ranges being in ascending order.

Functions may reference each other across files in any direction; bash resolves names at call time and every file is loaded before the dispatch gate runs.

### 5.2 Every top-level statement

Evaluation order in the split tree is the order of this table. "Moved earlier/later" is relative to the original file; a blank cell means its position relative to everything it depends on is unchanged.

| Orig. line | Statement | Lands in | Depends on | Order change and why it is safe |
|---|---|---|---|---|
| 25 | `set -euo pipefail` | ENTRY | – | |
| 38–48 | sudo re-exec | ENTRY | `BASH_SOURCE[0]`, `$0`, `$@`, `EUID`, `TACCTL_SKIP_SUDO`, `SSH_AUTH_SOCK` | Now runs before 29–32. It reads none of those four variables, and `:=` does not export, so the re-exec'd process sees the same environment. |
| 49 | `umask 077` | ENTRY | – | Now before 29–32, which create no files. |
| 78 | `PATCH_DIR=…` | ENTRY | `TACCTL_PATCH_DIR`, `BASH_SOURCE[0]`; runs `readlink`, `dirname` | Now before 51–74. Nothing reads `PATCH_DIR` at source time. |
| 1431 | `SCRIPT_DIR=…` | ENTRY | `BASH_SOURCE[0]`; runs `readlink`, `dirname`, `cd`, `pwd` | **Moved earlier**, ahead of all of core/conf. Nothing between its old and new position reads or sets it (uses: 1433, 4712, and inside `cmd_install` 10229, `cmd_upgrade` 10641). If it fails, `set -e` exits in both layouts; the only work skipped is read-only (`conf_get`). |
| 29–32 | `: "${TACCTL_ETC:=…}"` ×4 | core | environment | Moved after the sudo re-exec and umask (see above). |
| 51–64 | `CONFIG` … `SERVICE_FILE` | core | `TACCTL_CONFIG`, `TACCTL_ETC`, `TACCTL_LOG` | |
| 68 | `TACCTL_OVERRIDES_FILE` | core | `TACCTL_ETC` | |
| 71–74 | `GO_VERSION`, `TACQUITO_REPO`, `TACQUITO_SRC` | core | env `TACQUITO_SRC` | |
| 79–83 | `TACQUITO_BIN`, `HASHGEN_BIN`, `DEPLOY_DIR`, `MANAGE_REPO`, `GO_BIN` | core | `TACCTL_BIN` | |
| 1312–1317 | `RED` … `NC` | core | – | Moved earlier (was after the conf block). `info/warn/error` are not called at source time. |
| 199 | `_TACCTL_CFG_CACHE=""` | conf | – | Must precede 778 (`_conf_load_cache` tests it under `set -u`); same file, same order. |
| 778–781 | `PASSWORD_MAX_AGE_DAYS=$(conf_get …)` + clamp | conf | **source-time call** `conf_get`; `TACCTL_OVERRIDES_FILE`; line 55; `python3` + PyYAML | |
| 786–789 | `BCRYPT_COST=$(conf_get …)` + clamp | conf | same; line 56 | |
| 793–796 | `PASSWORD_MIN_LENGTH=$(conf_get …)` + clamp | conf | same; line 57 | |
| 801–804 | `SECRET_MIN_LENGTH=$(conf_get …)` + clamp | conf | same; line 58 | |
| 811–813 | `DISABLED_MARKER_HEX=` then `+=` ×2 | users | each other | Three consecutive lines; must stay together and in order. |
| 1432 | `TEMPLATE_DIR_LOCAL` | render_devices | `TACCTL_ETC` | Moved later. Only read inside `resolve_template`. |
| 1433 | `TEMPLATE_DIR_REPO=$(cd "${SCRIPT_DIR}/../config/templates" … pwd \|\| true)` | render_devices | `SCRIPT_DIR` | Moved later. Value is normalised by `pwd`, so identical. |
| 4711–4719 | `LINUX_DIR`, `LINUX_SRC_DIR`, `LINUX_UID_FILE`, `LINUX_UID_BASE`, `PAM_TACPLUS_*`, `LINUX_BUILDS_DIR` | linux_hosts | `TACCTL_LINUX_DIR`, `SCRIPT_DIR`, `TACCTL_ETC`, and `LINUX_DIR` (4718, 4719) | |
| 5209 | `LINUX_HOSTS_FILE` | linux_hosts | `TACCTL_ETC` | |
| 1489 | `BACKUP_RETENTION=30` | service | – | Moved later. Read only inside `backup_config`. |
| 1816–1817 | `OVERRIDE_DIR`, `OVERRIDE_FILE` | service | `TACCTL_OVERRIDE_DIR`; 1817 needs 1816 | Moved later. Read only inside functions. |
| 10164–10165 | `DEPS_CORE`, `DEPS_LINUX_HOSTS` | lifecycle | – | |
| 1997–2000 | `TIER_USERS_GROUP`, `TIER_GROUP_*` | dispatch | – | Moved later. Read only inside functions. |
| 9548, 9550 | `SUDOERS_FILE`, `TIER_SUDOERS_FILE` | dispatch | `TACCTL_SUDOERS_FILE`, `TACCTL_TIER_SUDOERS_FILE` | Moved later. Read only inside functions. |
| 11188–11283 | dispatch gate + main `case` | ENTRY | `BASH_SOURCE[0]`, `$0`, `$@`, every `cmd_*`, `enforce_tier`, `preflight`, `usage`, `get_version`, `list_scopes`, `CONFIG`, `BACKUP_DIR` | Still last. |

### 5.3 Source-time function calls

The only functions that run while the script is being sourced are the four `conf_get` calls at 778, 786, 793, 801. Call chain: `conf_get` → `_conf_walk` → `_conf_load_cache` → `conf_emit_defaults`, plus `python3`. All four functions are in `conf.sh`, defined above the calls; the only cross-file input is `TACCTL_OVERRIDES_FILE` from `core.sh`. There are **no cross-file source-time calls**. **[V]** by reading the four bodies (lines 112–269); none calls `info/warn/error` or anything outside the conf block.

Everything else is called from the main `case`, after all files are loaded.

## 6. What must stay in the entrypoint, and what changes meaning when moved

### 6.1 Must stay

| Lines | Why |
|---|---|
| 1 (shebang) | `bin/tacctl.sh` is what gets executed, through the symlink. |
| 25 `set -euo pipefail` | Must be in force before any lib file is read. It also applies to the bats shell that sources the script, as today. |
| 38–48 sudo re-exec | Uses `$0` and `"$@"` of the invoked script, and `BASH_SOURCE[0] == $0` to tell "executed" from "sourced". In a lib file `BASH_SOURCE[0]` is the lib file and the test is always false. It must also run **before** the lib files are sourced: an unprivileged caller should not need read access to `lib/` beyond what `hash` needs (§6.3). |
| 49 `umask 077` | Kept adjacent to the re-exec, ahead of any code that could create files. |
| 78 `PATCH_DIR` | Reads `BASH_SOURCE[0]`. In `lib/core.sh` it would evaluate to `<repo>/lib/../patches`: the same directory but a different string, and a wrong directory altogether if the code later moves to `lib/backends/` (WP2.1). Kept here, its value is byte-identical. |
| 1431 `SCRIPT_DIR` | Reads `BASH_SOURCE[0]`. It must mean "the directory of `bin/tacctl.sh`": the load block, `LINUX_SRC_DIR` (whose string value `…/bin/../config/linux` is preserved this way) and `PROJECT_DIR` in install/upgrade all derive from it. |
| 11188–11283 dispatch gate | `BASH_SOURCE[0] == $0` again; see §3 departure 1. |

### 6.2 Changes meaning when moved, and how each case is handled

| Construct | Where | Handling |
|---|---|---|
| `BASH_SOURCE[0]` at top level | 38, 78, 1431, 11188 | All four stay in the entrypoint. |
| `BASH_SOURCE[0]` inside a function | `get_version`, line 1326 | Moves to `lib/core.sh`. Inside a function, `BASH_SOURCE[0]` is the file that **defines** the function, so it becomes `<repo>/lib/core.sh`. The function only uses it as `git -C "<dir>/.."`, and `lib/..` is the same repo root as `bin/..`. Output is identical **[V]**. This holds only while the defining file is exactly one level below the repo root; do not move `get_version` into `lib/backends/`. |
| `$0` | 38, 45, 47, 11188 | Entrypoint only. No function uses `$0`. **[V]** (grep) |
| `SCRIPT_DIR` consumers | 1433, 4712, 10229, 10641 | Unchanged text; the value is unchanged because the assignment stays in the entrypoint. |
| Relative paths | none | The script uses no path relative to the working directory at top level. |
| `readonly` / `declare` / `local` at top level | none | Nothing to handle. Rule for later packages: the test harness sources the entrypoint from inside a function (`tacctl_source_lib`), so a top-level `declare` or `local` in a lib file would create a variable local to that function and invisible to tests. Use plain assignment or `declare -g`. |
| `trap` | none anywhere at top level | – |
| `FUNCNAME`, `LINENO`, `caller`, `BASH_LINENO`, `BASH_ARGV` | none | No code depends on file names or line numbers. No test asserts on a line number. **[V]** (grep) |
| Heredocs and multi-line strings | many, all inside functions or inside the main `case` | No cut falls inside one. **[V]** by a heredoc-aware scan and by `bash -n` on every output file. |
| Exit status of `source` under `set -e` | load block | A sourced file returns the status of its last command; a non-zero status would abort. Every lib file ends with a function definition (status 0). `conf.sh` ends with `cmd_config_dump`, not with the clamp `if` blocks. **[V]** |

### 6.3 How `bin/tacctl.sh` finds `lib/`

`SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"`, then `"${SCRIPT_DIR}/../lib/<name>.sh"`. `readlink -f` resolves every symlink in the path, so:

| Invocation | `BASH_SOURCE[0]` | `SCRIPT_DIR` | Result |
|---|---|---|---|
| `tacctl …` via `/usr/local/bin/tacctl` → `/opt/tacctl/bin/tacctl.sh` | `/usr/local/bin/tacctl` | `/opt/tacctl/bin` | `/opt/tacctl/bin/../lib/` **[V]** with a scratch symlink, by absolute path and via `PATH` |
| Non-root, any command except `hash` | – | not reached | Lines 38–48 `exec sudo "$0" "$@"` before the load block. `$0` is the path as invoked (`/usr/local/bin/tacctl`, or `./bin/tacctl.sh`), same as today. **[V]** with a stub `sudo`. |
| Re-exec'd under sudo | same `$0` | same | The root process resolves the same path. sudo keeps the working directory, so a relative `$0` still resolves, as today. `secure_path` is irrelevant because `$0` contains a slash. **[R]** |
| Non-root `tacctl hash …` | as invoked | resolved | Runs without sudo, so the invoking user must be able to read `lib/*.sh` and traverse `lib/`. See §7.4. **[V]** that `hash` loads the libs unprivileged. |
| `./bin/tacctl.sh`, `bash bin/tacctl.sh` from a checkout | relative path | absolute | Works. **[V]** |
| Sourced by bats (`tacctl_source_lib` → `source "$TACCTL_BIN_SCRIPT"`) | `<repo>/bin/tacctl.sh` | `<repo>/bin` | Libs load; `$0` is the bats runner, so neither gate fires. **[V]** |
| `cmd_upgrade` self re-exec (`exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade`) | `/opt/tacctl/bin/tacctl.sh` | `/opt/tacctl/bin` | Works. **[R]** |
| A **copy** of `bin/tacctl.sh` placed somewhere without `lib/` | the copy | the copy's directory | Fails at the first `source` with bash's own message (`…/lib/core.sh: No such file or directory`), exit 1 **[V]**. One test does exactly this (§7.5). An install where `/usr/local/bin/tacctl` is a copy rather than a symlink would break the same way. On the dev server it is a symlink **[V]**; on production **[A]** (the installer and README only ever create a symlink). |

**Decision required by the plan: tests keep calling `tacctl_source_lib` on `bin/tacctl.sh`.** `tests/helpers/setup.bash` and `tests/helpers/tmpenv.bash` need no functional change.

## 7. Follow-on edits for WP0.2 (outside the move itself)

Do the mechanical split first and run the §9 checks on it. Only then make these edits; §9.2 compares function bodies byte-for-byte and will fail on `lib/lifecycle.sh` once 7.3 and 7.4 are applied, which is expected.

### 7.1 `Makefile`

```make
# coverage: line 24
	$(KCOV) --include-path=bin,lib,tests/helpers --bash-dont-parse-binary-dir \

# lint: line 30
	$(SHELLCHECK) bin/tacctl.sh lib/*.sh
```

The installed kcov attributes lines to the lib files with that include path **[V]** (one test file run under kcov against the prototype; the full coverage run was not done).

### 7.2 shellcheck

Measured on the prototype with shellcheck 0.9.0 **[V]**:

- `source=lib/<name>.sh` directives in the load block are enough. No SC1090 or SC1091 appears as long as the lib files are passed on the same command line. `-x` is not needed and changes nothing when the files are listed.
- **Do not replace the per-file lint with `shellcheck -x bin/tacctl.sh` alone.** It follows the sources but reports only the entrypoint's findings (1 instead of 40); the lib files would go unlinted.
- Linting the lib files individually adds 38 findings. 32 are artefacts of the split, in two groups:
  - SC2034 ×23 in `core.sh`: constants assigned there and read in other files. Handled by the file-level `disable=SC2034` in the `core.sh` header.
  - SC2164 ×9 in `lifecycle.sh` (`cd` without `|| exit`): shellcheck no longer sees `set -e`, which is in the entrypoint. Handled by the file-level `disable=SC2164` in the `lifecycle.sh` header.
- With those two directives the result is **46 findings: the 40 baseline findings, unchanged, plus 6 that the monolith was masking**:
  - `lib/policy.sh`: SC2034 warning, `local line` in `conf_migrate_command_rules` (orig. line 1005) is never used. In the monolith other functions use a variable called `line`, which hid it.
  - `lib/service.sh`: SC2030 ×2 and SC2031 ×3 notes on `errors` in `cmd_config_validate` (orig. 9026–9244), modified inside a pipeline subshell.

  These are real observations about existing code. Fixing or suppressing them means touching function bodies, which is outside WP0.2. Recommendation: leave them visible and report them.
- The existing inline directives (`disable=SC2016` at original lines 514, 727, 4585, 4928, 4982, 5267) are inside function bodies and move with them.
- `tests/helpers/tmpenv.bash` keeps its `# shellcheck disable=SC1090`.

Acceptance for lint should therefore be: `shellcheck -f gcc bin/tacctl.sh lib/*.sh`, with file names and positions stripped, equals the baseline list plus exactly the 6 findings above. Command to produce a comparable list: `shellcheck -f gcc <files> | grep -oE '(error|warning|note): .*' | sort`.

### 7.3 Self-update detection in `cmd_upgrade` (orig. 10762–10788, now in `lib/lifecycle.sh`)

Today the upgrade copies `bin/tacctl.sh` to a temp file, pulls, and re-execs if the file changed. After the split a release that changes only `lib/*.sh` would not re-exec, and the rest of the upgrade would run with the old code already loaded in memory.

`LOCAL_MANAGE` (the commit before the pull) is already computed at orig. 10759–10760 and `git checkout -- .` at 10737 has already made the tree equal to it, so compare commits instead of files:

Remove (orig. 10763–10766):
```bash
            # Copy self to temp before pull (git pull will overwrite the running script)
            local SELF_TMP
            SELF_TMP=$(mktemp)
            cp "${DEPLOY_DIR}/bin/tacctl.sh" "$SELF_TMP"
```
Remove the `rm -f "$SELF_TMP"` in the pull-failure branch (orig. 10776).

Replace (orig. 10781–10787):
```bash
            # If tacctl changed, re-run the new version
            if ! diff -q "$SELF_TMP" "${DEPLOY_DIR}/bin/tacctl.sh" &>/dev/null; then
                rm -f "$SELF_TMP"
                info "tacctl updated — restarting upgrade with new version..."
                exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade
            fi
            rm -f "$SELF_TMP"
```
with:
```bash
            # If tacctl's own code changed (entrypoint or lib/), re-run the new version
            if ! git diff --quiet "$LOCAL_MANAGE" HEAD -- bin lib; then
                info "tacctl updated — restarting upgrade with new version..."
                exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade
            fi
```

`git diff --quiet A B -- bin lib` returns 0 when nothing under those paths differs, 1 when something does (including `lib/` appearing for the first time), and 128 on error, which the `if !` treats as "changed" and re-execs; the re-exec'd run then finds nothing to pull, so it cannot loop. **[V]** in a scratch repository. It is used as an `if` condition, so `set -e` does not trip. The plan's wording, "a hash of `bin/ lib/`", is satisfied in substance.

No test covers `cmd_upgrade`; this edit is unverified by the suite (§11).

The stale-code concern while pulling is unchanged: all lib files are fully read and parsed before `cmd_upgrade` starts, and the main `case` is one compound command that bash parses whole before running, so `git pull` replacing files on disk does not affect the running shell. **[R]**

### 7.4 Permissions

The script runs with `umask 077`, so files that git creates or rewrites during `tacctl upgrade` / `config branch` come out 0600 (0700 for directories and executables).

| Site | Orig. line | Covers `lib/`? | Action |
|---|---|---|---|
| `normalize_deploy_perms` (`chmod -R a+rX "$DEPLOY_DIR"`) | 1384–1387 | **Yes already**: recursive, adds read to files and traverse to directories. | None. |
| `cmd_install`: `normalize_deploy_perms`, then `chmod 755 …/bin/tacctl.sh` | 10339, 10349 | Yes, via normalize. | None. |
| `cmd_upgrade`: `normalize_deploy_perms`, then `chmod 755 …/bin/tacctl.sh` | 10797, 10804 | Yes, via normalize. | None. |
| `cmd_config_branch`: `chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"` only, after a checkout and pull | 5627 | **No.** Lib files changed by the branch switch stay 0600 root. Everything that goes through sudo still works; unprivileged `tacctl hash` fails to source them until the next `tacctl upgrade`. | Insert `normalize_deploy_perms` on the line before 5627. |

Lib files need to be readable, not executable: 0644, directory 0755. They are sourced as root, so they must stay root-owned and not group- or world-writable; `a+rX` never adds write permission. This is the same trust the entrypoint already has.

`cmd_uninstall` removes the whole of `$DEPLOY_DIR` (11057) and the symlink (11010); nothing to change. The `-bak` cleanup at 10744 only concerns `bin/tacctl.sh.*-bak` files, which nothing creates for `lib/`.

### 7.5 Tests

- **`tests/integration/config_templates.bats`, test "config wti: falls back to the inline walkthrough when no template resolves" (lines 246–253) must change.** It copies `bin/tacctl.sh` alone to `$BATS_TEST_TMPDIR/alt/bin/` and runs the copy so that no repo template directory resolves. After the split the copy has no `lib/` and exits 1. Add one line after the existing `cp`:
  ```bash
  cp -r "${TACCTL_SRC}/lib" "$BATS_TEST_TMPDIR/alt/lib"
  ```
  This is the only test that fails on the split (§10). "All 524 tests pass unchanged" in the plan needs this one exception.
- `tests/unit/sanity.bats`: add the two tests the plan asks for. Suggested bodies:
  ```bash
  @test "sanity: entrypoint and every lib file pass bash -n" {
      local f
      for f in "$TACCTL_SRC"/bin/tacctl.sh "$TACCTL_SRC"/lib/*.sh; do
          run bash -n "$f"
          assert_success
      done
  }

  @test "sanity: no function is defined twice across bin/ and lib/" {
      run bash -c 'grep -hoE "^[a-zA-Z_][a-zA-Z0-9_]*\(\)" "$1"/bin/tacctl.sh "$1"/lib/*.sh | sort | uniq -d' _ "$TACCTL_SRC"
      assert_success
      assert_output ""
  }
  ```
  The grep finds all 211 definitions and no duplicates on the prototype **[V]**. The test count becomes 526.
- `tests/helpers/tmpenv.bash`: comments only (lines 19, 23–24 say defaults are "embedded in bin/tacctl.sh" and "Source tacctl.sh"). No functional change.
- `tests/helpers/setup.bash`: no change. `TACCTL_BIN_SCRIPT` still points at `bin/tacctl.sh`.

### 7.6 `tests/README.md`

- Line 3: "Test suite for `bin/tacctl.sh`" → mention the entrypoint and `lib/*.sh`.
- "Layout" block: add a note that the code under test is `bin/tacctl.sh` (entrypoint) plus `lib/*.sh`, loaded by `tacctl_source_lib`.
- "Coverage baseline" table: the `bin/tacctl.sh` row (52.14 %, 2283 / 4379 lines, "335 tests") is already stale and after the split the figure is spread over twelve files. Either re-measure with `make coverage` or mark the table as pre-split.
- `make lint` comment: now covers `lib/*.sh`.

### 7.7 Other references to the script path

| Where | What | Action in WP0.2 |
|---|---|---|
| `README.md` lines 41–43, "Project Structure" | lists only `bin/tacctl.sh` | Add `lib/`. |
| `README.md` 70, 439, 472; `man/tacctl.1` 379, 1272, 1376 | "defaults embedded in `bin/tacctl.sh`" | Now `lib/conf.sh`. Documentation only; can wait for WP5.1. |
| `lib/conf.sh` (orig. 9806), `cmd_config_dump` | prints `Defaults:  embedded in bin/tacctl.sh (conf_emit_defaults)` | **Leave as is.** It is user-visible output and changing it is a behaviour change. No test asserts on it. Hand to WP5.1. |
| Comment at orig. 116, header comment at 3–23 | mention `bin/tacctl.sh` / `./tacctl.sh` | Leave. |
| `README.md` 9, 697; `man/tacctl.1` 1309–1311 | install one-liner and symlink description | Still correct. |
| `config/tacctl.bash-completion` | calls `tacctl` and `sudo -n tacctl _completion-names`; never names the script path | None. **[V]** |
| `config/tacquito.service`, `config/tacquito.logrotate`, `config/linux/*.sh`, `patches/` | no reference | None. **[V]** |
| sudoers bodies (orig. 9557, 9695) | `/usr/local/bin/tacctl` | None. |
| `.gitignore` | `coverage/` only | None. |
| kcov | via `Makefile` only | §7.1. |
| `.claude/settings.local.json` (untracked, local) | allow-rules name `bin/tacctl.sh` explicitly (`git add bin/tacctl.sh …`, `bash -n …/bin/tacctl.sh`) | Not part of the repo. The user may want matching rules for `lib/`. |

## 8. Where the plan's WP0.2 text cannot be met as written

1. **"`make lint && make test` green."** Lint is red today (§2). Use the comparison in §7.2 instead.
2. **"All 524 tests pass unchanged."** One test must gain a line (§7.5).
3. **"`bin/tacctl.sh` sources `"${SCRIPT_DIR}/../lib/"*.sh` in the listed order."** A glob sorts alphabetically (`conf` before `core`), which breaks constraint 1 of §5.1. Use the explicit load block of §4.4.

Also relevant to WP0.2's "Worktree: must run alone" and to every later package planned for a separate worktree: five golden-file tests only pass when the repo is checked out at `/home/user/tacctl`. The golden files under `tests/fixtures/golden/` contain the line `- Using template: /home/user/tacctl/config/templates/<name>.template`. In any other directory tests "config cisco … lab scope", "… prod scope", "config cisco --legacy …", "config juniper …" and "config wti: renders deterministic walkthrough …" fail, split or no split **[V]** (§10). Run WP0.2 in the main checkout, or expect those five failures in a worktree.

## 9. Procedure and checks for WP0.2

Extract each script from this document with, for example:

```
awk '/^```bash title=split.sh$/{f=1;next} f&&/^```$/{f=0} f' docs/split-map.md > /tmp/split.sh
```

(and likewise `title=check.py` with ```` ```python ````, `title=state.sh`).

Order of work:

1. Confirm `git status` shows `bin/tacctl.sh` unmodified and HEAD's blob for it is `2a00219…`.
2. `bash /tmp/split.sh /home/user/tacctl`
3. `python3 /tmp/check.py /home/user/tacctl` → must end with `PASS`.
4. `for f in bin/tacctl.sh lib/*.sh; do bash -n "$f"; done`
5. `bash /tmp/state.sh /home/user/tacctl` → must print `IDENTICAL (211 functions, 78 variables)`.
6. Apply §7 edits. Re-run step 4 and step 5 (step 5 still passes: the edits change function bodies, not names or variables; step 3 will now fail on `lib/lifecycle.sh`, as expected).
7. `make test`; lint comparison per §7.2.

Steps 3 and 5 read the original from `git show HEAD:bin/tacctl.sh`, so they work for as long as the split is uncommitted.

### 9.1 `split.sh`: performs the move

```bash title=split.sh
#!/usr/bin/env bash
# Usage: bash split.sh <repo-root>   -- rewrites <repo-root>/bin/tacctl.sh and creates <repo-root>/lib/*.sh
set -euo pipefail
ROOT="$(cd "${1:?repo root}" && pwd)"
ORIG="$(mktemp)"; trap 'rm -f "$ORIG"' EXIT
cp "$ROOT/bin/tacctl.sh" "$ORIG"
[[ "$(wc -l < "$ORIG")" -eq 11283 ]] || { echo "bin/tacctl.sh is not the 11283-line original" >&2; exit 1; }
[[ "$(sha256sum < "$ORIG" | cut -d' ' -f1)" == "b5a59714f08d911ba2b66807a4fa3b2a1ae8d3a051f219801daa55150b08ef30" ]] || { echo "bin/tacctl.sh sha256 mismatch" >&2; exit 1; }
r() { sed -n "${1},${2}p" "$ORIG"; }          # emit original lines $1..$2
# hdr <name> <purpose> [extra shellcheck directive line]; the header ends at the first blank line.
hdr() {
    printf '# shellcheck shell=bash\n'
    [[ -n "${3:-}" ]] && printf '%s\n' "$3"
    printf '# tacctl lib/%s.sh -- %s\n' "$1" "$2"
    printf '# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.\n\n'
}
mkdir -p "$ROOT/lib"

{ hdr core "paths, constants, output helpers, version, preflight, shared validators and CIDR helpers" \
      '# shellcheck disable=SC2034  # constants assigned here are read by the other lib files'
  r 27 33; r 51 74; r 79 84; r 1311 1329; r 1416 1427; r 1597 1647; r 3728 3793; } > "$ROOT/lib/core.sh"
{ hdr conf "tacctl.yaml: defaults, schema, read/write API, source-time tunables, tunable setters, config dump"
  r 85 805; r 9710 9829; } > "$ROOT/lib/conf.sh"
{ hdr policy "command-authorization rules and priv-exec mappings (commands.<group>, privileges.<group>), migrations, tacquito.yaml regeneration"
  r 819 1238; r 1275 1310; } > "$ROOT/lib/policy.sh"
{ hdr users "user data-model helpers, password/hash helpers, user and hash commands"
  r 806 818; r 1450 1468; r 1517 1596; r 1852 1982; r 2081 2909; r 7243 7394; r 10065 10159; r 11135 11185; } > "$ROOT/lib/users.sh"
{ hdr groups "group helpers, config show, group commands"
  r 1239 1274; r 2910 3067; r 7529 8681; } > "$ROOT/lib/groups.sh"
{ hdr scopes "scope (secrets[]) helpers, allow/deny prefix filters, scope commands"
  r 3068 3727; r 5634 5865; r 6042 7242; } > "$ROOT/lib/scopes.sh"
{ hdr render_devices "device templates, mgmt-ACL data, Cisco/Juniper/WTI renderers"
  r 1428 1428; r 1432 1443; r 1648 1781; r 3794 4700; r 5866 6041; } > "$ROOT/lib/render_devices.sh"
{ hdr linux_hosts "config linux (pam_tacplus client scripts, prebuilt modules) and host enroll/sync/unenroll"
  r 4701 5581; } > "$ROOT/lib/linux_hosts.sh"
{ hdr service "daemon control: restart, systemd drop-in, backups, status, validate, loglevel/listen/metrics, log"
  r 1444 1449; r 1469 1516; r 1782 1851; r 8682 9543; r 9830 10060; } > "$ROOT/lib/service.sh"
{ hdr lifecycle "tacquito patch overlay, deploy-repo helpers, config branch, install/upgrade/uninstall" \
      '# shellcheck disable=SC2164  # errexit is set by bin/tacctl.sh before this file is sourced'
  r 1330 1415; r 5582 5633; r 10061 10064; r 10160 11094; } > "$ROOT/lib/lifecycle.sh"
{ hdr dispatch "caller tiers, sudoers drop-ins, config dispatcher, usage"
  r 1983 2080; r 7395 7528; r 9544 9709; r 11095 11134; } > "$ROOT/lib/dispatch.sh"

{ r 1 26; r 34 50; r 75 78; r 1429 1431
  cat <<'LOAD'

# --- Load the library ---
# SCRIPT_DIR (above) is this file's real directory with symlinks resolved, so
# lib/ is found the same way through the /usr/local/bin/tacctl symlink, under
# the sudo re-exec, from a dev checkout, and when sourced by the test harness.
# Order: core.sh must come before conf.sh (conf.sh's source-time tunables
# overwrite the built-in defaults core.sh assigns and need
# TACCTL_OVERRIDES_FILE); render_devices.sh and linux_hosts.sh read SCRIPT_DIR.
# shellcheck source=lib/core.sh
source "${SCRIPT_DIR}/../lib/core.sh"
# shellcheck source=lib/conf.sh
source "${SCRIPT_DIR}/../lib/conf.sh"
# shellcheck source=lib/policy.sh
source "${SCRIPT_DIR}/../lib/policy.sh"
# shellcheck source=lib/users.sh
source "${SCRIPT_DIR}/../lib/users.sh"
# shellcheck source=lib/groups.sh
source "${SCRIPT_DIR}/../lib/groups.sh"
# shellcheck source=lib/scopes.sh
source "${SCRIPT_DIR}/../lib/scopes.sh"
# shellcheck source=lib/render_devices.sh
source "${SCRIPT_DIR}/../lib/render_devices.sh"
# shellcheck source=lib/linux_hosts.sh
source "${SCRIPT_DIR}/../lib/linux_hosts.sh"
# shellcheck source=lib/service.sh
source "${SCRIPT_DIR}/../lib/service.sh"
# shellcheck source=lib/lifecycle.sh
source "${SCRIPT_DIR}/../lib/lifecycle.sh"
# shellcheck source=lib/dispatch.sh
source "${SCRIPT_DIR}/../lib/dispatch.sh"

LOAD
  r 11186 11283; } > "$ROOT/bin/tacctl.sh.new"
chmod --reference="$ROOT/bin/tacctl.sh" "$ROOT/bin/tacctl.sh.new"
mv "$ROOT/bin/tacctl.sh.new" "$ROOT/bin/tacctl.sh"
chmod 644 "$ROOT"/lib/*.sh
wc -l "$ROOT/bin/tacctl.sh" "$ROOT"/lib/*.sh
```

### 9.2 `check.py`: proves the ranges cover every original line exactly once

It rebuilds each file's expected body from the original and the range table and compares byte-for-byte, checks the table is a gap-free partition of 1–11283, and checks the load block contains only comments, blank lines and the eleven `source` lines in the right order.

```python title=check.py
#!/usr/bin/env python3
"""Prove the split is a pure partition of the original bin/tacctl.sh.
Usage: python3 check.py <repo-root> [<path-to-original>]   (original defaults to `git show HEAD:bin/tacctl.sh`)"""
import re, subprocess, sys
root = sys.argv[1]
orig = (open(sys.argv[2]).read() if len(sys.argv) > 2 else
        subprocess.run(["git", "-C", root, "show", "HEAD:bin/tacctl.sh"], check=True, capture_output=True, text=True).stdout)
O = orig.split("\n"); assert O[-1] == ""; O.pop()
assert len(O) == 11283, f"original has {len(O)} lines, expected 11283"
SEG = """1 26 ENTRY|27 33 core|34 50 ENTRY|51 74 core|75 78 ENTRY|79 84 core|85 805 conf|806 818 users|819 1238 policy
1239 1274 groups|1275 1310 policy|1311 1329 core|1330 1415 lifecycle|1416 1427 core|1428 1428 render_devices
1429 1431 ENTRY|1432 1443 render_devices|1444 1449 service|1450 1468 users|1469 1516 service|1517 1596 users
1597 1647 core|1648 1781 render_devices|1782 1851 service|1852 1982 users|1983 2080 dispatch|2081 2909 users
2910 3067 groups|3068 3727 scopes|3728 3793 core|3794 4700 render_devices|4701 5581 linux_hosts|5582 5633 lifecycle
5634 5865 scopes|5866 6041 render_devices|6042 7242 scopes|7243 7394 users|7395 7528 dispatch|7529 8681 groups
8682 9543 service|9544 9709 dispatch|9710 9829 conf|9830 10060 service|10061 10064 lifecycle|10065 10159 users
10160 11094 lifecycle|11095 11134 dispatch|11135 11185 users|11186 11283 ENTRY"""
segs = [(int(a), int(b), t) for a, b, t in (x.split() for x in SEG.replace("\n", "|").split("|"))]
ORDER = "core conf policy users groups scopes render_devices linux_hosts service lifecycle dispatch".split()
# 1. the table is a partition of 1..11283
nxt = 1
for a, b, _ in segs:
    assert a == nxt and b >= a, f"gap/overlap at {a}"; nxt = b + 1
assert nxt == 11284
def read(p):
    L = open(p).read().split("\n"); assert L[-1] == "", f"{p}: no trailing newline"; L.pop(); return L
# 2. each lib file == header (through first blank line) + its ranges, ascending, byte-identical
total = 0
for name in ORDER:
    L = read(f"{root}/lib/{name}.sh")
    h = L.index("") + 1
    assert all(x.startswith("#") for x in L[:h-1]) and L[0] == "# shellcheck shell=bash", f"{name}: bad header"
    want = [l for a, b, t in segs if t == name for l in O[a-1:b]]
    assert L[h:] == want, f"lib/{name}.sh body differs from the original ranges"
    total += len(want); print(f"ok  lib/{name}.sh  header={h}  body={len(want)}  total={len(L)}")
# 3. entrypoint == ranges 1-26,34-50,75-78,1429-1431 + load block + 11186-11283
E = read(f"{root}/bin/tacctl.sh")
pre = [l for a, b, t in segs[:-1] if t == "ENTRY" for l in O[a-1:b]]
post = O[11185:11283]
assert E[:len(pre)] == pre and E[-len(post):] == post, "bin/tacctl.sh prefix/suffix differs from the original ranges"
load = E[len(pre):len(E)-len(post)]
srcs = []
for l in load:
    m = re.fullmatch(r'source "\$\{SCRIPT_DIR\}/\.\./lib/([a-z_]+)\.sh"', l)
    if m: srcs.append(m.group(1))
    else: assert l == "" or l.startswith("#"), f"unexpected statement in load block: {l!r}"
assert srcs == ORDER, f"source order is {srcs}"
total += len(pre) + len(post)
assert total == 11283
print(f"ok  bin/tacctl.sh  original={len(pre)+len(post)}  load-block={len(load)}  total={len(E)}")
print("PASS: every original line appears exactly once, unmodified; source order correct")
```

### 9.3 `state.sh`: proves sourcing leaves the same shell state

```bash title=state.sh
#!/usr/bin/env bash
# Usage: bash state.sh <repo-root>
# Sources the pre-split script (git HEAD) and the split tree in clean shells and
# diffs everything sourcing leaves behind: functions, variable values, shell
# options, umask, traps. Prints IDENTICAL on success.
set -euo pipefail
ROOT="$(cd "${1:?repo root}" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/old/bin" "$T/etc" "$T/log" "$T/bin"
git -C "$ROOT" show HEAD:bin/tacctl.sh > "$T/old/bin/tacctl.sh"
ln -s "$ROOT/config" "$T/old/config"; ln -s "$ROOT/patches" "$T/old/patches"
dump() {
    env -i PATH="$PATH" HOME="$HOME" TACCTL_SKIP_SUDO=1 \
        TACCTL_ETC="$T/etc" TACCTL_LOG="$T/log" TACCTL_BIN="$T/bin" bash -c '
        source "$1"
        declare -F | sort; echo "opts=$-"; shopt -o; shopt; umask; trap -p
        for v in $(compgen -v | sort); do
            case $v in
                BASH_*|_|PWD|OLDPWD|SHLVL|PPID|RANDOM|SRANDOM|SECONDS|EPOCH*|LINENO|FUNCNAME|PIPESTATUS|BASHPID|HISTCMD|DIRSTACK|GROUPS|v) ;;
                *) declare -p "$v" ;;
            esac
        done' _ "$1" | sed "s#$2#ROOT#g"
}
dump "$T/old/bin/tacctl.sh" "$T/old" > "$T/before"
dump "$ROOT/bin/tacctl.sh"  "$ROOT"  > "$T/after"
diff "$T/before" "$T/after" && echo "IDENTICAL ($(grep -c '^declare -f' "$T/after") functions, $(grep -c '^declare -[-aAirx]* [A-Za-z_]*=' "$T/after") variables)"
```

## 10. What was run against a prototype

A copy of the repo was split with `split.sh` in a scratch directory (nothing in `/home/user/tacctl` was touched) and exercised:

| Check | Result |
|---|---|
| `check.py` | PASS |
| `bash -n` on all 12 files | clean |
| `state.sh` | IDENTICAL (211 functions, 78 variables) |
| `tacctl version`, bare `tacctl` (usage) via a symlink, via `PATH`, by relative path, as `bash bin/tacctl.sh` | same output as the original, apart from the `-dirty` suffix `git describe` adds for a modified tree |
| Non-root invocation with a stub `sudo` on `PATH` | re-exec fires before the load block with the original `$0` and arguments; `host` carries `SSH_AUTH_SOCK` |
| `tacctl hash commands` as non-root, no `TACCTL_SKIP_SUDO` | runs without sudo, libs load |
| Entrypoint copied without `lib/` | exits 1 with bash's "No such file or directory" for `lib/core.sh` |
| shellcheck | §7.2 |
| kcov on `tests/unit/sanity.bats` with `--include-path=bin,lib,tests/helpers` | lib files appear in the report with per-file line counts |
| `make test` in the scratch copy, 13 m 19 s | unit 143/143. integration 362/368. `make` stops at the first failing tier, so e2e was run separately: 13/13. |
| The 6 integration failures | 1 is the lib-less copy test (§7.5); with the one-line fix applied it passes. 5 are the golden tests of §8: the only differing line in each is `Using template: <checkout path>/config/templates/…`. The **unsplit** code copied to a scratch path fails the same 5 and no others. |

So on the split tree every test passes except the five whose golden files hard-code `/home/user/tacctl`, and those fail identically without the split when run from another directory. They could not be re-run at the canonical path without modifying the repo (an unprivileged bind mount is not permitted on this host).

## 11. Risks not ruled out by reading

1. **`cmd_upgrade`, `cmd_install`, `cmd_uninstall` and `cmd_config_branch` have no test coverage.** The edits in §7.3 and §7.4 are small and were reasoned through, and the `git diff --quiet` semantics were checked in a scratch repo, but the upgrade path itself was not executed. The first real run will be `tacctl upgrade` on the dev server.
2. **The transition upgrade (0.1.14 monolith → first split release).** The *old* code performs it: it pulls, sees `bin/tacctl.sh` changed, and execs the new entrypoint, which sources `lib/` from the tree just pulled, as root. By reading this works, and `normalize_deploy_perms` fixes modes later in the same run. Not run. If that upgrade aborts between the pull and the normalize step (a tacquito build or patch failure exits before reaching it), `lib/` is left root-only; root and sudo use keep working, unprivileged `tacctl hash` does not, until an upgrade completes. Today the same abort leaves `bin/tacctl.sh` itself 0700, which is worse, so this is not a regression.
3. **Switching branches across the split boundary with the old code.** `tacctl config branch <split-branch>` run by a 0.1.14 monolith leaves `lib/` 0700/0600 (the old `cmd_config_branch` only chmods `bin/tacctl.sh`). Same limited effect as risk 2, cleared by `tacctl upgrade`. Switching back from a split branch to a monolith branch removes `lib/` from disk, harmless to the running process.
4. **Production layout is assumed, not checked.** The lookup needs `/usr/local/bin/tacctl` to be a symlink into a checkout that contains `lib/`. That is what the installer creates and what the dev server has. The production host was not inspected, by instruction.
5. **Full coverage run not done.** kcov was checked on one test file only. `make coverage` on the split tree is unverified end to end, and takes several times longer than `make test`.
6. **The prototype's test run happened outside `/home/user/tacctl`.** Five golden tests fail there for a reason unrelated to the split (§8); their output differs from the golden files only in the checkout path, and the unsplit code fails the same five from a scratch path (§10). They have not been seen passing on split code, because that needs the split tree at `/home/user/tacctl`; WP0.2's own `make test` is that run.
7. **Lint drift with other shellcheck versions.** The counts in §7.2 are for 0.9.0. A different version may report a different baseline and a different set of newly unmasked findings.
8. **The prototype's lib headers during the full test run lacked the two `disable=` comment lines** added afterwards for `core.sh` and `lifecycle.sh`. They are comments; `bash -n`, `check.py`, `state.sh` and the lint comparison were re-run on the final form.

## 12. Assumed rather than verified

- sudo preserves the working directory and passes `$0` through unchanged on production as it does here (default sudoers behaviour).
- Production's `/usr/local/bin/tacctl` is a symlink (risk 4).
- No external tooling outside this repo (cron jobs, monitoring, other repos) reads or copies `bin/tacctl.sh` as a single self-contained file.
