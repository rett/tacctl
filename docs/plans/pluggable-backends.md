# tacctl: pluggable auth backends — final plan

Repo `/home/user/tacctl` (branch `develop`, latest tag `0.1.14`, git-flow develop → release/x.y.z → master). Dev host `devserver` tracks develop; the production host tracks master. **All verification in this plan is local bats or the dev hosts `devserver`/`client`; nothing touches production. No work package commits or pushes; the user does that on explicit request.**

Markers: **[V]** verified by reading code/docs or running a read-only check; **[I]** inferred from code; **[A]** assumption about external software that must be checked against upstream before relying on it (collected in §9).

---

## 1. Current state

### 1.1 Shape of the tool [V]

- **One bash script**, `bin/tacctl.sh` (11,283 lines, ~190 functions) with embedded Python heredocs for all YAML work. Symlinked to `/usr/local/bin/tacctl`; re-execs under sudo (`bin/tacctl.sh:38-48`); dispatch only when executed, not when sourced (`:11188`), which is how the test harness loads it (`tests/helpers/tmpenv.bash:23-27`).
- **Two config files, two roles:**
  - `/etc/tacquito/tacquito.yaml` — tacquito's config **and tacctl's source of truth for users, groups, scopes, allow/deny filters**, edited by regex surgery on YAML anchors (`bcrypt_<user>`, `exec_<group>`, `junos_exec_<group>`) and section markers (`# --- Services ---`, `# --- Groups ---`, `# --- Users ---`, `# --- Secret Providers`).
  - `/etc/tacquito/tacctl.yaml` — tacctl-only tunables (defaults `:112-193`, schema `:279-503`, merge/cache `:195-269`, write path `:511-813`). Holds `commands.<group>`, `privileges.<group>`, `mgmt_acl.*`, `aaa.order.<scope>`, `exec_timeout.<scope>`, `tacacs_group.<scope>`, `scope_mgmt_acl.*`, `scope.default`, password/bcrypt/secret tunables. `commands.<group>` is already **tacctl-canonical and rendered into tacquito.yaml** by `regenerate_tacquito_commands` (`:1165-1237`) — the precedent for "tacctl owns the data, the daemon config is generated".
- **Other tacctl state under `/etc/tacquito/`:** `backups/` (`tacquito.yaml.<ts>`, `password-dates/<u>.date`, `disabled/<u>.hash` for `user disable`/`enable` at `:2537-2615`), `linux-hosts` (`:5209`), `linux-uids` (`:4713`), `templates/`, `README.md`. Build cache `/var/lib/tacctl/linux/` (`:4711`).
- **Daemon lifecycle:** `cmd_install :10211-10604` installs Go 1.26.2, clones `facebookincubator/tacquito` into `/opt/tacquito-src`, applies `patches/*.patch` (`:1330-1378`), builds `/usr/local/bin/tacquito` and `tacquito-hashgen`, creates the `tacquito` service user, installs `config/tacquito.service`, logrotate, completion, man page. `cmd_upgrade :10610-10951` re-pulls, re-patches, rebuilds, self-updates `/opt/tacctl` and re-execs. Listener/loglevel/metrics are `TACQUITO_*` `Environment=` keys in a systemd drop-in (`:1811-1850`, `config/tacquito.service:14-35`).
- **tacquito facts [V, `/opt/tacquito-src`]:** one process = one `net.Listen(network, address)` (`cmds/server/main.go:116-146`); TLS per draft-ietf-opsawg-tacacs-tls13 via flags `-tls -tls-cert -tls-key -tls-ca -tls-require-client-cert` (`main.go:43-47`, `docs/tls_support.md`); YAML loader is a plain `yaml.v3` unmarshal into `config.ServerConfig` requiring ≥1 `secrets` and ≥1 `users` (`cmds/server/loader/yaml/*.go`); anchors are only a convenience — the loader sees the resolved structure. `loader.go`, `tls.go`, `aaa.go` are root-only (0600) on the dev server; read them with sudo if an implementer needs them.
- **Host side:** `tacctl host enroll|sync|unenroll|list` (`:5211-5580`) ships a generated script = header vars (`TAC_SERVER/TAC_PORT/TAC_SECRET/TAC_SCOPE/TAC_USERS`, `:4855-4882`) + `config/linux/client-install.sh` + base64 pam_tacplus tarball and optional prebuilt module. Prebuilt modules are compiled in a rootless podman container per OS release (`:4887-5011`). Registry line format `name|target|port|scope|server|identity` (`:5225`).
- **Tests:** bats; 143 unit / 368 integration / 13 e2e (524). Fixtures `tests/fixtures/tacquito.*.yaml`; harness redirects `TACCTL_ETC/LOG/BIN/CONFIG/OVERRIDE_DIR/SUDOERS_FILE` into a tmpdir; stubs for `systemctl`, `journalctl`, `ssh`, `podman`, etc. `make lint` shellchecks `bin/tacctl.sh tests/helpers/*.bash config/linux/*.sh`; `make coverage` includes `bin,tests/helpers`.
- **Environment on the dev server [V]:** KDE neon (Ubuntu 24.04 base); `freeradius 3.2.5` and `libpam-radius-auth 2.0.1` available via apt, neither installed; libxcrypt bcrypt present (`crypt.METHOD_BLOWFISH` → True); Go 1.26.2; `python3-yaml` installed but **not** in `DEPS_CORE` (`:10164`) — latent gap, fix in passing.

### 1.2 Coupling inventory

**A. Structural — paths, units, identities**

| What | Where |
|---|---|
| Defaults `TACCTL_ETC=/etc/tacquito`, `TACCTL_LOG=/var/log/tacquito`, `TACCTL_CONFIG=…/tacquito.yaml` | `bin/tacctl.sh:29-32` |
| `CONFIG`, `BACKUP_DIR`, `PASSWORD_DATES_DIR`, `ACCT_LOG`, `SERVICE_FILE=/etc/systemd/system/tacquito.service`, `TACCTL_OVERRIDES_FILE` | `:51-68` |
| `GO_VERSION`, `TACQUITO_REPO/SRC/BIN`, `HASHGEN_BIN`, `PATCH_DIR`, `GO_BIN` | `:71-83` |
| Drop-in dir `tacquito.service.d`, keys `TACQUITO_NETWORK/ADDRESS/LEVEL/METRICS_ADDRESS` | `:1816-1817`; consumers `:9247-9542`, `:8735`, `:8789`, `:8907`, `:4846`, `:10848-10859` |
| `chown tacquito:tacquito` (40 sites) | e.g. `:2337, 2402, 2460, 6411, 7705, 10437` |
| `systemctl … tacquito` (28 sites) | `:1447` (`restart_service`), status `:8694-8737`, listen/loglevel/metrics `:9293-9532`, lifecycle `:10545-10989` |
| `journalctl -u tacquito` | `:8821, 9861-9862, 9884, 9896, 9904, 10555, 10921, 10925` |
| Port 49 literals | `:2946, 3057-3063, 4847, 7518, 8719-8723, 9310-9358, 10240, 10561-10599, 10854, 10931-10933` |
| Hard-coded `/etc/tacquito`, `/var/log/tacquito`, `/opt/tacquito-src` bypassing `TACCTL_*` | uninstall `:10965-11053`; `:10341, 10633`; completion `config/tacctl.bash-completion:54-86` |
| Backup naming `tacquito.yaml.<ts>` | `:1502-1513, 8779, 9958-10016, 11270-11271` |
| Prometheus metric names | `:8803-8806` |
| Shipped `config/tacquito.yaml`, `config/tacquito.service`, `config/tacquito.logrotate` | copied at `:10359, 10419, 10543, 10835-10875` |
| Patch overlay | `:1330-1378`, `patches/*` |

**B. Structural — the data model *is* the daemon file format**

| What | Where |
|---|---|
| User CRUD on `bcrypt_<u>` anchors / `users:` entries / `*file_accounter` | `cmd_add :2169-2345`, `replace_user_hash :1854-1874`, `user_exists :1877`, `get_user_hash :1883`, `get_user_group :1890`, `cmd_remove…cmd_move :2348-2912`, seed `:10487-10534` |
| Group = `exec_<g>` (`priv-lvl`) + `junos_exec_<g>` (`local-user-name`) anchors | `:7534-7909`, `get_group_privlvl :1253-1273`, `list_all_groups :1240`, `get_config_value :2915-2948` |
| Scope = flattened `secrets[]` prefix-provider entries, globally sorted by specificity | `:3085-3726` |
| Filters = top-level `prefix_allow`/`prefix_deny` | `:5635-5864` |
| Command authz rendered into group `commands:` blocks | `:1165-1237`; migrations `:999-1163` |
| Validation = structural checks on tacquito YAML | `cmd_config_validate :9026-9244` |
| Tier gate reads priv-lvl from tacquito.yaml | `caller_tier :2015-2038` |
| Completion enumerates from tacquito.yaml | `:11243-11274` |
| Tests encode the tacquito shape | `tests/fixtures/tacquito.*.yaml`, `tests/helpers/tmpenv.bash:8`, e2e stubs `tests/e2e/smoke.bats:74`, `tests/e2e/log.bats:30-39` |

**C. Legitimately protocol/vendor-specific (stays, behind the right boundary)**: device templates and renderers (`config/templates/*`, `cmd_config_cisco :3795-4086`, `cmd_config_juniper :4089-4417`, `cmd_config_wti :4450-4708`); `aaa.order.<scope>` values `tacacs-first|local-first`, `tacacs_group.<scope>` (`:299-322`); `commands.<group>` (TACACS+ has per-command authz, RADIUS does not); the pam_tacplus client (`client-install.sh:220-412, 499-608`), `PAM_TACPLUS_*` (`:4715-4718`), SELinux module `tacctl_pam`/`tacctl_tacacs_port_t` (`client-install.sh:590-598`); WTI secret constraints (`:4540-4560`).

**D. Cosmetic**: headings `"Tacquito Users"` `:2088`, `"Tacquito Configuration"` `:2953`, `"Tacquito Groups"` `:7536`, `"Tacquito Service Status"` `:8689`, `"Tacquito Control"` `:11101`, banners `:10233, 10645, 10958`, header `:3`; 88 "TACACS+" help strings (keep where the feature is TACACS+-only); tier groups `tac-users/tac-readonly/tac-operator/tac-superuser` (`:1997-2000`, `client-install.sh:26,417`) are protocol-neutral tiers with a "tac" name — **keep** (renaming groups on enrolled hosts is a migration with no benefit); README/man/completion wording.

---

## 2. Decisions (user's answers, folded in)

| # | Decision |
|---|---|
| 1 | **Name:** keep `tacctl` as binary, repo (`MANAGE_REPO` `:82`), `/opt/tacctl`. |
| 2 | **Layout:** new `/etc/tacctl/` for tacctl-owned state; `tacctl upgrade` moves files and leaves symlinks in `/etc/tacquito/` for one release cycle. `/etc/tacquito/` remains the TACACS+ backend's own directory (like `/etc/freeradius/`). |
| 3 | **RADIUS implementation:** FreeRADIUS distro package. |
| 4 | **Scopes:** shared across protocols — one client CIDR set and one secret per scope, optional per-scope `protocols` filter. |
| 5 | **RADIUS auth:** PAP only, reusing the bcrypt store. No CHAP/MS-CHAP/EAP. |
| 6 | **Device-config CLI:** `tacctl config <vendor> --protocol radius` (default `tacacs`). |
| 7 | **Canonical store flip: now.** Users/groups/scopes/filters move to a tacctl-owned store; `tacquito.yaml` becomes a fully generated artifact in this effort. |
| 8 | **TACACSS:** design-reserved only — listener model carries TLS fields and the TACACS+ backend can run N instances; no TLS listener or cert management is built. |
| 9 | **Host enroll for RADIUS: include.** pam_radius_auth client path alongside pam_tacplus in enroll/sync/unenroll. |
| 10 | Plugin discovery: in-tree backend modules only. |
| 11 | `tacctl install` installs TACACS+ only; RADIUS is opt-in via `tacctl backend enable radius`. |
| 12 | Per-backend health sections with differing counters. |

---

## 3. Target architecture

### 3.1 Layout

```
/opt/tacctl/
  bin/tacctl.sh              thin entrypoint: sources lib/*.sh in order, dispatches unless sourced
  lib/core.sh conf.sh model.sh store.sh policy.sh users.sh groups.sh scopes.sh
      render_devices.sh linux_hosts.sh backend.sh service.sh lifecycle.sh dispatch.sh
  lib/backends/tacacs.sh     TACACS+ (tacquito) backend module
  lib/backends/radius.sh     RADIUS (FreeRADIUS) backend module
  config/backends/tacacs/    tacquito.yaml.header, tacquito@.service, tacquito.logrotate
  config/backends/radius/    sites-tacctl.conf.tmpl, dictionary.tacctl, tacctl.logrotate
  config/templates/          cisco*.template juniper.template wti.template + *-radius.template
  config/linux/              client-install.sh client-remove.sh (multi-method)

/etc/tacctl/                 TACCTL_STATE_DIR (root:root 0700)
  store.yaml                 canonical users/groups/scopes/filters (0600)
  tacctl.yaml                tunables (moved from /etc/tacquito)
  linux-hosts  linux-uids    (moved)
  rendered.json              {path: sha256} of every rendered artifact (drift detection)
  backups/<ts>/{store.yaml,tacctl.yaml,manifest}   store snapshots (retention 30)
  backups/legacy/            pre-flip tacquito.yaml.<ts> files (moved from /etc/tacquito/backups)
  templates/                 (moved) operator template overrides
/etc/tacquito/tacquito.yaml  GENERATED (0640 tacquito:tacquito); symlinks tacctl.yaml, linux-*, backups → /etc/tacctl for one release
/etc/freeradius/3.0/… (Debian) or /etc/raddb/… (RHEL)   RADIUS backend artifacts (rendered)
```

### 3.2 Backend contract (in-tree modules)

**As implemented by WP2.1; the header of `lib/backend.sh` is authoritative** (it also explains each departure from the list this section first proposed). Each `lib/backends/<id>.sh` appends to `BACKEND_IDS` and defines `backend_<id>_<verb>` for every entry of `BACKEND_VERBS`:

```
describe            → key=value lines: protocol, impl, units, user, config_dir, log_dir
installed           → 0/1
install <phase> <tree>      phases: build files account start
upgrade <phase> <tree>      phases: preflight config build files finish
uninstall <phase> [--keep-logs]   phases: stop program data account
artifacts           → the files the backend renders, one path per line
render_check        → trial render + the daemon's own config check; prints current|same|ok|drift|unrecorded|missing|unreadable
render_gate         → may a mutation replace the artifacts? 0 yes / 10 yes, adopt (force) / 3 refused / 1 failed
render_stage <dir> [--force]  → render the current store into <dir> and prove it; touches nothing else
render_commit <dir>           → install what was staged, record shas; prints CHANGED|UNCHANGED
render_notes        → warnings after 'config render'
service <start|stop|restart|reload|is-active|since|pid> [listener]
listeners list|show [name]|set <name> <network> <address>|reset [name]   (list → '<name> <network> <address>' per listener; see 3.4)
status <service|config|accounting|activity>   → the backend's lines of 'tacctl status'
log <tail|search|failures|clear> …
accounting tail [n]
last_login <user>   → timestamp or "never"
secret_constraints  → max_len= charset=
device_vars <vendor> <scope> → KEY=VALUE lines merged into template env
```

`lib/backend.sh`: `backends_enabled` (from `tacctl.yaml` `backends.enabled`, default `[tacacs]`), `backend_call <id> <verb> …`, `backends_run <verb> …` (every enabled backend), `backends_gate`, `backends_render_all [--force] [--force=<id>]` (stage every backend, then commit; all artifacts are replaced or none), `backends_restart_changed`, `backends_restart_all`, `backends_check_drift`, and `store_apply`, the one mutation path: gate → snapshot → write → `backends_render_all` → `backends_restart_changed`, with store.yaml and tacctl.yaml put back when the render fails. Legacy mode (no store) is TACACS+-only and its code (the import gate, `store rollback`, in-place migrations) lives in `lib/backends/tacacs.sh`, outside the contract.

### 3.3 Model and store

`lib/model.sh` is the **only read interface** for users/groups/scopes/filters: `model_dump` (one JSON doc, cached per invocation like `_TACCTL_CFG_CACHE`), plus `model_user <u>`, `model_users`, `model_groups`, `model_scopes`, `model_scope <s>`, `model_filters`. It has two loaders:
- **store loader** — reads `/etc/tacctl/store.yaml` (normal mode);
- **legacy loader** — parses a tacquito.yaml with `yaml.safe_load` (today's reader logic consolidated). It is (a) the one-time importer, (b) the read-only fallback when the store does not exist yet, and (c) `tacctl config import tacacs` for adopting hand edits.

So the interim read-model is **not a throwaway**: it is written once, against the store schema, and the legacy loader is the importer. This is also the safest route to the flip, because a failed import leaves the server untouched in read-only legacy mode (see 4.4).

`lib/store.sh` owns writes: `store_mutate <python-snippet>` pattern (load → mutate → validate → atomic write 0600), with typed helpers `store_user_set/del`, `store_group_set/del`, `store_scope_set/del`, `store_filters_set`. Every write snapshots first (`backup_snapshot`, 4.6).

### 3.4 Listener model (TACACSS-ready, not built)

`tacctl.yaml` wildcard schema `listeners.<backend>.<name>` → dict `{network: tcp|tcp6|udp|udp6, address: host:port, role: auth|acct|both, tls: {enabled: bool, cert, key, ca, require_client_cert}}`. Defaults: `listeners.tacacs.default = {network: tcp, address: ":49", tls: {enabled: false}}`; `listeners.radius.auth = {udp, ":1812", role: auth}`, `listeners.radius.acct = {udp, ":1813", role: acct}`.
- TACACS+: one systemd unit per listener, each with a rendered drop-in `<unit>.d/tacctl.conf` (`Environment=` lines, now an artifact recorded in `rendered.json`, not the source of truth). Per-listener `-acct-log-path /var/log/tacquito/accounting[-<name>].log` and `-metrics-address` (the default listener keeps today's paths; another listener exports metrics only when it sets `metrics_address`). `tls.enabled: true` is **rejected by the schema with "reserved"** until Phase 6 implements it.
  **As built (WP2.2), departing from the proposal of `tacquito@default` plus a `tacquito.service` alias:** the default listener stays in `tacquito.service` itself and only the other listeners are instances `tacquito@<name>.service` of the template `tacquito@.service`. systemd cannot alias a plain name to a template instance — `Alias=tacquito.service` in the template is refused at `enable` ("cannot alias"), a symlink is rejected at load ("symlink target name type does not match source") — and a wrapper unit of that name would make `systemctl is-active tacquito` answer for the wrapper and `journalctl -u tacquito` show nothing of the daemon (the journal matches the unit a process runs in). The instances are `PartOf=` and `WantedBy=tacquito.service`, so `systemctl stop|start|restart|enable|disable tacquito` covers every listener. The header of the "Units, listeners and their systemd drop-ins" section in `lib/backends/tacacs.sh` is authoritative.
  Listener, log-level and metrics changes are written to `tacctl.yaml` outside `store_apply` (they need no store and prove themselves by restarting the unit, rolling back when it does not come up); the drop-ins are also staged and committed with `tacquito.yaml`, so a restored `tacctl.yaml` is applied by the render that follows.
- RADIUS: listeners render into `listen {}` blocks of the tacctl virtual server; `tls.enabled` reserved likewise.

---

## 4. The canonical store flip (Decision 7)

### 4.1 Store format: one file, `/etc/tacctl/store.yaml`

One file (atomic rename, one snapshot unit, <100 KB at any realistic size), YAML, `yaml.safe_dump(sort_keys=False)`, 0600 root. Maps keyed by name (stable diffs; order never matters in the store — renderers compute order).

```yaml
version: 1
groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: 7,  juniper_class: OP-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
  helpdesk:  {priv_lvl: 5,  juniper_class: HELPDESK-CLASS}
users:
  alice:
    group: superuser
    scopes: [lab, prod]
    hash: "243262243132..."        # hex bcrypt, today's canonical form (normalize_bcrypt_hash :1537); null = never set
    disabled: false
    password_changed: "2026-10-01" # from backups/password-dates/<u>.date; absent = unknown
  root:
    group: readonly
    scopes: [lab]
    hash: null
    disabled: true
    accounting_sink: true          # rendered with DISABLED_MARKER_HEX; `user passwd root` refused (today's rule)
scopes:
  lab:
    prefixes: ["10.0.0.0/8", "172.16.0.0/12"]   # canonical CIDRs (canonicalize_cidr :3733), stored sorted
    secret: "..."
    protocols: [tacacs, radius]                 # optional; absent = every enabled backend
filters:
  allow: []
  deny: []
```

Representation rules:
- **Disabled users** keep their real `hash` and set `disabled: true`. Importer reads `backups/disabled/<u>.hash` when the live hash is the marker (`DISABLED_MARKER_HEX` `:811` or literal `DISABLED` as tolerated by `cmd_list :2136`); if no sidecar exists, `hash: null`. The TACACS+ renderer emits the marker for `disabled: true` or `hash: null`; the RADIUS renderer omits the user.
- **Password dates** move into the store (`record_password_date :1451` becomes a store write); importer reads existing `.date` files; `status` password-age scan reads the store.
- **`scope.default`, `commands.<group>`, `privileges.<group>`, and all scope render knobs stay in `tacctl.yaml`** (already canonical and schema-validated; no churn). Renderers read both.
- **Validation** (`store_validate`, Python): names match today's regexes (`validate_username :1610`, group `^[a-z][a-z0-9_-]*$` `:7610`, scope `^[a-zA-Z][a-zA-Z0-9_-]{0,31}$` `:6345`); every `user.group` exists; every `user.scopes[]` exists; prefixes canonical and **owned by exactly one scope** (invariant from `scope_owning_prefix :3252`); `priv_lvl` 0-15; `juniper_class` per `validate_class_name :1598`; builtins present and `builtin: true` not removable; `protocols[]` ⊆ known backend protocols; reserved names (`tacquito`, `root` only as sink) per `reject_reserved_username :1623`.

### 4.2 One-time import (legacy tacquito.yaml → store)

`tacctl store import [--check|--force] [<file>]` (default `$CONFIG`). Implemented with `yaml.safe_load`, **never regex**, so anchor layout, header-comment variants (`# --- Secret Providers` with/without `(Scopes)`, `:2312-2314`), and spacing are irrelevant:
- groups: from each user's inlined `groups[0]`, plus any top-level group anchors not referenced by users (parsed by walking top-level maps that have `name` + `services`); `priv_lvl` from the service with `name in (shell, exec)` and `set_values[priv-lvl]` (legacy `exec` tolerated as `conf_migrate_exec_service_name :1123` does); `juniper_class` from service `junos-exec`/`local-user-name`.
- users: `name`, `scopes` (absent → `[]`, reported), group, hash from `authenticator.options.hash`, `disabled` when hash is the marker/`DISABLED`, `accounting_sink` for `root`, `password_changed` from `.date` files.
- scopes: group `secrets[]` entries by `name`; union of prefixes (parsing the `prefixes: |` JSON block exactly as `read_scope_prefixes :3144` does); `secret.key`; refuse if entries with the same name carry different keys (today's validate rule `:9176-9186`).
- filters: `prefix_allow`/`prefix_deny`.
- **Unrepresentable content** → listed and the import **fails** unless `--force` (which drops it and prints what was dropped): services other than shell/exec/junos-exec on a group, extra `set_values`, user-level `services`/`commands` overrides, non-bcrypt authenticators, accounters other than the file accounter, non-prefix secret providers, users with `groups` ≠ 1, unknown top-level keys. Nothing is written in that case; the install stays in legacy read-only mode (4.4).

### 4.3 Equivalence proof on a real install

`tacctl store import --check` performs, without writing anything persistent:
1. legacy load → model → `store_validate`;
2. render tacquito.yaml from that model into a temp file (the Phase-1 renderer);
3. `yaml.safe_load` both the live file and the rendered file and **normalize**: users → dict by name with `scopes` sorted, groups inlined (as safe_load already does), authenticator/accounter dicts as-is, group `commands` lists as-is; `secrets` → ordered list of `(name, key, parsed prefixes)` (order matters: first match); `prefix_allow/deny` → sets. Print `EQUIVALENT` or a unified diff of the two normalized JSON dumps;
4. if `/usr/local/bin/tacquito` exists: `timeout 5 tacquito -config <tmp> -network tcp -address 127.0.0.1:0 -acct-log-path <tmp> -metrics-address 127.0.0.1:0 -level 20`, pass when stderr shows `serve on` before timeout (loader rejects unparseable configs with `error fetching config` [V `main.go:76-96`]).

Procedure on the dev server (the test client only): `tacctl upgrade --branch develop` runs `--check` as a migration gate; only on `EQUIVALENT` + load-smoke pass does it write the store, move state, render, record `rendered.json`, and restart. The pre-flip `tacquito.yaml` is copied to `/etc/tacctl/backups/legacy/tacquito.yaml.pre-store.<ts>`. Then verify live: `tacctl status`, `tacctl config validate`, `tacctl user verify <existing>`, a TACACS+ login from `client` (already enrolled), `tacctl backup diff` shows no semantic change. The same gate runs on production later **only when the user performs the release**; the plan does not schedule that.

### 4.4 Failure and rollback

- **Import fails during upgrade:** upgrade finishes installing code, prints the import report, and leaves the system in **legacy read-only mode**: the model loads from tacquito.yaml, every read verb works, every mutating verb exits with `store not initialised — review 'tacctl store import --check' and run 'tacctl store import [--force]'`. The daemon is never restarted by a failed import.
- **Flip misbehaves on the test client:** `tacctl store rollback` restores `backups/legacy/tacquito.yaml.pre-store.<ts>` to `$CONFIG`, deletes `store.yaml` and `rendered.json`, restarts the TACACS+ backend → legacy read-only mode under the new code. Full rollback is the previous release: `tacctl upgrade --branch master` (or `git -C /opt/tacctl checkout 0.1.14`); the old code reads `tacctl.yaml`/`linux-*`/`backups` through the symlinks left in `/etc/tacquito/`. Because old `conf_set` replaces files by rename (`:511-676`), a symlink at the old path becomes a regular file after the first write; the state-dir migration is therefore **idempotent**: on every upgrade, if the old path is a regular file newer than the new one, it is moved over the new location (new one backed up) and the symlink recreated.

### 4.5 Hand-edits to tacquito.yaml after the flip

- Rendered header: `# GENERATED by tacctl from /etc/tacctl/store.yaml and tacctl.yaml. Edits here are overwritten. Use tacctl commands, or 'tacctl config import tacacs' to adopt manual edits.`
- `rendered.json` records sha256 per artifact. `backends_check_drift` runs at the start of every tacctl invocation (cheap): on mismatch, `status`/`validate` show a red `DRIFT` line, and any render **refuses to overwrite** without `--force`, pointing at `tacctl config import tacacs` (legacy loader re-import, same representability rules) or `tacctl config render --force` (the drifted file is snapshotted into `backups/legacy/` first). tacquito's fsnotify hot-reload still applies to hand edits, so a hand edit "works" until the next tacctl mutation, which is exactly when the operator is told.

### 4.6 Backup, restore, diff once the store is canonical

- `backup_snapshot` (replaces `backup_config :1491`) → `/etc/tacctl/backups/<ts>/{store.yaml,tacctl.yaml,manifest}`; manifest = `rendered.json` at that time + tacctl version. Retention 30 directories. Called before every mutation.
- `backup list` lists snapshots then legacy files; `backup diff [ts]` = `diff -u` of `store.yaml` and `tacctl.yaml` against the snapshot (shows secrets/hashes → stays superuser-only as today, `tier_permits :2044`); `backup restore <ts>` copies both files back, `backends_render_all --force`, `backends_restart_changed`. `backup restore <legacy-ts> --legacy` = `store import --check` then import of that file. `config diff/restore` aliases unchanged (`:7463-7468`).

---

## 5. RADIUS backend (FreeRADIUS, Decisions 3, 4, 5, 6, 11, 12)

- **Install (`backend_radius_install`):** Debian/Ubuntu `apt-get install freeradius freeradius-utils`; RHEL `dnf install freeradius freeradius-utils` [A]. Paths/units/users per distro: Debian `/etc/freeradius/3.0`, unit `freeradius`, user `freerad`; RHEL `/etc/raddb`, unit `radiusd`, user `radius` [A — from search results, confirm on target]. Disable the distro `default` and `inner-tunnel` sites (remove symlinks in `sites-enabled`), keep everything else distro-owned. `python3-yaml` added to `DEPS_CORE` while here.
- **Artifacts rendered from the model:**
  - `sites-available/tacctl` (+ `sites-enabled` symlink): `listen {}` per listener (`type = auth|acct`, `ipaddr`/`ipv6addr`, `port`, `proto = udp`); `clients tacctl { client <scope>-<n> { ipaddr = <cidr>; secret = "…"; tacctl_scope = "<scope>" } }` for every prefix of every scope whose `protocols` includes `radius` (FreeRADIUS accepts CIDR `ipaddr` and exposes arbitrary client fields as `%{client:tacctl_scope}` [A]); `authorize { files_tacctl; pap }`, `authenticate { pap }`, `accounting { detail_tacctl }`, with an `authorize` unlang guard that rejects when the user's scope list does not contain `%{client:tacctl_scope}` [A — implementer chooses between this and one `files` entry per (user, scope) after reading 3.2 `rlm_files`/unlang docs].
  - `mods-config/files/tacctl-users`: one entry per enabled user: `Crypt-Password := "$2b$…"` (hex → raw conversion), reply items from the group: `Service-Type`, `Cisco-AVPair = "shell:priv-lvl=<N>"`, `Juniper-Local-User-Name = "<class>"` [A: dictionary attribute names], optionally `Juniper-Allow-Commands/Deny-Commands` from `commands.<group>`. Disabled/sink users omitted.
  - `mods-available/tacctl` instances (`files files_tacctl { … }`, `detail detail_tacctl { filename = /var/log/freeradius/tacctl-accounting.log }`), `dictionary.tacctl` if a custom attribute is needed, `/etc/logrotate.d/tacctl-radius`.
- **bcrypt reuse:** `rlm_pap` passes `Crypt-Password` to the system `crypt()`, so `$2b$` works wherever libxcrypt does — **[V] upstream master source (`pap_auth_crypt`), [A] confirm identical in the 3.2.x branch**; libxcrypt bcrypt verified present on Ubuntu 24.04 (the dev server). PAP only (Decision 5): CHAP/MS-CHAP/EAP are not configured and documented as unsupported.
- **Validate:** `freeradius -CX -d <confdir>` (Debian) / `radiusd -CX` (RHEL) [A]. **Service:** `systemctl` on the distro unit. **Health:** `ss -ulnp` on configured listeners; counters: none by default (Decision 12) — optional `Status-Server` later. **Logs:** `journalctl -u <unit>`; **accounting:** `tail` of the detail file; `last_login` parses `Acct-Status-Type = Start` records for the user [I].
- **Device configs:** `config cisco|juniper|wti --protocol radius` → `cisco-radius.template`, `juniper-radius.template` (WTI RADIUS only if the unit supports it [A]); variables from `backend_radius_device_vars` (auth/acct ports, server IP, secret). `aaa.order.<scope>` semantics reused (`radius-first` wording handled in the renderer, schema values unchanged).
- **Scope `protocols` filter (Decision 4):** `tacctl scope protocols <name> [list|set <csv>|clear]`; `scope show` prints it; renderers skip scopes not listing them. Default absent = all enabled backends. `host enroll` sets it for auto-created per-host scopes (6.2).
- **Secret constraints:** `backend_radius_secret_constraints` → charset `[A-Za-z0-9_.+/=-]` (also what `pam_radius_auth.conf` tolerates, same regex as `:4835`), `max_len=64` unless a vendor limit is known [A]; `scope secret` warns when any enabled backend's constraint is violated.

---

## 6. Host enroll with two client methods (Decision 9)

Design decisions from project memory that the RADIUS path keeps: PAM-only (no NSS); real local accounts with locked passwords, UID = primary GID from `linux-uids`; tiers via `tac-users` + `tac-readonly|operator|superuser`; `%tac-superuser` sudo re-authenticating with the network password; manual `host sync`; PAM services `sshd sudo sudo-i login sddm gdm-password`, never `common-*`/`system-auth`/`password-auth`; reject is final, unreachable server falls through to local; secret kept in root-only files; KDE Plasma lock caveat (same: the pam_radius conf is root-only); `passwd` disabled, `tacctl passwd` on the server (pam_radius does not implement password change [V USAGE]); per-host scope `linux-<name>` with the host's /32 and its own secret.

### 6.1 Client-side abstraction (`config/linux/client-install.sh`, `client-remove.sh`)

Header gains `TAC_METHOD=tacplus|radius`, `TAC_ACCT_PORT` (radius). Shared (unchanged): arg parsing, family detection, local-admin lockout check, `check_ids`, `sync_accounts`, the PAM service-file splice loop (`:551-580`), sudoers drop-in, KDE no-lock, SDDM/GDM/sshd post-checks, state files. Per-method functions selected by `$TAC_METHOD`:

| Concern | `tacplus` (today) | `radius` (new) |
|---|---|---|
| Module install | `install_module` `:357-396` (prebuilt or compile) | `install_module_radius`: `pkg_ensure libpam-radius-auth` (Debian family) / `pkg_ensure pam_radius` (RHEL family, needs EPEL [A: EPEL9 ships 2.0.0]); verify `pam_radius_auth.so` exists in `pam_module_dir`; no compile fallback — `die` with "nothing changed" if the package cannot be installed |
| Secret file | PAM-line argument | `$STATE_DIR/pam_radius.conf` 0600 root: `<server>[:<port>] <secret> 3` (+ IPv6 form per upstream syntax [A]); referenced by `conf=` |
| `tacctl-auth` | `pam_tacplus.so <args>` with `[success=done authinfo_unavail=ignore default=die]` | `pam_radius_auth.so conf=$STATE_DIR/pam_radius.conf retry=2 client_id=tacctl` with the **same control** — no server response returns `PAM_AUTHINFO_UNAVAIL` [V implied by the `localifdown` option doc] |
| `tacctl-account` | gate + `pam_tacplus.so` account | gate + `@include common-account` / RHEL stack only (authorization already arrived in Access-Accept; removed/disabled users are handled by `host sync` as today) |
| `tacctl-session` | `session optional pam_tacplus.so` | `session optional pam_radius_auth.so conf=…` (Linux-only accounting [V README]) — only when an acct listener is enabled |
| SELinux | CIL module labelling the TCP port `:590-598` | Port 1812/1813 is already `radius_port_t`; try `setsebool -P authlogin_radius on` if the boolean exists, else a CIL variant allowing `sshd_t`/`local_login_t`/`sudodomain` → `radius_port_t` udp [A] |
| Reachability check | `/dev/tcp` probe `:671` | none for UDP (print the server:port and skip) |
| State | `$STATE_DIR/{module,files}` | `$STATE_DIR/method`, `$STATE_DIR/pam_radius.conf` |

Switching methods: the install script always runs `remove_method_artifacts <other>` first (idempotent: deletes the other method's module files from `files`, its conf, its SELinux module), writes `$STATE_DIR/method`, then installs. `client-remove.sh` removes both methods' artifacts unconditionally (packages are left installed).

### 6.2 Server side

- Registry gains a 7th field: `name|target|port|scope|server|identity|method`; readers default `method=tacplus` for 6-field lines (`host_record :5211`, `cmd_host_sync :5471`, `cmd_host_unenroll :5506`, `cmd_host_list :5538`).
- `host enroll … --method tacplus|radius` (default `conf_get host.default_method tacplus`, new schema key). Preconditions: the protocol's backend is enabled; `--scope <existing>` must allow the protocol; an auto-created `linux-<name>` scope gets `protocols: [<protocol>]`. Re-enrolling a registered host with a different `--method` is the switch path (6.1) and updates the registry.
- `--build-on-host`, the podman platform probe and `linux_prebuilt_for` are **tacplus-only**; for radius they are skipped (and `--build-on-host` warns "not applicable"). `config linux build|builds` stay tacplus-only; `config linux script --method radius` emits the package-based script.
- `linux_write_install_script` takes the method, reads the port from `listeners.<backend>` (today `:4845-4848` reads the drop-in), and omits the tarball/prebuilt sections for radius.
- `host sync` passes the registered method; `--accounts-only` behaviour unchanged.

---

## 7. Migration and compatibility

| Item | Today | Target | Compatibility |
|---|---|---|---|
| Canonical data | `/etc/tacquito/tacquito.yaml` | `/etc/tacctl/store.yaml` (+ `tacctl.yaml`); tacquito.yaml rendered | gated import (4.3), legacy read-only mode (4.4), drift detection (4.5), rollback (4.4) |
| tacctl state files | `/etc/tacquito/{tacctl.yaml,linux-hosts,linux-uids,backups/,templates/}` | `/etc/tacctl/…` | symlinks at old paths for one release; idempotent re-move (4.4); `TACCTL_STATE_DIR` env (tests), `TACCTL_ETC` keeps meaning the TACACS+ dir |
| systemd | `tacquito.service` + `tacquito.service.d/tacctl-overrides.conf` | `tacquito.service` (default listener) + `tacquito@.service` template for further listeners (see 3.4 for why not `tacquito@default` with an alias); drop-ins `<unit>.d/tacctl.conf` rendered from `listeners.tacacs.<name>` and `backends.tacacs.*` | upgrade imports the existing drop-in values once into `tacctl.yaml` and retires the file (a copy goes to `backups/legacy/`); `systemctl status tacquito`, `journalctl -u tacquito` are unchanged because the unit is unchanged |
| Accounting log / logrotate | one file | default instance unchanged; extra instances `accounting-<name>.log`; RADIUS detail file | logrotate rendered per backend |
| CLI | unchanged verbs | plus `backend …`, `store import|rollback|show`, `scope protocols …`, `config render|import`, `config <vendor> --protocol`, `config listen` gains `--backend/--listener` (no flag = TACACS+ default listener), `host enroll --method` | no verb removed; `tier_permits`/`emit_tier_sudoers` extended for the new read-only verbs |
| Backups | `tacquito.yaml.<ts>` | snapshot dirs; legacy files listed and importable | (4.6) |
| Completion | hard-coded paths | via `_completion-names` only | |
| Tests | fixtures `tacquito.*.yaml` | `load_fixture` runs `store import` so the importer is exercised by every integration test; new `store.*.yaml` and `radius` fixtures | existing assertions kept; e2e stubs keep matching `tacquito` (the default listener's unit kept its name, 3.4) |
| Suggested releases (user-driven) | | 0.2.0 = Phases 0-1 (split, state dir, store flip); 0.3.0 = Phases 2-3 (backends, RADIUS); 0.4.0 = Phases 4-5 (host RADIUS, docs) | each soaked on the dev server before the user cuts a release |

---

## 8. Phased plan (ordered)

Phase order rationale: the split is a hard prerequisite; the store flip is the riskiest change and the thing everything else consumes, so it goes first to maximize soak time on the dev server; the backend abstraction then wraps an already store-driven TACACS+ renderer; RADIUS consumes the model; host RADIUS needs the RADIUS backend; docs last. TACACSS is only reserved (Phase 2 listener model).

| Phase | Content | Work packages | Parallelism |
|---|---|---|---|
| 0 | Split the monolith (no behaviour change) | WP0.1 → WP0.2 | strictly sequential; blocks everything |
| 1 | State dir, store, importer, TACACS+ renderer, writer rewire, snapshots, flip migration | WP1.1 ∥ WP1.2 → WP1.3 → {WP1.4a, 1.4b, 1.4c ∥ WP1.5} → WP1.6 → WP1.7 | 1.4a/b/c in separate worktrees (separate lib files) |
| 2 | Backend contract, TACACS+ module, template unit + listeners, backend CLI, status/log/backup loops | WP2.1 → {WP2.2, WP2.3, WP2.4} | 2.3 and 2.4 parallel; 2.2 touches service.sh too — same worktree as 2.4 |
| 3 | FreeRADIUS backend | WP3.1 → {WP3.2, WP3.3, WP3.4} → WP3.5 | 3.2/3.3/3.4 parallel (different files) |
| 4 | Host enroll multi-method | WP4.1 → {WP4.2, WP4.3} → WP4.4 | 4.2/4.3 parallel |
| 5 | Docs, completion, man, cosmetic rename | WP5.1 ∥ WP5.2 (after 4) | conflict with any open WP touching usage strings |
| 6 (reserved) | TACACSS listener + cert management | not scheduled | needs Phase 2 |

---

## 9. Remaining items to check against upstream before implementation

1. FreeRADIUS **3.2.x** `rlm_pap`: `Crypt-Password` → `crypt_r()` with the stored hash as salt (verified only in master source). Check `src/modules/rlm_pap/rlm_pap.c` on the `v3.2.x` branch.
2. FreeRADIUS 3.2: `client { … }` custom fields readable as `%{client:name}`; CIDR `ipaddr`; `rlm_files` check-item/`Fall-Through` semantics for per-(user,scope) entries; `detail` module single-file config; `-CX` config check flag; dictionary names `Cisco-AVPair`, `Juniper-Local-User-Name`, `Juniper-Allow-Commands`.
3. Distro facts: Debian/Ubuntu `/etc/freeradius/3.0`, unit `freeradius`, user `freerad`; RHEL `/etc/raddb`, unit `radiusd`, user `radius`; package names (`freeradius`, `freeradius-utils`).
4. pam_radius_auth: conf line syntax (`server[:port] secret [timeout]`, IPv6 form), confirm `PAM_AUTHINFO_UNAVAIL` on no response, `account` behaviour, EPEL `pam_radius` 2.0.0 vs Debian 2.0.1 differences, default conf path (`/etc/pam_radius_auth.conf` vs `/etc/pam_radius.conf`), whether `conf=` accepts an absolute path on both.
5. SELinux on EL8/9/10: existence/semantics of `authlogin_radius` boolean; whether `sshd_t`, `local_login_t`, sudo domains may send UDP to `radius_port_t` without it.
6. tacquito: user order independence in `ServerConfig.Users` (read `loader.go` with sudo on the dev server); fsnotify reload after atomic rename (tacctl already restarts explicitly, so this is informational).
7. NAS RADIUS shared-secret length limits for the user's device vendors (Cisco IOS/IOS-XE, Junos, WTI).
8. WTI: RADIUS support on the v8.x firmware (decides whether `config wti --protocol radius` is offered).
9. TACACSS: which device OS versions implement draft-ietf-opsawg-tacacs-tls13 (informational; reserved).
10. Prometheus: FreeRADIUS has no exporter — accepted per Decision 12; optional `Status-Server` later.

---

## 10. Implementation work packages

Common rules for every package (restate in each hand-off): read `/home/user/tacctl/README.md`, `/home/user/tacctl/tests/README.md` and this plan's §3-4 first; never run anything against the production host; live checks only on the dev server (this machine) or `client`; create throwaway users only on the dev server and the test client and remove them; **do not `git commit` or `git push`** — stop at the working tree and report a file-by-file summary; `make lint && make test` must pass unless the package says otherwise; use absolute paths.

---

### WP0.1 — Split map for the monolith
- **Goal:** a precise, reviewable mapping of `bin/tacctl.sh` into `lib/*.sh` with zero behaviour change.
- **Read first:** `/home/user/tacctl/bin/tacctl.sh` function index (`grep -nE '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' bin/tacctl.sh`); top-level statements at `:25-83, 109-193, 195-269, 279-503, 811, 1311-1317, 1431-1433, 1489, 1816-1817, 1997-2000, 4711-4719, 5209, 9548-9550, 10164-10165, 11186-11283`; `tests/helpers/tmpenv.bash`, `Makefile`.
- **Scope:** produce `docs/split-map.md` (new file) listing for each target file (`lib/core.sh conf.sh policy.sh users.sh groups.sh scopes.sh render_devices.sh linux_hosts.sh service.sh lifecycle.sh dispatch.sh`) the exact source line ranges, the sourcing order, every top-level variable whose evaluation depends on an earlier one (e.g. `LINUX_SRC_DIR` needs `SCRIPT_DIR`), and how `bin/tacctl.sh` becomes the entrypoint (sources `lib/*.sh` via `SCRIPT_DIR`, keeps the sudo re-exec and the `BASH_SOURCE == $0` dispatch gate). Decide and state: tests keep calling `tacctl_source_lib` on `bin/tacctl.sh`. Out of scope: moving code.
- **Interfaces produced:** the map document; a list of `Makefile` and `tests/README.md` edits for WP0.2.
- **Acceptance:** map covers 100% of lines (sum of ranges = file length); no function split across files; reviewer can execute WP0.2 from the map alone.
- **Executor:** Opus (ordering/`set -u` hazards are design-sensitive). **Deps:** none. **Worktree:** safe (writes one new doc).

### WP0.2 — Execute the split
- **Goal:** `bin/tacctl.sh` becomes the entrypoint; code lives in `lib/`; all 524 tests pass unchanged.
- **Read first:** `docs/split-map.md` (WP0.1), `bin/tacctl.sh`, `Makefile`, `tests/helpers/tmpenv.bash`, `tests/unit/sanity.bats`.
- **Scope:** move code exactly per map (no edits to function bodies); `bin/tacctl.sh` sources `"${SCRIPT_DIR}/../lib/"*.sh` in the listed order; `Makefile`: `lint` adds `lib/*.sh`, `coverage` include-path adds `lib`; `cmd_upgrade` self-update detection (`:10766-10786`) compares a hash of `bin/ lib/` instead of one file; `normalize_deploy_perms`/`chmod 755` cover `lib/`; `tests/unit/sanity.bats` gains "each lib file passes `bash -n`" and "no function defined twice across lib/". Update `tests/README.md` layout. Out of scope: renames, behaviour changes.
- **Acceptance:** `make lint && make test` green; `bash -n` on every file; `diff <(declare -F after) <(declare -F before)` shows identical function sets; report line counts per lib file.
- **Executor:** Sonnet (mechanical against the map). **Deps:** WP0.1. **Worktree:** must run alone — conflicts with every other package.

### WP1.1 — State directory `/etc/tacctl` with symlink migration
- **Goal:** tacctl-owned state lives in `TACCTL_STATE_DIR` (default `/etc/tacctl`), with idempotent migration from `/etc/tacquito`.
- **Read first:** `lib/core.sh` (paths, ex-`:29-83`), `lib/lifecycle.sh` (install `:10405-10467`, upgrade `:10808-10901`, uninstall `:10954-11093`), `lib/conf.sh` write path (ex-`:511-676`), `lib/linux_hosts.sh` (`LINUX_UID_FILE`, `LINUX_HOSTS_FILE`), `tests/helpers/tmpenv.bash`, `config/tacctl.bash-completion:40-90`.
- **Scope:** add `TACCTL_STATE_DIR`; point `TACCTL_OVERRIDES_FILE`, `LINUX_UID_FILE`, `LINUX_HOSTS_FILE`, `BACKUP_DIR`, `PASSWORD_DATES_DIR`, `TEMPLATE_DIR_LOCAL` at it; `state_migrate` (called by install and upgrade): create dir 0700, for each item: if old path is a regular file/dir and new is absent → move + symlink; if both exist and old is a regular file newer than new → back up new under `backups/legacy/`, move old over new, re-symlink; never follow symlinks when deciding. Uninstall removes `/etc/tacctl` (prompt to preserve backups as today) and the symlinks. Completion reads only via `_completion-names`. Tests: `tmpenv` sets `TACCTL_STATE_DIR`; new `tests/integration/state_migrate.bats` covering fresh, half-migrated, regressed-after-rollback cases. Out of scope: the store.
- **Acceptance:** `make test` green; migration test proves idempotence (running twice is a no-op) and the rollback round-trip (old code writing through a symlink, then re-migrate).
- **Executor:** Sonnet (well-specified file moves). **Deps:** WP0.2. **Worktree:** safe in parallel with WP1.2 (different files: lifecycle/core vs model/store).

### WP1.2 — Store schema, model API, legacy importer, equivalence check
- **Goal:** `lib/model.sh` + `lib/store.sh` + `tacctl store import [--check|--force] [file]` and `tacctl store show`.
- **Read first:** this plan §4.1-4.3; today's readers to consolidate: `list_scopes/read_scope_*/read_user_scopes/count_users_in_scope/list_users_in_scope/scope_owning_prefix` (ex-`:3115-3279`), `cmd_list` (ex-`:2086-2166`), `get_group_privlvl` (ex-`:1253`), `list_all_groups`, `read_prefix_list` (ex-`:5804`), `cmd_disable/enable` sidecars (ex-`:2557-2608`), `is_disabled_hash :815`, `DISABLED_MARKER_HEX :811`, `conf_migrate_exec_service_name` (ex-`:1123`), validators `validate_username :1610`, `reject_reserved_username :1623`, `validate_class_name :1598`, `canonicalize_cidr :3733`; `tests/fixtures/tacquito.*.yaml`; `/opt/tacquito-src/cmds/server/config/types.go`.
- **Scope:** implement the schema in §4.1 as a Python `STORE_SCHEMA` + `store_validate`; `model_dump` with store loader and legacy loader (safe_load only), cached per invocation; `store_mutate` atomic writer (0600, tempfile+rename, snapshot hook left as a callable for WP1.5); `store import` with the representability rules and `--check` normalization/diff (steps 1 and 3 of §4.3; step 2 and 4 are wired by WP1.3/1.6 — leave a `store_render_hook` function). Fixtures: `tests/fixtures/store.minimal.yaml`, `store.multiscope.yaml`, golden `tests/fixtures/model/*.json`. Unit tests: importer on every existing tacquito fixture, on a fixture with legacy `name: exec`, with multi-prefix entries, with `DISABLED` literal, with an unrepresentable extra service (fails; `--force` drops and reports). Out of scope: rewiring any command; rendering.
- **Interfaces produced:** `model_dump`, `model_users`, `model_user <u>`, `model_groups`, `model_group <g>`, `model_scopes`, `model_scope <s>`, `model_filters`, `model_mode` (store|legacy); `store_user_set/del`, `store_group_set/del`, `store_scope_set/del`, `store_filters_set`, `store_validate`, `store_import`.
- **Acceptance:** `make test` green; importer round-trips every fixture; `tacctl store show` prints the model as YAML.
- **Executor:** Opus (schema and importer edge cases are design-sensitive). **Deps:** WP0.2. **Worktree:** safe in parallel with WP1.1.

### WP1.3 — TACACS+ renderer from the model + drift detection
- **Goal:** `render_tacacs_config <model.json> <out>` producing a tacquito.yaml semantically identical to today's; `rendered.json` bookkeeping; `tacctl config render [--force]`.
- **Read first:** `config/tacquito.yaml` (template shape), `regenerate_tacquito_commands` (ex-`:1165-1237`), `add_scope/set_scope_prefixes/reorder_secrets_by_prefix_specificity` (ex-`:3292-3612`) for the exact `secrets[]` chunk text and ordering key `(version, broadcast, network)`, `cmd_add` user/auth block text (ex-`:2300-2322`), `cmd_group_add` service/group block text (ex-`:7641-7692`), install seeding (ex-`:10487-10534`), `write_prefix_list` (ex-`:5824`), §4.3 and §4.5 of this plan.
- **Scope:** Python renderer that emits today's anchor layout and section markers (header per §4.5), groups ordered builtins first then by name, users by name, flattened sorted secrets, group `commands:` from `conf` merged view; `disabled`/null hash → marker; `accounting_sink` → marker; write 0640 `tacquito:tacquito` atomically; record sha in `rendered.json`; `backends_check_drift` + refusal/`--force` semantics; wire `store import --check` step 2 (render to temp) and step 4 (tacquito load smoke, skipped when the binary is absent). Golden tests: render each `store.*` fixture and compare `yaml.safe_load`-normalized output with the corresponding `tacquito.*` fixture → EQUIVALENT. Out of scope: calling the renderer from mutating commands.
- **Interfaces produced:** `render_tacacs_config`, `rendered_record <path>`, `rendered_check <path>`, `backends_check_drift` (temporary home in `lib/service.sh`; WP2.1 moves it).
- **Acceptance:** `make test` green; `--check` reports EQUIVALENT for all fixtures; drift test: hand-edit the rendered file → `config render` refuses, `--force` overwrites and snapshots.
- **Executor:** Opus. **Deps:** WP1.2. **Worktree:** safe (new functions; touches `lib/service.sh` minimally).

### WP1.4a — Rewire user commands to the store
- **Goal:** `tacctl user list|show|add|remove|passwd|disable|enable|rename|move|verify|scope …` and `tacctl passwd` mutate the store and render.
- **Read first:** `lib/users.sh` (ex-`:2086-2912`, `:7244-7393` user scope), `lib/model.sh`, `lib/store.sh`, `render_tacacs_config`, `tier`/`caller_tier` (ex-`:2015-2038`), `record_password_date/get_password_date` (ex-`:1451-1467`), `linux_scope_users` (ex-`:4736`), `_completion-names users` (ex-`:11254`), tests `tests/integration/user_crud.bats`, `user_lifecycle.bats`, `tiers.bats`.
- **Scope:** replace every regex read/write with `model_*`/`store_*`; keep CLI output byte-compatible where tests assert it; `disable/enable` use the `disabled` flag (no sidecar files); password dates in the store; `caller_tier` via model; each mutation = `backup_snapshot` (WP1.5 stub ok) → store write → `render_tacacs_config` → `restart_service`. In legacy mode (`model_mode == legacy`) every mutation errors per §4.4. Delete dead regex helpers (`replace_user_hash`, `user_exists`, `get_user_hash`, `get_user_group`) once unreferenced. Out of scope: groups, scopes, filters.
- **Acceptance:** `make test` green with fixtures loaded through the importer (WP1.7 helper may land first; if not, convert the affected tests' setup to run `store import` after `load_fixture`).
- **Executor:** Sonnet. **Deps:** WP1.3. **Worktree:** safe in parallel with 1.4b/1.4c (different lib files); shared edits to `tests/helpers/fixtures.bash` must be coordinated (one package owns it: WP1.7).

### WP1.4b — Rewire group commands to the store
- **Goal:** `tacctl group list|add|edit|remove|commands|privilege …` on the store.
- **Read first:** `lib/groups.sh` (ex-`:7534-8684`), `lib/policy.sh` (`write_group_commands`, `regenerate_tacquito_commands`), `cmd_config_show` priv/class readers (ex-`:2915-3005`), tests `group_crud.bats`, `group_edit_commands.bats`, `config_setters.bats`.
- **Scope:** groups from `model_groups`; `group add/edit/remove` → `store_group_set/del`; builtins protected via `builtin: true`; `regenerate_tacquito_commands` deleted — `write_group_commands` writes `tacctl.yaml` then renders; `cmd_config_show` reads the model. Out of scope: users, scopes.
- **Acceptance:** `make test` green.
- **Executor:** Sonnet. **Deps:** WP1.3. **Worktree:** parallel with 1.4a/1.4c.

### WP1.4c — Rewire scope and filter commands to the store
- **Goal:** `tacctl scope …` (all subcommands), `user scope`, `config allow|deny`, `config validate`, `status` posture on the store; add `scope protocols`.
- **Read first:** `lib/scopes.sh` (ex-`:3085-3726`, `:6046-7240`), `cmd_config_prefix_filter` (ex-`:5635-5864`), `cmd_config_validate` (ex-`:9026-9244`), `cmd_status` posture block (ex-`:8830-8994`), `cmd_host_enroll` scope creation (ex-`:5380-5391`), tests `scope_crud.bats`, `scope_prefixes_secret.bats`, `status_and_scope_lookup.bats`, `config_mgmt_acl.bats`.
- **Scope:** scopes/filters via model/store; one-prefix-one-scope invariant enforced by `store_validate`; `scope protocols <name> [list|set <csv>|clear]` with schema check against known protocols (`tacacs`, `radius`); `scope show` prints protocols; `config validate` = `store_validate` + `tacctl.yaml` schema walk + rendered-artifact validation via `render_tacacs_config` to temp + drift check; delete the flatten/reorder/regex editors. Out of scope: users, groups.
- **Acceptance:** `make test` green; `config validate` reports drift and store errors.
- **Executor:** Sonnet. **Deps:** WP1.3. **Worktree:** parallel with 1.4a/1.4b.

### WP1.5 — Snapshots: backup list/diff/restore on the store
- **Goal:** §4.6 implemented.
- **Read first:** `backup_config` (ex-`:1491-1515`), `cmd_backup` (ex-`:9949-10059`), `cmd_status` backup count (ex-`:8779`), `_completion-names backups` (ex-`:11270`), `tier_permits` (ex-`:2044`), tests `tests/integration/backup.bats`.
- **Scope:** `backup_snapshot` → `backups/<ts>/{store.yaml,tacctl.yaml,manifest}`; retention 30 dirs; `backup list` (snapshots, then `backups/legacy/*`); `backup diff [ts]` on store+tacctl.yaml; `backup restore <ts>` → copy back, render all backends (`render_tacacs_config` now; `backends_render_all` after WP2.1), restart; `backup restore <ts> --legacy` → `store import --check` then import. Keep `config diff/restore` aliases. Tests updated/added.
- **Acceptance:** `make test` green; restore round-trip test (mutate → restore → model equals snapshot).
- **Executor:** Sonnet. **Deps:** WP1.3. **Worktree:** parallel with 1.4x (owns `lib/service.sh` backup section only).

### WP1.6 — Flip migration in install/upgrade, rollback, the dev server verification
- **Goal:** fresh installs seed the store (no tacquito.yaml template editing); upgrades run the gated import; `tacctl store rollback`.
- **Read first:** `cmd_install` (ex-`:10411-10540`), `cmd_upgrade` migrations block (ex-`:10649-10663`), §4.3-4.4, WP1.1 `state_migrate`, `config/tacquito.yaml`.
- **Scope:** install: generate secret, write `store.yaml` with builtins (`engineer/operator/viewer` disabled, `root` sink, `lab` scope with RFC1918 prefixes), render, start; the shipped `config/tacquito.yaml` shrinks to the header/constants the renderer emits (`config/backends/tacacs/tacquito.yaml.header`) — keep the old file until WP2.1 moves it. Upgrade: after `state_migrate`, if `store.yaml` absent → `store import --check`; on success import, copy pre-flip file to `backups/legacy/tacquito.yaml.pre-store.<ts>`, render, record shas, restart; on failure print report, continue in legacy mode (no restart). `store rollback` per §4.4. Remove `conf_migrate_command_rules/dead_command_matches/exec_service_name` calls from upgrade only if the importer subsumes them (dead-match healing stays in `conf`). Then **on the dev server only**: `make test`, `tacctl upgrade --branch develop` from the working tree (or run the migration function directly), verify `tacctl status`, `config validate`, `user verify gotest1`, a TACACS+ login from `client`, `backup diff`. Report the `--check` output verbatim.
- **Acceptance:** e2e test of install seeding with stubs; integration test of upgrade-gate success and failure paths; the dev server check passes (no production involvement).
- **Executor:** Opus (migration gate and rollback semantics). **Deps:** WP1.1, 1.3, 1.4a-c, 1.5. **Worktree:** no — run in the main tree after the others merge.

### WP1.7 — Test harness for the store era
- **Goal:** every integration/e2e test runs against a store seeded from the existing tacquito fixtures.
- **Read first:** `tests/helpers/*.bash`, `tests/README.md`, a sample of integration tests, `tests/e2e/smoke.bats`.
- **Scope:** `load_fixture tacquito.X.yaml` copies the file to `$TACCTL_CONFIG` and runs a strict `store import` (never `--force`), failing the test if a fixture is unrepresentable (then fix the fixture); add `load_store_fixture store.X.yaml`; `tmpenv` sets `TACCTL_STATE_DIR`; stub `chown` already present; document in `tests/README.md`. Out of scope: changing assertions beyond what the store mode requires.
- **Acceptance:** `make test` green; `tests/README.md` updated.
- **Executor:** Sonnet. **Deps:** WP1.2. **Worktree:** owns `tests/helpers/`; coordinate with 1.4x (they must not edit helpers).

### WP2.1 — Backend contract and TACACS+ module
- **Goal:** `lib/backend.sh` + `lib/backends/tacacs.sh` per §3.2; all generic code calls `backend_call`/`backends_render_all`.
- **Read first:** §3.2, `lib/service.sh` (`restart_service`, override helpers ex-`:1811-1850`, `cmd_config_loglevel/listen/metrics` ex-`:9247-9542`, `cmd_log*` ex-`:9837-9943`, `get_last_login` ex-`:1472`), `lib/lifecycle.sh` (tacquito-specific parts of install/upgrade/uninstall: Go, clone, patches, build, service user, unit, logrotate), `render_tacacs_config` (WP1.3), `tests/unit/deps.bats`, `tests/e2e/log.bats`.
- **Scope:** move (not rewrite) tacquito-specific functions into the module; `backends.enabled` schema key (default `[tacacs]`); generic `cmd_install/upgrade/uninstall` orchestrate: deps → `state_migrate` → store gate → `for b in enabled: backend_<b>_install|_upgrade` → render → restart; `DEPS_CORE` gains `python3-yaml`; all `chown tacquito:tacquito`+`restart_service` pairs become `backends_render_all && backends_restart_changed`; `backends_check_drift` moves here; `tests/unit/backend.bats` (contract completeness: every id defines every verb). Move `config/tacquito.*` to `config/backends/tacacs/` and update paths. Out of scope: listeners/template unit (WP2.2), new CLI (WP2.3).
- **Acceptance:** `make lint && make test` green; `declare -F | grep backend_tacacs_` lists all contract verbs.
- **Executor:** Opus. **Deps:** WP1.6. **Worktree:** no (cross-cutting).

### WP2.2 — Template unit and listener model
- **Goal:** `tacquito@.service` + `tacquito.service` alias; `listeners.<backend>.<name>` schema with TLS fields reserved; drop-ins rendered.
- **Read first:** `config/backends/tacacs/tacquito.service`, override helpers and `cmd_config_listen/loglevel/metrics` (now in `lib/backends/tacacs.sh`), upgrade drop-in migration (ex-`:10843-10859`), `linux_write_install_script` port read (ex-`:4845-4848`), `cmd_status` listener lines (ex-`:8717-8747`), `config/backends/tacacs/tacquito.logrotate`, §3.4.
- **Scope:** schema type `listener` (validate network/address pairs via `validate_listen_address` ex-`:1783`; `tls.enabled: true` → error "reserved for a future release"); `backend_tacacs_listeners list|show|set|reset`; `tacctl config listen [--backend tacacs] [--listener default] tcp|tcp6 <addr>|show|reset` keeps today's syntax when flags are omitted; `loglevel` and `metrics` become per-backend settings in `tacctl.yaml` (`backends.tacacs.level`, `backends.tacacs.metrics_address`); render drop-ins `/etc/systemd/system/tacquito@<name>.service.d/tacctl.conf`; upgrade imports existing `tacctl-overrides.conf` once, installs the template unit, enables `tacquito@default`, creates the alias, removes the old unit+drop-in dir; per-instance acct log and logrotate; `status` lists each instance. Tests with stubbed `systemctl`; e2e stubs accept `tacquito@default`/alias.
- **Acceptance:** `make test` green; on the dev server after `tacctl upgrade --branch develop`: `systemctl status tacquito` active (there is no `tacquito@default`: see 3.4, as built), `tacctl config listen` and `tacctl config loglevel` show the migrated values.
- **Executor:** Opus. **Deps:** WP2.1. **Worktree:** no (edits `lib/backends/tacacs.sh`, `lib/service.sh`, lifecycle).

### WP2.3 — Backend CLI, tier/sudoers, completion
- **Goal:** `tacctl backend list|status|enable <id>|disable <id>`, `tacctl config render|import <backend>`, `tacctl store show|import|rollback` surfaced in usage/completion/tier rules.
- **Read first:** `lib/dispatch.sh` (usage, main case), `tier_permits`/`emit_tier_sudoers` (ex-`:2044-2063, 9556-9573`), `config/tacctl.bash-completion`, `man/tacctl.1` command sections, `lib/backend.sh`.
- **Scope:** implement the dispatchers (enable: runs `backend_<id>_install` if not installed, adds to `backends.enabled`, renders; disable: removes from enabled, stops the service, keeps artifacts, prompts); read-only verbs (`backend list|status`, `store show`) added to `TACCTL_RO`/`tier_permits`; completion words; man page entries. Out of scope: RADIUS module itself.
- **Acceptance:** `make test` green; `tests/integration/tiers.bats` extended for the new RO verbs; `visudo -cf` on the emitted sudoers in test.
- **Executor:** Sonnet. **Deps:** WP2.1. **Worktree:** parallel with WP2.4 (coordinate `lib/dispatch.sh` usage text — 2.3 owns it).

### WP2.4 — status / log / backup loops over backends
- **Goal:** `tacctl status`, `log *`, `backup restore` iterate enabled backends with per-backend sections (Decision 12).
- **Read first:** `cmd_status` (ex-`:8687-9023`), `cmd_log*` (ex-`:9837-9943`), WP1.5 `backup restore`, `backend_tacacs_health/log/accounting`.
- **Scope:** generic sections (users, scopes, posture, password age, drift) + `for b in enabled: section from backend_<b>_health`; `log tail|search|failures|accounting|clear [--backend <id>]` default all enabled; `backup restore` renders all backends. Keep single-backend output compatible with `tests/integration/status_and_scope_lookup.bats` and `tests/e2e/log.bats` (the stubs keep matching `tacquito`: WP2.2 left the default listener's unit name as it was).
- **Acceptance:** `make test` green.
- **Executor:** Sonnet. **Deps:** WP2.1 (and WP2.2 for instance names). **Worktree:** parallel with 2.3.

### WP3.1 — FreeRADIUS backend design and config templates
- **Goal:** `lib/backends/radius.sh` skeleton with every contract verb stubbed and a header design doc; `config/backends/radius/*` templates; §9 items 1-3 checked and recorded.
- **Read first:** §5, §3.2, `lib/backends/tacacs.sh` as the model implementation, `lib/model.sh` JSON shape, `normalize_bcrypt_hash` (ex-`:1537`), FreeRADIUS 3.2 docs for `clients.conf`, `rlm_files`, `rlm_pap`, `detail`, virtual-server `listen`, unlang `%{client:…}`.
- **Scope:** write the design (header comment) deciding: distro detection table (confdir, unit, user, `-CX` command), site/mods/users/dictionary templates with `${VAR}` placeholders, the user∈scope enforcement mechanism, disabled `default`/`inner-tunnel` handling, logrotate, uninstall semantics (remove tacctl artifacts, re-enable distro sites, package left installed); stub functions returning "not implemented" with the exact signature; `backend_radius_describe`. Record verification results for §9 items 1-3 in `docs/radius-notes.md`. No live FreeRADIUS run yet. Out of scope: rendering logic (WP3.2).
- **Acceptance:** `make lint` green; `tests/unit/backend.bats` contract check passes for `radius`; design doc answers every bullet in §5.
- **Executor:** Opus. **Deps:** WP2.1. **Worktree:** safe (new files).

### WP3.2 — FreeRADIUS renderer and lifecycle implementation
- **Goal:** fill the stubs: install/upgrade/uninstall, render, validate, service, listeners, health, log, accounting, last_login, secret_constraints.
- **Read first:** WP3.1 design + templates, `lib/model.sh`, `backends_render_all`, `rendered_record/check`, `_apt_install`/`ensure_dependencies` (ex-`:10171-10209`), `lib/backends/tacacs.sh` for patterns, `tests/helpers/mocks.bash`.
- **Scope:** per §5; hex→raw bcrypt; omit disabled/sink users; scopes filtered by `protocols`; atomic writes with `rendered.json`; `freeradius -CX` validate; `ss -ulnp` health; detail-file accounting tail; `install` disables distro sites and enables `tacctl`; `uninstall` reverses. All external commands stub-friendly. Tests belong to WP3.4 but add unit tests for pure functions (hex→raw, client block text).
- **Acceptance:** `make lint && make test` green; `tacctl backend enable radius` with stubs renders expected files (golden).
- **Executor:** Sonnet. **Deps:** WP3.1. **Worktree:** parallel with 3.3/3.4 (owns `lib/backends/radius.sh`).

### WP3.3 — RADIUS device templates and `--protocol`
- **Goal:** `config cisco|juniper [--protocol tacacs|radius]` with `cisco-radius.template`, `juniper-radius.template`; WTI only if §9 item 8 confirms support.
- **Read first:** `lib/render_devices.sh` (ex-`:3795-4708`), `config/templates/*`, `resolve_template` (ex-`:1435`), `tests/integration/config_templates.bats`, golden files, `backend_radius_device_vars` (WP3.1 signature).
- **Scope:** flag parsing, template selection `<vendor>-radius.template`, variables (`SERVER_IP`, `SECRET`, `AUTH_PORT`, `ACCT_PORT`, `RADIUS_GROUP` from a new `radius_group.<scope>` schema key defaulting `RADIUS-GROUP`, `AUTHN_METHODS` honouring `aaa.order`), Cisco `radius server`/`aaa group server radius`, Junos `radius-server` + `authentication-order`; group summary; golden files `*-radius-lab.conf`. Out of scope: WTI unless confirmed.
- **Acceptance:** `make test` green; goldens reviewed.
- **Executor:** Sonnet. **Deps:** WP3.1. **Worktree:** parallel (owns `lib/render_devices.sh`, `config/templates/`).

### WP3.4 — RADIUS tests
- **Goal:** integration/e2e coverage for the RADIUS backend with stubs.
- **Read first:** `tests/helpers/*`, `tests/integration/tacquito_patches.bats` (stub style), WP3.1 design, WP3.2 code.
- **Scope:** fixtures `store.radius.yaml`; stubs for `apt-get`, `dnf`, `systemctl`, `freeradius`, `radiusd`, `ss`, `journalctl`; tests: enable/disable, render goldens for Debian and RHEL path sets (via a `TACCTL_RADIUS_FAMILY` test override), scope `protocols` filtering, disabled user omitted, drift refusal, `status` section, `log --backend radius`. Document the manual the dev server check (WP3.5) in `tests/README.md`.
- **Acceptance:** `make test` green; coverage report shows `lib/backends/radius.sh` ≥ 70%.
- **Executor:** Sonnet. **Deps:** WP3.2 (can start on fixtures/stubs in parallel). **Worktree:** parallel (owns `tests/integration/radius*.bats`).

### WP3.5 — Live RADIUS verification on the dev server
- **Goal:** prove PAP against bcrypt works end to end on the dev host.
- **Read first:** WP3.1-3.4 outputs, `tests/README.md` manual section, project memory "no testing on production".
- **Scope (the dev server only):** `tacctl backend enable radius`; create throwaway user `radtest1` in scope `lab` (hash via `tacctl hash generate`); `radtest radtest1 <pw> 127.0.0.1 0 <lab secret>` from `freeradius-utils` with 127.0.0.1 covered by a scope prefix (add a temporary `/32` to `lab` or a temporary scope, then remove); confirm Access-Accept with `Cisco-AVPair`; confirm reject for wrong password and for a user outside the scope; check `tacctl status`, `tacctl log --backend radius failures`, accounting detail; remove the throwaway user/prefix; `tacctl backend disable radius` if the user wants the dev server back to TACACS+-only. Report commands and outputs. Fix defects found (small) or file them as follow-ups.
- **Acceptance:** written report; store and rendered files back to pre-test state.
- **Executor:** Opus. **Deps:** WP3.2-3.4. **Worktree:** no (live).

### WP4.1 — Client script method abstraction
- **Goal:** `config/linux/client-install.sh` and `client-remove.sh` support `TAC_METHOD=tacplus|radius` per §6.1.
- **Read first:** both scripts in full (`client-install.sh:1-685`, `client-remove.sh:1-96`), `tests/integration/config_linux.bats` (fake-DB and `TACCTL_CLIENT_TEST` patterns), project memory `project_linux_tacacs.md`, pam_radius USAGE (options, `localifdown`, `conf=`), §9 items 4-5.
- **Scope:** factor method-specific parts into `install_module_tacplus`/`install_module_radius`, `pam_lines_<method>`, `selinux_<method>`, `remove_method_artifacts <method>`, `$STATE_DIR/method`; radius conf file 0600; account/session lines per §6.1; `client-remove.sh` removes both; keep every existing tacplus test passing byte-for-byte; add radius tests using the fake DB (package install stubbed via `TACCTL_CLIENT_NEED_PKGS`, PAM dir scratch). Out of scope: server-side flags.
- **Acceptance:** `make lint && make test` green; shellcheck clean on both scripts.
- **Executor:** Opus (PAM control semantics are safety-critical). **Deps:** WP3.2 (for the acct listener name only; can proceed with a fixed default). **Worktree:** safe (owns `config/linux/`).

### WP4.2 — Server-side `--method`, registry, script generation
- **Goal:** `host enroll --method`, registry field 7, `config linux script --method`, `host.default_method` key, scope `protocols` seeding for auto-created scopes.
- **Read first:** `lib/linux_hosts.sh` (`linux_write_install_script` ex-`:4825-4885`, `cmd_host_*` ex-`:5304-5580`, `host_record/remember` ex-`:5211-5230`), `tests/integration/host.bats`, `tests/integration/config_linux.bats:1-60`, WP4.1 header variables, `backend_radius_listeners`.
- **Scope:** per §6.2; backend-enabled and scope-protocol preconditions; skip podman/prebuilt for radius; header emits `TAC_METHOD`, `TAC_PORT` from the method's auth listener, `TAC_ACCT_PORT`; `host list` shows METHOD; tests for default method, explicit radius, switch on re-enroll, 6-field legacy registry lines.
- **Acceptance:** `make test` green.
- **Executor:** Sonnet. **Deps:** WP4.1, WP3.2. **Worktree:** parallel with 4.3 (owns `lib/linux_hosts.sh`).

### WP4.3 — RHEL/SELinux radius path and container matrix
- **Goal:** EPEL packaging and SELinux handling for the radius method; verify in rootless podman containers (AlmaLinux 8/9/10, Ubuntu noble, Debian bookworm) on the dev server.
- **Read first:** `client-install.sh` family/SELinux sections (WP4.1 result), project memory test-container notes (`--cap-add AUDIT_WRITE`, `pam_loginuid` commented, `pam_unix account` → `pam_permit`), §9 items 4-5.
- **Scope:** `pkg_ensure` for `pam_radius` with an EPEL hint when missing; SELinux boolean/CIL per §6.1 (record findings in `docs/radius-notes.md`); run the enroll/login/sudo/unenroll cycle in containers against the dev server FreeRADIUS (throwaway user, removed afterwards); SELinux enforcing cannot be tested in containers — document as unverified like the TACACS+ CIL. Out of scope: production hosts.
- **Acceptance:** report per distro; any script fix passes `make test`.
- **Executor:** Sonnet (procedure is well-defined) — escalate to Opus if PAM behaviour differs from §6.1. **Deps:** WP4.1, WP3.5. **Worktree:** no (live containers).

### WP4.4 — Live multi-method verification on the test client
- **Goal:** `tacctl host enroll client --method radius` end to end, then switch back to tacplus.
- **Read first:** project memory `project_hosts.md`, `project_linux_tacacs.md` (the test client is enrolled on `lab`, a test user), WP4.1-4.3 reports.
- **Scope (the dev server → the test client only):** enroll the test client with `--method radius --scope lab` (lab must allow radius), SSH password login as a throwaway user, `sudo` re-auth, wrong-password reject, unreachable-server fallback by blocking UDP/1812 with iptables on the test client (never by stopping the daemon — same approach as the memory note), accounting visible in `tacctl log --backend radius accounting`; then re-enroll with `--method tacplus` and confirm the previous state; remove throwaway users. Report.
- **Executor:** Opus. **Deps:** WP4.2, 4.3. **Worktree:** no.

### WP5.1 — Documentation, man page, completion, tests README
- **Goal:** README, `man/tacctl.1`, completion and `tests/README.md` describe the backend model, store, `/etc/tacctl`, RADIUS, `--protocol`, `--method`, migration and rollback.
- **Read first:** `README.md` (whole), `man/tacctl.1`, `config/tacctl.bash-completion`, this plan §3-7.
- **Scope:** restructure README "System Files" per backend; new sections "Backends", "Canonical store and generated configs", "Upgrading to 0.2.0" (gate, legacy mode, rollback), "RADIUS", "Linux hosts: methods"; man page sections for every new verb; completion words. Out of scope: code.
- **Acceptance:** `man -l man/tacctl.1` renders; every new verb documented; README examples run on the dev server.
- **Executor:** Sonnet. **Deps:** WP2.3, 3.3, 4.2 merged. **Worktree:** safe (docs only), but conflicts with WP5.2 on README.

### WP5.2 — Cosmetic rename pass
- **Goal:** generic headings and messages where a feature is no longer TACACS+-only; keep "TACACS+" where accurate.
- **Read first:** inventory §1.2 D (line refs), `grep -n 'Tacquito\|TACACS' lib/*.sh`, tests asserting those strings (`grep -rn 'Tacquito\|TACACS' tests/`).
- **Scope:** `Tacquito Users` → `Users`, etc.; installer banners mention backends; help text per verb; update test assertions accordingly; do not rename `tac-*` groups, `tacacs_group`/`aaa.order` keys, or anything on enrolled hosts.
- **Acceptance:** `make test` green; `grep -c Tacquito lib/*.sh` limited to the TACACS+ module and legacy-mode messages.
- **Executor:** Sonnet. **Deps:** WP5.1 (or same worktree). **Worktree:** conflicts with 5.1 and any open package.

---

### Critical Files for Implementation
- `/home/user/tacctl/bin/tacctl.sh` — the monolith every phase starts from (paths `:29-83`, service control `:1446-1850`, data-model editors `:1854-3726`, status/log/backup `:8687-10059`, lifecycle `:10164-11093`, dispatch `:11099-11283`)
- `/home/user/tacctl/config/tacquito.yaml` — the anchor layout the renderer must reproduce for the equivalence proof
- `/home/user/tacctl/config/tacquito.service` — becomes the `tacquito@.service` template; listener/TLS fields originate here
- `/home/user/tacctl/config/linux/client-install.sh` — the pam_tacplus client whose shared/per-method split defines the RADIUS host path
- `/home/user/tacctl/tests/helpers/tmpenv.bash` — the harness that must learn `TACCTL_STATE_DIR`, `lib/`, store import on fixture load, and RADIUS stubs

Sources for external claims: [rlm_pap source (upstream master)](https://doc.freeradius.org/rlm__pap_8c_source.html), [rlm_pap man page](https://www.mankier.com/5/rlm_pap), [FreeRADIUS RadSec howto 3.2.7](https://freeradius.org/documentation/freeradius-server/3.2.7/howto/protocols/proxy/enable_radsec.html), [pam_radius USAGE](https://raw.githubusercontent.com/FreeRADIUS/pam_radius/master/USAGE), [pam_radius README](https://raw.githubusercontent.com/FreeRADIUS/pam_radius/master/README.md), [libpam-radius-auth (Debian sid)](https://packages.debian.org/en/sid/libpam-radius-auth), [pam_radius in Fedora/EPEL](https://packages.fedoraproject.org/pkgs/pam_radius/pam_radius/index.html), [RH bug 1169877 (pam_radius and SELinux)](https://bugzilla.redhat.com/show_bug.cgi?id=1169877), [layeh/radius on pkg.go.dev](https://pkg.go.dev/layeh.com/radius), [FreeRADIUS on Ubuntu (RADIUSdesk wiki)](https://github.com/RADIUSdesk/rdcore/wiki/Installing-FreeRADIUS-version-3.x-on-Ubuntu-20.04), [debops.freeradius defaults](https://docs.debops.org/en/latest/ansible/roles/freeradius/defaults/main.html).
