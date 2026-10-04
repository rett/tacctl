# tacctl 0.2.0 Go rewrite — line references at the `0.1.16` tag

Companion to `docs/plans/go-rewrite.md` (WP0.1). The plan cites `lib/users.sh`, `lib/scopes.sh`, `lib/core.sh`, `lib/conf.sh` and `lib/lifecycle.sh` by **0.1.15** line numbers and marks those citations **[refresh @0.1.16]**. This file gives the same constructs at the **`0.1.16` tag**, the parity baseline. Read the code with `git show 0.1.16:lib/<file>`, never from a working tree.

**Method.** Each 0.1.15 range was mapped line by line onto 0.1.16 with a diff of the two versions of the file (`git show 0.1.15:lib/<f>` against `git show 0.1.16:lib/<f>`; unchanged lines map exactly). Every range whose ends fell on a changed line was located by hand, and every function range was checked against the function's first line and closing brace at 0.1.16. Line counts: `users.sh` 1060 → 1096, `scopes.sh` 1937 → 1977, `core.sh` 188 → 199, `conf.sh` 1193 → 1245, `lifecycle.sh` 926 → 1021. The other lib files are not marked in the plan; the `0.1.16` tag's `lib/` is identical to `lib/` on `feature/go-rewrite` at `c69c251`.

"Where" names the plan's section; "0.1.15" is the citation as the plan has it.

## lib/core.sh

| 0.1.15 | 0.1.16 | What | Where |
|---|---|---|---|
| `8-30` | `8-30` | base paths (`TACCTL_ETC`, `TACCTL_STATE_DIR`, …, `DEPLOY_DIR`, `MANAGE_REPO`) | §3.1 `internal/paths` |
| `38-47` | `38-47` | colours and `info`/`warn`/`error` | §3.1 `internal/ui` |
| `45-47` | `45-47` | `info`/`warn`/`error` (stdout, stdout, stderr) | §1.2 output conventions |
| `50-54` | `50-54` | `get_version` | §5.3 |
| `57-70` | `63-81` | `preflight` — **changed in 0.1.16** (Decision 11d): store or `tacquito.yaml` must exist (`:65-68`); with a store and no `tacquito.yaml` it warns on stderr only when TACACS+ is enabled (`:69-72`); the `python3 -c "import bcrypt"` check stays (`:73-76`) | §1.1, §3.5 |
| `73-112` | `84-123` | `validate_class_name`, `validate_username`, `reject_reserved_username` | §3.1 `internal/names` |
| `73-187` | `84-198` | validators and the CIDR helpers (`validate_cidr`, `canonicalize_cidr`, `sort_cidrs_by_specificity`, `parse_cidr_list`) | WP1.2 |
| `87` | `98` | `validate_username`'s `[a-zA-Z0-9_-]` | §1.2 output conventions |
| `98-112` | `109-123` | `reject_reserved_username` | WP1.2 |

## lib/users.sh

Lines 1-765 are unchanged from 0.1.15, so every citation below 766 keeps its number.

| 0.1.15 | 0.1.16 | What | Where |
|---|---|---|---|
| `6-180,217-227` | `6-180,217-227` | hash forms, `generate_hash`/`verify_hash`, the masked prompt, `prompt_password`; `hash_type` | WP1.2 |
| `25-29` | `25-29` | python-bcrypt `hashpw` (`$2b$`) | §3.4 |
| `49,55` | `49,55` | the `$2[aby]$` prefix checks | §3.4 |
| `100-122` | `100-122` | `read_password_masked` | §1.2, §3.5 |
| `100-180` | `100-180` | masked prompt + `prompt_password` | §1.6 |
| `103` | `103` | the prompt is printed to stderr; `read -rsn1` reads stdin | §13 item 19 |
| `127-157` | `127-157` | `validate_password_strength` | WP1.2 |
| `161-180` | `161-180` | `prompt_password` (EOF/empty → generated password) | §1.2, §3.5 |
| `166` | `166` | `openssl rand -base64 18` | §1.4 |
| `492,511,687,694` | `492,511,687,694` | `logger -t tacctl -p auth.*` audit lines | §1.4 |
| `492-694` | `492-694` | the audit lines carry names only | §11.1 risk 12 |
| `683` | `683` | `SUDO_UID` | §2.2 |
| `737` | `737` | `user move` usage line without the word `user` | §1.2, §3.9 item 5 |
| `818-892` (`add\|remove\|set` branch) | `844-929` (`add\|remove\|replace` branch) | membership verbs of `user scope` | §1.2 |
| `845-847` (`set`) | `876-878` (`replace`) | replace the whole list | §1.2, §13 item 8 |
| `893-906` (`clear`) | `934-949` (`_user_scope_remove_all`, called at `845-846`) | `user scope <u> remove --all` with its `[y/N]` (`:944`) | §1.2, §13 item 8 |
| — | `781-788` | **new in 0.1.16:** the old `set`/`clear` fail naming `replace` / `remove --all` (exit 1) | §1.2 (Decision 11a) |
| — | `770-930` | `cmd_user_scope` as a whole; usage errors `:776-777`, `remove --all` argument check `:790-801` | §1.2 |
| `887-890` | `918-921` | the "NO scopes" warning | §13 item 8 |
| `1011-1059` | `1047-1095` | `cmd_user` dispatcher (usage block `:1065-1093`) | §1.2 |

## lib/scopes.sh

| 0.1.15 | 0.1.16 | What | Where |
|---|---|---|---|
| `29-30` | `29-30` | `SCOPE_CONF_KEYS` | WP2.4b |
| `90-95` | `90-95` | `SCOPE_CHOICE` globals | §1.6 |
| `142-283` | `142-283` | `cmd_config_prefix_filter` (`config allow\|deny`) | §1.2 |
| `289-319` | `289-319` | `cmd_scope` dispatcher (usage `cmd_scope_usage` `:321-353`) | §1.2 |
| `450-462,492` | `450-467,496` | `scope show`'s secret line — **changed in 0.1.16** (Decision 11b): the value is never printed, only `(set, N chars) — show with 'tacctl scope secret <s> show'` and the unset/placeholder/too-short forms (`:454-467`), printed at `:496` | §1.2 |
| `608` | `612` | scope-name validator `[a-zA-Z][a-zA-Z0-9_-]{0,31}` | §1.2 output conventions |
| `619-630` | `623-634` | `scope add` flag parsing | §1.2 |
| `686,1079` | `690,1119` | `openssl rand -base64 24` (scope add, secret generate) | §1.4 |
| `845-1007` | `849-1011` (+ `_scope_prefixes_remove_all` `1018-1047`) | `cmd_scope_prefixes_dispatch`. **0.1.16:** `clear` fails naming `remove --all [--force]` (`:860-863`); `remove --all [--force]` (`:864-884`); **no `replace` verb** for `scope prefixes` (usage `:900-910`: `list`, `add`, `remove`, `remove --all`) | §1.2 |
| `1010-1092` | `1050-1132` | `cmd_scope_secret_dispatch` | §1.2 |
| `1037-1056` | `1077-1096` | `scope secret <s> show` prints the value raw (its job) | §1.2 |
| `1099-1195` | `1139-1235` | `cmd_scope_protocols` | §1.2 |
| `1221-1313` | `1261-1353` | `cmd_scope_vendor_attrs` | §1.2 |
| `1323-1438` | `1363-1478` | `cmd_scope_devices` | §1.2 |
| `1652-1734` | `1692-1774` | `cmd_scope_auth_method` (`tacplus`→`tacacs`, `default`→`clear`) | §1.2 |
| `1748-1936` | `1788-1976` | `cmd_scope_mgmt_acl` | §1.2 |

## lib/conf.sh

| 0.1.15 | 0.1.16 | What | Where |
|---|---|---|---|
| `32-116` | `32-116` | `conf_emit_defaults` (embedded defaults) | WP1.3 |
| `122-125` | `155-158` | `_TACCTL_CFG_CACHE` and `_conf_invalidate` | §1.6, §4 |
| `122-190` | `155-237` | cache, `_conf_load_cache`, `_conf_walk` | WP1.3 |
| — | `118-149`, `159-162`, `194-199` | **new in 0.1.16** (Decision 11e): the loader (`_conf_overrides_py`) returns `({}, '<why>')` for a file that does not parse or is not a mapping; getters warn once on stderr: `tacctl.yaml: could not parse <file>: <why>; using the defaults (fix or remove the file; 'tacctl config validate' checks it).` | §1.3, WP1.3 |
| `226-455` | `273-502` | `_listener_py` (listener schema, reserved `tls` fields) | §3.1, §3.8, WP1.3 |
| `457-748` | `504-795` | `_conf_schema_py` | WP1.3 |
| `465-563` | `512-610` | `SCHEMA` and wildcards | §3.1 |
| `757-932` | `804-985` | `_conf_write` | §1.3, WP1.3 |
| — | `818-823`, `976-980` | **new in 0.1.16** (Decision 11e): a file that does not parse is refused before anything is written: `[ERROR] tacctl.yaml: could not parse <file>: <why>` then `[ERROR] Fix or remove the file ('tacctl config validate' checks it); nothing was written.`, return 1 | §1.3, WP1.3 |
| `912-917` | `960-965` | prune-to-default; an empty file is unlinked | §1.3 |
| `912-925` | `960-973` | prune, unlink, write (`NamedTemporaryFile` + `os.rename`) | WP1.1 |
| `924` | `972` | `os.chmod(tmp.name, 0o640)` | §1.3 |
| `929` | `982` | `chown tacquito:tacquito` best effort | §1.3 |
| `934-1035` | `987-1087` | `conf_set*`, `conf_get*`, `conf_unset`, helpers | WP1.3 |
| `1044-1072` | `1096-1124` | source-time tunables (`BCRYPT_COST` clamp 10..14, …) | §3.4, WP1.3 |
| `1075-1161` | `1127-1213` | `cmd_config_password_age` … `secret-min-length` | WP1.3 |
| `1075-1192` | `1127-1244` | the same plus `cmd_config_dump` | WP2.4c |
| `1166-1192` | `1218-1244` | `cmd_config_dump` | WP1.3 |

## lib/lifecycle.sh

| 0.1.15 | 0.1.16 | What | Where |
|---|---|---|---|
| `10-13` | `10-13` | `normalize_deploy_perms` | §11.2 |
| `100-148` | `100-148` | dependencies (`DEPS_CORE` …, `ensure_dependencies`) | WP3.3d |
| `103` | `103` | `DEPS_CORE="git wget python3 python3-yaml python3-bcrypt"` | §3.9 item 6 |
| `150-372` | `150-372` | state migration, `install_seed_config` | WP3.3a |
| `338` | `338` | `openssl rand -hex 16` | §1.4 |
| `374-550` | `374-553` | `cmd_install` | WP3.3d |
| `384-389` | `384-389` | install prerequisites `git wget python3` | §3.9 item 6 |
| `409,811,827,834` | `409,906,922,929` | the `[y/N]` prompts of install and uninstall | §1.2 |
| `452-456` | `453-459` | install seeds the templates — **0.1.16:** through `templates_sync` (`:454`) | §3.7 |
| `559-561` | `562-564` | `update_if_changed` skips a missing source | §3.7 |
| — | `575-665` | **new in 0.1.16** (Decision 11f): template manifest `TEMPLATE_MANIFEST_NAME=".shipped.sha256"` (`:587`; lines `<sha256>  <name>.template`, as `sha256sum` prints them), `_template_is_shipped` (`:593-606`, git-history fallback `git log -m --format= --raw --no-abbrev --no-renames`), `templates_sync` (`:613-665`; `<name>.template.new` beside a customised one) | §1.3, §3.7, WP3.3d |
| `584-768` | `680-863` | `cmd_upgrade` | §5.2, WP3.3d |
| `586-592` | `682-688` | `--branch` parsing (no value: `shift 2` fails under `set -e`, exit 1 silently) | §1.2, §5.2 |
| `596` | `692` | `backends_run upgrade preflight` | §5.2 |
| `617` | `713` | `state_migrate` | §5.2 |
| `624` | `720` | `backends_run upgrade build` (tacquito fetch and rebuild) | §5.2 |
| `627-669` | `723-772` | the management-repo update | §5.1 |
| `633` | `729` | `git checkout -- .` | §5.2 |
| — | `741` | **new in 0.1.16** (Decision 18g): `START_MANAGE=$(git rev-parse HEAD)` before any branch switch | §5.2 |
| `642-650` | `742-754` | `--branch`: fetch, `checkout <b>` or `checkout -b <b> origin/<b>` (an error now names the branch, `:750-751`) | §5.2 |
| `651` | `755` | `git fetch --tags --force` | §5.2 |
| `656-657` | `759-760` | `LOCAL_MANAGE`, `REMOTE_MANAGE` | §5.2 |
| `642-662` | `742-777` | branch switch through pull and the "updated" messages | §13 item 6 |
| `662` | `765` | `git pull --ff-only` | §5.2 |
| `672-675` | `781-784` | **changed in 0.1.16** (18g): re-exec `"${DEPLOY_DIR}/bin/tacctl.sh" upgrade` when `bin`/`lib` differ from `START_MANAGE` (also after a branch switch with nothing to pull) | §1.5, §5.2 |
| `685` | `791` | `normalize_deploy_perms` | §5.2 |
| `688` | `794` | `ensure_dependencies` | §5.2 |
| `692-693` | `798-799` | `chmod 755 bin/tacctl.sh; ln -sf … /usr/local/bin/tacctl` | §5.2 |
| `729-745` | `837` (calls `templates_sync`, `575-665`), summary note `849-851` | templates on upgrade — **rewritten in 0.1.16** (11f) | critical files |
| `782-925` | `877-1020` | `cmd_uninstall` | §5.2, WP3.3d |
| `896` | `991` | `git config --system --unset-all safe.directory` | §5.2 |
| `920-923` | `1015-1018` | the "Not removed" list | §5.2 |

## Related 0.1.16 lines outside the five files

Cited by the refreshed §5.2 (F3, Decision 18h), so that the Go upgrade reproduces them:

| 0.1.16 | What |
|---|---|
| `lib/backends/tacacs.sh:2980-2988` | `upgrade build`: sources up to date, patches applied, binary present **and `tacquito.bak` present** → the binary built before the re-exec is not running yet: `SKIP_BUILD=false`, `TACQUITO_PREBUILT=1`, `CURRENT_COMMIT` from `TACCTL_UPGRADE_TACQUITO_FROM` |
| `lib/backends/tacacs.sh:2991-3000` | a real rebuild keeps an existing `tacquito.bak` (the binary to go back to) and exports `TACCTL_UPGRADE_TACQUITO_FROM` across the re-exec |
| `lib/backends/tacacs.sh:3093-3096` | `finish` restarts when `SKIP_BUILD=false`, units changed, the store was flipped or the config re-rendered; a failed `systemctl restart` falls through to the `is-active` check and rollback |
| `tests/integration/upgrade_restart.bats` | the "second upgrade restarts nothing" contract (Decision 11c) and the re-exec cases |
| `tests/integration/upgrade_templates.bats` | the template manifest and `.template.new` contract (Decision 11f) |
