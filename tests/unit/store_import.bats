#!/usr/bin/env bats
# Unit tests for the legacy tacquito.yaml importer (store_import, lib/store.sh
# + the legacy loader in lib/model.sh) and the equivalence check.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

hexhash() { printf '24326224313224'; printf "${1}%.0s" {1..53}; }
HASH_A="$(hexhash 41)"
HASH_D="$(hexhash 44)"

setup() {
    tacctl_tmpenv_init
    export TACCTL_STATE_DIR="${BATS_TEST_TMPDIR}/state"
    mkdir -p "$TACCTL_STATE_DIR"
    tacctl_source_lib
}

# Pretty-printed model, for golden comparison.
dump_model_to() {
    model_dump | python3 -m json.tool --sort-keys > "$1"
}

# Sidecar files that accompany tests/fixtures/legacy.import-edge.yaml.
edge_sidecars() {
    mkdir -p "$PASSWORD_DATES_DIR" "${BACKUP_DIR}/disabled"
    echo "2026-08-15" > "${PASSWORD_DATES_DIR}/alice.date"
    echo "2026-01-02" > "${PASSWORD_DATES_DIR}/dave.date"
    echo "not a date"  > "${PASSWORD_DATES_DIR}/erin.date"
    echo "$HASH_D"     > "${BACKUP_DIR}/disabled/dave.hash"
}

# Append one secrets[] entry to $CONFIG (secrets is the last section of the
# minimal fixture).
append_secret() {
    local name="$1" key="$2" prefix="$3"
    cat >> "$CONFIG" <<YAML
  - name: ${name}
    secret:
      group: tacquito
      key: ${key}
    handler:
      type: *handler_type_start
    type: *provider_type_prefix
    options:
      prefixes: |
        [
          "${prefix}"
        ]
YAML
}

# --- every existing tacquito fixture ----------------------------------------

@test "import: every tacquito.* fixture imports strictly, validates, and matches its golden model" {
    local f name
    for f in "${TACCTL_SRC}"/tests/fixtures/tacquito.*.yaml; do
        name=$(basename "$f" .yaml)
        name="${name#tacquito.}"
        rm -f "$STORE_FILE"
        cp "$f" "$CONFIG"
        run store_import
        assert_success
        refute_output --partial "Cannot be represented"
        run store_validate
        assert_success
        [[ "$(stat -c %a "$STORE_FILE")" == "600" ]]
        _model_invalidate
        dump_model_to "${BATS_TEST_TMPDIR}/${name}.json"
        golden_diff "${BATS_TEST_TMPDIR}/${name}.json" "../model/${name}.json"
    done
}

@test "import: legacy loader and store loader give the same model for every fixture" {
    local f
    for f in "${TACCTL_SRC}"/tests/fixtures/tacquito.*.yaml; do
        rm -f "$STORE_FILE"
        cp "$f" "$CONFIG"
        _model_invalidate
        [[ "$(model_mode)" == "legacy" ]]
        local legacy
        legacy=$(model_dump)
        store_import > /dev/null
        [[ "$(model_mode)" == "store" ]]
        [[ "$(model_dump)" == "$legacy" ]]
    done
}

@test "import: tacquito.minimal / tacquito.multiscope produce the shipped store fixtures" {
    local name
    for name in minimal multiscope; do
        rm -f "$STORE_FILE"
        load_fixture "tacquito.${name}.yaml"
        store_import > /dev/null
        # Same regeneration switch as golden_diff (which is rooted in golden/).
        if [[ "${UPDATE_GOLDEN:-0}" == "1" ]]; then
            cp "$STORE_FILE" "${TACCTL_SRC}/tests/fixtures/store.${name}.yaml"
        fi
        diff -u "${TACCTL_SRC}/tests/fixtures/store.${name}.yaml" "$STORE_FILE"
    done
}

@test "import: re-importing the same file is a no-op" {
    load_fixture tacquito.multiscope.yaml
    store_import > /dev/null
    local before
    before=$(stat -c %i "$STORE_FILE")
    run store_import --replace
    assert_success
    [[ "$(stat -c %i "$STORE_FILE")" == "$before" ]]
}

# --- legacy `name: exec` -----------------------------------------------------

@test "import: legacy 'name: exec' service yields the same groups as 'name: shell', with a note" {
    load_fixture tacquito.legacy-exec.yaml
    run store_import
    assert_success
    assert_output --partial "group 'readonly': legacy service name 'exec'"
    run model_group superuser priv_lvl
    assert_output "15"
    run model_group readonly priv_lvl
    assert_output "1"
    diff -u "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml" "$STORE_FILE"
}

# --- edge fixture: disabled users, sink, sidecars, multi-prefix -------------

@test "import: edge fixture imports strictly and matches its golden model" {
    load_fixture legacy.import-edge.yaml
    edge_sidecars
    run store_import
    assert_success
    refute_output --partial "Cannot be represented"
    assert_output --partial "Users:    6 (3 disabled, 1 accounting sink)"
    run store_validate
    assert_success
    dump_model_to "${BATS_TEST_TMPDIR}/edge.json"
    golden_diff "${BATS_TEST_TMPDIR}/edge.json" ../model/import-edge.json
}

@test "import: disabled by marker restores the real hash from the sidecar" {
    load_fixture legacy.import-edge.yaml
    edge_sidecars
    store_import > /dev/null
    run model_user dave disabled
    assert_output "true"
    run model_user dave hash
    assert_output "$HASH_D"
}

@test "import: marker without a sidecar, and the DISABLED literal, give hash null + disabled" {
    load_fixture legacy.import-edge.yaml
    store_import > /dev/null
    local u
    for u in dave erin engineer; do
        run model_user "$u" disabled
        assert_output "true"
        run model_user "$u" hash
        assert_output ""
    done
    run grep -c "$DISABLED_MARKER_HEX" "$STORE_FILE"
    assert_output "0"
}

@test "import: a sidecar that is not a bcrypt hash blocks a strict import" {
    load_fixture legacy.import-edge.yaml
    mkdir -p "${BACKUP_DIR}/disabled"
    echo "garbage-sidecar-content" > "${BACKUP_DIR}/disabled/dave.hash"
    run store_import
    assert_failure
    assert_output --partial "user 'dave': saved hash of the disabled account is not a bcrypt hash"
    refute_output --partial "garbage-sidecar-content"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import: root is the accounting sink (no hash, disabled, flagged)" {
    load_fixture legacy.import-edge.yaml
    store_import > /dev/null
    run model_user root
    assert_output '{"accounting_sink": true, "disabled": true, "group": "readonly", "hash": null, "name": "root", "password_changed": null, "scopes": ["lab"]}'
}

@test "import: a real hash on root is unrepresentable; --force stores the sink without it" {
    load_fixture legacy.import-edge.yaml
    python3 - "$CONFIG" "$DISABLED_MARKER_HEX" "$HASH_D" <<'PY'
import sys
p, marker, real = sys.argv[1:4]
s = open(p).read()
head, sep, tail = s.partition('bcrypt_root: &bcrypt_root')
open(p, 'w').write(head + sep + tail.replace(marker, real, 1))
PY
    run store_import
    assert_failure
    assert_output --partial "user 'root': carries a real password hash"
    refute_output --partial "$HASH_D"
    [[ ! -e "$STORE_FILE" ]]
    run store_import --force
    assert_success
    run model_user root hash
    assert_output ""
    run model_user root disabled
    assert_output "true"
}

@test "import: password dates come from the sidecar files; bad content is noted and ignored" {
    load_fixture legacy.import-edge.yaml
    edge_sidecars
    run store_import
    assert_success
    assert_output --partial "user 'erin': password-date file does not hold a YYYY-MM-DD date"
    run model_user alice password_changed
    assert_output "2026-08-15"
    run model_user dave password_changed
    assert_output "2026-01-02"
    run model_user erin password_changed
    assert_output ""
    run model_user frank password_changed
    assert_output ""
}

@test "import: an unquoted all-digit hash (YAML integer) is read exactly" {
    load_fixture legacy.import-edge.yaml
    store_import > /dev/null
    run model_user alice hash
    assert_output "$HASH_A"
    run model_user alice disabled
    assert_output "false"
}

@test "import: user scope order is kept; a user with no scopes key gets [] and a note" {
    load_fixture legacy.import-edge.yaml
    run store_import
    assert_success
    assert_output --partial "user 'frank': has no scopes"
    run model_user alice scopes
    assert_output "prod
lab"
    run model_user frank scopes
    assert_output ""
}

@test "import: multi-prefix and repeated entries are unioned, canonicalised and sorted" {
    load_fixture legacy.import-edge.yaml
    store_import > /dev/null
    run model_scopes
    assert_output "lab
prod
v6"
    run model_scope lab prefixes
    assert_output "10.1.0.0/16
172.16.0.0/12"
    run model_scope prod prefixes
    assert_output "10.0.0.0/8
192.168.5.0/24"
    run model_scope v6 prefixes
    assert_output "2001:db8::/32"
    run model_scope lab secret
    assert_output "edge-lab-secret-0123456789"
}

@test "import: groups come from users and from unreferenced top-level groups; orphan anchors are noted" {
    load_fixture legacy.import-edge.yaml
    run store_import
    assert_success
    assert_output --partial "top-level 'bcrypt_user': authenticator anchor no user uses"
    assert_output --partial "top-level 'exec_retired': service anchor no group uses"
    run model_groups
    assert_output "auditors
helpdesk
operator
readonly
superuser"
    run model_group auditors
    assert_output '{"builtin": false, "juniper_class": "AUDIT-CLASS", "name": "auditors", "priv_lvl": 3}'
    run model_group helpdesk priv_lvl
    assert_output "5"
    run model_group superuser builtin
    assert_output "true"
}

@test "import: prefix_allow / prefix_deny become filters" {
    load_fixture legacy.import-edge.yaml
    store_import > /dev/null
    run model_filters
    assert_output '{"allow": ["10.0.0.0/8", "192.168.0.0/16"], "deny": ["10.66.0.0/16"]}'
}

# --- unrepresentable content ------------------------------------------------

@test "import: unrepresentable content fails, lists every item, writes nothing" {
    load_fixture legacy.unrepresentable.yaml
    run store_import
    assert_failure
    assert_output --partial "Cannot be represented in the store"
    assert_output --partial "group 'netops': service 'ppp'"
    assert_output --partial "group 'netops': service 'shell': extra set_value 'idletime'"
    assert_output --partial "user 'mallory': user-level commands override"
    assert_output --partial "user 'sha': non-bcrypt authenticator"
    assert_output --partial "user 'twogroups': 2 groups"
    assert_output --partial "user 'syslogger': accounter other than the file accounter"
    assert_output --partial "scope 'dnszone' (secrets[1]): non-prefix secret provider"
    assert_output --partial "unknown top-level key 'custom_setting'"
    assert_output --partial "8 item(s) cannot be represented"
    assert_output --partial "Nothing was written"
    [[ ! -e "$STORE_FILE" ]]
    [[ "$(model_mode)" == "legacy" ]]
    # No secret or hash in the report.
    refute_output --partial "unrep-lab-secret"
    refute_output --partial "unrep-dns-secret"
    refute_output --partial "0123456789abcdef"
}

@test "import: --force drops the unrepresentable items, reports them, and writes a valid store" {
    load_fixture legacy.unrepresentable.yaml
    run store_import --force
    assert_success
    assert_output --partial "Dropped (--force)"
    assert_output --partial "group 'netops': service 'ppp'"
    assert_output --partial "unknown top-level key 'custom_setting'"
    run store_validate
    assert_success
    run model_group netops
    assert_output '{"builtin": false, "juniper_class": "NETOPS-CLASS", "name": "netops", "priv_lvl": 15}'
    run model_user mallory group
    assert_output "netops"
    run model_user sha
    assert_output '{"accounting_sink": false, "disabled": true, "group": "readonly", "hash": null, "name": "sha", "password_changed": null, "scopes": ["lab"]}'
    run model_user twogroups group
    assert_output "readonly"
    run model_scopes
    assert_output "lab"
}

@test "import: legacy read-only mode still serves a file with unrepresentable content" {
    load_fixture legacy.unrepresentable.yaml
    [[ "$(model_mode)" == "legacy" ]]
    run model_users
    assert_success
    assert_output "mallory
sha
syslogger
twogroups"
}

@test "import: a user with no group cannot be stored; --force drops the user" {
    load_fixture legacy.import-edge.yaml
    sed -i '/^  - name: frank$/,/^    accounter:/ s/^    groups: .*$/    groups: []/' "$CONFIG"
    run store_import
    assert_failure
    assert_output --partial "user 'frank': no group"
    run store_import --force
    assert_success
    run model_user frank
    assert_failure
}

# --- errors --force cannot override -----------------------------------------

@test "import: same scope with different keys is refused even with --force, keys not printed" {
    load_fixture tacquito.minimal.yaml
    append_secret lab '"a-different-key-0123456789"' 10.20.0.0/16
    run store_import
    assert_failure
    assert_output --partial "scope 'lab' has 2 entries but 2 distinct secret.key values"
    refute_output --partial "a-different-key"
    refute_output --partial "lab-secret-placeholder"
    run store_import --force
    assert_failure
    assert_output --partial "--force does not override these"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import: a secret key that YAML reads as a number is refused, not guessed" {
    load_fixture tacquito.minimal.yaml
    append_secret branch 1234567890123456 10.20.0.0/16
    run store_import --force
    assert_failure
    assert_output --partial "scope 'branch' (secrets[1]): secret.key is missing or not a YAML string"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import: one prefix in two scopes is refused" {
    load_fixture tacquito.minimal.yaml
    append_secret other '"other-secret-0123456789"' 192.168.0.0/16
    run store_import --force
    assert_failure
    assert_output --partial "prefix 192.168.0.0/16 is claimed by scopes 'lab' and 'other'"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import: a user referencing a scope that does not exist is refused" {
    load_fixture tacquito.multiscope.yaml
    sed -i 's/^      - dmz$/      - mars/' "$CONFIG"
    run store_import --force
    assert_failure
    assert_output --partial "user 'carol': scope 'mars' does not exist"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import: a missing built-in group is refused" {
    load_fixture tacquito.minimal.yaml
    sed -i '/^operator: &operator$/,/^  accounter:/d' "$CONFIG"
    run store_import --force
    assert_failure
    assert_output --partial "built-in group 'operator' is missing"
}

@test "import: malformed YAML fails with a position and no file content" {
    printf 'secrets:\n  - name: lab\n    secret: {key: "leaky-secret-0123456789"\n' > "$CONFIG"
    run store_import
    assert_failure
    assert_output --partial "tacquito.yaml"
    refute_output --partial "leaky-secret"
    [[ ! -e "$STORE_FILE" ]]
}

# --- flags, files, overwrite ------------------------------------------------

@test "import: explicit file argument is imported instead of \$CONFIG" {
    load_fixture tacquito.minimal.yaml
    run store_import "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    assert_success
    run model_users
    assert_output "alice
bob
carol"
}

@test "import: missing source file and bad flags" {
    run store_import "${BATS_TEST_TMPDIR}/absent.yaml"
    assert_failure
    assert_output --partial "not found"
    load_fixture tacquito.minimal.yaml
    run store_import --frobnicate
    assert_failure 2
    run store_import a.yaml b.yaml
    assert_failure 2
}

@test "import: refuses to overwrite an existing store without --replace" {
    load_fixture tacquito.multiscope.yaml
    store_import > /dev/null
    cp "$STORE_FILE" "${BATS_TEST_TMPDIR}/before.yaml"
    load_fixture tacquito.minimal.yaml
    run store_import
    assert_failure
    assert_output --partial "A store already exists"
    cmp "$STORE_FILE" "${BATS_TEST_TMPDIR}/before.yaml"
    run store_import --replace
    assert_success
    run model_users
    assert_output ""
}

@test "import: --replace keeps what tacquito.yaml cannot carry" {
    load_fixture legacy.import-edge.yaml
    edge_sidecars
    store_import > /dev/null
    store_scope_set lab protocols=tacacs
    # After the flip the sidecars are gone; the store is the only holder of
    # dave's real hash and of the password dates.
    rm -rf "$PASSWORD_DATES_DIR" "${BACKUP_DIR}/disabled"
    run store_import --replace
    assert_success
    assert_output --partial "kept the protocols filter of 1 scope(s)"
    assert_output --partial "kept the password date of 2 user(s)"
    assert_output --partial "kept the saved password of 1 disabled user(s)"
    run model_scope lab protocols
    assert_output "tacacs"
    run model_user dave hash
    assert_output "$HASH_D"
    run model_user alice password_changed
    assert_output "2026-08-15"
}

@test "import: --replace snapshots first when backup_snapshot exists" {
    load_fixture tacquito.multiscope.yaml
    store_import > /dev/null
    backup_snapshot() { touch "${BATS_TEST_TMPDIR}/snapped"; }
    load_fixture tacquito.minimal.yaml
    store_import --replace > /dev/null
    [[ -e "${BATS_TEST_TMPDIR}/snapped" ]]
}

@test "import: the model temp file is cleaned up" {
    load_fixture tacquito.multiscope.yaml
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$TMPDIR"
    store_import > /dev/null
    run find "$TMPDIR" -mindepth 1
    assert_output ""
    load_fixture legacy.unrepresentable.yaml
    run store_import --replace
    assert_failure
    run find "$TMPDIR" -mindepth 1
    assert_output ""
}

# --- --check ----------------------------------------------------------------

@test "import --check: writes nothing; without a renderer it exits 3 and says so" {
    load_fixture tacquito.multiscope.yaml
    run store_import --check
    assert_failure 3
    assert_output --partial "import + validate:   OK"
    assert_output --partial "render:              SKIPPED (no renderer available)"
    assert_output --partial "equivalence with ${CONFIG} was not proven"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import --check: unrepresentable content fails before any render" {
    load_fixture legacy.unrepresentable.yaml
    render_tacacs_config() { touch "${BATS_TEST_TMPDIR}/rendered-called"; }
    run store_import --check
    assert_failure 1
    assert_output --partial "group 'netops': service 'ppp'"
    [[ ! -e "${BATS_TEST_TMPDIR}/rendered-called" ]]
    [[ ! -e "$STORE_FILE" ]]
}

@test "import --check: the render hook receives the model and an output path; EQUIVALENT passes" {
    load_fixture tacquito.multiscope.yaml
    render_tacacs_config() {
        python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); assert sorted(m["users"])==["alice","bob","carol"]' "$1" || return 1
        [[ "$(stat -c %a "$1")" == "600" ]] || return 1
        cp "$CONFIG" "$2"
    }
    run store_import --check
    assert_success
    assert_output --partial "render:              OK"
    assert_output --partial "EQUIVALENT"
    assert_output --partial "daemon load-smoke:   SKIPPED"
    assert_output --partial "Check passed. Nothing was written."
    [[ ! -e "$STORE_FILE" ]]
}

@test "import --check: a non-equivalent render fails with a redacted diff" {
    load_fixture tacquito.multiscope.yaml
    render_tacacs_config() { sed 's/dmz-secret-0123456789abcdef/rotated-secret-0123456789abc/' "$CONFIG" > "$2"; }
    run store_import --check
    assert_failure 1
    assert_output --partial "NOT EQUIVALENT"
    assert_output --partial "203.0.113.0/24"
    refute_output --partial "dmz-secret"
    refute_output --partial "rotated-secret"
    [[ ! -e "$STORE_FILE" ]]
}

@test "import --check: render failure and smoke failure both fail the check" {
    load_fixture tacquito.multiscope.yaml
    render_tacacs_config() { return 1; }
    run store_import --check
    assert_failure 1
    assert_output --partial "render:              FAILED"
    render_tacacs_config() { cp "$CONFIG" "$2"; }
    tacacs_load_smoke() { return 1; }
    run store_import --check
    assert_failure 1
    assert_output --partial "daemon load-smoke:   FAILED"
    tacacs_load_smoke() { return 0; }
    run store_import --check
    assert_success
    assert_output --partial "daemon load-smoke:   OK"
}

# --- store_equiv_check (plan 4.3 step 3) ------------------------------------

@test "equiv: a file is equivalent to itself" {
    run store_equiv_check "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml" "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    assert_success
    assert_output "EQUIVALENT"
}

@test "equiv: comments, anchors-vs-inline and user scope order do not matter" {
    local a="${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml" b="${BATS_TEST_TMPDIR}/b.yaml"
    python3 - "$a" "$b" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for u in d['users']:
    u['scopes'] = list(reversed(u['scopes']))
class NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True
yaml.dump({k: d[k] for k in ('users', 'secrets')}, open(sys.argv[2], 'w'), Dumper=NoAlias)
PY
    run store_equiv_check "$a" "$b"
    assert_success
    assert_output "EQUIVALENT"
}

@test "equiv: one multi-prefix entry equals one entry per prefix in any harmless order" {
    load_fixture tacquito.minimal.yaml
    cp "$CONFIG" "${BATS_TEST_TMPDIR}/multi.yaml"
    sed -i 's|"192.168.0.0/16"|"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"|' "${BATS_TEST_TMPDIR}/multi.yaml"
    append_secret lab '"lab-secret-placeholder-16chars"' 172.16.0.0/12
    append_secret lab '"lab-secret-placeholder-16chars"' 10.0.0.0/8
    run store_equiv_check "${BATS_TEST_TMPDIR}/multi.yaml" "$CONFIG"
    assert_success
    assert_output "EQUIVALENT"
}

@test "equiv: an order change that re-routes clients is NOT equivalent" {
    # In the fixture 10.0.0.0/8 (prod) precedes 10.10.99.0/24 (prod-inner), so
    # prod-inner never matches. Sorting by specificity brings it to life.
    local a="${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml" b="${BATS_TEST_TMPDIR}/b.yaml"
    python3 - "$a" "$b" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
s = d['secrets']
s[0], s[1] = s[1], s[0]
yaml.safe_dump({k: d[k] for k in ('users', 'secrets')}, open(sys.argv[2], 'w'))
PY
    run store_equiv_check "$a" "$b"
    assert_failure
    assert_output --partial "NOT EQUIVALENT"
    assert_output --partial "never_matches_because_of"
    assert_output --partial "prod-inner"
}

@test "equiv: a changed user hash or group is reported without printing hashes" {
    local a="${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml" b="${BATS_TEST_TMPDIR}/b.yaml"
    sed '0,/646f6e7463617265/s//646f6e7463617266/' "$a" > "$b"
    run store_equiv_check "$a" "$b"
    assert_failure
    assert_output --partial "NOT EQUIVALENT"
    assert_output --partial "<redacted:"
    refute_output --partial "646f6e74636172"
}

@test "equiv: legacy 'exec' service and 'DISABLED' literal compare equal to their modern forms" {
    run store_equiv_check "${TACCTL_SRC}/tests/fixtures/tacquito.legacy-exec.yaml" "${TACCTL_SRC}/tests/fixtures/tacquito.minimal.yaml"
    assert_success
    assert_output "EQUIVALENT"
    load_fixture legacy.import-edge.yaml
    sed "s/hash: DISABLED\$/hash: ${DISABLED_MARKER_HEX}/; s/^  name: exec\$/  name: shell/" "$CONFIG" > "${BATS_TEST_TMPDIR}/modern.yaml"
    run store_equiv_check "$CONFIG" "${BATS_TEST_TMPDIR}/modern.yaml"
    assert_success
    assert_output --partial "note: ${CONFIG}: service name 'exec' compared as 'shell'"
    assert_output --partial "EQUIVALENT"
}

@test "equiv: prefix filters compare as sets" {
    load_fixture legacy.import-edge.yaml
    sed 's|^prefix_allow: .*|prefix_allow: ["192.168.0.0/16", "10.0.0.0/8"]|' "$CONFIG" > "${BATS_TEST_TMPDIR}/b.yaml"
    run store_equiv_check "$CONFIG" "${BATS_TEST_TMPDIR}/b.yaml"
    assert_success
    sed 's|^prefix_deny: .*|prefix_deny: ["10.67.0.0/16"]|' "$CONFIG" > "${BATS_TEST_TMPDIR}/c.yaml"
    run store_equiv_check "$CONFIG" "${BATS_TEST_TMPDIR}/c.yaml"
    assert_failure
    assert_output --partial "10.67.0.0/16"
}
