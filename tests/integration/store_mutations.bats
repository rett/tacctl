#!/usr/bin/env bats
# How every mutating command applies a change: gate, backup, store write,
# render, restart (store_apply in lib/render_tacacs.sh).
#
#   - legacy mode (no store): every mutating verb refuses and changes nothing,
#     every read verb still works from tacquito.yaml;
#   - the store is what a command writes, tacquito.yaml is rendered from it;
#   - a hand-edited tacquito.yaml refuses the command before anything is
#     written; a failed render puts store.yaml and tacctl.yaml back;
#   - a never-rendered tacquito.yaml is adopted only when it says what the
#     store says;
#   - secrets and hashes stay out of error output.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
HASH_B="24326224313024626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    # 'status' is exercised below; keep it off the host's real daemon.
    stub_cmd ss
    stub_cmd curl
    stub_cmd journalctl
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    LEGACY_DIR="${TACCTL_STATE_DIR}/backups/legacy"
}

# A store plus the tacquito.yaml tacctl rendered from it, recorded.
rendered_install() {
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    chmod 600 "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    : > "$CALLS_LOG"
}

# store_get <section> <name> <field>: one field of the canonical store, as
# text (true/false for a boolean, a list comma-joined, empty for null/absent).
store_get() {
    python3 - "$STORE" "$@" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    ent = (yaml.safe_load(f).get(sys.argv[2]) or {}).get(sys.argv[3])
if ent is None:
    sys.exit(1)
v = ent.get(sys.argv[4]) if len(sys.argv) > 4 else ent
if isinstance(v, bool):
    v = str(v).lower()
elif isinstance(v, list):
    v = ','.join(str(x) for x in v)
print('' if v is None else v)
PY
}

teardown() {
    # A test below makes the config directory read-only.
    chmod 755 "${TACCTL_ETC}" 2>/dev/null || true
}

refute_stub_called() {
    if stub_called "$1"; then
        echo "unexpected call matching '$1':"
        stub_calls
        return 1
    fi
}

# Snapshots (backups/<ts>/) plus old-style tacquito.yaml.<ts> files: anything
# a command could have left behind as a backup.
backup_count() {
    find "${TACCTL_STATE_DIR}/backups" -maxdepth 1 \( -name 'tacquito.yaml.*' -o -type d -name '[0-9]*' \) 2>/dev/null | wc -l
}

# Everything a refused or rolled-back command must leave exactly as it was.
snapshot_state() {
    cp "$STORE" "${BATS_TEST_TMPDIR}/store.before"
    cp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/config.before"
    if [[ -f "$OVERRIDES" ]]; then cp "$OVERRIDES" "${BATS_TEST_TMPDIR}/overrides.before"; fi
    : > "$CALLS_LOG"
}

assert_state_unchanged() {
    cmp "$STORE" "${BATS_TEST_TMPDIR}/store.before"
    cmp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/config.before"
    if [[ -f "${BATS_TEST_TMPDIR}/overrides.before" ]]; then
        cmp "$OVERRIDES" "${BATS_TEST_TMPDIR}/overrides.before"
    else
        [[ ! -e "$OVERRIDES" ]]
    fi
    refute_stub_called 'systemctl restart'
    # No rollback copy left behind.
    [[ -z "$(find "$TACCTL_STATE_DIR" -maxdepth 1 -name '.apply.*')" ]]
}

# =============================================================================
#  Legacy read-only mode
# =============================================================================

legacy_install() {
    # A pre-store install with real content: users, a custom group, filters.
    cp "${TACCTL_SRC}/tests/fixtures/golden/tacquito.multiscope.rendered.yaml" "$TACCTL_CONFIG"
    [[ ! -e "$STORE" ]]
}

@test "legacy mode: every mutating verb refuses with the store message and changes nothing" {
    legacy_install
    local before
    before=$(cksum "$TACCTL_CONFIG")
    local -a verbs=(
        "user add dave operator --hash $HASH --scopes lab"
        "user remove alice"
        "user passwd alice --hash $HASH_B"
        "user disable alice"
        "user enable alice"
        "user rename alice alicia"
        "user move alice operator"
        "user scope alice add dmz"
        "user scope alice remove lab"
        "user scope alice set dmz"
        "user scope alice clear"
        "group add helpdesk 5 HELPDESK-CLASS"
        "group edit operator priv-lvl 9"
        "group edit operator juniper-class OPS"
        "group remove operator"
        "group commands default operator permit"
        "group commands add operator configure --action deny"
        "group commands remove operator show"
        "group commands clear operator"
        "group commands seed"
        "scope add edge --prefixes 192.168.40.0/24 --secret edge-secret-0123456789abcdef"
        "scope remove dmz"
        "scope rename dmz edge"
        "scope prefixes lab add 192.168.77.0/24"
        "scope prefixes lab remove 172.16.0.0/12"
        "scope prefixes lab clear --force"
        "scope secret lab set rotated-secret-0123456789abc"
        "scope secret lab generate"
        "scope protocols lab set tacacs"
        "scope protocols lab clear"
        "config allow add 10.0.0.0/8"
        "config allow remove 10.0.0.0/8"
        "config allow clear"
        "config deny add 10.66.0.0/16"
        "config deny remove 10.66.0.0/16"
        "config deny clear"
        "config render"
    )
    local v
    for v in "${verbs[@]}"; do
        # shellcheck disable=SC2086  # the verb is a word list
        run "$TACCTL_BIN_SCRIPT" $v <<< "y"
        [[ "$status" -eq 1 ]] || { echo "'$v' exited $status: $output"; false; }
        [[ "$output" == *"store not initialised"* ]] || { echo "'$v' printed: $output"; false; }
        [[ "$output" == *"tacctl store import"* ]]
        [[ "$(cksum "$TACCTL_CONFIG")" == "$before" ]] || { echo "'$v' changed tacquito.yaml"; false; }
        [[ ! -e "$STORE" ]] || { echo "'$v' created a store"; false; }
        [[ ! -e "$OVERRIDES" ]] || { echo "'$v' wrote tacctl.yaml"; false; }
    done
    [[ ! -e "$RENDERED" ]]
    [[ "$(backup_count)" -eq 0 ]]
    refute_stub_called 'systemctl restart'
}

@test "legacy mode: self-service passwd refuses before asking for a password" {
    legacy_install
    stub_cmd id 'echo "users tac-users"'
    local before
    before=$(cksum "$TACCTL_CONFIG")
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" passwd < /dev/null
    assert_failure 1
    assert_output --partial "store not initialised"
    refute_output --partial "Current password"
    [[ "$(cksum "$TACCTL_CONFIG")" == "$before" ]]
}

@test "legacy mode: host enroll that would create a scope refuses; nothing reaches the host" {
    legacy_install
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    stub_cmd ssh
    local before
    before=$(cksum "$TACCTL_CONFIG")
    # Without --scope, enroll creates a per-host scope: a store write.
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_failure 1
    [[ "$(cksum "$TACCTL_CONFIG")" == "$before" ]]
    [[ ! -e "$STORE" ]]
    [[ ! -e "${TACCTL_STATE_DIR}/linux-hosts" ]]
    refute_stub_called '^ssh .*bash'
}

@test "legacy mode: read verbs work from tacquito.yaml" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    assert_output --partial "alice"
    assert_output --partial "carol"
    run "$TACCTL_BIN_SCRIPT" user show carol
    assert_success
    assert_output --partial "readonly"
    assert_output --partial "dmz"
    run "$TACCTL_BIN_SCRIPT" user scope alice list
    assert_success
    assert_output --partial "- prod"
    run "$TACCTL_BIN_SCRIPT" group list
    assert_success
    assert_line --regexp '^  superuser +15 +RW-CLASS +1'
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_success
    assert_output --partial "prod-inner"
    run "$TACCTL_BIN_SCRIPT" scope show lab
    assert_success
    assert_output --partial "lab-secret-0123456789abcdef"
    assert_output --partial "- alice"
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_success
    assert_output --partial "172.16.0.0/12"
    run "$TACCTL_BIN_SCRIPT" scope secret prod show
    assert_success
    assert_output --partial "prod-secret-0123456789abcdef"
    run "$TACCTL_BIN_SCRIPT" scope protocols lab
    assert_success
    assert_output --partial "all (no filter"
    run "$TACCTL_BIN_SCRIPT" scope lookup 10.10.99.7
    assert_success
    assert_output --partial "prod-inner"
    run "$TACCTL_BIN_SCRIPT" config allow list
    assert_success
    run "$TACCTL_BIN_SCRIPT" config show
    assert_success
    assert_output --partial "Super-user:         15"
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_output --partial "not initialised"
    assert_line --regexp 'Users:.* 3$'
    run "$TACCTL_BIN_SCRIPT" _completion-names users
    assert_output "alice
bob
carol"
    run "$TACCTL_BIN_SCRIPT" _completion-names scopes
    assert_line "prod-inner"
    run "$TACCTL_BIN_SCRIPT" _completion-names groups
    assert_line "superuser"
    [[ ! -e "$STORE" ]]
}

@test "legacy mode: tacctl.yaml tunables that render nothing can still be set" {
    legacy_install
    local before
    before=$(cksum "$TACCTL_CONFIG")
    run "$TACCTL_BIN_SCRIPT" scope default prod
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first
    assert_success
    run "$TACCTL_BIN_SCRIPT" group privilege add operator 'show running-config'
    assert_success
    [[ "$(conf_get scope.default)" == "prod" ]]
    [[ "$(cksum "$TACCTL_CONFIG")" == "$before" ]]
    [[ ! -e "$STORE" ]]
}

@test "legacy mode: the tier gate still reads users and groups from tacquito.yaml" {
    legacy_install
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" log tail
    assert_failure
    assert_output --partial "not permitted for the readonly tier"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" config validate
    refute_output --partial "not permitted"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" scope show lab
    assert_failure
    assert_output --partial "not permitted for the operator tier"
    SUDO_USER=ghost run "$TACCTL_BIN_SCRIPT" status
    assert_failure
    assert_output --partial "no active tacctl user"
    # A superuser passes the gate and then meets the store requirement.
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_failure 1
    assert_output --partial "store not initialised"
}

# =============================================================================
#  The store is what commands write
# =============================================================================

@test "user commands write the store and render tacquito.yaml from it" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" user add dave operator --hash "$HASH" --scopes lab,dmz
    assert_success
    [[ "$(store_get users dave group)" == "operator" ]]
    [[ "$(store_get users dave scopes)" == "lab,dmz" ]]
    [[ "$(store_get users dave hash)" == "$HASH" ]]
    [[ "$(store_get users dave disabled)" == "false" ]]
    [[ "$(store_get users dave password_changed)" == "$(date +%Y-%m-%d)" ]]
    run grep -A4 '^  - name: dave$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab", "dmz"]'
    assert_output --partial 'groups: [*operator]'
    stub_called 'systemctl restart tacquito'

    run "$TACCTL_BIN_SCRIPT" user move dave readonly
    assert_success
    [[ "$(store_get users dave group)" == "readonly" ]]

    run "$TACCTL_BIN_SCRIPT" user scope dave remove lab
    assert_success
    [[ "$(store_get users dave scopes)" == "dmz" ]]

    run "$TACCTL_BIN_SCRIPT" user remove dave <<< "y"
    assert_success
    run store_get users dave
    assert_failure
    run grep -c 'dave' "$TACCTL_CONFIG"
    assert_output "0"

    # After all of that the rendered file is exactly the render of the store.
    run "$TACCTL_BIN_SCRIPT" config render
    assert_output --partial "already up to date"
}

@test "group commands write the store; command rules stay in tacctl.yaml and are rendered" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HELPDESK-CLASS
    assert_success
    [[ "$(store_get groups helpdesk priv_lvl)" == "5" ]]
    [[ "$(store_get groups helpdesk juniper_class)" == "HELPDESK-CLASS" ]]
    run "$TACCTL_BIN_SCRIPT" group edit helpdesk priv-lvl 6
    assert_success
    [[ "$(store_get groups helpdesk priv_lvl)" == "6" ]]
    run grep -A5 '^exec_helpdesk:' "$TACCTL_CONFIG"
    assert_output --partial "values: [6]"

    run "$TACCTL_BIN_SCRIPT" group commands add helpdesk show --action permit
    assert_success
    grep -q 'helpdesk' "$OVERRIDES"
    run awk '/^helpdesk: &helpdesk/,/^  accounter:/' "$TACCTL_CONFIG"
    assert_output --partial 'name: "show"'
    # The rules are not store data.
    run grep -c 'show' "$STORE"
    assert_output "0"

    run "$TACCTL_BIN_SCRIPT" group remove helpdesk <<< "y"
    assert_success
    run store_get groups helpdesk
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config render
    assert_output --partial "already up to date"
}

@test "scope and filter commands write the store" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" scope add edge --prefixes 192.168.40.9/24,2001:DB8::/32 --secret edge-secret-0123456789abcdef
    assert_success
    [[ "$(store_get scopes edge prefixes)" == "192.168.40.0/24,2001:db8::/32" ]]
    [[ "$(store_get scopes edge secret)" == "edge-secret-0123456789abcdef" ]]
    run "$TACCTL_BIN_SCRIPT" scope prefixes edge remove 2001:db8::/32
    assert_success
    [[ "$(store_get scopes edge prefixes)" == "192.168.40.0/24" ]]
    run "$TACCTL_BIN_SCRIPT" scope secret edge set rotated-secret-0123456789abc
    assert_success
    [[ "$(store_get scopes edge secret)" == "rotated-secret-0123456789abc" ]]
    run "$TACCTL_BIN_SCRIPT" scope rename dmz perimeter
    assert_success
    [[ "$(store_get users carol scopes)" == "lab,perimeter" ]]
    run store_get scopes dmz
    assert_failure

    run "$TACCTL_BIN_SCRIPT" config deny add 10.66.0.9/16
    assert_success
    run "$TACCTL_BIN_SCRIPT" config allow add 192.168.0.0/16,10.0.0.0/8
    assert_success
    [[ "$(store_get filters deny)" == "10.66.0.0/16" ]]
    [[ "$(store_get filters allow)" == "10.0.0.0/8,192.168.0.0/16" ]]
    grep -q '^prefix_deny: \["10.66.0.0/16"\]$' "$TACCTL_CONFIG"
    grep -q '^prefix_allow: \["10.0.0.0/8", "192.168.0.0/16"\]$' "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" config allow clear <<< "y"
    assert_success
    [[ -z "$(store_get filters allow)" ]]
    run grep -c '^prefix_allow' "$TACCTL_CONFIG"
    assert_output "0"

    run "$TACCTL_BIN_SCRIPT" config render
    assert_output --partial "already up to date"
}

@test "the one-prefix-one-scope rule is enforced by the store as well as the command" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" scope add clash --prefixes 10.10.99.0/24 --secret clash-secret-0123456789abcdef
    assert_failure
    assert_output --partial "already in scope 'prod-inner'"
    # Past the command's own check, the writer refuses too.
    tacctl_source_lib
    run store_scope_set clash prefixes=10.10.99.0/24 secret=clash-secret-0123456789abcdef
    assert_failure
    assert_output --partial "one scope per prefix"
    run store_get scopes clash
    assert_failure
}

@test "each mutation snapshots the store and tacctl.yaml it changes" {
    rendered_install
    cp "$STORE" "${BATS_TEST_TMPDIR}/store.before"
    [[ "$(backup_count)" -eq 0 ]]
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_success
    [[ "$(backup_count)" -eq 1 ]]
    cmp "$(find "${TACCTL_STATE_DIR}/backups" -mindepth 2 -maxdepth 2 -name store.yaml)" "${BATS_TEST_TMPDIR}/store.before"
    # The snapshot is not the rendered file: tacquito.yaml is no longer backed up.
    [[ -z "$(find "${TACCTL_STATE_DIR}/backups" -maxdepth 1 -name 'tacquito.yaml.*')" ]]
}

@test "a change that leaves the rendered file as it was does not restart the daemon" {
    rendered_install
    # Listing every known protocol changes the store but not what TACACS+
    # serves.
    run "$TACCTL_BIN_SCRIPT" scope protocols lab set radius,tacacs
    assert_success
    [[ "$(store_get scopes lab protocols)" == "tacacs,radius" ]]
    refute_stub_called 'systemctl restart'
    refute_output --partial "Service restarted"
}

# =============================================================================
#  A hand-edited or foreign tacquito.yaml
# =============================================================================

@test "drift: a hand-edited tacquito.yaml refuses the command before anything is written" {
    rendered_install
    echo "# hand edit" >> "$TACCTL_CONFIG"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" user add dave operator --hash "$HASH" --scopes lab
    assert_failure 3
    assert_output --partial "was edited since tacctl rendered it"
    assert_output --partial "Nothing was changed"
    assert_output --partial "tacctl store import --replace"
    assert_output --partial "tacctl config render --force"
    refute_output --partial "User 'dave' added"
    assert_state_unchanged
    [[ "$(backup_count)" -eq 0 ]]

    # Every kind of mutation meets the same gate.
    run "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 9
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" scope secret lab generate
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" config deny add 10.66.0.0/16
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" group commands add operator configure --action deny
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" user remove bob <<< "y"
    assert_failure 3
    assert_state_unchanged

    # Reads are unaffected, and say what is wrong.
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    run "$TACCTL_BIN_SCRIPT" status
    assert_output --partial "DRIFT:"
}

@test "drift: after 'config render --force' discards the edit, the command goes through" {
    rendered_install
    echo "# hand edit" >> "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_success
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_success
    [[ "$(store_get users bob disabled)" == "true" ]]
    run grep -c 'hand edit' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "drift: 'store import --replace' adopts a hand edit, and the next command keeps it" {
    rendered_install
    # The operator edited the file directly: bob moved to readonly.
    python3 - "$TACCTL_CONFIG" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s, n = re.subn(r'(- name: bob\n    scopes: \[[^\]]*\]\n    groups: \[\*)operator', r'\1readonly', s)
assert n == 1
open(p, 'w').write(s)
PY
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_failure 3
    run "$TACCTL_BIN_SCRIPT" store import --replace
    assert_success
    [[ "$(store_get users bob group)" == "readonly" ]]
    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_success
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success
    [[ "$(store_get users bob group)" == "readonly" ]]
    run grep -A3 '^  - name: bob$' "$TACCTL_CONFIG"
    assert_output --partial 'groups: [*readonly]'
}

@test "a tacquito.yaml tacctl never rendered is adopted when it says what the store says" {
    # The state right after 'store import' on an existing install.
    place_fixture tacquito.multiscope.yaml
    "$TACCTL_BIN_SCRIPT" store import > /dev/null
    [[ ! -e "$RENDERED" ]]
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_success
    assert_output --partial "Previous ${TACCTL_CONFIG} saved to ${LEGACY_DIR}/tacquito.yaml.drift."
    [[ "$(store_get users bob disabled)" == "true" ]]
    # The old file is kept, the new one is tacctl's and recorded.
    cmp "$(find "$LEGACY_DIR" -name 'tacquito.yaml.drift.*')" "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    head -1 "$TACCTL_CONFIG" | grep -q '^# GENERATED by tacctl'
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
    stub_called 'systemctl restart tacquito'
}

@test "a tacquito.yaml tacctl never rendered that says something else refuses the command" {
    place_fixture tacquito.multiscope.yaml
    "$TACCTL_BIN_SCRIPT" store import > /dev/null
    # Edited after the import: the file and the store no longer agree.
    sed -i 's/key: "lab-secret-0123456789abcdef"/key: "changed-by-hand-0123456789"/' "$TACCTL_CONFIG"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_failure 3
    assert_output --partial "was not rendered by tacctl and does not say what the store says"
    assert_output --partial "tacctl config render --force"
    refute_output --partial "changed-by-hand"
    assert_state_unchanged
    [[ ! -e "$RENDERED" ]]
    [[ ! -d "$LEGACY_DIR" ]]
}

@test "a never-rendered file holding content the store cannot represent is not adopted" {
    # 'store import --force' dropped something: only an explicit
    # 'config render --force' may replace the file that still has it.
    place_fixture legacy.unrepresentable.yaml
    run "$TACCTL_BIN_SCRIPT" store import --force
    assert_success
    assert_output --partial "Dropped (--force)"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" config deny add 10.66.0.0/16
    assert_failure 3
    assert_output --partial "was not rendered by tacctl"
    assert_state_unchanged

    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_success
    run "$TACCTL_BIN_SCRIPT" config deny add 10.66.0.0/16
    assert_success
}

@test "unreadable render records refuse the command" {
    rendered_install
    echo "{not json" > "$RENDERED"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_failure 1
    assert_output --partial "refusing to overwrite"
    assert_state_unchanged
}

@test "a missing tacquito.yaml does not block a change that recreates it" {
    rendered_install
    rm "$TACCTL_CONFIG"
    # preflight needs the config for most commands; the writer itself does not.
    tacctl_source_lib
    run store_apply store_user_set bob disabled=true
    assert_success
    [[ -f "$TACCTL_CONFIG" ]]
    [[ "$(store_get users bob disabled)" == "true" ]]
}

# =============================================================================
#  A failure partway
# =============================================================================

@test "render failure: the store is put back, and the command says the change was not applied" {
    rendered_install
    # A tacctl.yaml that does not parse makes every render refuse.
    printf 'commands: [unterminated\n' > "$OVERRIDES"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" user add dave operator --hash "$HASH" --scopes lab
    assert_failure 1
    assert_output --partial "The change was not applied"
    refute_output --partial "User 'dave' added"
    refute_output --partial "$HASH"
    assert_state_unchanged
    run store_get users dave
    assert_failure

    run "$TACCTL_BIN_SCRIPT" scope secret lab set rotated-secret-0123456789abc
    assert_failure 1
    [[ "$(store_get scopes lab secret)" == "lab-secret-0123456789abcdef" ]]
    assert_state_unchanged
}

@test "render failure: a command-rule change puts tacctl.yaml back too" {
    rendered_install
    "$TACCTL_BIN_SCRIPT" group commands add operator configure --action deny > /dev/null
    grep -q 'configure' "$OVERRIDES"
    # Make the render fail after tacctl.yaml was written: the store names a
    # group the renderer cannot validate.
    sed -i 's/group: operator/group: nosuchgroup/' "$STORE"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" group commands add operator reload --action deny
    assert_failure 1
    assert_output --partial "The change was not applied"
    assert_state_unchanged
    run grep -c 'reload' "$OVERRIDES"
    assert_output "0"
}

@test "render failure: 'scope add --default' leaves neither the scope nor the default behind" {
    rendered_install
    # The rendered file cannot be moved into place.
    chmod 555 "$TACCTL_ETC"
    snapshot_state
    run "$TACCTL_BIN_SCRIPT" scope add edge --prefixes 192.168.40.0/24 --secret edge-secret-0123456789abcdef --default
    assert_failure 1
    assert_output --partial "The change was not applied"
    refute_output --partial "Scope 'edge' added"
    assert_state_unchanged
    run store_get scopes edge
    assert_failure
    [[ "$(conf_get scope.default)" == "lab" ]]
}

@test "a store write the schema refuses changes nothing and renders nothing" {
    rendered_install
    snapshot_state
    tacctl_source_lib
    run store_apply store_user_set bob group=nosuchgroup
    assert_failure 1
    assert_output --partial "group 'nosuchgroup' does not exist"
    assert_state_unchanged
}

# =============================================================================
#  Secrets and hashes
# =============================================================================

@test "a failing command prints neither the hash nor the secret it was given" {
    rendered_install
    echo "# hand edit" >> "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" user passwd bob --hash "$HASH_B"
    assert_failure 3
    refute_output --partial "$HASH_B"
    run "$TACCTL_BIN_SCRIPT" scope secret lab set rotated-secret-0123456789abc
    assert_failure 3
    refute_output --partial "rotated-secret-0123456789abc"
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1

    # A store that fails validation: the report names the field, not its value.
    sed -i "0,/hash: .*/s//hash: 'not-a-hash-value'/" "$STORE"
    run "$TACCTL_BIN_SCRIPT" scope secret lab set rotated-secret-0123456789abc
    assert_failure
    refute_output --partial "rotated-secret-0123456789abc"
    refute_output --partial "not-a-hash-value"
    refute_output --partial "lab-secret-0123456789abcdef"
}

@test "hashes and secrets do not reach any process's argv" {
    rendered_install
    # Record the command line of every python3 the commands start.
    local real_python
    real_python=$(command -v python3)
    cat > "${STUB_BIN}/python3" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${BATS_TEST_TMPDIR}/python-argv.log"
exec "${real_python}" "\$@"
STUB
    chmod +x "${STUB_BIN}/python3"

    run "$TACCTL_BIN_SCRIPT" user add dave operator --hash "$HASH" --scopes lab
    assert_success
    run "$TACCTL_BIN_SCRIPT" user passwd dave --hash "$HASH_B"
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope add edge --prefixes 192.168.40.0/24 --secret edge-secret-0123456789abcdef
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope secret edge set rotated-secret-0123456789abc
    assert_success
    run "$TACCTL_BIN_SCRIPT" user disable dave
    assert_success
    run "$TACCTL_BIN_SCRIPT" user show dave
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope show edge
    assert_success

    [[ -s "${BATS_TEST_TMPDIR}/python-argv.log" ]]
    local needle
    for needle in "$HASH" "$HASH_B" "edge-secret-0123456789abcdef" "rotated-secret-0123456789abc" \
                  "lab-secret-0123456789abcdef"; do
        run grep -cF -- "$needle" "${BATS_TEST_TMPDIR}/python-argv.log"
        assert_output "0"
    done
}

@test "the store stays 0600 and tacquito.yaml 0640 through a mutation" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" user disable bob
    assert_success
    [[ "$(stat -c %a "$STORE")" == "600" ]]
    [[ "$(stat -c %a "$TACCTL_CONFIG")" == "640" ]]
    [[ "$(stat -c %a "$RENDERED")" == "600" ]]
}
