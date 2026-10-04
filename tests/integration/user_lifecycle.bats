#!/usr/bin/env bats
# Integration tests for the user-lifecycle subcommands:
#   passwd, disable, enable, rename, move, scopes {list|add|remove|replace|remove --all}.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

# Two distinct hex-encoded bcrypt hashes (cost 10, canned). Used to assert
# that passwd actually swaps the stored value.
HASH_A="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
HASH_B="24326224313024626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml

    # Seed a prod scope + alice so every test starts from a clean known state.
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$HASH_A" --scopes lab > /dev/null
}

# One field of a user in the canonical store, as text (true/false for a
# boolean, empty for null or absent).
store_user() {
    python3 - "${TACCTL_STATE_DIR}/store.yaml" "$1" "$2" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    user = (yaml.safe_load(f).get('users') or {}).get(sys.argv[2])
if user is None:
    sys.exit(1)
v = user.get(sys.argv[3])
print('' if v is None else str(v).lower() if isinstance(v, bool) else v)
PY
}

# alice's hash as tacquito reads it from the rendered config. The
# authenticator block is:
#   bcrypt_alice: &bcrypt_alice
#     type: *authenticator_type_bcrypt
#     options:
#       hash: <hex>          (quoted when the hex is all digits)
_alice_hash() {
    grep -A5 '^bcrypt_alice:' "$TACCTL_CONFIG" | awk '/^[[:space:]]*hash:/ {gsub(/"/, "", $2); print $2; exit}'
}

# '$2b$12$' + 53 dots, hex-encoded: the hash no password matches.
DISABLED_MARKER="243262243132242e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

no_sidecars() {
    [[ -z "$(find "${TACCTL_STATE_DIR}/backups" \( -name '*.hash' -o -name '*.date' \) 2>/dev/null)" ]]
}

# --- user passwd --------------------------------------------------------------

@test "user verify: a stored bcrypt cost above 16 is refused before the password is asked (exit 1)" {
    # HASH_A with its cost 10 made 31: a check would run for days.
    local hash31="24326224333124${HASH_A#24326224313024}"
    "$TACCTL_BIN_SCRIPT" user add bob readonly --hash "$hash31" --scopes lab > /dev/null
    run timeout 30 "$TACCTL_BIN_SCRIPT" user verify bob <<< "whatever-password"
    assert_failure 1
    assert_output --partial "bcrypt cost 31 exceeds the verify limit (16); tacquito still authenticates it"
    refute_output --partial "Enter password"
    # A cost tacctl writes is checked as before.
    run timeout 30 "$TACCTL_BIN_SCRIPT" user verify alice <<< "whatever-password"
    assert_output --partial "Password does not match."
}

@test "user passwd --hash: swaps the stored bcrypt hash" {
    local before; before=$(_alice_hash)
    [[ "$before" == "$HASH_A" ]]

    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "$HASH_B"
    assert_success

    local after; after=$(_alice_hash)
    [[ "$after" == "$HASH_B" ]]
    [[ "$(store_user alice hash)" == "$HASH_B" ]]
}

@test "user passwd: records the password date in the store, not in a sidecar" {
    # Start from a known-old date so the change is visible.
    sed -i "s/password_changed: .*/password_changed: '2020-01-01'/" "${TACCTL_STATE_DIR}/store.yaml"
    [[ "$(store_user alice password_changed)" == "2020-01-01" ]]
    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "$HASH_B"
    assert_success
    [[ "$(store_user alice password_changed)" == "$(date +%Y-%m-%d)" ]]
    no_sidecars
    run "$TACCTL_BIN_SCRIPT" user list
    assert_output --partial "$(date +%Y-%m-%d)"
}

@test "user passwd: setting a password enables a disabled user" {
    "$TACCTL_BIN_SCRIPT" user disable alice > /dev/null
    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "$HASH_B"
    assert_success
    [[ "$(store_user alice disabled)" == "false" ]]
    [[ "$(_alice_hash)" == "$HASH_B" ]]
}

@test "user passwd: rejects unknown user" {
    run "$TACCTL_BIN_SCRIPT" user passwd ghost --hash "$HASH_B"
    assert_failure
    assert_output --partial "does not exist"
}

@test "user passwd: rejects invalid hash" {
    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "not-a-hash"
    assert_failure
    assert_output --partial "Invalid bcrypt hash"
}

# --- user disable / enable ---------------------------------------------------

@test "user disable: renders the marker hash; the store keeps the real one, flagged disabled" {
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success

    # tacquito gets the hash nothing matches; the original stays in the
    # store (no sidecar file) for 'enable' to bring back.
    [[ "$(_alice_hash)" == "$DISABLED_MARKER" ]]
    [[ "$(store_user alice hash)" == "$HASH_A" ]]
    [[ "$(store_user alice disabled)" == "true" ]]
    no_sidecars
    run "$TACCTL_BIN_SCRIPT" user list
    assert_output --partial "disabled"
}

@test "user disable: idempotent on an already-disabled user" {
    "$TACCTL_BIN_SCRIPT" user disable alice
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success
    assert_output --partial "already disabled"
}

@test "user enable: restores the original hash and clears the disabled flag" {
    "$TACCTL_BIN_SCRIPT" user disable alice
    [[ "$(store_user alice disabled)" == "true" ]]

    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_success
    [[ "$(_alice_hash)" == "$HASH_A" ]]
    [[ "$(store_user alice hash)" == "$HASH_A" ]]
    [[ "$(store_user alice disabled)" == "false" ]]
}

@test "user enable: refuses when the user is not disabled" {
    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_success
    assert_output --partial "not disabled"
}

@test "user enable: errors when there is no saved hash to restore" {
    # A disabled user with no password of its own: a seeded placeholder, or
    # an import that found the marker and no saved hash.
    # alice was added with --hash in setup(); take the hash away by editing
    # the store file (no command does that, and the test must not call
    # bash internals: it also runs against the Go binary).
    python3 - "${TACCTL_STATE_DIR}/store.yaml" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path) as f:
    text = f.read()
header = "".join(l for l in text.splitlines(True) if l.startswith("#")) + "\n"
store = yaml.safe_load(text)
store["users"]["alice"]["hash"] = None
store["users"]["alice"]["disabled"] = True
with open(path, "w") as f:
    f.write(header + yaml.safe_dump(store, sort_keys=False, default_flow_style=None, width=4096))
PY
    [[ -z "$(store_user alice hash)" ]]
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"
    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_failure
    assert_output --partial "No saved hash"
    assert_output --partial "tacctl user passwd alice"
    cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"
}

@test "user disable/enable: a disabled user imported from a legacy config with its sidecar can be enabled" {
    # The pre-store 'user disable' parked the real hash in a sidecar file;
    # the importer reads it, so 'enable' still restores the password.
    "$TACCTL_BIN_SCRIPT" user disable alice > /dev/null
    mkdir -p "${TACCTL_STATE_DIR}/backups/disabled"
    echo "$HASH_A" > "${TACCTL_STATE_DIR}/backups/disabled/alice.hash"
    rm "${TACCTL_STATE_DIR}/store.yaml"
    "$TACCTL_BIN_SCRIPT" store import > /dev/null
    [[ "$(store_user alice disabled)" == "true" ]]
    [[ "$(store_user alice hash)" == "$HASH_A" ]]

    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_success
    [[ "$(_alice_hash)" == "$HASH_A" ]]
}

# --- user rename -------------------------------------------------------------

@test "user rename: updates both anchor name and user entry in one pass" {
    run "$TACCTL_BIN_SCRIPT" user rename alice aliceA
    assert_success

    run grep -c '^bcrypt_alice: &bcrypt_alice$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^bcrypt_aliceA: &bcrypt_aliceA$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -c '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^  - name: aliceA$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -F '*bcrypt_aliceA' "$TACCTL_CONFIG"
    assert_success
}

@test "user rename: the password date, the hash and the disabled flag move with the user" {
    sed -i "s/password_changed: .*/password_changed: '2021-03-04'/" "${TACCTL_STATE_DIR}/store.yaml"
    "$TACCTL_BIN_SCRIPT" user disable alice > /dev/null
    run "$TACCTL_BIN_SCRIPT" user rename alice aliceA
    assert_success
    run store_user alice group
    assert_failure
    [[ "$(store_user aliceA password_changed)" == "2021-03-04" ]]
    [[ "$(store_user aliceA hash)" == "$HASH_A" ]]
    [[ "$(store_user aliceA disabled)" == "true" ]]
    [[ "$(store_user aliceA group)" == "superuser" ]]
}

@test "user rename: rejects reserved new names" {
    run "$TACCTL_BIN_SCRIPT" user rename alice tacquito
    assert_failure
    assert_output --partial "reserved"
    run "$TACCTL_BIN_SCRIPT" user rename alice root
    assert_failure
    assert_output --partial "reserved"
    [[ "$(store_user alice group)" == "superuser" ]]
}

@test "user rename: rejects when new name is already taken" {
    "$TACCTL_BIN_SCRIPT" user add bob operator --hash "$HASH_A" --scopes lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" user rename alice bob
    assert_failure
    assert_output --partial "already exists"
}

@test "user rename: rejects unknown old-name" {
    run "$TACCTL_BIN_SCRIPT" user rename ghost aliceA
    assert_failure
    assert_output --partial "does not exist"
}

@test "user rename: rejects invalid new-name" {
    run "$TACCTL_BIN_SCRIPT" user rename alice 'alice evil'
    assert_failure
}

# --- user move ---------------------------------------------------------------

@test "user move: rewrites groups: reference to the new group" {
    run "$TACCTL_BIN_SCRIPT" user move alice operator
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'groups: [*operator]'
    refute_output --partial 'groups: [*superuser]'
}

@test "user move: no-op when already in target group" {
    run "$TACCTL_BIN_SCRIPT" user move alice superuser
    assert_success
    assert_output --partial "already in"
}

@test "user move: rejects unknown group" {
    run "$TACCTL_BIN_SCRIPT" user move alice nosuchgroup
    assert_failure
    assert_output --partial "does not exist"
}

# --- user scopes -------------------------------------------------------------

@test "user scopes list: prints current scope memberships" {
    run "$TACCTL_BIN_SCRIPT" user scope alice list
    assert_success
    assert_output --partial "lab"
    refute_output --partial "prod"
}

@test "user scopes add: appends a new scope to the list" {
    run "$TACCTL_BIN_SCRIPT" user scope alice add prod
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    # Order is "prior list then appended" — lab first, then prod.
    assert_output --partial 'scopes: ["lab", "prod"]'
}

@test "user scopes add: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" user scope alice add nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "user scopes remove: drops a scope from the list" {
    "$TACCTL_BIN_SCRIPT" user scope alice add prod > /dev/null
    run "$TACCTL_BIN_SCRIPT" user scope alice remove lab
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["prod"]'
    refute_output --partial '"lab"'
}

@test "user scopes replace: replaces the list wholesale" {
    run "$TACCTL_BIN_SCRIPT" user scope alice replace prod
    assert_success
    assert_output --partial "Replaced scopes on user 'alice': prod"

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["prod"]'
    refute_output --partial '"lab"'
}

@test "user scopes replace: takes a comma list in the order given" {
    run "$TACCTL_BIN_SCRIPT" user scope alice replace prod,lab
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["prod", "lab"]'
}

@test "user scopes replace: one unknown scope aborts the lot and writes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" user scope alice replace prod,nosuchscope
    assert_failure 1
    assert_output --partial "Scope 'nosuchscope' does not exist"
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "user scopes replace: needs at least one scope name" {
    run "$TACCTL_BIN_SCRIPT" user scope alice replace
    assert_failure 1
    assert_output --partial "Usage: tacctl user scope alice replace <scope>"
}

@test "user scopes remove --all: wipes all scopes after 'y' confirmation" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" user scope alice remove --all'
    assert_success
    assert_output --partial "unable to authenticate on any device"
    assert_output --partial "Distinct from 'tacctl user disable'"
    assert_output --partial "Removed all scopes from user 'alice'."

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: []'
}

@test "user scopes remove --all: 'n' declines and changes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" user scope alice remove --all <<< "n"
    assert_success
    assert_output --partial "Aborted."
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
}

@test "user scopes remove --all: closed stdin cancels with a message and changes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" user scope alice remove --all < /dev/null
    assert_success
    assert_output --partial "Aborted."
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "user scopes remove --all: a user with no scopes is a no-op without a prompt" {
    "$TACCTL_BIN_SCRIPT" user scope alice remove --all <<< "y" > /dev/null
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" user scope alice remove --all < /dev/null
    assert_success
    assert_output --partial "User 'alice' already has no scopes."
    refute_output --partial "unable to authenticate"
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "user scopes remove --all: scope names beside --all are a usage error" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    local args
    for args in "--all lab" "lab --all" "--all --all"; do
        # shellcheck disable=SC2086  # the args are a word list
        run "$TACCTL_BIN_SCRIPT" user scope alice remove $args <<< "y"
        assert_failure 1
        assert_output --partial "'--all' takes no scope names"
        [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
    done
}

@test "user scopes set and clear: removed, fail naming the replacement, change nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" user scope alice set prod
    assert_failure 1
    assert_output --partial "'set' was renamed: use 'tacctl user scope alice replace <scope>[,<scope>...]'"
    run "$TACCTL_BIN_SCRIPT" user scope alice clear <<< "y"
    assert_failure 1
    assert_output --partial "'clear' was renamed: use 'tacctl user scope alice remove --all'"
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
}

@test "user scopes help: lists replace and remove --all, not set or clear" {
    run "$TACCTL_BIN_SCRIPT" user scope alice --help
    assert_success
    assert_output --partial "tacctl user scope alice replace <scope>"
    assert_output --partial "tacctl user scope alice remove  --all"
    refute_output --regexp "alice (set|clear) "
}

@test "user scopes: rejects unknown user" {
    run "$TACCTL_BIN_SCRIPT" user scope ghost list
    assert_failure
    assert_output --partial "does not exist"
}
