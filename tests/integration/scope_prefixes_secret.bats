#!/usr/bin/env bats
# Integration tests for per-scope prefix + secret management:
#   tacctl scope prefixes <scope> {list|add|remove|remove --all [--force]}
#   tacctl scope secret   <scope> {show|set|generate}

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    # Seed a second scope for collision tests.
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" > /dev/null
}

# --- scopes prefixes list ----------------------------------------------------

@test "scopes prefixes list: shows the current prefix list" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_success
    assert_output --partial "192.168.0.0/16"
}

@test "scopes prefixes list: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes nosuchscope list
    assert_failure
    assert_output --partial "does not exist"
}

# --- scopes prefixes add -----------------------------------------------------

@test "scopes prefixes add: appends a new CIDR" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add 172.16.0.0/12
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "192.168.0.0/16"
    assert_output --partial "172.16.0.0/12"
}

@test "scopes prefixes add: canonicalizes host bits on input" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add 172.16.5.5/12
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    # Input was 172.16.5.5/12 — stored canonical form is 172.16.0.0/12.
    assert_output --partial "172.16.0.0/12"
    refute_output --partial "172.16.5.5/12"
}

@test "scopes prefixes add: accepts comma-separated list" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add "172.16.0.0/12,100.64.0.0/10"
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "172.16.0.0/12"
    assert_output --partial "100.64.0.0/10"
}

@test "scopes prefixes add: rejects invalid CIDR" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add not-a-cidr
    assert_failure
}

@test "scopes prefixes add: rejects CIDR owned by another scope" {
    # 10.0.0.0/8 was claimed by 'prod' in setup.
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add 10.0.0.0/8
    assert_failure
    assert_output --partial "already in scope 'prod'"
}

@test "scopes prefixes add: idempotent when CIDR already present" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add 192.168.0.0/16
    assert_success
    assert_output --partial "No new CIDRs"
}

# --- scopes prefixes remove --------------------------------------------------

@test "scopes prefixes remove: drops the CIDR from the list" {
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 172.16.0.0/12 > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove 192.168.0.0/16
    assert_success

    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    refute_output --partial "192.168.0.0/16"
    assert_output --partial "172.16.0.0/12"
}

@test "scopes prefixes remove: warns when CIDR isn't present" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove 100.64.0.0/10
    # Exit status from the "Nothing to remove" path is 0 (`exit 0`).
    assert_success
    assert_output --partial "Nothing to remove"
}

# --- scopes prefixes remove --all -------------------------------------------

@test "scopes prefixes remove --all: wipes all prefixes from an unreferenced scope" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab remove --all'
    assert_success
    assert_output --partial "Removing all 1 prefix(es) from 'lab' removes the scope."
    assert_output --partial "Removed all prefixes from scope 'lab' (the scope is removed)."
    # Flat emission: removing all prefixes deletes the scope's secrets[] entry
    # entirely. The scope name vanishes from the YAML.
    run "$TACCTL_BIN_SCRIPT" scope list
    refute_output --partial "lab"
}

@test "scopes prefixes remove --all: 'n' declines and changes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove --all <<< "n"
    assert_success
    assert_output --partial "Aborted."
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "192.168.0.0/16"
}

@test "scopes prefixes remove --all: closed stdin cancels with a message and changes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove --all < /dev/null
    assert_success
    assert_output --partial "Aborted."
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "scopes prefixes remove --all: refuses when users reference the scope (no --force)" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$TEST_HASH" --scopes lab > /dev/null
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab remove --all'
    assert_failure
    assert_output --partial "still reference"
    assert_output --partial "tacctl user scope alice remove lab"
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "scopes prefixes remove --all: CIDRs beside --all, or --force without it, are usage errors" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    local args
    for args in "--all 192.168.0.0/16" "192.168.0.0/16 --all" "--all --force 192.168.0.0/16" "--all --all"; do
        # shellcheck disable=SC2086  # the args are a word list
        run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove $args <<< "y"
        assert_failure 1
        assert_output --partial "'--all' takes no CIDRs"
    done
    for args in "--force" "192.168.0.0/16 --force"; do
        # shellcheck disable=SC2086  # the args are a word list
        run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove $args <<< "y"
        assert_failure 1
        assert_output --partial "'--force' is only valid with --all"
    done
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
}

@test "scopes prefixes clear: removed, fails naming the replacement, changes nothing" {
    local before
    before=$(cksum "${TACCTL_STATE_DIR}/store.yaml")
    local args
    for args in "" "--force"; do
        # shellcheck disable=SC2086  # the args are a word list
        run "$TACCTL_BIN_SCRIPT" scope prefixes lab clear $args <<< "y"
        assert_failure 1
        assert_output --partial "'clear' was renamed: use 'tacctl scope prefixes lab remove --all [--force]'"
    done
    [[ "$(cksum "${TACCTL_STATE_DIR}/store.yaml")" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "192.168.0.0/16"
}

@test "scopes prefixes help: lists remove --all, not clear" {
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab --help
    assert_success
    assert_output --partial "tacctl scope prefixes lab remove --all [--force]"
    refute_output --partial "lab clear"
}

@test "scopes prefixes remove --all: --force removes the scope and strips it from its users" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$TEST_HASH" --scopes lab > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab remove --all --force'
    assert_success

    # A scope cannot exist without a prefix, so it is gone; and the store
    # holds no reference to a scope that does not exist, so alice loses the
    # grant rather than keeping an orphan reference.
    run "$TACCTL_BIN_SCRIPT" scope list
    refute_output --partial "lab"
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: []'
    run "$TACCTL_BIN_SCRIPT" user scope alice list
    assert_output --partial "(none"
    run "$TACCTL_BIN_SCRIPT" config validate
    refute_output --partial "nonexistent scope"
}

@test "scopes prefixes remove: refuses to remove a scope's last prefix" {
    # 'lab' has two prefixes in the minimal fixture: removing both at once
    # would leave a scope no client can match.
    local all
    all=$("$TACCTL_BIN_SCRIPT" scope prefixes lab list | sed -n 's/^  - //p' | paste -sd,)
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab remove "$all"
    assert_failure
    assert_output --partial "a scope needs at least one"
    cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"
}

# --- scopes secret show ------------------------------------------------------

@test "scopes secret show: prints value and length (healthy)" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod show
    assert_success
    assert_output --partial "prod-secret-1234567890abcdef"
    assert_output --partial "chars"
}

@test "scopes secret show: flags REPLACE placeholder secrets" {
    # Build a scope with a placeholder value that contains 'REPLACE' — the
    # minimum-length check is 16; stay above that with a leading pad.
    "$TACCTL_BIN_SCRIPT" scope add placeholder \
        --prefixes 198.51.100.0/24 --secret "REPLACE_WITH_REAL_SECRET" > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope secret placeholder show
    assert_success
    assert_output --partial "PLACEHOLDER"
}

# --- scopes secret set -------------------------------------------------------

@test "scopes secret set: persists the new secret" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod set "NEW-prod-secret-0123456789"
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope secret prod show
    assert_output --partial "NEW-prod-secret-0123456789"
}

@test "scopes secret set: rejects value below SECRET_MIN_LENGTH" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod set "short"
    assert_failure
    assert_output --partial "minimum is"
}

@test "scopes secret set: rejects single-character-class secrets (low entropy)" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod set "aaaaaaaaaaaaaaaaaaaa"
    assert_failure
    assert_output --partial "single-character-class"
    run "$TACCTL_BIN_SCRIPT" scope secret prod set "12345678901234567890"
    assert_failure
}

# --- scopes secret generate --------------------------------------------------

# 0.1.16 ran 'openssl rand -base64 24'; 0.2.0 draws the same 24 random bytes
# itself (docs/plans/go-rewrite.md 3.9 item 2). Either way: a fresh
# 32-character base64 value, printed once and stored.
@test "scopes secret generate: prints a fresh 32-character base64 secret and persists it" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod generate
    assert_success
    local secret
    secret=$(printf '%s\n' "$output" | sed -n 's/^  Generated: \x1b\[1m\(.*\)\x1b\[0m$/\1/p')
    [[ "$secret" =~ ^[A-Za-z0-9+/]{32}$ ]]
    [[ "$secret" != "prod-secret-1234567890abcdef" ]]

    run "$TACCTL_BIN_SCRIPT" scope secret prod show
    assert_output --partial "Value:  "$'\e'"[1m${secret}"$'\e'"[0m"
    assert_output --partial "Length: 32 chars"
}

# --- scopes secret: unknown scope -------------------------------------------

@test "scopes secret show: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope secret nosuchscope show
    assert_failure
    assert_output --partial "does not exist"
}
