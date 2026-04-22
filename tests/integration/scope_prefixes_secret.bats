#!/usr/bin/env bats
# Integration tests for per-scope prefix + secret management:
#   tacctl scope prefixes <scope> {list|add|remove|clear}
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
    # Deterministic `openssl rand -base64 24` — used by scopes secret generate.
    stub_cmd openssl 'if [[ "$1" == "rand" && "$2" == "-base64" ]]; then echo "DETERMINISTICSECRET=="; else exit 1; fi'
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

# --- scopes prefixes clear ---------------------------------------------------

@test "scopes prefixes clear: wipes all prefixes from an unreferenced scope" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab clear'
    assert_success
    # Flat emission: clearing all prefixes deletes the scope's secrets[] entry
    # entirely. The scope name vanishes from the YAML.
    run "$TACCTL_BIN_SCRIPT" scope list
    refute_output --partial "lab"
}

@test "scopes prefixes clear: refuses when users reference the scope (no --force)" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$TEST_HASH" --scopes lab > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab clear'
    assert_failure
    assert_output --partial "still reference"
}

@test "scopes prefixes clear: --force clears with users present (leaves orphan refs)" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$TEST_HASH" --scopes lab > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes lab clear --force'
    assert_success

    # Scope is gone from secrets[], but alice's scopes[] still refers to it
    # (orphan reference that `tacctl config validate` would surface).
    run "$TACCTL_BIN_SCRIPT" scope list
    refute_output --partial "lab"
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial '"lab"'
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

@test "scopes secret generate: uses openssl and persists the value" {
    run "$TACCTL_BIN_SCRIPT" scope secret prod generate
    assert_success
    assert_output --partial "DETERMINISTICSECRET=="

    run "$TACCTL_BIN_SCRIPT" scope secret prod show
    assert_output --partial "DETERMINISTICSECRET=="
    stub_called 'openssl rand -base64 24'
}

# --- scopes secret: unknown scope -------------------------------------------

@test "scopes secret show: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope secret nosuchscope show
    assert_failure
    assert_output --partial "does not exist"
}
