#!/usr/bin/env bats
# End-to-end CRUD for `tacctl user`: add, list, show, remove.
# Exercises the full CLI path (subprocess) with external side-effect commands
# stubbed via PATH.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

# A pre-baked hex-encoded bcrypt hash (cost 10, known-good format). Passing
# --hash bypasses the interactive password prompt inside cmd_add.
TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    # chown: no-op; tacquito user doesn't exist in the test env.
    stub_cmd chown
    # systemctl: no-op; hot-reload-on-save doesn't apply in tests.
    stub_cmd systemctl
    # logger: journal isn't available; swallow calls.
    stub_cmd logger

    load_fixture tacquito.minimal.yaml
}

@test "user add: inserts authenticator anchor + user entry into YAML" {
    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    assert_success
    assert_output --partial "alice"

    # Authenticator anchor is inserted before '# --- Services ---'.
    run grep -c '^bcrypt_alice: &bcrypt_alice$' "$TACCTL_CONFIG"
    assert_output "1"

    # User entry is inserted before '# --- Secret Providers ---'.
    run grep -c '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output "1"

    # The user entry references the anchor and the chosen group + scope.
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
    assert_output --partial 'groups: [*superuser]'
    assert_output --partial 'authenticator: *bcrypt_alice'
}

@test "user add: restarts the service after mutation" {
    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    assert_success
    stub_called 'systemctl restart tacquito'
}

@test "user add: rejects duplicate username" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    run "$TACCTL_BIN_SCRIPT" user add alice operator --hash "$TEST_HASH" --scopes lab
    assert_failure
    assert_output --partial "already exists"
}

@test "user add: rejects unknown group" {
    run "$TACCTL_BIN_SCRIPT" user add alice nosuchgroup --hash "$TEST_HASH" --scopes lab
    assert_failure
    assert_output --partial "does not exist"
}

@test "user add: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "user add: rejects invalid username" {
    run "$TACCTL_BIN_SCRIPT" user add 'alice evil' superuser --hash "$TEST_HASH" --scopes lab
    assert_failure
}

@test "user add: rejects reserved usernames (root, tacquito)" {
    # root is seeded by install as a permanent accounting-only sink (Junos
    # internal daemons emit accounting as root). tacquito is the service
    # user. Neither should be creatable as a TACACS+-authenticable account.
    run "$TACCTL_BIN_SCRIPT" user add root superuser --hash "$TEST_HASH" --scopes lab
    assert_failure
    assert_output --partial "reserved"

    run "$TACCTL_BIN_SCRIPT" user add tacquito superuser --hash "$TEST_HASH" --scopes lab
    assert_failure
    assert_output --partial "reserved"
}

@test "user passwd: rejects reserved usernames (root, tacquito)" {
    # Even if a root entry exists as an accounting sink, setting a
    # password on it would silently enable TACACS+ auth — must stay
    # disabled forever.
    run "$TACCTL_BIN_SCRIPT" user passwd root --hash "$TEST_HASH"
    assert_failure
    assert_output --partial "reserved"

    run "$TACCTL_BIN_SCRIPT" user passwd tacquito --hash "$TEST_HASH"
    assert_failure
    assert_output --partial "reserved"
}

@test "user add: writes a backup before mutating" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    # backup_config writes tacquito.yaml.<timestamp> into $BACKUP_DIR.
    run bash -c 'ls "$TACCTL_ETC/backups"/tacquito.yaml.* 2>/dev/null | wc -l'
    [[ "${output:-0}" -ge 1 ]]
}

@test "user list: shows added user with group and scopes" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    assert_output --partial "alice"
    assert_output --partial "superuser"
}

@test "user show: prints details for known user" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    run "$TACCTL_BIN_SCRIPT" user show alice
    assert_success
    assert_output --partial "alice"
    assert_output --partial "superuser"
    assert_output --partial "lab"
}

@test "user show: errors on unknown user" {
    run "$TACCTL_BIN_SCRIPT" user show ghost
    assert_failure
}

@test "user remove: deletes authenticator anchor and user entry" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab

    # Confirm removal via stdin 'y'.
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" user remove alice'
    assert_success

    run grep -c '^bcrypt_alice:' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "user remove: 'n' confirmation aborts without mutation" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    local before_sha
    before_sha=$(sha256sum "$TACCTL_CONFIG" | awk '{print $1}')

    run bash -c 'echo n | "'"$TACCTL_BIN_SCRIPT"'" user remove alice'
    assert_success
    assert_output --partial "Cancelled"

    local after_sha
    after_sha=$(sha256sum "$TACCTL_CONFIG" | awk '{print $1}')
    [[ "$before_sha" == "$after_sha" ]]
}

@test "user remove: errors on unknown user" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" user remove ghost'
    assert_failure
    assert_output --partial "does not exist"
}

# --scopes comma list -----------------------------------------------------

@test "user add: multi-scope comma list lands all scopes in YAML" {
    # Add another scope first so we have two to pick from.
    run "$TACCTL_BIN_SCRIPT" scopes add prod --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    assert_success

    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab,prod
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab", "prod"]'
}
