#!/usr/bin/env bats
# Integration tests for `tacctl backup`: list, diff, restore.

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
}

@test "backup list: reports 'No backups found' on a fresh config" {
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    assert_output --partial "No backups found"
}

@test "backup list: enumerates backups created by mutating commands" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    "$TACCTL_BIN_SCRIPT" user add bob operator --hash "$TEST_HASH" --scopes lab

    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    # Milliseconds in backup_config's timestamp prevent same-second collisions.
    run bash -c 'ls "$TACCTL_ETC/backups"/tacquito.yaml.* | wc -l'
    [[ "$output" -ge 2 ]]
}

@test "backup diff: shows the diff between current and last backup" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "Diff:"
    # The diff should mention the added user.
    assert_output --partial "alice"
}

@test "backup restore: rolls the config back to a named backup" {
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab

    # Grab the pre-add backup timestamp (oldest file).
    local backup_file ts
    backup_file=$(ls -1 "$TACCTL_ETC/backups"/tacquito.yaml.* | head -1)
    ts=$(basename "$backup_file" | sed 's/tacquito\.yaml\.//')

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" backup restore '"$ts"
    assert_success

    # Alice is gone again.
    run grep -c '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "backup restore: rejects unknown timestamp" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" backup restore 19990101_000000'
    assert_failure
    assert_output --partial "not found"
}
