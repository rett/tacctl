#!/usr/bin/env bats
# Integration tests for `tacctl config validate --fix-names`: the report, then
# the rename of each device, host, user and scope with upper case in its name.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    DEVICES="${TACCTL_STATE_DIR}/devices.yaml"
    STORE="${TACCTL_STATE_DIR}/store.yaml"

    # Names from before new ones were lower case: a device, a user and a scope.
    "$TACCTL_BIN_SCRIPT" scope add dmz --prefixes 203.0.113.0/24 --secret "dmz-secret-1234567890abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add carol readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key > /dev/null
    sed -i 's/^  core-sw1:/  Core-SW1:/' "$DEVICES"
    sed -i 's/^  carol:$/  Carol:/; s/^  dmz:$/  Dmz:/' "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null 2>&1
}

# snapshot_count: snapshots in the backup directory.
snapshot_count() { find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | wc -l; }

# plain: the last output with colours stripped.
plain() { output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); }

@test "config validate --fix-names -y: renames every name, one snapshot per rename" {
    run "$TACCTL_BIN_SCRIPT" config validate
    plain
    assert_output --partial "the device 'Core-SW1' has upper case in its name"
    n=$(snapshot_count)
    run "$TACCTL_BIN_SCRIPT" config validate --fix-names -y
    assert_success
    plain
    assert_output --partial "Device 'Core-SW1' renamed to 'core-sw1'."
    assert_output --partial "User renamed: Carol -> carol"
    assert_output --partial "Scope renamed: Dmz -> dmz"
    assert_output --partial "Names: renamed 3, declined 0, not offered 0, failed 0."
    (( $(snapshot_count) == n + 3 ))
    grep -q '^  core-sw1:' "$DEVICES"
    grep -q '^  carol:$' "$STORE"
    grep -q '^  dmz:$' "$STORE"
    run "$TACCTL_BIN_SCRIPT" config validate
    plain
    refute_output --partial "has upper case"
}

@test "config validate --fix-names: a piped y renames, anything else declines and the exit is 0" {
    n=$(snapshot_count)
    run bash -c 'printf "y\nn\nn\n" | "$1" config validate --fix-names' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    plain
    assert_output --partial "Names: renamed 1, declined 2, not offered 0, failed 0."
    grep -q '^  core-sw1:' "$DEVICES"
    grep -q '^  Carol:$' "$STORE"
    (( $(snapshot_count) == n + 1 ))
}

@test "config validate --fix-names: a name whose lower-case spelling is taken is not offered and the exit is 1" {
    "$TACCTL_BIN_SCRIPT" user add carol readonly --hash "$HASH" --scopes lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" config validate --fix-names -y
    assert_failure 1
    plain
    assert_output --partial "'Carol' is not offered: 'carol' is taken; pick a name: tacctl user rename Carol <new>"
    assert_output --partial "Names: renamed 2, declined 0, not offered 1, failed 0."
}

@test "config validate --fix-names: not with --json" {
    run "$TACCTL_BIN_SCRIPT" config validate --json --fix-names
    assert_failure 1
    plain
    assert_output --partial "does not go with --json"
}

@test "config validate: takes no argument" {
    run "$TACCTL_BIN_SCRIPT" config validate extra
    assert_failure 1
    plain
    assert_output --partial "Unknown argument: 'extra'"
    refute_output --partial "Validating"
    run "$TACCTL_BIN_SCRIPT" config validate --json extra
    assert_failure 1
    plain
    assert_output --partial "Unknown argument: 'extra'"
}
