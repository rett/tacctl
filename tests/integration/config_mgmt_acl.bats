#!/usr/bin/env bats
# Integration tests for `tacctl config mgmt-acl`: list/add/remove/clear + ACL names.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
}

# --- list / help -------------------------------------------------------------

@test "config mgmt-acl: empty-list output when no file exists" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    assert_success
    assert_output --partial "(empty)"
}

@test "config mgmt-acl (no args): prints usage + current count" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl
    assert_success
    assert_output --partial "Current entries: 0"
    assert_output --partial "Storage:"
}

# --- add ---------------------------------------------------------------------

@test "config mgmt-acl add: persists a CIDR to the permit list" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    assert_output --partial "10.0.0.0/8"
}

@test "config mgmt-acl add: accepts comma-separated list (canonical + sorted)" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add "192.168.5.5/24,10.0.0.0/8"
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    # Canonicalized (host bits zeroed) + emitted as sorted by write_mgmt_acl_cidrs.
    assert_output --partial "192.168.5.0/24"
    assert_output --partial "10.0.0.0/8"
    refute_output --partial "192.168.5.5/24"
}

@test "config mgmt-acl add: idempotent when CIDR already present" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8
    assert_success
    assert_output --partial "No new CIDRs"
}

@test "config mgmt-acl add: rejects invalid CIDR" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add not-a-cidr
    assert_failure
}

@test "config mgmt-acl add: rejects missing argument" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add
    assert_failure
    assert_output --partial "Usage:"
}

# --- remove ------------------------------------------------------------------

@test "config mgmt-acl remove: drops a CIDR from the permit list" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8,192.168.0.0/16 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl remove 10.0.0.0/8
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    refute_output --partial "10.0.0.0/8"
    assert_output --partial "192.168.0.0/16"
}

@test "config mgmt-acl remove: warns on not-present CIDR" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl remove 203.0.113.0/24
    # Exits 0 with a "nothing to remove" message.
    assert_success
    assert_output --partial "Nothing to remove"
}

@test "config mgmt-acl remove: warns when file doesn't exist yet" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl remove 10.0.0.0/8
    assert_success
    assert_output --partial "does not exist"
}

# --- clear -------------------------------------------------------------------

@test "config mgmt-acl clear: wipes entries after 'y' confirmation" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config mgmt-acl clear'
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    assert_output --partial "(empty)"
}

@test "config mgmt-acl clear: no-op when already empty" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl clear
    assert_success
    assert_output --partial "Already empty"
}

@test "config mgmt-acl clear: 'n' confirmation aborts" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run bash -c 'echo n | "'"$TACCTL_BIN_SCRIPT"'" config mgmt-acl clear'
    assert_success
    assert_output --partial "Aborted"

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl list
    assert_output --partial "10.0.0.0/8"
}

# --- cisco-name / juniper-name ----------------------------------------------

@test "config mgmt-acl cisco-name: shows default with no argument" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name
    assert_success
    assert_output --partial "VTY-ACL"
    assert_output --partial "default"
}

@test "config mgmt-acl cisco-name: sets an override" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name MY-VTY-ACL
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name
    assert_output --partial "MY-VTY-ACL"
    assert_output --partial "override"
}

@test "config mgmt-acl cisco-name: rejects invalid names" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name "1bad"
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name ""
    # Empty arg = show (not set). Expect success, not failure.
    assert_success
}

@test "config mgmt-acl juniper-name: sets an override" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl juniper-name CUSTOM-MGMT-ACL
    assert_success

    run "$TACCTL_BIN_SCRIPT" config mgmt-acl juniper-name
    assert_output --partial "CUSTOM-MGMT-ACL"
}

@test "config mgmt-acl cisco-name: no-op when set to current value" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name MY-ACL > /dev/null
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name MY-ACL
    assert_success
    assert_output --partial "no change"
}

# --- unknown subcommand ------------------------------------------------------

@test "config mgmt-acl: rejects unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl bogus
    assert_failure
    assert_output --partial "Unknown subcommand"
}
