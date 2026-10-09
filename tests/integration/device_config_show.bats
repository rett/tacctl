#!/usr/bin/env bats
# Integration tests for `tacctl device config show <name>`: the device's data,
# then the walkthrough `tacctl config <vendor> --scope <scope> --name <name>`
# prints. The walkthrough is pinned by config_templates.bats and the goldens;
# these pin the wiring and the refusals.

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
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
}

# plain: the last output (and its lines) with colours stripped.
plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# prod is 10.0.0.0/8 in the multiscope fixture.
@test "device config show: the data block, then exactly the walkthrough config <vendor> prints" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key \
        --snmp-location "Site A, rack 4" --description "core switch" > /dev/null
    run "$TACCTL_BIN_SCRIPT" device config show core-sw1
    assert_success
    plain
    local shown="$output"
    assert_line "Device core-sw1"
    assert_line "  Name:         core-sw1"
    assert_line "  Address:      10.99.0.1"
    assert_line "  Vendor:       cisco"
    assert_line --regexp "^  Scope:        prod  \(via prefix 10\.0\.0\.0/8\)$"
    assert_line "  Description:  core switch"
    assert_line "  Location:     Site A, rack 4"
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod --name core-sw1
    assert_success
    plain
    # The walkthrough is the tail of the output, byte for byte.
    [[ "$shown" == *"$output" ]]
    [[ ${#shown} -gt ${#output} ]]
}

@test "device config show: juniper and wti devices, and the options of config <vendor>" {
    "$TACCTL_BIN_SCRIPT" device add jun1 10.99.0.2 --vendor juniper --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add pdu1 10.99.0.3 --vendor wti --no-host-key > /dev/null
    run "$TACCTL_BIN_SCRIPT" device config show jun1 --protocol tacacs --server 192.0.2.77
    assert_success
    plain
    assert_output --partial "Device jun1"
    assert_output --partial "Juniper Junos Configuration  (scope: prod"
    assert_output --partial "192.0.2.77"
    run "$TACCTL_BIN_SCRIPT" device config show pdu1
    assert_success
    plain
    assert_output --partial "WTI Console Server Configuration  (scope: prod"
    run "$TACCTL_BIN_SCRIPT" device config show jun1 --legacy
    assert_failure 1
    plain
    assert_output --partial "--legacy (IOS 12.x syntax) applies to Cisco devices; 'jun1' is a juniper device."
    refute_output --partial "Device jun1"
}

@test "device config show: refusals say what to run" {
    "$TACCTL_BIN_SCRIPT" device add sw-o 10.99.0.4 --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw-x 198.51.100.5 --vendor cisco --no-host-key > /dev/null
    run "$TACCTL_BIN_SCRIPT" device config show sw-o
    assert_failure 1
    plain
    assert_output --partial "Device 'sw-o' has vendor 'other', and only cisco, juniper and wti have a walkthrough."
    assert_output --partial "Set the vendor with: tacctl device vendor sw-o cisco|juniper|wti"
    run "$TACCTL_BIN_SCRIPT" device config show sw-x
    assert_failure 1
    plain
    assert_output --partial "Device 'sw-x' (198.51.100.5) is in no scope: no scope's prefixes cover its address."
    assert_output --partial "Add them with: tacctl scope prefixes <scope> add <cidr>"
    run "$TACCTL_BIN_SCRIPT" device config show nope
    assert_failure 1
    assert_output --partial "Device 'nope' not found."
    run "$TACCTL_BIN_SCRIPT" device config show
    assert_failure 1
    assert_output --partial "Usage: tacctl device config show <name>"
}

@test "device config: alone it prints the usage; an unknown subcommand is an error" {
    run "$TACCTL_BIN_SCRIPT" device config
    assert_success
    plain
    assert_output --partial "Usage: tacctl device config <subcommand> [arguments]"
    assert_output --partial "show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>] [--source <address>]"
    refute_output --partial "pull"
    refute_output --partial "apply"
    run "$TACCTL_BIN_SCRIPT" device config frob
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frob'"
}
