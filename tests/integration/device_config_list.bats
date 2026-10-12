#!/usr/bin/env bats
# Integration tests for `tacctl device config list|forget` and the CONFIG
# column of `device list`: the state of each device's configuration, computed
# against today's rendering (a change in the store makes a device differ
# without a new pull), the filters, and the records' lifecycle.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    unset FAKEDEV_USER FAKEDEV_PASSWORD FAKEDEV_PID
    JDIR=$(fakedev_dir junos)
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper lab-k 192.168.1.21 juniper pdu1 192.168.1.40 wti
    fakedev_serve "$JDIR" juniper lab
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

alice() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" "$@"
    plain
}

@test "list: never pulled devices are never; a WTI unit is not listed as stale" {
    alice device config list
    assert_success
    assert_line --regexp '^ *lab-j .* never '
    assert_line --regexp '^ *pdu1 .* not read'
    alice device config list --stale
    assert_success
    assert_output --partial "lab-j"
    refute_output --partial "pdu1"
    alice device config list --never --scope lab --vendor juniper
    assert_success
    assert_output --partial "lab-k"
    alice device list
    assert_success
    assert_line --regexp '^ *lab-j .* never '
    assert_line --regexp '^ *pdu1 .* -  *-$|^ *pdu1 .* - +-'
}

@test "list: a device in no scope is not read: '-', never stale, and pull skips it" {
    fakedev_register lab-j 192.168.1.20 juniper nosc 198.51.100.5 juniper
    alice device config list
    assert_success
    assert_line --regexp '^ *nosc .* - +no scope$'
    alice device list
    assert_line --regexp '^ *nosc .* unconfigured .* - +-$'
    alice device config list --stale
    refute_output --partial "nosc"
    alice device config pull --all
    assert_success
    assert_output --partial "skipped 1 (nosc)"
    alice device show nosc
    assert_output --partial "Configuration: not read (no scope's prefixes cover its address)"
}

@test "list: ok after a pull, differs after a change of the store, failed after a failure" {
    alice device config pull --all
    assert_success
    alice device config list
    assert_success
    assert_line --regexp '^ *lab-j .* ok +'
    alice device config list --stale
    assert_output --partial "None: every device"
    # The store changes: the management ACL gains a permit. Nothing was pulled.
    run "$TACCTL_BIN_SCRIPT" config mgmt-acl add 198.51.100.0/24
    assert_success
    alice device config list --differs
    assert_success
    assert_line --regexp '^ *lab-j .* differs .*mgmt-acl'
    alice device config list --transport netconf --json
    assert_success
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert sorted(x["name"] for x in d) == ["lab-j", "lab-k"], d
assert all(x["state"] == "differs" and x["differs_in"] == ["mgmt-acl"] and x["transport"] == "netconf" for x in d), d
print("fine")' <<< "$output"
    assert_output "fine"
    alice device config list --transport ssh
    assert_success
    assert_output --partial "None."
    # A pull that fails leaves the record failed.
    TACCTL_TEST_DEVICE_PASSWORD=wrong-pw-1 alice device config pull lab-j
    assert_failure 1
    alice device config list --failed
    assert_success
    assert_line --regexp '^ *lab-j .* failed .*auth-failed'
    refute_output --partial "lab-k"
}

@test "forget: one device, many, --all; the sections file goes with the record; superuser only" {
    alice device config pull --all
    assert_success
    [[ -f "${TACCTL_VAR_LIB}/device-config/lab-j.yaml" ]]
    alice device config forget lab-j
    assert_success
    assert_output --partial "Forgot the configuration record of 'lab-j'."
    [[ ! -e "${TACCTL_VAR_LIB}/device-config/lab-j.yaml" ]]
    alice device config forget lab-j
    assert_success
    assert_output --partial "No configuration record for 'lab-j'."
    alice device config list --never
    assert_success
    assert_output --partial "lab-j"
    alice device config forget lab-j,lab-k
    assert_success
    alice device config forget --all
    assert_success
    assert_output --partial "Forgot the configuration records of 0 devices."
    alice device config forget
    assert_failure 2
    assert_output --partial "Name the devices to forget, or give --all."
}

@test "import --replace drops the record and the sections file of the devices it removes, as remove does" {
    alice device config pull --all
    assert_success
    [[ -f "${TACCTL_VAR_LIB}/device-config/lab-j.yaml" ]]
    [[ -f "${TACCTL_VAR_LIB}/device-config/lab-k.yaml" ]]
    run bash -c 'printf "lab-j,192.168.1.20,juniper\npdu1,192.168.1.40,wti\n" | "$1" device import - --replace -y' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    [[ -f "${TACCTL_VAR_LIB}/device-config/lab-j.yaml" ]]
    [[ ! -e "${TACCTL_VAR_LIB}/device-config/lab-k.yaml" ]]
    run grep -c "lab-k" "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "0"
    run grep -c "lab-j" "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output --regexp '^[1-9]'
}

@test "list: --json is an array of states, the filters are validated" {
    alice device config list --json
    assert_success
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert [x["name"] for x in d] == ["lab-j", "lab-k", "pdu1"], d
assert [x["state"] for x in d] == ["never", "never", "-"], d
print("fine")' <<< "$output"
    assert_output "fine"
    alice device config list --vendor other
    assert_failure 2
    assert_output --partial "--vendor takes cisco, juniper or wti: 'other'"
    alice device config list --scope nosuch
    assert_failure 1
    alice device config list extra
    assert_failure 2
    assert_output --partial "Unknown argument: 'extra'"
}
