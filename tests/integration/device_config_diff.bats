#!/usr/bin/env bats
# Integration tests for `tacctl device config diff`: the last pull against
# what tacctl renders now, per section, with --pull, --section, --json and
# --exit-code. The fake device is `tacctl _fake-device` of a test build.

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
    JCMD="${JDIR}/show configuration | display inheritance no-comments | display set.out"
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
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

@test "diff: a device that agrees is ok in every section, exit 0 even with --exit-code" {
    alice device config pull lab-j
    assert_success
    alice device config diff lab-j --exit-code
    assert_success
    assert_output --partial "Device lab-j (lab, juniper): pulled "
    assert_output --partial " by alice over netconf"
    assert_line --regexp '^  aaa +ok$'
    assert_line --regexp '^  roles +ok$'
    assert_output --partial "1 ok"
    refute_output --partial "differs"
}

@test "diff: a missing statement is '-', a stray one '+', --exit-code is 2, no secret value shown" {
    alice device config pull lab-j
    assert_success
    # Now the device loses its accounting and grows a server of its own.
    grep -v '^set system accounting destination' "$JCMD" > "${JCMD}.new"
    printf '%s\n' 'set system tacplus-server 192.0.2.99 secret "$9$STRAY-VALUE-123"' >> "${JCMD}.new"
    mv "${JCMD}.new" "$JCMD"
    alice device config diff lab-j --pull
    assert_success
    assert_output --partial "lab-j  ok, differs in aaa via netconf"
    assert_line --regexp '^  aaa +differs$'
    assert_line --regexp '^      - set system accounting destination tacplus$'
    assert_line --regexp '^      \+ set system tacplus-server 192.0.2.99 secret \(present, not compared\)$'
    refute_output --partial "STRAY-VALUE-123"
    alice device config diff lab-j --exit-code
    assert_failure 2
    alice device config diff lab-j --section roles --exit-code
    assert_success
    refute_output --partial "differs"
    alice device config diff lab-j --json
    assert_success
    refute_output --partial "STRAY-VALUE-123"
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())[0]
assert d["name"] == "lab-j" and d["status"] == "differs" and d["differs_in"] == ["aaa"], d
aaa = [s for s in d["sections"] if s["name"] == "aaa"][0]
ops = sorted((l["op"], l["text"]) for l in aaa["lines"] if l["op"] in "-+")
assert ops[0][0] == "+" and ops[1][0] == "-", ops
print("fine")' <<< "$output"
    assert_output "fine"
}

@test "diff: a device never pulled is not compared; the verb says how to read it" {
    alice device config diff lab-j
    assert_failure 1
    assert_output --partial "Device lab-j (lab, juniper): no configuration has been pulled"
    assert_output --partial "Read it with: tacctl device config pull lab-j"
    alice device config diff lab-j --pull
    assert_success
    assert_line --regexp '^  aaa +ok$'
}

@test "diff --pull: the exit status is the pull's, whatever the stored diffs say" {
    alice device config pull lab-j
    assert_success
    TACCTL_TEST_DEVICE_PASSWORD="not-the-password-77" alice device config diff lab-j --pull --exit-code
    assert_failure 1
    assert_output --partial "lab-j  failed: authentication failed"
    assert_output --partial "the pull failed (authentication failed); this is the last good pull"
    assert_line --regexp '^  aaa +ok$'
    assert_output --partial "1 failed"
    refute_output --partial "not-the-password-77"
    TACCTL_TEST_DEVICE_PASSWORD="not-the-password-77" alice device config diff lab-j --pull --json
    assert_failure 1
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())[0]
assert d["status"] == "failed" and "last good pull" in d["reason"] and d["sections"], d
print("fine")' <<< "$output"
    assert_output "fine"
}

@test "diff: usage, and options that need --pull" {
    alice device config diff
    assert_failure 2
    assert_output --partial "Name the devices to diff, or select them with --all, --scope <name>, --vendor <vendor> or --stale."
    alice device config diff lab-j --transport ssh
    assert_failure 2
    assert_output --partial "--transport is for --pull: the diff alone reads no device."
    alice device config diff lab-j --section bogus
    assert_failure 2
    assert_output --partial "--section takes sections of aaa, roles, mgmt-acl, snmp, netconf, breakglass: 'bogus'"
    alice device config diff nope
    assert_failure 1
    assert_output --partial "Device 'nope' not found."
}
