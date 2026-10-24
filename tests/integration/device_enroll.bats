#!/usr/bin/env bats
# Integration tests for `tacctl device enroll` (0.2.17 D261-D264, D269):
# per address, the one host key shown and accepted by typing the device's
# name, the vendor and name (asked here: SNMP is not set up), the
# registration at once, the pull as the invoking user, the device's own
# configured name, the plan. The device is the fake Junos device's blank
# configure model (tests/fixtures/devconf/fake/junos-blank: host name
# example-sw5); alice, a superuser of prod and lab, is accepted with the
# password of TACCTL_TEST_DEVICE_PASSWORD. The pieces are pinned by the Go
# tests (internal/cli/device_enroll_test.go); these pin the wiring: the
# terminal rules, the name typed on a real pty, the registry and known_hosts
# after a refusal mid-list, one snapshot for the run, the records and the
# audit lines.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

ADDR=192.168.1.31
ADDR2=192.168.1.32

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    unset FAKEDEV_USER FAKEDEV_PASSWORD FAKEDEV_PID
    JDIR=$(fakedev_dir junos-blank)
    : > "${JDIR}/echo.plain"
    fakedev_start "$JDIR"
    # ssh-keyscan offers the fake device's key at any address
    stub_cmd ssh-keyscan "echo \"\${!#} ${FAKEDEV_KEY}\""
    FP=$(ssh-keygen -lf - <<< "$FAKEDEV_KEY" | awk '{print $2}')
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//' <<< "$output")
    mapfile -t lines <<< "$output"
}

# enroll <args...>: as alice, with no terminal.
enroll() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device enroll "$@"
    plain
}

# tenroll <typed> <args...>: on a terminal, the lines of <typed> (a printf
# format) typed at it.
tenroll() {
    local typed="$1" cmd rc=0 a
    shift
    printf -v cmd '%q device enroll' "$TACCTL_BIN_SCRIPT"
    for a in "$@"; do printf -v cmd '%s %q' "$cmd" "$a"; done
    # shellcheck disable=SC2059
    printf "$typed" | SUDO_USER=alice script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/enroll.out" 2>&1 || rc=$?
    status=$rc
    output=$(sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/enroll.out")
    mapfile -t lines <<< "$output"
}

# record <name> <field>: a field of the device's pull record.
record() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
print(r.get(sys.argv[3], ""))' "${TACCTL_VAR_LIB}/devices-config.json" "$1" "$2"
}

snapshot_count() { find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | wc -l; }

@test "enroll: without a terminal it needs --host-key for one address; nothing is scanned" {
    enroll "$ADDR"
    assert_failure 2
    assert_output --partial "No terminal to answer the host-key question on"
    enroll "$ADDR" "$ADDR2" --host-key "$FP"
    assert_failure 2
    assert_output --partial "--host-key answers for ONE device"
    enroll "$ADDR" --vendor hp
    assert_failure 2
    run grep -F "ssh-keyscan" "$CALLS_LOG"
    assert_failure
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
}

@test "enroll --host-key: registered, pulled under the device's own name, planned; one snapshot" {
    before=$(snapshot_count)
    enroll "$ADDR" --host-key "$FP" --vendor juniper --name lab-sw5
    assert_success
    assert_output --partial "Device 'lab-sw5' registered: ${ADDR}, juniper."
    assert_output --partial "renamed lab-sw5 -> example-sw5 (the device's configured name"
    assert_output --partial "Host key pinned (it matches --host-key):"
    assert_output --partial "The plan above leaves each secret as a marked line; to paste it: tacctl device config plan <name>."
    assert_output --partial "The apply review needs a terminal; run: tacctl device config apply example-sw5"
    assert_output --regexp "${ADDR} +example-sw5 +juniper +flag +ok +differs +planned"
    grep -q "^  example-sw5:" "${TACCTL_STATE_DIR}/devices.yaml"
    ! grep -q "lab-sw5" "${TACCTL_STATE_DIR}/devices.yaml"
    [[ "$(record example-sw5 result)" == ok ]]
    [[ "$(snapshot_count)" -eq $((before + 1)) ]]
    stub_called "device enroll hostkey user=alice addr=${ADDR} device=lab-sw5 alg=ssh-ed25519 fp=${FP} result=accepted source=flag"
    stub_called "device rename from=lab-sw5 to=example-sw5 count=1 reason=device-name by=alice"
    stub_called "device enroll user=alice addr=${ADDR} device=example-sw5 vendor=juniper source=given result=planned"
    run grep -r -e "$FAKEDEV_PASSWORD" "$CALLS_LOG" "${TACCTL_VAR_LIB}" "${TACCTL_STATE_DIR}/devices.yaml"
    assert_failure
}

@test "enroll: the name typed on a terminal; a refusal mid-list leaves the first registered" {
    before=$(snapshot_count)
    tenroll 'pdu-a\nother\ny\nswitch\n' "$ADDR" "$ADDR2"
    [[ "$status" -eq 1 ]]
    assert_output --partial "Type the name to register it as to accept it, or press Enter to skip the device:"
    assert_output --partial "Vendor of ${ADDR} (cisco, juniper, wti or other; Enter skips the device):"
    assert_output --regexp "${ADDR} +pdu-a +other +accepted +- +- +registered-other"
    assert_output --partial "Host key pinned (the key you accepted):"
    assert_output --partial "${ADDR2}: refused: the name is a generic name"
    grep -q "^  pdu-a:" "${TACCTL_STATE_DIR}/devices.yaml"
    ! grep -q "$ADDR2" "${TACCTL_STATE_DIR}/devices.yaml"
    grep -qF "$(cut -d' ' -f2 <<< "$FAKEDEV_KEY")" "${TACCTL_VAR_LIB}/ssh/known_hosts"
    [[ "$(snapshot_count)" -eq $((before + 1)) ]]
    stub_called "device enroll hostkey user=alice addr=${ADDR2} device=- alg=ssh-ed25519 fp=${FP} result=refused source=confirmed"
    stub_called "device enroll user=alice addr=${ADDR} device=pdu-a vendor=other source=asked result=registered-other"
}
