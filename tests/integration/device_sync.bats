#!/usr/bin/env bats
# Integration tests for `tacctl device sync` (plan D137): the registry's
# empty hostname, location and description filled from a device's last pull
# record, preview first, one registry write with --apply, what a device
# reports checked. The record is made by `device collect --register` against
# the fake Junos device (tests/fixtures/devconf/fake/junos-blank: host name
# example-sw5, domain lab.example.net, snmp location "Lab rack 5", no
# description). sync logs in to nothing, so the fake device is stopped after
# the seed. A reported host name is filled only when it resolves to the
# registered address and no other; TACCTL_TEST_RESOLVE is the fake resolver.
# The pieces are pinned by the Go tests (internal/cli/
# device_sync_test.go); these pin the wiring.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

ADDR=192.168.1.31

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    unset FAKEDEV_USER FAKEDEV_PASSWORD FAKEDEV_PID
    export TACCTL_TEST_RESOLVE="example-sw5.lab.example.net=${ADDR}"
    JDIR=$(fakedev_dir junos-blank)
    : > "${JDIR}/echo.plain"
    fakedev_start "$JDIR"
    stub_cmd ssh-keyscan "echo \"\${!#} ${FAKEDEV_KEY}\""
    FP=$(ssh-keygen -lf - <<< "$FAKEDEV_KEY" | awk '{print $2}')
    # the registered device and its record: a collect as alice
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device collect "$ADDR" --host-key "$FP" --register -y > /dev/null 2>&1
    fakedev_stop
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//' <<< "$output")
    mapfile -t lines <<< "$output"
}

# sync <args...>: as alice, with no terminal.
sync() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device sync "$@"
    plain
}

# tsync <typed> <args...>: on a terminal, the lines of <typed> typed at it.
tsync() {
    local typed="$1" cmd rc=0 a
    shift
    printf -v cmd '%q device sync' "$TACCTL_BIN_SCRIPT"
    for a in "$@"; do printf -v cmd '%s %q' "$cmd" "$a"; done
    # shellcheck disable=SC2059
    printf "$typed" | SUDO_USER=alice script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/sync.out" 2>&1 || rc=$?
    status=$rc
    output=$(sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/sync.out")
    mapfile -t lines <<< "$output"
}

# field <name> <field>: a field of the device in the registry file.
field() {
    python3 - "${TACCTL_STATE_DIR}/devices.yaml" "$1" "$2" << 'EOF'
import sys
want, key, in_dev = sys.argv[2], sys.argv[3], False
for l in open(sys.argv[1]):
    if l.startswith("  " + want + ":"):
        in_dev = True
    elif in_dev and l.startswith("    " + key + ":"):
        print(l.split(":", 1)[1].strip().strip('"'))
        break
    elif in_dev and l.startswith("  ") and not l.startswith("    "):
        break
EOF
}

@test "sync: only a superuser" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" device sync example-sw5
    assert_failure
    plain
    assert_output --partial "'tacctl device sync' is not permitted for the operator tier."
}

@test "sync: the preview writes nothing and logs in to nothing" {
    [[ -z "$(field example-sw5 location)" ]]
    sync example-sw5
    assert_success
    assert_output --regexp "example-sw5 +hostname +- +example-sw5\.lab\.example\.net +fill"
    assert_output --regexp "example-sw5 +location +- +Lab rack 5 +fill"
    assert_output --regexp "example-sw5 +description +- +- +none"
    assert_output --partial "ex4300-48mp"
    assert_output --partial "2 field(s) on 1 device(s) would be written. Write them with --apply."
    [[ -z "$(field example-sw5 location)" ]]
    [[ -z "$(field example-sw5 hostname)" ]]
}

@test "sync --apply: without a terminal it needs -y; with it one write, audited" {
    sync example-sw5 --apply
    assert_failure 2
    assert_output --partial "without one needs -y"
    [[ -z "$(field example-sw5 location)" ]]
    sync example-sw5 --apply -y
    assert_success
    assert_output --partial "Wrote 2 field(s) on 1 device(s)."
    [[ "$(field example-sw5 location)" == "Lab rack 5" ]]
    [[ "$(field example-sw5 hostname)" == "example-sw5.lab.example.net" ]]
    [[ "$(field example-sw5 address)" == "$ADDR" ]]
    [[ "$(field example-sw5 vendor)" == juniper ]]
    stub_called "logger -t tacctl -p auth.info device sync user=alice devices=1 fields=2"
    sync example-sw5 --apply -y
    assert_success
    assert_output --partial "Nothing to fill"
}

@test "sync: the question at a terminal; declined writes nothing" {
    tsync 'n\n' example-sw5 --apply
    [[ "$status" -eq 0 ]]
    assert_output --partial "Write 2 field(s) on 1 device(s) of the registry? [y/N]"
    assert_output --partial "Aborted; nothing was written."
    [[ -z "$(field example-sw5 location)" ]]
    tsync 'y\n' example-sw5 --apply
    [[ "$status" -eq 0 ]]
    [[ "$(field example-sw5 location)" == "Lab rack 5" ]]
}

@test "sync: a set field is kept, --overwrite replaces it and shows the old value" {
    "$TACCTL_BIN_SCRIPT" device location example-sw5 "Old rack" > /dev/null
    sync example-sw5 --apply -y
    assert_success
    assert_output --regexp "example-sw5 +location +Old rack +Lab rack 5 +keep"
    [[ "$(field example-sw5 location)" == "Old rack" ]]
    sync example-sw5 --overwrite
    assert_output --regexp "example-sw5 +location +Old rack +Lab rack 5 +replace"
    [[ "$(field example-sw5 location)" == "Old rack" ]]
    sync example-sw5 --overwrite --apply -y
    assert_success
    [[ "$(field example-sw5 location)" == "Lab rack 5" ]]
}

@test "sync: a host name that does not resolve to the address and only it is not filled" {
    local bad
    for bad in "other.example.net=192.168.1.99" "example-sw5.lab.example.net=${ADDR},192.168.1.99" \
        "example-sw5.lab.example.net=192.168.1.99"; do
        TACCTL_TEST_RESOLVE="$bad" sync example-sw5 --apply -y
        assert_success
        assert_output --regexp "example-sw5 +hostname +- +example-sw5\.lab\.example\.net +refused: does not resolve: not filled"
        [[ -z "$(field example-sw5 hostname)" ]]
    done
    # a resolving name, then a set hostname that --overwrite does not replace with an unresolved one
    sync example-sw5
    assert_output --regexp "example-sw5 +hostname +- +example-sw5\.lab\.example\.net +fill: resolves to the address"
    "$TACCTL_BIN_SCRIPT" device hostname example-sw5 old.example.net > /dev/null
    TACCTL_TEST_RESOLVE="old.example.net=${ADDR}" sync example-sw5 --overwrite --apply -y
    assert_success
    assert_output --partial "does not resolve: not filled"
    [[ "$(field example-sw5 hostname)" == old.example.net ]]
    sync example-sw5 --overwrite --apply -y
    [[ "$(field example-sw5 hostname)" == example-sw5.lab.example.net ]]
}

@test "sync: what a device reports is checked: a value the registry would not accept is refused" {
    # a device that says hostile things of itself, collected afresh
    "$TACCTL_BIN_SCRIPT" device remove example-sw5 -y > /dev/null
    rm -f "${TACCTL_VAR_LIB}/devices-config.json"
    sed -i '/^set snmp location/d' "${JDIR}/config.set"
    printf 'set snmp location "%s"\nset snmp description "%s"\n' "$(printf 'l%.0s' $(seq 1 130))" "$(printf 'd%.0s' $(seq 1 200))" >> "${JDIR}/config.set"
    fakedev_start "$JDIR"
    stub_cmd ssh-keyscan "echo \"\${!#} ${FAKEDEV_KEY}\""
    FP=$(ssh-keygen -lf - <<< "$FAKEDEV_KEY" | awk '{print $2}')
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device collect "$ADDR" --host-key "$FP" --register -y > /dev/null 2>&1
    fakedev_stop
    sync example-sw5 --apply -y
    assert_success
    assert_output --regexp "example-sw5  location +- +l+\.\.\. +refused: The location is limited to 120 characters"
    assert_output --regexp "example-sw5  description +- +d+\.\.\. +refused: The description is limited to 120 characters"
    # the host name, which is fine, is still filled
    [[ "$(field example-sw5 hostname)" == "example-sw5.lab.example.net" ]]
    [[ -z "$(field example-sw5 location)" ]]
    [[ -z "$(field example-sw5 description)" ]]
}

@test "sync --json, a device with no record, the selectors" {
    "$TACCTL_BIN_SCRIPT" device add bare-sw 192.168.1.32 --vendor juniper --no-lookup --no-host-key > /dev/null
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device sync --all --json > "${BATS_TEST_TMPDIR}/sync.json"
    run python3 -c '
import json, sys
o = json.load(open(sys.argv[1]))
by = {d["name"]: d for d in o["devices"]}
assert o["apply"] is False and o["fields"] == 2, o
assert "no pull record" in by["bare-sw"]["skipped"], by
assert [f["action"] for f in by["example-sw5"]["fields"]] == ["fill", "fill", "none"], by
' "${BATS_TEST_TMPDIR}/sync.json"
    assert_success
    sync
    assert_failure 2
    assert_output --partial "Name the devices to sync"
    sync example-sw5 --all
    assert_failure 2
    assert_output --partial "not both"
    sync no-such-device
    assert_failure 1
    assert_output --partial "not found"
}
