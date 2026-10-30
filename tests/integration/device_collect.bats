#!/usr/bin/env bats
# Integration tests for `tacctl device collect` (plan D137): an address
# nobody registered is logged in to once (the invoking user's own login, or
# a local account of the device), read with `show version` and the pull's
# read command, shown in one table and, with --register, registered through
# `device add` with its first pull record. The device is the fake Junos
# device's blank configure model (tests/fixtures/devconf/fake/junos-blank:
# a local account 'admin', host name example-sw5, domain lab.example.net,
# snmp location "Lab rack 5"); alice, a superuser of prod and lab, is
# accepted with the password of TACCTL_TEST_DEVICE_PASSWORD. The pieces are
# pinned by the Go tests (internal/cli/device_collect_test.go); these pin the
# wiring: the questions, the terminal rules, the registry, the records, the
# audit lines.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

ADDR=192.168.1.31
LOCAL_PW=local-fakedev-pw

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

# collect <args...>: as alice, with no terminal.
collect() {
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD="$LOCAL_PW" run "$TACCTL_BIN_SCRIPT" device collect "$@"
    plain
}

# tcollect <typed> <args...>: on a terminal, the lines of <typed> (a printf
# format) typed at it.
tcollect() {
    local typed="$1" cmd rc=0 a
    shift
    printf -v cmd 'TACCTL_TEST_LOCAL_PASSWORD=%q %q device collect' "$LOCAL_PW" "$TACCTL_BIN_SCRIPT"
    for a in "$@"; do printf -v cmd '%s %q' "$cmd" "$a"; done
    # shellcheck disable=SC2059
    printf "$typed" | SUDO_USER=alice script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/collect.out" 2>&1 || rc=$?
    status=$rc
    output=$(sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/collect.out")
    mapfile -t lines <<< "$output"
}

# record <name> <field>: a field of the device's pull record.
record() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
print(r.get(sys.argv[3], ""))' "${TACCTL_VAR_LIB}/devices-config.json" "$1" "$2"
}

# unregistered: nothing of the address is in the registry.
unregistered() {
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
}

# nothing_secret: no password in what tacctl keeps or logs.
nothing_secret() {
    run grep -r -e "$LOCAL_PW" -e "$FAKEDEV_PASSWORD" "$CALLS_LOG" "${TACCTL_VAR_LIB}" "${TACCTL_STATE_DIR}/devices.yaml"
    assert_failure
}

@test "collect: engineers and above; an operator is refused before anything is scanned or sent" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" device collect "$ADDR" --host-key "$FP"
    assert_failure
    plain
    assert_output --partial "'tacctl device collect' is not permitted for the operator tier."
    run grep -F "ssh-keyscan" "$CALLS_LOG"
    assert_failure
    unregistered
}

@test "collect: without a terminal it needs --host-key, one address, and --yes for --register" {
    collect "$ADDR"
    assert_failure 2
    assert_output --partial "No terminal to answer the host-key question on"
    collect "$ADDR" 192.168.1.32 --host-key "$FP"
    assert_failure 2
    assert_output --partial "--host-key names the key of ONE device"
    collect "$ADDR" --host-key "$FP" --register
    assert_failure 2
    assert_output --partial "--register without one needs --yes"
    collect --host-key "$FP"
    assert_failure 2
    assert_output --partial "Name the addresses to collect from"
    collect "$ADDR" --host-key SHA256:nope
    assert_failure 2
    assert_output --partial "Invalid --host-key"
    # nothing was scanned, registered or sent
    run grep -F "ssh-keyscan" "$CALLS_LOG"
    assert_failure
    unregistered
}

@test "collect: an unregistered address is collected into one table and nothing is kept" {
    collect "$ADDR" --host-key "$FP"
    assert_success
    assert_output --partial "${ADDR} offers:"
    assert_output --partial "$FP matches --host-key."
    assert_output --regexp "ADDRESS +HOSTNAME +MODEL +RELEASE +AUTH-ORDER +SERVERS +EN-CLASS +NETCONF +LO0-FILTER +LEGACY +RESULT"
    assert_output --regexp "${ADDR} +example-sw5 +ex4300-48mp +25\.4R1-S2\.3 +- +- +- +- +- +- +collected"
    assert_output --partial "tacctl device add example-sw5 ${ADDR} --vendor juniper"
    unregistered
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]] || [[ -z "$(record example-sw5 result)" ]]
    stub_called "logger -t tacctl -p auth.info device collect user=alice addr=${ADDR} login=own result=collected"
    grep -qF "logger -t tacctl -p auth.notice device collect hostkey user=alice addr=${ADDR} device=- alg=" "$CALLS_LOG"
    grep -qF "fp=${FP} result=accepted source=flag sid=" "$CALLS_LOG"
    nothing_secret
}

@test "collect --json: one object, the progress on standard error" {
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device collect "$ADDR" --host-key "$FP" --json 2> "${BATS_TEST_TMPDIR}/collect.err" > "${BATS_TEST_TMPDIR}/collect.json"
    grep -q "offers:" "${BATS_TEST_TMPDIR}/collect.err"
    output=$(cat "${BATS_TEST_TMPDIR}/collect.json")
    run python3 -c '
import json, sys
o = json.loads(sys.argv[1])
d = o["devices"][0]
assert o["login"] == "own" and o["exit"] == 0
assert d["address"] == sys.argv[2] and d["result"] == "collected" and d["hostname"] == "example-sw5", d
assert d["add"].startswith("tacctl device add example-sw5 "), d
' "$output" "$ADDR"
    assert_success
}

@test "collect --register --yes: registered through device add, the key pinned, the first record kept" {
    collect "$ADDR" --host-key "$FP" --register --yes
    assert_success
    assert_output --partial "Device 'example-sw5' registered: ${ADDR}, juniper."
    assert_output --partial "the read is kept as its first pull record"
    grep -qF "$(cut -d' ' -f2 <<< "$FAKEDEV_KEY")" "${TACCTL_STATE_DIR}/devices.yaml"
    [[ "$(record example-sw5 result)" == ok ]]
    [[ "$(record example-sw5 by)" == alice ]]
    [[ "$(record example-sw5 login)" == "" ]]
    [[ "$(record example-sw5 user_pulled)" == True ]]
    [[ "$(record example-sw5 model)" == ex4300-48mp ]]
    [[ "$(record example-sw5 release)" == 25.4R1-S2.3 ]]
    [[ "$(record example-sw5 hostname)" == example-sw5.lab.example.net ]]
    stub_called "device collect user=alice addr=${ADDR} login=own result=registered device=example-sw5"
    # the address is the normal flow's now: refused, nothing sent
    collect "$ADDR" --host-key "$FP"
    assert_failure 1
    assert_output --partial "${ADDR} is registered as 'example-sw5'"
    nothing_secret
}

@test "collect --login: the key accepted by the address typed; a local account's one-shot password; the record says local" {
    tcollect "${ADDR}\ny\n" "$ADDR" --login admin --register
    [[ "$status" -eq 0 ]]
    assert_output --partial "Will pin:  "
    assert_output --partial "Compare the key with the console of ${ADDR}. Type the address (${ADDR}) to accept it and send it the local password of 'admin', or press Enter to skip the address:"
    assert_output --partial "Register 1 device(s), pinning the host key accepted for each: example-sw5 (${ADDR})? [y/N]"
    assert_output --partial "Device 'example-sw5' registered: ${ADDR}, juniper."
    assert_output --partial "Host key pinned (the key you accepted):"
    grep -qF "device collect hostkey user=alice addr=${ADDR} device=- alg=" "$CALLS_LOG"
    grep -qF "fp=${FP} result=accepted source=confirmed sid=" "$CALLS_LOG"
    # the acceptance's line is written before the registration's
    [[ $(grep -nF "device collect hostkey " "$CALLS_LOG" | head -1 | cut -d: -f1) -lt $(grep -nF "device add name=example-sw5 " "$CALLS_LOG" | head -1 | cut -d: -f1) ]]
    [[ "$(record example-sw5 login)" == local:admin ]]
    [[ "$(record example-sw5 user_pulled)" == "" || "$(record example-sw5 user_pulled)" == False ]]
    stub_called "device collect user=alice addr=${ADDR} login=local:admin result=registered device=example-sw5"
    nothing_secret
}

@test "collect: Enter or a wrong answer at the key's question sends nothing" {
    tcollect '\n' "$ADDR"
    [[ "$status" -eq 1 ]]
    assert_output --regexp "${ADDR} +- +- +- +- +- +- +- +- +- +skipped"
    assert_output --partial "${ADDR}: not accepted; nothing was sent"
    grep -qF "device collect hostkey user=alice addr=${ADDR} device=- alg=" "$CALLS_LOG"
    grep -qF "result=skipped source=confirmed" "$CALLS_LOG"
    tcollect 'y\n' "$ADDR"
    [[ "$status" -eq 1 ]]
    assert_output --regexp "${ADDR} +- +- +- +- +- +- +- +- +- +refused"
    assert_output --partial "${ADDR}: the answer typed is not the device's address; nothing was sent"
    grep -qF "result=refused source=confirmed" "$CALLS_LOG"
    unregistered
    nothing_secret
}

@test "collect: a refused password is the one attempt and nothing is registered" {
    TACCTL_TEST_DEVICE_PASSWORD=wrong-password collect "$ADDR" --host-key "$FP" --register --yes
    assert_failure 1
    assert_output --regexp "${ADDR} +- +- +- +- +- +- +- +- +- +auth-failed"
    assert_output --partial "the device refused the password"
    unregistered
    stub_called "device collect user=alice addr=${ADDR} login=own result=auth-failed"
}

@test "collect: a key that is not the one trusted is refused at the login" {
    ssh-keygen -q -t ed25519 -N '' -f "${BATS_TEST_TMPDIR}/other"
    OTHER=$(cut -d' ' -f1,2 "${BATS_TEST_TMPDIR}/other.pub")
    stub_cmd ssh-keyscan "echo \"\${!#} ${OTHER}\""
    OFP=$(ssh-keygen -lf "${BATS_TEST_TMPDIR}/other.pub" | awk '{print $2}')
    collect "$ADDR" --host-key "$OFP" --register --yes
    assert_failure 1
    assert_output --partial "it presented a host key that is not the trusted one"
    unregistered
    # a --host-key that the address does not offer sends nothing
    collect "$ADDR" --host-key "$FP"
    assert_failure 1
    assert_output --partial "No host key ${ADDR} offers matches"
}

@test "collect: a registered address, an address no scope answers and a held address are refused before anything is sent" {
    "$TACCTL_BIN_SCRIPT" device add known-sw 192.168.1.40 --vendor juniper --no-lookup --host-key "$FP"
    collect 192.168.1.40 --host-key "$FP"
    assert_failure 1
    assert_output --partial "192.168.1.40 is registered as 'known-sw'"
    collect 198.51.100.9 --host-key "$FP"
    assert_failure 1
    assert_output --partial "No scope answers 198.51.100.9"
    printf 'breakglass_hold:\n  held-sw:\n    address: %s\n    since: "2026-10-13T00:00:00Z"\n    by: alice\n    reason: console recovery\n' "$ADDR" > "${TACCTL_STATE_DIR}/tacctl.yaml"
    collect "$ADDR" --host-key "$FP"
    assert_failure 1
    assert_output --partial "break-glass is held on held-sw"
    unregistered
}

@test "collect: a host that is not Junos is listed and never registered" {
    fakedev_stop
    IDIR=$(fakedev_dir ios)
    fakedev_start "$IDIR"
    stub_cmd ssh-keyscan "echo \"\${!#} ${FAKEDEV_KEY}\""
    FP=$(ssh-keygen -lf - <<< "$FAKEDEV_KEY" | awk '{print $2}')
    collect "$ADDR" --host-key "$FP" --register --yes
    assert_failure 1
    assert_output --regexp "${ADDR} +- +- +- +- +- +- +- +- +- +not-junos"
    assert_output --partial "not a Junos device"
    assert_output --partial "Nothing to register."
    unregistered
}

@test "collect --discovered: the unregistered addresses that authenticated, from the seen cache" {
    mkdir -p "${TACCTL_VAR_LIB}"
    printf '{"version":1,"sources":{},"hostkeys":{},"addresses":{"%s":{"tacacs":{"first":"2026-10-01T00:00:00Z","last":"2026-10-02T00:00:00Z","count":3,"last_user":"alice","last_outcome":"pass","last_ok":"2026-10-02T00:00:00Z"}}}}' "$ADDR" > "${TACCTL_VAR_LIB}/devices-seen.json"
    chmod 600 "${TACCTL_VAR_LIB}/devices-seen.json"
    collect --discovered
    assert_failure 2
    assert_output --partial "No terminal to answer the host-key question on"
    tcollect "${ADDR}\n" --discovered
    [[ "$status" -eq 0 ]]
    assert_output --regexp "${ADDR} +example-sw5 +ex4300-48mp"
    unregistered
}
