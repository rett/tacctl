#!/usr/bin/env bats
# Integration tests for `tacctl device onboard` (plan D136): a blank Junos
# device (the fake device's configure model, tests/fixtures/devconf/fake/
# junos-blank: a local account 'admin' and a root login, no TACACS+ server)
# identified, registered, read and checked as the local account, then
# committed as it and proven by the invoking user's own login. The pieces are
# pinned by the Go tests (internal/cli/device_onboard_test.go); these pin the
# wiring: the questions, the terminal rules, the records, the audit lines.

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

# onboard <args...>: as alice, a superuser of prod and lab, with no terminal
# and the local account's password from the test knob.
onboard() {
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD="$LOCAL_PW" run "$TACCTL_BIN_SCRIPT" device onboard "$@"
    plain
}

# tonboard <typed> <args...>: on a terminal, the lines of <typed> (a printf
# format) typed at it.
tonboard() {
    local typed="$1" cmd rc=0 a
    shift
    printf -v cmd 'TACCTL_TEST_LOCAL_PASSWORD=%q %q device onboard' "$LOCAL_PW" "$TACCTL_BIN_SCRIPT"
    for a in "$@"; do printf -v cmd '%s %q' "$cmd" "$a"; done
    # shellcheck disable=SC2059
    printf "$typed" | SUDO_USER=alice script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/onboard.out" 2>&1 || rc=$?
    status=$rc
    output=$(sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/onboard.out")
    mapfile -t lines <<< "$output"
}

# committed: the configuration the device runs.
committed() {
    if [[ -f "${JDIR}/committed.set" ]]; then cat "${JDIR}/committed.set"; else cat "${JDIR}/config.set"; fi
}

# unchanged: the device runs no TACACS+ server and its local account and
# root are as they were.
unchanged() {
    run committed
    refute_output --partial "tacplus-server"
    assert_output --partial "set system login user admin authentication encrypted-password"
    assert_output --partial "set system root-authentication encrypted-password"
}

# record <name> <field>: a field of the device's pull record.
record() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
v = r.get(sys.argv[3], "")
if sys.argv[3].startswith("applied."):
    v = (r.get("applied") or {}).get(sys.argv[3][8:], "")
print(v)' "${TACCTL_VAR_LIB}/devices-config.json" "$1" "$2"
}

# nothing_secret: no password in what tacctl keeps or logs.
nothing_secret() {
    run grep -r -e "$LOCAL_PW" -e "$FAKEDEV_PASSWORD" "$CALLS_LOG" "${TACCTL_VAR_LIB}" "${TACCTL_STATE_DIR}/devices.yaml"
    assert_failure
}

@test "onboard: only a superuser, before anything is scanned or sent" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" device onboard "$ADDR" --login admin --host-key "$FP" --check
    assert_failure
    plain
    assert_output --partial "'tacctl device onboard' is not permitted for the operator tier."
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    onboard "$ADDR" --login admin --host-key "$FP" --check
    assert_failure
    assert_output --partial "not permitted for the engineer tier"
    run grep -F "ssh-keyscan" "$CALLS_LOG"
    assert_failure
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
}

@test "onboard: without a terminal it needs --host-key, and then only --check" {
    onboard "$ADDR" --login admin
    assert_failure 2
    assert_output --partial "No terminal to answer the identity question on"
    onboard "$ADDR" --login admin --host-key "$FP"
    assert_failure 2
    assert_output --partial "No terminal to review the change on"
    onboard "$ADDR"
    assert_failure 2
    assert_output --partial "--login <local-user>"
    onboard "$ADDR" --login admin --host-key SHA256:nope --check
    assert_failure 2
    assert_output --partial "Invalid --host-key"
    # nothing was scanned, registered or sent
    run grep -F "ssh-keyscan" "$CALLS_LOG"
    assert_failure
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
}

@test "onboard --host-key --check: registered, read as the local account, nothing committed" {
    onboard "$ADDR" --login admin --host-key "$FP" --check
    assert_success
    assert_output --partial "$FP matches --host-key."
    refute_output --partial "Trust these keys"
    assert_output --partial "${ADDR}  Junos 25.4R1-S2.3"
    assert_output --partial "device reports host name example-sw5; no TACACS+ or RADIUS server"
    assert_output --partial "Device 'example-sw5' registered: ${ADDR}, juniper."
    assert_output --partial 'From the device: location "Lab rack 5"'
    # the registry's hostname is never the device's (ssh would dial it)
    refute_output --partial 'hostname "'
    if grep -qF "hostname:" "${TACCTL_STATE_DIR}/devices.yaml"; then false; fi
    assert_output --partial "example-sw5  read as local:admin:"
    assert_output --regexp "example-sw5  checked: shape [0-9a-f]{12} \(new\)"
    assert_output --partial "nothing was committed: --check ends after the device's own commit check."
    unchanged
    [[ "$(record example-sw5 login)" == local:admin ]]
    [[ "$(record example-sw5 by)" == alice ]]
    [[ "$(record example-sw5 applied.result)" == checked ]]
    # the key shown is the key pinned
    grep -qF "$(cut -d' ' -f2 <<< "$FAKEDEV_KEY")" "${TACCTL_STATE_DIR}/devices.yaml"
    stub_called "logger -t tacctl -p auth.info device onboard user=alice device=example-sw5 addr=${ADDR} login=local:admin result=checked"
    nothing_secret
}

@test "onboard: the trust question, the review, the two passwords, the TACACS+ sessions after the commit" {
    tonboard 'y\nexample-sw5\n' "$ADDR" --login admin
    [[ "$status" -eq 0 ]]
    assert_output --partial "${ADDR} offers:"
    assert_output --partial "Trust these keys and send the local password of 'admin' to ${ADDR}? [y/N]"
    assert_output --partial "first-time plan:"
    assert_output --partial "set system tacplus-server 10.0.0.42 secret <secret>"
    refute_output --partial "lab-secret"
    assert_output --partial "never written: the local account 'admin', root, the break-glass accounts"
    assert_output --partial "kept only after a TACACS+ login as alice works"
    assert_output --partial "Type the device name to go on:"
    assert_output --partial "example-sw5  committing as admin, verifying as alice ..."
    assert_output --regexp "example-sw5  applied \(roles,aaa: [0-9]+ set, 0 delete\) \[tacctl-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}\]"
    assert_output --partial "The local account 'admin' was not probed: a login would send its password to the TACACS+ server."
    refute_output --partial "still logs in"
    refute_output --partial "is refused while the server answers"
    run committed
    assert_output --partial "set system tacplus-server 10.0.0.42 single-connection"
    assert_output --partial "set system authentication-order tacplus"
    # the local account and root are as they were
    assert_output --partial 'set system login user admin authentication encrypted-password'
    assert_output --partial 'set system root-authentication encrypted-password'
    # the record: the read after the commit was alice's own login
    [[ "$(record example-sw5 login)" == "" ]]
    [[ "$(record example-sw5 user_pulled)" == True ]]
    [[ "$(record example-sw5 applied.result)" == applied ]]
    [[ "$(record example-sw5 applied.kind)" == onboard ]]
    stub_called "logger -t tacctl -p auth.notice device onboard user=alice device=example-sw5 approved=1 shape="
    stub_called "logger -t tacctl -p auth.info device onboard user=alice device=example-sw5 addr=${ADDR} login=local:admin result=applied"
    nothing_secret
    # the device is the normal flow's now
    onboard "$ADDR" --login admin --host-key "$FP" --check
    assert_failure
    assert_output --partial "is registered as 'example-sw5' and was read as your own login"
}

@test "onboard: a refused fresh login rolls the change back and leaves the local account as it was" {
    : > "${JDIR}/verify.fail"
    tonboard 'y\nexample-sw5\n' "$ADDR" --login admin
    [[ "$status" -eq 1 ]]
    assert_output --regexp "example-sw5  rolled back: verification failed \(the fresh login was refused\)"
    assert_output --partial "the change was rolled back and the local account 'admin' is as it was"
    assert_output --partial "The local account 'admin' was not probed"
    refute_output --partial "still logs in"
    unchanged
    [[ "$(record example-sw5 applied.result)" == rolled-back ]]
    [[ "$(record example-sw5 login)" == local:admin ]]
    stub_called "device onboard user=alice device=example-sw5 addr=${ADDR} login=local:admin result=rolled-back"
}

@test "onboard: a declined question sends nothing; a device with a server is refused" {
    tonboard 'n\n' "$ADDR" --login admin
    [[ "$status" -eq 1 ]]
    assert_output --partial "Not trusted. Nothing was sent."
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
    printf 'set system tacplus-server 192.0.2.10 secret "$9$fakeSecretValue1"\n' >> "${JDIR}/config.set"
    onboard "$ADDR" --login admin --host-key "$FP" --check
    assert_failure 1
    assert_output --partial "refused: the device already has a TACACS+ or RADIUS server; it is reached by the normal flow (device add, device config pull)"
    [[ ! -e "${TACCTL_STATE_DIR}/devices.yaml" ]] || ! grep -q "$ADDR" "${TACCTL_STATE_DIR}/devices.yaml"
}

@test "onboard: a fresh login that is not the template user rolls back; a proof that could be local is refused" {
    # alice's login lands on no template user (a local account of her name)
    rm -f "${JDIR}/template"
    tonboard 'y\nexample-sw5\n' "$ADDR" --login admin
    [[ "$status" -eq 1 ]]
    assert_output --regexp "example-sw5  rolled back: verification failed \(the fresh login: the current user is 'alice', a local account"
    unchanged
    onboard "$ADDR" --login alice --host-key "$FP" --check
    assert_failure 2
    assert_output --partial "'alice' is your own login"
    onboard "$ADDR" --login admin --host-key "$FP" --check --section roles
    assert_failure 2
    assert_output --partial "--section must include aaa"
}

@test "onboard --login root: the CLI through the csh wrapper" {
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD=root-fakedev-pw run "$TACCTL_BIN_SCRIPT" device onboard "$ADDR" --login root --host-key "$FP" --check --name sw-root
    plain
    assert_success
    assert_output --partial "sw-root  read as local:root:"
    assert_output --regexp "sw-root  checked: shape [0-9a-f]{12}"
    [[ "$(record sw-root login)" == local:root ]]
    unchanged
}

@test "onboard --login root: committed, and root is not probed afterwards" {
    LOCAL_PW=root-fakedev-pw tonboard 'y\nsw-root\n' "$ADDR" --login root --name sw-root
    [[ "$status" -eq 0 ]]
    assert_output --regexp "sw-root  applied \("
    assert_output --partial "The local account 'root' was not probed: a login would send its password to the TACACS+ server."
    refute_output --partial "still logs in"
    refute_output --partial "is refused while the server answers"
    nothing_secret
}

@test "onboard: any local account, a break-glass one included; a held address is refused" {
    onboard "$ADDR" --login bgadmin --host-key "$FP" --check --name sw-bg
    assert_success
    assert_output --partial "sw-bg  read as local:bgadmin:"
    [[ "$(record sw-bg login)" == local:bgadmin ]]
    stub_called "device onboard user=alice device=sw-bg addr=${ADDR} login=local:bgadmin result=checked"
    printf 'breakglass_hold:\n  sw-bg:\n    address: %s\n    since: "2026-10-13T00:00:00Z"\n    by: alice\n    reason: console recovery\n' "$ADDR" > "${TACCTL_STATE_DIR}/tacctl.yaml"
    onboard "$ADDR" --login bgadmin --host-key "$FP" --check
    assert_failure 1
    assert_output --partial "break-glass is held on sw-bg"
    assert_output --partial "release it first"
}
