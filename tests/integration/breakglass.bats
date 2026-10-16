#!/usr/bin/env bats
# Integration tests for `tacctl breakglass hold|release|list` (docs/plans/
# 0.2.5-plan.md D121-D126): the server stops answering one device by a /32
# carved out of every scope's prefixes at render time, shown until released.
# The device's name is typed back at a terminal, so `hold` runs under
# script(1), which gives it a pseudo-terminal.

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
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" device add lab-sw 192.168.1.1 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add prod-sw 10.20.30.40 --vendor juniper --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add core-rtr 100.64.0.9 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    # One render, so what a hold has to give back exists.
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null
}

# tacctl's output without colours (stdout and stderr).
plain() {
    local rc=0
    "$TACCTL_BIN_SCRIPT" "$@" > "${BATS_TEST_TMPDIR}/plain.out" 2>&1 || rc=$?
    sed -E 's/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/plain.out"
    return "$rc"
}

# hold <device> <reason> [typed]: `breakglass hold` on a terminal, the name
# typed back (or the third word, when it is to be wrong). The report comes
# out with the terminal's carriage returns taken off.
hold() {
    local typed="${3:-$1}" cmd rc=0
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" breakglass hold "$1" --reason "$2"
    printf '%s\n' "$typed" | script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/hold.out" 2>&1 || rc=$?
    sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/hold.out"
    return "$rc"
}

# hold_list <typed> <argument>... : `breakglass hold` of a list on a
# terminal, <typed> typed back; the arguments are the hold's own.
hold_list() {
    local typed="$1" cmd rc=0
    shift
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" breakglass hold "$@"
    printf '%s\n' "$typed" | script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/hold.out" 2>&1 || rc=$?
    sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/hold.out"
    return "$rc"
}

rendered() { sha256sum < "$TACCTL_CONFIG"; }

# restarts: the restarts of a service so far (the setup's render counts).
restarts() { grep -c 'systemctl restart' "$CALLS_LOG" || true; }

@test "hold: needs --reason and a terminal, and the name typed back; nothing changes" {
    local base
    base=$(restarts)
    run plain breakglass hold lab-sw
    assert_failure 1
    assert_output --partial "--reason is required"
    run plain breakglass hold lab-sw --reason "console recovery"
    assert_failure 1
    assert_output --partial "No terminal to confirm on"
    run hold lab-sw "console recovery" lab-sx
    assert_failure 1
    assert_output --partial "Hold break-glass on lab-sw (192.168.1.1, scope lab, cisco)?"
    assert_output --partial "This is for one device in exceptional circumstances."
    assert_output --partial "lab-admin [admin]"
    assert_output --partial "The name typed back is not 'lab-sw'. Nothing was changed."
    refute_output --partial "HELD"
    run grep -c breakglass_hold "$OVERRIDES"
    assert_output "0"
    [[ "$(restarts)" == "$base" ]]
}

@test "hold, list, show and release: one restart each way, and the original bytes come back" {
    local before after held base
    before=$(rendered)
    base=$(restarts)
    run hold lab-sw "console recovery after a failed paste"
    assert_success
    assert_output --partial "Break-glass HELD on lab-sw (192.168.1.1) since "
    assert_output --partial "Reason:   console recovery after a failed paste"
    assert_output --partial "Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1; tacacs restarted."
    assert_output --partial "Held now: lab-sw ("
    assert_output --partial "When done: tacctl breakglass release lab-sw"
    [[ "$(restarts)" == "$((base + 1))" ]]
    stub_called 'logger -t tacctl -p auth.info breakglass hold device=lab-sw addr=192.168.1.1 reason="console recovery after a failed paste" by=root'
    held=$(rendered)
    [[ "$held" != "$before" ]]
    run grep -c '"192.168.0.0/16"' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -F '# break-glass held: 192.168.1.1 (device lab-sw)' "$TACCTL_CONFIG"
    assert_success
    run grep -c 'console recovery' "$TACCTL_CONFIG"
    assert_output "0"
    # The store is the operator's intent and stays as it was.
    run grep -c '192.168.0.0/16' "${TACCTL_STATE_DIR}/store.yaml"
    assert_output "1"

    run plain breakglass list
    assert_success
    assert_output --partial "Break-glass holds (1)"
    assert_output --partial "lab-sw"
    assert_output --partial "console recovery after a failed paste"
    run plain breakglass list --json
    assert_success
    assert_output --partial '"device": "lab-sw"'
    assert_output --partial '"address": "192.168.1.1"'
    run plain device show lab-sw
    assert_output --partial "Break-glass:  HELD since "
    assert_output --partial "the server does not answer 192.168.1.1"
    run plain device list
    assert_output --partial "BREAK-GLASS"
    assert_output --partial "1 device(s) held for break-glass: tacctl breakglass list"
    run plain status
    assert_output --partial "Break-glass:        HELD on lab-sw (192.168.1.1)"
    run plain scope lookup 192.168.1.1
    assert_output --partial "NOT ANSWERED: break-glass held on lab-sw"
    run plain scope lookup 192.168.1.2
    refute_output --partial "NOT ANSWERED"

    run plain breakglass release lab-sw
    assert_success
    assert_output --partial "Break-glass RELEASED on lab-sw (192.168.1.1): held "
    assert_output --partial "Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted."
    assert_output --partial "Still held: none"
    [[ "$(restarts)" == "$((base + 2))" ]]
    after=$(rendered)
    [[ "$after" == "$before" ]]
    run grep -c breakglass_hold "$OVERRIDES"
    assert_output "0"
    stub_called 'logger -t tacctl -p auth.info breakglass release device=lab-sw addr=192.168.1.1 held='
    run plain breakglass list
    assert_output --partial "None held"
}

@test "hold: a held device is not moved or removed, and a rename follows" {
    run hold lab-sw "console recovery"
    assert_success
    run plain device address lab-sw 192.168.1.9
    assert_failure 1
    assert_output --partial "break-glass is held on lab-sw: release it first (tacctl breakglass release lab-sw)"
    run plain device remove lab-sw -y
    assert_failure 1
    assert_output --partial "break-glass is held on lab-sw: release it first"
    run plain device rename lab-sw lab-core
    assert_success
    run plain breakglass list
    assert_output --partial "lab-core"
    run plain breakglass release lab-sw
    assert_failure 1
    assert_output --partial "Break-glass is not held on 'lab-sw'. Held now: lab-core"
    run plain breakglass release lab-core
    assert_success
}

@test "hold: refused for an unknown device, the server's own address and an address no scope covers" {
    run hold nosuch "x"
    assert_failure 1
    assert_output --partial "Device 'nosuch' not found"
    "$TACCTL_BIN_SCRIPT" device add self 127.0.0.1 --no-host-key > /dev/null
    run hold self "x"
    assert_failure 1
    assert_output --partial "127.0.0.1 is a loopback address"
    run hold core-rtr "x"
    assert_failure 1
    assert_output --partial "'core-rtr' is already unanswered: no scope covers 100.64.0.9"
    run grep -c breakglass_hold "$OVERRIDES"
    assert_output "0"
}

@test "hold: the plan of a held device names it, and a pull refuses it up front" {
    run hold lab-sw "console recovery"
    assert_success
    SUDO_USER=alice run plain device config pull lab-sw
    assert_failure 1
    assert_output --partial "break-glass is held on lab-sw: the device does not authenticate your login until it is released (tacctl breakglass release lab-sw)"
    run plain device config plan --all
    assert_output --partial "[break-glass held]"
}

@test "rollback: refused while a hold stands, in the dry run and with --apply" {
    run hold lab-sw "console recovery"
    assert_success
    run plain rollback 0.2.3
    assert_failure 1
    assert_output --partial "Break-glass is held on lab-sw (192.168.1.1"
    assert_output --partial "Release it first: tacctl breakglass release lab-sw. Nothing was changed."
    run plain rollback 0.2.3 --apply --yes
    assert_failure 1
    assert_output --partial "Release it first: tacctl breakglass release lab-sw."
    run grep -c '^breakglass_hold:' "$OVERRIDES"
    assert_output "1"
    run plain breakglass release lab-sw
    assert_success
    run plain rollback 0.2.3
    assert_success
    refute_output --partial "Break-glass is held"
}

@test "hold and release of a list: best effort, one restart each way, exit 1 for what was not held" {
    local before base
    before=$(rendered)
    base=$(restarts)
    run hold_list "lab-sw,prod-sw" "lab-sw=console recovery,prod-sw,core-rtr,nosuch" --reason "paste cut the session"
    assert_failure 1
    assert_output --partial "Hold break-glass on 2 devices (lab-sw,prod-sw)?"
    assert_output --partial "Break-glass HELD on lab-sw (192.168.1.1) since "
    assert_output --partial "Break-glass HELD on prod-sw (10.20.30.40) since "
    assert_output --partial "Reason:   console recovery"
    assert_output --partial "Reason:   paste cut the session"
    assert_output --partial "Not held: core-rtr: it is already unanswered: no scope covers 100.64.0.9"
    assert_output --partial "Not held: nosuch: not found (tacctl device list)"
    assert_output --partial "When done: tacctl breakglass release lab-sw,prod-sw"
    [[ "$(restarts)" == "$((base + 1))" ]]
    stub_called 'logger -t tacctl -p auth.info breakglass hold device=lab-sw addr=192.168.1.1 reason="console recovery" by=root'
    stub_called 'logger -t tacctl -p auth.info breakglass hold device=prod-sw addr=10.20.30.40 reason="paste cut the session" by=root'
    run plain breakglass list
    assert_output --partial "Break-glass holds (2)"

    run plain breakglass release lab-sw,prod-sw,nosuch
    assert_failure 1
    assert_output --partial "Break-glass RELEASED on lab-sw (192.168.1.1): held "
    assert_output --partial "Break-glass RELEASED on prod-sw (10.20.30.40): held "
    assert_output --partial "Not released: nosuch: break-glass is not held on it"
    assert_output --partial "Still held: none"
    [[ "$(restarts)" == "$((base + 2))" ]]
    [[ "$(rendered)" == "$before" ]]
    run grep -c breakglass_hold "$OVERRIDES"
    assert_output "0"
}
