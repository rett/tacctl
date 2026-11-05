#!/usr/bin/env bats
# Integration tests for the nftables table of the held addresses (0.2.24):
# `tacctl breakglass hold|release` and `config breakglass-firewall` write the
# rules file and load it with `nft -f`. nft is a stub on PATH (tests/helpers/
# mocks.bash), so no real table is ever loaded; the rules file is real. The
# device's name is typed back at a terminal, so `hold` runs under script(1).

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
    stub_cmd nft
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    RULES="${TACCTL_STATE_DIR}/breakglass-firewall.nft"
    "$TACCTL_BIN_SCRIPT" device add lab-sw 192.168.1.1 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null
}

# tacctl's output without colours (stdout and stderr).
plain() {
    local rc=0
    "$TACCTL_BIN_SCRIPT" "$@" > "${BATS_TEST_TMPDIR}/plain.out" 2>&1 || rc=$?
    sed -E 's/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/plain.out"
    return "$rc"
}

# hold <device> <reason>: `breakglass hold` on a terminal, the name typed back.
hold() {
    local cmd rc=0
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" breakglass hold "$1" --reason "$2"
    printf '%s\n' "$1" | script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/hold.out" 2>&1 || rc=$?
    sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/hold.out"
    return "$rc"
}

@test "hold loads the table after the restart, release lifts it, the file is the whole table" {
    run hold lab-sw "console recovery"
    assert_success
    assert_output --partial "Firewall: 192.168.1.1 refused on tcp/49 (reject)"
    stub_called "^nft -f ${RULES}\$"
    run grep -F 'elements = { 192.168.1.1 }' "$RULES"
    assert_success
    run grep -F 'ip saddr @held4 tcp dport { 49 } reject with tcp reset' "$RULES"
    assert_success
    run grep -F 'delete table inet tacctl' "$RULES"
    assert_success
    run grep -c 'ct state' "$RULES"
    assert_output "0"
    stub_called 'logger -t tacctl -p auth.info breakglass hold device=lab-sw addr=192.168.1.1 reason="console recovery" by=root firewall=reject result=ok'
    # the restart comes first, the table after it
    local restart load
    restart=$(grep -n 'systemctl restart' "$CALLS_LOG" | tail -n 1 | cut -d: -f1)
    load=$(grep -n '^nft -f' "$CALLS_LOG" | tail -n 1 | cut -d: -f1)
    [[ "$load" -gt "$restart" ]]
    # nftables.service is never touched, the ruleset is never read or flushed
    run grep -E 'nftables|flush|ruleset' "$CALLS_LOG"
    assert_failure

    run plain breakglass release lab-sw
    assert_success
    assert_output --partial "Firewall: 192.168.1.1 accepted again on tcp/49"
    run grep -c elements "$RULES"
    assert_output "0"
    stub_called 'firewall=reject result=ok'
}

@test "config breakglass-firewall: drop, off and reject; the file follows" {
    run plain config breakglass-firewall
    assert_success
    assert_output --partial "Break-glass firewall: reject   (default)"
    run plain config breakglass-firewall drop
    assert_success
    assert_output --partial "breakglass.firewall is drop (it was reject)."
    run grep -F 'tcp dport { 49 } drop' "$RULES"
    assert_success
    run plain config breakglass-firewall off
    assert_success
    assert_output --partial "the table inet tacctl is removed"
    run grep -c chain "$RULES"
    assert_output "0"
    run plain config breakglass-firewall block
    assert_failure 1
    assert_output --partial "Invalid value: 'block'. Use: reject, drop, off"
    run plain config breakglass-firewall reject
    assert_success
    run grep -c firewall "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
}

@test "an nft that fails: the hold stands, the report is red with the fix, exit 1" {
    stub_cmd nft 'echo "Error: Operation not permitted" >&2; exit 1'
    run hold lab-sw "console recovery"
    assert_failure 1
    assert_output --partial "Break-glass HELD on lab-sw (192.168.1.1)"
    assert_output --partial "Firewall: NOT APPLIED (nft -f "
    assert_output --partial "Operation not permitted"
    assert_output --partial "The server still completes the TCP handshake on tcp/49 for 192.168.1.1"
    assert_output --partial "tacctl config breakglass-firewall reject"
    run grep -c breakglass_hold "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "1"
    run grep -c '"192.168.0.0/16"' "$TACCTL_CONFIG"
    assert_output "0"
    stub_called 'firewall=failed result=ok'
    run plain breakglass release lab-sw
    assert_failure 1
    assert_output --partial "may still refuse the TCP connections of 192.168.1.1"
}
