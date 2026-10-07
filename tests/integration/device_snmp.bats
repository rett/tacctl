#!/usr/bin/env bats
# Integration tests for the SNMP name hint of `tacctl device add` and the
# `SNMP name` row of `device check`, against the stub agent (`tacctl
# _snmp-agent`, a -tags testknobs build) on 127.0.0.1: snmp.port points at
# it and the devices are registered at 127.0.0.1.

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
    DEVICES="${TACCTL_STATE_DIR}/devices.yaml"
}

teardown() {
    if [[ -n "${SNMP_PID:-}" ]]; then kill "$SNMP_PID" 2> /dev/null || true; fi
}

# plain: the last output (and its lines) with colours stripped.
plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# snmp_agent <sysname>: the stub agent on 127.0.0.1 answering v2c with the
# community 'c0mm' for a minute, and tacctl set up to ask it (timeout 1 s).
snmp_agent() {
    local pf="${BATS_TEST_TMPDIR}/snmp-agent.port"
    rm -f "$pf"
    "$TACCTL_BIN_SCRIPT" _snmp-agent --port-file "$pf" --seconds 60 --sysname "$1" --community c0mm > /dev/null 2>&1 3>&- &
    SNMP_PID=$!
    local _
    for _ in $(seq 50); do
        [[ -s "$pf" ]] && break
        sleep 0.1
    done
    "$TACCTL_BIN_SCRIPT" config snmp port "$(cat "$pf")" > /dev/null
    "$TACCTL_BIN_SCRIPT" config snmp timeout 1 > /dev/null
    printf 'c0mm\n' | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
}

@test "device add: without SNMP set up, one info line and the add goes ahead" {
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 192.0.2.10 --vendor juniper --no-host-key
    assert_success
    plain
    assert_output --partial "[INFO] No name hint: SNMP is not configured ('tacctl config snmp')."
    run grep -c "core-sw1" "$DEVICES"
    assert_output "1"
}

@test "device add: a sysName that matches the name (or its first label) is one line" {
    snmp_agent SW1.site-a.example
    run "$TACCTL_BIN_SCRIPT" device add sw1 127.0.0.1 --vendor juniper --no-host-key
    assert_success
    plain
    assert_line "[INFO] Device 'sw1' registered: 127.0.0.1, juniper."
    assert_line "  The device calls itself 'SW1.site-a.example' (SNMP sysName)."
    refute_output --partial "!"
}

@test "device add: a different sysName is a warning with the fixes; the add goes ahead" {
    snmp_agent sw1.site-a.example
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 127.0.0.1 --vendor juniper --no-host-key
    assert_success
    plain
    assert_line "  The device calls itself 'sw1.site-a.example' (SNMP sysName)."
    assert_line "  ! That is not the name given or its --hostname: add --hostname sw1.site-a.example, or register it as sw1.site-a.example."
    run grep -c "core-sw1: {address: 127.0.0.1" "$DEVICES"
    assert_output "1"
    # A matching --hostname is a match.
    "$TACCTL_BIN_SCRIPT" device remove core-sw1 -y > /dev/null
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 127.0.0.1 --hostname sw1.site-a.example --no-host-key
    assert_success
    refute_output --partial "!"
}

@test "device add: no answer (a wrong community) is an info line; --no-lookup asks nothing" {
    snmp_agent sw1.site-a.example
    printf 'wrong\n' | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 127.0.0.1 --no-host-key
    assert_success
    plain
    assert_line "[INFO] No SNMP answer from 127.0.0.1; no name hint."
    run grep -c "core-sw1" "$DEVICES"
    assert_output "1"
    "$TACCTL_BIN_SCRIPT" device remove core-sw1 -y > /dev/null
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 127.0.0.1 --no-host-key --no-lookup
    assert_success
    refute_output --partial "SNMP"
    refute_output --partial "name hint"
}

@test "device add: with no answer, the NAS-Identifier a scan recorded stands in, labelled" {
    mkdir -p "$TACCTL_VAR_LIB"
    cat > "${TACCTL_VAR_LIB}/devices-seen.json" << 'EOF'
{"version": 1, "updated": "2026-10-03T08:00:00Z", "sources": {}, "hostkeys": {},
 "addresses": {"192.0.2.20": {"radius": {"first": "2026-10-03T08:00:00Z", "last": "2026-10-03T08:00:00Z",
   "count": 1, "last_user": "alice", "last_outcome": "accept", "last_nas_id": "edge-sw5"}}}}
EOF
    run "$TACCTL_BIN_SCRIPT" device add edge-sw5.site-a.example 192.0.2.20 --no-host-key
    assert_success
    plain
    assert_line "  The device calls itself 'edge-sw5' (NAS-Identifier seen by a scan)."
    refute_output --partial "!"
}

@test "device add <address>: the sysName is offered only at a terminal; otherwise refused with the usage line" {
    run "$TACCTL_BIN_SCRIPT" device add 127.0.0.1 --no-host-key
    assert_failure 1
    assert_output --partial "No name given, and there is none to offer: SNMP is not configured ('tacctl config snmp')."
    assert_output --partial "Usage: tacctl device add [<name>] <address> [options]"
    snmp_agent SW1.site-a.example
    run "$TACCTL_BIN_SCRIPT" device add 127.0.0.1 --no-host-key < /dev/null
    assert_failure 1
    assert_output --partial "No name given; the device calls itself 'SW1.site-a.example' (SNMP sysName). Give the name to register it under it."
    assert_output --partial "Usage: tacctl device add [<name>] <address> [options]"
    run "$TACCTL_BIN_SCRIPT" device add 127.0.0.1 --no-lookup
    assert_failure 1
    assert_output --partial "No name given, and --no-lookup reads none from the device."
    [[ ! -e "$DEVICES" ]]
}

@test "device add <address>: a generic sysName (a WTI Site ID) is never offered" {
    snmp_agent WTI
    run "$TACCTL_BIN_SCRIPT" device add 127.0.0.1 --no-host-key --vendor wti
    assert_failure 1
    assert_output --partial "No name given; the device calls itself 'WTI' (SNMP sysName), but it is a generic name."
    run "$TACCTL_BIN_SCRIPT" device add pdu1 127.0.0.1 --no-host-key --vendor wti
    assert_success
    plain
    assert_line "  The device calls itself 'WTI' (SNMP sysName)."
    assert_line "  ! That is not the name given or its --hostname: add --hostname WTI."
}

@test "device check: the SNMP name row, and sysname in --json" {
    snmp_agent sw1.site-a.example
    "$TACCTL_BIN_SCRIPT" device add sw1 127.0.0.1 --no-host-key --port 1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" device check sw1
    assert_success
    plain
    assert_line "  SNMP name:   sw1.site-a.example  (match)"
    run "$TACCTL_BIN_SCRIPT" device check sw1 --json
    assert_success
    run python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(d["name"], d["sysname"], d["sysname_match"])' <<< "$output"
    assert_output "sw1 sw1.site-a.example True"
    "$TACCTL_BIN_SCRIPT" device rename sw1 core-sw1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" device check core-sw1
    plain
    assert_line "  SNMP name:   sw1.site-a.example  (differs)"
}
