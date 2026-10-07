#!/usr/bin/env bats
# Integration tests for `tacctl config snmp`: the settings in tacctl.yaml, the
# credentials in snmp.yaml (0600, never printed), and 'test' against the stub
# agent (`tacctl _snmp-agent`, a -tags testknobs build) on 127.0.0.1.

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
    SNMP_FILE="${TACCTL_STATE_DIR}/snmp.yaml"
    COMMUNITY="c0mmunity-bats"
}

teardown() {
    if [[ -n "${SNMP_PID:-}" ]]; then kill "$SNMP_PID" 2> /dev/null || true; fi
}

# snmp_agent <args...>: the stub agent on 127.0.0.1, answering for a minute;
# SNMP_PORT is its port.
snmp_agent() {
    local pf="${BATS_TEST_TMPDIR}/snmp-agent.port"
    rm -f "$pf"
    "$TACCTL_BIN_SCRIPT" _snmp-agent --port-file "$pf" --seconds 60 "$@" > /dev/null 2>&1 3>&- &
    SNMP_PID=$!
    local _
    for _ in $(seq 50); do
        [[ -s "$pf" ]] && break
        sleep 0.1
    done
    SNMP_PORT=$(cat "$pf")
}

# no_secret: the last output holds none of the secrets.
no_secret() {
    refute_output --partial "$COMMUNITY"
    refute_output --partial "auth-pass-bats"
    refute_output --partial "priv-pass-bats"
}

@test "config snmp: no subcommand prints the usage; show says nothing is set" {
    run "$TACCTL_BIN_SCRIPT" config snmp
    assert_success
    assert_output --partial "Usage: tacctl config snmp <subcommand>"
    assert_output --partial "v3-user <user> [--auth sha|sha256] [--priv aes128] [--stdin]"
    run "$TACCTL_BIN_SCRIPT" config snmp show
    assert_success
    assert_output --partial "version:    not set (no lookup; 'community' or 'v3-user' sets it)"
    assert_output --partial "port:       161 (default)"
    assert_output --partial "timeout:    2 (default) s, one retry"
    assert_output --partial "community:  not set"
    run "$TACCTL_BIN_SCRIPT" config snmp frob
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frob'"
    run "$TACCTL_BIN_SCRIPT" config
    assert_output --partial "snmp    show|community|v3-user|port|timeout|clear|test"
}

@test "config snmp community: stdin only without a terminal; stored 0600, never printed; the version becomes v2c" {
    run "$TACCTL_BIN_SCRIPT" config snmp community < /dev/null
    assert_failure 1
    assert_output --partial "No terminal to ask for the community on; pipe it in with --stdin."
    [[ ! -e "$SNMP_FILE" ]]
    run bash -c "printf '%s\n' '$COMMUNITY' | '$TACCTL_BIN_SCRIPT' config snmp community --stdin"
    assert_success
    assert_output --partial "SNMP community set (${SNMP_FILE}); version v2c."
    no_secret
    run stat -c %a "$SNMP_FILE"
    assert_output "600"
    run grep -c "$COMMUNITY" "$SNMP_FILE"
    assert_output "1"
    [[ "$(conf_get snmp.version)" == "v2c" ]]
    run grep -c "$COMMUNITY" "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" config snmp show
    assert_output --partial "version:    v2c (the community)"
    refute_output --partial "v3 user"
    assert_output --partial "community:  set"
    no_secret
    run "$TACCTL_BIN_SCRIPT" config dump
    no_secret
}

@test "config snmp port and timeout: shown, set and range-checked in tacctl.yaml" {
    run "$TACCTL_BIN_SCRIPT" config snmp port 1161
    assert_success
    [[ "$(conf_get snmp.port)" == "1161" ]]
    run "$TACCTL_BIN_SCRIPT" config snmp timeout 11
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config snmp timeout 1
    assert_success
    run "$TACCTL_BIN_SCRIPT" config snmp show
    assert_output --partial "port:       1161"
    assert_output --partial "timeout:    1 s, one retry"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_output --regexp "tacctl.yaml:.* valid"
}

@test "config snmp test: v2c answers with the sysName; a wrong community is a timeout" {
    snmp_agent --sysname sw1.site-a.example --community "$COMMUNITY"
    "$TACCTL_BIN_SCRIPT" config snmp port "$SNMP_PORT" > /dev/null
    "$TACCTL_BIN_SCRIPT" config snmp timeout 1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_failure 1
    assert_output --partial "Cannot test: SNMP is not configured ('tacctl config snmp')."
    printf '%s\n' "$COMMUNITY" | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_success
    assert_output --partial "127.0.0.1 calls itself 'sw1.site-a.example' (SNMP sysName)."
    printf 'wrong-community\n' | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_failure 1
    assert_output --partial "No answer from 127.0.0.1: no answer (2 tries, 1s each). No agent there, a filter on the way, or a wrong community"
    refute_output --partial "wrong-community"
    run "$TACCTL_BIN_SCRIPT" config snmp test not-a-device
    assert_failure 1
    assert_output --partial "'not-a-device' is neither an address nor a registered device."
}

@test "config snmp v3-user: authPriv with SHA-256 answers; wrongDigest and unknownUserName are named" {
    snmp_agent --sysname rtr1.site-b.example --user alice --auth-pass auth-pass-bats --priv-pass priv-pass-bats --auth sha256
    "$TACCTL_BIN_SCRIPT" config snmp port "$SNMP_PORT" > /dev/null
    "$TACCTL_BIN_SCRIPT" config snmp timeout 1 > /dev/null
    run bash -c "printf 'auth-pass-bats\npriv-pass-bats\n' | '$TACCTL_BIN_SCRIPT' config snmp v3-user alice --auth sha256 --stdin"
    assert_success
    assert_output --partial "version v3, auth sha256, priv aes128."
    no_secret
    [[ "$(conf_get snmp.version)" == "v3" && "$(conf_get snmp.v3.auth)" == "sha256" ]]
    run stat -c %a "$SNMP_FILE"
    assert_output "600"
    run "$TACCTL_BIN_SCRIPT" config snmp show
    assert_output --partial "v3 user:    set; passphrases: set"
    assert_output --partial "v3 auth:    sha256; priv: aes128 (default)"
    refute_output --partial "alice"
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_success
    assert_output --partial "127.0.0.1 calls itself 'rtr1.site-b.example' (SNMP sysName)."
    printf 'wrong-pass-1\npriv-pass-bats\n' | "$TACCTL_BIN_SCRIPT" config snmp v3-user alice --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_failure 1
    assert_output --partial "127.0.0.1 refused the request: wrongDigest (wrong authentication passphrase or protocol)."
    printf 'auth-pass-bats\npriv-pass-bats\n' | "$TACCTL_BIN_SCRIPT" config snmp v3-user bob --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_failure 1
    assert_output --partial "127.0.0.1 refused the request: unknownUserName (the agent has no such user)."
    run bash -c "printf 'short\nshort\n' | '$TACCTL_BIN_SCRIPT' config snmp v3-user alice --stdin"
    assert_failure 1
    assert_output --partial "at least 8 characters"
    run "$TACCTL_BIN_SCRIPT" config snmp v3-user alice --auth md5 --stdin
    assert_failure 1
    assert_output --partial "Unknown --auth 'md5': sha or sha256."
}

@test "config snmp clear: removes the credentials and the version" {
    printf '%s\n' "$COMMUNITY" | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp clear
    assert_success
    assert_output --partial "SNMP credentials removed and snmp.version unset"
    [[ ! -e "$SNMP_FILE" ]]
    [[ -z "$(conf_get snmp.version)" ]]
    run "$TACCTL_BIN_SCRIPT" config snmp clear
    assert_output --partial "No SNMP credentials were set; nothing was changed."
}
