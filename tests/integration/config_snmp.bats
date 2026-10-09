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

# --- scope snmp (0.2.3: D41, D46) ----------------------------------------------------------

# scope_snmp <scope> <args...>: tacctl scope snmp, output stripped of colours.
scope_snmp() { local s="$1"; shift; run "$TACCTL_BIN_SCRIPT" scope snmp "$s" "$@"; output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); }

@test "scope snmp: the usage; show says nothing is set and writes nothing" {
    load_fixture tacquito.multiscope.yaml
    local before
    before=$(ls -A "$TACCTL_STATE_DIR")
    scope_snmp lab
    assert_success
    assert_output --partial "Usage: tacctl scope snmp lab <subcommand>"
    assert_output --partial "clients list|add|remove [<cidr>[,<cidr>...]]"
    scope_snmp lab show
    assert_success
    assert_output --partial "SNMP for scope 'lab'"
    assert_output --partial "version:    not set"
    assert_output --partial "port:       161  (built-in)"
    assert_output --partial "the scope lists no ranges: only the tacctl server may query"
    scope_snmp lab frob
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frob'"
    scope_snmp nosuch show
    assert_failure 1
    assert_output --partial "Scope 'nosuch' does not exist. Available:"
    [[ "$(ls -A "$TACCTL_STATE_DIR")" == "$before" ]]
    [[ ! -e "${TACCTL_STATE_DIR}/snmp" && ! -e "$SNMP_FILE" ]]
}

@test "scope snmp community: a file of the scope's own (0600 in a 0700 directory), never printed but by show --reveal" {
    load_fixture tacquito.multiscope.yaml
    run bash -c "printf '%s\n' '$COMMUNITY' | '$TACCTL_BIN_SCRIPT' scope snmp lab community --stdin"
    assert_success
    assert_output --partial "SNMP community of scope 'lab' set (${TACCTL_STATE_DIR}/snmp/lab.yaml); the scope's version is v2c."
    no_secret
    run stat -c %a "${TACCTL_STATE_DIR}/snmp/lab.yaml"
    assert_output "600"
    run stat -c %a "${TACCTL_STATE_DIR}/snmp"
    assert_output "700"
    [[ ! -e "$SNMP_FILE" ]]
    [[ "$(conf_get snmp_scope.lab.version)" == "v2c" ]]
    run grep -c "$COMMUNITY" "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
    scope_snmp lab show
    assert_success
    assert_output --partial "version:    v2c (the community)  (scope)"
    assert_output --partial "community:  set  (scope)"
    no_secret
    scope_snmp lab show --reveal
    assert_success
    assert_output --partial "community:  ${COMMUNITY}  (scope)"
    # Another scope has nothing, and no file.
    scope_snmp prod show
    assert_output --partial "version:    not set"
    [[ ! -e "${TACCTL_STATE_DIR}/snmp/prod.yaml" ]]
}

@test "scope snmp: the default beneath a scope, and which one wins" {
    load_fixture tacquito.multiscope.yaml
    printf 'def-community-bats\n' | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" config snmp port 1161 > /dev/null
    scope_snmp prod show --reveal
    assert_success
    assert_output --partial "version:    v2c (the community)  (default)"
    assert_output --partial "port:       1161  (default)"
    assert_output --partial "community:  def-community-bats  (default)"
    printf 'scope-community-bats\n' | "$TACCTL_BIN_SCRIPT" scope snmp prod community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp prod timeout 5 > /dev/null
    scope_snmp prod show --reveal
    assert_output --partial "community:  scope-community-bats  (scope)"
    assert_output --partial "port:       1161  (default)"
    assert_output --partial "timeout:    5 s, one retry  (scope)"
    # The default's own show is the default's.
    run "$TACCTL_BIN_SCRIPT" config snmp show --reveal
    assert_output --partial "def-community-bats"
    refute_output --partial "scope-community-bats"
    run "$TACCTL_BIN_SCRIPT" config snmp show
    refute_output --partial "def-community-bats"
    # clear: the scope's file and keys go, the default stays.
    scope_snmp prod clear
    assert_success
    assert_output --partial "removed: the default applies again"
    [[ ! -e "${TACCTL_STATE_DIR}/snmp/prod.yaml" && ! -d "${TACCTL_STATE_DIR}/snmp" ]]
    [[ -z "$(conf_get snmp_scope.prod.timeout)" ]]
    [[ -f "$SNMP_FILE" ]]
}

@test "scope snmp clients: IPv4 only, in the order given, never 0.0.0.0/0, at most 32; overlaps are a note" {
    load_fixture tacquito.multiscope.yaml
    scope_snmp lab clients add 198.51.100.0/24,10.0.0.0/8,192.0.2.7
    assert_success
    assert_output --partial "Added 3 allowed SNMP client range(s) to scope 'lab': 198.51.100.0/24 10.0.0.0/8 192.0.2.7/32"
    scope_snmp lab clients list
    assert_success
    assert_output --partial "  1. the tacctl server's own /32"
    assert_output --partial "  2. 198.51.100.0/24"
    assert_output --partial "  4. 192.0.2.7/32"
    assert_output --partial "  5. 0.0.0.0/0 refused (always last, never stored)"
    scope_snmp lab clients add 10.1.0.0/16
    assert_success
    assert_output --partial "10.0.0.0/8 already contains 10.1.0.0/16 (both stay)."
    scope_snmp lab clients add 0.0.0.0/0
    assert_failure 1
    assert_output --partial "would allow every address"
    scope_snmp lab clients add 2001:db8::/32
    assert_failure 1
    assert_output --partial "IPv6 network"
    scope_snmp lab clients add 198.51.100.0/24
    assert_success
    assert_output --partial "No new ranges to add"
    run grep -c '0.0.0.0/0' "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
    local many
    many=$(for i in $(seq 0 39); do printf '172.20.%s.0/24,' "$i"; done)
    scope_snmp lab clients add "${many%,}"
    assert_failure 1
    assert_output --partial "at most 32 client ranges"
    scope_snmp lab clients remove 10.0.0.0/8,203.0.113.0/24
    assert_success
    assert_output --partial "Removed 1 SNMP client range(s) from scope 'lab': 10.0.0.0/8"
    scope_snmp lab clients remove 203.0.113.0/24
    assert_output --partial "Nothing to remove (not in the list: 203.0.113.0/24)."
}

@test "scope snmp contact: shown, set, validated, removed" {
    load_fixture tacquito.multiscope.yaml
    scope_snmp lab contact
    assert_output "not set"
    scope_snmp lab contact NOC '<noc@example.net>'
    assert_success
    assert_output --partial "Contact of scope 'lab' set to 'NOC <noc@example.net>'."
    scope_snmp lab contact
    assert_output "NOC <noc@example.net>"
    scope_snmp lab contact 'help?'
    assert_failure 1
    assert_output --partial "The contact may not contain '?'"
    scope_snmp lab contact --clear
    assert_success
    assert_output --partial "Contact of scope 'lab' removed."
    if grep -qs snmp_scope "${TACCTL_STATE_DIR}/tacctl.yaml"; then cat "${TACCTL_STATE_DIR}/tacctl.yaml"; return 1; fi
}

@test "scope snmp test and device add: a device's name is read with the credentials of its scope" {
    load_fixture tacquito.multiscope.yaml
    snmp_agent --sysname sw1.site-a.example --community "$COMMUNITY"
    "$TACCTL_BIN_SCRIPT" config snmp port "$SNMP_PORT" > /dev/null
    "$TACCTL_BIN_SCRIPT" config snmp timeout 1 > /dev/null
    printf 'default-wrong\n' | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope prefixes dmz add 127.0.0.0/8
    assert_success
    printf '%s\n' "$COMMUNITY" | "$TACCTL_BIN_SCRIPT" scope snmp dmz community --stdin > /dev/null
    scope_snmp dmz test 127.0.0.1
    assert_success
    assert_output --partial "127.0.0.1 calls itself 'sw1.site-a.example' (SNMP sysName)."
    run "$TACCTL_BIN_SCRIPT" config snmp test 127.0.0.1
    assert_failure 1
    assert_output --partial "No answer from 127.0.0.1"
    run "$TACCTL_BIN_SCRIPT" device add sw1 127.0.0.1 --no-host-key
    assert_success
    assert_output --partial "The device calls itself 'sw1.site-a.example' (SNMP sysName)."
    run "$TACCTL_BIN_SCRIPT" device check sw1
    assert_output --partial "sw1.site-a.example"
    # Without the scope's own credentials the default's apply.
    "$TACCTL_BIN_SCRIPT" scope snmp dmz clear > /dev/null
    run "$TACCTL_BIN_SCRIPT" device check sw1
    refute_output --partial "sw1.site-a.example"
}

@test "scope snmp follows a scope's rename and removal" {
    load_fixture tacquito.multiscope.yaml
    printf '%s\n' "$COMMUNITY" | "$TACCTL_BIN_SCRIPT" scope snmp dmz community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp dmz contact NOC > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope rename dmz edge
    assert_success
    [[ -f "${TACCTL_STATE_DIR}/snmp/edge.yaml" && ! -e "${TACCTL_STATE_DIR}/snmp/dmz.yaml" ]]
    scope_snmp edge show --reveal
    assert_output --partial "community:  ${COMMUNITY}  (scope)"
    assert_output --partial "contact:    NOC  (scope)"
    run bash -c "printf 'y\n' | '$TACCTL_BIN_SCRIPT' scope remove edge --force"
    assert_success
    [[ ! -e "${TACCTL_STATE_DIR}/snmp/edge.yaml" ]]
    if grep -qs 'snmp_scope\|edge' "${TACCTL_STATE_DIR}/tacctl.yaml"; then cat "${TACCTL_STATE_DIR}/tacctl.yaml"; return 1; fi
}

@test "a tacctl.yaml and a devices.yaml without the new settings are not changed by reading or by a walkthrough" {
    load_fixture tacquito.multiscope.yaml
    printf 'scope:\n  default: lab\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key > /dev/null
    cp "${TACCTL_STATE_DIR}/tacctl.yaml" "$BATS_TEST_TMPDIR/tacctl.before"
    cp "${TACCTL_STATE_DIR}/devices.yaml" "$BATS_TEST_TMPDIR/devices.before"
    "$TACCTL_BIN_SCRIPT" config cisco --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" config juniper --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" config wti --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab show > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab clear > /dev/null
    "$TACCTL_BIN_SCRIPT" device location core-sw1 > /dev/null
    cmp "$BATS_TEST_TMPDIR/tacctl.before" "${TACCTL_STATE_DIR}/tacctl.yaml"
    cmp "$BATS_TEST_TMPDIR/devices.before" "${TACCTL_STATE_DIR}/devices.yaml"
    run grep -c 'location' "${TACCTL_STATE_DIR}/devices.yaml"
    assert_output "0"
}

@test "config snmp show --reveal prints the default's credentials; plain show never does" {
    printf '%s\n' "$COMMUNITY" | "$TACCTL_BIN_SCRIPT" config snmp community --stdin > /dev/null
    run "$TACCTL_BIN_SCRIPT" config snmp show
    assert_success
    no_secret
    assert_output --partial "'show --reveal' prints them"
    run "$TACCTL_BIN_SCRIPT" config snmp show --reveal
    assert_success
    assert_output --partial "community:  ${COMMUNITY}"
}
