#!/usr/bin/env bats
# Integration tests for the per-device SNMP settings (`tacctl device snmp`,
# docs/plans/0.2.4-plan.md D72): the snmp: map of devices.yaml, the
# credentials file snmp/devices/<name>.yaml, the resolution order and its
# labels in `device show|check`, `scope snmp show` and `device config show`,
# the sysName lookup against the stub agent (`tacctl _snmp-agent`, a -tags
# testknobs build) on 127.0.0.1, and the tiers.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_TIER_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl-tiers"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    DEVICES="${TACCTL_STATE_DIR}/devices.yaml"
    SNMPDIR="${TACCTL_STATE_DIR}/snmp"
    T="$TACCTL_BIN_SCRIPT"
}

teardown() {
    if [[ -n "${SNMP_PID:-}" ]]; then kill "$SNMP_PID" 2> /dev/null || true; fi
}

# plain: the last output (and its lines) with colours stripped.
plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# mode <path>: the octal permission bits.
mode() { stat -c '%a' "$1"; }

# snmp_agent <sysname> <community>: the stub agent on 127.0.0.1 for a
# minute; its port is in $AGENT_PORT.
snmp_agent() {
    local pf="${BATS_TEST_TMPDIR}/snmp-agent.port"
    rm -f "$pf"
    "$T" _snmp-agent --port-file "$pf" --seconds 60 --sysname "$1" --community "$2" > /dev/null 2>&1 3>&- &
    SNMP_PID=$!
    local _
    for _ in $(seq 50); do
        [[ -s "$pf" ]] && break
        sleep 0.1
    done
    AGENT_PORT=$(cat "$pf")
}

# as_engineer <name> -- <tacctl args...>: 'sudo tacctl' by an engineer (a
# superuser of the store whose group is given the engineer tier).
as_engineer() {
    local name="$1"; shift 2
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER="$name" run "$T" "$@"
}

@test "device snmp: nothing set shows the built-in values and writes nothing" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    before=$(cat "$DEVICES")
    run "$T" device snmp lab-sw1
    assert_success
    plain
    assert_output --partial "SNMP for device 'lab-sw1'"
    assert_output --partial "version:    not set"
    assert_output --partial "port:       161  (built-in)"
    assert_output --partial "timeout:    2 s, one retry  (built-in)"
    assert_output --partial "order:      the device's own setting, then its scope's, then the default's, then the built-in"
    [[ "$(cat "$DEVICES")" == "$before" ]]
    [[ ! -e "$SNMPDIR" ]]
    run "$T" device snmp nosuch
    assert_failure 1
    assert_output --partial "Device 'nosuch' not found."
}

@test "device snmp: version, port, timeout and clients are the registry's map; clear gives the file back byte for byte" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    before=$(cat "$DEVICES")
    run "$T" device snmp lab-sw1 version v3
    assert_success
    "$T" device snmp lab-sw1 port 2161 > /dev/null
    "$T" device snmp lab-sw1 timeout 7 > /dev/null
    run "$T" device snmp lab-sw1 clients add 192.0.2.0/24,192.0.2.7/32
    assert_success
    plain
    assert_output --partial "Added 2 allowed SNMP client range(s) to device 'lab-sw1': 192.0.2.0/24 192.0.2.7/32"
    run grep -E "snmp|version: v3|port: 2161|timeout: 7|192.0.2.0/24" "$DEVICES"
    assert_success
    [[ "$(mode "$DEVICES")" == 600 ]]
    run "$T" device snmp lab-sw1
    plain
    assert_output --partial "version:    v3 (the user, authPriv)  (device)"
    assert_output --partial "port:       2161  (device)"
    assert_output --partial "timeout:    7 s, one retry  (device)"
    assert_output --partial "192.0.2.7/32"
    run "$T" device snmp lab-sw1 port 0
    assert_failure 1
    assert_output --partial "Invalid UDP port '0': expected 1-65535."
    run "$T" device snmp lab-sw1 clients add 0.0.0.0/0
    assert_failure 1
    assert_output --partial "would allow every address"
    run "$T" device snmp lab-sw1 clear
    assert_success
    [[ "$(cat "$DEVICES")" == "$before" ]]
}

@test "device snmp: the credentials are a file of the device's own (0600, in a 0700 directory), never printed but by --reveal, and never in devices.yaml" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    run "$T" device snmp lab-sw1 community
    assert_failure 1
    assert_output --partial "No terminal to ask for the community on; pipe it in with --stdin."
    printf 'dev-community-bats\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    f="${SNMPDIR}/devices/lab-sw1.yaml"
    [[ "$(mode "$f")" == 600 ]]
    [[ "$(mode "${SNMPDIR}/devices")" == 700 ]]
    [[ "$(mode "$SNMPDIR")" == 700 ]]
    run grep -c "dev-community-bats" "$DEVICES"
    assert_output "0"
    run "$T" device snmp lab-sw1 show
    assert_success
    refute_output --partial "dev-community-bats"
    plain
    assert_output --partial "version:    v2c (the community)  (device)"
    assert_output --partial "community:  set  (device)"
    run "$T" device snmp lab-sw1 show --reveal
    plain
    assert_output --partial "community:  dev-community-bats  (device)"
    run "$T" device show lab-sw1
    plain
    assert_output --partial "credentials: community set (device)"
    refute_output --partial "dev-community-bats"
    run "$T" device show lab-sw1 --json
    refute_output --partial "dev-community-bats"
    assert_output --partial '"community_from": "device"'
    # v3 user: both passphrases, one level.
    printf 'dev-auth-pass-1\ndev-priv-pass-1\n' | "$T" device snmp lab-sw1 v3-user carol --stdin > /dev/null
    run "$T" device snmp lab-sw1 show --reveal
    plain
    assert_output --partial "v3 user:    carol  (device)"
    assert_output --partial "auth dev-auth-pass-1, priv dev-priv-pass-1  (device)"
    run "$T" device snmp lab-sw1 clear
    assert_success
    [[ ! -e "$f" ]]
    [[ ! -e "${SNMPDIR}/devices" ]]
}

@test "device snmp: the device's value, then the scope's, then the default's, then the built-in; every view says which" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    "$T" device add lab-sw2 192.168.1.2 --vendor juniper --no-host-key --no-lookup > /dev/null
    printf 'def-community-bats\n' | "$T" config snmp community --stdin > /dev/null
    "$T" config snmp port 1161 > /dev/null
    printf 'lab-community-bats\n' | "$T" scope snmp lab community --stdin > /dev/null
    "$T" scope snmp lab timeout 4 > /dev/null
    "$T" scope snmp lab clients add 198.51.100.0/24 > /dev/null
    "$T" device snmp lab-sw1 port 2161 > /dev/null
    run "$T" device snmp lab-sw1 show
    plain
    assert_output --partial "port:       2161  (device)"
    assert_output --partial "timeout:    4 s, one retry  (scope lab)"
    assert_output --partial "community:  set  (scope lab)"
    run "$T" device snmp lab-sw2 show
    plain
    assert_output --partial "port:       1161  (default)"
    run "$T" device show lab-sw1
    plain
    assert_output --partial "version v2c (scope lab), port 2161 (device), timeout 4 s (scope lab)"
    assert_output --partial "credentials: community set (scope lab)"
    assert_output --partial "clients: 1 range(s) (scope lab), after the tacctl server"
    run "$T" scope snmp lab show
    plain
    assert_output --partial "order:      a device's own setting first (tacctl device snmp <name>), then the scope's, then the default's, then the built-in"
    assert_output --partial "devices with settings of their own: lab-sw1 (port)"
    # The walkthrough of the device: its own community and ranges, said so.
    "$T" device snmp lab-sw1 clients add 192.0.2.0/24 > /dev/null
    printf 'dev-community-bats\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    run "$T" device config show lab-sw1 --source 10.0.0.42
    assert_success
    plain
    assert_output --partial "snmp-server community dev-community-bats RO TACCTL-SNMP"
    assert_output --partial "Credentials: this device's own (tacctl device snmp lab-sw1 show --reveal)."
    assert_output --partial "Allowed clients: the tacctl server first, this device's own ranges"
    assert_output --partial "permit 192.0.2.0 0.0.0.255"
    refute_output --partial "198.51.100.0"
    run "$T" device config show lab-sw2 --source 10.0.0.42
    assert_output --partial "set snmp community lab-community-bats"
    assert_output --partial "198.51.100.0"
}

@test "device snmp: a rename moves the credentials, a removal drops them, a leftover is never picked up" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    printf 'c-one\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    run "$T" device rename lab-sw1 core-1
    assert_success
    [[ ! -e "${SNMPDIR}/devices/lab-sw1.yaml" ]]
    [[ "$(mode "${SNMPDIR}/devices/core-1.yaml")" == 600 ]]
    run "$T" device snmp core-1 show --reveal
    assert_output --partial "c-one"
    mkdir -p "${SNMPDIR}/devices"
    printf 'version: 1\ncommunity: stranger\n' > "${SNMPDIR}/devices/other.yaml"
    run "$T" device rename core-1 other
    assert_failure
    assert_output --partial "SNMP credentials for a device named 'other' are already on disk"
    run "$T" device add other 192.168.1.9 --no-host-key --no-lookup
    assert_failure
    assert_output --partial "SNMP credentials for a device named 'other' are already on disk"
    rm "${SNMPDIR}/devices/other.yaml"
    run "$T" device remove core-1 -y
    assert_success
    [[ ! -e "${SNMPDIR}/devices" ]]
}

@test "device snmp: the sysName lookup of device check uses the device's own community and port" {
    snmp_agent sw1.site-a.example device-right
    printf 'default-wrong\n' | "$T" config snmp community --stdin > /dev/null
    "$T" config snmp timeout 1 > /dev/null
    "$T" device add sw1 127.0.0.1 --no-host-key --no-lookup > /dev/null
    run "$T" device check sw1
    plain
    assert_output --partial "SNMP name:   no answer"
    printf 'device-right\n' | "$T" device snmp sw1 community --stdin > /dev/null
    "$T" device snmp sw1 port "$AGENT_PORT" > /dev/null
    "$T" device snmp sw1 timeout 1 > /dev/null
    run "$T" device check sw1
    assert_success
    plain
    assert_output --partial "SNMP:        version v2c (device), port ${AGENT_PORT} (device), timeout 1 s (device)"
    assert_output --partial "SNMP creds:  community set (device)"
    assert_output --partial "SNMP name:   sw1.site-a.example  (match)"
    refute_output --partial "device-right"
    run "$T" device check sw1 --json
    assert_output --partial '"sysname": "sw1.site-a.example"'
    assert_output --partial '"community_from": "device"'
    refute_output --partial "device-right"
}

@test "device snmp: a snapshot holds the credentials and a restore brings them back" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    printf 'dev-community-one\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    "$T" group add extra 5 EXTRA-CLASS > /dev/null
    id=$("$T" backup list | awk '/^ *[0-9]/{print $1; exit}')
    [[ -n "$id" ]]
    printf 'dev-community-two\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    run "$T" device snmp lab-sw1 show --reveal
    assert_output --partial "dev-community-two"
    run bash -c 'printf "y\n" | "$1" backup restore "$2"' _ "$T" "$id"
    assert_success
    run "$T" device snmp lab-sw1 show --reveal
    assert_output --partial "dev-community-one"
    [[ "$(mode "${SNMPDIR}/devices/lab-sw1.yaml")" == 600 ]]
}

@test "tier: an engineer reads the SNMP settings of a device of their own scope (logged on --reveal) and changes none" {
    "$T" user add en superuser --hash "$(printf 'x' | python3 -c 'import bcrypt,binascii,sys;print(binascii.hexlify(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(rounds=4))).decode())')" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    printf 'dev-community-bats\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    as_engineer en -- device snmp lab-sw1 show
    assert_success
    refute_output --partial "dev-community-bats"
    if stub_called "secret-read kind=snmp-device"; then echo "plain show was logged"; return 1; fi
    as_engineer en -- device snmp lab-sw1 show --reveal
    assert_success
    assert_output --partial "dev-community-bats"
    stub_called "logger -t tacctl -p auth.info secret-read kind=snmp-device name=lab-sw1 by=en"
    run grep -c "secret-read.*dev-community-bats" "$CALLS_LOG"
    assert_output "0"
    local args
    for args in "community --stdin" "version v3" "clients add 192.0.2.0/24" "port 162" "timeout 3" "clear"; do
        # shellcheck disable=SC2086
        as_engineer en -- device snmp lab-sw1 $args
        assert_failure
        assert_output --partial "The engineer tier reads a device's SNMP settings"
    done
    run "$T" device snmp lab-sw1 show --reveal
    assert_output --partial "dev-community-bats"
}

@test "device snmp: a credentials file that cannot be parsed is cleared without being read, or replaced by a new credential" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    "$T" device snmp lab-sw1 version v2c > /dev/null
    mkdir -p "${SNMPDIR}/devices"
    printf 'version: 1\nbogus: [unclosed\n' > "${SNMPDIR}/devices/lab-sw1.yaml"
    chmod 600 "${SNMPDIR}/devices/lab-sw1.yaml"
    run "$T" device snmp lab-sw1
    assert_failure 1
    assert_output --partial "lab-sw1.yaml"
    assert_output --partial "Remove the unreadable file with: tacctl device snmp lab-sw1 clear"
    run "$T" scope snmp lab show
    plain
    assert_output --partial "lab-sw1 (credentials file unreadable: tacctl device snmp lab-sw1 clear)"
    run "$T" device snmp lab-sw1 clear
    assert_success
    [[ ! -e "${SNMPDIR}/devices" ]]
    "$T" device snmp lab-sw1 version v2c > /dev/null
    mkdir -p "${SNMPDIR}/devices"
    printf 'version: 1\nbogus: [unclosed\n' > "${SNMPDIR}/devices/lab-sw1.yaml"
    run bash -c 'printf "fresh-community\n" | "$1" device snmp lab-sw1 community --stdin' _ "$T"
    assert_success
    assert_output --partial "was unreadable"
    assert_output --partial "it is replaced"
    run "$T" device snmp lab-sw1 show --reveal
    plain
    assert_output --partial "community:  fresh-community  (device)"
}

@test "device snmp: a restore of a snapshot made before the credentials leaves no file of a device the registry has no map for" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    "$T" group add extra 5 EXTRA-CLASS > /dev/null
    id=$("$T" backup list | awk '/^ *[0-9]/{print $1; exit}')
    [[ -n "$id" ]]
    printf 'dev-community-one\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    [[ -f "${SNMPDIR}/devices/lab-sw1.yaml" ]]
    run bash -c 'printf "y\n" | "$1" backup restore "$2"' _ "$T" "$id"
    assert_success
    [[ ! -e "${SNMPDIR}/devices/lab-sw1.yaml" ]]
    run "$T" device snmp lab-sw1 show --reveal
    plain
    refute_output --partial "dev-community-one"
    assert_output --partial "version:    not set"
}

@test "tier: below the engineer tier a device's SNMPv3 user is 'set', not its name" {
    local hash
    hash=$(printf 'x' | python3 -c 'import bcrypt,binascii,sys;print(binascii.hexlify(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(rounds=4))).decode())')
    "$T" user add op operator --hash "$hash" --scopes lab > /dev/null
    "$T" user add en superuser --hash "$hash" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    printf 'auth-pass-bats-1\npriv-pass-bats-1\n' | "$T" device snmp lab-sw1 v3-user svc-reader --stdin > /dev/null
    run "$T" device show lab-sw1
    plain
    assert_output --partial "v3 user svc-reader, passphrases set (device)"
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=op run "$T" device show lab-sw1
    assert_success
    plain
    assert_output --partial "v3 user set, passphrases set (device)"
    refute_output --partial "svc-reader"
    SUDO_USER=op run "$T" device show lab-sw1 --json
    refute_output --partial "svc-reader"
    assert_output --partial '"v3_user_set": true'
    SUDO_USER=en run "$T" device show lab-sw1 --json
    assert_output --partial '"v3_user": "svc-reader"'
}

@test "device snmp: a credentials file with no snmp map beside it (a rollback to 0.2.3 leaves it) is ignored until the device has settings again" {
    "$T" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    printf 'scope-community-bats\n' | "$T" scope snmp lab community --stdin > /dev/null
    printf 'dev-community-bats\n' | "$T" device snmp lab-sw1 community --stdin > /dev/null
    "$T" device snmp lab-sw1 port 2161 > /dev/null
    # What the rollback leaves: the file, and no map.
    python3 - "$DEVICES" << 'EOF2'
import re, sys
t = open(sys.argv[1]).read()
t = re.sub(r',? ?snmp: \{[^}]*\}', '', t)
t = re.sub(r'\n    snmp:\n(      .*\n)+', '\n', t)
open(sys.argv[1], 'w').write(t)
EOF2
    run grep -c "snmp:" "$DEVICES"
    assert_output "0"
    [[ -f "${SNMPDIR}/devices/lab-sw1.yaml" ]]
    run "$T" device snmp lab-sw1 show --reveal
    assert_success
    plain
    assert_output --partial "community:  scope-community-bats  (scope lab)"
    assert_output --partial "port:       161  (built-in)"
    assert_output --partial "credentials file present but the device has no settings of its own (ignored): tacctl device snmp lab-sw1 clear removes it, or set its settings"
    refute_output --partial "dev-community-bats"
    run "$T" device show lab-sw1
    plain
    assert_output --partial "credentials: community set (scope lab)"
    assert_output --partial "(ignored)"
    run "$T" scope snmp lab show
    plain
    refute_output --partial "devices with settings of their own"
    run "$T" device snmp lab-sw1 version v2c
    assert_success
    assert_output --partial "ignored until now, is in force"
    run "$T" device snmp lab-sw1 show --reveal
    plain
    assert_output --partial "community:  dev-community-bats  (device)"
}

