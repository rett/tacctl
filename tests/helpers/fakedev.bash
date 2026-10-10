#!/usr/bin/env bash
# The fake network device of the device configuration tests: a test build's
# hidden verb 'tacctl _fake-device <dir>' (internal/devssh/fakedev) answers
# ssh and NETCONF on a loopback port from the transcript files of <dir>
# (tests/fixtures/devconf/fake/README.md), and TACCTL_TEST_DEVICE_DIAL sends
# every device a pull logs in to there. Requires helpers/setup and
# $BATS_TEST_TMPDIR.

# fakedev_dir <junos|ios>
# A fresh transcript directory (a copy of the fixture's) for the test; its
# path is on stdout.
fakedev_dir() {
    local d="${BATS_TEST_TMPDIR}/fakedev-$1"
    rm -rf "$d"
    mkdir -p "$d"
    cp -r "${TACCTL_SRC}/tests/fixtures/devconf/fake/$1/." "$d/"
    printf '%s' "$d"
}

# fakedev_start <dir> [_fake-device options]
# Starts the fake device, waits until it listens, and sets FAKEDEV_ADDR,
# FAKEDEV_KEY (the '<type> <base64>' text devices.yaml pins), FAKEDEV_PID, and
# exports TACCTL_TEST_DEVICE_DIAL. The login it accepts is $FAKEDEV_USER
# with $FAKEDEV_PASSWORD (default: alice, fakedev-secret-pw); the pull's
# password is TACCTL_TEST_DEVICE_PASSWORD.
fakedev_start() {
    local dir="$1"; shift
    FAKEDEV_USER="${FAKEDEV_USER:-alice}"
    FAKEDEV_PASSWORD="${FAKEDEV_PASSWORD:-fakedev-secret-pw}"
    FAKEDEV_INFO="${BATS_TEST_TMPDIR}/fakedev.info"
    rm -f "$FAKEDEV_INFO"
    # fd 3 closed: bats waits on it, and a background server holds it open.
    "$TACCTL_BIN_SCRIPT" _fake-device "$dir" --user "$FAKEDEV_USER" --password "$FAKEDEV_PASSWORD" \
        --info-file "$FAKEDEV_INFO" --seconds 300 "$@" > /dev/null 2>&1 3>&- &
    FAKEDEV_PID=$!
    local _
    for _ in $(seq 1 100); do
        [[ -s "$FAKEDEV_INFO" ]] && [[ "$(wc -l < "$FAKEDEV_INFO")" -ge 2 ]] && break
        sleep 0.1
    done
    [[ -s "$FAKEDEV_INFO" ]] || { echo "fakedev_start: the fake device did not start" >&2; return 1; }
    FAKEDEV_ADDR=$(sed -n 1p "$FAKEDEV_INFO")
    FAKEDEV_KEY=$(sed -n 2p "$FAKEDEV_INFO")
    export FAKEDEV_ADDR FAKEDEV_KEY FAKEDEV_PID
    export TACCTL_TEST_DEVICE_DIAL="$FAKEDEV_ADDR"
    export TACCTL_TEST_DEVICE_PASSWORD="$FAKEDEV_PASSWORD"
}

# fakedev_stop: ends the fake device (teardown calls it).
fakedev_stop() {
    if [[ -n "${FAKEDEV_PID:-}" ]]; then
        kill "$FAKEDEV_PID" 2> /dev/null || true
        wait "$FAKEDEV_PID" 2> /dev/null || true
        FAKEDEV_PID=
    fi
}

# fakedev_register <name> <address> <vendor> [<name> <address> <vendor>]...
# Writes the device registry: each device pinned to the fake device's key
# (the pull dials the fake whatever the address says).
fakedev_register() {
    local f="${TACCTL_STATE_DIR}/devices.yaml"
    {
        printf 'version: 1\nsettings:\n  stale_days: 30\ndevices:\n'
        while (( $# >= 3 )); do
            printf '  %s:\n    address: %s\n    vendor: %s\n    host_keys:\n    - %s\n' "$1" "$2" "$3" "$FAKEDEV_KEY"
            shift 3
        done
    } > "$f"
    chmod 600 "$f"
}

# fakedev_serve <dir> <junos|cisco> <scope> [<name>]
# Makes the device answer its read command with what tacctl's walkthrough for
# <scope> carries as statements: the configuration a device that agrees with
# tacctl runs.
fakedev_serve() {
    local dir="$1" vendor="$2" scope="$3"
    local out
    out=$("$TACCTL_BIN_SCRIPT" config "$vendor" --scope "$scope" ${4:+--name "$4"}) || return 1
    # The walkthrough's colour is stripped with sed (a pattern, not a plain
    # substitution).
    # shellcheck disable=SC2001
    if [[ "$vendor" == "juniper" ]]; then
        sed 's/\x1b\[[0-9;]*m//g' <<< "$out" | grep '^set ' > "${dir}/show configuration | display inheritance no-comments | display set.out"
    else
        {
            printf 'version 15.2\nhostname %s\n!\n' "${4:-fake}"
            sed 's/\x1b\[[0-9;]*m//g' <<< "$out" | grep -E '^(aaa |tacacs|radius|privilege|ip access-list|snmp-server|line vty|username |netconf-yang| +[a-z])'
            printf 'end\n'
        } > "${dir}/show running-config.out"
    fi
}
