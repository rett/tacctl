#!/usr/bin/env bats
# Integration tests for the transport of `tacctl device config apply`
# (--transport auto|cli|netconf and device.apply.transport): the check and
# the apply over NETCONF against the fake Junos device with a configure
# model of a test build (`tacctl _fake-device`, internal/devssh/fakedev,
# tests/fixtures/devconf/fake/junos-apply), reached through
# TACCTL_TEST_DEVICE_DIAL. The transaction is pinned per transport by the Go
# tests of devapply; these pin the wiring: the words of the lines, the JSON,
# the record, the setting and the refusals.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    unset FAKEDEV_USER FAKEDEV_PASSWORD FAKEDEV_PID
    JDIR=$(fakedev_dir junos-apply)
    # the CLI echoes a command as typed, with no trailing blank
    : > "${JDIR}/echo.plain"
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//' <<< "$output")
    mapfile -t lines <<< "$output"
}

start() {
    fakedev_start "$JDIR"
    fakedev_register example-sw1 192.168.1.20 juniper
    # one session, so that the fake has written the configuration it runs
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device config pull example-sw1 > /dev/null 2>&1
    rm -rf "${TACCTL_VAR_LIB}/device-config" "${TACCTL_VAR_LIB}/devices-config.json"
    : > "$CALLS_LOG"
}

apply() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config apply "$@"
    plain
}

committed() {
    if [[ -f "${JDIR}/committed.set" ]]; then cat "${JDIR}/committed.set"; else cat "${JDIR}/config.set"; fi
}

# applied <field>: a field of the device's apply record.
applied() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
v = (r.get("applied") or {}).get(sys.argv[3], "")
print(v if not isinstance(v, (list, dict)) else json.dumps(v))' "${TACCTL_VAR_LIB}/devices-config.json" example-sw1 "$1"
}

@test "apply --transport: only auto, cli and netconf; ssh is the read's word" {
    start
    apply example-sw1 --check --transport ssh
    assert_failure 2
    assert_output --partial "--transport takes auto, cli or netconf: 'ssh'"
}

@test "apply --check --transport netconf: the check over the subsystem, the record says so" {
    start
    before=$(committed)
    apply example-sw1 --check --transport netconf
    assert_success
    assert_line --regexp '^  example-sw1  checked: shape [0-9a-f]{12} \(new\) .* \[via netconf\]$'
    [[ "$(committed)" == "$before" ]]
    [[ "$(applied via)" == netconf ]]
    [[ "$(applied kind)" == check ]]
    run python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"]["example-sw1"]
print(r["transport"], r["netconf"])' "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "netconf hello ok"
    # the read has recorded a hello, so auto now takes the subsystem
    apply example-sw1 --check
    assert_success
    assert_output --partial "[via netconf]"
}

@test "apply --check --json: via, via_reason; a never probed device is the command line" {
    start
    apply example-sw1 --check --json
    assert_success
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read().splitlines()[0])
assert d["via"] == "cli" and "not probed" in d["via_reason"], d
print("ok")' <<< "$output"
    assert_output ok
    # and its line says nothing of it
    apply example-sw1 --check
    assert_success
    refute_output --partial "[via"
    [[ "$(applied via)" == cli ]]
}

@test "apply --confirmed --yes --transport netconf: applied through NETCONF, then no change" {
    start
    apply example-sw1 --check
    assert_success
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    assert_success
    before=$(committed)
    apply example-sw1 --confirmed --yes --transport netconf
    assert_success
    assert_line --regexp '^  example-sw1  applied \(.*\) \[tacctl-[0-9A-Za-z-]+\] \[via netconf\]$'
    [[ "$(committed)" != "$before" ]]
    [[ "$(applied result)" == applied ]]
    [[ "$(applied via)" == netconf ]]
    after=$(committed)
    apply example-sw1 --check --transport netconf
    assert_success
    assert_output --partial "no change"
    [[ "$(committed)" == "$after" ]]
}

@test "apply --transport netconf: a device with no NETCONF is failed, nothing is typed over the command line" {
    start
    : > "${JDIR}/netconf.off"
    before=$(committed)
    apply example-sw1 --check --transport netconf
    assert_failure 1
    assert_output --partial "failed: NETCONF: "
    [[ "$(committed)" == "$before" ]]
    # the setting is the command line's way out, and so is auto
    apply example-sw1 --check --transport auto
    assert_success
}

@test "config devices apply-transport: shown, set, validated; --transport replaces it for one run" {
    start
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" config devices apply-transport
    assert_success
    plain
    assert_output --partial "auto"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" config devices apply-transport bogus
    assert_failure
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" config devices apply-transport netconf
    assert_success
    run grep -E '^\s*transport:\s*netconf' "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_success
    # the setting is netconf; the run's flag is the command line
    apply example-sw1 --check --transport cli
    assert_success
    [[ "$(applied via)" == cli ]]
    apply example-sw1 --check
    assert_success
    [[ "$(applied via)" == netconf ]]
}

# --- a change to the NETCONF service: proved by a probe (D148) -------------------

# scope_of: the scope the registered device is covered by.
scope_of() {
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device config apply example-sw1 --check --json 2> /dev/null \
        | python3 -c '
import json, sys
for l in sys.stdin:
    if l.startswith("{"):
        d = json.loads(l)
        if "scope" in d:
            print(d["scope"]); break'
}

set_netconf() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" scope netconf "$1" "$2"
    assert_success
}

seed() {
    apply example-sw1 --check
    assert_success
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    assert_success
}

# probe: the device's NETCONF probe in its record.
probe() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
print(r.get("netconf", ""))' "${TACCTL_VAR_LIB}/devices-config.json" example-sw1
}

@test "apply: enabling the NETCONF service is proved by a hello and the record learns it" {
    start
    : > "${JDIR}/netconf.follow"
    scope=$(scope_of)
    [[ -n "$scope" ]]
    set_netconf "$scope" enable
    seed
    apply example-sw1 --confirmed --yes
    assert_success
    assert_output --partial "applied"
    assert_output --partial "[NETCONF verified: hello ok]"
    run committed
    assert_output --partial "set system services netconf ssh"
    [[ "$(probe)" == "hello ok" ]]
    # the change is made over the command line; it is not an apply over NETCONF
    [[ "$(applied via)" == cli ]]
}

@test "apply: disabling the NETCONF service is proved by a refused hello" {
    start
    : > "${JDIR}/netconf.follow"
    scope=$(scope_of)
    set_netconf "$scope" enable
    seed
    apply example-sw1 --confirmed --yes
    assert_success
    set_netconf "$scope" disable
    seed
    apply example-sw1 --confirmed --yes --json
    assert_success
    assert_output --partial '"service_proof":"NETCONF verified: not answering"'
    run committed
    refute_output --partial "set system services netconf"
    [[ "$(probe)" == "port closed" ]]
    apply example-sw1 --check
    assert_success
    assert_output --partial "no change"
}

@test "apply: a disable that did not take effect is rolled back and the record keeps its probe" {
    start
    : > "${JDIR}/netconf.follow"
    scope=$(scope_of)
    set_netconf "$scope" enable
    seed
    apply example-sw1 --confirmed --yes
    assert_success
    set_netconf "$scope" disable
    seed
    : > "${JDIR}/netconf.disable.noeffect"
    before=$(committed)
    apply example-sw1 --confirmed --yes
    assert_failure 1
    assert_output --partial "still answers NETCONF after the change"
    assert_output --partial "the record's NETCONF probe stays 'hello ok'"
    [[ "$(committed)" == "$before" ]]
    [[ "$(probe)" == "hello ok" ]]
}
