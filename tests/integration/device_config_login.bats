#!/usr/bin/env bats
# Integration tests for '--login <local-user>' on `tacctl device config
# pull|diff --pull|plan --pull` (plan D136): one registered Junos device read
# as one of its local accounts, the superuser's only, against the fake
# device's blank configure model (tests/fixtures/devconf/fake/junos-blank).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

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
    fakedev_register example-sw5 192.168.1.31 juniper example-sw6 192.168.1.32 juniper
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//' <<< "$output")
    mapfile -t lines <<< "$output"
}

# cfg <args...>: 'device config <args>' as alice, no terminal, the local
# password from the test knob.
cfg() {
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD="$LOCAL_PW" run "$TACCTL_BIN_SCRIPT" device config "$@"
    plain
}

record() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"].get(sys.argv[2], {})
print(r.get(sys.argv[3], ""))' "${TACCTL_VAR_LIB}/devices-config.json" "$1" "$2"
}

@test "--login: engineers and above; an operator is the tier denial" {
    stub_cmd id 'echo "users tac-users tac-operator"'
    SUDO_USER=bob TACCTL_TEST_LOCAL_PASSWORD="$LOCAL_PW" run "$TACCTL_BIN_SCRIPT" device config pull example-sw5 --login admin
    plain
    assert_failure 1
    assert_output --partial "is not permitted for the operator tier."
    stub_called "tier DENY user=bob tier=operator cmd=device config pull"
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]]
}

@test "--login: one device by name; a selection is a usage error" {
    for sel in "--all" "--scope lab" "--vendor juniper" "--stale" "example-sw5,example-sw6"; do
        # shellcheck disable=SC2086
        cfg pull $sel --login admin
        assert_failure 2
        assert_output --partial "--login logs in to one device as its local account"
    done
    cfg diff example-sw5 --login admin
    assert_failure 2
    assert_output --partial "give --pull with it"
    cfg plan example-sw5 --login 'a b'
    assert_failure 2
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]]
}

@test "--login: the pull as the local account, recorded and logged, never the user's password" {
    # no password of the user's is at hand: the local login asks none
    unset TACCTL_TEST_DEVICE_PASSWORD
    cfg pull example-sw5 --login admin
    assert_success
    assert_output --partial "example-sw5"
    [[ "$(record example-sw5 login)" == local:admin ]]
    [[ "$(record example-sw5 by)" == alice ]]
    [[ "$(record example-sw5 result)" == ok ]]
    stub_called "logger -t tacctl -p auth.info device config pull user=alice device=example-sw5 login=local:admin"
    stub_called "device config pull user=alice device=example-sw5 transport=.* result=ok .* login=local:admin"
    run grep -r -e "$LOCAL_PW" "$CALLS_LOG" "${TACCTL_VAR_LIB}"
    assert_failure
    # plan --pull as the local account
    cfg plan example-sw5 --pull --login admin
    assert_success
    assert_output --partial "set system tacplus-server 10.0.0.42"
}

@test "--login: without a terminal and without the knob the password cannot be asked" {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config pull example-sw5 --login admin
    plain
    assert_failure 1
    assert_output --partial "the password of a local account is asked on a terminal, and there is none; nothing was sent"
}

@test "--login root: through the wrapper, and only on a device never read as the user" {
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD=root-fakedev-pw run "$TACCTL_BIN_SCRIPT" device config pull example-sw5 --login root
    plain
    assert_success
    [[ "$(record example-sw5 login)" == local:root ]]
    # read as alice: root is refused from then on
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config pull example-sw5
    assert_success
    SUDO_USER=alice TACCTL_TEST_LOCAL_PASSWORD=root-fakedev-pw run "$TACCTL_BIN_SCRIPT" device config diff example-sw5 --pull --login root
    plain
    assert_failure 1
    assert_output --partial "--login root is for a device that was never read as your own login"
    cfg pull example-sw5 --login root --transport netconf
    assert_failure 2
}

@test "--login: any local account, a break-glass one included; a held device is refused" {
    cfg pull example-sw5 --login bgadmin
    assert_success
    [[ "$(record example-sw5 login)" == local:bgadmin ]]
    stub_called "device config pull user=alice device=example-sw5 login=local:bgadmin"
    printf 'breakglass_hold:\n  example-sw5:\n    address: 192.168.1.31\n    since: "2026-10-13T00:00:00Z"\n    by: alice\n    reason: console recovery\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    cfg pull example-sw5 --login bgadmin
    assert_failure 1
    assert_output --partial "break-glass is held on example-sw5"
    assert_output --partial "release it first"
}
