#!/usr/bin/env bats
# Integration tests for `tacctl device config pull`: the real ssh and NETCONF
# exchange of a pull, against the fake device of a test build (`tacctl
# _fake-device`, internal/devssh/fakedev), reached through
# TACCTL_TEST_DEVICE_DIAL. The pieces are pinned by the Go tests of devssh,
# devconf and batch; these pin the wiring: the login as the invoking user,
# the pinned key, the records, the audit line, the exit statuses.

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
    JDIR=$(fakedev_dir junos)
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# pull <args...>: as alice, a superuser of prod and lab.
pull() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config pull "$@"
    plain
}

@test "pull: one Junos device over NETCONF, recorded, audited, in device list and show" {
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
    pull lab-j
    assert_success
    assert_line --regexp '^  lab-j  ok via netconf$'
    assert_output --partial "1 ok"
    # The record, root's 0600 file, and the sections file beside it.
    [[ "$(stat -c %a "${TACCTL_VAR_LIB}/devices-config.json")" == 600 ]]
    [[ "$(stat -c %a "${TACCTL_VAR_LIB}/device-config/lab-j.yaml")" == 600 ]]
    run python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"]["lab-j"]
print(r["result"], r["transport"], r["netconf"], r["by"], r["address"])' "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "ok netconf hello ok alice 192.168.1.20"
    # The audit line: who, which device, over what, with what result.
    stub_called 'logger -t tacctl -p auth.info device config pull user=alice device=lab-j transport=netconf result=ok duration='
    # Nothing of the password anywhere it must not be.
    run grep -r "$FAKEDEV_PASSWORD" "$CALLS_LOG" "${TACCTL_VAR_LIB}" "${TACCTL_STATE_DIR}"
    assert_failure
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device list
    plain
    assert_success
    assert_output --partial "CONFIG"
    assert_line --regexp '^ *lab-j .* ok +-'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show lab-j
    plain
    assert_line --regexp '^  Configuration: pulled .* by alice over netconf \(hello ok\), ok; sections: aaa '
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device check lab-j --json
    assert_success
    run python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[0]["netconf"])' <<< "$output"
    assert_output "hello ok"
}

@test "pull --all: three devices at once, one summary, --json lines" {
    fakedev_start "$JDIR"
    fakedev_register lab-a 192.168.1.21 juniper lab-b 192.168.1.22 juniper lab-c 192.168.1.23 juniper
    fakedev_serve "$JDIR" juniper lab
    pull --all --concurrency 2
    assert_success
    assert_output --partial "3 ok"
    pull --all --json --concurrency 2
    assert_success
    [[ "${#lines[@]}" -eq 4 ]]
    run python3 -c '
import json, sys
docs = [json.loads(l) for l in sys.stdin.read().splitlines()]
assert sorted(d["name"] for d in docs[:3]) == ["lab-a", "lab-b", "lab-c"], docs
assert all(d["status"] == "ok" and d["transport"] == "netconf" for d in docs[:3]), docs
s = docs[3]["summary"]
assert s["ok"] == 3 and s["failed"] == 0 and s["exit"] == 0 and s["pool"] == 2, s
print("fine")' <<< "$output"
    assert_output "fine"
}

@test "pull: a wrong password stops the batch at the first rejection and says so" {
    fakedev_start "$JDIR"
    fakedev_register lab-a 192.168.1.21 juniper lab-b 192.168.1.22 juniper lab-c 192.168.1.23 juniper
    fakedev_serve "$JDIR" juniper lab
    TACCTL_TEST_DEVICE_PASSWORD="not-the-password-77" pull --all --concurrency 1
    assert_failure 1
    assert_line --regexp '^  lab-a  failed: authentication failed$'
    assert_output --partial "stopped at the first authentication failure: 2 not started"
    refute_output --partial "not-the-password-77"
    # The record of the rejection; nothing of the devices that were not tried.
    run python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["devices"]
print(sorted(d), d["lab-a"]["result"])' "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "['lab-a'] auth-failed"
}

@test "pull: no pinned host key, a different key, and the invoking user are checked first" {
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    # Unpinned: refused before any connection, with the command to run.
    sed -i '/host_keys:/,$d' "${TACCTL_STATE_DIR}/devices.yaml"
    pull lab-j
    assert_failure 1
    assert_output --partial "failed: no host key is pinned for the device"
    assert_output --partial "tacctl device hostkey lab-j accept"
    # A key that is not the pinned one: refused, never a prompt.
    fakedev_register lab-j 192.168.1.20 juniper
    sed -i "s|ssh-ed25519 .*|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl|" "${TACCTL_STATE_DIR}/devices.yaml"
    pull lab-j
    assert_failure 1
    assert_output --partial "failed: the device offered a host key (ssh-ed25519 SHA256:"
    assert_output --partial "that is not pinned"
    run python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["devices"]["lab-j"]["result"])' \
        "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "host-key-mismatch"
    # root, and no SUDO_USER at all, log in as nobody.
    SUDO_USER=root run "$TACCTL_BIN_SCRIPT" device config pull lab-j
    assert_failure 1
    assert_output --partial "logs in to the devices as the user who invoked it"
    run "$TACCTL_BIN_SCRIPT" device config pull lab-j
    assert_failure 1
    assert_output --partial "logs in to the devices as the user who invoked it"
}

@test "pull: --concurrency never exceeds device.config.max_concurrency; config devices sets it" {
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
    pull lab-j --concurrency 9
    assert_failure 2
    assert_output --partial "--concurrency 9 is above device.config.max_concurrency (8)."
    assert_output --partial "tacctl config devices max-concurrency <n>"
    run "$TACCTL_BIN_SCRIPT" config devices max-concurrency 16
    assert_success
    pull lab-j --concurrency 9
    assert_success
    pull lab-j --concurrency 0
    assert_failure 2
    pull lab-j --timeout 5
    assert_failure 2
    assert_output --partial "--timeout takes seconds per device, 10 to 600"
}

@test "pull: a Cisco device is read over the ssh command line" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    fakedev_serve "$cdir" cisco lab lab-c
    pull lab-c
    assert_success
    assert_line --regexp '^  lab-c  ok.* via ssh'
    # NETCONF is not read for Cisco: refused before any login, with no record
    # of it, so a device never pulled stays never (and stale), and the record
    # of a good pull is left as it was.
    fakedev_register lab-c 192.168.1.30 cisco lab-c2 192.168.1.31 cisco
    pull lab-c --transport netconf
    assert_failure 2
    assert_output --partial "NETCONF is not read for Cisco devices"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_line --regexp '^ *lab-c .* (ok|differs) .* alice +ssh '
    pull lab-c2 --transport netconf
    assert_failure 2
    assert_output --partial "Nothing was tried."
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list --stale
    plain
    assert_output --partial "lab-c2"
    assert_line --regexp '^ *lab-c2 .* never '
    refute_output --partial "unsupported"
    # A Cisco device has no NETCONF row in its check.
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device check lab-c
    plain
    refute_output --partial "NETCONF:"
}

@test "pull: NETCONF off falls back to ssh under auto and says why; netconf does not fall back" {
    fakedev_start "$JDIR" --netconf off
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
    pull lab-j
    assert_success
    assert_line --regexp '^  lab-j  ok via ssh \(netconf: port closed\)$'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device check lab-j
    plain
    assert_line --regexp '^  NETCONF: +port closed \(probed '
    pull lab-j --transport netconf
    assert_failure 1
    assert_output --partial "failed: NETCONF is not enabled on the device"
    pull lab-j --transport ssh
    assert_success
    assert_line --regexp '^  lab-j  ok via ssh$'
}

@test "pull: what a device runs beyond tacctl's statements is a difference, and no secret value is printed or kept" {
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
    local f="${JDIR}/show configuration | display inheritance no-comments | display set.out"
    printf '%s\n' 'set system tacplus-server 192.0.2.99 secret "$9$STRAY-KEY-VALUE-xyz"' \
        'set snmp community stray-community-shhh authorization read-only' >> "$f"
    pull lab-j --diff
    assert_success
    assert_output --partial "ok, differs in"
    assert_output --partial "+ set system tacplus-server 192.0.2.99 secret (present, not compared)"
    refute_output --partial "STRAY-KEY-VALUE-xyz"
    refute_output --partial "stray-community-shhh"
    run grep -r "STRAY-KEY-VALUE-xyz\|stray-community-shhh" "${TACCTL_VAR_LIB}"
    assert_failure
}
