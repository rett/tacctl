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
    # the device's facts: the release from show version, the model and the
    # serial number from the chassis row
    assert_line --regexp '^  Release: +25\.4R1-S2\.3$'
    assert_line --regexp '^  Model: +EX4300-48MP$'
    assert_line --regexp '^  Serial: +FXYZ00000001$'
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

# The Cisco configuration syntax is a fact of its own (D113): legacy-ssh is the
# ssh algorithms, the pull reads the image's version line and the device is
# compared in the syntax that line says.
cisco_record() {
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"]["lab-c"]
print(r.get("syntax", "-"), "|", r.get("os", "-"))' "${TACCTL_VAR_LIB}/devices-config.json"
}

@test "pull: a legacy-ssh Cisco device that runs the modern syntax is ok and records its image" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh lab-c enable
    assert_success
    fakedev_serve "$cdir" cisco lab lab-c
    pull lab-c --diff
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
    refute_output --partial "differs"
    run cisco_record
    assert_output "modern | Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show lab-c
    plain
    assert_line --regexp '^  Legacy ssh: +enabled$'
    assert_line --regexp '^  Config syntax: auto \(modern, from the pull of [0-9-]+\)$'
    assert_line --regexp '^  Release: +15\.6\(2\)T$'
    assert_line --regexp '^  Model: +IOSv$'
    assert_line --regexp '^  Serial: +FXYZ0000001$'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show lab-c --json
    run python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["config_syntax"], d["syntax"], d["syntax_source"], d["legacy_ssh"])' <<< "$output"
    assert_output "auto modern pull True"
}

@test "pull: a legacy-ssh Cisco device that runs IOS 12.x is ok in the IOS 12.x syntax" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh lab-c enable
    assert_success
    FAKEDEV_IOS_SYNTAX=ios12 fakedev_serve "$cdir" cisco lab lab-c
    grep -q '^tacacs-server host' "${cdir}/show running-config.out"
    pull lab-c --diff
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
    refute_output --partial "differs"
    run cisco_record
    assert_output --regexp '^ios12 \| Cisco IOS Software, 7200 Software .*Version 12\.4\(15\)T14'
    # The setting overrides what the line says, and the record keeps the line.
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c modern
    assert_success
    pull lab-c
    assert_success
    assert_output --partial "differs in aaa"
    run cisco_record
    assert_output --regexp '^ios12 \|'
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c auto
    assert_success
    pull lab-c
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
}

@test "pull: a setting that the device's image contradicts wins and is shown by pull, show, list and the walkthrough" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c modern
    assert_success
    # The device runs the modern text and says IOS 12.4.
    fakedev_serve "$cdir" cisco lab lab-c
    printf '%s\n' 'Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 12.4(15)T14, RELEASE SOFTWARE (fc2)' \
        > "${cdir}/show version | include Version.out"
    pull lab-c
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh; warning: config-syntax is modern but the device says IOS 12\.4\(15\)T14 \(ios12 syntax\)$'
    pull lab-c --json
    assert_success
    run python3 -c 'import json,sys; d=json.loads(sys.stdin.readline()); print(d["syntax"], d["syntax_conflict"], d["image_syntax"])' <<< "$output"
    assert_output "modern True ios12"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show lab-c
    plain
    assert_line --regexp '^  Config syntax: modern \(the pull of [0-9-]+ read IOS 12\.4\(15\)T14, which is ios12 syntax, not modern: check the setting\)$'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show lab-c --json
    run python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["syntax"], d["syntax_conflict"], d["image_syntax"])' <<< "$output"
    assert_output "modern True ios12"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_output --partial "config-syntax modern, the pull read ios12"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config show lab-c
    plain
    assert_success
    assert_line --regexp '^# warning: config-syntax of lab-c is modern but the pull of [0-9-]+ read IOS 12\.4\(15\)T14, which is ios12 syntax, not modern; '
    # What the image says silences it all.
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c ios12
    assert_success
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    refute_output --partial "the pull read"
}

@test "pull: a version line no row maps (an ASA registered as cisco, IOS 15.1) is refused, not guessed modern" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    FAKEDEV_IOS_VERSION='Cisco Adaptive Security Appliance Software Version 9.8(4)' fakedev_serve "$cdir" cisco lab lab-c
    pull lab-c
    assert_failure 1
    assert_output --partial "failed: the device's version line \"Cisco Adaptive Security Appliance Software Version 9.8(4)\" is not an image tacctl maps"
    assert_output --partial "tacctl device config-syntax lab-c ios12|modern"
    # Nothing is recorded: the list says what it said before.
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_line --regexp '^ *lab-c .* never '
    printf '%s\n' 'Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.1(4)M, RELEASE SOFTWARE' \
        > "${cdir}/show version | include Version.out"
    pull lab-c
    assert_failure 1
    assert_output --partial "is not an image tacctl maps"
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c modern
    assert_success
    pull lab-c
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
}

@test "pull: a Cisco device that answers no version line needs its setting, and a record of 0.2.4 needs a pull" {
    local cdir
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    FAKEDEV_IOS_VERSION=none fakedev_serve "$cdir" cisco lab lab-c
    pull lab-c
    assert_failure 1
    assert_output --partial "failed: the device's IOS version was not read"
    assert_output --partial "tacctl device config-syntax lab-c ios12|modern"
    # With the setting it is compared, and the record holds no image.
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c modern
    assert_success
    pull lab-c
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
    run cisco_record
    assert_output "- | -"
    run "$TACCTL_BIN_SCRIPT" device config-syntax lab-c auto
    assert_success
    # The record of a pull with no version line is what 0.2.4 wrote: it is
    # not guessed either way, and --stale selects it for the one pull.
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_success
    assert_line --regexp '^ *lab-c .* pull .*needs pull \(syntax unknown\)'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device list
    plain
    assert_line --regexp '^ *lab-c .* pull '
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list --stale
    plain
    assert_output --partial "lab-c"
    fakedev_serve "$cdir" cisco lab lab-c
    printf '%s\n' 'Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)' \
        > "${cdir}/show version | include Version.out"
    pull --stale
    assert_success
    assert_line --regexp '^  lab-c  ok via ssh$'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list --stale
    plain
    assert_output --partial "None: every device"
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
