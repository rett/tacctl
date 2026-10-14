#!/usr/bin/env bats
# Integration tests for `tacctl device config apply` and `device config
# shapes`: the whole transaction (the check on the device, the review, the
# confirmed commit, the fresh login, the confirm) against the fake Junos
# device with a configure model of a test build (`tacctl _fake-device`,
# internal/devssh/fakedev, tests/fixtures/devconf/fake/junos-apply), reached
# through TACCTL_TEST_DEVICE_DIAL. The pieces are pinned by the Go tests of
# devapply, plan and batch; these pin the wiring: the typed answer, the
# records, the audit lines, the exit statuses, and that nothing but the plan
# reaches the device.

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
    SECRET="lab-secret-0123456789abcdef"
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//' <<< "$output")
    mapfile -t lines <<< "$output"
}

# start: the fake device with the fixture's configuration, registered under
# the name it calls itself.
start() {
    fakedev_start "$JDIR"
    fakedev_register example-sw1 192.168.1.20 juniper
    # one session, so that the fake has written the configuration it runs
    # (committed.set) in its own form; the pull's record is then dropped
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device config pull example-sw1 > /dev/null 2>&1
    rm -rf "${TACCTL_VAR_LIB}/device-config" "${TACCTL_VAR_LIB}/devices-config.json"
    : > "$CALLS_LOG"
}

# apply <args...>: as alice, a superuser of prod and lab, with no terminal.
apply() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config apply "$@"
    plain
}

# tapply <typed> <args...>: on a terminal, the lines of <typed> (a printf
# format) typed at it; the output is stdout and stderr, without the
# terminal's carriage returns and colours.
tapply() {
    local typed="$1" cmd rc=0
    shift
    printf -v cmd '%q device config apply' "$TACCTL_BIN_SCRIPT"
    local a
    for a in "$@"; do printf -v cmd '%s %q' "$cmd" "$a"; done
    # shellcheck disable=SC2059
    printf "$typed" | SUDO_USER=alice script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/apply.out" 2>&1 || rc=$?
    status=$rc
    output=$(sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/apply.out")
    mapfile -t lines <<< "$output"
}

# committed: the configuration the device runs (the fake writes committed.set
# at its first commit; until then it is the fixture's).
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

# nothing_secret: no secret and no password in what tacctl keeps or logs.
nothing_secret() {
    run grep -r -e "$SECRET" -e "$FAKEDEV_PASSWORD" "$CALLS_LOG" "${TACCTL_VAR_LIB}"
    assert_failure
}

@test "apply: only a superuser, before any login: an operator and an engineer are refused" {
    start
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" device config apply example-sw1 --check
    assert_failure
    plain
    assert_output --partial "'tacctl device config apply' is not permitted for the operator tier."
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" device config shapes
    assert_failure
    assert_output --partial "not permitted"
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config apply example-sw1 --check
    assert_failure
    plain
    assert_output --partial "'tacctl device config apply' is not permitted for the engineer tier."
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    assert_failure
    assert_output --partial "not permitted for the engineer tier"
    # nothing was dialled or written
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]]
    [[ ! -e "${TACCTL_VAR_LIB}/device-apply" ]]
}

@test "apply --check: the device's own check, nothing committed, the shape and the record kept" {
    start
    before=$(committed)
    apply example-sw1 --check
    assert_success
    assert_line --regexp '^  example-sw1  checked: shape [0-9a-f]{12} \(new\) \(roles, aaa: 17 set, 1 delete\); kept 2; check ok$'
    assert_line "  1 checked"
    assert_output --partial "Nothing was committed"
    # no review, no question
    refute_output --partial "Type "
    [[ "$(committed)" == "$before" ]]
    [[ "$(applied result)" == checked ]]
    [[ "$(applied kind)" == check ]]
    [[ "$(applied shape)" =~ ^[0-9a-f]{12}$ ]]
    [[ "$(applied id)" == tacctl-* ]]
    # the shape store holds the lines, confirmed by nobody
    run python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
(h, e), = m.items()
print(len(e["lines"]) > 0, e["confirmed"])' "${TACCTL_VAR_LIB}/device-apply/shapes.json"
    assert_output "True []"
    [[ "$(stat -c %a "${TACCTL_VAR_LIB}/device-apply/shapes.json")" == 600 ]]
    stub_called 'logger -t tacctl -p auth.info device config apply user=alice device=example-sw1 id=tacctl-'
    nothing_secret
    # the pull part of the record is the read this run made
    run python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["devices"]["example-sw1"]
print(r["result"], r["transport"], r["by"], r["sections"]["roles"]["state"])' "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "ok ssh alice missing"
    # a check of the same device again is the same shape
    first=$(applied shape)
    apply example-sw1 --check
    assert_success
    [[ "$(applied shape)" == "$first" ]]
}

@test "apply --check --json --exit-code: one object per device, the summary, exit 2 for a change" {
    start
    apply example-sw1 --check --json --exit-code
    assert_failure 2
    [[ "${#lines[@]}" -eq 2 ]]
    run python3 -c '
import json, sys
docs = [json.loads(l) for l in sys.stdin.read().splitlines()]
d, s = docs
assert d["name"] == "example-sw1" and d["phase"] == "check" and d["status"] == "checked", d
assert d["set"] == 17 and d["delete"] == 1 and d["sections"] == ["roles", "aaa"], d
assert any(l.startswith("set system tacplus-server 10.0.0.42 secret") for l in d["lines"]), d
assert not any("lab-secret" in l for l in d["lines"]), d
assert s["summary"]["checked"] == 1 and s["summary"]["exit"] == 2, s
print("fine")' <<< "$output"
    assert_output "fine"
}

@test "apply: the review is typed back, then the change is committed, proven and confirmed" {
    start
    tapply 'example-sw1\n' example-sw1
    [[ "$status" -eq 0 ]]
    assert_output --partial "Shape "
    assert_output --partial "1 device (example-sw1), not confirmed yet:"
    assert_output --partial "set system tacplus-server 10.0.0.42 secret <secret>"
    refute_output --partial "$SECRET"
    assert_output --partial "kept: 2 statements of the managed sections that the plan leaves alone"
    assert_output --partial "Apply to example-sw1 under commit confirmed 10 and kept only after a fresh login as alice works and what landed is what the check showed?"
    assert_output --partial "Type the device name to go on:"
    assert_output --regexp "example-sw1  committed, verifying \.\.\."
    assert_output --regexp "example-sw1  applied \(roles,aaa: 17 set, 1 delete\) \[tacctl-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}\]"
    assert_output --partial "1 applied"
    # what the device runs now: the plan, and nothing it was not given
    run committed
    assert_output --partial "set system tacplus-server 10.0.0.42 single-connection"
    assert_output --partial "set system authentication-order tacplus"
    assert_output --partial "set system accounting events change-log"
    assert_output --partial "set system login class RW-CLASS permissions all"
    # the planner's kept statement stays; the statement it replaced is gone
    assert_output --partial "set system tacplus-server 192.0.2.10 source-address 192.0.2.77"
    refute_output --partial "authentication-order password"
    # the device's history: tacctl's two commits with their comments
    [[ "$(applied result)" == applied ]]
    [[ "$(applied kind)" == apply ]]
    id=$(applied id)
    [[ "$(applied commit)" == *'"time"'* ]]
    # the record's pull part is the picture after the change: nothing differs
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    # what tacctl renders is there; the device's own extra server is kept,
    # which is the one thing the aaa section still differs in
    assert_line --regexp "^  example-sw1 .* differs +applied [0-9-]+ [0-9:]+ .* aaa$"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show example-sw1
    plain
    assert_output --regexp "apply: applied [0-9-]+ [0-9:]+ by alice \(${id}, shape [0-9a-f]{12}\)"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config diff example-sw1 --pull
    plain
    assert_success
    assert_output --partial "roles       ok"
    assert_output --partial "+ set system tacplus-server 192.0.2.10 source-address 192.0.2.77"
    refute_output --partial "- set"
    # the audit lines carry no value
    stub_called "logger -t tacctl -p auth.notice device config apply user=alice approved=1 shapes="
    stub_called "logger -t tacctl -p auth.notice device config apply user=alice device=example-sw1 id=${id} shape="
    run grep -F "result=applied" "$CALLS_LOG"
    assert_success
    nothing_secret
    # the shape is confirmed on the device that proved it
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes
    plain
    assert_line --regexp '^  [0-9a-f]{12} +confirmed +1 device +example-sw1 '
    # a second apply finds nothing to do and asks nothing
    tapply '' example-sw1
    [[ "$status" -eq 0 ]]
    assert_output --partial "example-sw1  no change"
    refute_output --partial "Type "
}

@test "apply: a wrong answer to the review changes nothing" {
    start
    before=$(committed)
    tapply 'yes\n' example-sw1
    [[ "$status" -eq 1 ]]
    assert_output --partial "The answer typed is not 'example-sw1'. Nothing was changed."
    [[ "$(committed)" == "$before" ]]
    # only the check was recorded: no commit, no approval line
    [[ "$(applied result)" == checked ]]
    run grep -F "approved=" "$CALLS_LOG"
    assert_failure
}

@test "apply: with no terminal it needs --confirmed --yes; --yes alone is a usage error" {
    start
    apply example-sw1
    assert_failure 2
    assert_output --partial "No terminal to confirm on"
    assert_output --partial "--confirmed --yes"
    apply example-sw1 --yes
    assert_failure 2
    assert_output --partial "--yes answers the review only with --confirmed"
    apply example-sw1 --check --hold
    assert_failure 2
    assert_output --partial "--hold, --pause and --no-canary are for an apply"
    apply example-sw1 --exit-code
    assert_failure 2
    apply example-sw1 --check --max 0
    assert_failure 2
    apply example-sw1 --check --section netconf
    assert_failure 2
    assert_output --partial "never written"
    # nothing was dialled for any of them
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]]
}

@test "apply --confirmed: an unknown shape is skipped, a seeded one goes on with no terminal" {
    start
    before=$(committed)
    apply example-sw1 --confirmed --yes
    assert_success
    assert_line --regexp '^  example-sw1  skipped: unknown shape [0-9a-f]{12}: review and apply it by hand first$'
    assert_line "  1 skipped"
    [[ "$(committed)" == "$before" ]]
    # the person's word that the device has the shape, one question
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    plain
    assert_success
    assert_output --partial "This is your word that each shape above was applied"
    assert_output --regexp "is confirmed on example-sw1\."
    stub_called "logger -t tacctl -p auth.notice device config shapes seed user=alice device=example-sw1 shape="
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes
    plain
    assert_line --regexp '^  [0-9a-f]{12} +seeded +1 device +example-sw1 '
    # now the shape is known: the batch applies it, still one review, here
    # answered by --yes, which says so
    apply example-sw1 --confirmed --yes
    assert_success
    assert_output --partial "--yes: every shape is one another device confirmed; going on."
    assert_line --regexp '^  example-sw1  applied \(roles,aaa: 17 set, 1 delete\) \[tacctl-'
    run committed
    assert_output --partial "set system tacplus-server 10.0.0.42 single-connection"
}

@test "apply: a refused fresh login rolls the change back, and is not a wrong password" {
    start
    before=$(committed)
    : > "${JDIR}/verify.fail"
    tapply 'example-sw1\n' example-sw1
    [[ "$status" -eq 1 ]]
    assert_output --regexp "example-sw1  rolled back: verification failed \(the fresh login was refused\)"
    assert_output --partial "1 rolled back"
    # the device is as it was; the cancel is in its history, not in its state
    [[ "$(committed)" == "$before" ]]
    [[ "$(applied result)" == rolled-back ]]
    [[ "$(applied kind)" == apply ]]
    # no shape was confirmed by it
    run python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print(all(not e["confirmed"] for e in m.values()))' "${TACCTL_VAR_LIB}/device-apply/shapes.json"
    assert_output "True"
    run grep -F "result=rolled-back" "$CALLS_LOG"
    assert_success
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_line --regexp "^  example-sw1 .* rolled-back "
    nothing_secret
}

@test "apply: a dropped session leaves the change pending, and the next run settles it" {
    start
    # a minute of the window is a second of the fake's clock
    printf '1\n' > "${JDIR}/timer.minute"
    : > "${JDIR}/commit.drop"
    tapply 'example-sw1\n' example-sw1
    [[ "$status" -eq 1 ]]
    assert_output --regexp "PENDING until [0-9:]+: do not type commit or commit check on the device"
    assert_output --partial "1 PENDING"
    [[ "$(applied result)" == pending ]]
    [[ -n "$(applied until)" ]]
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config list
    plain
    assert_line --regexp "^  example-sw1 .* PENDING [0-9:]+ "
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device show example-sw1
    plain
    assert_output --partial "do not type commit or commit check on the device"
    rm -f "${JDIR}/commit.drop"
    # still pending: nothing is sent to the device, not even a check
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "is pending until"
    assert_output --partial "do not type commit or commit check on the device before then"
    # the device undoes it by itself; the next run reads the history first
    sleep 14
    apply example-sw1 --check
    assert_success
    assert_line --regexp '^  example-sw1  checked: shape '
    [[ "$(applied result)" == checked ]]
}

@test "apply: another editor's staged change is refused at the gate" {
    # read once, at the fake's first session
    printf 'user mallory\nset system ntp server 192.0.2.99\n' > "${JDIR}/dirty.shared"
    start
    before=$(committed)
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "failed: other editors or staged changes"
    [[ "$(committed)" == "$before" ]]
    [[ "$(applied result)" == failed ]]
}

@test "apply: an exclusive session someone else holds is refused, naming the holder" {
    start
    printf 'mallory\n' > "${JDIR}/exclusive.held-by"
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "mallory"
    rm -f "${JDIR}/exclusive.held-by"
    apply example-sw1 --check
    assert_success
}

@test "apply: a statement the device refuses fails the device, nothing is committed" {
    start
    before=$(committed)
    printf 'set system accounting events login => error: invalid value\n' > "${JDIR}/load.errors"
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "failed: load: set system accounting events login"
    [[ "$(committed)" == "$before" ]]
    rm -f "${JDIR}/load.errors"
    printf 'configuration check fails: the fake says no\n' > "${JDIR}/check.errors"
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "failed: check:"
    [[ "$(committed)" == "$before" ]]
}

@test "apply: --hold keeps the change on the typed word only" {
    start
    before=$(committed)
    tapply 'example-sw1\nno\n' example-sw1 --hold
    [[ "$status" -eq 1 ]]
    assert_output --partial "Log in with one account of each class in another terminal."
    assert_output --partial "rolled back: verification failed (the hold was not confirmed)"
    [[ "$(committed)" == "$before" ]]
    tapply 'example-sw1\nOK\n' example-sw1 --hold
    [[ "$status" -eq 0 ]]
    assert_output --regexp "example-sw1  applied "
    run committed
    assert_output --partial "set system tacplus-server 10.0.0.42 single-connection"
}

@test "apply: --hold needs a terminal, --max caps the run, --section limits it" {
    start
    apply example-sw1 --hold --confirmed --yes
    assert_failure 2
    assert_output --partial "--hold asks a person"
    # a second name for the same fake: every device of the run is the same one
    cat >> "${TACCTL_STATE_DIR}/devices.yaml" <<EOF
  example-sw2:
    address: 192.168.1.21
    vendor: juniper
    hostname: example-sw1
    host_keys:
    - ${FAKEDEV_KEY}
EOF
    apply example-sw1,example-sw2 --check --concurrency 1 --section snmp
    assert_success
    # the fixture's snmp matches nothing tacctl renders for lab: no change
    assert_line "  example-sw1  no change"
    assert_line "  example-sw2  no change"
    apply example-sw1,example-sw2 --concurrency 1 --max 1 --section aaa --yes --confirmed
    assert_success
}

@test "apply: --max 1 applies the first device and skips the rest, with the reason" {
    start
    cat >> "${TACCTL_STATE_DIR}/devices.yaml" <<EOF
  example-sw2:
    address: 192.168.1.21
    vendor: juniper
    hostname: example-sw1
    host_keys:
    - ${FAKEDEV_KEY}
EOF
    # both devices are the same fake: seed the shape, then the batch
    apply example-sw1 --check
    assert_success
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    assert_success
    apply example-sw1,example-sw2 --concurrency 1 --confirmed --yes --max 1 --pause 0
    assert_success
    assert_line --regexp '^  example-sw1  applied '
    assert_line --regexp '^  example-sw2  skipped: beyond --max 1: run it again for the rest$'
}

@test "apply: Cisco and WTI devices are refused with the reason, before any login" {
    start
    fakedev_register example-sw1 192.168.1.20 juniper cisco-sw 192.168.1.30 cisco wti-ts 192.168.1.31 wti
    apply cisco-sw --check
    assert_failure 1
    assert_line --regexp '^  cisco-sw  failed: apply is not available for Cisco devices in this release$'
    apply wti-ts --check
    assert_failure 1
    assert_output --partial "unsupported: apply is not available for WTI units"
    # a selector leaves them out and counts them; the Junos device is checked
    apply --scope lab --check --concurrency 1
    assert_success
    assert_line --regexp '^  example-sw1  checked: shape '
    assert_output --partial "skipped 2 (cisco-sw, wti-ts): apply writes to Junos devices only in this release"
    # the devices that were never dialled have no apply record
    run python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["devices"]
print(sorted(d))' "${TACCTL_VAR_LIB}/devices-config.json"
    assert_output "['example-sw1']"
}

@test "apply: a device held for break-glass is refused before any login" {
    start
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" config render --force
    printf 'example-sw1\n' | SUDO_USER=alice script -qec "$TACCTL_BIN_SCRIPT breakglass hold example-sw1 --reason 'console recovery'" /dev/null > /dev/null 2>&1 || true
    apply example-sw1 --check
    assert_failure 1
    assert_output --partial "break-glass is held on example-sw1"
    [[ ! -e "${TACCTL_VAR_LIB}/devices-config.json" ]]
}

@test "shapes: list, --show, --json; seed refuses a device with nothing checked" {
    start
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes
    plain
    assert_success
    assert_output --partial "None. A check or an apply of a device that needs a change files its shape"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1 -y
    plain
    assert_failure 1
    assert_output --partial "has no check or apply on record that found a change"
    apply example-sw1 --check
    assert_success
    h=$(applied shape)
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes list --show "${h:0:6}"
    plain
    assert_success
    assert_output --partial "Shape ${h}  (new)"
    assert_output --partial "[aaa]"
    assert_output --partial "set system tacplus-server 10.0.0.42 secret <secret>"
    assert_output --partial "at this shape now (last check or apply): example-sw1"
    refute_output --partial "$SECRET"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes --json
    assert_success
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert len(d) == 1 and d[0]["state"] == "new" and d[0]["devices"] == ["example-sw1"], d
print("fine")' <<< "$output"
    assert_output "fine"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes list --show nothere
    assert_failure 1
    # a seed the person declines changes nothing
    printf 'n\n' | SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes seed example-sw1
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" device config shapes --json
    run python3 -c '
import json, sys
print(json.loads(sys.stdin.read())[0]["state"])' <<< "$output"
    assert_output "new"
}
