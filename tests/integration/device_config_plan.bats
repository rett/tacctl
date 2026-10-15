#!/usr/bin/env bats
# Integration tests for `tacctl device config plan`: the report, the one
# region, the check and the back-out for each device, from the last pull.
# The fake device is `tacctl _fake-device` of a test build; the planner's own
# output is pinned by internal/devconf/plan's goldens, these pin the wiring:
# the record it reads, the refusals, the formats and files, the audit line.

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
    JCMD="${JDIR}/show configuration | display inheritance no-comments | display set.out"
    JPLAIN="${JDIR}/show configuration | display set.out"
    fakedev_start "$JDIR"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$JDIR" juniper lab lab-j
}

teardown() {
    fakedev_stop
}

plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

alice() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" "$@"
    plain
}

# drift: the device loses its authentication order and grows a server of its
# own (with a secret), in both views; then a pull records it.
drift() {
    grep -v '^set system authentication-order' "$JCMD" > "${JCMD}.new"
    printf '%s\n' 'set system tacplus-server 192.0.2.99 secret "$9$STRAY-VALUE-123"' >> "${JCMD}.new"
    mv "${JCMD}.new" "$JCMD"
    cp "$JCMD" "$JPLAIN"
    alice device config pull lab-j
    assert_success
}

@test "plan: a device that agrees is consistent: no region, exit 0, one audit line" {
    alice device config pull lab-j
    assert_success
    alice device config plan lab-j
    assert_success
    assert_line --regexp '^##### lab-j  192\.168\.1\.20  scope lab  juniper \(TACACS\+\) #####$'
    assert_output --partial "CONSISTENT: nothing to paste."
    refute_output --partial "PASTE FROM HERE"
    refute_output --partial "configure exclusive"
    stub_called 'logger -t tacctl -p auth.info device config plan user=alice device=lab-j status=consistent sections=- converge=no secrets=none out=-'
}

@test "plan: the report, one region, the check and the follow-up as a comment; no secret value" {
    drift
    alice device config plan lab-j
    assert_success
    assert_line --regexp '^##### lab-j  192\.168\.1\.20  scope lab  juniper \(TACACS\+\) #####$'
    assert_output --partial "What is irregular on lab-j (2 items; the paste fixes 1, leaves 1):"
    assert_output --partial "extra: a TACACS+ server 192.0.2.99"
    assert_output --partial "Left alone. To remove it later: delete system"
    assert_line "##### PASTE FROM HERE: lab-j #####"
    assert_line "configure exclusive"
    assert_line "set system authentication-order tacplus"
    assert_line "show | compare | no-more"
    assert_line "commit check"
    assert_line --regexp '^commit confirmed 5 comment "tacctl plan lab-j [0-9T:Z-]+ by alice"$'
    assert_line "##### PASTE TO HERE: lab-j #####"
    # nothing after the region is a line to type: the follow-up is a comment
    assert_line --regexp '^# When both checks are fine, type this one word yourself:  commit +\(before the 5 minutes end\)$'
    run python3 -c '
import sys
text = sys.stdin.read()
after = text.split("##### PASTE TO HERE: lab-j #####\n", 1)[1]
bad = [l for l in after.splitlines() if l and not l.startswith("#")]
assert not bad, bad
print("fine")' <<< "$output"
    assert_output "fine"
    refute_output --partial "STRAY-VALUE-123"
    stub_called 'logger -t tacctl -p auth.info device config plan user=alice device=lab-j status=needs-change sections=aaa converge=no secrets=none out=-'
    # the plan reads no device: no new login after the pull
}

@test "plan: --plain is the statements of one device; the wrong arguments are exit 2" {
    drift
    alice device config plan lab-j --plain
    assert_success
    assert_output "set system authentication-order tacplus"
    alice device config plan lab-j --plain --no-secrets
    assert_failure 2
    assert_output --partial "--plain with --no-secrets"
    alice device config plan lab-j --plain --json
    assert_failure 2
    alice device config plan lab-j --secrets --no-secrets
    assert_failure 2
    alice device config plan lab-j --section breakglass
    assert_failure 2
    assert_output --partial "'breakglass' is never planned"
    alice device config plan lab-j --transport ssh
    assert_failure 2
    assert_output --partial "--transport is for --pull"
    alice device config plan
    assert_failure 2
    assert_output --partial "Name the devices to plan, or select them with --all, --scope <name>, --vendor <vendor> or --stale."
    alice device config plan nope
    assert_failure 1
    assert_output --partial "Device 'nope' not found."
}

@test "plan: --json is an array with the region, the back-out and the extras; no value in it" {
    drift
    alice device config plan lab-j --json
    assert_success
    refute_output --partial "STRAY-VALUE-123"
    run python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert len(d) == 1, d
d = d[0]
assert d["name"] == "lab-j" and d["scope"] == "lab" and d["vendor"] == "juniper", d
assert d["status"] == "needs-change", d
assert d["region"][0] == "configure exclusive" and d["region"][-1].startswith("commit confirmed 5 "), d["region"]
assert d["backout"], d
assert [e["text"] for e in d["extras"]] == ["set system tacplus-server 192.0.2.99 secret"], d["extras"]
assert d["extras"][0]["remove"] == ["delete system tacplus-server 192.0.2.99"], d["extras"]
assert d["based_on"]["by"] == "alice" and d["based_on"]["transport"] == "netconf", d
print("fine")' <<< "$output"
    assert_output "fine"
}

@test "plan: --backout is its own region; --out writes 0600 and refuses an existing file" {
    drift
    alice device config plan lab-j --backout
    assert_success
    assert_line "##### BACK-OUT FROM HERE: lab-j #####"
    assert_line "##### BACK-OUT TO HERE: lab-j #####"
    assert_line "delete system authentication-order"
    refute_output --partial "PASTE FROM HERE"
    out="${BATS_TEST_TMPDIR}/lab-j.txt"
    alice device config plan lab-j --out "$out"
    assert_success
    assert_output --partial "Wrote ${out}"
    [[ "$(stat -c %a "$out")" == 600 ]]
    grep -q "PASTE FROM HERE: lab-j" "$out"
    run grep -c "STRAY-VALUE-123" "$out"
    assert_output "0"
    alice device config plan lab-j --out "$out"
    assert_failure 1
    assert_output --partial "exist"
    assert_output --partial "--force"
    alice device config plan lab-j --out "$out" --force --plain
    assert_success
    [[ "$(cat "$out")" == "set system authentication-order tacplus" ]]
    stub_called 'logger -t tacctl -p auth.info device config plan user=alice device=lab-j status=needs-change sections=aaa converge=no secrets=none out='"${out}"
}

@test "plan: --out-dir holds a file per device, the cover and the back-outs, 0600 in a 0700 directory" {
    fakedev_register lab-j 192.168.1.20 juniper lab-j2 192.168.1.21 juniper
    alice device config pull --all
    assert_success
    grep -v '^set system authentication-order' "$JCMD" > "${JCMD}.new"
    mv "${JCMD}.new" "$JCMD"
    alice device config pull lab-j
    assert_success
    alice device config plan --all
    assert_success
    assert_line --regexp '^# tacctl device config plan: 2 devices$'
    assert_line --regexp '^#   lab-j2  consistent$'
    assert_line --regexp '^#   lab-j  +needs change: 1 irregularity fixed by the paste$'
    dir="${BATS_TEST_TMPDIR}/plans"
    alice device config plan --all --out-dir "$dir"
    assert_success
    [[ "$(stat -c %a "$dir")" == 700 ]]
    for f in lab-j.txt lab-j2.txt lab-j.backout.txt COVER.txt; do
        [[ "$(stat -c %a "${dir}/${f}")" == 600 ]]
    done
    grep -q "lab-j2  consistent" "${dir}/COVER.txt"
    alice device config plan --all --out-dir "$dir"
    assert_failure 1
    assert_output --partial "--force"
    alice device config plan --all --plain
    assert_failure 2
    assert_output --partial "--plain is the statements of one device"
    alice device config plan --all --plain --out-dir "${BATS_TEST_TMPDIR}/sets"
    assert_success
    [[ "$(cat "${BATS_TEST_TMPDIR}/sets/lab-j.set")" == "set system authentication-order tacplus" ]]
    [[ ! -s "${BATS_TEST_TMPDIR}/sets/lab-j2.set" ]]
}

@test "plan: --converge: a first region gets no cleanup beside it; after the paste the cleanup is the whole output" {
    drift
    alice device config plan lab-j --converge
    assert_success
    assert_line "##### PASTE FROM HERE: lab-j #####"
    assert_line "##### PASTE TO HERE: lab-j #####"
    refute_output --partial "CLEANUP FROM HERE"
    refute_output --partial "tacctl cleanup lab-j"
    assert_output --regexp "Cleanup \(--converge\): cleanup comes after this region is pasted and verified: pull the device, then[[:space:]#]+plan --converge again\."
    run grep -c "commit confirmed" <<< "$output"
    assert_output "1"
    stub_called 'logger -t tacctl -p auth.info device config plan user=alice device=lab-j status=needs-change sections=aaa converge=yes secrets=none out=-'
    # plain with --converge is two files, the cleanup's only when there is one
    alice device config plan lab-j --plain --converge
    assert_failure 2
    f="${BATS_TEST_TMPDIR}/lab-j.set"
    alice device config plan lab-j --plain --converge --out "$f"
    assert_success
    [[ "$(cat "$f")" == "set system authentication-order tacplus" ]]
    [[ ! -e "${BATS_TEST_TMPDIR}/lab-j.cleanup.set" ]]

    # the paste is made (the stray server stays) and the check pull reads it
    printf '%s\n' 'set system authentication-order tacplus' >> "$JCMD"
    cp "$JCMD" "$JPLAIN"
    alice device config pull lab-j
    assert_success
    alice device config plan lab-j --converge
    assert_success
    assert_line "##### CLEANUP FROM HERE: lab-j #####"
    assert_line "delete system tacplus-server 192.0.2.99"
    assert_line --regexp '^commit confirmed 5 comment "tacctl cleanup lab-j [0-9T:Z-]+ by alice"$'
    assert_line "##### CLEANUP TO HERE: lab-j #####"
    refute_output --partial "PASTE FROM HERE"
    refute_output --partial "PASTE TO HERE"
    assert_output --regexp "Removed by the cleanup[[:space:]#]+region, line 3"
    alice device config plan lab-j --converge --from 192.0.2.99
    assert_success
    refute_output --partial "CLEANUP FROM HERE"
    assert_output --partial "Cleanup (--converge): nothing to remove."
    f="${BATS_TEST_TMPDIR}/after.set"
    alice device config plan lab-j --plain --converge --out "$f"
    assert_success
    [[ ! -s "$f" ]]
    [[ "$(cat "${BATS_TEST_TMPDIR}/after.cleanup.set")" == "delete system tacplus-server 192.0.2.99" ]]

    # the device changes again: the new statements are written and the
    # cleanup file of the earlier plan is taken away, never left beside them
    head -n -1 "$JCMD" > "${JCMD}.new"
    mv "${JCMD}.new" "$JCMD"
    cp "$JCMD" "$JPLAIN"
    alice device config pull lab-j
    assert_success
    alice device config plan lab-j --plain --converge --out "$f" --force
    assert_success
    assert_output --partial "Removed ${BATS_TEST_TMPDIR}/after.cleanup.set"
    [[ "$(cat "$f")" == "set system authentication-order tacplus" ]]
    [[ ! -e "${BATS_TEST_TMPDIR}/after.cleanup.set" ]]
}

@test "plan: --backout after the check pull prints the back-out the plan kept; --backout --pull is refused" {
    drift
    alice device config plan lab-j
    assert_success
    alice device config plan lab-j --backout
    assert_success
    assert_line "delete system authentication-order"
    # the one kept prints, saying which plan and pull it undoes; the record's
    # pull is still the stamp, so nothing says a later pull replaced it
    assert_line --regexp '^# This back-out undoes the plan of aaa made from the pull of [0-9: -]+ \(UTC\); it is the one tacctl kept from that plan\.$'
    refute_output --partial "a later pull replaced that picture"
    # the paste is made and the check pull replaces the baseline
    printf '%s\n' 'set system authentication-order tacplus' >> "$JCMD"
    cp "$JCMD" "$JPLAIN"
    alice device config pull lab-j
    assert_success
    alice device config plan lab-j --backout
    assert_success
    assert_line --regexp '^# This back-out undoes the plan of aaa made from the pull of [0-9: -]+ \(UTC\); a later pull replaced that picture'
    assert_line "##### BACK-OUT FROM HERE: lab-j #####"
    assert_line "delete system authentication-order"
    alice device config plan lab-j --backout --pull
    assert_failure 2
    assert_output --partial "--backout with --pull"
    # forgetting the record takes the kept back-out with it
    alice device config forget lab-j
    assert_success
    alice device config pull lab-j
    alice device config plan lab-j --backout
    assert_success
    assert_output --partial "nothing to back out: no plan was made from an earlier pull of lab-j"
    refute_output --partial "BACK-OUT FROM HERE"
}

@test "plan: a device never pulled, a stale pull and a failed pull cannot be planned (exit 1)" {
    alice device config plan lab-j
    assert_failure 1
    assert_output --partial "lab-j cannot be planned: not pulled: tacctl device config pull lab-j (or --pull)"
    assert_output --partial "CANNOT BE PLANNED: not pulled"
    refute_output --partial "configure exclusive"
    alice device config pull lab-j
    assert_success
    # a pull of 45 days ago
    python3 - "${TACCTL_VAR_LIB}/devices-config.json" <<'PY'
import json, sys, datetime
p = sys.argv[1]
d = json.load(open(p))
t = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
d["devices"]["lab-j"]["pulled"] = t
json.dump(d, open(p, "w"))
PY
    alice device config plan lab-j
    assert_failure 1
    assert_output --partial "stale pull (45 days old, stale-days is 30)"
    alice device config plan lab-j --json
    assert_failure 1
    run python3 -c '
import json, sys
t = sys.stdin.read()
d = json.loads(t[t.index("[\n"):])[0]
assert d["status"] == "cannot-plan" and "stale pull" in d["reason"] and d["region"] == [], d
print("fine")' <<< "$output"
    assert_output "fine"
    # --pull makes it current
    alice device config plan lab-j --pull
    assert_success
    assert_output --partial "CONSISTENT: nothing to paste."
    # a wrong password: the pull fails, and the device cannot be planned
    TACCTL_TEST_DEVICE_PASSWORD="not-the-password-77" alice device config plan lab-j --pull
    assert_failure 1
    assert_output --partial "lab-j cannot be planned: the pull failed (authentication failed)"
    refute_output --partial "not-the-password-77"
}

@test "plan: a statement a group supplies is read from the plain view and refused" {
    alice device config pull lab-j
    assert_success
    # the device has another order, which the inheritance view shows and the
    # plain view does not: a group supplies it
    grep -v '^set system authentication-order' "$JCMD" > "${JCMD}.new"
    printf '%s\n' 'set system authentication-order password' >> "${JCMD}.new"
    mv "${JCMD}.new" "$JCMD"
    grep -v '^set system authentication-order' "$JPLAIN" > "${JPLAIN}.new"
    mv "${JPLAIN}.new" "$JPLAIN"
    alice device config pull lab-j
    assert_success
    [[ "$(stat -c %a "${TACCTL_VAR_LIB}/device-config/lab-j.plain")" == 600 ]]
    alice device config plan lab-j
    assert_failure 1
    assert_output --partial "lab-j cannot be planned: refused: aaa:"
    assert_output --partial "inherited from a group"
    refute_output --partial "configure exclusive"
    # a device that answers no plain view: planned, and the report says the
    # check was not made
    rm -f "$JPLAIN"
    alice device config pull lab-j
    assert_success
    [[ ! -e "${TACCTL_VAR_LIB}/device-config/lab-j.plain" ]]
    alice device config plan lab-j
    assert_success
    assert_output --partial "The pull has no plain view of the configuration"
    assert_line "set system authentication-order tacplus"
}

@test "plan: a Cisco device is planned in the dialect its image says; the ssh flag decides nothing" {
    local cdir
    fakedev_stop
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    # legacy-ssh on a 15.x image: the ssh algorithms, and the modern block
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh lab-c enable
    assert_success
    fakedev_serve "$cdir" cisco lab lab-c
    alice device config pull lab-c
    assert_success
    # the device loses its server block
    python3 - "${cdir}/show running-config.out" <<'PY'
import sys
p = sys.argv[1]
out, skip = [], False
for l in open(p).read().split("\n"):
    if l.startswith("tacacs server "):
        skip = True
        continue
    if skip and l.startswith(" "):
        continue
    skip = False
    out.append(l)
open(p, "w").write("\n".join(out))
PY
    alice device config pull lab-c
    assert_success
    alice device config plan lab-c
    assert_success
    assert_line --regexp '^!!!!! lab-c  192\.168\.1\.30  scope lab  cisco \(IOS-XE and IOS 15 syntax, TACACS\+\) !!!!!$'
    assert_line "!!!!! PASTE FROM HERE: lab-c !!!!!"
    assert_line "configure terminal"
    assert_line "tacacs server TACACS"
    assert_line "end"
    assert_line "!!!!! PASTE TO HERE: lab-c !!!!!"
    refute_output --partial "tacacs-server host"
    assert_output --partial "type this one command yourself:  write memory"
    assert_output --partial "NOTHING rolls it back by itself"
    stub_called 'logger -t tacctl -p auth.info device config plan user=alice device=lab-c status=needs-change sections=aaa converge=no secrets=values out=-'
    # a record that says nothing of the image needs a pull, not a guess
    python3 - "${TACCTL_VAR_LIB}/devices-config.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["devices"]["lab-c"].pop("os", None)
d["devices"]["lab-c"].pop("syntax", None)
json.dump(d, open(p, "w"))
PY
    alice device config plan lab-c
    assert_failure 1
    assert_output --partial "needs pull (the image's configuration syntax is not known)"
    # the 12.x image, no flag: the IOS 12.x lines
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh lab-c disable
    assert_success
    FAKEDEV_IOS_SYNTAX=ios12 fakedev_serve "$cdir" cisco lab lab-c
    python3 - "${cdir}/show running-config.out" <<'PY'
import sys
p = sys.argv[1]
out = [l for l in open(p).read().split("\n") if not l.startswith("tacacs-server host ")]
open(p, "w").write("\n".join(out))
PY
    alice device config pull lab-c
    assert_success
    alice device config plan lab-c
    assert_success
    assert_output --partial "cisco (IOS 12.x syntax, TACACS+)"
    assert_output --partial "tacacs-server host "
    refute_output --partial "tacacs server TACACS"
}

@test "plan: --restore-point puts a restore block before a Cisco region; the bare flag follows the archive path" {
    local cdir
    fakedev_stop
    cdir=$(fakedev_dir ios)
    fakedev_start "$cdir"
    fakedev_register lab-c 192.168.1.30 cisco
    fakedev_serve "$cdir" cisco lab lab-c
    # the device loses its server block and has an archive path
    python3 - "${cdir}/show running-config.out" <<'PY'
import sys
p = sys.argv[1]
out, skip = [], False
for l in open(p).read().split("\n"):
    if l.startswith("tacacs server "):
        skip = True
        continue
    if skip and l.startswith(" "):
        continue
    skip = False
    out.append(l)
text = "\n".join(out).rstrip("\n") + "\narchive\n log config\n path flash:tacctl-\n!\n"
open(p, "w").write(text)
PY
    alice device config pull lab-c
    assert_success
    alice device config plan lab-c --restore-point=disk0:
    assert_success
    assert_line "!!!!! RESTORE POINT FROM HERE: lab-c !!!!!"
    assert_line --regexp '^copy running-config disk0:tacctl-lab-c-[0-9]{8}-[0-9]{4}\.cfg$'
    assert_line "!!!!! RESTORE POINT TO HERE: lab-c !!!!!"
    assert_line "!!!!! PASTE FROM HERE: lab-c !!!!!"
    refute_output --partial "not lab-tested"
    # the restore block comes first, and it is the only command outside the region
    run python3 -c '
import sys
text = sys.stdin.read()
before = text.split("!!!!! PASTE FROM HERE: lab-c !!!!!\n", 1)[0]
typed = [l for l in before.splitlines() if l and not l.startswith(("!", "lab-c:"))]
assert len(typed) == 1 and typed[0].startswith("copy running-config disk0:tacctl-lab-c-"), typed
assert "RESTORE POINT FROM HERE" in before
print("fine")' <<< "$output"
    assert_output "fine"
    alice device config plan lab-c --backout
    assert_success
    assert_output --partial "its restore point is disk0:tacctl-lab-c-"
    assert_line --regexp '^!   configure replace disk0:tacctl-lab-c-[0-9]{8}-[0-9]{4}\.cfg force$'
    # the bare flag: the archive path the pull read
    alice device config plan lab-c --restore-point
    assert_success
    assert_line "archive config"
    refute_output --partial "copy running-config"
    assert_output --partial "not lab-tested"
    # refused: with --plain and with --backout
    alice device config plan lab-c --restore-point --plain
    assert_failure 2
    assert_output --partial "--restore-point with --plain"
    alice device config plan lab-c --restore-point --backout
    assert_failure 2
    # a device with no archive path: the bare flag is a usage error
    python3 - "${cdir}/show running-config.out" <<'PY'
import sys
p = sys.argv[1]
t = open(p).read().replace(" path flash:tacctl-\n", "")
open(p, "w").write(t)
PY
    alice device config pull lab-c
    assert_success
    alice device config plan lab-c --restore-point
    assert_failure 2
    assert_output --partial "--restore-point with no file system"
    alice device config plan lab-c --restore-point=flash:
    assert_success
    assert_line --regexp '^copy running-config flash:tacctl-lab-c-'
}

@test "plan: --restore-point is for IOS and IOS-XE devices only" {
    alice device config pull lab-j
    assert_success
    alice device config plan lab-j --restore-point
    assert_failure 2
    assert_output --partial "--restore-point is for IOS and IOS-XE devices"
    assert_output --partial "lab-j (juniper)"
    refute_output --partial "RESTORE POINT"
}

@test "plan: the confirm timeout is the N of the confirmed commit" {
    drift
    run "$TACCTL_BIN_SCRIPT" config devices confirm-timeout 12
    assert_success
    alice device config plan lab-j
    assert_success
    assert_line --regexp '^commit confirmed 12 comment "tacctl plan lab-j '
    assert_output --partial "undoes this by itself in 12 minutes"
    run "$TACCTL_BIN_SCRIPT" config devices confirm-timeout 61
    assert_failure
    assert_output --partial "device.config.confirm_timeout"
}
