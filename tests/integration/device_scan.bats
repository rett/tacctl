#!/usr/bin/env bats
# Integration tests for the seen data of `tacctl device`: `device scan`,
# `device discover`, `device check`, `device list --scan|--probe`, the seen
# columns of list and show, the scan-time notices and the "Device notices"
# section of `tacctl status`.
#
# journalctl is stubbed to print made-up journal records
# (tests/fixtures/sightings/tacquito.journal-1.json, then -2.json for a scan
# that resumes after the cursor); the RADIUS auth log is a fixture file under
# TACCTL_RADIUS_LOG. ssh-keyscan answers with a key generated for the tests.
# The clock is TACCTL_TEST_NOW and the zone UTC, so the output is fixed. No
# test connects anywhere but to 127.0.0.1.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

SIGHTINGS="${BATS_TEST_DIRNAME}/../fixtures/sightings"
KEYS="${BATS_TEST_DIRNAME}/../../internal/devreg/testdata/hostkeys"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TZ=UTC
    stub_cmd chown
    stub_cmd logger
    stub_cmd systemctl
    # journalctl: the first stretch of the journal; after its last cursor
    # the second; after the second's last cursor nothing new.
    stub_cmd journalctl "
case \" \$* \" in
  *' --after-cursor s=f00d;i=208 '*) ;;
  *' --after-cursor '*) cat '${SIGHTINGS}/tacquito.journal-2.json' ;;
  *) cat '${SIGHTINGS}/tacquito.journal-1.json' ;;
esac"
    # ssh-keyscan: every address offers the ed25519 test key.
    stub_cmd ssh-keyscan "echo \"\${!#} $(cut -d' ' -f1,2 "${KEYS}/ed25519.pub")\""
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "${TACCTL_STATE_DIR}/store.yaml"
    chmod 600 "${TACCTL_STATE_DIR}/store.yaml"
    printf 'backends:\n  enabled: [tacacs, radius]\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    mkdir -p "$TACCTL_RADIUS_LOG"
    AUTHLOG="${TACCTL_RADIUS_LOG}/tacctl-auth.log"
    SEEN="${TACCTL_VAR_LIB}/devices-seen.json"
}

# plain: the last output with colours stripped.
plain() { output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); mapfile -t lines <<< "$output"; }

# at <RFC3339> <args...>: tacctl at that time.
at() { local t="$1"; shift; TACCTL_TEST_NOW="$t" "$TACCTL_BIN_SCRIPT" "$@"; }

# register: the devices of the scenario, pinned to the test key.
register() {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 203.0.113.1 --vendor cisco > /dev/null
    "$TACCTL_BIN_SCRIPT" device add edge-fw 203.0.113.20 > /dev/null
    "$TACCTL_BIN_SCRIPT" device add oob-con1 203.0.113.9 --vendor wti > /dev/null
    "$TACCTL_BIN_SCRIPT" device add access-sw2 203.0.113.12 --vendor cisco > /dev/null
    "$TACCTL_BIN_SCRIPT" device add lab-rtr2 198.51.100.7 --vendor juniper > /dev/null
}

# two_scans: a scan on 2026-08-21 (the first stretch of each log), then the
# logs grow and a scan on 2026-10-04 resumes where the first stopped.
two_scans() {
    cp "${SIGHTINGS}/tacctl-auth.log-1" "$AUTHLOG"
    at 2026-08-21T12:00:00Z device scan > /dev/null
    cat "${SIGHTINGS}/tacctl-auth.log-2" >> "$AUTHLOG"
}

# --- the acceptance scenario ------------------------------------------------------------

@test "device scan, discover, list and status on the multiscope store with a stubbed journal" {
    register
    two_scans

    run at 2026-10-04T12:00:00Z device scan
    assert_success
    plain
    # Two sources, each with the window it read.
    assert_output --partial "  tacacs  journal 2026-10-02 14:03:00 to 2026-10-03 16:07:00 (8 entries): 6 sightings of 5 addresses"
    assert_output --partial "  radius  tacctl-auth.log 2026-10-03 07:40:00 to 2026-10-03 08:00:00 (2 entries): 2 sightings of 2 addresses"
    assert_output --partial "  Host keys: 5 entries re-scanned: 5 unchanged"
    assert_output --partial "  Seen: 8 addresses, 4 registered, 4 not (tacctl device discover)"
    assert_output --partial "  Notices (2):"
    assert_output --partial "    oob-con1  name-mismatch: 203.0.113.9 identifies itself as 'oob-con-01', not 'oob-con1' (informational)"
    assert_output --partial "    access-sw2  generic-nas-id: 203.0.113.12 identifies itself as 'Switch' (NAS-Identifier), a generic name"
    stub_called "^journalctl -u tacquito -o json --output-fields=MESSAGE --no-pager --since 2026-07-22 12:00:00$"
    stub_called "^journalctl -u tacquito -o json --output-fields=MESSAGE --no-pager --after-cursor s=f00d;i=101$"
    stub_called "^ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 203.0.113.1$"

    # discover: the unregistered addresses that authenticated, each with
    # the add line (the NAS-Identifier when it can be a name).
    run at 2026-10-04T12:00:00Z device discover
    assert_success
    plain
    assert_output --partial "Unregistered addresses that authenticated (2)"
    assert_output --regexp "203\.0\.113\.50 +dmz +- +2026-10-03 08:00 +2026-10-03 08:00 +1 +carol +accept +radius +edge-sw5"
    assert_output --regexp "203\.0\.113\.77 +dmz +- +2026-10-03 15:00 +2026-10-03 15:00 +1 +carol +accept +tacacs +-"
    assert_output --partial "    tacctl device add edge-sw5 203.0.113.50"
    assert_output --partial "    tacctl device add <name> 203.0.113.77"
    refute_output --partial "192.0.2.66"

    # list: seen via tacacs, stale (last seen in August), rejected with a
    # bad secret, never seen.
    run at 2026-10-04T12:00:00Z device list
    assert_success
    plain
    assert_output --regexp "core-sw1 +203\.0\.113\.1 +cisco +dmz +configured +2026-10-02 14:03 +alice +tacacs +-"
    assert_output --regexp "edge-fw +203\.0\.113\.20 +other +dmz +configured +rejected 2026-10-03 14:05 \(bad secret\) +- +tacacs +-"
    assert_output --regexp "oob-con1 +203\.0\.113\.9 +wti +dmz +configured stale +2026-08-20 09:12 +asmith +radius +name-mismatch"
    assert_output --regexp "lab-rtr2 +198\.51\.100\.7 +juniper +- +unconfigured +never +- +- +-"
    assert_output --partial "seen data as of 2026-10-04 12:00 (tacctl device scan to refresh); stale after 30 days"
    assert_output --partial "2 open notice(s): tacctl device notices"

    run at 2026-10-04T12:00:00Z status
    assert_success
    plain
    assert_line "  Device notices: 2 (tacctl device notices)"
    assert_output --partial "    oob-con1  name-mismatch:"
    assert_output --partial "    access-sw2  generic-nas-id:"

    # A scan never writes the registry; the cache is root-only.
    run stat -c %a "$SEEN"
    assert_output "600"
}

# --- the cache ------------------------------------------------------------------------

@test "device scan: the first scan reads the last stale-days days; --since and --full replace" {
    register
    cp "${SIGHTINGS}/tacctl-auth.log-1" "$AUTHLOG"
    cat "${SIGHTINGS}/tacctl-auth.log-2" >> "$AUTHLOG"
    run at 2026-10-04T12:00:00Z device scan --backend radius
    assert_success
    plain
    # The August line is outside the 30 days.
    assert_output --partial "  radius  tacctl-auth.log 2026-10-03 07:40:00 to 2026-10-03 08:00:00 (2 entries)"
    refute_output --partial "  tacacs "
    ! stub_called "^journalctl"
    run at 2026-10-04T12:00:00Z device scan --backend radius --since 8w
    plain
    assert_output --partial "  radius  tacctl-auth.log 2026-08-20 09:12:00 to 2026-10-03 08:00:00 (3 entries)"
    run at 2026-10-04T12:00:00Z device scan --backend radius --full
    plain
    assert_output --partial "(3 entries): 3 sightings of 3 addresses"
    run at 2026-10-04T12:00:00Z device show oob-con1
    plain
    assert_output --partial "First seen:   2026-08-20 09:12  (1 sighting)"
    run "$TACCTL_BIN_SCRIPT" device scan --full --since 1d
    assert_failure 1
    plain
    assert_output --partial "Give --full or --since, not both."
}

@test "device scan --full reads the rotated and gzipped auth logs, oldest first" {
    register
    head -c 0 /dev/null > "$AUTHLOG"
    cp "${SIGHTINGS}/tacctl-auth.log-1" "${AUTHLOG}.2"
    gzip "${AUTHLOG}.2"
    cp "${SIGHTINGS}/tacctl-auth.log-2" "${AUTHLOG}.1"
    run at 2026-10-04T12:00:00Z device scan --full --backend radius
    assert_success
    plain
    assert_output --partial "  radius  tacctl-auth.log 2026-08-20 09:12:00 to 2026-10-03 08:00:00 (3 entries): 3 sightings of 3 addresses"
}

@test "device scan resumes the auth log after copytruncate" {
    register
    two_scans
    # logrotate copytruncate: the log is copied to .1 and emptied, then
    # written on.
    cp "$AUTHLOG" "${AUTHLOG}.1"
    : > "$AUTHLOG"
    echo "2026-10-04 09:00:00 Access-Reject scope=dmz device=generic client=203.0.113.9 nas=oob-con1 reason='Invalid password' user=asmith" >> "$AUTHLOG"
    run at 2026-10-04T12:00:00Z device scan --backend radius
    assert_success
    plain
    assert_output --partial "  radius  tacctl-auth.log 2026-10-03 07:40:00 to 2026-10-04 09:00:00 (3 entries)"
    run at 2026-10-04T12:00:00Z device list
    plain
    assert_output --regexp "oob-con1 +203\.0\.113\.9 +wti +dmz +configured +rejected 2026-10-04 09:00 +asmith +radius"
    # The NAS-Identifier now matches: no name-mismatch; it changed:
    # identity-changed.
    run at 2026-10-04T12:00:00Z device notices oob-con1
    plain
    assert_output --partial "oob-con1  identity-changed: 203.0.113.9 now identifies as 'oob-con1' (was 'oob-con-01', changed 2026-10-04 09:00)"
    refute_output --partial "name-mismatch"
}

@test "device scan: a fully qualified registry name matches the unit's short name; two units sending one name are told apart" {
    "$TACCTL_BIN_SCRIPT" device add sw1.site-a.example 203.0.113.41 --vendor juniper > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw1.site-b.example 203.0.113.42 --vendor juniper > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw2.site-a.example 203.0.113.43 --vendor juniper > /dev/null
    {
        echo "2026-10-04 09:00:00 Access-Accept scope=dmz device=generic client=203.0.113.41 nas=sw1 user=jdoe"
        echo "2026-10-04 09:01:00 Access-Accept scope=dmz device=generic client=203.0.113.42 nas=sw1 user=jdoe"
        echo "2026-10-04 09:02:00 Access-Accept scope=dmz device=generic client=203.0.113.43 nas=SW2 user=jdoe"
    } > "$AUTHLOG"
    run at 2026-10-04T12:00:00Z device scan --backend radius
    assert_success
    run at 2026-10-04T12:00:00Z device notices
    plain
    # 'sw1' and 'SW2' are the first labels of the registry names: no
    # name-mismatch; 'sw1' from two addresses is ambiguous, and the remedy
    # names a fully qualified host name.
    refute_output --partial "name-mismatch"
    assert_output --partial "sw1.site-a.example  ambiguous-nas-id: NAS-Identifier 'sw1' is sent from 2 addresses (203.0.113.41, 203.0.113.42); give each device a name of its own (a fully qualified host name tells them apart: Junos: 'set system host-name <name>'), or acknowledge it: 'tacctl device notice sw1.site-a.example ack ambiguous-nas-id'"
    assert_output --partial "sw1.site-b.example  ambiguous-nas-id:"
    refute_output --partial "sw2.site-a.example"
}

@test "device discover --all includes addresses only ever refused, IPv6 included" {
    register
    two_scans
    run at 2026-10-04T12:00:00Z device discover --all
    assert_success
    plain
    assert_output --partial "Unregistered addresses seen (4)"
    # A bad secret, then no scope (tacquito: 'remote [..] has no secret providers').
    assert_output --regexp "192\.0\.2\.66 +- +- +2026-10-03 15:10 +2026-10-03 16:06 +2 +- +no-scope +tacacs +-"
    assert_output --regexp "2001:db8::5 +- +- +2026-10-03 16:00 +2026-10-03 16:00 +1 +mallory +reject +tacacs +-"
    assert_output --partial "    tacctl device add <name> 2001:db8::5"
}

# --- notices -----------------------------------------------------------------------------

@test "device scan: host-key re-scan notices, the pin stays, hostkey-changed cannot be acknowledged" {
    register
    local before
    before=$(sha256sum < "${TACCTL_STATE_DIR}/devices.yaml")
    stub_cmd ssh-keyscan "echo \"\${!#} $(cut -d' ' -f1,2 "${KEYS}/ed25519.pub")\"; [[ \"\${!#}\" == 203.0.113.20 ]] && echo \"\${!#} $(cut -d' ' -f1,2 "${KEYS}/rsa.pub")\"; true"
    run at 2026-10-04T12:00:00Z device scan --backend radius
    assert_success
    plain
    assert_output --partial "Host keys: 5 entries re-scanned: 4 unchanged, 1 with a new key type"
    assert_output --partial "edge-fw  hostkey-added: 'edge-fw' offers a new host key type (scan 2026-10-04 12:00): RSA SHA256:"
    [[ "$(sha256sum < "${TACCTL_STATE_DIR}/devices.yaml")" == "$before" ]]

    "$TACCTL_BIN_SCRIPT" device notice edge-fw ack hostkey-added
    run at 2026-10-04T12:00:00Z device show edge-fw --all
    plain
    assert_output --partial "hostkey-added (acknowledged): 'edge-fw' offers a new host key type"
    run at 2026-10-04T12:00:00Z device list
    plain
    assert_output --regexp "edge-fw +203\.0\.113\.20 +other +dmz +configured +never +- +- +-"

    stub_cmd ssh-keyscan "true"
    run at 2026-10-05T12:00:00Z device scan --backend radius
    plain
    assert_output --partial "core-sw1  hostkey-unreachable: no host key could be read from 'core-sw1' (203.0.113.1 port 22) at 2026-10-05 12:00; last good scan 2026-10-04 12:00"
    run "$TACCTL_BIN_SCRIPT" device notice core-sw1 ack hostkey-changed
    assert_failure 1
}

@test "status: no Device notices section without devices or hosts" {
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    refute_output --partial "Device notices"
    "$TACCTL_BIN_SCRIPT" device add core-sw1 203.0.113.1 --vendor cisco > /dev/null
    run "$TACCTL_BIN_SCRIPT" status
    plain
    assert_line "  Device notices: none"
    run "$TACCTL_BIN_SCRIPT" device list
    plain
    assert_output --partial "seen data: none (tacctl device scan)"
}

# --- check and probe ---------------------------------------------------------------------

@test "device check: scope, seen, reachable (a closed local port), host key; list --probe" {
    "$TACCTL_BIN_SCRIPT" device add loop 127.0.0.1 --port 1 --vendor cisco > /dev/null
    run at 2026-10-04T12:00:00Z device check loop
    assert_success
    plain
    assert_output --partial "Check loop (127.0.0.1, cisco)"
    assert_output --partial "Seen:        no seen data (tacctl device scan)"
    assert_output --partial "Reachable:   closed (127.0.0.1 port 1: connection refused)"
    assert_output --partial "Host key:    matches the pinned keys"
    stub_called "^ssh-keyscan -T 5 -p 1 -t ed25519,ecdsa,rsa 127.0.0.1$"
    run "$TACCTL_BIN_SCRIPT" device list --probe
    assert_success
    plain
    assert_output --regexp "loop +127\.0\.0\.1 +cisco +- +unconfigured +- +- +- +closed +-"
    run "$TACCTL_BIN_SCRIPT" device check
    assert_failure 1
    plain
    assert_output --partial "Usage: tacctl device check <name>|--all"
}

@test "device list --scan scans first" {
    register
    cp "${SIGHTINGS}/tacctl-auth.log-1" "$AUTHLOG"
    run at 2026-08-21T12:00:00Z device list --scan
    assert_success
    plain
    assert_output --partial "Device scan"
    assert_output --regexp "core-sw1 +203\.0\.113\.1 +cisco +dmz +configured +2026-08-20 10:00 +alice +tacacs"
    [[ -f "$SEEN" ]]
}
