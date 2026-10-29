#!/usr/bin/env bats
# Integration tests for 'tacctl rollback <version> [--apply] [--yes] [--hosts]'
# (docs/plans/0.2.4-plan.md D73): the 0.2.4 state is built with the verbs
# that write the formats a 0.2.3 binary does not read, then rolled back. The
# dry run is the default and writes nothing; --apply takes a snapshot first,
# needs --yes while a setting is dropped, leaves store.yaml alone and is
# idempotent; --hosts is accepted and touches no host. The 0.2.3 parsers
# themselves are checked in internal/cli/rollback_test.go
# (TestRollbackRealOldBinary, TestRollbackRealOldBinary029 and
# TestRollbackRealOldBinary0219 build the 0.2.3, 0.2.9 and 0.2.19 tags).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_TIER_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl-tiers"
    export PUSHED="${BATS_TEST_TMPDIR}/pushed"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    stub_cmd ssh 'cat > "$PUSHED"'
    stub_cmd id 'echo "users"'
}

# A 0.2.4 state: what 0.2.3 has (an engineer group at tier engineer, SNMP
# settings of a scope, a device location, space completion off) and what
# 0.2.4 added: two devices with SNMP settings of their own (one with
# credentials), the device.config keys, the password cache's tiers, the
# records of a pull, and the sudoers drop-ins as 0.2.4 writes them.
_state_024() {
    "$TACCTL_BIN_SCRIPT" group add engineer 15 EN-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit engineer tier engineer > /dev/null
    "$TACCTL_BIN_SCRIPT" user add erin engineer --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab version v2c > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw1 192.0.2.7 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw2 192.0.2.8 --vendor juniper --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device location sw1 "Rack 4, DC1" > /dev/null
    "$TACCTL_BIN_SCRIPT" console space-completion off > /dev/null
    "$TACCTL_BIN_SCRIPT" device snmp sw1 version v3 > /dev/null
    "$TACCTL_BIN_SCRIPT" device snmp sw1 port 2161 > /dev/null
    printf 'sw2-community\nsw2-community\n' | "$TACCTL_BIN_SCRIPT" device snmp sw2 community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" console password-cache tiers engineer,superuser > /dev/null
    # The console switches of a release before 0.2.20, still in the file: this
    # release ignores and keeps them, and 0.2.3 reads them as it always did.
    sed -i '0,/^version: 1$/s//version: 1\ntiers: {readonly: enable, operator: enable, engineer: enable, superuser: enable}/' "${TACCTL_STATE_DIR}/console.yaml"
    "$TACCTL_BIN_SCRIPT" config devices max-concurrency 16 > /dev/null
    "$TACCTL_BIN_SCRIPT" config devices timeout 120 > /dev/null
    mkdir -p "$TACCTL_VAR_LIB/device-config" "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    echo '{"version": 1, "devices": {}}' > "$TACCTL_VAR_LIB/devices-config.json"
    echo 'aaa: []' > "$TACCTL_VAR_LIB/device-config/sw1.yaml"
    "$TACCTL_BIN_SCRIPT" config sudoers tiers install > /dev/null <<< "y"
}

# A 0.2.10 state: the 0.2.4 one, the settings of 'device config apply' of
# 0.2.9 and 0.2.10 (the transport), the NETCONF service setting of a scope
# and of a device, a record whose apply names its transport, and the apply
# state directory.
_state_029() {
    _state_024
    "$TACCTL_BIN_SCRIPT" config devices apply-confirm-timeout 15 > /dev/null
    "$TACCTL_BIN_SCRIPT" config devices apply-pause 30 > /dev/null
    "$TACCTL_BIN_SCRIPT" config devices apply-transport netconf > /dev/null
    "$TACCTL_BIN_SCRIPT" scope netconf lab enable --connection-limit 3 --rate-limit 10 > /dev/null
    "$TACCTL_BIN_SCRIPT" device netconf sw2 enable --connection-limit 5 > /dev/null
    cat > "$TACCTL_VAR_LIB/devices-config.json" <<'JSON'
{"version": 1, "devices": {
 "sw2": {"address": "192.0.2.8", "vendor": "juniper", "hostname": "sw2.example.net", "login": "local:admin", "user_pulled": true,
   "applied": {"at": "2026-10-15T10:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261015T100000Z-ab12", "kind": "apply", "shape": "0123abcd", "via": "netconf"}}}}
JSON
    mkdir -p "$TACCTL_VAR_LIB/device-apply/locks"
    echo '{}' > "$TACCTL_VAR_LIB/device-apply/shapes.json"
    : > "$TACCTL_VAR_LIB/device-apply/locks/sw2.lock"
}

# Every regular file of the state, with its checksum.
_sums() { (cd "$BATS_TEST_TMPDIR" && find state var-lib sudoers.d -type f ! -name '.*.lock' -print0 2> /dev/null | sort -z | xargs -0 sha256sum); }
_snapshots() { find "$TACCTL_STATE_DIR/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | wc -l; }
_overrides() { cat "${TACCTL_STATE_DIR}/tacctl.yaml" 2>/dev/null; }

@test "rollback: 0.2.2 and other versions are refused with the reason, and nothing is read for writing" {
    _state_024
    before=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2
    assert_failure 1
    assert_output --partial "and 0.2.3 only (0.2.2 is older)"
    assert_output --partial "Go back one release at a time"
    assert_output --partial "tacctl rollback 0.2.3 --apply"
    assert_output --partial "tacctl upgrade --branch 0.2.3"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes
    assert_failure 1
    assert_output --partial "0.2.2 is older"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.1
    assert_failure 1
    assert_output --partial "Rolling back to 0.2.1 is not supported from this release"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.4
    assert_failure 1
    assert_output --partial "and 0.2.3 only (0.2.4 is further back)"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.7 --apply --yes
    assert_failure 1
    assert_output --partial "and 0.2.3 only (0.2.7 is further back)"
    assert_output --partial "tacctl rollback 0.2.9 --apply"
    assert_output --partial "tacctl upgrade --branch 0.2.9"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.8
    assert_failure 1
    assert_output --partial "and 0.2.3 only (0.2.8 is further back)"
    assert_output --partial "tacctl rollback 0.2.9 --apply"
    run "$TACCTL_BIN_SCRIPT" rollback develop
    assert_failure 1
    assert_output --partial "'develop' is not a release this tacctl knows"
    [[ "$(_sums)" == "$before" ]]
}

@test "rollback: usage" {
    run "$TACCTL_BIN_SCRIPT" rollback
    assert_failure 1
    assert_output --partial "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --bogus
    assert_failure 1
    assert_output --partial "Usage: tacctl rollback <version>"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 extra
    assert_failure 1
}

@test "rollback: the dry run is the default, lists every step and warning, and writes nothing" {
    _state_024
    before=$(_sums)
    n=$(_snapshots)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --hosts
    assert_success
    assert_output --partial "Roll back to 0.2.3 (dry run)"
    assert_output --partial "tacctl.yaml: remove the keys 0.2.3 does not know   [does]"
    assert_output --partial "remove device.config.max_concurrency"
    assert_output --partial "remove device.config.timeout"
    assert_output --partial "console.yaml: write it the way 0.2.3 reads it   [does]"
    assert_output --partial "remove settings.password_cache: tiers engineer,superuser"
    assert_output --partial "devices.yaml: remove the per-device SNMP settings   [does]"
    assert_output --partial "remove the snmp map of sw1 (version v3, port 2161)"
    assert_output --partial "remove the snmp map of sw2 (version v2c)"
    assert_output --partial "put back the sudoers drop-ins 0.2.3 writes   [does]"
    assert_output --partial "rewrite ${TACCTL_TIER_SUDOERS_FILE}"
    assert_output --partial "leave ${TACCTL_STATE_DIR}/snmp/devices"
    assert_output --partial "1 file (mode 0600, kept): sw2"
    assert_output --partial "leaves ${TACCTL_VAR_LIB}/devices-config.json"
    assert_output --partial "store.yaml untouched"
    assert_output --partial "no host is synced"
    assert_output --partial "Settings 0.2.3 cannot use are dropped"
    assert_output --partial "This was a dry run: nothing was changed."
    assert_output --partial "tacctl rollback 0.2.3 --apply --yes"
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]
}

@test "rollback: a management ACL entry with services stops it, the dry run and --apply alike, and changes nothing" {
    _state_024
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8,172.16.100.0/23:tcp/22,udp/161 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab add 192.0.2.0/24:icmp > /dev/null
    before=$(_sums)
    n=$(_snapshots)
    for args in "" "--apply" "--apply --yes"; do
        # shellcheck disable=SC2086
        run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 $args
        assert_failure 1
        assert_output --partial "The management ACL has 2 entries with services"
        assert_output --partial "mgmt_acl.permits: 172.16.100.0/23:tcp/22,udp/161   (tacctl config mgmt-acl remove 172.16.100.0/23:tcp/22,udp/161)"
        assert_output --partial "scope_mgmt_acl.permits.lab: 192.0.2.0/24:icmp   (tacctl scope mgmt-acl lab remove 192.0.2.0/24:icmp)"
        assert_output --partial "would permit every protocol and port"
        assert_output --partial "Nothing was changed."
        refute_output --partial "10.0.0.0/8"
    done
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]

    # removed, the same state rolls back
    "$TACCTL_BIN_SCRIPT" config mgmt-acl remove 172.16.100.0/23 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab remove 192.0.2.0/24 > /dev/null
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_success
    assert_output --partial "Roll back to 0.2.3 (dry run)"
}

@test "rollback: --apply refuses while a setting would be dropped and --yes is missing" {
    _state_024
    before=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply
    assert_failure 1
    assert_output --partial "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed."
    [[ "$(_sums)" == "$before" ]]
}

@test "rollback --apply --yes: snapshot first, the files converted, store.yaml byte-identical, a second run changes nothing" {
    _state_024
    store_before=$(sha256sum "${TACCTL_STATE_DIR}/store.yaml")
    run _overrides
    assert_output --partial "max_concurrency: 16"
    run cat "${TACCTL_STATE_DIR}/console.yaml"
    assert_output --partial "password_cache:"
    assert_output --partial "space_completion: false"
    run cat "${TACCTL_STATE_DIR}/devices.yaml"
    assert_output --partial "snmp:"
    assert_output --partial "location:"
    grep -q "TACCTL_ASKPASS" "$TACCTL_TIER_SUDOERS_FILE"
    n=$(_snapshots)

    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply --yes
    assert_success
    assert_output --partial "Config snapshot saved to"
    assert_output --partial "removed 2 keys"
    assert_output --partial "console.yaml: removed settings.password_cache"
    assert_output --partial "devices.yaml: removed the SNMP settings of 2 devices"
    assert_output --partial "${TACCTL_TIER_SUDOERS_FILE}: rewritten with the text 0.2.3 writes"
    assert_output --partial "tacctl upgrade --branch 0.2.3"
    [[ "$(_snapshots)" == "$((n + 1))" ]]
    # The snapshot holds the 0.2.4 form, the devices' credentials included.
    snap=$(find "$TACCTL_STATE_DIR/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -1)
    grep -q "max_concurrency" "$snap/tacctl.yaml"
    grep -q "password_cache" "$snap/console.yaml"
    grep -q "snmp:" "$snap/devices.yaml"
    [[ -s "$snap/snmp/devices/sw2.yaml" ]]

    [[ "$(sha256sum "${TACCTL_STATE_DIR}/store.yaml")" == "$store_before" ]]
    run _overrides
    refute_output --partial "max_concurrency"
    refute_output --partial "device:"
    assert_output --partial "engineer: engineer"
    run cat "${TACCTL_STATE_DIR}/console.yaml"
    refute_output --partial "password_cache"
    assert_output --partial "engineer: enable"
    assert_output --partial "space_completion: false"
    assert_output --partial "list_max: 40"
    run cat "${TACCTL_STATE_DIR}/devices.yaml"
    refute_output --partial "snmp"
    assert_output --partial "location:"
    assert_output --partial "sw1"
    # The 0.2.4-only files stay: the devices' credentials and the records.
    [[ -s "${TACCTL_STATE_DIR}/snmp/devices/sw2.yaml" ]]
    [[ -s "${TACCTL_VAR_LIB}/devices-config.json" ]]
    [[ -s "${TACCTL_VAR_LIB}/device-config/sw1.yaml" ]]
    # The tiers drop-in is 0.2.3's text.
    run grep -c "TACCTL_ASKPASS\|device snmp\|console forget\|device config pull" "$TACCTL_TIER_SUDOERS_FILE"
    assert_output "0"
    grep -q 'Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"' "$TACCTL_TIER_SUDOERS_FILE"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success

    after=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply --yes
    assert_success
    assert_output --partial "Nothing to convert: every file is one 0.2.3 can read."
    [[ "$(_sums)" == "$after" ]]
    [[ "$(_snapshots)" == "$((n + 1))" ]]
}

@test "rollback --apply: a state with nothing dropped needs no --yes" {
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply
    assert_success
    assert_output --partial "Applying."
    assert_output --partial "Nothing to convert: every file is one 0.2.3 can read."
}

@test "rollback: a registry with SNMP maps is one the converted state reads again (0.2.4's own parser as the check)" {
    _state_024
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply --yes
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    assert_success
    assert_output --partial "sw1"
    assert_output --partial "sw2"
    run "$TACCTL_BIN_SCRIPT" device snmp sw1
    assert_success
    refute_output --partial "(device)"
}

@test "rollback: it is the superuser's alone; an engineer, an operator and a readonly user are refused" {
    _state_024
    "$TACCTL_BIN_SCRIPT" user add oper operator --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add rdo readonly --hash "$HASH" --scopes lab > /dev/null
    before=$(_sums)
    stub_cmd id 'echo "users tac-users tac-engineer"'
    SUDO_USER=erin run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
    SUDO_USER=erin run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply --yes --hosts
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
    stub_cmd id 'echo "users tac-users tac-operator"'
    SUDO_USER=oper run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_failure 1
    assert_output --partial "is not permitted for the operator tier"
    stub_cmd id 'echo "users tac-users tac-readonly"'
    SUDO_USER=rdo run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_failure 1
    assert_output --partial "is not permitted for the readonly tier"
    [[ "$(_sums)" == "$before" ]]
    # A superuser may.
    stub_cmd id 'echo "users tac-users tac-superuser"'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_success
    assert_output --partial "Roll back to 0.2.3 (dry run)"
}

@test "rollback --hosts: accepted, no host is synced and no script is pushed" {
    _state_024
    printf 'authsrv|local||lab|127.0.0.1|\nweb1|admin@web1.example.net||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    rm -f "$PUSHED"
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3 --apply --yes --hosts
    assert_success
    assert_output --partial "Applying."
    refute_output --partial "Taking the engineers' sudo off"
    [[ ! -e "$PUSHED" ]]
    ! stub_called "^ssh "
    run _overrides
    refute_output --partial "max_concurrency"
}

@test "rollback 0.2.9: the dry run lists every step and warning and writes nothing" {
    _state_029
    before=$(_sums)
    n=$(_snapshots)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --hosts
    assert_success
    assert_output --partial "Roll back to 0.2.9 (dry run)"
    assert_output --partial "tacctl.yaml: remove the keys 0.2.9 does not know   [does]"
    assert_output --partial "remove device.apply.transport"
    assert_output --partial "remove netconf_scope.lab.state"
    assert_output --partial "devices.yaml: remove the per-device NETCONF service setting   [does]"
    assert_output --partial "remove the netconf map of sw2 (enable, connection-limit 5)"
    assert_output --partial "leaves ${TACCTL_VAR_LIB}/devices-config.json"
    assert_output --partial "1 record has the 'via' field of its 'applied' part"
    assert_output --partial "0.2.9 ignores the fields it does not know"
    assert_output --partial "no host is synced"
    assert_output --partial "Settings 0.2.9 cannot use are dropped"
    assert_output --partial "device.apply.transport=netconf"
    assert_output --partial "This was a dry run: nothing was changed."
    assert_output --partial "tacctl rollback 0.2.9 --apply --yes"
    refute_output --partial "console.yaml: write it"
    refute_output --partial "put back the sudoers drop-ins"
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]
}

@test "rollback 0.2.9 --apply --yes: the keys and device maps removed, what 0.2.9 reads left, a second run changes nothing" {
    _state_029
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply
    assert_failure 1
    assert_output --partial "The warnings above need your decision"
    n=$(_snapshots)
    kept=("$TACCTL_VAR_LIB/devices-config.json" "$TACCTL_VAR_LIB/device-apply/shapes.json" "${TACCTL_STATE_DIR}/console.yaml" "${TACCTL_STATE_DIR}/store.yaml" "$TACCTL_TIER_SUDOERS_FILE")
    records=$(sha256sum "${kept[@]}")
    : > "$CALLS_LOG"

    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply --yes
    assert_success
    assert_output --partial "Config snapshot saved to"
    assert_output --partial "removed 4 keys"
    assert_output --partial "removed the NETCONF service setting of 1 device"
    assert_output --partial "tacctl upgrade --branch 0.2.9"
    stub_called "^logger .*rollback target=0.2.9 keys=4"
    [[ "$(_snapshots)" == "$((n + 1))" ]]
    snap=$(find "$TACCTL_STATE_DIR/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -1)
    grep -q "netconf_scope" "$snap/tacctl.yaml"
    grep -q "netconf:" "$snap/devices.yaml"

    run _overrides
    refute_output --partial "netconf_scope"
    refute_output --partial "transport: netconf"
    assert_output --partial "confirm_timeout: 15"
    assert_output --partial "max_concurrency: 16"
    run cat "${TACCTL_STATE_DIR}/devices.yaml"
    refute_output --partial "netconf"
    assert_output --partial "sw2"
    # What 0.2.9 reads as it is, and the drop-in (0.2.10 changed none), stay
    # byte for byte.
    [[ "$(sha256sum "${kept[@]}")" == "$records" ]]
    [[ -e "$TACCTL_VAR_LIB/device-apply/locks/sw2.lock" ]]
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success

    after=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply --yes
    assert_success
    assert_output --partial "Nothing to convert: every file is one 0.2.9 can read."
    [[ "$(_sums)" == "$after" ]]
    [[ "$(_snapshots)" == "$((n + 1))" ]]
}

@test "rollback 0.2.9: a state without the 0.2.10 settings has nothing to convert" {
    _state_024
    # The state allows the password cache to engineer and superuser, and
    # 0.2.9 turns it on for every user of those tiers: that is the one
    # warning, and --apply refuses without --yes and changes nothing.
    local before
    before=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply
    assert_failure 1
    assert_line "  1. Users who gain a system shell or the password cache"
    refute_line --regexp '^  2\. [A-Z]'
    assert_line --partial "engineer: erin (the cache is on for the tier again, without their own choice)"
    assert_output --partial "The warnings above need your decision"
    [[ "$(_sums)" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply --yes
    assert_success
    assert_output --partial "Nothing to convert: every file is one 0.2.9 can read."
}

@test "rollback: a pending or unknown apply stops it for every target, the dry run too, and changes nothing" {
    _state_029
    cat > "$TACCTL_VAR_LIB/devices-config.json" <<'JSON'
{"version": 1, "devices": {
 "sw2": {"address": "192.0.2.8", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply"}}}}
JSON
    before=$(_sums)
    n=$(_snapshots)
    for target in 0.2.20 0.2.19 0.2.9 0.2.3; do
        for args in "" "--apply --yes"; do
            # shellcheck disable=SC2086
            run "$TACCTL_BIN_SCRIPT" rollback "$target" $args
            assert_failure 1
            assert_output --partial "is not settled on 1 device"
            assert_output --partial "sw2: pending until 2026-10-13"
            assert_output --partial "tacctl device config apply sw2 --check"
            assert_output --partial "tacctl device config forget sw2"
            assert_output --partial "Nothing was changed."
        done
    done
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]
}

@test "rollback 0.2.20: the dry run names the release before this one and writes nothing; this release is no target" {
    _state_024
    before=$(_sums)
    n=$(_snapshots)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.20 --hosts
    assert_success
    assert_output --partial "Roll back to 0.2.20 (dry run)"
    assert_output --partial "nothing to do for 0.2.20: this release changed nothing on the enrolled hosts"
    assert_output --partial "This was a dry run: nothing was changed."
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.19 --hosts
    assert_success
    assert_output --partial "Roll back to 0.2.19 (dry run)"
    assert_output --partial "put back the per-tier sudoers drop-in 0.2.19 writes"
    [[ "$(_sums)" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.21
    assert_failure 1
    assert_output --partial "'0.2.21' is not a release to roll back to"
    assert_output --partial "prepares the state for 0.2.20 (the release before this one)"
}

@test "rollback 0.2.9 is the superuser's alone" {
    _state_029
    before=$(_sums)
    stub_cmd id 'echo "users tac-users tac-engineer"'
    SUDO_USER=erin run "$TACCTL_BIN_SCRIPT" rollback 0.2.9 --apply --yes
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
    [[ "$(_sums)" == "$before" ]]
}
