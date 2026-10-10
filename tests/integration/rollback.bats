#!/usr/bin/env bats
# Integration tests for 'tacctl rollback <version> [--apply] [--yes] [--hosts]'
# (docs/plans/0.2.4-plan.md D73): the 0.2.4 state is built with the verbs
# that write the formats a 0.2.3 binary does not read, then rolled back. The
# dry run is the default and writes nothing; --apply takes a snapshot first,
# needs --yes while a setting is dropped, leaves store.yaml alone and is
# idempotent; --hosts is accepted and touches no host. The 0.2.3 parsers
# themselves are checked in internal/cli/rollback_test.go
# (TestRollbackRealOldBinary builds the 0.2.3 tag).

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
    "$TACCTL_BIN_SCRIPT" config devices max-concurrency 16 > /dev/null
    "$TACCTL_BIN_SCRIPT" config devices timeout 120 > /dev/null
    mkdir -p "$TACCTL_VAR_LIB/device-config" "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    echo '{"version": 1, "devices": {}}' > "$TACCTL_VAR_LIB/devices-config.json"
    echo 'aaa: []' > "$TACCTL_VAR_LIB/device-config/sw1.yaml"
    "$TACCTL_BIN_SCRIPT" config sudoers tiers install > /dev/null <<< "y"
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
    assert_output --partial "prepares the state for 0.2.3 only (0.2.2 is older)"
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
    assert_output --partial "prepares the state for 0.2.3 only"
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
