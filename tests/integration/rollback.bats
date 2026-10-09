#!/usr/bin/env bats
# Integration tests for 'tacctl rollback <version> [--apply] [--yes] [--hosts]'
# (docs/plans/0.2.3-plan.md D50): the 0.2.3 state is built with the verbs
# that write the formats a 0.2.2 binary does not read, then rolled back. The
# dry run is the default and writes nothing; --apply takes a snapshot first,
# needs --yes while a warning applies, leaves store.yaml alone and is
# idempotent; --hosts syncs the enrolled hosts with TAC_REVOKE_ENGINEER=1
# (ssh stubbed as in host.bats). The 0.2.2 parsers themselves are checked in
# internal/cli/rollback_test.go (TestRollbackRealOldBinary builds the tag).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    export PUSHED="${BATS_TEST_TMPDIR}/pushed"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *) [[ -z "${SSH_RUN_FAILS:-}" ]] ;;
    esac'
    stub_cmd id 'echo "users"'
}

# A 0.2.3 state: an engineer group at priv-lvl 15 (tier engineer) with a
# user in lab, per-scope SNMP settings, a break-glass user, a device with a
# location, space completion off, an engineer-sudo list.
_state_023() {
    "$TACCTL_BIN_SCRIPT" group add engineer 15 ENG-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit engineer tier engineer > /dev/null
    "$TACCTL_BIN_SCRIPT" user add erin engineer --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab version v2c > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab contact "NOC, building 2" > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab clients add 10.1.0.0/16 > /dev/null
    printf 'lab-community-1\nlab-community-1\n' | "$TACCTL_BIN_SCRIPT" scope snmp lab community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add bg-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" device add sw1 192.0.2.7 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device location sw1 "Rack 4, DC1" > /dev/null
    "$TACCTL_BIN_SCRIPT" console space-completion off > /dev/null
    "$TACCTL_BIN_SCRIPT" config linux engineer-sudo /usr/bin/systemctl > /dev/null
}

# Every regular file of the state, with its checksum.
_sums() { (cd "$TACCTL_STATE_DIR" && find . -type f ! -name '.*.lock' -print0 | sort -z | xargs -0 sha256sum); }
_snapshots() { find "$TACCTL_STATE_DIR/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | wc -l; }
_overrides() { cat "${TACCTL_STATE_DIR}/tacctl.yaml" 2>/dev/null; }

@test "rollback: a version other than 0.2.2 is refused with the reason, and nothing is read for writing" {
    _state_023
    before=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.1
    assert_failure 1
    assert_output --partial "Rolling back to 0.2.1 is not supported"
    assert_output --partial "0.2.2 changed the state as well"
    assert_output --partial "tacctl backup restore"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.0 --apply --yes
    assert_failure 1
    assert_output --partial "older than 0.2.2"
    run "$TACCTL_BIN_SCRIPT" rollback 0.1.16
    assert_failure 1
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.3
    assert_failure 1
    assert_output --partial "prepares the state for 0.2.2 only"
    run "$TACCTL_BIN_SCRIPT" rollback develop
    assert_failure 1
    assert_output --partial "'develop' is not a release this tacctl knows"
    [[ "$(_sums)" == "$before" ]]
}

@test "rollback: usage" {
    run "$TACCTL_BIN_SCRIPT" rollback
    assert_failure 1
    assert_output --partial "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --bogus
    assert_failure 1
    assert_output --partial "Usage: tacctl rollback <version>"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 extra
    assert_failure 1
}

@test "rollback: the dry run is the default, lists every step and warning, and writes nothing" {
    _state_023
    before=$(_sums)
    n=$(_snapshots)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --hosts
    assert_success
    assert_output --partial "Roll back to 0.2.2 (dry run)"
    assert_output --partial "tacctl.yaml: remove the keys 0.2.2 does not know   [does]"
    assert_output --partial "remove linux.engineer_sudo"
    assert_output --partial "remove snmp_scope.lab.version"
    assert_output --partial "remove breakglass_scope.lab.users"
    assert_output --partial "console.yaml: write it the way 0.2.2 reads it   [does]"
    assert_output --partial "remove tiers.engineer: enable"
    assert_output --partial "remove settings.space_completion: false"
    assert_output --partial "devices.yaml: remove the per-device location   [does]"
    assert_output --partial "remove the location of 1 device: sw1"
    assert_output --partial "moves ${TACCTL_STATE_DIR}/snmp/lab.yaml"
    assert_output --partial "snmp.rolled-back-<timestamp>"
    assert_output --partial "store.yaml untouched"
    assert_output --partial "Warnings (--apply refuses without --yes while any applies)"
    assert_output --partial "Groups change tier"
    assert_output --partial "group engineer (priv-lvl 15): engineer now, superuser under 0.2.2 (higher)"
    assert_output --partial "Settings 0.2.2 cannot use are dropped"
    assert_output --partial "This was a dry run: nothing was changed."
    assert_output --partial "tacctl rollback 0.2.2 --apply --yes --hosts"
    [[ "$(_sums)" == "$before" ]]
    [[ "$(_snapshots)" == "$n" ]]
    [[ ! -e "$PUSHED" ]]
}

@test "rollback: --apply refuses while a warning applies and --yes is missing" {
    _state_023
    before=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply
    assert_failure 1
    assert_output --partial "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed."
    [[ "$(_sums)" == "$before" ]]
}

@test "rollback --apply --yes: snapshot first, the files converted, store.yaml byte-identical, a second run changes nothing" {
    _state_023
    store_before=$(sha256sum "${TACCTL_STATE_DIR}/store.yaml")
    run _overrides
    assert_output --partial "snmp_scope:"
    assert_output --partial "breakglass_scope:"
    assert_output --partial "engineer_sudo:"
    run cat "${TACCTL_STATE_DIR}/console.yaml"
    assert_output --partial "engineer: enable"
    assert_output --partial "space_completion: false"
    run cat "${TACCTL_STATE_DIR}/devices.yaml"
    assert_output --partial "location:"
    n=$(_snapshots)

    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes
    assert_success
    assert_output --partial "Config snapshot saved to"
    assert_output --partial "removed 5 keys"
    assert_output --partial "console.yaml: removed tiers.engineer and settings.space_completion"
    assert_output --partial "devices.yaml: removed the location of 1 device"
    assert_output --partial "${TACCTL_STATE_DIR}/snmp: moved to ${TACCTL_STATE_DIR}/snmp.rolled-back-"
    [[ ! -e "${TACCTL_STATE_DIR}/snmp/lab.yaml" ]]
    compgen -G "${TACCTL_STATE_DIR}/snmp.rolled-back-*/lab.yaml" > /dev/null
    assert_output --partial "tacctl upgrade --branch 0.2.2"
    assert_output --partial "Before upgrading, note the newest entry of 'tacctl backup list'"
    assert_output --partial "That entry is your way back: 'tacctl backup restore <id>'"
    [[ "$(_snapshots)" == "$((n + 1))" ]]
    # The snapshot holds the 0.2.3 form.
    snap=$(find "$TACCTL_STATE_DIR/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -1)
    grep -q "snmp_scope" "$snap/tacctl.yaml"
    grep -q "location:" "$snap/devices.yaml"
    grep -q "engineer: enable" "$snap/console.yaml"

    [[ "$(sha256sum "${TACCTL_STATE_DIR}/store.yaml")" == "$store_before" ]]
    run _overrides
    refute_output --partial "snmp_scope"
    refute_output --partial "breakglass_scope"
    refute_output --partial "engineer_sudo"
    assert_output --partial "engineer: engineer"
    run cat "${TACCTL_STATE_DIR}/console.yaml"
    refute_output --partial "engineer"
    refute_output --partial "space_completion"
    assert_output --partial "list_max: 40"
    run cat "${TACCTL_STATE_DIR}/devices.yaml"
    refute_output --partial "location"
    assert_output --partial "sw1"
    # The credentials of the scope are moved aside whole, not left live.
    [[ ! -e "${TACCTL_STATE_DIR}/snmp/lab.yaml" ]]
    snmp_aside=$(compgen -G "${TACCTL_STATE_DIR}/snmp.rolled-back-*/lab.yaml")
    [[ -s "$snmp_aside" ]]
    # tacctl still reads the converted state.
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    assert_success
    assert_output --partial "sw1"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success

    after=$(_sums)
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes
    assert_success
    assert_output --partial "Nothing to convert: every file is one 0.2.2 can read."
    [[ "$(_sums)" == "$after" ]]
    [[ "$(_snapshots)" == "$((n + 1))" ]]
}

@test "rollback --apply: a state without a warning needs no --yes" {
    "$TACCTL_BIN_SCRIPT" console space-completion off > /dev/null
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply
    assert_success
    assert_output --partial "console.yaml: removed tiers.engineer and settings.space_completion"
    run cat "${TACCTL_STATE_DIR}/console.yaml"
    refute_output --partial "space_completion"
    refute_output --partial "engineer"
}

@test "rollback: it is the superuser's alone; an engineer, an operator and a readonly user are refused" {
    _state_023
    "$TACCTL_BIN_SCRIPT" user add oper operator --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add rdo readonly --hash "$HASH" --scopes lab > /dev/null
    before=$(_sums)
    stub_cmd id 'echo "users tac-users tac-engineer"'
    SUDO_USER=erin run "$TACCTL_BIN_SCRIPT" rollback 0.2.2
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
    SUDO_USER=erin run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes --hosts
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
    stub_cmd id 'echo "users tac-users tac-operator"'
    SUDO_USER=oper run "$TACCTL_BIN_SCRIPT" rollback 0.2.2
    assert_failure 1
    assert_output --partial "is not permitted for the operator tier"
    stub_cmd id 'echo "users tac-users tac-readonly"'
    SUDO_USER=rdo run "$TACCTL_BIN_SCRIPT" rollback 0.2.2
    assert_failure 1
    assert_output --partial "is not permitted for the readonly tier"
    [[ "$(_sums)" == "$before" ]]
    # A superuser may.
    stub_cmd id 'echo "users tac-users tac-superuser"'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" rollback 0.2.2
    assert_success
    assert_output --partial "Roll back to 0.2.2 (dry run)"
}

@test "rollback --hosts: every enrolled host is synced through host sync with TAC_REVOKE_ENGINEER=1" {
    _state_023
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_success
    rm -f "$PUSHED"
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes --hosts
    assert_success
    assert_output --partial "Taking the engineers' sudo off 1 host."
    assert_output --partial "web1: synced"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_output --partial $'TAC_ENGINEER_SUDO=ALL\nTAC_REVOKE_ENGINEER=1\nTAC_PROTOCOL=6'
    stub_called "ssh .*admin@web1.example.net .*sudo -n bash /tmp/tacctl.AbCd1234 --accounts-only"
    # The files are converted too.
    run _overrides
    refute_output --partial "snmp_scope"
    # An ordinary sync afterwards does not revoke.
    rm -f "$PUSHED"
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    run grep -c '^TAC_REVOKE_ENGINEER=' "$PUSHED"
    assert_output "0"
}

@test "rollback --hosts: a host that cannot be synced is named and the exit status is 1" {
    _state_023
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_success
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" rollback 0.2.2 --apply --yes --hosts
    assert_failure 1
    assert_output --partial "Not synced: web1. Their engineers may still have sudo there."
    assert_output --partial "The rollback did not finish"
    run _overrides
    refute_output --partial "snmp_scope"
}
