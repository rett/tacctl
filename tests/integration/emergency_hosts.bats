#!/usr/bin/env bats
# Integration tests for the emergency lockdown on enrolled hosts (0.2.23,
# D309-D311): 'emergency lockdown <scope> enable|disable' changes the devices
# and offers the sync of the scope's hosts, the hosts that are not settled
# stay on the record's pending list, and 'host sync' completes them. ssh is
# stubbed as in host.bats: the stub keeps what would have been copied to the
# host. The scope's name is typed back at a terminal, so 'enable' runs under
# script(1), which gives it a pseudo-terminal; its ssh stub never reads it.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

bats_require_minimum_version 1.5.0

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    export PUSHED="${BATS_TEST_TMPDIR}/pushed"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add bob operator --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add carol readonly --hash "$HASH" --scopes lab > /dev/null
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    stub_cmd getent 'case "$2" in
        web2*) echo "192.0.2.51 STREAM $2" ;;
        *) echo "192.0.2.50 STREAM web1" ;;
    esac'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *) [[ -z "${SSH_RUN_FAILS:-}" ]] ;;
    esac'
    "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" host enroll admin@web2.example.net --scope lab > /dev/null
    : > "$CALLS_LOG"
}

# plain: tacctl's output without colours (stdout and stderr).
plain() {
    local rc=0
    "$TACCTL_BIN_SCRIPT" "$@" > "${BATS_TEST_TMPDIR}/plain.out" 2>&1 || rc=$?
    sed -E 's/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/plain.out"
    return "$rc"
}

# on_terminal <typed>... -- <argument>...: 'emergency lockdown <argument>...' on
# a terminal, each <typed> word a line typed.
on_terminal() {
    local typed=() cmd rc=0
    while [[ "$1" != "--" ]]; do typed+=("$1"); shift; done
    shift
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" emergency lockdown "$@"
    printf '%s\n' "${typed[@]}" | script -qec "$cmd" /dev/null > "${BATS_TEST_TMPDIR}/term.out" 2>&1 || rc=$?
    sed -E 's/\r$//; s/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/term.out"
    return "$rc"
}

# no_record: no emergency lockdown is in tacctl.yaml (the file goes with its last key).
no_record() { ! grep -qs emergency "$OVERRIDES"; }

# header: the variables of the script the last sync pushed.
header() { sed '/^# --- tacctl Linux client/,$d' "$PUSHED"; }

@test "lockdown enable: names the hosts and the command, a 'no' sends nothing; host sync then closes them" {
    run on_terminal lab n -- lab enable --reason drill
    assert_success
    assert_output --partial "Hosts (2): web1, web2."
    assert_output --partial "[WARN] The lockdown has not reached 2 enrolled hosts (ssh key logins, forwarding and open sessions of the accounts that are not superusers stay open there): tacctl host sync web1 web2"
    refute_output --partial "does not name every group"
    run grep -c "^ssh .*bash /tmp/tacctl" "$CALLS_LOG"
    assert_output "0"
    run grep -A3 "pending:" "$OVERRIDES"
    assert_output --partial "- web1"
    assert_output --partial "- web2"
    run plain emergency lockdown status
    assert_success
    assert_output --partial "Hosts not locked yet (2 of 2): web1, web2"
    run plain emergency lockdown status --json
    assert_output --partial '"pending_hosts": ['
    # the first sync of a host that waits ends the sessions too, the next only keeps the file
    run plain host sync web1
    assert_success
    run header
    assert_line "TAC_LOCKDOWN=on-end"
    assert_line "TAC_PROTOCOL=7"
    run plain host sync web1
    assert_success
    run header
    assert_line "TAC_LOCKDOWN=on"
    run plain host sync web2
    assert_success
    ! grep -qs pending "$OVERRIDES"
    run plain emergency lockdown status
    assert_output --partial "Hosts (2): the sshd lockdown is in force on web1, web2."
}

@test "lockdown enable of some groups says that the hosts lock every account that is not a superuser's" {
    run on_terminal -- lab enable operator --dry-run
    assert_success
    assert_output --partial "This lockdown does not name every group of the scope's users. A host knows tiers, not the store's groups, so on the hosts it locks EVERY account that is not a superuser's, including carol, whose groups are not locked."
    no_record
}

@test "lockdown disable: with --yes the hosts are synced and a failing one stays on the list" {
    run on_terminal lab n -- lab enable
    assert_success
    # 'enable' again with --yes offers the hosts that wait and syncs both
    run plain emergency lockdown lab enable --yes
    assert_success
    assert_output --partial "Already locked"
    assert_output --partial "The lockdown is in force on the hosts."
    run header
    assert_line "TAC_LOCKDOWN=on-end"
    ! grep -qs pending "$OVERRIDES"

    SSH_RUN_FAILS=1 run plain emergency lockdown lab disable --yes
    assert_success
    assert_output --partial "Emergency lockdown LIFTED on scope 'lab'"
    assert_output --partial "2 enrolled hosts not settled (web1, web2;"
    run plain emergency lockdown status
    assert_output --partial "The lockdown of scope 'lab' is lifted, but sshd's lockdown drop-in is still on 2 enrolled hosts (web1, web2): tacctl host sync web1 web2"
    run plain config validate
    assert_output --partial "sshd's lockdown drop-in of scope lab is still on 2 enrolled hosts (web1, web2)"

    run plain host sync web1 web2
    assert_success
    run header
    refute_line --regexp '^TAC_LOCKDOWN='
    no_record
}

@test "lockdown disable with no terminal and no --yes names the command and sends nothing" {
    run on_terminal lab n -- lab enable
    assert_success
    run plain emergency lockdown lab enable --yes
    assert_success
    : > "$CALLS_LOG"
    run plain emergency lockdown lab disable
    assert_success
    assert_output --partial "[WARN] sshd's lockdown drop-in is still on 2 enrolled hosts: tacctl host sync web1 web2"
    run grep -c "^ssh .*bash /tmp/tacctl" "$CALLS_LOG"
    assert_output "0"
}

@test "lockdown: a host enrolled while it stands gets the drop-in, a hand-written script carries it" {
    run on_terminal lab n -- lab enable
    assert_success
    run plain emergency lockdown lab enable --yes
    assert_success
    run plain host sync web2
    assert_success
    "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab > /dev/null
    run header
    assert_line "TAC_LOCKDOWN=on"
    run plain config linux script --scope lab --server 192.0.2.1 --output "${BATS_TEST_TMPDIR}/lab.sh"
    assert_success
    run sed '/^# --- tacctl Linux client/,$d' "${BATS_TEST_TMPDIR}/lab.sh"
    assert_line "TAC_LOCKDOWN=on"
}

@test "rollback is refused while a lockdown has enrolled hosts, for every target" {
    run on_terminal lab n -- lab enable
    assert_success
    for target in 0.2.22 0.2.21 0.2.20 0.2.19; do
        run plain rollback "$target"
        assert_failure
        assert_output --partial "Scope lab is locked down and has enrolled hosts (web1, web2)"
        assert_output --partial "Lift it first and sync the hosts: tacctl emergency lockdown lab disable; tacctl host sync web1 web2. Nothing was changed."
    done
    # lifted on the devices, the hosts still hold the file: still refused
    run plain emergency lockdown lab enable --yes
    assert_success
    SSH_RUN_FAILS=1 run plain emergency lockdown lab disable --yes
    assert_success
    run plain rollback 0.2.22
    assert_failure
    assert_output --partial "A lockdown that was lifted still has its sshd drop-in on web1, web2."
    # settled, the rollback goes on
    run plain host sync web1 web2
    assert_success
    run plain rollback 0.2.22
    assert_success
    refute_output --partial "locked down"
}

@test "a snapshot brings the record back with its list of hosts" {
    run on_terminal lab n -- lab enable
    assert_success
    # the snapshot a change takes first holds the lockdown and the list
    "$TACCTL_BIN_SCRIPT" user add dave readonly --hash "$HASH" --scopes lab > /dev/null
    local id
    id=$(ls "${TACCTL_STATE_DIR}/backups" | grep '^2' | sort | tail -n 1)
    grep -q "pending" "${TACCTL_STATE_DIR}/backups/${id}/tacctl.yaml"
    run plain emergency lockdown lab enable --yes
    assert_success
    run plain emergency lockdown lab disable --yes
    assert_success
    no_record
    run plain backup restore "$id" <<< "y"
    assert_success
    assert_output --partial "Emergency lockdowns change: locked now: none; locked after the restore: lab (operator, readonly)"
    run plain emergency lockdown status
    assert_output --partial "Hosts not locked yet (2 of 2): web1, web2"
}

@test "a snapshot taken before the lockdown, restored while the hosts hold the file, lists them for the next sync" {
    run on_terminal lab n -- lab enable
    assert_success
    run plain host sync web1 web2
    assert_success
    # the snapshot the enable took first has no lockdown
    local id d
    for d in "${TACCTL_STATE_DIR}"/backups/2*; do
        grep -q emergency "$d/tacctl.yaml" 2>/dev/null || id=$(basename "$d")
    done
    [[ -n "$id" ]]
    run plain backup restore "$id" <<< "y"
    assert_success
    assert_output --partial "sshd's lockdown drop-in on 2 enrolled hosts (web1, web2) follows the restored lockdown record only at their next sync: tacctl host sync web1 web2"
    run plain emergency lockdown status
    assert_output --partial "The lockdown of scope 'lab' is lifted, but sshd's lockdown drop-in is still on 2 enrolled hosts (web1, web2)"
    run plain emergency lockdown status --json
    assert_output --partial '"lifted": true'
    run plain host sync web1 web2
    assert_success
    no_record
}
