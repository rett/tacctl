#!/usr/bin/env bats
# A confirmation prompt read from a closed stdin (< /dev/null: a script, a
# pipeline, cron) is a "no": the command says it cancelled, exits 0 and
# changes nothing. Under errexit a bare 'read' that hits end of input would
# instead end the command silently, part-way.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    stub_cmd journalctl
    load_fixture tacquito.multiscope.yaml
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1
    "$TACCTL_BIN_SCRIPT" user add zed readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" group add spare 3 SPARE-CLASS > /dev/null
}

# Everything a cancelled command must leave as it was.
state() {
    local f
    for f in "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_STATE_DIR}/tacctl.yaml" "$TACCTL_CONFIG"; do
        if [[ -f "$f" ]]; then sha256sum < "$f"; else echo "absent"; fi
    done
    find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 | sort
}

# closed <args...>: the CLI with stdin closed, colours stripped.
closed() {
    run "$TACCTL_BIN_SCRIPT" "$@" < /dev/null
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

@test "user remove with stdin closed: cancelled, exit 0, nothing changed" {
    local before
    before=$(state)
    closed user remove zed
    assert_success
    assert_output --partial "Cancelled."
    [[ "$(state)" == "$before" ]]
    "$TACCTL_BIN_SCRIPT" user show zed > /dev/null
}

@test "group remove with stdin closed: cancelled, exit 0, nothing changed" {
    local before
    before=$(state)
    closed group remove spare
    assert_success
    assert_output --partial "Cancelled."
    [[ "$(state)" == "$before" ]]
    "$TACCTL_BIN_SCRIPT" group list | grep -q spare
}

@test "scope remove with stdin closed: aborted, exit 0, nothing changed" {
    local before
    before=$(state)
    closed scope remove dmz --force
    assert_success
    assert_output --partial "About to remove scope 'dmz'."
    assert_output --partial "Aborted."
    [[ "$(state)" == "$before" ]]
    "$TACCTL_BIN_SCRIPT" scope show dmz > /dev/null
}

@test "scope prefixes remove --all, user scope remove --all and config allow clear with stdin closed: aborted, exit 0, nothing changed" {
    "$TACCTL_BIN_SCRIPT" config allow add 10.0.0.0/8 > /dev/null
    local before
    before=$(state)
    closed scope prefixes dmz remove --all --force
    assert_success
    assert_output --partial "Aborted."
    closed user scope zed remove --all
    assert_success
    assert_output --partial "Aborted."
    closed config allow clear
    assert_success
    assert_output --partial "Aborted."
    [[ "$(state)" == "$before" ]]
}

@test "log clear (TACACS+) with stdin closed: cancelled, exit 0, the logs kept" {
    mkdir -p "$TACCTL_LOG"
    echo "a record" > "${TACCTL_LOG}/accounting.log"
    closed log clear
    assert_success
    assert_output --partial "Cancelled."
    grep -q "a record" "${TACCTL_LOG}/accounting.log"
}
