#!/usr/bin/env bats
# Integration tests for `tacctl shell`: -c and batch mode through a stubbed
# `sudo` that records its argv and runs the rest (the shell runs every line
# as `sudo [-n] <exe> <words>`), exit statuses, the history file and its
# redaction. The interactive mode is covered by the pty tests of
# internal/shell.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    # sudo: drop -n and NAME=value, run the rest as this user.
    stub_cmd sudo 'while [[ "${1:-}" == -n || "${1:-}" == *=* ]]; do shift; done; exec "$@"'
    stub_cmd id 'echo tester adm'
    export HOME="${BATS_TEST_TMPDIR}/home"
    mkdir -p "$HOME"
    HISTFILE_PATH="${HOME}/.local/state/tacctl/history"
}

# sudo_lines: the sudo calls of the run, one per line.
sudo_lines() { grep '^sudo ' "$CALLS_LOG" || true; }

@test "shell -c: runs the line as 'sudo <exe> <words>' and prints its output" {
    run "$TACCTL_BIN_SCRIPT" shell -c "user list"
    assert_success
    assert_output --partial "USERNAME"
    run sudo_lines
    assert_output --regexp '^sudo /[^ ]*/dist/tacctl user list$'
}

@test "shell -c: a tac-users member's line runs with sudo -n" {
    stub_cmd id 'echo tester tac-users tac-readonly'
    run "$TACCTL_BIN_SCRIPT" shell -c "user list"
    assert_success
    run sudo_lines
    assert_output --regexp '^sudo -n /[^ ]*/dist/tacctl user list$'
}

@test "shell -c: a tier denial replaces sudo's password message; other refusals keep it" {
    bats_require_minimum_version 1.5.0
    stub_cmd id 'echo tester tac-users tac-readonly'
    stub_cmd sudo 'echo "sudo: a password is required" >&2; exit 1'
    run --separate-stderr "$TACCTL_BIN_SCRIPT" shell -c "user add bob ops"
    assert_failure 1
    [[ "$stderr" == *"'tacctl user add' is not permitted for the readonly tier."* ]]
    [[ "$stderr" != *"a password is required"* ]]
    # A line the readonly rules cover: sudo's own message stays.
    run --separate-stderr "$TACCTL_BIN_SCRIPT" shell -c "user list"
    assert_failure 1
    [[ "$stderr" == *"sudo: a password is required"* ]]
    [[ "$stderr" != *"not permitted"* ]]
}

@test "shell -c: the line's exit status is the shell's" {
    run "$TACCTL_BIN_SCRIPT" user show nosuchuser
    local direct=$status
    [ "$direct" -ne 0 ]
    run "$TACCTL_BIN_SCRIPT" shell -c "user show nosuchuser"
    [ "$status" -eq "$direct" ]
}

@test "shell: metacharacters are words, nothing else runs" {
    run "$TACCTL_BIN_SCRIPT" shell -c "user list; touch ${BATS_TEST_TMPDIR}/pwned \$(touch ${BATS_TEST_TMPDIR}/pwned2)"
    assert_failure
    assert_file_not_exists "${BATS_TEST_TMPDIR}/pwned"
    assert_file_not_exists "${BATS_TEST_TMPDIR}/pwned2"
    run sudo_lines
    assert_output --partial "tacctl user list; touch ${BATS_TEST_TMPDIR}/pwned \$(touch"
}

@test "shell < file: runs the lines in order and stops at the first failure" {
    run bash -c 'printf "user list\nbogus\nuser list\n" | "$TACCTL_BIN_SCRIPT" shell'
    assert_failure 1
    run sudo_lines
    assert_line --index 0 --regexp '^sudo /[^ ]*/dist/tacctl user list$'
    assert_line --index 1 --regexp '^sudo /[^ ]*/dist/tacctl bogus$'
    [ "${#lines[@]}" -eq 2 ]
    # A batch writes no history.
    assert_file_not_exists "$HISTFILE_PATH"
}

@test "shell < file: every line succeeds, exit 0; exit stops the run" {
    run bash -c 'printf "user list\n\ngroup list\nexit\nbogus\n" | "$TACCTL_BIN_SCRIPT" shell'
    assert_success
    run sudo_lines
    [ "${#lines[@]}" -eq 2 ]
}

@test "shell: help prints a usage block without running anything" {
    run "$TACCTL_BIN_SCRIPT" shell -c "help user"
    assert_success
    assert_output --partial "User Commands"
    run sudo_lines
    assert_output ""
    run "$TACCTL_BIN_SCRIPT" shell -c "help nosuchcommand"
    assert_failure 1
    assert_output --partial "no help for 'nosuchcommand'"
}

@test "shell -c: the history is written redacted, 0600; --no-history writes none" {
    run "$TACCTL_BIN_SCRIPT" shell -c "scope secret lab set x"
    assert_file_exists "$HISTFILE_PATH"
    run cat "$HISTFILE_PATH"
    assert_output "scope secret lab set …(redacted)"
    run stat -c %a "$HISTFILE_PATH"
    assert_output "600"
    run "$TACCTL_BIN_SCRIPT" shell --no-history -c "user list"
    assert_success
    run cat "$HISTFILE_PATH"
    assert_output "scope secret lab set …(redacted)"
    # A recalled redacted line is refused, not run.
    run "$TACCTL_BIN_SCRIPT" shell --no-history -c "scope secret lab set …(redacted)"
    assert_failure 2
    run sudo_lines
    refute_output --partial "redacted"
}

@test "shell: usage errors" {
    run "$TACCTL_BIN_SCRIPT" shell --idle soon
    assert_failure 1
    assert_output --partial "Usage: tacctl shell [--no-history] [--idle <min>] [-c <line>]"
    run "$TACCTL_BIN_SCRIPT" shell extra
    assert_failure 1
    assert_output --partial "Unknown argument: 'extra'"
}
