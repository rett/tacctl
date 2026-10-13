#!/usr/bin/env bats
# Styling is for a terminal. Output into a pipe (what bats' `run` captures)
# is plain; TACCTL_COLOR=always styles it, TACCTL_COLOR=never and NO_COLOR
# take it out, and TACCTL_COLOR wins over NO_COLOR. The decision is made once
# per process (internal/ui/colour.go, internal/app) for standard output and
# standard error separately.

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
    # What the caller of the suite has set must not decide these tests.
    unset NO_COLOR TACCTL_COLOR
    export TERM=xterm
    ESC=$'\e'
}

# styled <cmd...>: runs the command with stdout and stderr in files and says
# whether either holds an escape byte (0: some did, 1: none).
styled() {
    "$@" > "${BATS_TEST_TMPDIR}/out" 2> "${BATS_TEST_TMPDIR}/err" || true
    grep -q "$ESC" "${BATS_TEST_TMPDIR}/out" "${BATS_TEST_TMPDIR}/err"
}

# assert_styled / assert_plain <cmd...>: bats does not fail a test on a
# negated command in the middle of it, so both say so themselves.
assert_styled() { styled "$@" || { echo "no escape in the output of: $*" >&2; return 1; }; }
assert_plain() { ! styled "$@" || { echo "escape in the output of: $*" >&2; return 1; }; }

# An error line (stderr) and a listing with a bold label (stdout).
errline() { "$TACCTL_BIN_SCRIPT" user show nobody; }
listing() { "$TACCTL_BIN_SCRIPT" status; }

@test "colour: a pipe is plain" {
    run "$TACCTL_BIN_SCRIPT" user show nobody
    assert_failure
    [[ "$output" != *"$ESC"* ]]
    assert_output --partial "[ERROR]"
    assert_plain errline
    assert_plain listing
}

@test "colour: TACCTL_COLOR=always styles a pipe" {
    export TACCTL_COLOR=always
    run "$TACCTL_BIN_SCRIPT" user show nobody
    assert_failure
    [[ "$output" == *"${ESC}[0;31m[ERROR]${ESC}[0m"* ]]
    assert_styled errline
    assert_styled listing
}

@test "colour: TACCTL_COLOR=never and NO_COLOR take it out" {
    export TACCTL_COLOR=never
    run "$TACCTL_BIN_SCRIPT" user show nobody
    [[ "$output" != *"$ESC"* ]]
    assert_output --partial "[ERROR]"
    assert_plain listing
    unset TACCTL_COLOR
    export NO_COLOR=1
    run "$TACCTL_BIN_SCRIPT" user show nobody
    [[ "$output" != *"$ESC"* ]]
    assert_plain errline
}

@test "colour: TACCTL_COLOR wins over NO_COLOR, in either direction" {
    export NO_COLOR=1 TACCTL_COLOR=always
    assert_styled errline
    export NO_COLOR= TACCTL_COLOR=never
    assert_plain errline
}

@test "colour: an empty NO_COLOR and an unknown TACCTL_COLOR are ignored" {
    export NO_COLOR= TACCTL_COLOR=sometimes
    assert_plain errline
    export TACCTL_COLOR=ALWAYS
    assert_styled errline
}
