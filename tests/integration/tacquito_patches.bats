#!/usr/bin/env bats
# Tests for the tacquito source patch overlay in bin/tacctl.sh
# (apply_tacquito_patches / tacquito_patches_applied). These validate the real
# patches/*.patch against a throwaway git checkout seeded with the pristine
# upstream files the patches target (tests/fixtures/tacquito-src).

load ../helpers/setup
load ../helpers/tmpenv

SP="cmds/server/config/authorizers/stringy"
AP="cmds/server/config/accounters"

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib

    # Throwaway git repo standing in for /opt/tacquito-src.
    FAKE_SRC="${BATS_TEST_TMPDIR}/tacquito-src"
    mkdir -p "$FAKE_SRC"
    cp -r "${TACCTL_SRC}/tests/fixtures/tacquito-src/." "$FAKE_SRC/"
    git -C "$FAKE_SRC" init -q
    git -C "$FAKE_SRC" config user.email t@t.local
    git -C "$FAKE_SRC" config user.name tester
    git -C "$FAKE_SRC" add -A
    git -C "$FAKE_SRC" commit -qm pristine

    # Point the overlay helpers at the fake source + the real shipped patches.
    TACQUITO_SRC="$FAKE_SRC"
    PATCH_DIR="${TACCTL_SRC}/patches"
    SESSION_GO="${FAKE_SRC}/${SP}/session.go"
    LOCAL_GO="${FAKE_SRC}/${AP}/local/local.go"
    SYSLOG_GO="${FAKE_SRC}/${AP}/syslog/syslog.go"
}

@test "patches report as not-applied on a pristine tree" {
    run tacquito_patches_applied
    assert_failure
}

@test "apply_tacquito_patches applies the default-permit patch" {
    run apply_tacquito_patches
    assert_success
    assert_output --partial "Applied tacquito patch: 0001"
    grep -q "default service = permit" "$SESSION_GO"
}

@test "apply_tacquito_patches applies the empty accounting server_msg patch" {
    run apply_tacquito_patches
    assert_success
    assert_output --partial "Applied tacquito patch: 0002"
    # Success replies no longer carry a server_msg; failure replies still do.
    run grep -c 'SetAcctReplyServerMsg("success' "$LOCAL_GO" "$SYSLOG_GO"
    assert_output --partial "local.go:0"
    assert_output --partial "syslog.go:0"
    grep -q 'SetAcctReplyServerMsg("unexpected accounting flag")' "$LOCAL_GO"
}

@test "apply is idempotent: second run does not re-apply" {
    apply_tacquito_patches
    run apply_tacquito_patches
    refute_output --partial "Applied tacquito patch"
    # Sentinel that appears exactly once in the patched file (the phrase
    # "default service = permit" intentionally recurs across two comments).
    run grep -c "clientNamedCmd := false" "$SESSION_GO"
    assert_output "1"
}

@test "tacquito_patches_applied flips with apply / revert" {
    apply_tacquito_patches
    run tacquito_patches_applied
    assert_success
    git -C "$FAKE_SRC" checkout -- .
    run tacquito_patches_applied
    assert_failure
}

@test "apply aborts loudly when a patch no longer applies (upstream drift)" {
    echo "// upstream rewrote this file" > "$SESSION_GO"
    git -C "$FAKE_SRC" commit -qam drift
    run apply_tacquito_patches
    assert_failure
    assert_output --partial "will not apply cleanly"
}
