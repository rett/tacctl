#!/usr/bin/env bash
# Redirect tacctl's paths into the bats tmpdir so tests never touch host state.
# Call from test setup() after load helpers/setup.

tacctl_tmpenv_init() {
    export TACCTL_ETC="${BATS_TEST_TMPDIR}/etc"
    export TACCTL_STATE_DIR="${BATS_TEST_TMPDIR}/state"
    export TACCTL_VAR_LIB="${BATS_TEST_TMPDIR}/var-lib"
    export TACCTL_LOG="${BATS_TEST_TMPDIR}/log"
    export TACCTL_BIN="${BATS_TEST_TMPDIR}/bin"
    export TACCTL_CONFIG="${TACCTL_ETC}/tacquito.yaml"
    export TACCTL_OVERRIDE_DIR="${BATS_TEST_TMPDIR}/systemd-dropin"
    export TACCTL_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl"
    # The RADIUS backend's paths: its raddb, log
    # directory, daemon binary and logrotate directory. The systemd directory
    # is TACCTL_SYSTEMD_DIR, shared with the TACACS+ backend.
    export TACCTL_RADIUS_DIR="${BATS_TEST_TMPDIR}/raddb"
    export TACCTL_RADIUS_LOG="${BATS_TEST_TMPDIR}/radius-log"
    export TACCTL_RADIUS_BIN="${BATS_TEST_TMPDIR}/radius-bin/radiusd"
    export TACCTL_LOGROTATE_DIR="${BATS_TEST_TMPDIR}/logrotate.d"
    # The package's main dictionary, which tacctl's own includes: present, as
    # an installed package has it (a test that wants it absent removes it).
    export TACCTL_RADIUS_DICT="${BATS_TEST_TMPDIR}/radius-share/dictionary"
    # Skip the sudo re-exec so tacctl runs as the current (non-root) user.
    # Prod never sets this.
    export TACCTL_SKIP_SUDO=1
    # A sudo caller's SUDO_UID would make tacctl check SUDO_USER against it
    # (getent passwd); a test that wants the check sets both.
    unset SUDO_UID

    mkdir -p "$(dirname "$TACCTL_RADIUS_DICT")" && : > "$TACCTL_RADIUS_DICT"
    mkdir -p "${TACCTL_ETC}" "${TACCTL_LOG}" "${TACCTL_BIN}" \
             "${TACCTL_STATE_DIR}/backups" \
             "${TACCTL_STATE_DIR}/backups/password-dates"
    # The tacctl.yaml defaults are embedded in the binary; no fixture file to
    # seed.
}
