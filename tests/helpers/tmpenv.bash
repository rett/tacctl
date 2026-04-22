#!/usr/bin/env bash
# Redirect tacctl's paths into the bats tmpdir so tests never touch host state.
# Call from test setup() after load helpers/setup.

tacctl_tmpenv_init() {
    export TACCTL_ETC="${BATS_TEST_TMPDIR}/etc"
    export TACCTL_LOG="${BATS_TEST_TMPDIR}/log"
    export TACCTL_BIN="${BATS_TEST_TMPDIR}/bin"
    export TACCTL_CONFIG="${TACCTL_ETC}/tacquito.yaml"
    export TACCTL_OVERRIDE_DIR="${BATS_TEST_TMPDIR}/systemd-dropin"
    export TACCTL_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl"
    # Skip the sudo re-exec so subprocess invocations of tacctl.sh from tests
    # run as the current (non-root) user. Prod never sets this.
    export TACCTL_SKIP_SUDO=1

    mkdir -p "${TACCTL_ETC}" "${TACCTL_LOG}" "${TACCTL_BIN}" \
             "${TACCTL_ETC}/backups" \
             "${TACCTL_ETC}/backups/password-dates"
}

# Source tacctl.sh so unit tests can call its functions directly.
# Depends on the main-gate (BASH_SOURCE==$0) introduced for testability.
tacctl_source_lib() {
    # shellcheck disable=SC1090
    source "${TACCTL_BIN_SCRIPT}"
}
