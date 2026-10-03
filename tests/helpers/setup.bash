#!/usr/bin/env bash
# Common bats setup. Source from test files via:
#   load ../helpers/setup

TACCTL_SRC="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
export TACCTL_SRC
# The implementation under test (docs/plans/go-rewrite.md 2.1): bash runs
# bin/tacctl.sh; go runs the binary 'make build' writes to dist/tacctl, which
# hands every command it does not implement yet to TACCTL_BASH_IMPL and takes
# TACCTL_TREE as its checkout. Phase 4 of the Go rewrite flips the default.
: "${TACCTL_IMPL:=bash}"
case "$TACCTL_IMPL" in
    go)
        TACCTL_BIN_SCRIPT="${TACCTL_SRC}/dist/tacctl"
        export TACCTL_BASH_IMPL="${TACCTL_SRC}/bin/tacctl.sh"
        export TACCTL_TREE="${TACCTL_SRC}"
        ;;
    bash)
        TACCTL_BIN_SCRIPT="${TACCTL_SRC}/bin/tacctl.sh"
        ;;
    *)
        echo "setup.bash: TACCTL_IMPL must be bash or go, not '${TACCTL_IMPL}'" >&2
        return 1
        ;;
esac
export TACCTL_IMPL TACCTL_BIN_SCRIPT

load "${TACCTL_SRC}/tests/bats/bats-support/load"
load "${TACCTL_SRC}/tests/bats/bats-assert/load"
load "${TACCTL_SRC}/tests/bats/bats-file/load"

# Thin wrappers around the user-facing CLI. Integration tests that invoke
# tacctl.sh as a subprocess (so conf_* isn't in their shell env) can use
# these to read merged config values without reaching into YAML directly.
conf_get()      { "$TACCTL_BIN_SCRIPT" config get      "$@"; }
conf_get_list() { "$TACCTL_BIN_SCRIPT" config get-list "$@"; }
