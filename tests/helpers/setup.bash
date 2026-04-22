#!/usr/bin/env bash
# Common bats setup. Source from test files via:
#   load ../helpers/setup

TACCTL_SRC="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
export TACCTL_SRC
export TACCTL_BIN_SCRIPT="${TACCTL_SRC}/bin/tacctl.sh"

load "${TACCTL_SRC}/tests/bats/bats-support/load"
load "${TACCTL_SRC}/tests/bats/bats-assert/load"
load "${TACCTL_SRC}/tests/bats/bats-file/load"

# Thin wrappers around the user-facing CLI. Integration tests that invoke
# tacctl.sh as a subprocess (so conf_* isn't in their shell env) can use
# these to read merged config values without reaching into YAML directly.
conf_get()      { "$TACCTL_BIN_SCRIPT" config get      "$@"; }
conf_get_list() { "$TACCTL_BIN_SCRIPT" config get-list "$@"; }
