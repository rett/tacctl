#!/usr/bin/env bash
# Common bats setup. Source from test files via:
#   load ../helpers/setup

TACCTL_SRC="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
export TACCTL_SRC
export TACCTL_BIN_SCRIPT="${TACCTL_SRC}/bin/tacctl.sh"

load "${TACCTL_SRC}/tests/bats/bats-support/load"
load "${TACCTL_SRC}/tests/bats/bats-assert/load"
load "${TACCTL_SRC}/tests/bats/bats-file/load"
