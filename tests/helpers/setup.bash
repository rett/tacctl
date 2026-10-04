#!/usr/bin/env bash
# Common bats setup. Source from test files via:
#   load ../helpers/setup

TACCTL_SRC="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
export TACCTL_SRC
# The binary under test: 'make build' writes it (bin/tacctl.sh --build with
# the test knobs compiled in). TACCTL_TREE is the checkout it treats as its
# own (templates, patches, the deploy tree of 'config branch').
TACCTL_BIN_SCRIPT="${TACCTL_SRC}/dist/tacctl"
if [[ ! -x "$TACCTL_BIN_SCRIPT" ]]; then
    echo "setup.bash: ${TACCTL_BIN_SCRIPT} is missing; run 'make build' first" >&2
    return 1
fi
export TACCTL_BIN_SCRIPT TACCTL_TREE="${TACCTL_SRC}"

load "${TACCTL_SRC}/tests/bats/bats-support/load"
load "${TACCTL_SRC}/tests/bats/bats-assert/load"
load "${TACCTL_SRC}/tests/bats/bats-file/load"

# Thin wrappers around the CLI: read merged tacctl.yaml values without
# reaching into YAML directly.
conf_get()      { "$TACCTL_BIN_SCRIPT" config get      "$@"; }
conf_get_list() { "$TACCTL_BIN_SCRIPT" config get-list "$@"; }
