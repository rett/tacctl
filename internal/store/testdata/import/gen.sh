#!/usr/bin/env bash
# Regenerate internal/store/testdata/import/expected/*.out from the python of
# the 0.1.16 tag (needs python3 with PyYAML, and git). See gen.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$top" archive 0.1.16 lib | tar -x -C "$tmp"
# shellcheck disable=SC1091
( source "${tmp}/lib/store.sh"; source "${tmp}/lib/model.sh"
  { _store_py; _model_py; } > "${tmp}/prog.py" )
rm -rf "${here}/expected"
TACCTL_STORE_NOT_INITIALISED_MSG=x python3 "$here/gen.py" "${tmp}/prog.py" "$here" "${top}/tests/fixtures"
