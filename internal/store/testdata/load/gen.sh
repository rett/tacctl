#!/usr/bin/env bash
# Regenerate internal/store/testdata/load/expected.jsonl from the python of
# the 0.1.16 tag (needs git, bash and python3 with PyYAML 6.0.1; run it as
# a user that cannot read a mode-000 file, i.e. not root). See gen.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT
git -C "$top" archive 0.1.16 lib | tar -x -C "$tmp"
# The program _store_python runs (lib/store.sh): the store, the model and
# the dispatcher.
# shellcheck disable=SC1091
( source "${tmp}/lib/store.sh"; source "${tmp}/lib/model.sh"
  { _store_py; _model_py; _store_main_py; } > "${tmp}/prog.py" )
python3 "${here}/gen.py" "${tmp}/prog.py" "${tmp}/work" "${top}/tests/fixtures" > "${here}/expected.jsonl"
