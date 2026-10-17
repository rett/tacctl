#!/usr/bin/env bash
# no-os-tempdir.sh
#
# Fails when program code reads the process's temporary directory:
# os.TempDir, os.MkdirTemp("", ...) or os.CreateTemp("", ...) in a non-test
# .go file of internal/ or cmd/. The temporary directory of an invocation is
# paths.Paths.TempDir (the TMPDIR of the environment it was given), so a test
# can sandbox it without changing the process; internal/paths/paths.go is the
# one place that asks the process, for the default. A caller that has no
# Paths takes the directory as an argument.
set -euo pipefail
cd "$(dirname "$0")/../.."

re='os\.TempDir|MkdirTemp\(""|CreateTemp\(""'
hits=$(git grep -nIE "$re" -- 'internal/*.go' 'cmd/*.go' ':!*_test.go' ':!internal/paths/paths.go' || true)
if [[ -n "$hits" ]]; then
    echo "no-os-tempdir: the process's temporary directory is read outside internal/paths/paths.go:" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    echo "no-os-tempdir: use paths.Paths.TempDir (or a directory passed in) instead." >&2
    exit 1
fi
