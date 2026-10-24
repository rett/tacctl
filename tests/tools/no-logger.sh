#!/usr/bin/env bash
# no-logger.sh
#
# Fails when program code starts logger(1) itself: an execx.Cmd{Name:
# "logger"...} in a non-test .go file of internal/ or cmd/ outside
# internal/audit. Every audit line goes through the invocation's writer
# (app.App.Audit), which runs logger on a context no signal cancels, adds the
# session id and reports a logger that failed; a second call site would have
# none of that.
set -euo pipefail
cd "$(dirname "$0")/../.."

re='Name:[[:space:]]*"logger"'
hits=$(git grep -nIE "$re" -- 'internal/*.go' 'cmd/*.go' ':!*_test.go' ':!internal/audit/*.go' || true)
if [[ -n "$hits" ]]; then
    echo "no-logger: logger is started outside internal/audit:" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    echo "no-logger: write the line with app.App.Audit() (Line or Raw) instead." >&2
    exit 1
fi
