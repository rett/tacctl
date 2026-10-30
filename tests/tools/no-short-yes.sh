#!/usr/bin/env bash
# no-short-yes.sh
#
# Fails when a non-test .go file of internal/ or cmd/ gives --yes a
# one-letter spelling again: a "-y" string, or '-y' in the usage and help
# text ('[-y]', '-y|--yes', '-y, --yes'). --yes has no shorthand. The lines of
# the other programs tacctl runs are left out: ssh-keygen -y, and the
# install -y of apt-get, dnf and yum.
set -euo pipefail
cd "$(dirname "$0")/../.."

re='(^|[^[:alnum:]_-])-y([^[:alnum:]_-]|$)'
hits=$(git grep -nIE "$re" -- 'internal/*.go' 'cmd/*.go' ':!*_test.go' ':!internal/yamlpy/*' |
    grep -vE 'ssh-keygen|apt-get|dnf|yum|-y -qq?' || true)
if [[ -n "$hits" ]]; then
    echo "no-short-yes: --yes has no -y shorthand; found:" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    echo "no-short-yes: declare and document --yes only." >&2
    exit 1
fi
