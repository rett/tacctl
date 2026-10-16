#!/usr/bin/env bash
# release-preflight.sh <tag> [<tree>]
#
# The release metadata of <tag> (docs/releasing.md) is in place in <tree>
# (default: this repository), before anything is built or signed:
#   - CHANGELOG.md has the dated heading '## <tag> (YYYY-MM-DD)' (a real
#     date) and no '## <tag> (unreleased)' heading;
#   - the .TH line of man/tacctl.1 carries 'tacctl <tag>' and the same date;
#   - docs/release-notes-<tag>.md exists.
# Every problem is listed; exit 1 when there is one. 'make release-assets'
# runs it for a release tag (not for RELEASE_TAG trials).
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || -z "$1" ]]; then
    echo "Usage: release-preflight.sh <tag> [<tree>]" >&2
    exit 2
fi
tag="$1"
tree="${2:-$(cd "$(dirname "$0")/../.." && pwd)}"
bad=0
fail() { echo "release-preflight: ${tag}: $*" >&2; bad=1; }

[[ "$tag" =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || { echo "release-preflight: '${tag}' is not a release tag name" >&2; exit 2; }
[[ -d "$tree" ]] || { echo "release-preflight: ${tree} is not a directory" >&2; exit 2; }

esc="${tag//./\\.}"
changelog="${tree}/CHANGELOG.md"
date=""
if [[ ! -f "$changelog" ]]; then
    fail "CHANGELOG.md is missing"
else
    if grep -qE "^## ${esc} \(unreleased\)" "$changelog"; then
        fail "CHANGELOG.md still has the heading '## ${tag} (unreleased)' (the release start dates it: '## ${tag} (YYYY-MM-DD)')"
    fi
    heading=$(grep -E "^## ${esc} \(" "$changelog" | head -n 1 || true)
    if [[ -z "$heading" ]]; then
        fail "CHANGELOG.md has no '## ${tag} (YYYY-MM-DD)' heading"
    elif [[ "$heading" =~ ^##\ .*\ \(([0-9]{4}-[0-9]{2}-[0-9]{2})\)$ ]]; then
        date="${BASH_REMATCH[1]}"
        if [[ "$(date -u -d "$date" +%F 2> /dev/null || true)" != "$date" ]]; then
            fail "CHANGELOG.md heading '${heading}' does not hold a valid date"
            date=""
        fi
    elif [[ "$heading" != *"(unreleased)"* ]]; then
        fail "CHANGELOG.md heading '${heading}' is not '## ${tag} (YYYY-MM-DD)'"
    fi
fi

man="${tree}/man/tacctl.1"
if [[ ! -f "$man" ]]; then
    fail "man/tacctl.1 is missing"
else
    th=$(grep -m 1 '^\.TH ' "$man" || true)
    if [[ -z "$th" ]]; then
        fail "man/tacctl.1 has no .TH line"
    else
        if [[ "$th" != *'"tacctl '"${tag}"'"'* ]]; then
            fail "the .TH line of man/tacctl.1 does not name \"tacctl ${tag}\": ${th}"
        fi
        if [[ -n "$date" && "$th" != *'"'"${date}"'"'* ]]; then
            fail "the .TH line of man/tacctl.1 does not carry the CHANGELOG date \"${date}\": ${th}"
        fi
    fi
fi

[[ -s "${tree}/docs/release-notes-${tag}.md" ]] \
    || fail "docs/release-notes-${tag}.md is missing or empty"

if [[ $bad -ne 0 ]]; then
    echo "release-preflight: the release metadata of ${tag} is not ready (docs/releasing.md, step 1)" >&2
    exit 1
fi
echo "Release metadata of ${tag} in place (CHANGELOG ${date}, man page, release notes)."
