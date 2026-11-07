#!/usr/bin/env bash
# release-notes-check.sh <version> [<tree>]
#
# What a release needs before it is cut (docs/releasing.md), checked from the
# tree's files; qargi runs it as release.preflight before 'release start' and
# 'release push' change anything:
#   - docs/release-notes-<version>.md exists, starts with '# tacctl <version>'
#     and says where the full list is (CHANGELOG.md);
#   - CHANGELOG.md has the section of <version> (unreleased or dated) with at
#     least one numbered item, numbered 1, 2, 3 ... without a gap;
#   - 'const rollbackFrom' in internal/cli/rollback.go is <version>.
# Every problem is listed; exit 1 when there is one.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || -z "$1" ]]; then
    echo "Usage: release-notes-check.sh <version> [<tree>]" >&2
    exit 2
fi
version="$1"
tree="${2:-$(cd "$(dirname "$0")/../.." && pwd)}"
[[ "$version" =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || { echo "release-notes-check: '${version}' is not a version" >&2; exit 2; }
[[ -d "$tree" ]] || { echo "release-notes-check: ${tree} is not a directory" >&2; exit 2; }

bad=0
fail() { echo "release-notes-check: ${version}: $*" >&2; bad=1; }

notes="${tree}/docs/release-notes-${version}.md"
if [[ ! -f "$notes" ]]; then
    fail "docs/release-notes-${version}.md is missing"
else
    [[ "$(head -n 1 "$notes")" == "# tacctl ${version}" ]] || fail "the first line of docs/release-notes-${version}.md is not '# tacctl ${version}'"
    grep -q 'CHANGELOG\.md' "$notes" || fail "docs/release-notes-${version}.md does not point at CHANGELOG.md"
fi

changelog="${tree}/CHANGELOG.md"
if [[ ! -f "$changelog" ]]; then
    fail "CHANGELOG.md is missing"
else
    items=$(awk -v v="$version" '
        index($0, "## " v " (") == 1 { in_sec = 1; next }
        /^## / { in_sec = 0 }
        in_sec && /^[0-9]+\. / { sub(/\..*/, ""); print }' "$changelog")
    if [[ -z "$items" ]]; then
        fail "CHANGELOG.md has no section '## ${version} (...)' with numbered items"
    else
        want=1
        while read -r n; do
            [[ "$n" == "$want" ]] || { fail "CHANGELOG.md items are not numbered 1, 2, 3 ... (found ${n} where ${want} was expected)"; break; }
            want=$((want + 1))
        done <<< "$items"
    fi
fi

from=$(sed -n 's/^const rollbackFrom = "\(.*\)"$/\1/p' "${tree}/internal/cli/rollback.go" 2> /dev/null || true)
[[ "$from" == "$version" ]] || fail "const rollbackFrom in internal/cli/rollback.go is '${from}', not '${version}'"

exit "$bad"
