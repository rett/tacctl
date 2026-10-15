#!/usr/bin/env bash
# release-stamps.sh <dir> <commit>
#
# The release binaries tacctl-*-linux-{amd64,arm64} in <dir> were built
# without the test knobs and from <commit>. Neither binary is executed (the
# other architecture could not be): 'go version -m' reads the build tags, and
# the commit is the string the build stamped in with -X main.commit (a
# -trimpath build does not record -ldflags, so it is not in the build info).
# Used by 'make release-verify' and tests/tools/release-reproduce.sh
# (docs/releasing.md).
#
# GO names the go command; default $TACCTL_TEST_ROOT/usr/local/go/bin/go,
# else the one on PATH.
set -euo pipefail

die() { echo "release-stamps: $*" >&2; exit 1; }

[[ $# -eq 2 && -d "$1" && "$2" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "Usage: release-stamps.sh <dir> <commit (40 hex digits)>" >&2; exit 2; }
dir="$1" commit="$2"

go_bin="${GO:-${TACCTL_TEST_ROOT:-}/usr/local/go/bin/go}"
if [[ ! -x "$go_bin" ]]; then
    go_bin=$(command -v go) || die "no Go toolchain (GO=$go_bin is not executable and go is not on PATH)"
fi

for arch in amd64 arm64; do
    shopt -s nullglob
    files=("$dir"/tacctl-*-linux-"$arch")
    shopt -u nullglob
    [[ ${#files[@]} -eq 1 ]] || die "expected one tacctl-*-linux-${arch} in ${dir}, found ${#files[@]}"
    f="${files[0]}"
    info=$(GOTOOLCHAIN=local "$go_bin" version -m "$f" 2> /dev/null) \
        || die "${f##*/}: not a Go binary ('go version -m' failed)"
    tags=$(sed -n 's/^[[:space:]]*build[[:space:]][[:space:]]*-tags=//p' <<< "$info")
    if [[ "$tags" == *testknobs* ]]; then
        die "${f##*/}: built with the testknobs tag (test knobs: on)"
    fi
    if ! grep -qaF -- "$commit" "$f"; then
        die "${f##*/}: not built from commit ${commit} (the commit is not stamped in)"
    fi
    echo "${f##*/}: test knobs off, built from ${commit}."
done
echo "Release binaries in ${dir}: test knobs off, built from ${commit} (amd64 and arm64)."
