#!/usr/bin/env bash
# release-reproduce.sh <tag> [<dir>]
#
# Is the published release <tag> what a clean checkout of the tag builds?
# Run it from a clean checkout of <tag> (the clone's current directory; it
# needs the tag's own bin/tacctl.sh, Makefile and release/allowed_signers,
# the Go toolchain of that tacctl.sh, gh and ssh-keygen). It:
#   1. downloads the published SHA256SUMS and SHA256SUMS.sig with gh into
#      <dir> (default: a temporary directory, removed on exit);
#   2. verifies that signature with the tag's release/allowed_signers (the
#      published sums are the signed ones; no private key is involved);
#   3. rebuilds both binaries with 'make release-assets' (dist/release);
#   4. compares the rebuilt SHA256SUMS with the published one;
#   5. checks the rebuilt binaries: test knobs off, built from the tag's
#      commit (tests/tools/release-stamps.sh, neither is executed).
# Exit 0 when reproducible; 1, with the diff, when not. <dir> keeps
# SHA256SUMS, SHA256SUMS.sig, SHA256SUMS.rebuilt and SHA256SUMS.diff.
# GH_REPO names the repository (default $GITHUB_REPOSITORY, else
# rett/tacctl); GH_TOKEN or 'gh auth login' authenticates gh.
set -euo pipefail

die() { echo "release-reproduce: $*" >&2; exit 1; }

if [[ $# -lt 1 || $# -gt 2 || -z "$1" || "$1" == -* ]]; then
    echo "Usage: release-reproduce.sh <tag> [<dir>]" >&2
    exit 2
fi
tag="$1"
out="${2:-}"
tools="$(cd "$(dirname "$0")" && pwd)"

[[ "$tag" =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || die "'${tag}' is not a release tag name"
for c in git make gh ssh-keygen sha256sum diff; do
    command -v "$c" > /dev/null 2>&1 || die "${c} is not installed"
done
top=$(git rev-parse --show-toplevel 2> /dev/null) \
    || die "not in a git checkout (run it from a clean checkout of ${tag})"
cd "$top"

want=$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}") \
    || die "the tag ${tag} is not in this clone (git fetch --tags)"
have=$(git rev-parse HEAD)
[[ "$have" == "$want" ]] \
    || die "HEAD is ${have}, not the commit of ${tag} (${want}); git checkout ${tag} first"
[[ -z "$(git status --porcelain)" ]] \
    || die "the tree has local changes; run it from a clean checkout of ${tag}"
signers="${top}/release/allowed_signers"
grep -qE '^[[:space:]]*[^#[:space:]]' "$signers" 2> /dev/null \
    || die "no release key in release/allowed_signers of ${tag}"

if [[ -z "$out" ]]; then
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
else
    mkdir -p "$out"
    out=$(cd "$out" && pwd)
fi
repo="${GH_REPO:-${GITHUB_REPOSITORY:-rett/tacctl}}"

echo "Downloading SHA256SUMS and SHA256SUMS.sig of ${repo} ${tag}..."
rm -f "${out}/SHA256SUMS" "${out}/SHA256SUMS.sig"
gh release download "$tag" --repo "$repo" --dir "$out" --clobber \
    --pattern SHA256SUMS --pattern SHA256SUMS.sig \
    || die "could not download SHA256SUMS and SHA256SUMS.sig of release ${tag} from ${repo} (is the release published, and gh authenticated?)"
for f in SHA256SUMS SHA256SUMS.sig; do
    [[ -s "${out}/${f}" ]] || die "release ${tag} has no ${f}"
done

# The same check a host makes (bin/tacctl.sh shim_verify_sig).
if ! msg=$(ssh-keygen -Y verify -f "$signers" -I tacctl-release -n tacctl-release \
    -s "${out}/SHA256SUMS.sig" < "${out}/SHA256SUMS" 2>&1); then
    echo "$msg" >&2
    die "the published SHA256SUMS.sig does not verify with the release key of ${tag}"
fi
echo "Published SHA256SUMS: good signature by tacctl-release."

make release-assets
sums=dist/release/SHA256SUMS
[[ -s "$sums" ]] || die "make release-assets wrote no ${sums}"
for arch in amd64 arm64; do
    [[ -f "dist/release/tacctl-${tag}-linux-${arch}" ]] \
        || die "make release-assets built no tacctl-${tag}-linux-${arch} (HEAD is at another tag as well?)"
done
cp "$sums" "${out}/SHA256SUMS.rebuilt"

status=0
if diff -u --label "published SHA256SUMS" --label "rebuilt SHA256SUMS" \
    "${out}/SHA256SUMS" "${out}/SHA256SUMS.rebuilt" > "${out}/SHA256SUMS.diff"; then
    echo "The rebuilt SHA256SUMS is the published one."
else
    cat "${out}/SHA256SUMS.diff"
    echo "release-reproduce: ${tag} is NOT reproducible: the rebuilt SHA256SUMS differs from the published one" >&2
    status=1
fi

"${tools}/release-stamps.sh" dist/release "$want" || status=1

if [[ $status -ne 0 ]]; then
    exit 1
fi
echo "${tag} is reproducible: the published SHA256SUMS is signed by the release key and a clean rebuild gives the same sums."
