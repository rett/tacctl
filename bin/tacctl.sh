#!/usr/bin/env bash
#
# tacctl — bootstrap shim (docs/plans/go-rewrite.md 5.2).
#
# tacctl is a Go program; this script makes sure the installed command
# (/usr/local/bin/tacctl) is the binary of this tree, then runs it with the
# arguments given:
#
#   1. As root (it re-runs itself under sudo otherwise), umask 022.
#   2. The binary is current (a regular file built from this tree's HEAD):
#      run it, nothing else.
#   3. Otherwise the Go toolchain is checked (go.mod's go line) and, when it
#      is missing or older, Go GO_VERSION is installed in /usr/local/go; a
#      newer Go is never replaced.
#   4. The binary is obtained (shim_obtain): when this tree is checked out at
#      a release tag, the release binary for this machine is downloaded and
#      installed if its signature, its checksum and the commit it was built
#      from all check out (docs/releasing.md); otherwise (a branch, or any of
#      those failing, which is said in one line) it is built from this tree
#      (the recipe below). It is installed in one rename; on failure the
#      installed command is left as it was and the way back to the bash
#      release is printed (exit 1).
#   5. The new binary runs with the arguments.
#   6. '--build <out> [--tags <tags>] [--goarch <arch>]' only builds (no
#      root, nothing installed): 'make build' and 'make release-assets' use
#      it.
#   7. '--install-binary <out>' only obtains (step 4) into <out>, without
#      sudo and without the toolchain step: 'tacctl install' and 'tacctl
#      upgrade' use it.
#   8. '--verify-release <dir> [<allowed_signers>]' checks release assets
#      before they are uploaded ('make release-verify').
#
# It runs when the README one-liner installs tacctl, when the bash release
# hands an upgrade over to this tree, and whenever /usr/local/bin/tacctl
# still points here; it is idempotent.
#
# TACCTL_TEST_ROOT (tests only) moves /usr/local/bin/tacctl and
# /usr/local/go under that directory; TACCTL_RELEASE_BASE_URL (tests only)
# replaces the GitHub releases URL the release assets are fetched from.
set -euo pipefail

# The Go toolchain this tree is built with, and the bash release the way
# back leads to.
GO_VERSION="1.26.2"
TACCTL_BASH_RELEASE="0.1.18"

# tacctl.sh --build <out> [--tags <tags>] [--goarch <arch>]: compile the Go
# implementation in this script's tree (cmd/tacctl, vendored modules, no
# network) into <out>, atomically, and exit. Needs no root and installs
# nothing: 'make build' uses it, and the bootstrap shim and upgrade share
# the same recipe (docs/plans/go-rewrite.md 5.1). --goarch cross-builds for
# linux/<arch> ('make release-assets'); the default is this machine's. The
# version stamped in is 'git describe' of the tree; GOCACHE as root
# defaults to /root/.cache/go-build.
tacctl_go_build() {
    local out="${1:-}" tags="" goarch="" tree version commit date
    local go_bin="${TACCTL_TEST_ROOT:-}/usr/local/go/bin/go"
    local usage="Usage: tacctl.sh --build <out> [--tags <tags>] [--goarch <arch>]"
    if [[ -z "$out" || "$out" == -* ]]; then
        echo "$usage" >&2
        return 1
    fi
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tags) tags="${2:-}"; [[ -n "$tags" ]] || { echo "$usage" >&2; return 1; } ;;
            --goarch) goarch="${2:-}"; [[ "$goarch" =~ ^[a-z0-9]+$ ]] || { echo "$usage" >&2; return 1; } ;;
            *) echo "$usage" >&2; return 1 ;;
        esac
        shift 2
    done
    tree="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)" || return 1
    if [[ ! -f "${tree}/go.mod" ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m No Go module in ${tree} (go.mod missing)." >&2
        return 1
    fi
    if [[ ! -x "$go_bin" ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m Go toolchain not found at ${go_bin}." >&2
        return 1
    fi
    [[ "$out" == /* ]] || out="${PWD}/${out}"
    mkdir -p "$(dirname "$out")" || return 1
    version=$(git -C "$tree" describe --tags --always --dirty 2> /dev/null) || version="unknown"
    commit=$(git -C "$tree" rev-parse HEAD 2> /dev/null) || commit="unknown"
    date=$(git -C "$tree" log -1 --format=%cI 2> /dev/null) || date="unknown"
    if [[ -z "${GOCACHE:-}" && $EUID -eq 0 ]]; then
        export GOCACHE=/root/.cache/go-build
    fi
    local -a build=(build -trimpath -buildvcs=false)
    [[ -z "$tags" ]] || build+=(-tags "$tags")
    build+=(-ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}")
    build+=(-o "${out}.new" ./cmd/tacctl)
    local -a goenv=(GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0)
    [[ -z "$goarch" ]] || goenv+=(GOOS=linux GOARCH="$goarch")
    # A subshell for cd and umask; the trap drops a half-written binary on
    # failure or Ctrl-C. <out> itself changes only by the final rename.
    (
        trap 'rm -f "${out}.new"' EXIT
        cd "$tree" \
            && umask 022 \
            && env "${goenv[@]}" "$go_bin" "${build[@]}" \
            && chmod 755 "${out}.new" \
            && mv -f "${out}.new" "$out"
    )
}
# Sourced (by the tests): the recipe only.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0
if [[ "${1:-}" == "--build" ]]; then
    shift
    tacctl_go_build "$@" || exit 1
    exit 0
fi

umask 022
SHIM_TREE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
SHIM_CMD="${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl"
SHIM_GOROOT="${TACCTL_TEST_ROOT:-}/usr/local/go"
SHIM_TMP=""
trap '[[ -z "$SHIM_TMP" ]] || rm -rf "$SHIM_TMP"' EXIT

# [INFO] goes to stderr, or to stdout for '--install-binary' (tacctl's own
# INFO lines are on stdout, and the shim's then read as part of them).
SHIM_INFO_FD=2
shim_info() { echo -e "\033[0;32m[INFO]\033[0m $*" >&"$SHIM_INFO_FD"; }
shim_warn() { echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
shim_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# The installed command is the binary of this tree's HEAD.
shim_current() {
    local head have
    [[ -f "$SHIM_CMD" && ! -L "$SHIM_CMD" && -x "$SHIM_CMD" ]] || return 1
    head=$(git -C "$SHIM_TREE" rev-parse HEAD 2> /dev/null) || return 1
    have=$(TACCTL_SKIP_SUDO=1 "$SHIM_CMD" version --long 2> /dev/null | sed -n 's/^commit:[[:space:]]*//p') || return 1
    [[ -n "$head" && "$have" == "$head" ]]
}

# shim_version_ge <a> <b>: version a is b or newer.
shim_version_ge() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]
}

# shim_arch: this machine as a Go architecture (the Go download and the
# release binary), "" for any other.
shim_arch() {
    case "$(uname -m 2> /dev/null)" in
        x86_64 | amd64) echo amd64 ;;
        aarch64 | arm64) echo arm64 ;;
        *) echo "" ;;
    esac
}

# The Go this tree needs (go.mod's go line) and the one installed ("" for
# none).
shim_go_need() { sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' "${SHIM_TREE}/go.mod" | head -n 1; }
shim_go_have() {
    local v
    v=$("${SHIM_GOROOT}/bin/go" version 2> /dev/null | awk '{print $3}') || return 0
    echo "${v#go}"
}

# Install Go GO_VERSION in SHIM_GOROOT: the tarball and its published
# checksum, from the same origin (go.dev/dl redirects the tarball there but
# answers a .sha256 with a web page), verified before anything installed
# is touched. Without a checksum to verify against, nothing is installed.
SHIM_GO_DL="https://dl.google.com/go"
shim_install_go() {
    local arch tarball want sum
    arch=$(shim_arch)
    if [[ -z "$arch" ]]; then
        shim_error "Go ${GO_VERSION} cannot be installed on this machine: no Go download for $(uname -m 2> /dev/null || echo 'an unknown architecture') (amd64 and arm64 only). Install Go ${GO_VERSION} or newer in ${SHIM_GOROOT} by hand."
        return 1
    fi
    tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
    SHIM_TMP=$(mktemp -d)
    shim_info "Installing Go ${GO_VERSION}..."
    if ! wget -q -O "${SHIM_TMP}/${tarball}" "${SHIM_GO_DL}/${tarball}"; then
        shim_error "Could not download ${SHIM_GO_DL}/${tarball}."
        return 1
    fi
    # Go is installed only verified: no checksum (or anything but one) is a
    # refusal, as is a mismatch; the Go in place stays as it is.
    want=$(wget -qO- "${SHIM_GO_DL}/${tarball}.sha256" 2> /dev/null || true)
    want="${want#"${want%%[![:space:]]*}"}"
    want="${want%"${want##*[![:space:]]}"}"
    if [[ ! "$want" =~ ^[0-9a-f]{64}$ ]]; then
        rm -f "${SHIM_TMP}/${tarball}"
        shim_error "Go ${GO_VERSION} was not installed: it could not be verified (no checksum at ${SHIM_GO_DL}/${tarball}.sha256)."
        return 1
    fi
    sum=$(sha256sum "${SHIM_TMP}/${tarball}" | awk '{print $1}')
    if [[ "$want" != "$sum" ]]; then
        rm -f "${SHIM_TMP}/${tarball}"
        shim_error "Go tarball checksum mismatch!"
        shim_error "  Expected: ${want}"
        shim_error "  Got:      ${sum}"
        return 1
    fi
    shim_info "Go tarball checksum verified."
    rm -rf "$SHIM_GOROOT"
    mkdir -p "$(dirname "$SHIM_GOROOT")"
    tar -C "$(dirname "$SHIM_GOROOT")" -xzf "${SHIM_TMP}/${tarball}" || return 1
    rm -rf "$SHIM_TMP"
    SHIM_TMP=""
    shim_info "Go ${GO_VERSION} installed."
}

# The toolchain: go.mod's version or newer is there, or Go GO_VERSION is
# installed over an older one. A newer Go is never replaced.
shim_toolchain() {
    local need have
    need=$(shim_go_need)
    have=$(shim_go_have)
    if [[ -n "$have" && -n "$need" ]] && shim_version_ge "$have" "$need"; then
        return 0
    fi
    if [[ -n "$have" ]]; then
        if shim_version_ge "$have" "$GO_VERSION"; then
            shim_error "Go ${have} at ${SHIM_GOROOT} is older than this tree needs (${need}); install Go ${need} or newer."
            return 1
        fi
        shim_warn "Go ${have} found, upgrading to ${GO_VERSION}..."
    fi
    shim_install_go || return 1
    have=$(shim_go_have)
    if [[ -z "$have" || -z "$need" ]] || ! shim_version_ge "$have" "$need"; then
        shim_error "Go ${GO_VERSION} is older than this tree needs (${need:-unknown})."
        return 1
    fi
}

# Decision 20: say so, leave the installed command as it is, print the way
# back to the bash release, exit 1. Every later run of the command comes
# here again until the cause is fixed or the way back taken.
shim_fail() {
    local prev
    prev=$(git -C "$SHIM_TREE" rev-parse --abbrev-ref '@{-1}' 2> /dev/null) || prev=""
    [[ -n "$prev" && "$prev" != "HEAD" ]] || prev="master"
    shim_error "tacctl could not be built (see above). The installed command is unchanged."
    shim_error "Fix the cause and run the command again, or go back to the bash release:"
    shim_error "  sudo git -C ${SHIM_TREE} checkout ${TACCTL_BASH_RELEASE} && sudo tacctl config branch ${prev}"
    exit 1
}

# --- release binaries (docs/releasing.md) ------------------------------------
# A release tag publishes tacctl-<tag>-linux-{amd64,arm64}, SHA256SUMS and
# SHA256SUMS.sig, a signature by 'ssh-keygen -Y sign' with the release key
# whose public half is release/allowed_signers (identity and namespace
# tacctl-release).
SHIM_RELEASE_URL="${TACCTL_RELEASE_BASE_URL:-https://github.com/rett/tacctl/releases/download}"
SHIM_RELEASE_ID="tacctl-release"

# shim_has_key <allowed_signers>: the file names at least one key (a line
# that is not blank and not a comment).
shim_has_key() { [[ -f "$1" ]] && grep -qE '^[[:space:]]*[^#[:space:]]' "$1"; }

# shim_verify_sig <dir> <allowed_signers>: <dir>/SHA256SUMS.sig is a good
# signature of <dir>/SHA256SUMS by the release identity.
shim_verify_sig() {
    ssh-keygen -Y verify -f "$2" -I "$SHIM_RELEASE_ID" -n "$SHIM_RELEASE_ID" \
        -s "${1}/SHA256SUMS.sig" < "${1}/SHA256SUMS" > /dev/null 2>&1
}

# shim_verify_sum <dir> <file>: SHA256SUMS has exactly one line for <file>,
# and <dir>/<file> matches it.
shim_verify_sum() {
    local lines
    lines=$(awk -v f="$2" '($2 == f || $2 == "*" f) && $1 ~ /^[0-9a-f]{64}$/' "${1}/SHA256SUMS") || return 1
    [[ -n "$lines" && "$(wc -l <<< "$lines")" -eq 1 ]] || return 1
    (cd "$1" && sha256sum -c --quiet --status <<< "$lines")
}

# shim_commit_of <binary>: the commit a tacctl binary says it was built from.
shim_commit_of() {
    TACCTL_SKIP_SUDO=1 "$1" version --long 2> /dev/null | sed -n 's/^commit:[[:space:]]*//p'
}

# shim_download <tmp> <tag> <asset>: the three release files into <tmp>;
# the name of the first that could not be fetched on failure.
shim_download() {
    local f
    for f in SHA256SUMS SHA256SUMS.sig "$3"; do
        if ! wget -q --timeout=30 --tries=2 -O "${1}/${f}" "${SHIM_RELEASE_URL}/${2}/${f}" 2> /dev/null; then
            echo "$f"
            return 1
        fi
    done
}

# shim_release <dst> <tmp>: when this tree is at a release tag, the release
# binary for this machine into <dst>, verified. Silent (status 2) on a
# branch; otherwise prints the INFO line and returns 0, or sets
# SHIM_RELEASE_WHY and returns 1.
SHIM_RELEASE_TAG=""
SHIM_RELEASE_WHY=""
shim_release() {
    local dst="$1" tmp="$2" tag arch asset head have missing
    local signers="${SHIM_TREE}/release/allowed_signers"
    tag=$(git -C "$SHIM_TREE" describe --tags --exact-match --match '[0-9]*' HEAD 2> /dev/null) || return 2
    [[ "$tag" =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || return 2
    SHIM_RELEASE_TAG="$tag"
    if ! git -C "$SHIM_TREE" diff --quiet HEAD -- 2> /dev/null; then
        SHIM_RELEASE_WHY="the tree has local changes"
        return 1
    fi
    if ! shim_has_key "$signers"; then
        SHIM_RELEASE_WHY="no release key configured"
        return 1
    fi
    arch=$(shim_arch)
    if [[ -z "$arch" ]]; then
        SHIM_RELEASE_WHY="no release binary for linux/$(uname -m 2> /dev/null || echo unknown)"
        return 1
    fi
    if ! command -v wget > /dev/null 2>&1; then
        SHIM_RELEASE_WHY="wget is not installed"
        return 1
    fi
    if ! command -v ssh-keygen > /dev/null 2>&1; then
        SHIM_RELEASE_WHY="ssh-keygen is not installed"
        return 1
    fi
    asset="tacctl-${tag}-linux-${arch}"
    if ! missing=$(shim_download "$tmp" "$tag" "$asset"); then
        SHIM_RELEASE_WHY="could not download ${missing}"
        return 1
    fi
    if ! shim_verify_sig "$tmp" "$signers"; then
        SHIM_RELEASE_WHY="the signature of SHA256SUMS does not verify"
        return 1
    fi
    if ! shim_verify_sum "$tmp" "$asset"; then
        SHIM_RELEASE_WHY="${asset} does not match SHA256SUMS"
        return 1
    fi
    chmod 755 "${tmp}/${asset}"
    head=$(git -C "$SHIM_TREE" rev-parse HEAD 2> /dev/null) || head=""
    have=$(shim_commit_of "${tmp}/${asset}") || have=""
    if [[ -z "$head" || "$have" != "$head" ]]; then
        SHIM_RELEASE_WHY="it was built from commit ${have:-unknown}, not ${head:-unknown}"
        return 1
    fi
    # Into place in one rename on dst's own filesystem.
    if ! mkdir -p "$(dirname "$dst")" || ! cp "${tmp}/${asset}" "${dst}.new" \
        || ! chmod 755 "${dst}.new" || ! mv -f "${dst}.new" "$dst"; then
        rm -f "${dst}.new"
        SHIM_RELEASE_WHY="it could not be installed as ${dst}"
        return 1
    fi
    shim_info "Installing the ${tag} release binary (linux/${arch}, verified)"
}

# shim_obtain <dst>: the release binary (shim_release), else the binary
# built from this tree, as <dst>. Any reason the release binary was not
# used is one INFO line; only a failed build is an error.
shim_obtain() {
    local dst="$1" rc=0
    [[ "$dst" == /* ]] || dst="${PWD}/${dst}"
    SHIM_TMP=$(mktemp -d)
    shim_release "$dst" "$SHIM_TMP" || rc=$?
    rm -rf "$SHIM_TMP"
    SHIM_TMP=""
    [[ $rc -ne 0 ]] || return 0
    if [[ $rc -eq 1 ]]; then
        shim_info "Release binary for ${SHIM_RELEASE_TAG} not used (${SHIM_RELEASE_WHY}); building from source."
    fi
    shim_info "Building ${dst} from ${SHIM_TREE}..."
    tacctl_go_build "$dst"
}

# shim_verify_release <dir> [<allowed_signers>]: the release assets in <dir>
# before they are uploaded: SHA256SUMS.sig verifies, every file SHA256SUMS
# lists is there and matches, and the binary for this machine was built
# from this tree's HEAD.
shim_verify_release() {
    local dir="${1:-}" signers="${2:-${SHIM_TREE}/release/allowed_signers}" arch head have f n=0
    if [[ -z "$dir" || ! -d "$dir" ]]; then
        echo "Usage: tacctl.sh --verify-release <dir> [<allowed_signers>]" >&2
        return 1
    fi
    if ! shim_has_key "$signers"; then
        shim_error "No release key in ${signers} (docs/releasing.md says how to add it)."
        return 1
    fi
    if ! command -v ssh-keygen > /dev/null 2>&1; then
        shim_error "ssh-keygen is not installed."
        return 1
    fi
    for f in SHA256SUMS SHA256SUMS.sig; do
        [[ -f "${dir}/${f}" ]] || { shim_error "${dir}/${f} is missing."; return 1; }
    done
    if ! shim_verify_sig "$dir" "$signers"; then
        shim_error "The signature ${dir}/SHA256SUMS.sig does not verify with ${signers}."
        return 1
    fi
    shim_info "SHA256SUMS: good signature by ${SHIM_RELEASE_ID}."
    if ! (cd "$dir" && sha256sum -c --strict SHA256SUMS); then
        shim_error "A file does not match SHA256SUMS (or is missing)."
        return 1
    fi
    head=$(git -C "$SHIM_TREE" rev-parse HEAD 2> /dev/null) || head=""
    arch=$(shim_arch)
    while read -r _ f; do
        f="${f#\*}"
        n=$((n + 1))
        [[ -n "$arch" && "$f" == tacctl-*-linux-"$arch" ]] || continue
        have=$(shim_commit_of "${dir}/${f}") || have=""
        if [[ -z "$head" || "$have" != "$head" ]]; then
            shim_error "${f} was built from commit ${have:-unknown}, not this tree's HEAD (${head:-unknown})."
            return 1
        fi
        shim_info "${f}: built from ${head}."
    done < "${dir}/SHA256SUMS"
    if [[ $n -eq 0 ]]; then
        shim_error "SHA256SUMS lists no file."
        return 1
    fi
    shim_info "Release assets in ${dir} verified."
}

case "${1:-}" in
    --install-binary)
        if [[ $# -ne 2 || -z "$2" || "$2" == -* ]]; then
            echo "Usage: tacctl.sh --install-binary <out>" >&2
            exit 1
        fi
        SHIM_INFO_FD=1
        shim_obtain "$2" || exit 1
        exit 0
        ;;
    --verify-release)
        shift
        shim_verify_release "$@" || exit 1
        exit 0
        ;;
esac

if shim_current; then
    exec "$SHIM_CMD" "$@"
fi

# Building and installing need root; re-run under sudo as tacctl does
# ('host' keeps the agent socket for its ssh: sudo accepts the assignment
# because the tacctl drop-ins keep SSH_AUTH_SOCK with env_keep, or the rule
# is ALL).
if [[ $EUID -ne 0 && "${TACCTL_SKIP_SUDO:-0}" != "1" ]]; then
    if [[ "${1:-}" == host && -n "${SSH_AUTH_SOCK:-}" ]]; then
        exec sudo SSH_AUTH_SOCK="$SSH_AUTH_SOCK" "$0" "$@"
    fi
    exec sudo "$0" "$@"
fi

shim_toolchain || shim_fail
mkdir -p "$(dirname "$SHIM_CMD")"
shim_obtain "$SHIM_CMD" || shim_fail
exec "$SHIM_CMD" "$@"
